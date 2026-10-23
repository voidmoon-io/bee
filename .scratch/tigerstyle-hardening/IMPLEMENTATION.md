# Practical TigerStyle hardening

Implemented 2026-10-22 against `ebf2d29` plus the existing worktree edits. The implementation covers
the 13 findings in [the audit](../tigerstyle-audit/AUDIT.md). Existing transactional reload work and
unrelated changes were preserved in the original workspace. The tested changes were committed in an
isolated checkout for the pull request on 2026-10-23; no production deployment was made.

**PR status:** draft. Current `main` (`50e0ee1`) includes substantial session/interception changes and
the transactional reload fix from PR #39. A trial merge found conflicts. The validation below applies
to the audited `ebf2d29` baseline plus these changes, not to a merge with current `main`. Integration
and fresh verification are required before this PR is ready to merge.

## Coverage

| Finding | Change | Regression evidence |
| --- | --- | --- |
| S01: attenuation loses filesystem defaults | Effective default-deny state survives derivation, serialization, compilation, and planning; inherited read-only rules also survive omission. | Core attenuation tests; two tests over encoded enforcement plans, including sampled child-allow ⇒ parent-allow checks; live kernel write-denial test. |
| S02: grant normalization is discarded | Startup grants and dynamic grant/release/expiry store the derived policy, including executable pins. Transitions install before committing state. | Grant unit/property tests and host pin regression; live replacement of a granted executable's inode remains denied. |
| S03: host ledger writes follow project symlinks | Descriptor-relative traversal, no symlink following, regular-file/single-link checks, exclusive cache temporaries and relative rename. | Outside-sentinel tests, parent symlink and hardlink rejection, existing ledger/cache and human-verdict tests. |
| S04: output capture is unbounded | Concurrent bounded stdout/stderr drains, overflow discard for ordinary output, protocol overflow errors, final decoded-text cap and truncation notice. | Both pipes emit 400,000 bytes total; exact-cap/overflow/invalid-UTF-8 cases; early stdin close; 9 MB scanner output fails. |
| S05: canceled children outlive their owner | One child owner performs bounded cleanup on success, failure and cancellation. Enforced invocations own child cgroups; unconfirmed cleanup poisons execution. | Host delayed-marker regression; live `setsid` descendant cancellation while a sibling command and persistent service survive; invocation cgroup removal checked. |
| S06: hook actions are ignored | Shared exhaustive event/action interpretation for headless and interactive loops; explicit termination outcomes and one reactive retry. | Denial/termination produce no command side effects; hook-dispatch unit tests; existing dynamic-grant integration suite. |
| S07: finite leases never expire | Monotonic model-turn clock, expiry before schema construction, staged mandatory narrowing, tool lease ownership. | Host and REPL expiry tests, two tools share a turn, separate exchanges retain the lease clock; live policy expiry and live-service refusal prevent further privileged execution. |
| S08: operation deadlines are incomplete | Absolute episode deadline includes provider, backoff, hooks, consent and retries. MCP handshake plus bounded discovery share one startup deadline. | Stalled provider/consent and retry-backoff tests; in-memory MCP handshake/list fixtures for stalls, repeated cursor, oversized tool count, and success. |
| S09: audit work and retention are unbounded | Bounded ring batches, independent bounded subscriber queues, sticky loss/failure state, bounded lifetime retention, additive transcript health and conservative scoring. | Slow subscriber does not block a healthy sibling; retention/legacy transcript/scoring tests; live concurrent audit-isolation matrix case. |
| S10: chat height overflows `u16` | Document positions and totals use `usize`; only visible coordinates narrow to terminal types. | More than 65,535 rows render without overflow and the final marker remains visible; existing TUI layout/property tests. |
| P01: scanner imports repeatedly fold the ledger | At most 200 records per batch, one locked fold/publication, streaming bounded records, shared admitted blocking worker for imports and finding tools. | Two concurrent batches publish all 200 findings; existing verdict/rediscovery and scanner integrations; measurement below. |
| D01: feature failures escape CI | Required default/headless/MCP-security-grammar suites and enforcement/concurrency test compilation; explicit color state in affected TUI tests; isolated skill-test temporary directories. | Local feature suites, combined-feature Clippy, and `NO_COLOR=1` workspace tests. |
| D02: VM runner can falsely pass | Shared 38-case manifest; strict parser requires zero guest status, complete unique cases and one matching summary. | Three parser test methods with malformed/partial/duplicate/failure subcases; live matrix reports all 38 cases passed. |

The code and public behavior contracts are described in [docs/hardening.md](../../docs/hardening.md).

## Verification

Commands used for the final checks:

```sh
NO_COLOR=1 cargo test --workspace --locked --offline
cargo test --no-default-features --locked --offline
cargo test --features mcp,sec,astgrep-rust --locked --offline
cargo test --features concurrent,mcp,sec,astgrep-rust --test hardening --lib --locked --offline
cargo test -p bee-userspace --features tokio --locked --offline
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo clippy --no-default-features --all-targets --locked --offline -- -D warnings
cargo clippy --features concurrent,mcp,sec,astgrep-rust --all-targets --locked --offline -- -D warnings
cargo fmt --all -- --check
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/vm -p 'test_*.py'
bash test/vm/matrix.sh
```

The targeted kernel tests run serially as root on the reference KubeVirt VM, using the host-built
hardening executable: `bee-hardening-test kernel:: --ignored --test-threads=1 --nocapture`.
The VM has a real BPF-LSM kernel; these results are distinct from compiling enforcement features on
the host. The persistent-service isolation test uses a long-lived process in the parent scope, which
exercises the same cgroup lifetime as a stdio service; it is not an MCP protocol integration test.

| Check | Result |
| --- | --- |
| Workspace, `NO_COLOR=1` | 691 passed |
| Headless application | 413 passed |
| MCP, security tools, Rust grammar | 746 passed; 5 explicitly ignored |
| Combined enforcement/concurrency features, library and hardening tests | 512 passed; 7 explicitly ignored |
| Userspace async audit tests | 45 passed |
| Encoded-plan attenuation regressions | 2 passed (also included in the workspace run) |
| REPL clock across separate exchanges | Passed in a separate final focused run |
| Clippy: workspace, headless, combined features | Passed with warnings denied |
| Formatting and diff whitespace | Passed |
| VM parser fixtures | 3 methods passed, including multiple invalid-output subcases |
| Existing live VM matrix | All 38 required cases passed |
| New live kernel regressions | All 5 passed |

Counts are executions within each command, not unique tests across commands. Logs are in
[evidence/](evidence/). Ordinary test runs explicitly ignore tests requiring external MCP services,
the manual benchmark, and live kernel execution. They are not counted as passing. The five new
kernel regressions ran separately; the manual benchmark ran separately for the measurement below.

## Persistence measurement

One local debug-build measurement used the same workload: 2,000 existing records followed by 200
new findings. The control calls the current secure single-record API 200 times; the batch calls the
new batch API once. Thus this isolates repeated fold/publication, not every difference from the old
insecure implementation.

| Operation | View refreshes | Measured import time | Process peak RSS |
| --- | ---: | ---: | ---: |
| Repeated single-record calls | 200 | 18,756 ms | 16,960 KiB |
| One batch | 1 | 107 ms | 16,824 KiB |

These were single samples, with some concurrent host work, using `/usr/bin/time -v`. The stable
improvement is removing 199 full refreshes. The timings are a local illustration, not a production
latency or speedup guarantee. Peak RSS covers the whole test process, including fixture setup; it
does not establish constant-memory folding. The implementation keeps one record buffer plus the
distinct-finding view.

Reproduce with the compiled hardening test executable's `measure_ledger_batch --ignored --nocapture`
filter; set `BEE_LEDGER_BENCH_BASELINE=1` for the repeated single-record control. The output includes
workload size, refresh count and elapsed import time. The finite noisy-pipe test peaked at 10,624 KiB
RSS; byte-cap assertions provide stronger evidence of the output bound than that small stress sample.

## Implementation choices and limits

- Effective policy metadata lives in a typed `EffectiveDefaults` field on the existing `Policy`.
  This preserves serialization and the existing crate boundaries without a separate effective-policy
  wrapper migration. Every installation path now keeps the normalized result.
- Cancellation cleanup stays with the borrowed sandbox owner and can synchronously block for up to
  one second. This avoids detached cleanup racing enforcement teardown. Host process groups cannot
  contain deliberate session escapes; the enforced cgroup path supplies that guarantee.
- If final scope cleanup fails, BPF descriptors remain open until the Bee process exits. This does
  not promise enforcement after process exit. Runs with teardown failure report infrastructure error.
- Existing live-service reload restrictions are enforced. Transparent pause/reload/resume of persistent
  MCP services is outside this implementation.
- MCP discovery limits apply after rmcp transport decoding. A single oversized wire message can
  allocate before Bee inspects it; no transport-memory completeness claim is made.
- Known userspace audit loss is explicit. Kernel ring reservation loss remains uncounted; a healthy
  userspace stream is not proof that no kernel events were lost.
- Blocking filesystem work remains owned after async cancellation and may delay runtime shutdown.
  Batches preserve successful appends but are not crash-atomic transactions. The lock coordinates
  cooperating writers only; ledger paths through symlinks are intentionally refused.
- The plan's numbered commits describe review units. They were implemented together in the existing
  dirty worktree, preserving the user's changes. PR preparation then copied only the hardening work
  and its transactional-reload prerequisite into an isolated checkout. Unrelated edits remain local.

This closes the audited scope. It is not a complete dependency vulnerability audit or proof that
every sandbox boundary is secure.
