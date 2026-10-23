# Practical TigerStyle audit

Reviewed 2026-10-22 at `ebf2d29`, including the existing uncommitted worktree changes.

The main weaknesses are enforcement invariants, cancellation ownership, and resource bounds. The
code already has useful architectural seams and substantial tests. A broad stylistic rewrite would
deliver less value than repairing the specific contracts below.

I used TigerStyle's safety → performance → developer-experience priorities. I did not count assertions,
enforce a 70-line function quota, recommend eliminating normal Rust allocation, or flag idiomatic Rust
naming and guard clauses. Assertions should document established internal invariants; untrusted input
and expected operating failures should return errors.

**Scope and evidence**

Reviewed the policy compiler and attenuation path, enforcement planning and scope lifecycle, eBPF
hooks, grant handling, both execution loops, subprocess tools, MCP connection/registration, finding
storage and scanner ingestion, configuration boundaries, selected search/render paths, and verification
automation. This is a source audit with targeted host reproductions, not a complete kernel penetration
test, dependency vulnerability scan, or exhaustive review of every UI helper and excluded xtask crate.

Eight local Rust probes reproduce the behaviors identified as **reproduced** below. The policy probe
uses the actual encoded enforcement plan and shared host reference matcher; it does not execute an
operation against a live BPF-LSM kernel. Static findings are explicitly marked. Production source and
the pre-existing edits were left unchanged. Probe sources and test logs accompany this report.

## Safety

### S01 — High: narrowing the last write grant can grant writes outside the parent

**Locations:** [attenuation.rs:94](/home/jg/git/bee/crates/core/src/attenuation.rs:94),
[plan.rs:48](/home/jg/git/bee/crates/userspace/src/plan.rs:48).
**Evidence:** reproduced by `probe_narrowing_write_to_read_widens_unmatched_writes`.
**Principle:** preserve invariants across representations; check the negative space too.

A parent granting `/project-audit = write` sets `FLAG_FS_WRITE_DEFAULT_DENY`, so an unmatched write
to `/outside-audit/file` is denied. An accepted child changing that grant to `read` has no write rules,
so planning clears the flag and the same unmatched write is allowed. `inherit_restrictions` preserves
explicit denies but loses this implicit restriction. Project configuration reaches `derive` through
`resolve_from_layers`, so this affects a real authority boundary.

**Fix:** represent the default filesystem-write decision explicitly in the effective policy and carry
it through derivation, compilation, and planning. An inherited default denial must survive removing
the last write grant. Add semantic attenuation properties: for sampled operations, an accepted child's
allow decision must imply the parent's allow decision. Checking only whether `derive` returns `Ok`
cannot establish that property.

### S02 — High: grant application discards the normalized policy and loses executable pins

**Locations:** [grants/mod.rs:262](/home/jg/git/bee/src/grants/mod.rs:262),
[skills/grant.rs:161](/home/jg/git/bee/src/skills/grant.rs:161).
**Evidence:** reproduced by `probe_grant_discards_inherited_executable_pin`.
**Principle:** one authoritative state; validate the value that will actually be used.

`Policy::derive` returns the effective policy, including inherited restrictions. `try_apply` drops that
return value and recomputes from the original delta. With base `!/bin/true`, ceiling additionally
allowing `!/bin/sh`, and a request for `/bin/sh`, derivation succeeds by inheriting the pin. The installed
active policy instead contains unpinned `/bin/sh`. Startup skill grants also discard the derived
policy and retain the raw candidate. This defeats the guarantee that a pin cannot be weakened into a
path rule; exploitation of that weakening additionally requires replacing the allowed image.

**Fix:** make the derived effective policy the value that is stored and compiled, including on lease
recomputation. Normalize retained lease state or derive every recomputation against the ceiling.
Consider separate request/effective policy types so ignoring the normalized value is harder.

### S03 — High: finding-ledger writes follow repository-controlled symlinks on the host

**Locations:** [findings.rs:471](/home/jg/git/bee/src/findings.rs:471),
[findings.rs:515](/home/jg/git/bee/src/findings.rs:515).
**Evidence:** reproduced by `probe_ledger_follows_project_symlink`.
**Principle:** validate at the I/O boundary; minimize check/use gaps.

The harness appends to `.bee/findings/ledger.jsonl` outside the sandbox with a normal pathname open.
A repository can pre-place that name, or a parent directory, as a symlink. The probe appended a finding
event to a sentinel file outside the ledger directory. The destination is limited by the harness's
filesystem permissions, not the tool policy. `materialise` also writes through a predictable
`view.json.<pid>.tmp` pathname. Protecting `.bee` from tool children does not make its pre-existing
repository contents trustworthy.

**Fix:** establish a trusted ledger directory handle, resolve descendants without following symlinks,
require the expected file types, and create cache temporaries exclusively with unique names. Cover
both final-component and parent-directory symlinks. A separate canonicalize-then-open check is not a
complete fix because it leaves a race.

### S04 — High: subprocess output is bounded only after unbounded capture

**Locations:** [tools/exec.rs:62](/home/jg/git/bee/src/tools/exec.rs:62),
[tools/exec.rs:145](/home/jg/git/bee/src/tools/exec.rs:145).
**Evidence:** static control-flow verification; no memory-exhaustion attack was run.
**Principle:** put limits on buffers where they grow.

`run_child` calls `wait_with_output`, then allocates decoded strings and combines stderr, and only then
applies `cap`. A noisy command or a read of a very large file therefore allocates its complete output
in the harness despite the small tool-result limit. `run_child_timed` also captures both streams
without a byte limit. A wall-clock timeout is not a memory bound: a process can emit a large volume
well before it expires. Conversion and concatenation add further copies at peak memory use.

**Fix:** drain stdout and stderr concurrently in bounded chunks, retain only the permitted payload,
and explicitly choose whether excess bytes are discarded or terminate the command. Keep draining
discarded bytes if execution continues, so full pipes cannot deadlock the child. Give scanner output
an explicit parser-compatible bound and a distinct oversized-output error.

### S05 — High: timeout cancellation skips descendant cleanup

**Locations:** [tools/exec.rs:52](/home/jg/git/bee/src/tools/exec.rs:52),
[repl.rs:635](/home/jg/git/bee/src/repl.rs:635).
**Evidence:** reproduced by `probe_cancelled_child_leaves_descendant_alive`.
**Principle:** resource ownership must cover every exit, including cancellation.

The process-group kill occurs after `wait_with_output` returns. When an outer timeout drops the
future, that code never runs; `kill_on_drop` handles the direct child but not the group. The probe
cancelled a shell after 300 ms and observed its background descendant write a marker a second later.
The existing descendant test covers normal shell completion, which follows the successful cleanup
path. An outer cancellation can similarly bypass the explicit timeout arm in `run_child_timed`.

**Fix:** put process-group cleanup in an owned drop guard immediately after spawn and provide explicit
completion/reaping. Keep stdin pumping under the same lifetime. For enforced tools, use cgroup
ownership to cover descendants that escape process groups. The reproduction establishes a host-mode
cleanup failure; enforced descendants can remain scoped until teardown, so this alone is not proof of
a live-kernel sandbox escape.

### S06 — Medium: refusal and termination actions from hooks are silently ignored

**Locations:** [grants/escalate.rs:156](/home/jg/git/bee/src/grants/escalate.rs:156),
[hooks.rs:66](/home/jg/git/bee/src/hooks.rs:66).
**Evidence:** reproduced by `probe_deny_hook_does_not_prevent_execution`.
**Principle:** handle every outcome explicitly; make control flow express the contract.

`Flow` advertises `Deny`, `Terminate`, and `Deescalate`, but the proactive and reactive helpers match
only `Escalate`; every other action becomes `None`. A `BeforeToolCall` hook returning `Deny` therefore
allows the command to run. Both execution loops share this helper. The shipped escalation hooks mainly
return `Continue`/`Escalate`, so the immediate risk is to library consumers adding policy hooks.

**Fix:** return an explicit execution decision to the loop and exhaustively handle it before dispatch.
Implement the advertised outcomes, or reject/remove unsupported ones until implemented. Add an
integration assertion that a denied call produces no process side effect.

### S07 — Medium: finite grant leases never expire in either execution loop

**Locations:** [episode.rs:184](/home/jg/git/bee/src/episode.rs:184),
[repl.rs:493](/home/jg/git/bee/src/repl.rs:493),
[grants/mod.rs:278](/home/jg/git/bee/src/grants/mod.rs:278).
**Evidence:** reproduced by `probe_one_turn_grant_survives_next_turn`.
**Principle:** state transitions must be connected to their lifecycle owner.

`ActivePolicy::expire` exists and is unit-tested, but neither loop calls it or dispatches `TurnStart`.
A `Turns(1)` tool grant made on turn 0 remains usable on turn 1 and remains registered afterward. The
REPL also advances its grant turn counter per tool call, rather than per model turn. The CLI currently
selects `Forever`, and the spec records expiry integration as unfinished; the bug is the public API
accepting finite leases while silently treating them as permanent.

**Fix:** until implemented, refuse finite TTLs at session setup. Then perform one shared turn-start
transition that expires leases, narrows enforcement, and removes tools whose last grant disappeared.
Define failure behavior for a narrowing reload before allowing another tool to run.

### S08 — Medium: episode and MCP startup deadlines do not cover all awaited work

**Locations:** [episode.rs:111](/home/jg/git/bee/src/episode.rs:111),
[mcp/bridge.rs:260](/home/jg/git/bee/src/mcp/bridge.rs:260).
**Evidence:** episode reproduced by `probe_provider_outlives_episode_deadline`; MCP statically traced.
**Principle:** bound the operation, not only retries around it.

An episode checks its deadline between turns and before retry sleeps, but directly awaits
`model.complete`. A model that never returns outlives a one-second episode deadline; the probe's
separate watchdog was needed to stop it. MCP wraps initialization in a startup timeout, then performs
`list_all_tools` outside that timeout. A stalled tools-list response can therefore stall startup after
a successful handshake. Proactive consent also occurs after the episode's remaining time is sampled.

**Fix:** use an absolute deadline for the whole episode operation, including provider requests and
consent, and distinguish deadline expiry from provider failure. Apply an overall startup deadline to
MCP handshake plus discovery, with bounded pagination/tool counts. Recompute remaining time after any
awaited work. Explicit timeouts need cancellation-safe cleanup as in S05.

### S09 — Medium: audit fan-out moves bounded kernel data into unbounded host queues

**Locations:** [audit_demux.rs:52](/home/jg/git/bee/crates/userspace/src/audit_demux.rs:52),
[async_events.rs:71](/home/jg/git/bee/crates/userspace/src/async_events.rs:71).
**Evidence:** statically revalidated; already tracked as `VULN-FINDINGS-current.md` F-002.
**Principle:** bound queues and processing batches; make loss observable.

Each scope receives an unbounded channel, consumed mainly at tool-call boundaries. Repeated denied
operations can accumulate host allocations throughout a long call. The async ring drain also collects
until the ring is empty without a batch bound. Its dispatch task silently stops on stream errors,
while consumers do not receive an explicit loss-of-audit state. A fixed kernel ring size does not
bound these host buffers.

**Fix:** bound batches and per-scope queues, track overflow and stream failure, and mark audit evidence
incomplete rather than silently dropping it or growing memory indefinitely. Ensure a slow subscriber
cannot stall every other scope.

### S10 — Medium: chat history height overflows a terminal-coordinate integer

**Location:** [tui/view.rs:379](/home/jg/git/bee/src/tui/view.rs:379).
**Evidence:** reproduced by `probe_chat_height_overflows_u16` using an in-memory terminal backend.
**Principle:** distinguish logical counts from bounded display coordinates.

The renderer sums the entire conversation's rows into `u16`. A 65,536-line message panics in the debug
build; unchecked release addition wraps, and the subsequent saturating `u16` row cursor also cannot
address the remaining history. Smaller messages can cross the same threshold cumulatively. This is
an actual representation mismatch, not a preference for one integer naming convention.

**Fix:** keep document heights, offsets, and scroll positions in `usize` or another sufficiently wide
count type. Convert only visible, clipped positions to terminal `u16` coordinates. Separately choose
a history retention budget; saturating the total to 65,535 alone would still strand later messages.

## Performance

### P01 — Medium: importing findings repeatedly rebuilds the entire ledger view

**Locations:** [findings.rs:655](/home/jg/git/bee/src/findings.rs:655),
[tools/scanner.rs:410](/home/jg/git/bee/src/tools/scanner.rs:410).
**Evidence:** static cost analysis; no throughput benchmark claim.
**Principle:** batch work to amortize disk, parsing, and allocation costs.

Every `record` appends an event, reads and parses the complete ledger, folds it, serializes the entire
view, and replaces the cache. A scanner calls it once per finding, up to 200 times. With N existing
events and M new findings, it processes MN + M(M+1)/2 events during one import. At M=200 that is
200N + 20,100 events, versus N + 200 for one fold after the batch. These synchronous operations run
inside the async tool call and cannot be interrupted mid-operation by its Tokio timeout.

**Fix:** separate validated append from view refresh, append the scan's findings, and refresh once.
Stream ledger input instead of holding both raw JSON and all decoded events when folding. Move
expensive persistence work off the async executor. If multiple writers refresh concurrently, also use
unique cache temporaries and a defined publication policy; a PID-only temporary name is not unique
within one process.

## Developer experience and verification

### D01 — Medium: CI misses shipping feature combinations that already fail to compile tests

**Locations:** [ci.yml:52](/home/jg/git/bee/.github/workflows/ci.yml:52),
[concurrent.rs:270](/home/jg/git/bee/src/concurrent.rs:270),
[episode.rs:924](/home/jg/git/bee/src/episode.rs:924).
**Evidence:** compiler reproduced two E0063 errors.
**Principle:** verification must exercise the supported program, including optional boundaries.

`cargo check --features concurrent,mcp,sec,astgrep-rust --tests --locked --offline` fails because two
`Scenario` initializers omit `security`. CI tests default and MCP builds, while the enforcement job is
non-blocking and checks neither tests nor concurrency. The security-tool features are also absent from
the required matrix. This permits ordinary struct changes to break feature-specific test code without
affecting the default green result.

**Fix:** repair the initializers and add a small required feature matrix: default, headless,
MCP+security+one grammar, and compile-checks of enforcement/concurrency tests on the toolchain-equipped
runner. A kernel is needed to execute BPF integration tests, not to compile their Rust callers. Keep
actual VM execution a separate gate.

The first default test run also failed five animation assertions with ambient `NO_COLOR=1`; all default
tests passed after unsetting it. Inject color settings into those tests rather than depending on the
developer's shell environment.

### D02 — Medium: the VM result parser can label an incomplete or failing summary as success

**Location:** [test/vm/matrix.sh:49](/home/jg/git/bee/test/vm/matrix.sh:49).
**Evidence:** reproduced against the actual parser, without contacting the VM.
**Principle:** handle errors and verify completeness before reporting success.

The orchestrator discards the guest exit status with `|| true`, counts only individual non-PASS result
lines, and prints the summary without validating it. Feeding it `SUMMARY|pass=0|fail=1` produces exit 0
and `ALL CASES PASSED`. A one-case PASS plus a matching one-case summary also passes regardless of the
expected suite. Completely empty output does fail because the summary grep runs under `pipefail`;
the defect is the missing consistency/completeness checks, not acceptance of every transport failure.

**Fix:** retain the remote exit status, require one valid summary, cross-check its totals against
unique result records and the expected case set, and fail on malformed or missing results. Exercise
the parser independently with failed, truncated, duplicate, and empty output fixtures.

## Maintainability priorities

1. **Make effective policies explicit.** A request, a derived effective policy, and an installable plan
   are different states. Keep that distinction visible in APIs and consume normalized return values.
2. **Give resource lifetimes one owner.** A subprocess operation should own its child, descendants,
   pipes, cancellation cleanup, byte budgets, and deadline. This addresses several defects together.
3. **Share security transitions between loops.** Keep streaming REPL and headless presentation
   separate, but make hook decisions and lease transitions use the same exhaustive execution path.
   Splitting long functions merely to satisfy a line count would not establish this invariant.
4. **Keep comments about the current contract.** The code often documents intent thoroughly, but
   statements about bounded output, lease expiry, or complete deadlines currently outrun behavior.
   Move historical spec narration out of frequently read implementation paths and keep the invariants
   and reasons that help a maintainer make the next change.

Useful foundations to retain: the injected policy resolver, pure enforcement planning, fail-closed
unsupported-rule checks, credential allowlisting, terminal-text sanitization, worker execution inside
the scope, and the current transactional reload abstraction with fault-injection tests.

The existing uncommitted reload fix addresses the old F-001 partial-update concern; I did not count
that stale report as a new defect. Scope creation rollback and engine-owned map reclamation remain
worth following up from the earlier lifecycle findings: `Scope::teardown` removes the cgroup but does
not remove its entries from the shared engine's maps. I did not reproduce kernel exhaustion or cgroup
ID reuse in this audit. MCP's dynamically leaked tool-name strings are another lower-priority cleanup:
change the tool-name API to borrowed strings and store owned registry keys before adding more dynamic
tool sources.

## Validation

- Initial `cargo test --workspace --locked --offline`: 405 library tests passed, five animation tests
  failed under `NO_COLOR=1`; the run stopped before integration suites.
- `env -u NO_COLOR cargo test --workspace --locked --offline`: **674 existing tests passed**, plus
  seven audit probes compiled in that configuration. Some environment-gated live tests self-skip
  internally; a passing host suite is not evidence of live-provider or BPF enforcement coverage.
- `env -u NO_COLOR cargo test --workspace --features findings --locked --offline --test
  _tigerstyle_audit_probe -- --nocapture`: **eight defect probes reproduced their expected observations**.
  These intentionally assert current defects; invert their assertions before installing them as
  regression tests.
- Feature compile-check: failed on the two missing `security` fields described in D01. The BPF build
  completed sufficiently for the compiler to reach these feature-specific Rust test errors.
- `env -u NO_COLOR cargo test --features mcp,sec,astgrep-rust --locked --offline`:
  **728 existing application tests passed**, plus seven application audit probes; four MCP tests were
  explicitly ignored because they require an external server. This command selects the application
  package rather than `--workspace`, so its count is not directly comparable to the default run.
- VM result-parser probes used only synthetic captured output. No VM deployment or kernel mutation
  was performed.

Suggested implementation order: S01–S03, then S04–S05; repair D01 alongside those fixes so broader
tests can enforce them. Address hook/lease/deadline contracts next, then audit queues, chat counts,
batched persistence, and result-parser completeness.
