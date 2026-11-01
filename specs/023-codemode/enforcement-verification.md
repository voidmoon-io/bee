# Codemode enforcement verification

Verified on 2026-10-31 against KubeVirt VM `ac-matrix/ac-matrix-vm`, Ubuntu kernel
`6.8.0-147-generic`. Active LSMs: `lockdown,capability,landlock,yama,apparmor,bpf`.
The VM gate ran as root against the real kernel, with the shipping Bee worker and
test harness built using `durable-sessions,enforce` and the locked dependency graph.

## Results

All twelve mandatory tests executed and passed. No case was skipped. The guest exited
successfully; the host independently validated the complete manifest and summary.

| Case | Result |
| --- | --- |
| `kernel_codemode_file_policy` | PASS |
| `kernel_codemode_worker_exec_denied` | PASS |
| `kernel_codemode_inner_exec_denied` | PASS |
| `kernel_codemode_worker_timeout` | PASS |
| `kernel_codemode_cancel_child` | PASS |
| `kernel_codemode_memory_cleanup` | PASS |
| `kernel_codemode_committed_recovery` | PASS |
| `kernel_codemode_parent_death` | PASS |
| `kernel_codemode_unknown_child` | PASS |
| `kernel_codemode_write_policy` | PASS |
| `kernel_codemode_write_recovery` | PASS |
| `kernel_codemode_cancel_write` | PASS |

The file-policy case verifies a permitted read/list, a kernel-denied secret read,
receipt preservation, and correctly associated audits. Executable-denial cases
separately deny the Python worker and its inner `cat` tool. The worker denial audit
also survives reopening the durable session.

Cleanup cases observe the worker inside its enforced cgroup before timeout, require
an actual memory-limit error, and cancel a blocked inner read while a sibling scope
stays alive. Each requires empty scopes and removal of invocation cgroups.

Recovery cases kill the actual driver process. A changed file proves that the first
committed read is retained and only the next read executes after reopen. A stopped
Python worker dies when its parent dies; restarting retains the lost invocation's
charge. An unfinished native read is stopped before reconciliation and remains
unresolved and charged, without dispatching the next call.

## Fixes validated

Python-worker audit events now settle into the durable outer operation and its
transcript record; previously a denied worker launch returned an error with no
associated audit. The cursor retains these events across suspension and recovery,
including cancellation reporting.

The Python worker's Linux parent-death guard is installed before `exec`, then
checked again at worker entry. This closes the startup window before the interpreter
initializes. Ordinary tool executors retain their existing recovery behavior.

## Reproduce

Start the existing enforcement VM, then run from the repository root:

```bash
bash test/vm/codemode.sh
```

The runner prints binary checksums, checks every case exists and executes exactly
one test, applies a per-case watchdog, validates guest status and result completeness,
and removes its unique guest staging directory. It does not manage VM lifecycle.
No staging directories or codemode cgroups remained after this run. The VM was
started for these tests and returned to its original stopped state afterward.

Tested stripped binaries (SHA-256):

- `bee`: `ff54dc3cf9e4ba9c01d7b6241ed0ffa1f4c1d3ad68107c6cc13f71c9c4d99954`
- `codemode_kernel`: `ee46a4b7c58d9047c0ce5eaf3b128d799524b43b20f8974ffeff8038c08bdea5`

Host verification also passed: 247 library tests, eleven durable-codemode tests, six
Python-worker tests, 16 existing durable-driver tests and one render-exchange test.
Two existing host tests remained ignored. Four VM parser/manifest tests passed;
formatting, shell syntax, diff whitespace and Clippy checks passed.

## Limits of this result

This is the dedicated codemode gate, not a rerun of the separate 38-case general
matrix. The production Python allowlist includes `write_file` with `NeverReplay`. Engine-owned BPF links
have the driver's process lifetime: these tests prove cleanup and conservative
recovery, not continuous enforcement of arbitrary native descendants while the
owner is dead. Host-mode execution remains unenforced.

## Checkpoint regression run

Reran the full dedicated nine-case VM gate after checkpoint `fd2fd91` and
deadline-admission fix `7905409`; all cases passed. The host regression run
found a deadline expiring before script admission: cancellation indexed a script
that had never been committed. The fix clears that unadmitted cursor so ordinary
outer-operation cancellation can complete. All 279 host tests then passed, with
two existing tests ignored; Clippy, formatting, four VM parser tests and shell
syntax checks passed. Binary hashes above have since been updated for the write validation run. Logs:
`/tmp/bee-checkpoint-tests.log`, `/tmp/bee-checkpoint-vm.log` and
`/tmp/bee-checkpoint-clippy.log`. Mutation validation was completed in the subsequent run below.

## Write mutation validation

The first twelve-case gate exercised the shipping writer through a trusted test
alias before production exposure. All cases passed. The catalog was then extended
to `write_file` and the same gate rerun using the actual tool name: all twelve
cases passed again, with no skips. The guest staging directory was removed and
the VM returned to its original stopped state. Host fixtures
cover suspension, authorization, completed effects without a result, receipt
publication, child completion and outer completion. Destinations changed between
crash and recovery remain changed, proving writes are not repeated. Unknown writes
retain their charges and prevent the next call. The VM verifies denied-path audits,
receipts surviving a Python error, SIGKILL recovery and cancellation of a blocked
`tee` while a sibling scope survives. `NeverReplay` is unchanged.

Host results: 281 tests passed across the selected suites, two existing tests
ignored. One initial run hit `Store(Locked)` in the existing immediate-reopen
error/budget test; the integration rerun passed without code changes. This
intermittent failure remains unexplained. Clippy (including both codemode test
harnesses), formatting, diff whitespace, shell syntax and all four manifest/parser
tests passed. Raw logs are `/tmp/bee-write-final-host.log`,
`/tmp/bee-write-final-retry.log`, `/tmp/bee-write-final-clippy.log` and
`/tmp/bee-write-final-vm.log`.

## Follow-up: inherited writer descriptor (2026-10-31)

A deterministic store regression forks while the writer is open and holds the
child before exec with a pipe. The child uses only async-signal-safe syscalls,
never accesses SQLite, and exits without Rust destructors. After dropping the
store, immediate reopen failed with `StoreError::Locked` before the change.
The child is released and reaped before asserting the result, including failure.
This proves inherited open-description ownership can reproduce the symptom;
it does not establish which process caused the original intermittent failure.

`Directory::drop` now explicitly releases flock. Store field order closes SQLite
first, so commits and SQLite shutdown finish under exclusion. A live competing
writer is still refused, including after reopen. No retries, delays, weaker
acquisition, or global test serialization were added. Broader startup cancellation,
owner panic, and instrumented session-level stress coverage remain pending.

Validation:

- `cargo test --offline --no-default-features --features durable-sessions --lib
  --test durable_codemode --test durable_driver --test python_worker
  --test render_exchange`: 248 library, 11 codemode, 16 driver, six Python worker,
  and one render exchange tests passed; two pre-existing ignores.
- `cargo clippy --offline --features durable-sessions,enforce --lib --bin bee
  --test codemode_kernel -- -D warnings`: passed.
- `cargo fmt --all -- --check` and `git diff --check`: passed.
- `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/vm -p
  'test_*.py'`: four passed.
- `bash -n test/vm/codemode.sh test/vm/remote-codemode.sh`: passed.

Host logs: `/tmp/bee-followup-host.log`, `/tmp/bee-followup-clippy.log`.
Grouped presentation and checkpoint reclamation have not been implemented.
- Five additional default-parallel `durable_codemode` suite runs passed (55 test
  executions), covering success, Python errors, budget exhaustion, cancellation,
  unresolved effects and lost acknowledgements. These stress runs support the
  change but do not identify the owner in the historical intermittent failure.
  Log: `/tmp/bee-followup-stress.log`.
- `bash test/vm/codemode.sh`: all 12 BPF-LSM cases passed; guest artifacts
  removed by the gate. VM initially `Stopped`, started with `virtctl start`,
  and stopped afterward with `virtctl stop`. Log: `/tmp/bee-followup-vm.log`.
  Tested stripped binary SHA-256:
  - bee: `bef8994821136ed08f4c2860350451c373a115a0466a35db53fdf20deecbe0a0`
  - codemode_kernel: `593e9e429dcf2595a9274d8d589d875137c8f5677bacef58f453a8d70e8e7582`

## Follow-up implementation: lifecycle, presentation, retention (2026-10-31)

Storage startup now installs its ownership guard before awaiting readiness, so
cancellation and owner failure cannot detach the storage thread. Tests cover a
barrier-held startup cancellation, startup-owner panic, and a retained
`Arc<Session>` refusing reopen until its final owner drops. Existing lost-ack,
worker cancellation and process-crash suites cover active work. The inherited
flock lifecycle is deterministically demonstrated; the original intermittent
failure's specific process was not captured, so historical attribution remains
unproven.

Presentation uses typed submission/turn/call identities and optional parent
identity on start, completion and unresolved events. Compatibility callbacks keep
ordinary tools working. Live and replay use the same result projection, with
explicit replay labels for append-only sinks. TUI rows upsert by identity and
create a parent placeholder for early children. Python source, arguments, results,
full audit details and receipts remain in the scrolling view. Cancelled admitted
children without a committed result remain explicitly unresolved; calls stopped
before dispatch do not invent child results. The flat transcript retains parent
bindings, while model messages still receive only the outer codemode result.

Error reporting now reconstructs partial reports from the last acknowledged
checkpoint, validates the journal and compares recorded result/audit data with
committed receipt delivery. Batch and REPL errors preserve those validated prior
observations. An unacknowledged commit is deliberately absent until reopen; no
in-memory proposal is promoted to evidence.

The v7 snapshot/store contract retains the latest continuation of each active
script. Historical references remain validated metadata. Store migration checks
all v6 historical blobs under the old contract before atomically upgrading;
corruption rolls back the version, snapshot and activation changes. The v5 path
remains supported. Older readers reject the v7 version.

Reclamation runs on the serialized writer within the snapshot transaction and
on validated activation, and before checkpoint quota checks. Pending staging is
protected until a new suspension adopts it, explicit abandonment, or recovery
under a new owner. Restaging an already-live digest survives unrelated commits.
Shared live digests remain protected. Terminal state needs no interpreter bytes;
results, operations, receipts, audits and suspension metadata remain. SQLite
pages are reused; physical compaction and other session-cap changes are excluded.

Retention tests cover real process kills before/after blob insertion, suspension
and completion, and inside the transaction after deletion. They also cover lost
acknowledgements, shared digests, staging, rollback on deletion failure, corrupt
live blobs, v6 migration rollback, and 20 stopped programs writing 80 MiB through
the 64 MiB quota while retaining their history. The existing hard-live/staging
quota test still refuses overflow.

Completed implementation commits:

- `e95b57f`: join storage ownership during cancelled startup.
- `a767d42`: grouped live/replay projection, TUI/terminal integration, validated partial evidence.
- `6c8ba86`: v7 retention, migration and transactional reclamation.

Final host verification:

- `cargo test --offline --no-default-features --features durable-sessions --lib
  --test durable_codemode --test durable_driver --test python_worker
  --test render_exchange`: 258 library, 13 codemode, 17 driver, six Python and one
  render test passed; two existing ignored fixtures. Log:
  `/tmp/bee-followup-verified-host.log`.
- `cargo test --offline --features durable-sessions --lib --test durable_sessions`:
  431 library tests (including TUI), 20 durable-core integration tests passed;
  one existing ignored fixture. Log: `/tmp/bee-followup-verified-ui.log`.
- The subsequently added terminal rendering test
  `cargo test --offline --features durable-sessions --lib grouped_denial` passed,
  proving replay indentation, receipt and full denial details survive long output
  without terminal escape leakage. Log: `/tmp/bee-followup-denial.log`.
- `cargo clippy --offline --features durable-sessions,enforce --lib --bin bee
  --test codemode_kernel --test durable_codemode -- -D warnings`: passed.
  Log: `/tmp/bee-followup-verified-clippy.log`.
- `cargo fmt --all -- --check`, `git diff --check`, the four VM parser tests and
  `bash -n test/vm/codemode.sh test/vm/remote-codemode.sh`: passed.

An intermediate host regression detected an undispatched budget-blocked child
being included as an unresolved cancellation record. The implementation now
requires an admitted attempt; the final host run above passed. No host test
failures remain. The preliminary 12-case BPF-LSM gate also passed, but was rerun
because presentation code changed during that run. New storage crash/retention
cases run on the host; no new kernel-dependent case was added to the manifest.

Final kernel gate: `bash test/vm/codemode.sh` passed all 12 cases against the
completed implementation. Log: `/tmp/bee-followup-verified-vm.log`.
Tested stripped binary SHA-256:

- bee: `116374139c28b8cfc098ee1ef5b774b95ac08de998369030e92680d854dedf47`
- codemode_kernel: `45f91aaa4863c3d8aba5a3fd98ef26bc474f17de0ded5b7acd0fbba800f5ebbd`

The VM initially reported `Stopped`. It was started for verification; the gate
removed guest staging artifacts. `virtctl stop ac-matrix-vm -n ac-matrix` and
`kubectl wait --for=delete vmi/ac-matrix-vm -n ac-matrix --timeout=45s` restore its
initial lifecycle state. No push, PR or deployment was performed. Unrelated
scratch directories and vulnerability reports remain untouched.

## Batch, nesting and shell validation

Rerun on 2026-10-31 (kernel `6.8.0-147-generic`) after adding `call_tools`, nested
codemode and the broadened catalog. The gate now has 17 cases; all passed with no
skips. New cases:

| Case | Verifies |
| --- | --- |
| `kernel_codemode_shell_policy` | `bash` allowed read + write; denied secret read audited on that call only; reopen does not repeat the shell effect |
| `kernel_codemode_batch_attribution` | three-call batch; only the denied member carries the `file_open` denial; ordered results |
| `kernel_codemode_nested_effects` | nested write and denied read keep ancestry, audits and receipts; parent reads the nested write |
| `kernel_codemode_nested_cancel` | cancelling a blocked read inside a nested batch stops every level, admits nothing further, empties the scope and reopens |
| `kernel_codemode_batch_kill_recovery` | SIGKILL after the first batch member commits: it is not repeated, only the unstarted member runs after reopen |

Enforced batches execute one member at a time (see implementation notes). The
`nested_cancel` case therefore expects a single attempted leaf.

The shell case exposed a policy-authoring pitfall: unpinned exec rules match the
executed file's path, so allowing `sh` does not permit `/usr/bin/sh` → `dash`. The
fixture allows the canonical path. The resolver was not changed.

Tested stripped binaries (SHA-256):

- `bee`: `c53c0eff4252565bce94cec02797c5e2f53bfc859299a140dcac1d71dfbdc3a8`
- `codemode_kernel`: `56ec5793c3171112fd30c7862806d4d53893473a7f760bc3b8afb818f51570a2`

No guest staging directories or codemode cgroups remained, and the VM was returned to
its original stopped state. Log: `/tmp/bee-parallel-vm.log`.

## Port onto main

After porting onto `main` (snapshot/store v7, journal v3, main's call lifecycle), the
17-case codemode gate passed again on `6.8.0-147-generic`, and main's four-case durable
executor-recovery gate (`test/vm/durable.sh`) passed. No staging directories or codemode
cgroups remained; the VM was returned to Stopped.

- `bee`: `6c5083e2adcc4591657ec2aa6957538df44f7bac3442c94cdd6d785b3b360e3e`
- `codemode_kernel`: `90f574e224bef7f19aabc009a3e4dcc91fe4062351b2a88b6b914e807c9af586`

Host: 905 tests (`--workspace`), 968 (`mcp,sec,astgrep-rust`), 923 (`durable-sessions`),
723 (`--no-default-features --features durable-sessions`), 582 (`--no-default-features`),
81 `test-support` and 135 `intercept,test-support` tests passed with no failures;
`test/durable-investigation.sh` and the VM parser tests passed. Clippy `-D warnings`
passed for every CI feature set and `durable-sessions,enforce`.


## Issues 02 and 04: enforced overlap and presentation depth

Verified 2026-10-31 with snapshot/store v7 and driver journal v4. Batches now
execute up to four ordinary leaves concurrently under kernel enforcement, with
separate executor identities and audit attribution. Journal-aware tools and nested
scripts still execute sequentially. Live and replayed terminal/TUI presentation
carry explicit depth.

- `cargo test --offline --locked --features durable-sessions --lib --tests`:
  **932 passed**, zero failures. Log: `/tmp/bee-host-verified.log`.
- `cargo test --offline --locked -p bee-core`: **62 passed**.
- `cargo test --offline --locked -p bee-userspace --features tokio audit_demux`:
  **3 passed**.
- Clippy with `durable-sessions,enforce,concurrent`, `--lib --tests -- -D warnings`:
  passed. Headless durable-session check and formatting also passed.
- VM gate `bash test/vm/codemode.sh`: **20/20 passed**, no skipped gate cases,
  kernel `6.8.0-147-generic`. Log: `/tmp/bee-vm-verified.log`.

The three added cases are `kernel_codemode_overlap_barrier`,
`kernel_codemode_overlap_cancel` and `kernel_codemode_overlap_deadline`.
The barrier forces overlapping tools and reverses completion order; the denied
second call alone receives its audit. The stop cases require four live subprocesses
in four slots and preserve a separate session's process. The updated SIGKILL case
preserves the durable first result, proves a blocked sibling survives until recovery,
then verifies every old slot is removed and the ambiguous sibling is not repeated.
Nested cancellation now expects both batch leaves to have been attempted.

During verification the old fixture waited for receipt publication (`Completed`)
while a sibling blocked. It now pauses after the durable result/receipt intent
(`Publishing`). An old pre-recovery emptiness assertion was also replaced: the new
case deliberately requires a surviving process for recovery to stop. An initial
host retry-deadline test failed under parallel load; it passed in isolation and in
the final full run. No verification failures remain.

Tested stripped binary SHA-256:

- `bee`: `593fd52327d2d04a4251563ac33f35eeab347dc2c70b0320f3cf074f334351e5`
- `codemode_kernel`: `07255c739462a9e14b2e45499f5483825c0365ef917fcb7f1076652438801792`

The gate removed its guest staging files; the temporary debugging binaries were
removed separately. This verification preceded PR preparation; the PR isolates issues 02 and 04 from unrelated workspace changes.

The VM was returned to its original `Stopped` state and verified with kubectl.


### Isolated PR verification

The PR branch starts from `origin/main` at `f809140` and excludes the unrelated
provider/retry and decision-model work. On this isolated checkout, the full
`--features durable-sessions --lib --tests` run passed **925 tests**. Enforcement
and concurrency Clippy (`-D warnings`), formatting and all four VM result-parser
tests passed. Logs: `/tmp/bee-023-pr-tests.log` and `/tmp/bee-023-pr-clippy.log`.
The 932-test and 20-case kernel results above were obtained before this isolation;
the kernel gate was not rerun during PR preparation. No runtime changes were made
during isolation, apart from excluding the unrelated decision-provider key list.
