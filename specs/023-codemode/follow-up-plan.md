# Codemode follow-up plan

Status: implemented and verified. Lifecycle ownership, grouped live/replay
presentation with validated partial reports, and v7 checkpoint retention are
committed. See `enforcement-verification.md` for tests, kernel-gate hashes and
compatibility details. The inherited-lock mechanism is reproduced deterministically;
the original intermittent failure's specific process remains unproven.
Baseline: `40b6326` (validated durable `write_file`).

## Scope and order

1. Diagnose and fix intermittent immediate-reopen `Store(Locked)`.
2. Group inner calls beneath the outer codemode invocation in live and replayed output.
3. Reclaim obsolete checkpoint blobs without weakening crash recovery.

Each item is an independently reviewable change with its own tests. Keep the
current trusted tool catalog and `NeverReplay` behavior. Parallel execution,
nesting, captured print output and additional tools remain deferred. Preserve
unrelated scratch notes and vulnerability reports.

## 1. Immediate-reopen lock failure

### Observed problem

One parallel host test run failed in
`forbidden_calls_errors_and_session_budget_keep_prior_results` when reopening a
session after dropping it. The integration suite passed unchanged on rerun.
`Storage::drop` closes its request sender and joins the storage owner thread;
therefore an unjoined owner is not an established explanation. The writer lock is
an exclusive, nonblocking `flock` on the session-directory descriptor. Opens use
`O_CLOEXEC`, which does not by itself rule out inheritance during fork-before-exec.

### Investigation and implementation

- Build a bounded reproducer around run, drop and immediate reopen, both alone
  and while other sessions launch Python/native children. Include success, Python
  error, budget exhaustion and lost-acknowledgement paths.
- Capture failing directory device/inode, open/close timing, owner-thread exit,
  outstanding session ownership, and relevant process/file-descriptor ownership.
  Keep diagnostics local to the failing fixture or opt-in tracing.
- Test competing explanations: retained `Arc<Session>`, incomplete startup or
  shutdown, and descriptors inherited by a child before exec. Do not select a fix
  based solely on timing or on a passing rerun.
- Once the owner of the lock is identified, introduce synchronization/barriers
  that deterministically reproduce that lifecycle and fix the ownership boundary.
  Evaluate explicit lock release or a close protocol only if the evidence supports
  it; account for active commits and real competing owners.
- Retain fail-closed single-writer exclusion. Do not add arbitrary sleeps, retries,
  weakened lock acquisition or broad test serialization as the fix.

Primary files: `src/session/driver/storage.rs`, `src/session/driver/mod.rs`,
`src/session/durable/store/files.rs`, subprocess ownership in `src/tools/exec.rs`,
and the relevant durable-driver/store integration tests.

### Acceptance

A deterministic regression fails before the fix and passes afterward. Immediate
reopen succeeds once the final owner closes. A genuinely live second owner is
still refused. Cancellation, startup failure, owner panic and commit-acknowledgement
loss cannot admit concurrent writers or discard durable work. Run the bounded
reproducer under concurrent worker activity and the existing lock/recovery suites.
If reproduction remains elusive, record evidence and the remaining hypothesis;
do not describe the issue as fixed.

## 2. Grouped inner-call presentation

### Desired behavior

Show one codemode group with its Python source and outer status. Under it, show
children in execution order with tool name, arguments, running/final status,
result, denial/audit details and receipt identity. Preserve earlier successful
writes when a later call fails or the script is cancelled. An unresolved effect
must remain explicitly unresolved; it must not look like an ordinary tool error
or a successful completion.

Plain terminal and batch progress output use indentation and concise group labels.
The TUI uses a parent row with child rows and existing detail affordances. Avoid
adding a new interaction system merely to support grouping. Receipt and denial
information must remain discoverable when output is shortened.

### Implementation

- Introduce typed presentation context carrying invocation identity and optional
  parent identity. Scope identity by submission/turn where provider call IDs may
  repeat. Keep it separate from model messages and recovery authority.
- Extend the output interface so both call-start and call-result events carry
  this identity. Use compatibility defaults for ordinary/non-durable output.
- Route live driver events and replay through the same grouping logic. Replace
  the current informational parent labels with structured context.
- Derive groups from `RecordedCall.parent_call_id` plus active cursor/operation
  state. Children can be recorded before the outer completion: create a parent
  placeholder when needed rather than dropping or misplacing them.
- Preserve parent/child records in the flat durable transcript. Treat grouping as
  a presentation projection; only the outer result enters model conversation.
- Ensure the active progress view can retain committed children on unresolved
  recovery errors. Review error paths that currently return empty `turns`/`audit`;
  decide whether to expose a validated partial report rather than lose evidence.
- Use stable identities to update existing rows on replay/reconnect. Plain
  append-only output should identify replay explicitly, without promising
  exactly-once external display.

Primary files: `src/repl.rs`, `src/repl/terminal.rs`, `src/tui/`,
`src/session/driver/presentation.rs`, `execution.rs`, `codemode.rs`, and
`src/transcript.rs`.

### Acceptance

Test a write followed by a read; a write followed by Python error; denial;
cancellation; unresolved mutation; and reopen after child completion. Live and
replayed views associate the same children, audits and receipts with the same
parent. Repeated call IDs in separate turns do not merge groups. Direct tool
presentation remains intact. Model conversation still contains only the outer
codemode result. Use focused event/projection tests and terminal/TUI rendering
checks rather than large snapshots of unrelated output.

## 3. Checkpoint retention and garbage collection

### Current constraint

The private SQLite checkpoint table deduplicates blobs by digest and enforces
4 MiB per blob, 64 MiB total and 1,024 blobs. Every suspension retains its reference,
and store load/commit validation currently requires every referenced blob to exist.
Deleting old blobs alone would make valid sessions appear corrupt.

### Retention contract

Separate historical suspension metadata from blobs required to resume:

- Retain the latest continuation of every active script, including one waiting
  for a child or blocked on an unresolved effect.
- Keep the previous continuation until the next suspension or final script state
  is durably committed. A saved worker result or an unacknowledged proposal is not
  enough to release it.
- Completed/stopped scripts retain identity, binding metadata, child operations,
  results, budgets, audits and receipts; their interpreter blobs may be reclaimed
  once the durable state no longer permits resumption.
- Preserve any blob shared with another live continuation.
- Protect blobs staged by the current storage owner before their references are
  committed. After activation changes, abandoned staging is reclaimable only once
  authoritative recovery state is loaded; stale owners cannot publish references.

### Implementation

- Define one authoritative function for the set of required checkpoint references.
  Use it for load/commit validation and reclamation; validate historical metadata
  independently. Review terminal-state delivery/recovery before classifying any
  blob as unnecessary.
- Version the changed storage/validation contract. Migrate the known v6 snapshot
  and database atomically, preserving evidence. Do not silently reinterpret old
  stores or allow older readers to treat reclaimed history as corruption.
- Add bounded reclamation on the serialized storage owner at safe points: after
  activation/recovery, and after durable transitions release continuations. Track
  staged references explicitly so GC cannot delete a just-written blob before
  admission. Release staging protection when adopted or explicitly abandoned.
- Make snapshot update and release of now-unneeded blobs transactional where
  possible. If cleanup is deferred, failure may leak bytes but must never delete a
  live continuation. Avoid a concurrent background collector in the first slice.
- Reclaim eligible blobs before rejecting an insertion for aggregate limits.
  Keep hard limits when the live set itself is too large. Missing or corrupt live
  blobs must still fail closed.
- Distinguish logical quota recovery from SQLite file shrinkage. Reuse freed pages;
  do not run blocking full VACUUM on each call. Keep physical compaction out of this
  slice unless measurements show it is necessary.

Primary files: `src/session/durable/composition.rs`, `store/checkpoints.rs`,
`store/mod.rs`, `src/session/driver/storage.rs`, and store/composition tests.

### Acceptance

Inject crashes before/after blob insertion, suspension commit, completion commit
and reclamation, including lost acknowledgements. Prove the last required
continuation survives and obsolete/orphan blobs are eventually reclaimed. Cover
shared digests, pending staging, stale activation, terminal delivery, active
unresolved writes, quota pressure, corrupt live blobs and migration rollback.
Repeated completed programs must reuse checkpoint capacity without losing receipts
or repeating effects. Other existing session caps (scripts, operations, journal
history) remain explicit limits; checkpoint GC does not promise unlimited sessions.

## Delivery and verification

Suggested reviewable units:

1. Lock reproducer and evidence, then the targeted lifecycle fix.
2. Presentation identity/events and common projection.
3. Terminal/TUI integration plus replay and partial-result coverage.
4. Retention model, version migration and invariants.
5. Transactional reclamation, staging protection and crash/quota tests.

For each unit, run focused tests first, then affected Rust formatting/Clippy and
integration checks. At the end run the handoff host regression command and the
12-case codemode BPF-LSM gate; extend the manifest for new kernel-dependent cases.
Re-run the kernel gate earlier if the lock fix touches subprocess descriptors or
executor lifecycle. Validate the four VM parser tests and shell syntax. Restore
the VM's initial lifecycle state and record commands, results, hashes and any
remaining failures in `enforcement-verification.md`. Commit each completed unit;
no push, PR or deployment is implied by this plan.
