# Implement the practical TigerStyle audit

Status: ready-for-agent

Created: 2026-10-22
Implementation: complete. See [implementation and validation evidence](../IMPLEMENTATION.md).
Baseline: `ebf2d29`, including the existing uncommitted transactional reload work.
Source: [audit and evidence](../../tigerstyle-audit/AUDIT.md),
[reproduction instructions](../../tigerstyle-audit/REPRODUCE.md).

## Problem Statement

The audit found 13 concrete problems affecting policy enforcement, subprocess lifetimes, finding
storage, resource consumption, execution-loop behavior, and verification. Several APIs describe
stronger guarantees than their callers actually enforce. Broad formatting changes would not fix
those contracts.

The highest-priority outcomes are that derived policies cannot gain authority, repository contents
cannot redirect host ledger writes, and a canceled or noisy child cannot leave uncontrolled work or
unbounded buffers behind. Subsequent work makes hook decisions, lease expiry, deadlines, and audit
health consistent between headless execution and the REPL.

## Solution

Deliver the changes in seven batches. Each numbered commit below includes its regression tests and
must leave its supported feature combinations working. The numbers express implementation order,
not a requirement to accumulate one large PR.

| Batch | Commits | Outcome | Findings |
| --- | --- | --- | --- |
| 1. Trust the checks | 1–3 | Feature coverage and reliable VM pass/fail reporting | D01, D02 |
| 2. Preserve authority and storage boundaries | 4–6 | Effective policies survive derivation and grants; ledger I/O rejects symlinks | S01, S02, S03 |
| 3. Own subprocess lifetimes and output | 7–9 | Cancellation cleans up children; capture memory is bounded | S04, S05 |
| 4. Share execution decisions | 10–12 | Hooks are exhaustive; grants expire before further execution | S06, S07 |
| 5. Apply complete deadlines | 13–14 | Provider work, consent, and MCP discovery cannot exceed their operation budget | S08 |
| 6. Bound audit processing and fix rendering counts | 15–17 | Slow consumers cannot grow queues forever; long chats remain navigable | S09, S10 |
| 7. Batch persistence and close validation | 18–19 | One view refresh per scan; enforcement changes have kernel evidence | P01, cross-cutting |

Batches 2 and 3 are the first security deliverables. Keep batch 1 small: repair the observed checks,
without turning it into a CI platform overhaul. Run relevant kernel tests as each enforcement change
lands; commit 19 consolidates the final scenarios rather than postponing all kernel validation.

## Commits

### 1. Repair the feature-test baseline

- Add the missing security configuration to the two feature-specific scenario fixtures.
- Make animation tests supply color settings directly, avoiding dependence on ambient `NO_COLOR`
  and avoiding process-global environment mutation in parallel tests.
- Verify default tests both with and without `NO_COLOR`, and compile the combined concurrency,
  MCP, security, and Rust-grammar test configuration.
- Keep this separate from behavior changes so later failures have a useful baseline. Covers D01.

### 2. Make the supported feature matrix required

- Require tests for the default workspace, the headless application, and MCP plus security tools
  plus the Rust grammar. Run the applicable existing lint checks over these boundaries.
- On the BPF-toolchain runner, require compile-checks of tests for enforcement and the combined
  concurrency/MCP/security/grammar build. Remove best-effort treatment of those source checks.
- Keep live BPF execution separate from compilation. Use a verified compatible toolchain/linker
  combination; a missing toolchain is a failed check, not a successful skipped compile. Covers D01.

### 3. Validate complete VM results before reporting success

- Separate captured-result parsing from VM transport so the parser can run against local fixtures.
- Preserve the guest/transport exit status. Require exactly one valid summary, unique result names,
  the expected case set for the selected suite, and summary counts consistent with the records.
- Share the suite's expected case manifest between execution and validation; do not maintain a
  second handwritten count. Required cases that are skipped do not satisfy the gate.
- Test valid output, nonzero exit, summary-only failure, partial success, duplicate/missing cases,
  malformed counts, duplicate summaries, and empty output. Covers D02.

### 4. Carry the effective filesystem default through attenuation

- Distinguish authored policy input from effective policy state at the derivation/compiler boundary.
  Represent the unmatched-write decision explicitly in effective state. Keep this change inside
  the current core/compiler/planner boundaries rather than introducing another crate.
- Derive the root decision using existing operator-policy semantics. An accepted child must retain
  an inherited denial even when its last explicit write rule becomes read-only or disappears.
- Carry the decision through compilation into enforcement flags. Migrate affected callers together;
  do not reconstruct effective state by serializing it back into authoring TOML.
- Invert the audit probe. Add repeated-derivation cases and semantic properties over encoded plans:
  for sampled filesystem operations, a child allow must imply a parent allow. Include unmatched
  paths, omission, explicit denial, and protected-default boundaries. Covers S01.

### 5. Install normalized policies in every grant path

- Make startup skill grants and dynamic grants retain the effective value returned by derivation.
  Use that same value for compilation and installation.
- Recompute base plus retained leases through one normalization path against the ceiling. Use it
  for grant addition, release, expiry, and initial active-policy validation; propagate failures.
- Migrate all callers that currently use derivation only as an acceptance check and then install the
  raw candidate. Keep request deltas as provenance, not as an alternative authoritative policy.
- Cover executable pins, inherited denies/defaults, overlapping leases, and removal of one lease
  while another remains. Assert the resulting compiled authority, not just successful validation.
  Covers S02 and builds on commit 4.

### 6. Anchor finding-ledger I/O to directory handles

- Establish the ledger root under the selected operator/project root and resolve project-controlled
  components relative to open directory handles without following symlinks. Check directory and
  regular-file types on the opened objects. Use the existing syscall dependencies.
- Apply the same rules to appends, ledger reads, cache reads, and cache publication. Do not use
  canonicalize-then-open as the security check.
- Create cache temporaries exclusively with unique names and restrictive permissions; publish them
  with a descriptor-relative rename. Clean up only the temporary owned by that operation.
- Test final and intermediate symlinks, non-regular files, competing cache writers, and replacement
  attempts. The outside sentinel must remain unchanged. Preserve ledger format and human verdicts.
  Covers S03; batch optimization waits until commit 18.

### 7. Make host child ownership survive cancellation

- Give each spawned command one owner for its child, process group, pipe tasks, stdin pumping, and
  cleanup state. Establish ownership immediately after spawn, including setup-error paths.
- On cancellation/drop, initiate group termination synchronously. On ordinary completion and
  timeout, explicitly terminate descendants and reap the direct child before reporting completion.
- Track pending cleanup through the session lifetime so teardown or policy reload cannot race it.
  A dropped caller must not leave an untracked stdin task or cleanup task.
- Test cancellation, timeout, early shell exit with a background child, stdin failure, and normal
  completion using process handshakes rather than timing-only sleeps. The delayed marker must never
  appear after canceled same-group work. This fixes the reproduced host-mode portion of S05.

### 8. Own enforced descendants per invocation

- Run each short-lived enforced invocation in an owned child cgroup beneath its policy scope, using
  ancestor policy lookup. Keep persistent MCP services in their own lifetime; per-call cleanup must
  not kill the session cgroup.
- Terminate the invocation subtree, wait for confirmed emptiness within a cleanup budget, then
  remove it. Retain enforcement and report a failed session if cleanup cannot be confirmed; do not
  treat a successful write to `cgroup.kill` as proof that all processes have exited.
- Make the required subtree-cleanup capability explicit at setup. Do not silently substitute a
  process-group-only guarantee for enforced mode when that capability is unavailable.
- Verify on the supported kernel that a descendant which changes session/process group is removed,
  siblings and MCP services survive, and repeated cancellation leaves no invocation cgroups behind.
  Completes S05; depends on commit 7.

### 9. Bound subprocess capture at the pipes

- Replace whole-output capture with concurrent bounded-chunk draining of stdout and stderr under
  the same child owner. Bound retained raw bytes, decoding scratch space, and final formatted output.
- Keep the existing ordinary-tool output cap. After filling it, discard excess bytes while draining
  both pipes until exit or deadline; preserve useful truncation metadata without retaining overflow.
- Give scanner protocol output a separate explicit byte budget and a distinct oversized-output
  failure. Select the initial budget against checked-in representative scanner fixtures and document
  it. Never parse a truncated protocol document as a successful complete scan.
- Test simultaneous noisy stdout/stderr, invalid UTF-8, exact boundaries, huge output, oversize scanner
  JSON, and cancellation while draining. Assert bounded retained bytes and absence of deadlocks;
  use a finite stress run to corroborate peak-memory behavior. Covers S04; depends on commits 7–8.

### 10. Stage grant transitions before installing them

- Compute a candidate policy, lease set, and tool-membership change without mutating active state.
  Install enforcement successfully before committing the corresponding in-memory state.
- Reuse the existing transactional reload and poisoned-sandbox behavior. A refused widening keeps
  the old policy and denies the request. A failed mandatory narrowing stops further execution even
  if rollback restored a consistent but now overprivileged policy.
- Track tool availability as base membership plus live lease ownership; removing one lease must not
  remove a base tool or a tool retained by another lease.
- Enforce reload's existing no-running-child precondition. Until persistent-service quiescence is
  implemented, reject reload-requiring dynamic grants with live stdio MCP services. For finite
  policy leases, reject this combination before activation so expiry cannot become impossible.
- Temporarily reject finite TTLs at session setup until commit 12 connects both loops. Test refused,
  successful, and inconsistent installs with the existing reload fault-injection approach. Prepares S07.

### 11. Interpret hook actions exhaustively in both loops

- Introduce one shared execution-decision path, leaving streaming and presentation in their existing
  loops. Preserve the first-non-Continue hook ordering.
- Continue proceeds; Deny produces a tool refusal without dispatch; Terminate stops the active agent
  run; Escalate follows staged consent/install with at most one reactive retry; Deescalate releases
  the named lease through the staged narrowing transition.
- Define valid event/action combinations. Deny and Escalate apply to BeforeToolCall and KernelDenial;
  Deescalate may also apply at TurnStart and AfterToolResult after child cleanup. Continue and
  Terminate are valid everywhere. An unsupported combination is an explicit contract error that
  stops execution, never an implicit Continue. A reactive denial cannot undo an already-run call;
  it prevents a retry and returns the refusal.
- Test both loops with observable command side effects, including denial, termination, release
  failure, and the retry limit. Covers S06; depends on commit 10.

### 12. Expire grants at a shared turn boundary

- Use one monotonically advancing model-turn counter per active-policy lifetime. Multiple tools from
  one model response share a turn; REPL user exchanges must not reset live leases' clock.
- Before each model turn: wait for invocation cleanup, expire due leases, install required narrowing,
  reconcile tool membership, and dispatch TurnStart. Build the model's tool schemas afterward.
- Define Turns(1) as valid for the granting turn and expired before the next turn. Reject Turns(0),
  and handle turn/expiry arithmetic overflow explicitly rather than making a lease effectively eternal.
- Enable finite TTLs only after both loops use this transition. Cover tool-only and policy leases,
  overlapping ownership, multiple tools per turn, repeated REPL exchanges, and failed expiry reload.
  The audit probe must now observe that the expired tool is unavailable. Completes S07.

### 13. Use one absolute episode deadline

- Carry the episode deadline through provider calls, retries/backoff, hook dispatch, consent, tool
  execution, and reactive retries. Use the earlier of that deadline and any existing per-operation
  deadline; never restart the episode budget after an await.
- Distinguish deadline expiry from provider failure and tool failure in the existing outcome model.
  Cleanup has its own bounded completion phase: describe the execution deadline separately from
  the maximum time needed to finish cleanup.
- Preserve the REPL's interactive lifetime; do not impose a new whole-session timeout there. Keep
  its individual timed operations cancellation-safe.
- Use stalled mock providers, hooks, and consent handlers to prove expiry; cover retries near the
  deadline and ensure no tool starts after the budget is exhausted. Covers episode S08 and depends
  on cancellation ownership and shared decisions.

### 14. Bound complete MCP startup and discovery

- Apply one startup deadline across transport initialization, handshake, and tool discovery for each
  server. Failed discovery leaves no registered tools and shuts down the owned stdio transport.
- Replace unbounded tool-list pagination with bounded requests, page count, and accumulated tool
  data; reject repeated cursors and excessive schemas with a specific discovery failure. Apply
  equivalent budgets to tool-list refresh notifications and bound concurrent refresh work.
- Check where the MCP transport decodes messages: application pagination limits alone do not bound
  one oversized wire response. Use supported transport limits where available, and document any
  remaining dependency limitation rather than claiming a complete transport-memory guarantee.
- Test a completed handshake followed by a stalled list, endless pagination, oversized discovery,
  partial discovery failure, and cancellation of stdio startup. Completes S08.

### 15. Bound audit draining and fan-out

- Limit ring-drain batches and per-scope queue capacity. Nonblocking dispatch must let a healthy
  scope continue when another scope's queue is full.
- Preserve readiness when a bounded batch leaves ring data unread, so stopping a batch cannot strand
  events until another kernel notification.
- Track dropped events and dispatcher failure in sticky health state outside the data queue. Closing
  or failing the stream must be observable even if its last data queue was full.
- Use a fake event source to test overflow, sustained producers, stream errors, and independent
  progress of subscribers. Record the chosen capacities and their per-scope memory cost. Covers the
  queue/dispatcher part of S09.

### 16. Carry incomplete-audit status through bounded retention

- Bound per-call and episode audit retention so commit 15 does not merely move the unbounded buffer
  into transcript vectors. Avoid duplicating retained payloads where practical.
- Propagate queue loss, retention truncation, and stream failure into additive transcript fields with
  backwards-compatible deserialization defaults. Expose a clear incomplete-evidence status to users
  and scoring; missing evidence must not be counted as a clean security result.
- Keep observed userspace loss distinct from kernel loss. This batch does not establish kernel
  ring-loss accounting; document that limitation and do not label the stream provably complete.
- Test serialization of old/new transcripts and scoring with overflow or stream failure. Completes
  the audited userspace S09 scope; depends on commit 15.

### 17. Use document-sized counts for chat layout

- Keep conversation heights, row offsets, and scroll state in `usize`; clip the visible window before
  converting coordinates to terminal `u16`. Avoid recomputing narrow intermediate sums.
- Test more than 65,535 rows from one message and from many messages, including scrolling to the final
  message and resizing. Use the existing in-memory terminal backend in debug and release modes.
- Keep conversation retention policy separate; this fix must make later rows reachable rather than
  merely saturating the total. Covers S10 and can be reviewed independently.

### 18. Append scanner findings in a batch and refresh once

- Add a batch recording operation that validates bounded records, appends sightings, then refreshes
  the derived view once. Route single-record operations through the same storage contract.
- Stream the ledger fold with a per-record byte bound instead of loading raw JSON and all decoded
  events simultaneously. Retain only the state required for the resulting finding view; do not claim
  constant memory as the number of distinct findings grows.
- Serialize cooperating writers across append/fold/publication using a securely opened file lock.
  Unique temporaries alone do not prevent an older snapshot replacing a newer cache. Define errors
  for incomplete/malformed trailing records and report partial batch persistence without discarding
  already-appended events; keep the ledger authoritative if cache refresh fails.
- Move persistence off the async executor with bounded admission. A canceled wait must leave the
  blocking operation tracked until completion; a Tokio timeout cannot interrupt a filesystem call.
- Preserve human-verdict precedence and finding identity. Test concurrent batches, cache failure,
  partial writes, and rediscovery after adjudication. Compare one 200-finding import over the same
  seeded ledger before/after, reporting fold count, elapsed time, and peak memory without imposing a
  flaky wall-clock threshold. Covers P01; builds on the secure I/O in commit 6.

### 19. Complete cross-boundary enforcement coverage and update contracts

- Run the required feature matrix and the strict VM parser. Add/run kernel scenarios for the
  unmatched-write attenuation regression, installed executable pins, cancellation with detached
  descendants, and lease expiry with successful and refused narrowing.
- Verify cleanup isolation with a persistent MCP service and a sibling invocation. Verify that the
  explicitly unsupported live-service/reload combination returns its documented failure before
  granting authority.
- Update touched API comments and user-facing behavior documentation to match actual guarantees,
  limits, and compatibility changes. Keep useful reasons and invariants; remove stale claims in
  touched code rather than doing a repository-wide comment rewrite.
- Attach evidence per finding and mark it resolved only when its acceptance tests pass. If a kernel
  runner is unavailable, mark the enforcement validation pending; host tests are not a replacement.

## Decision Document

- **Pragmatic scope:** repair observable contracts and their ownership. No function-length quotas,
  assertion quotas, blanket renaming, allocation ban, or new general-purpose framework.
- **Policy authority:** authored input and effective state have distinct roles. Derived defaults and
  pins remain authoritative through every consumer. Root operator semantics stay explicit; project
  configuration cannot override inherited restrictions.
- **Grant transactions:** prepare, install, then commit. A mandatory narrowing failure ends execution.
  Existing reload/rollback work is retained and extended, not replaced.
- **Process ownership:** one owner spans child execution, pipes, cancellation, and cleanup. Enforced
  invocations own descendant cgroups; persistent MCP services have a different lifetime. Host mode
  remains explicitly unable to guarantee cleanup of descendants that deliberately escape its process
  group, and is not presented as an enforcement sandbox.
- **Persistent MCP and reload:** a turn boundary alone does not establish kernel-reload quiescence.
  The initial implementation refuses combinations that cannot satisfy the existing precondition;
  freeze/resume or atomic multi-map policy replacement is a separate design.
- **Output behavior:** ordinary tools drain and discard overflow; scanner protocol overflow fails the
  scan. Bounds apply before decoding and concatenation. Start with internal documented limits rather
  than adding configuration for every buffer.
- **Deadlines:** one absolute execution budget, plus explicitly bounded cleanup. The REPL retains its
  interactive lifetime. Non-cancelable filesystem work remains owned after its waiter is canceled.
- **Audit health:** userspace loss is explicit and disqualifies a clean evidence claim. Kernel loss
  accounting remains a separate follow-up; no completeness claim exceeds the measurement available.
- **Persistence:** the append-only finding ledger is authoritative; the view is replaceable derived
  data. Human verdict precedence is unchanged. Descriptor-relative I/O addresses symlink races;
  writer locking addresses publication ordering. Neither is a substitute for the other.
- **Compatibility:** preserve existing configuration and ledger formats where possible. Record any
  public Rust API migration explicitly; use additive, defaulted transcript fields. No new executable
  or crate boundary is needed, consistent with the existing ADRs.

## Testing Decisions

- Convert the audit's defect probes into tests of the desired outcome; do not install probes that
  intentionally assert the bugs. Keep regression tests next to the owning module or existing
  integration suite.
- Prefer outcomes: an outside write is denied, a denied command leaves no marker, an expired tool is
  unavailable, a cache cannot overwrite an outside file, a canceled descendant is gone. Assertions
  that a helper was called or a request was accepted are insufficient.
- Reuse the existing resolver fakes and encoded-plan matcher, grant tests, reload fault injection,
  mock providers, process tests, ledger/verdict fixtures, and in-memory terminal backend.
- Use generated policy samples for attenuation and deterministic fault injection for transactional
  failures. Use Tokio's controlled time where supported for pure async timeout tests; use explicit
  process readiness handshakes for OS process tests.
- Test host logic without requiring a live provider or external scanner installation. Keep real
  BPF behavior in kernel tests and state which level supplied the evidence.
- For resource bounds, test exact boundaries and overflow policy, then corroborate with finite stress
  workloads. For persistence performance, compare identical workloads and report the number of
  ledger folds alongside time/memory; avoid unsupported performance percentages.
- Run the relevant focused tests after each commit and the required feature matrix per batch. Do not
  repeatedly run unrelated expensive suites when neither code nor the failure hypothesis changed.

## Out of Scope

- Broad architectural rewrites, wholesale hook-loop unification, new CLI features, or style-only churn.
- General scope-map reclamation and scope-creation rollback beyond the invocation lifecycle needed
  for S05; the audit identified these as follow-ups, not reproduced findings in this set.
- MCP tool-name lifetime cleanup, arbitrary third-party MCP transport rewrites, and kernel audit-loss
  counters. Record a focused follow-up if implementation exposes a concrete prerequisite.
- New scanner engines, finding-schema redesign, full crash-atomic multi-record transactions, or
  suppressing human verdicts during automated rediscovery.
- Automatic chat-history eviction and a new whole-session timeout for interactive use.
- A complete dependency vulnerability audit or a claim that this work proves the whole sandbox secure.

## Further Notes

Preserve the pre-existing worktree changes, especially the transactional reload implementation and
its poisoned-sandbox handling. Recheck the baseline before implementation and avoid staging unrelated
files with these commits. The audit did not run live VM enforcement, and its broad feature check
failed on known fixture errors; the implementation must replace those gaps with actual evidence.

This plan makes the routine design choices explicit so implementation can proceed without a design
interview. Split a commit further if review exposes an independently verifiable boundary, but keep
each security behavior change together with its regression test. Completion means all 13 findings
meet their acceptance criteria, not merely that the default host suite is green.
