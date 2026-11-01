# Parallel and nested codemode

Status: implemented; verification recorded below.
Authorized scope: parallel execution, nested codemode, and broader tool exposure.
This extends the completed follow-up plan.

## Contract

Keep ordinary `call_tool(name, arguments)` sequential. Add an explicit bounded
`call_tools(calls)` operation returning results in input order, with at most four
concurrently executing children. Each request contains a name and arguments.
This API provides real overlap without requiring arbitrary Python async tasks.
An ordinary child error is a result; cancellation, deadline expiry, and unresolved
effects stop admission and prevent Python continuation. Completed sibling receipts
remain visible. No implicit dependency ordering is promised inside a batch.

Permit `call_tool('codemode', {'source': ..., 'inputs': ...})`, bounded to four
script levels including the root. Each nested call has an ordinary durable
operation identity and its own interpreter continuation. Children inherit the
minimum ancestor deadline. All descendants share the root's 32-call and
64-interpreter-invocation limits, as well as the existing session budget; nesting
must not multiply available work. Charge every script operation and leaf attempt.

Broaden the explicit catalog to registered shell, analysis, findings, source,
hunt, and scanner tools. Preserve each registration's recovery contract, consent,
policy checks, evidence validation, and journal executor. Unknown tools and MCP
registrations remain excluded until their cancellation/reconciliation behavior is
qualified. `submit_flag`, `give_up`, and `render` remain excluded because their
session-terminal or UI behavior needs a separate contract. Catalog exposure never
adds grants. Shell mutations retain `NeverReplay`.

## Implementation sequence

1. Expand and test the trusted catalog through the existing sequential path.
   Verify real shell execution, receipts, budget charges, and reopen without
   repeating a completed effect. Keep absent registrations unavailable.
2. Replace the single script cursor with a bounded persisted script tree. Separate
   the model-turn cursor from leaf execution slots. Validate parent bindings,
   unique ownership, acyclic ancestry, aggregate charges and ancestor deadlines.
   Version the journal; atomically migrate existing single-script journals.
3. Generalize suspension bindings to an ordered child set. Commit the checkpoint
   and all child admissions before releasing any dispatch. Resume only with the
   entire validated committed result vector. Version snapshot/storage and migrate
   v7 singleton bindings transactionally. Keep checkpoint retention derived from
   every active script's latest continuation.
4. Add the bounded worker batch API and nested-script dispatch. Nested completion
   supplies a result to its parent without adding inner model messages. Retain
   stable ancestor identities in live/replayed terminal and TUI presentation.
5. Execute ready leaves with at most four independent executor scopes and audit
   collectors. Serialize consent, authorization, budget reservations and commits;
   execution alone overlaps. Do not concurrently drain the existing shared
   Sandbox audit buffer. Persist each executor identity before dispatch and
   reconcile/clean every slot on activation, cancellation and deadline expiry.
   Journal-aware tools need per-slot journal and mutable sandbox ownership.
6. Run host and kernel verification; update the specification, implementation
   notes and final verification record to match shipped behavior.

## Acceptance

- A barrier-based test proves two leaf tools overlap; input-order results stay
  stable when completion order reverses. Width limits prevent a fifth dispatch.
- Crash before/after batch admission, each authorization, individual result and
  receipt commit, parent completion and delivery. Completed siblings never repeat;
  ambiguous mutations block continuation under their original recovery policies.
- Nested write/read and nested failure preserve ancestor relationships and all
  receipts. Depth, aggregate calls, worker invocations and deadlines survive reopen.
- Cancellation during consent, worker execution, nested execution and partially
  completed batches stops new work and cleans every admitted executor. A surviving
  sibling scope cannot inherit a cancelled scope's authority or audit attribution.
- Shared checkpoint digests and active parents survive reclamation; migration
  rollback preserves old stores. Corrupt bindings fail before dispatch.
- Existing direct/sequential execution and model-message behavior remain intact.
- Extend the BPF-LSM matrix for shell allow/deny, overlapping scopes, nested
  effects, cancellation and process-kill recovery. Restore the VM lifecycle state.

## Current evidence

Steps 1–6 are implemented, including enforced-mode overlap.

- Step 2–3: `Suspension` binds an ordered child set with a batch flag; `Script`
  records an optional parent `(script, child)`. Core validation enforces at most four
  children per suspension, unique ownership, bounded acyclic ancestry (four levels),
  deadlines no later than the parent child's, and the root's call limit across the
  whole tree. Stop cascades to descendants and their admitted children. On `main`
  this lands as snapshot/store version 7 (version 6 is main's conversation archive);
  v5/v6 open in place and roll back on invalid scripts. Finished trees are forgotten
  after delivery and pruned with their operations. Checkpoint retention still derives
  from every active script's latest suspension.
- Step 4: the driver keeps a root-to-innermost cursor stack (journal v4). A batch
  resumes with the full committed result vector; nested completion completes the
  child operation and advances its parent without model messages. Live, replayed and
  unresolved presentation carry stable parent ids at every level.
- Step 5: `src/session/driver/parallel.rs` overlaps up to four ordinary leaves in
  Host, Enforced and Concurrent sandboxes. Each kernel leaf has a child cgroup and a
  durable OperationId-to-executor entry. A single collector partitions audit by
  `executor_cgroup_id`; policy-scope routing is unchanged. Ordered futures commit
  completed prefixes while later leaves run. Activation, cancellation and expiry
  stop every slot using boot/device/inode identity before resolving outcomes.
  Journal-aware tools and nested scripts remain sequential.
- Presentation: explicit depth comes from the cursor stack live and the parent-id
  chain on replay. Replay opens ancestors root-first; terminal and TUI share the
  same indentation, including unresolved outcomes.

Verification for issues 02/04 (2026-10-31):

- 932 main-package host tests passed with `--features durable-sessions --lib --tests`;
  62 bee-core tests and three concurrent audit-demux tests also passed.
- Headless durable-session check, formatting, and Clippy `-D warnings` for
  `durable-sessions,enforce,concurrent` passed.
- Full codemode VM gate: **20/20 passed** on BPF LSM (`6.8.0-147-generic`). New
  cases prove barrier overlap with reversed completion order, denial attribution,
  four-slot cancellation and deadline cleanup while a sibling session survives.
  The updated SIGKILL case kills after a result/receipt intent is durable but before
  receipt publication; recovery stops all slots, preserves that result and leaves
  the running sibling unresolved. Journal-aware tools remain sequential.
- The VM is back in its original `Stopped` state. Details and binary hashes:
  `enforcement-verification.md`. Implemented on the PR branch.

Prior baseline validation (2026-10-31, before issues 02/04):

- Host: 571 tests passed with `--no-default-features --features durable-sessions`,
  and 758 with `--features durable-sessions` (TUI included). Zero failures. New
  coverage includes barrier-proven overlap with reversed completion order, width
  four, rejection of a fifth call, lost acknowledgements around batch admission and
  each sibling result, a crash with one sibling committed and one running (completed
  sibling kept, running one unresolved and never rerun), cancellation of overlapped and
  nested batches, nested crash points, depth and shared-limit bounds, and v6→v7
  migration with rollback.
- Kernel: the codemode VM gate grew from 12 to 17 cases (shell allow/deny, batch audit
  attribution, nested effects, nested-batch cancellation, batch SIGKILL recovery).
  All 17 passed under BPF LSM on `6.8.0-147-generic`. The VM was returned to Stopped.
- Clippy `-D warnings` passed for default, `durable-sessions`, and
  `durable-sessions,enforce` targets; formatting is clean.

## Port onto main (2026-10-31)

The work was developed on an older local line and ported onto `main` (024 session
core, 025 context budget, reviewed durable sessions #45–#47) in three commits: the
Python visual renderer, durable compositions, and the codemode driver. Driver
integration uses main's call lifecycle (`crate::call::before_call`), provenance,
`Event::Expire` and conversation archive. Version numbers were reassigned as above.
