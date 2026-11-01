# Overlap batch calls under kernel enforcement

Status: ready-for-agent

Depends on: 01. Plan step 5 in `specs/023-codemode/parallel-nesting-plan.md`.

## Problem

`call_tools` leaves overlap only when the sandbox has no kernel executor scope
(`src/session/driver/parallel.rs::overlap_candidates`). Under `Sandbox::Enforced` /
`Concurrent`, batch members run one at a time because the driver:

- persists **one** executor identity in `Step::Tools { executor, executor_activation }`
  (`driver/types.rs`, `driver/executor.rs`), used by recovery and
  `cleanup_cancelled` to stop a crashed attempt's cgroup;
- drains **one** shared scope audit stream after each call
  (`sandbox.settle()` + `drain_audit(None)`), so concurrent calls would lose per-call
  attribution;
- gives journal-aware tools one `&mut Sandbox` and one worker journal.

## Approach

1. **Per-slot scopes.** Give each admitted leaf its own child cgroup under the session
   scope with its own audit attribution. `Sandbox::invocation_command` already creates
   `call-N` cgroups; the audit path must tag events with the slot (cgroup id) and return
   them per call. Do not drain the shared buffer concurrently.
2. **Persist every executor.** Replace the single `executor` with a bounded map
   `OperationId → Executor` (≤4) committed **before** dispatch. Bump the journal version.
   Recovery, `cleanup_cancelled` and `cleanup_script_siblings` must stop and verify every
   slot (boot id + inode, never PID) on activation, cancel and deadline.
3. **Journal-aware tools.** Either per-slot journal + sandbox handles, or keep them
   excluded from overlap (document which).
4. Keep consent, authorization, budget reservation and result commits serialized in
   input order. Only execution overlaps.

## Acceptance

- A barrier test (like `batch_leaves_overlap_and_keep_input_order_when_completion_reverses`)
  passes under `Sandbox::Enforced` in the VM.
- New VM cases: overlapping scopes with per-call audit attribution (a denial lands only
  on its own call), cancellation of an overlapped batch empties every slot while a
  sibling session scope survives, and SIGKILL mid-overlap reconciles every slot, with
  completed siblings never repeated and running ones unresolved.
- `test/vm/codemode-cases.txt` and `test_results.py`'s case count updated; the full
  17+N gate passes. VM returned to Stopped.
- Update `implementation.md` and the plan's "Current evidence".
