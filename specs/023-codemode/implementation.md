# Durable Python codemode implementation

Implemented 2026-10-31. Durable `bee run` and `bee repl` now advertise `codemode` through their shared driver. Python can call registered `read_file`, `list_directory`, `search`, `write_file`, `bash`, analysis, findings, source, hunt and scanner tools, admit up to four calls together with `call_tools`, and run nested `codemode` scripts. Ordinary, non-durable registries do not advertise it. Terminal tools, MCP registrations and visual rendering remain excluded. See "Batches and nesting" below.

## Driver execution

`src/session/driver/codemode.rs` owns a persisted cursor and a normal outer tool operation. The outer attempt consumes one tool-budget reservation; every inner attempt consumes another. A suspension admits an ordinary child operation and goes through the existing proactive consent, authorization, executor recovery, audit settlement, receipt publication and result-delivery path. Only the committed, validated result is supplied to Python. An uncertain child blocks continuation.

The cursor, checkpoint binding and child identity are committed together. Source/input digest, runtime identity, current registration schemas, implementation versions, recovery contracts and configuration must match on restore. The private storage owner reads and writes checkpoint blobs. A completed script result is committed before its outer completion and model delivery; reopening either intermediate state finishes delivery without rerunning the source.

Each child is recorded with `parent_call_id` in the transcript, including its audit and receipt. The model conversation gets only the outer tool result; no unmatched inner tool-result messages are invented. Earlier child records survive a Python exception or cancellation. The outer JSON result is explicitly untrusted data and cannot set a receipt or terminal flag.

The hidden `bee python-worker --parent <pid>` subcommand is shared with visual scripting. On Linux its parent-death signal is armed before exec and the expected parent is checked again before consuming input. Worker audit events are persisted on the outer operation and its transcript record. Dropping the worker future kills and reaps the child through the existing subprocess owner. The worker cannot dispatch tools independently: it returns a request to the serialized driver.

## Scheduling limits

A composition inherits the lesser of the existing session deadline and a tool timeout measured at admission. This absolute deadline includes consent, children and restarts. Source is limited to 32 KiB and JSON object inputs to 8 KiB, within the existing 64 KiB encoded operation envelope. Final durable output is capped at 64 KiB; oversized results become explicit script errors. Print output is discarded.

There are at most 32 admitted children and 64 interpreter invocations, including recovery attempts. Every invocation reserves its count and a 4,000 ms time charge before launching. A returned invocation replaces that charge with its measured elapsed time; a lost response retains the charge. The final result records `worker_invocations` and `worker_time_charge_ms`; the outer completion duration uses this charge, while child durations stay on their own records. Each worker retains its one-second interpreter budget, three-second parent watchdog and 64 MiB memory limit. These host-owned counters cannot be reset by a snapshot.

Driver journal version 4 adds the bounded batch executor map alongside the script stack introduced in v3. Version-2/3 journals upgrade on open with an empty map; older readers reject version 4. Changes to the advertised runtime/tool surface still require compatible current configuration, so an unfinished older session can be refused rather than silently changing its model request.

## State and commit ordering

`src/session/durable/composition.rs` adds a persisted script specification (source/input digest, runtime identity, compatibility, deadline and call limit), append-only suspension bindings, and completed/stopped states. Each binding references a checkpoint and an ordinary durable child operation. The number of bindings is the continuation generation and admitted call count.

The host first writes opaque checkpoint bytes with `Store::put_checkpoint`. It then proposes `Event::Script(Suspend)`, which atomically records the binding and admits the child in the core snapshot. The store refuses to commit a reference whose bytes are absent, incorrectly sized or corrupt. Only the matching commit acknowledgement releases the child's `Ready` notification. Execution still requires the existing `Authorize` commit before `Dispatch`.

On recovery, `Snapshot::resume_script` checks the supplied current script specification and deadline. It returns a continuation plus the child's existing completion only after the child reaches `Completed`, including any receipt publication gate. Unresolved and stopped children are reported explicitly; in-progress children remain waiting for existing recovery/cleanup decisions. The composition cannot advance to another call or finish while that child is uncertain. Runtime compatibility mismatches, stale activation IDs, stale generations and exhausted call counts fail before admitting work.

Stopping a composition also requests the existing cancellation transition for its current child. Previously completed child results and receipts are retained. Composition state uses the core's existing commit-failure suspension mechanism; losing an acknowledgement requires reopening authoritative storage.

## Storage and compatibility

Checkpoint bytes live in the same private SQLite database as session state, under its exclusive owner and FULL-synchronous WAL configuration. Content hashes deduplicate bytes and detect corruption. They do not authenticate an untrusted runtime producer: only the trusted host may write checkpoint bytes, and the interpreter must restore only compatible state from this protected store.

Bounds: 4 MiB per checkpoint, 64 MiB total checkpoint bytes, 1,024 distinct blobs, 64 scripts and a core maximum of 256 admitted calls per script (the shipping driver sets a stricter 32-call limit) (also constrained by the existing session operation cap). Only active scripts' latest continuations are retained; obsolete and orphaned blobs are reclaimed in the same transaction as the commit that makes them unnecessary.

The durable snapshot and database versions are now 7 (version 6 added the conversation archive). Version-5 and version-6 databases open in place: the claiming transaction adds the missing tables, and pre-composition snapshots load with no scripts. A pre-composition snapshot that carries scripts is rejected without changing the stored version. Operations, results, driver state, submissions and worker journals are preserved. Older Bee versions reject version 7 rather than silently ignoring compositions.

## Verification

Store tests exercise atomic checkpoint/child binding, lost completion acknowledgements, uncertain effects, stale callbacks, cancellation, deadline and compatibility checks, receipt publication, persistent call limits, missing/corrupt blobs, individual/aggregate storage bounds and version-5 migration. Existing durable core and driver tests cover the lifecycle reused here.

The Monty spike has a real-store integration test: save a Python continuation, admit and authorize a controlled mutation, commit its result, discard the acknowledgement and interpreter state, reopen the store, and resume a fresh worker with that exact committed result. The resumed program preserves its locals and reaches the second host call. The mutation's operation is not redispatched. That spike keeps its fixture-supplied second result; the production-driver tests below now cover actual registry execution.

## Driver verification and remaining scope

`tests/durable_codemode.rs` executes the shipping `read_file` tool through batch and fresh REPL exchanges, checks the advertised catalog and idempotent replay, and injects lost acknowledgements before interpreter launch, after suspension, after child completion and after outer completion. It checks that an uncertain child never redispatches, implementation-version changes reject saved continuations, budgets retain charges, parent timeouts and cancellation stop scheduling, call/output limits return errors, and earlier child receipts survive later Python errors.

The existing durable-driver process-kill tests and core/store tests remain in the regression suite. The production worker tests cover fresh-process continuation restoration, exact integer inputs, memory exhaustion and host-access denial. The nine-case codemode VM gate also passed under BPF LSM on kernel `6.8.0-147-generic`; see [enforcement verification](enforcement-verification.md). Enforced policies must already allow the Bee executable; no new grants are implicit.

Restrictions at the time of that slice: no mutation tools beyond `write_file`, no parallel or nested codemode, no captured print stream. The later batch/nesting slice below lifts the first two. `write_file` and `bash` retain their `NeverReplay` contracts; an ambiguous effect blocks the script and retains its charge.

## Shipping write validation

The real `WriteFile` implementation is exercised at suspension, authorization,
a completed effect without a result, receipt publication, child completion and
outer completion. Reopening after ambiguous effects blocks the next call and
retains charges. Changing the destination after a committed write proves recovery
does not silently repeat it. A shipping registry test writes and reads the result.
The VM gate adds allowed/denied writes with associated denial audits and receipts,
Python errors after writes, actual driver SIGKILL recovery and blocked-write
cancellation while a sibling scope survives. No alternate execution path or
recovery contract was introduced.

## Batches and nesting

`call_tools([{'name': ..., 'arguments': {...}}, ...])` proposes one to four calls.
The worker validates the request shape and suspends once; the driver commits the
checkpoint and every child admission in one `Suspend` transition, then resumes the
continuation with the committed results in input order. A child error is an ordinary
result. Cancellation, deadline expiry and unresolved effects stop admission and prevent
continuation; delivered sibling results and receipts remain recorded.

`call_tool('codemode', {...})` runs a nested script as an ordinary durable child
operation (`Reconcile`, like the root). Its script records its parent script and child
operation. At most four levels, including the root, are admitted. All levels share the
root's 32-call and 64-invocation limits and the session tool budget; every script
operation and leaf attempt is charged. A nested result is delivered to its parent only
and adds no model messages. Transcript records keep stable ancestry
(`outer/1/2` under `outer/1`). Stopping the root stops every active descendant and its
admitted children in one commit.

Up to four never-started batch leaves overlap in Host, Enforced and Concurrent
sandboxes. Journal-aware tools and nested scripts still execute sequentially: they
require the single worker journal and mutable sandbox handle. Consent, authorization,
budget reservations and result commits stay serialized in input order. Completed
prefixes commit while later siblings are running.

Each enforced leaf receives a child cgroup under the session scope. Its boot id,
canonical path, device and inode are journaled under its OperationId before dispatch.
The parent retains the only audit reader. Kernel records keep the policy cgroup id
for routing and add `executor_cgroup_id`, captured from the immediate child of that
policy scope; this survives removal of a leaf's subprocess cgroups. One collector
partitions records per executor, including events from siblings that finish early.

Activation, cancellation and expiry stop and verify every recorded slot before
resolving individual outcomes. Completed siblings remain committed; ambiguous leaves
retain their original recovery policy. Slot identities stay durable until quiescence
is committed, then empty cgroups are removed. The existing sequential executor fields
remain for direct calls and journal-aware tools; the batch map never borrows that
single ownership boundary.

Snapshot/store version 7 carries ordered child sets, a batch flag and parent links.
Driver journal version 4 holds the cursor stack and at most four batch executors.
Presentation carries explicit depth from the live cursor stack or replay parent chain;
terminal and TUI rows use four spaces per level without interpreting call ids.

Finished script trees are released: the driver forgets a root's tree after delivering
its result, and pruning drops finished scripts together with their operations. A
crash between delivery and the forget commit leaves the tree for pruning. Without
this, long sessions would exhaust the 64-script bound.
