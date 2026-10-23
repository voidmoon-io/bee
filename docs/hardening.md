# Execution and storage guarantees

This describes the contracts repaired by the October 2026 TigerStyle audit. Limits are internal
defaults; they do not add new command-line settings. Host mode is still intended for trusted tools.

## Policies and grants

Derived policies carry an explicit `defaults.deny_unmatched_writes` decision. Removing the last
write rule cannot restore writes outside the parent's writable surface. Parent read-only and deny
rules survive omission by a child. The compiler passes the effective default to the enforcement
plan. Existing policy files remain valid because the new metadata defaults to false; derivation can
only strengthen it. Explicit root write rules retain their existing default-deny semantics.

Startup and dynamic grants install the policy returned by derivation, including inherited executable
pins. Lease addition, release, and expiry use the same normalization. Grant transitions install the
candidate policy before changing the active lease set or tool membership. A refused widening keeps
the current state. Cancellation during a kernel/proxy policy transition stops further dispatch
because the two layers may disagree. A failed mandatory narrowing terminates execution and makes the sandbox refuse
further tool dispatch.

`Turns(1)` grants last through the granting model turn and expire before the next turn's tool schemas
are built. Multiple tool calls in one response share a turn. Interactive exchanges share a monotonically
advancing lease clock. Zero-turn leases and arithmetic overflow are errors. Base tools and tools owned
by another live lease remain available when a lease ends.

Tool-scope policy reload requires an empty scope. A live persistent stdio MCP service therefore
prevents a reload-requiring grant; tool-only grants do not reload policy. If a service starts after a finite policy
grant and prevents its expiry, Bee terminates the run. Quiescing persistent services for reload is not
implemented.

Hooks interpret every action in both execution loops. `Continue` and `Terminate` are valid at every
event. `Deny` and `Escalate` apply before a tool call, after a kernel denial, or after a proxy refusal.
`RefreshTools` applies at turn start. Hooks compose through the shared dispatcher; denial takes
precedence over escalation. `Deescalate` also works
at turn start and after tool results. Other combinations terminate with a contract error. A reactive
grant permits at most one retry; a reactive denial prevents retry but cannot undo the first attempt.

Rust API changes: `Policy` and `CompiledPolicy` carry effective-default state; `ActivePolicy::new`,
`release`, and `expire` return errors; `ReplEscalation::new` validates its configuration. Callers must
retain normalized policies rather than treating derivation as a boolean check.

## Child processes and deadlines

Each short-lived subprocess has one owner for its process group, pipes, stdin, and cleanup. Output
is drained concurrently in 8 KiB chunks. Ordinary tools retain at most their requested cap on stdout
and the smaller of that cap or 64 KiB on stderr, discard overflow, and cap the decoded model-facing
result again. The truncation notice adds a small amount beyond that cap. Raw byte counts remain
available in truncation metadata. Invalid UTF-8 cannot bypass the final text cap.

Scanner protocols allow 8 MiB stdout and 64 KiB stderr. Exceeding either fails the operation rather
than parsing a partial report. This provides headroom beyond the checked-in scanner fixtures and the
200 normalized findings limit (each ledger record is at most 4,000 bytes); large raw reports can still
hit the limit before normalization.

In enforced mode each invocation owns a child cgroup. Cleanup uses `cgroup.kill`, confirms the subtree
is empty, then removes it. Detached descendants that call `setsid` remain in that subtree. Sibling
invocations and persistent MCP services in the parent scope have separate lifetimes. The kernel must
provide `cgroup.kill`; Bee refuses invocation setup without it. Host mode kills the process group and
reaps the direct child, but cannot guarantee cleanup of descendants that deliberately escape the group.

Cancellation initiates cleanup synchronously. Cleanup can block the executor for up to one second
while waiting for exit; nested cgroup removal is limited to 256 directories. Unconfirmed cleanup
poisons the sandbox. Scope teardown failure is an infrastructure error. The engine attempts final
scope cleanup before detaching BPF links; if it cannot confirm emptiness, it retains the descriptors
for the remaining lifetime of the Bee process. This is not persistence across Bee process exit.

Headless episodes share one absolute execution deadline across provider requests, backoff, hooks,
consent, tools, and reactive retries. Cleanup has its separate budget, so returning from a canceled
operation can exceed the execution deadline. The REPL keeps its interactive lifetime and per-operation
timeouts.

MCP startup allows 10 seconds for stdio and 15 seconds for remote servers, including handshake and
discovery. Discovery and refresh allow at most 32 pages, 1,024 tools, 4 MiB of serialized tool data,
and 4 KiB per cursor. Repeated cursors fail. Only one refresh runs per server; failed refresh removes
its advertised tools. These checks apply after rmcp decodes a response. The current transport does
not expose a suitable wire-message allocation limit, so one oversized wire response can still allocate
before Bee checks it.

## Finding storage

Ledger I/O opens every directory component relative to a held descriptor with `O_NOFOLLOW`.
Parent traversal, symlinks, non-regular ledger/lock files, and multiply linked ledger/lock files are
rejected. A ledger path through a symlinked checkout is therefore rejected too; select its real path.
New directories use mode 0700 and files 0600. Cache publication uses exclusive unique temporaries
and descriptor-relative rename, replacing a cache symlink itself rather than following its target.

A securely opened advisory lock serializes cooperating writers across append, fold, and publication.
Lock acquisition waits at most five seconds. The lock does not protect against an unrelated process
that ignores it. A partial trailing record must be repaired before appending. Malformed complete
records are reported by the fold rather than treated as valid sightings.

Scanner imports append at most 200 sightings and refresh the view once. Per-record errors preserve
already-appended events and are reported to the caller; this is not a crash-atomic batch transaction.
The append-only ledger stays authoritative if cache publication fails. Human verdict precedence and
finding identity are unchanged.

The fold streams records with a 4,000-byte record bound. Memory still grows with the number of distinct
findings in the resulting view. Async scanner imports and finding tools use one admitted blocking
worker at a time. Canceling the waiter does not interrupt a filesystem syscall: the owned worker
retains its admission permit until completion, and runtime shutdown waits for blocking work.

## Audit evidence and rendering

Async ring draining stops after 256 events per batch without clearing unread readiness. Each scope
queue holds 1,024 events; a full queue drops that scope's new events without blocking others. It keeps
a sticky drop count and shared dispatcher-failure flag outside the queue. A full queue owns 1,024
`AuditEvent` values and their strings: roughly 1 MiB for maximum-length decoded targets and short
scope IDs, excluding allocator overhead. Kernel targets contain at most 256 raw bytes (up to 768
bytes after lossy UTF-8 decoding).

Synchronous draining stops after 4,096 events and marks evidence incomplete if it has not observed
an empty ring. Retention is capped at 4,096 events across a sandbox's lifetime, including successive
REPL exchanges. Call records and the transcript trail can hold copies of these retained events.
Overflow, retention loss, dispatcher failure, and incomplete drain state propagate through additive
`audit_health` fields. Bee displays a warning and scoring sets `evidence_incomplete`; incomplete
evidence cannot count as a captured flag. Older transcripts deserialize with default health fields; the health key is omitted when all
fields are at their default, preserving round trips of existing transcripts.

Kernel ring-buffer reservation loss is not counted. Absence of a userspace loss flag is therefore
not proof of complete audit evidence.

Conversation row counts and scroll offsets use `usize`. Terminal coordinates are converted to `u16`
only after clipping to the visible window, so rows beyond 65,535 remain reachable. Chat-history
retention is unchanged.

See [the VM harness](../test/vm/README.md) for live enforcement verification and
[the implementation report](../.scratch/tigerstyle-hardening/IMPLEMENTATION.md) for audit coverage.
