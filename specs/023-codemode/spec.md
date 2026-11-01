# Feature Specification: Durable Python Codemode

**Created**: 2026-10-31
**Status**: Draft; Monty selected, continuation spike and durable composition/storage foundation implemented; session scheduling and tool exposure pending
**Runtime**: Pydantic Monty, embedded through Rust in a supervised worker
**Depends on**: the current durable session driver, store, tool adapter and evidence receipts

## Decision and scope

Bee accepts a bounded Python program that composes its existing tools and returns a compact result. Monty is the selected interpreter. This supersedes the JavaScript/QuickJS decision and HTTP-first dependency in `research.md`. The original research remains historical evidence. The runtime investigation is in `rust-runtime-research.md`.

Codemode is a durable session operation. Both `bee run` and `bee repl` use the same driver integration. Builds or sessions without durable execution do not advertise codemode. Direct tool calls remain available. Python source is interpreted by Monty; no installed CPython, package installation, JavaScript compatibility, or arbitrary Python dependency support is promised.

The first implementation supported sequential tool calls. A bounded `call_tools` batch (at most four calls, ordered results) and nested `codemode` (at most four levels sharing the root's limits) were added later; see [parallel and nested codemode](parallel-nesting-plan.md). Arbitrary Python async tasks and multiple outstanding futures remain unsupported. Unsupported host interactions fail explicitly. There is one fresh interpreter session per program; no globals leak between programs.

## Current implementation baseline

`src/session/driver/types.rs` currently models `Step::Model` and a sequential `Step::Tools`, with one active operation. `src/session/driver/execution.rs` owns execution and `src/tools/durable.rs` binds registered tools to durable contracts. `src/session/durable` owns commit-gated transitions and recovery policies. Codemode extends these structures with persisted composition state; it does not recursively invoke the driver or directly invoke `Tool::call` from the guest.

There is no `src/call.rs`, `ToolRegistry::surface()`, implemented HTTP family, or generic nested transcript model in this checkout. These are not prerequisites assumed to exist. The existing trusted worker journal's 20-probe limit and intent semantics do not make it a general script journal. Composition needs its own versioned state and validation.

## Model-facing contract

The proposed outer tool is `codemode`, with `source: string` and optional JSON `inputs: object`. The source is a Python program whose final expression is its result. The first host API is `call_tool(name: str, arguments: dict) -> dict`; a bounded catalog advertises actual registered names and JSON schemas. Exact names avoid identifier collisions and work for MCP names. Python convenience wrappers are a later addition.

`call_tool` suspends the guest while Bee runs an asynchronous host operation; the Python program need not manage futures. Its result preserves the tool's content, error flag, truncation metadata and receipt identity. Structured outcomes are preserved where provided; Bee does not claim every current tool has a typed result. Ordinary tool failures return an explicit error result that the program can inspect. Cancellation, budget exhaustion and unresolved durable effects stop the composition and cannot be swallowed as ordinary tool errors.

Initial exposure uses an explicit trusted allowlist drawn from existing registry tools. The validated catalog includes `read_file`, `list_directory`, `search` and `write_file`. `write_file` retains `NeverReplay`; ambiguous effects block continuation. `bash` remains excluded. Each tool retains its existing recovery policy. Exclude `codemode`, `submit_flag`, `give_up`, `render`, and any tool requiring unsupported lifecycle behavior. Discovery never grants execution authority. Recheck current policy and compatibility when admitting every call, including after restore.

Return the final JSON-compatible value and an explicit completion status. The first shipping slice discards print output; captured logs remain deferred. Reject unsupported values rather than silently stringify them. Script output remains untrusted tool data. Inner results, audits and receipts remain available even if Python raises, serialization fails, or the outer call is cancelled. Script text cannot mint evidence receipts or adjudicate findings.

## Durable composition contract

Persist a host-owned script identity, source/input digest, runtime/prelude/protocol version, catalog compatibility identity, absolute deadline, accumulated budget, checkpoint reference, continuation generation, next call ordinal, and current child operation identity. The guest supplies only requested tool name and arguments; it cannot choose operation IDs, attempts, authority, recovery policy or accounting.

The following ordering is mandatory:

1. Admit the script durably before running its worker. Charge script execution separately from inner tool attempts.
2. At a tool suspension, validate the request and write the snapshot to bounded, protected durable storage. Make the blob durable before committing any reference to it.
3. Commit a checkpoint record binding that snapshot and call ordinal to the requested name/input digest and a stable child operation identity. Dispatch nothing until the binding and child admission are durably acknowledged. A recoverable intermediate state may finish admission, but cannot mint a second child identity.
4. Authorize, reserve and execute the child through the existing durable lifecycle: escalation/consent, execution, audit settlement, result commit and receipt publication as required by that lifecycle.
5. Supply only the committed child result to the suspended interpreter. Keep the earlier checkpoint until the next checkpoint or final script completion is durable.
6. Persist final completion before model delivery. Existing delivery cursor semantics apply; transcript presentation must not imply exactly-once external delivery.

Recovery may restore the previous checkpoint and inject the same committed child result again. This repeats local computation, not the external effect. Before another effect, the next suspension must be committed under a validated new generation. An old worker cannot advance the composition after a new activation. Late messages are rejected using host activation, script and generation identity.

For an unfinished child, use its existing `NeverReplay`, bounded `RetrySafe` or `Reconcile` contract. A snapshot does not establish whether an external effect occurred. Unknown outcomes block continuation. Commit acknowledgement ambiguity suspends execution and requires store recovery, as in the existing driver. Cancellation or expiry forbids new child admission even when an old result becomes available.

Logs and other guest-visible host inputs must not create hidden side effects during replay. Buffer output by continuation generation and commit it with the next checkpoint/completion, deduplicating delivery. Do not expose ambient time, entropy, filesystem, environment or network services; reject their host requests in v1. Snapshot restore cannot restore authority. Runtime or tool incompatibility stops recovery with a diagnostic; never silently restart from source.

## Worker and snapshot boundaries

Use a hidden `bee python-worker --parent <pid>` subcommand, consistent with ADR 0002's single installed application. Compile and execute untrusted source in that supervised process. Prefer reusable upstream Monty components where compatible; upstream pool examples require a separate Monty worker binary, so packaging and allocator integration must be proved rather than assumed.

Use versioned, bounded IPC. The worker has no credentials, durable-store handles or ambient tool access. Apply Bee's configured execution posture and record it; a process boundary alone is not kernel enforcement. Parent watchdog termination, reaping and executor quiescence are distinct from receiving a cancellation response. Remote tool quiescence is independently reconciled.

Snapshot bytes are opaque and bounded. Store them outside the current 64-KiB operation input envelope with a protected reference and digest. Specify blob durability, ownership, retention and garbage collection; an orphan blob is harmless, a committed missing blob is an error. Restore only snapshots produced by Bee's pinned compatible Monty build from trusted storage. Hashes detect corruption, not malicious replacement; storage must exclude guest/project writes. Validate metadata and size before decoding inside the worker.

## Limits and accounting

Effective configuration must resolve finite nonzero limits before execution, within user configuration authority (ADR 0001). Required limits cover source, input, output/logs, checkpoint bytes and total retained checkpoints, IPC frames/queues, interpreter memory/recursion, worker resources, execution time and total suspension count. Exact defaults are set by the spike and become required configuration defaults before shipping.

The absolute session deadline includes tool and consent waits; restoring a snapshot never extends it. Persist aggregate suspension and execution accounting independently of Monty dumps. Each inner attempt reserves the existing tool budget; uncertain attempts are not refunded. Bound aggregate checkpoint storage as well as individual blobs. No unbounded defaults or model-selected limits.

Monty's direct Rust memory limit requires its allocator integration, and direct hosts must enforce suspension counts. Verify these in the resolved dependency build. Parent deadlines must also cover compilation, serialization and blocked IPC. Memory-limit failure discards the worker; never reuse potentially inconsistent state.

## Acceptance criteria

- A Python program calls two available tools and returns a selected result in both batch and REPL through the same durable path.
- Reopening after a committed child result resumes local computation without rerunning that child.
- Crashes before admission, after intent, after effect, after result commit, after resume, and before final delivery preserve identity, charges, audits and receipts. Unknown effects never silently repeat.
- Snapshot replacement, corruption, missing blobs, incompatible versions, duplicate messages and stale activations fail without dispatching a tool.
- Consent reaches the existing interactive input path. Cancellation during consent or execution prevents further admission and preserves uncertain-effect accounting.
- Infinite loops, oversized source/results/checkpoints, recursion, print floods and blocked IPC terminate within configured bounds while the driver stays responsive.
- A script failure after a successful mutation leaves that mutation's durable record and receipt intact.
- Budget and deadline survive repeated restores. Logs do not duplicate after restoring an earlier checkpoint.
- Existing direct-call behavior and durable recovery checks continue to pass.

## Implementation sequence

1. Pin a Monty revision/version compatible with Bee's toolchain. Build a worker spike that suspends, dumps, exits, restores and resumes with a supplied result; verify memory and parent timeout enforcement. Use controlled fixtures and no production tool authority.
2. Add versioned composition state, protected checkpoint storage, child identity bindings and reducer/store tests for persistence ordering and recovery. Define compatibility rejection/migration for existing sessions.
3. Connect real child dispatch to the durable adapter, budgets, consent and evidence. Prove recovery with a mutation fixture and crash injection before broadening tool exposure.
4. Advertise the outer tool and bounded catalog in durable batch and REPL sessions, add nested transcript presentation and diagnostics, and run the acceptance matrix.

Monty is selected; these gates validate its integration rather than reopen an engine contest. If a required API or packaging constraint is unsupported, report the specific blocker before changing the runtime choice.

## Sources

- [Monty Rust guide](https://pydantic.dev/docs/monty/quickstart/rust/): Rust suspension API and worker integration.
- [Snapshot contract](https://pydantic.dev/docs/monty/concepts/snapshots/): serialized continuation and restore trust requirements.
- [Resource limits](https://pydantic.dev/docs/monty/limitations/resource_limits/): allocator and host enforcement responsibilities.

Upstream documentation checked 2026-10-31. The isolated [worker spike](spike/README.md) pins and builds Monty 1.4.0 on Rust 1.96. Its continuation, interpreter limits, allocator ceiling and parent watchdog tests pass. Bee production dependencies are unchanged; its application requirement and development/CI toolchain now target Rust 1.96 to support Monty 1.4.0. Production packaging, durable storage and driver integration remain pending. Requirements above are proposed Bee behavior, not claims that Monty already provides a durable tool scheduler.

## Implementation progress

See [implementation.md](implementation.md) for the durable composition foundation, database/snapshot v7 migration, storage bounds, recovery tests and remaining session-driver integration.
