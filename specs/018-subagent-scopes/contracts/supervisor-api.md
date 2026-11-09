# Contract: Supervisor and SupervisorHandle

**Feature**: 018-subagent-scopes | Consumers: `src/supervisor.rs`, `src/sandbox.rs`,
`src/delegate.rs`, `src/grants/escalate.rs`, `src/concurrent.rs`, `src/app/session.rs`

The `Supervisor` is the session-scoped owner of enforcement. It exists because `aya::Ebpf` is not
`Send` and must outlive every scope, which made scopes uncreatable from anywhere but the one task
holding the sandbox (research R2).

## Ownership rules

1. **One supervisor per session.** It owns `Engine` and `AuditDemux` for the session's whole life.
2. **The engine is dropped last**, after every scope has been torn down. Dropping it detaches the LSM
   programs, so a process surviving into that moment becomes unenforced — the failure this ordering
   exists to prevent.
3. **All map writes happen on the supervisor task.** BPF map writes are not concurrent; this is already
   the concurrent runner's rule (`src/concurrent.rs:3`) and it is now the only rule, for every caller.
4. Callers hold a `SupervisorHandle`: `Clone + Send`, an mpsc sender with `oneshot` replies. There is
   no other route to the engine.

## Command set

```rust
enum Command {
    CreateScope {
        scope_id: String,
        parent: Option<ScopeId>,        // BOOKKEEPING ONLY — teardown order + attribution.
                                        // Every cgroup is created FLAT under DEFAULT_PARENT.
        plan: EnforcementPlan,          // ALREADY compiled and validated by the caller
        reply: oneshot::Sender<Result<ScopeGrant, ScopeError>>,
    },
    Reload {
        scope: ScopeId,
        plan: EnforcementPlan,
        reply: oneshot::Sender<Result<(), ScopeError>>,
    },
    Teardown {
        scope: ScopeId,                 // tears children down first
        reply: oneshot::Sender<Result<(), String>>,
    },
    Shutdown { reply: oneshot::Sender<()> },   // tear down all, stop the demux, drop the engine
}

pub struct ScopeGrant {
    pub scope_id: ScopeId,
    pub cgroup_id: u64,
    pub audit: AuditSubscription,       // subscribed BEFORE this reply is sent
}
```

### `CreateScope`

**Takes an `EnforcementPlan`, never a `Policy`.** This is the load-bearing part of the contract: a
plan can only be produced by `policy.compile(&resolver)` then `EnforcementPlan::prepare(...)`, and for
a subagent that policy can only have come from `parent.active().derive(declared)`. There is therefore
**no route to a scope that skipped attenuation** — not a convention, a type-level fact.

- Subscribes to the demux for the new `cgroup_id` **before** replying, so no early event is missed
  (the rule `src/concurrent.rs:185` already states for concurrent episodes).
- `parent: Some(id)` records a **userspace** parent for teardown ordering and record attribution. The
  cgroup itself is created **flat** under `DEFAULT_PARENT`, as a sibling.

  **Do not "fix" this by nesting.** `resolve_scope` (`crates/ebpf/src/main.rs:97`) falls back to an
  ancestor walk from the root downward and returns the **shallowest** registered scope. Nest a child
  inside its parent and a subagent that `mkdir`s a sub-cgroup and migrates into it resolves to the
  **parent** scope — acquiring the parent's broader rules, enforced and audited as if correct. Flat
  layout makes the child scope the only scope ancestor, so the same migration still resolves to the
  child. See research R5 for the rejected alternative (deepest-match `resolve_scope`, an eBPF change
  with verifier-budget risk).
- On any failure, removes whatever it created and returns `Err`. No partial scope survives.

### `Reload`

Replaces `Sandbox::reload`'s engine access. Preconditions unchanged from 007
(`specs/007-dynamic-grants/contracts/reload-api.md`): no sandboxed child is executing in the scope (a
turn boundary), and the plan came from a policy already validated `⊆ ceiling`.

**This is where SC-007 is delivered.** Today `Sandbox::Concurrent::reload` returns
`Err("reload unsupported on a concurrent sandbox (engine owned by the runner)")`
(`src/sandbox.rs:94`) — dynamic grants are simply dead under the concurrent runner. Routing through
the handle makes reload work identically for a single session, a concurrent episode, and a subagent.

On error the prior enforced maps are left in place — unchanged from `EnforcedSandbox::reload`, and the
fail-closed direction.

### `Teardown`

Walks the supervisor's own `ScopeRecord` forest, **children-first**, and for each scope:

1. `kill_scope_cgroup` (prefers `cgroup.kill`, atomic over that cgroup's own subtree and unraceable by
   a fork).
2. `unsubscribe` it from the demux.
3. `rmdir` its cgroup.

Because the layout is flat, a parent's `cgroup.kill` does **not** reap its children as a side effect —
each child is its own sibling cgroup. The explicit children-first walk is therefore load-bearing, not
a tidiness measure: skip it and a subagent process outlives the engine drop and becomes unenforced.
The supervisor must do this walk anyway to unsubscribe each child from the demux.

`rmdir` returning `EBUSY` means processes survived the kill. That error is **reported, never
swallowed** — it surfaces on the existing operator warning path (`src/episode.rs:741`). A teardown
failure makes the delegation `Failed`, never `Completed` (FR-022).

### `Shutdown`

Tears down every remaining scope children-first, stops the demux task, then drops the engine. Called
once, by whoever owns the session.

## Sandbox as a handle

```rust
pub struct Sandbox {
    scope:     Option<ScopeRef>,       // None ⇒ host mode
    audit:     Option<AuditSubscription>,
    handle:    Option<SupervisorHandle>,
    strip_env: Vec<String>,
}
```

- `Send`. This is the whole point: a child loop, or a spawned sibling, can hold one.
- `drain_audit()` reads the subscription and **stamps `AuditEvent.scope_id`** with this scope's id
  before returning. Host mode returns empty.
- `reload(policy)` compiles, prepares, and sends `Reload`. Host mode is a no-op `Ok` (nothing to
  enforce), which is the existing behaviour.
- `tool_command(...)` is **unchanged**: same `hardened_command`, same cgroup-join `pre_exec`, same
  env allowlist (`INHERITED_ENV_VARS` minus `strip_env`).

### Why a tool's `&Sandbox` reaching the handle is safe

A tool can technically call `sandbox.reload(...)`, and could before this change too. What it cannot do
is create a scope: `CreateScope` demands an `EnforcementPlan`, which requires a `Policy` a tool has no
way to obtain — the parent's `ActivePolicy` lives in the loop, not the sandbox. And the `task` tool
never touches the sandbox at all; it returns a `DelegationRequest` and the loop does the work
(`task-tool.md`). Recorded in the plan's Complexity Tracking rather than assumed.

## Migration: every construction site

Slice 1 must land with **no behaviour change**. Its success criterion is that the existing test suite
and the VM matrix pass unchanged.

| Site | Today | After |
|---|---|---|
| `src/app/session.rs:296` `build_sandbox` | builds `Engine` + `Scope` + reader | `build_supervisor` → session `ScopeGrant` → `Sandbox` |
| `src/episode.rs:876` `build_enforced_sandbox` | same, per episode | supervisor `CreateScope` |
| `src/episode.rs:664` | `Sandbox::host` | `Sandbox::host` (unchanged shape, no handle) |
| `src/concurrent.rs:200` | `Sandbox::concurrent` | `Sandbox` from a `ScopeGrant`; runner keeps sequential scope creation and now *gains* reload |
| `src/grants/escalate.rs:125` | `sandbox.reload(...)` | unchanged call, different implementation |
| test fixtures (`tools/finding.rs:404`, `tools/skill.rs:149`, `grants/escalate.rs:377`, `repl.rs:1362`, `mcp/bridge.rs:382`) | `Sandbox::host(...)` | unchanged |

The `concurrent` Cargo feature becomes a deprecated alias of `enforce`, since the demux is now the
only audit path (research R4).
