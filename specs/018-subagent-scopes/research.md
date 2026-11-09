# Phase 0 Research: Subagent Delegation Under Attenuated Scopes

**Feature**: 018-subagent-scopes | **Date**: 2026-08-09

All Technical Context unknowns are resolved here. Each entry records the decision, why, and what was
rejected. Nothing below changes `bee-core`.

---

## R1 — A tool cannot spawn a subagent through the `Tool` trait

**Problem**: `Tool::call(&self, arguments: serde_json::Value, sandbox: &Sandbox) -> ToolResult`
(`src/tools.rs:244`) hands a tool an **immutable** `&Sandbox` and nothing else — no model, no
registry, no policy, no budget, no way to create a scope. A delegation tool cannot do its job from
inside that signature.

**Decision**: **Side-channel the request on `ToolResult`**, exactly as `render` already does.

`render` does not draw anything. It validates its script and returns
`ToolResult { render_spec, panel_ops, .. }`, which the loop and front-end act on and which the model
never sees (`src/tools.rs:136-151`). Delegation takes the same shape:

- `task` resolves the agent name against its `Arc<AgentRegistry>`, validates arguments, and returns
  `ToolResult { delegate: Some(DelegationRequest { agent, prompt }), .. }`.
- The **loop** owns the act: it derives the policy, asks the supervisor for a scope, runs the child,
  and replaces `content` with the child's report before the result reaches the conversation.

**Rationale**: One new optional field on a type that already carries four such fields; zero change to
the trait; every existing tool untouched. It also puts derivation where the parent's *active* policy
actually lives — the loop's `ActivePolicy` (`src/grants/mod.rs:135`) — rather than smuggling a
policy handle into a tool.

**Alternatives rejected**:
- *Widen the `Tool` trait to a context object.* ~20 implementations across `src/tools/`, plus every
  test fixture, for one caller's benefit.
- *Name-match `"task"` in the loop.* `run_loop` is deliberately tool-name-agnostic; it reads
  `result.terminal`, not names (`src/episode.rs:389`). A second name special-case erodes that.

---

## R2 — Engine ownership: a supervisor actor with a `Send` handle

> **Superseded 2026-11-09** (see plan.md "Refresh"). The engine is now `Send` — `src/call.rs:583`
> asserts `run_call`'s future is `Send` while holding a `Sandbox::Enforced` that owns it. The
> supervisor is a shared `Arc` with the engine behind a `Mutex`, not an actor. The decision's
> substance — one session-owned owner of engine + demux, every scope created through it — stands.

**Problem**: `EnforcedSandbox` owns `bee_userspace::Engine` (`src/sandbox.rs:58`), which owns
`aya::Ebpf` and is **not `Send`**. The engine must stay alive for the whole session or the LSM
programs detach. So a child loop cannot be given a scope, siblings cannot be created, and
`Sandbox::Concurrent::reload` is a hard `Err` (`src/sandbox.rs:94`) because the concurrent runner —
not the sandbox — owns the engine.

**Decision**: A harness-level **`Supervisor`** owns `Engine` + `AuditDemux` and runs as a task.
Everything else holds a **`SupervisorHandle`**: `Clone + Send`, an mpsc command channel with
`oneshot` replies — `CreateScope`, `Reload`, `Teardown`, `Unsubscribe`. `Sandbox` collapses to one
`Send` struct: `{ scope: Option<Scope>, audit: AuditSubscription, handle: SupervisorHandle,
strip_env: Vec<String> }`.

**Rationale**: The standard actor treatment of a non-`Send` resource, and the only shape that serves
all three callers uniformly — a single session, concurrent episodes, and a subagent tree. Making
*every* path use the handle (including the parent's, which could have borrowed `&mut`) means one code
path rather than two, and delivers FR-021/SC-007 — reload under concurrency — as a side effect rather
than as separate work.

**Alternatives rejected**:
- *Parent lends `&mut engine` to children.* Sequential only; forecloses US5; leaves the concurrent
  reload gap.
- *`unsafe impl Send` on the engine wrapper.* Unsound, and Constitution I forbids trading a proof for
  a convenience.
- *A second engine per subagent.* `load_and_attach` per delegation is expensive, and multiple attached
  copies of the same LSM programs is not a configuration this project has ever tested.

---

## R3 — Audit attribution across a scope tree

**Problem**: `EnforcedSandbox::drain_audit` keeps only `ev.cgroup_id == own scope`
(`src/sandbox.rs:238`). A subagent's denials would be dropped in silence — and by the constitution's
own gate, "a denial that no test exercises is not considered enforced."

**Decision**: Every scope — parent, sibling episode, subagent — is a **demux subscription**.
`AuditDemux` (`crates/userspace/src/audit_demux.rs`) already routes one ring to per-`cgroup_id`
subscribers and drops unsubscribed events; it needs no change. On drain, the sandbox **stamps
`AuditEvent.scope_id`** with its own scope id.

**Rationale**: `AuditEvent.scope_id: Option<String>` already exists in the schema
(`crates/core/src/audit.rs:15`) and is populated nowhere — it is `None` on every event today. This
feature is what it was reserved for. No transcript schema change is needed for attribution; only the
field starts carrying a value, which keeps SC-006 (existing consumers read unchanged) cheap to honour.

**Alternatives rejected**:
- *Widen the parent's cgroup filter to a scope set.* Re-introduces cross-attribution — the parent's
  drain would pull a child's events into the parent's turn — which is precisely what SC-004 forbids.

---

## R4 — Feature wiring, and why Constitution V still holds

**Problem**: The supervisor needs the async demux, which lives behind `bee-userspace/tokio`. Today the
app's `enforce` feature deliberately does *not* pull it, so a plain enforce build stays
async-runtime-free; `concurrent = ["enforce", "bee-userspace/tokio"]` is the only path that does.

**Decision**: In the **application** package, `enforce = ["bee-userspace/enforce",
"bee-userspace/tokio"]`. `concurrent` becomes a deprecated alias of `enforce`. **`bee-userspace`'s own
feature set is unchanged** — its synchronous `events::AuditReader` path stays exactly as it is.

**Rationale**: Constitution V constrains the *core* ("the core policy engine MUST NOT require an async
runtime"). `bee-core` and `bee-common` are untouched. A library embedder using `bee-userspace` with
`enforce` and no async keeps the sync reader. What changes is only that the `bee` binary — which has
required tokio since 002 for `rig-core` and every async tool — now uses the async audit path it was
already compiling under `concurrent`. Recorded in Complexity Tracking, not waved past.

---

## R5 — cgroup topology for child scopes

**Decision**: Create every subagent's cgroup **flat** under `DEFAULT_PARENT`
(`/sys/fs/cgroup/bee`, `crates/userspace/src/cgroup.rs:14`), as a *sibling* of its parent's scope
cgroup — **not** nested inside it. The parent/child relationship is tracked in the supervisor's
userspace `ScopeRecord.parent`, which is what orders teardown children-first.

**This reverses the obvious answer, and the reason is in the kernel.** `resolve_scope`
(`crates/ebpf/src/main.rs:97`) tries the exact current cgroup first, and on a miss walks ancestors
**from the root downward** (`level = 0, 1, 2 …`), returning the **first** — that is, the
**shallowest** — ancestor registered in `SCOPES`. That walk exists to keep a process enforced after it
`mkdir`s a sub-cgroup and migrates into it, which would otherwise be an escape.

Now nest a child scope inside its parent's cgroup and replay that same escape:

| Layout | Tool child sits directly in its scope | Process migrates into a sub-cgroup it created |
|---|---|---|
| **Nested** | exact match → child's rules ✅ | ancestor walk finds the **parent** first (shallower) → **parent's broader rules** ❌ |
| **Flat** | exact match → child's rules ✅ | ancestor walk finds the child scope (the only scope ancestor) → child's rules ✅ |

So under nesting, the very manoeuvre the ancestor walk was added to defeat becomes a **silent
attenuation escape**: a subagent that migrates gains its parent's authority, enforced and audited as
though nothing were wrong. That is precisely the failure this feature exists to prevent, and it would
be invisible. Flat layout has no such path.

**What flat costs, and how it is paid**: `kill_scope_cgroup` can no longer reap a child's processes as
a side effect of the parent's atomic subtree `cgroup.kill`. The supervisor therefore tears children
down **explicitly and first**, walking its own `ScopeRecord` forest — which it must do anyway to
unsubscribe each child from the demux. `rmdir` `EBUSY` remains the leak signal, surfaced on the
existing teardown-warning path (`src/episode.rs:741`).

**Rejected alternative**: nest, and change `resolve_scope` to return the **deepest** matching
ancestor. That is a correct fix in principle, but it means replacing an early-returning scan with one
that must visit all 16 levels and keep the best hit — the exact no-early-return shape that has already
blown the verifier's instruction budget in this codebase once (the most-specific-wins rule ranking,
which had to be moved to load-time sorting for the same reason). Not worth taking on inside a feature
that has a zero-eBPF-change option.

**Documentation caveat that stands regardless of layout**: a scope's rules are found by *identity*,
not by inheritance — `resolve_scope` looks for a cgroup registered in `SCOPES` and applies **that
scope's own rule list**. There is no merging of a parent's and a child's rules in the kernel.
Attenuation is guaranteed entirely by `Policy::derive` at install time. Any document that lets a
reader assume the kernel composes a policy from a cgroup chain is wrong.

**Note on TRIAGE.md:92**, which reads "All three LSM hooks use only the exact current cgroup ID and
allow when SCOPES lacks it": that finding described the pre-`resolve_scope` code and is **fixed** —
the ancestor walk is the fix. Anyone planning from that entry alone would reach the wrong conclusion
here, in both directions.

---

## R6 — Agent definitions extend the skills loader

**Decision**: Add an optional `kind: skill | agent` key to the existing frontmatter
(`src/skills.rs:66`, `Frontmatter`), defaulting to `skill`. Agents are discovered from the same roots
in the same pass — project `.claude/skills`, then user `~/.claude/skills`
(`SkillRegistry::default_roots`) — and the registry partitions by kind.

**Rationale**: A skill and an agent already differ in exactly one way — whether the body is injected
into the current agent or delegated to a child. Everything else is shared and already built:
discovery, precedence, `SkillLoadError` warnings that never abort a session, `SkillRequires` →
`GrantDelta`, and consent wiring. A second loader would mean a second warnings path and a second
consent story to keep in sync, for no new capability.

`SkillRequires` gains `exec` and `net` lists (it has `tools` + `filesystem` today) so an agent can
declare the whole policy surface `GrantDelta` already models (`src/grants/mod.rs:30`).

**Rejected**: a separate `.bee/agents/` format (the user considered and declined this).

---

## R7 — Two loops, one delegation helper

**Problem**: There are two turn loops — `episode::run_loop` (`src/episode.rs:140`, headless) and the
REPL's `run_exchange` (`src/repl.rs`, ~line 651 for the audit-drain/escalation block). 007 duplicated
its escalation logic across both.

**Decision**: One `src/delegate.rs` helper, `run_delegation(...)`, called from both loops at the same
point — after a tool result carrying a `DelegationRequest`, before the result enters the conversation.

**Rationale**: 007's own SC-006 already sets the precedent in the other direction — "`run_loop` and
`run_exchange` share one hooks lifecycle; the tool-execution/audit-drain path is not duplicated."
Delegation is more intricate than escalation (scope creation, budget, nested transcript, teardown);
duplicating it would guarantee drift in the security-relevant path.

---

## R8 — Shared budget

**Decision**: A `Budget` handle in `LoopOptions`, cloned into children: `AtomicU32` turns remaining,
a shared `Instant` deadline, `AtomicU64` token ceiling. A child debits the same counters the parent
draws from. Token spend rides the existing `metrics::Recorder` (`src/metrics.rs`), with child records
carrying the parent's run id for attribution.

**Rationale**: The alternative — per-child limits — makes `task` an unbounded multiplier of both cost
and wall-clock, which is the failure mode that makes delegation unusable in practice even when it is
perfectly safe. `scenario.turn_limit` and `scenario.timeout()` become the pool's initial values, so a
session that never delegates behaves identically.

---

## R9 — Derivation semantics

**Decision**: `child_policy = parent.active().derive(agent_declared_policy)?`, one call to the
existing, property-tested validator (`crates/core/src/attenuation.rs:75`).

**Rationale**: `derive`'s `inherit_restrictions` step is what makes an agent declaration *subtractive*:
a child stating no filesystem rules inherits the parent's map wholesale, and a child that does state
rules re-acquires every parent `Deny`. So FR-011 — "a subagent MUST NOT gain authority by omission" —
is already the validator's behaviour rather than new logic. Mode may only stay the same or become
stricter, which gives the mode half of attenuation for free.

The child's escalation ceiling is a **clone of the parent's active policy taken at spawn**, so a later
parent narrowing cannot rewrite a running child (spec Assumptions), and the child's own escalations
are bounded by what the parent actually held.

**Property test** extends 007's existing harness (`src/grants/mod.rs:509`) from one `ActivePolicy` to a
tree: no reachable sequence of delegate/escalate/expire/release places any descendant's active policy
outside its ancestor's.

---

## R10 — Delegation depth and the registry subset check

**Decision**: Depth is carried in a `DelegationCtx` threaded into the child's `LoopOptions`; a child
at `depth >= max_depth` (default 1) has the `task` tool omitted from its registry entirely, *and* the
loop refuses a delegation request if one arrives anyway.

**Rationale**: Belt and braces, in the project's idiom — omitting the tool is how a capability is
normally withheld, and the loop-side refusal is the fail-closed backstop for a registry built wrong.
The same double check applies to FR-012: an agent's `tools` list is intersected with the parent's
registry, and a name the parent lacks is a refusal naming the tool (US1 AS-3), not a silent drop.

---

## Resolved Technical Context

| Unknown | Resolution |
|---|---|
| How a tool spawns a subagent | R1 — `DelegationRequest` on `ToolResult`; the loop acts |
| Who owns the engine | R2 — `Supervisor` actor + `Send` handle; `Sandbox` becomes one struct |
| How child audit is attributed | R3 — per-scope demux subscription; stamp `AuditEvent.scope_id` |
| Async runtime and Constitution V | R4 — app `enforce` pulls `bee-userspace/tokio`; the crate's own features and sync path unchanged |
| cgroup layout | R5 — **flat**, siblings under `/sys/fs/cgroup/bee`; nesting would let a migrating child inherit its parent's rules via the shallowest-first ancestor walk |
| Where agent definitions live | R6 — `kind: agent` in existing skill frontmatter, same roots |
| Duplication across two loops | R7 — one `delegate::run_delegation` helper |
| Budget model | R8 — shared atomic pool in `LoopOptions` |
| Attenuation mechanism | R9 — `parent.active().derive(declared)`; tree property test |
| Depth enforcement | R10 — omit the tool *and* refuse in the loop |
