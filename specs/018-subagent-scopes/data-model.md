# Phase 1 Data Model: Subagent Delegation Under Attenuated Scopes

**Feature**: 018-subagent-scopes | **Date**: 2026-08-09

Entities, their fields, the invariants that must hold over them, and how they change state. Types are
given in Rust shorthand for precision; the *rules* are the contract, not the syntax.

---

## AgentDefinition

An operator-authored, delegable agent. Discovered by the existing `SkillRegistry` pass from
`.claude/skills` (project) then `~/.claude/skills` (user), distinguished by `kind: agent`.

| Field | Type | Rule |
|---|---|---|
| `name` | `String` | Required. Unique within a root; earlier root wins and shadowing warns. |
| `description` | `String` | Required. The only text the delegating model sees when choosing. Never truncated. |
| `kind` | `Kind::Agent` | Required to be an agent; absent or `skill` ⇒ ordinary skill, unchanged behaviour. |
| `tools` | `Vec<String>` | Required, may be empty. Must be a subset of the parent's registry at delegation time. |
| `turn_limit` | `u32` | Required. The child's own cap; the effective cap is `min(turn_limit, budget.turns_remaining)`. |
| `requires` | `Option<SkillRequires>` | The declared capability surface. Absent ⇒ the child inherits the parent's policy wholesale via `derive`. |
| `dir`, `skill_md` | `PathBuf` | As for skills. The body is the child's instructions, read lazily. |
| `source` | `SkillSource` | `Project` \| `User`, for precedence and diagnostics. |

**`SkillRequires` extension.** Today it carries `tools` and `filesystem` (`src/skills.rs:49`). It
gains `exec: Vec<String>` and `net: Vec<String>` so a declaration covers everything `GrantDelta`
already models. Both default empty; existing skills are unaffected.

**Validation**
1. Malformed frontmatter ⇒ `SkillLoadError` warning, omitted from the registry, session continues.
2. `kind: agent` with no `description` ⇒ malformed (the model cannot choose blind).
3. A name shadowed across roots ⇒ warning naming both paths; the project one wins.
4. `requires.filesystem` values outside `read`/`write`/`deny` ⇒ malformed.

**Not validated at discovery**: whether the declaration is within any parent's authority. That is
per-delegation (a session's active policy is not known at discovery, and the same definition is
legitimately usable from parents of differing authority).

---

## DelegationRequest

What the `task` tool returns instead of doing the work. Carried on `ToolResult`, never shown to the
model, exactly as `render_spec` is (`src/tools.rs:136`).

```rust
pub struct DelegationRequest {
    pub agent: String,   // resolved name — the tool already proved it exists
    pub prompt: String,  // the task, written by the parent model
}
```

`ToolResult` gains one field:

```rust
#[serde(default, skip_serializing_if = "Option::is_none")]
pub delegate: Option<DelegationRequest>,
```

**Invariant**: a `ToolResult` reaching the model's conversation always has `delegate == None` — the
loop consumes it and replaces `content` with the report. A `delegate` value surviving into a
`Message::ToolResult` is a bug, and is the assertion the round-trip test makes.

---

## DelegationCtx

Threaded into a child's `LoopOptions`; what makes the tree bounded and attributable.

| Field | Type | Rule |
|---|---|---|
| `depth` | `u32` | Parent's + 1. A child at `depth >= max_depth` gets no `task` tool, and the loop refuses a request anyway (R10). |
| `max_depth` | `u32` | Operator-configured, default `1`. |
| `parent_scope_id` | `String` | The cgroup the child's cgroup nests under, and the attribution parent in the record. |
| `spawn_ceiling` | `Policy` | **Clone of the parent's active policy at spawn.** The child's escalation ceiling; a later parent narrowing does not touch it. |
| `budget` | `Budget` | Cloned handle onto the *same* counters (not a copy of the values). |

---

## Budget

One pool per session. Children draw from it; they never replenish it.

```rust
pub struct Budget {
    turns:    Arc<AtomicU32>,   // remaining, saturating at 0
    tokens:   Arc<AtomicU64>,   // remaining ceiling; u64::MAX ⇒ uncapped
    deadline: Instant,          // shared wall clock, Copy
}
```

**Rules**
1. A loop decrements `turns` **before** the model call, and stops when the decrement would underflow.
2. Every loop in the tree checks the same `deadline`; a child never gets a later one.
3. Exhaustion ends a child with a **cut-short** report, never a completed one (FR-024).
4. Concurrent siblings draw from the same counters, so exhaustion stops all of them (US5 AS-4) rather
   than each spending the remainder.
5. Initial values come from `scenario.turn_limit` / `scenario.timeout()`, so a session that never
   delegates is behaviourally identical to today.

---

## Supervisor and SupervisorHandle

The session-scoped owner of enforcement. See `contracts/supervisor-api.md` for the command set.

```rust
pub struct Supervisor {          // !Send — lives on one task for the session's life
    engine: Engine,              // must stay alive or every scope loses enforcement
    demux:  AuditDemux,
    scopes: HashMap<ScopeId, ScopeRecord>,
}

pub struct ScopeRecord {
    cgroup_id: u64,
    cgroup_path: PathBuf,        // ALWAYS flat: <DEFAULT_PARENT>/<scope_id>
    parent: Option<ScopeId>,     // USERSPACE forest only — teardown order + attribution.
                                 // Never cgroup nesting; see research R5.
    net_keys: Vec<NetKey>,       // as today, for narrowing reloads
}

#[derive(Clone)]
pub struct SupervisorHandle { tx: mpsc::Sender<Command> }  // Send + Clone
```

**Invariants**
- `engine` is dropped **last**, after every scope is torn down. Dropping it detaches the LSM programs,
  so any surviving process becomes unenforced.
- Scope creation and every map write happen on the supervisor task only — never concurrently.
- `scopes` forms a **userspace** forest; teardown of a node tears its children down first. Since every
  cgroup is flat, a parent's `cgroup.kill` does not reap children implicitly — the explicit walk is
  what prevents a subagent process from outliving the engine.
- `rmdir` returning `EBUSY` means the kill left survivors; reported, never swallowed.

---

## Sandbox (reworked)

Collapses from three variants to one `Send` struct.

```rust
pub struct Sandbox {
    scope:     Option<ScopeRef>,      // None ⇒ host mode, no kernel scope
    audit:     Option<AuditSubscription>,
    handle:    Option<SupervisorHandle>,
    strip_env: Vec<String>,
}
```

**Rules**
1. `scope.is_none()` is host mode: `drain_audit` returns empty, `reload` is a no-op `Ok`, and every
   delegation made from it is marked **unenforced** in the record (FR-032).
2. `drain_audit` stamps `AuditEvent.scope_id` with this sandbox's scope id before returning. The field
   has existed since 001 (`crates/core/src/audit.rs:15`) and is `None` on every event today.
3. `reload` forwards to the supervisor handle. It no longer returns `Err` merely because the caller is
   concurrent — that limitation was engine ownership, and it is gone (FR-021).
4. Child-process spawning (`tool_command`) is unchanged: same `hardened_command`, same env allowlist.

---

## DelegationRecord

What a delegation leaves in the transcript. Nested rather than flattened, so a subagent's turns are
never mistaken for the parent's.

`RecordedCall` gains one optional field:

```rust
#[serde(default, skip_serializing_if = "Option::is_none")]
pub child: Option<Box<DelegationRecord>>,
```

```rust
pub struct DelegationRecord {
    pub agent: String,
    pub scope_id: String,
    pub enforced: bool,          // false ⇒ host mode / non-enforce build (FR-034)
    pub depth: u32,
    pub outcome: DelegationOutcome,
    pub transcript: EpisodeTranscript,   // the child's own turns, verbatim
    pub turns_used: u32,
    pub tokens_used: u64,
}

pub enum DelegationOutcome {
    Completed,
    CutShort { reason: CutShortReason },  // Turns | Deadline | Tokens
    Refused  { reason: RefusalReason },   // see contracts/task-tool.md
    Failed   { detail: String },          // scope creation, teardown, infra
}
```

**Invariants**
1. `child` is `None` on every call that is not a delegation — a transcript from a non-delegating
   session serializes identically to one produced before this feature (SC-006).
2. A subagent's audit events appear in **its own** `transcript.audit_trail`, stamped with its
   `scope_id`, and **not** in the parent's. Exactly-once across the tree (FR-018, SC-004).
3. `outcome == Completed` requires the child's loop to have finished *and* its scope to have torn down
   cleanly. A teardown failure yields `Failed`, and the parent is not told the delegation was clean
   (FR-022).
4. `enforced` is recorded from the sandbox at spawn, not inferred at read time from build features.

---

## State transitions

A delegation, from the model's call to the parent's next turn:

```
        task(agent, prompt)
                │
        ┌───────▼────────┐  name unknown / tool not held / depth exceeded
        │ resolve + args ├──────────────────────────────► Refused (no scope)
        └───────┬────────┘
                │ DelegationRequest on ToolResult
        ┌───────▼────────┐  derive() fails
        │  derive policy ├──────────────────────────────► Refused (no scope)
        └───────┬────────┘
                │ child policy ⊆ parent.active(), proven
        ┌───────▼────────┐  create_scope / plan fails
        │  spawn  scope  ├──────────────────────────────► Failed
        └───────┬────────┘
                │ subscribed to demux BEFORE the loop starts
        ┌───────▼────────┐  budget exhausted
        │  child run_loop├──────────────────────────────► CutShort
        └───────┬────────┘
                │
        ┌───────▼────────┐  scope will not empty
        │ teardown child ├──────────────────────────────► Failed (+ operator warning)
        └───────┬────────┘
                │
             Completed  ──►  bounded report replaces ToolResult.content
```

**Ordering rules that are not negotiable**
- Subscribe to the demux **before** the child's first tool call, or early events are lost (the
  concurrent runner already states this: `src/concurrent.rs:185`).
- Derive **before** any cgroup exists, so a refusal leaves nothing behind (FR-010).
- Tear the child's scope down **explicitly**, before the parent's, and before the engine drops. Flat
  layout means nothing reaps it implicitly (R5).
