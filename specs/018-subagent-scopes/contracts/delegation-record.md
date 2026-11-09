# Contract: The Delegation Record

**Feature**: 018-subagent-scopes | Consumers: `src/transcript.rs`, `src/delegate.rs`,
`src/sandbox.rs`, `src/metrics.rs`

What a delegation leaves behind, and the compatibility rules that keep every existing transcript
consumer working (SC-006).

## Nesting

`RecordedCall` gains exactly one optional field:

```rust
pub struct RecordedCall {
    pub call: ToolCall,
    pub result: ToolResult,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit: Vec<AuditEvent>,
    /// The subagent this call delegated to (018). Absent on every non-delegating call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child: Option<Box<DelegationRecord>>,
}
```

**Compatibility rules**
1. `#[serde(default)]` + `skip_serializing_if` means a session that never delegates produces
   byte-identical JSON to today, and an old transcript deserializes unchanged.
2. No existing field changes type, meaning, or presence.
3. `EpisodeTranscript` itself is unchanged, so `DelegationRecord.transcript` is the same type at every
   depth. One shape, recursively.

## The record

```rust
pub struct DelegationRecord {
    pub agent: String,
    pub scope_id: String,
    pub enforced: bool,
    pub depth: u32,
    pub outcome: DelegationOutcome,
    pub transcript: EpisodeTranscript,
    pub turns_used: u32,
    pub tokens_used: u64,
}
```

`enforced` is captured **from the sandbox at spawn**, not inferred at read time. A reader must be able
to tell an unenforced delegation from an enforced one without knowing which features the binary was
built with (FR-034) — a transcript outlives the build that produced it.

## Audit attribution

The rule, in one sentence: **every kernel decision appears exactly once in the tree, in the transcript
of the scope that produced it, stamped with that scope's id.**

- `Sandbox::drain_audit` stamps `AuditEvent.scope_id` with its own scope id before returning. The
  field has existed since 001 (`crates/core/src/audit.rs:15`) and is `None` on every event emitted
  today; this feature is what it was reserved for.
- A child's events land in `DelegationRecord.transcript.audit_trail` and in that transcript's
  per-call `audit` vectors. They are **not** copied into the parent's `audit_trail`.
- No de-duplication is needed, because the demux routes each event to exactly one subscriber by
  `cgroup_id` and each scope has exactly one subscription.

**Why not merge child events into the parent's trail**: `EpisodeTranscript::denials()` and
`ScoreReport::from_transcript` (`src/transcript.rs`) both read `audit_trail`. Merging would silently
change what a CTF score counts and what a denial report shows, for every existing consumer. A reader
that *wants* the whole tree walks it; the default stays own-scope.

### Whole-tree access

```rust
impl EpisodeTranscript {
    /// Every audit event in this transcript and every descendant delegation, in tree order.
    pub fn audit_tree(&self) -> impl Iterator<Item = &AuditEvent>;
    /// Every delegation in this transcript, depth-first.
    pub fn delegations(&self) -> impl Iterator<Item = &DelegationRecord>;
}
```

Additive. `denials()`, `audit_trail`, and the score keep their current, own-scope meaning; where a
score covers a tree, `ScoreReport` states which scopes it counted (spec US3 AS-4).

## Budget accounting

| Field | Source | Rule |
|---|---|---|
| `turns_used` | the child's loop | Debited from the shared `Budget.turns` as they are consumed, not reconciled afterwards |
| `tokens_used` | `metrics::Recorder` | Child `CallRecord`s carry the parent's run id, so `bee metrics` attributes a delegation to the session that caused it |

A child's `CallRecord`s go to the same recorder as the parent's. The run id is
`"<parent-run-id>/<agent>@<depth>"`, so per-agent cost is groupable without a schema change.

**Invariant**: `sum(turns_used over the tree) + parent turns <= the session's initial turn budget`.
This is the assertion behind SC-005, and it is checkable directly from a transcript.

## Outcomes

```rust
pub enum DelegationOutcome {
    Completed,
    CutShort { reason: CutShortReason },   // Turns | Deadline | Tokens
    Refused  { reason: RefusalReason },    // see task-tool.md
    Failed   { detail: String },
}
```

- `Refused` records a delegation that never got a scope. It is still recorded — a refusal is
  information about what the model tried, and dropping it would make the record less truthful than the
  session.
- `Completed` requires **both** that the child's loop finished and that its scope tore down cleanly. A
  teardown failure is `Failed`, and the parent's report says so (FR-022).
- `CutShort` is never reported to the model as completion; the harness-authored status line in the
  report carries it (`task-tool.md`).

## Progress output

The existing `ProgressSink` (`src/episode.rs:22`) gains delegation lines, indented by depth so a
fan-out is readable:

```
  call task {"agent":"test-runner",…}
  delegate 'test-runner' → scope bee-sub-test-runner-1 (enforced, depth 1)
    turn 0
    call bash {"command":"cargo test"}
    result ok (exit 101): test result: FAILED. 2 passed; 1 failed
    audit: connect denied api.crates.io:443
  delegate 'test-runner' ← completed, 3 turns, 1 denial
```

A denial inside a child appears under the child's indentation, not the session's — the operator-facing
half of the same attribution rule the transcript enforces.

## Test assertions this contract implies

1. A non-delegating session's transcript JSON is byte-identical to a pre-018 run (SC-006).
2. A parent and child both performing denied operations: each denial appears exactly once, under the
   right scope, with the right `scope_id` (SC-004).
3. Three simultaneous subagents: no event appears under a sibling (US5 AS-1).
4. `sum(turns_used) + parent turns <= initial budget`, over a run that hits the cap (SC-005).
5. A host-mode delegation deserializes with `enforced: false` and is distinguishable without build
   knowledge (SC-008).
6. A round-trip test asserting `ToolResult.delegate == None` on every result reaching the conversation.
