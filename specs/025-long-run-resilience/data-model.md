# Data Model: Long-Run Resilience (025)

Rust types this feature adds or changes. New session-record fields are additive and
`serde(default, skip_serializing_if = empty)`, so a session that triggers none of them serializes as it
does today (FR-039).

## ContextConfig (`src/context/config.rs`, serde, `deny_unknown_fields`)

| Field | Type | Default | Meaning |
|---|---|---|---|
| `window_tokens` | `Option<u32>` | provider file → model table → 32,000 | Model context window (R3) |
| `compaction` | `Option<bool>` | `false`; `true` after SC-010 | Elision and summarization on/off |
| `soft` | `Option<f32>` | 0.60 | Elision threshold, share of budget |
| `hard` | `Option<f32>` | 0.85 | Summarization threshold |
| `target_gap` | `Option<f32>` | 0.10 | Compaction stops at `soft − target_gap` (FR-015) |
| `recent_share` | `Option<f32>` | 0.30 | Budget share kept verbatim at the end (≥ 2 turns) |
| `bulky_tokens` | `Option<u32>` | 300 | Results larger than this may be elided |
| `summary_share` | `Option<f32>` | 0.10 | Maximum summary size |
| `result_cap_bytes` | `Option<u32>` | 24,000 | Model-facing per-result cap |
| `result_cap_share` | `Option<f32>` | 0.10 | Per-result cap as a share of budget |

Validation: `0 < soft < hard < 1`; `0 < target_gap < soft`; the shares lie in `(0, 0.5]`;
`window_tokens ≥ 4,096 + max_tokens`. A violation is a configuration error at start-up (exit 64), never
a silent clamp.

## ContextBudget

```rust
pub struct ContextBudget {
    pub window: u32,          // tokens
    pub reply_reserve: u32,   // max_tokens + 2% of window
    pub source: WindowSource, // Table | ProviderFile | Config | Default
}
impl ContextBudget { pub fn tokens(&self) -> u32 { self.window - self.reply_reserve } }
```

`source == Default` produces the one-time start-up notice (FR-001).

## ContextManager (`src/context/mod.rs`)

One per session. In 024 PR5 it becomes a `Session` field.

```rust
pub struct ContextManager {
    cfg: ResolvedContext,          // ContextConfig with defaults applied
    budget: ContextBudget,
    ratio: f32,                    // bytes per token, R2; starts 3.0, clamped [2.0, 6.0]
    notes: HashMap<String, CallNote>,   // call_id → what a stub needs
    summary: Option<SummaryState>,
    preamble_len: usize,           // messages[..preamble_len] are never touched
    head_len: usize,               // bee-inserted summary/marker messages right after the preamble (0..=2);
                                   // tracked by position, never recognised by text
    events: Vec<CompactionEvent>,  // drained into the record
}
```

| Method | Does |
|---|---|
| `cap(&self, content: &str) -> String` | Model-facing cap (R8) |
| `note_call(call_id, CallNote)` | Called when a result is pushed |
| `async prepare(&mut self, convo: &mut Conversation, tools: &[ToolSchema], model: &dyn Model, deadline) -> Result<Prepared, ContextExhausted>` | Measure the request; elide, summarize or remove as needed; guard the budget |
| `observe(&mut self, sent_bytes: usize, usage: Option<&Usage>)` | Recalibrate `ratio` |
| `take_events(&mut self) -> Vec<CompactionEvent>` | Drained into the record each turn |
| `reset(&mut self)` | `/clear` (FR-019) |

`Prepared { estimate_tokens, sent_bytes, compacted: Option<CompactionEvent> }`. The loop shows
`compacted` as a progress or info line (FR-018).

With `compaction == false`, `prepare` only measures. If the request exceeds the budget, it returns
`ContextExhausted` rather than sending a request the provider will refuse.

## CallNote

```rust
pub struct CallNote {
    pub tool: String,
    pub args_short: String,     // preview(args, 80)
    pub outcome: NoteOutcome,   // Ok | Error | TimedOut | Denied | RefusedByHook | NotRun
    pub original_bytes: usize,
    pub denials: Vec<String>,   // "filesystem:/etc/shadow denied (open)", "proxy refused api.x:443 (out of scope)"
}
```

It is built from 024's `CallOutcome`: `result`, `timed_out`, final audit denies, and proxy events with
`refused_out_of_scope`. `denials` is capped at 5 entries plus "and N more".

## SummaryState

`text: String`, `generation: u32` (keys the stable nonce, R10), `covers_turns: Range<u32>`.

## CompactionEvent (session record)

```rust
#[derive(Serialize, Deserialize)]
pub struct CompactionEvent {
    pub turn: u32,
    pub kind: CompactionKind,          // Elided | Summarized | Removed
    pub items: u32,                    // results elided or turns folded/removed
    pub before_tokens: u32,            // estimates
    pub after_tokens: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,          // summary call only
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,         // Removed after a failed summary
}
```

## StuckConfig (`src/stuck.rs`, serde, `deny_unknown_fields`)

| Field | Default | Meaning |
|---|---|---|
| `remind_after` | 5 | Identical calls before the general reminder |
| `denied_remind_after` | 2 | Identical denied calls before the policy reminder |
| `stop_after` | 8 | Identical failing calls before the run ends |
| `stop` | `true` | Whether termination is enabled (FR-030) |

Validation: `1 ≤ denied_remind_after ≤ remind_after < stop_after`.

## StreakTracker

```rust
pub struct StreakTracker {
    cfg: StuckConfig,
    key: Option<CallKey>,        // (tool, canonical args JSON)
    count: u32,                  // identical calls
    failing: u32,                // consecutive identical failing calls
    all_denied: bool,
    reminded: Reminded,          // None | General | Policy
}
pub enum StuckSignal { None, Remind(Reminder), Stop { tool: String, arguments: Value, repeats: u32 } }
impl StreakTracker {
    pub fn observe(&mut self, call: &ToolCall, outcome: &CallOutcome) -> StuckSignal;
    pub fn reset(&mut self);
}
```

State transitions per observed call:

- A different key starts a new streak: `count = 1`, `failing = failing?1:0`,
  `all_denied = denied`, `reminded = None`.
- The same key increments `count`. A failing call increments `failing`; a non-failing call resets it to
  0. `all_denied &= denied`.
- `all_denied && count == denied_remind_after && reminded == None` gives `Remind(Policy)`.
- `count == remind_after && reminded == None` gives `Remind(General)`.
- `stop && failing == stop_after` gives `Stop`.

## Reminder / HarnessNote (session record)

```rust
#[derive(Serialize, Deserialize)]
pub struct HarnessNote {
    pub kind: NoteKind,      // StuckGeneral | StuckPolicy | FinishRequired | Passive (existing turn_notes)
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call: Option<ToolCall>,   // the repeated call, for stuck notes
}
```

`TranscriptTurn` gains `#[serde(default, skip_serializing_if = "Vec::is_empty")] notes: Vec<HarnessNote>`.
These are the notes injected before that turn's model call. Existing `turn_notes` are recorded here as
`Passive`, which is new data (they were previously only in progress output).

## Transcript changes (`src/transcript.rs`)

`EpisodeStatus` gains:

```rust
Finished { outcome: FinishOutcome, summary: String, turn: u32 },   // FinishOutcome: Completed|Blocked|Abandoned
EndedWithoutFinish,
Stuck { tool: String, arguments: serde_json::Value, repeats: u32 },
ContextExhausted { detail: String },
```

- `EpisodeTranscript` gains `compactions: Vec<CompactionEvent>`, `summary_usage: Option<Usage>` and
  `finish_offered: bool`. `usage` stays the total, including summaries (FR-013).
- `RecordedCall` gains `not_run: bool` (FR-034).
- `ExchangeOutcome` (REPL) gains `Stuck { tool, repeats }` and `ContextExhausted(String)`.

Matches that must handle the new statuses:

- `status_label` (`episode.rs:79`)
- the exit-code map (`app/run.rs:291`)
- `batch::Status::from_episode` (`batch.rs:39`)
- `viz/grid.rs:22`

`Finished { Completed }` maps to Pass. `Stuck`, `ContextExhausted`, `EndedWithoutFinish`,
`Finished { Blocked | Abandoned }` map to Fail.

## Scenario changes (`src/scenario.rs`)

`#[serde(default = "yes")] finish: bool`, `#[serde(default)] context: ContextConfig`,
`#[serde(default)] stuck: StuckConfig`. Validation: `finish` listed in `tools` with `mode = ctf` is an
error.

## ProviderConfig change (`src/config.rs`)

`#[serde(default)] context_window: Option<u32>`.
