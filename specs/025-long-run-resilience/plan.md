# Implementation Plan: Long-Run Resilience — Context Management, Stuck Detection, and a Finish Tool

**Branch**: `025-long-run-resilience` | **Date**: 2026-10-11 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/025-long-run-resilience/spec.md`

## Summary

Three things a watching person used to do during a long run, done by bee instead. Each lives in one
shared module that both loops call, and each becomes a field of 024's `Session` once that lands.

- **Context** (`src/context/`):
  - Every session gets a context budget: model window minus reply reserve, from a per-model table,
    overridable (R3).
  - Request size is estimated from bytes, calibrated by reported usage (R2).
  - bee never sends a request over budget.
  - Tool results reach the model capped at min(24,000 bytes, 10% of budget), while the record keeps the
    full output (R8).
  - With compaction on, the conversation is edited in place (R1): bulky middle-region results become
    stubs above 60%, and old turns fold into an untrusted-framed running summary above 85% (R5, R6),
    with a fallback removal and a `ContextExhausted` ending (R7).
- **Stuck detection** (`src/stuck.rs`): a streak tracker fed every call outcome from 024's `run_call`.
  It reminds the model at 5 identical calls, or 2 identical denied ones, and stops at 8 identical
  failing calls (R9).
- **Finish tool** (`src/tools/finish.rs`): a terminal tool for autonomous standard-mode runs. It adds
  outcome-bearing statuses, a one-reminder rule for text-only turns, and exit 3 for "ended without
  completing" (R11).
- **Prerequisite** (R10): tool-result envelope nonces become stable per result. Today a fresh nonce on
  every request breaks prompt caching for all history after the first child-process result.

## Technical Context

**Language/Version**: Rust (stable); `bee` crate edition 2021, MSRV 1.88.

**Primary Dependencies**: Existing only: tokio, async-trait, serde/serde_json (no `preserve_order`, so
canonical key order, R9), rig-core (via `RigModel`). **No new dependencies** (R10 uses a nonce cache, not
a hash crate).

**Storage**: JSON transcripts gain additive fields: `compactions`, `summary_usage`, `finish_offered`,
`TranscriptTurn.notes` and `RecordedCall.not_run`, plus four `EpisodeStatus` variants. App config gains
`[context]` and `[stuck]`, and scenarios gain `finish`, `[context]` and `[stuck]`.

**Testing**: `cargo test` with `MockModel` (`scripted`, `from_fn`), tokio `test-util`, and 024's
`test-support` scripted audit for denials and refusals. No VM tier: nothing here changes an enforcement
point (Constitution check).

**Target Platform**: Linux; every test is host-runnable.

**Project Type**: A Rust library (`bee`) with a thin CLI (`src/main.rs`, `src/app/`).

**Performance Goals**:

- Estimation is O(conversation bytes) per turn, with no allocation beyond a running sum. Elision is
  O(middle messages).
- At most one summary call per compaction, and none on turns below the hard threshold.
- Prompt-cache hit rate must not fall. R10 should raise it; it is measured in the SC-010 run.

**Constraints**:

- Behaviour preserved for sessions that cross no threshold (FR-038). The only intended differences are
  the finish tool in autonomous runs and the additive record fields.
- 024's progress-string pins hold, except for the additive lines in [contracts/](./contracts/).
- The code compiles under every CI feature set: default, `mcp`, `intercept`, `intercept,enforce,concurrent`
  and `test-support` combinations.
- `ContextManager::prepare` and `StreakTracker::observe` are `Send`, because the concurrent runner
  spawns `run_loop`.

**Scale/Scope**:

- New: about 900 lines (`context/` about 550, `stuck.rs` about 150, `finish.rs` about 120, framing
  about 80).
- Changed: both loops, at about 40 lines each; `transcript.rs`, `scenario.rs`, `config.rs`,
  `app/config/`, `app/run.rs`, `batch.rs`, `viz/grid.rs`.
- Five PRs plus a one-line default flip.

Every unknown is resolved in [research.md](./research.md) (R1–R13). None remains.

## Constitution Check

*GATE: checked before Phase 0 and re-checked after Phase 1 design.*

| Principle | Assessment |
|---|---|
| **I. Deny-by-default & fail-closed** | **Pass.** <ul><li>An over-budget request is refused with `ContextExhausted`, not sent (FR-002).</li><li>Invalid configuration is a start-up error, never clamped.</li><li>Stubs and summaries keep every denial, so compaction cannot make the model forget a wall and retry blindly (D4).</li><li>The policy reminder states that a denial is policy.</li><li>No path widens scope.</li></ul> |
| **II. Capability attenuation** | **Pass, untouched.** `finish` requires and grants nothing. Stuck detection only observes. |
| **III. Kernel enforcement is authoritative** | **Pass.** No enforcement point moves, and no claim about kernel behaviour is made. Stuck detection reads the audit that 024's `CallOutcome` already reports; it decides nothing about access. No VM case is needed. |
| **IV. Policy-as-data** | **Pass.** Policy files are unchanged. New settings are declarative TOML with `deny_unknown_fields`. |
| **V. Library-first** | **Pass.** `context/`, `stuck.rs` and `finish.rs` are library modules. The CLI only maps config and exit codes. No async enters `bee-core`. |
| **Auditability** (Security & Platform Constraints) | **Pass, and strengthened.** The record is never compacted (D2, FR-011), and every compaction, reminder and finish is itself recorded (FR-012, FR-028, FR-033). Existing passive `turn_notes` become recorded too. |
| **Untrusted content** (019 framing contract) | **Pass, with one change to review.** Summaries are framed `<untrusted-data source="bee:summary">` (FR-008). R10 changes nonce *lifetime* from per-request to per-result. The security property, that content cannot know **its own** envelope's nonce, is kept, because each nonce is drawn after its content exists. Old nonces become knowable to later content, but a forged closing tag for an older envelope still sits inside the later result's own envelope (research R10). Listed under Complexity Tracking for an explicit review. |
| **Test-first for the security boundary** | **Pass.** The denial-retention tests (`stub_keeps_denial`, `denied_repeat_gets_policy_reminder_at_two`) and the framing tests are written before their implementation. |

**Post-design re-check**: the data model, contracts and quickstart add no violations beyond the R10 item
below.

## Project Structure

### Documentation (this feature)

```text
specs/025-long-run-resilience/
├── spec.md
├── plan.md              # this file
├── research.md          # R1–R13
├── data-model.md
├── quickstart.md
├── contracts/
│   ├── context.md
│   ├── stuck.md
│   ├── finish.md
│   └── config.md
├── checklists/requirements.md
└── tasks.md             # /speckit-tasks
```

### Source Code (repository root)

```text
src/
├── context/                   # NEW
│   ├── mod.rs                 #      ContextManager, Prepared, ContextExhausted, for_session()      (B, E)
│   ├── config.rs              #      ContextConfig, ResolvedContext, validation                     (B)
│   ├── budget.rs              #      ContextBudget, WindowSource, estimate(), ratio calibration      (B)
│   ├── compact.rs             #      regions, elision, removal, CallNote, stubs                      (E)
│   └── summary.rs             #      summary prompt, rendering, framing, SummaryState                (E)
├── provider/limits.rs         # NEW  context_window(model_id) table                                  (B)
├── provider/framing.rs        # CHANGED frame_tool_result(.., nonce); frame_untrusted(source, ..)     (A)
├── provider/rig_model.rs      # CHANGED nonce cache keyed by call_id                                  (A)
├── stuck.rs                   # NEW  StuckConfig, StreakTracker, StuckSignal, reminder texts          (C)
├── tools/finish.rs            # NEW  Finish tool, FinishOutcome                                       (D)
├── tools.rs                   # CHANGED "finish" known + registered; not in DEFAULT_TOOLS             (D)
├── episode.rs                 # CHANGED prepare/cap/note_call/observe; notes; stuck; finish arm;
│                              #         text-only reminder; status_label                              (B–E)
├── repl.rs                    # CHANGED same hooks; ExchangeOutcome::{Stuck, ContextExhausted};
│                              #         /clear resets                                                 (B, C, E)
├── transcript.rs              # CHANGED statuses, HarnessNote, CompactionEvent, record fields          (B–E)
├── scenario.rs                # CHANGED finish, context, stuck; ctf validation                        (B–D)
├── config.rs                  # CHANGED ProviderConfig.context_window                                  (B)
├── batch.rs, viz/grid.rs      # CHANGED new statuses mapped                                           (C–E)
└── app/
    ├── config/{file,mod}.rs   # CHANGED [context], [stuck] layered into EffectiveConfig               (B, C)
    ├── run.rs                 # CHANGED exit-code map (exit 3), summary line                           (D)
    └── repl.rs                # CHANGED ReplConfig gets context/stuck                                  (B, C)

tests/
├── context_budget.rs          # NEW (B)
├── stuck_detection.rs         # NEW (C)  required-features = ["test-support"]
├── finish_tool.rs             # NEW (D)
├── context_compaction.rs      # NEW (E)  required-features = ["test-support"]
└── fixtures/mock-finish.toml  # NEW (D)
```

**Structure Decision**: a single crate, with no moves. `context/` is a directory because it has five
concerns (config, budget, compaction, summary, manager). Stuck detection and finish are single files.
Once 024 PR5 lands, `Session` owns a `ContextManager` and a `StreakTracker`, and `context::for_session`
becomes the builder's step. Until then both loops call that one constructor (R13).

## Phases (delivery order)

This revises FR-041's order: the nonce fix (A) goes first, and the budget and its guard ship with the
cap (B). Both are small and unblock E. Each phase is one PR, and each leaves the full suite green.

| # | PR | Scope | Needs | Exit gate |
|---|---|---|---|---|
| A | Stable nonces | R10: nonce cache, `frame_tool_result(.., nonce)`, `frame_untrusted` | — | framing tests; requests byte-identical across turns |
| B | Budget, cap, guard | `provider/limits.rs`, `ContextConfig`/`ContextBudget`/estimator, `cap` at push in both loops, `HarnessNote` + `TranscriptTurn.notes` + the pending-notes list (passive notes recorded too), `ContextExhausted`, unknown-window notice, `[context]` config and scenario table, `ProviderConfig.context_window` | — | `context_budget` passes; 024 pins unchanged |
| C | Stuck detection | `stuck.rs`, feeding from both loops after `run_call`, `Stuck` status / `ExchangeOutcome::Stuck`, `[stuck]` config | 024 PR3 (`CallOutcome`) | `stuck_detection` passes on both feature sets |
| D | Finish tool | `finish.rs`, registration rule, terminal arm, text-only reminder, `EndedWithoutFinish`, `not_run`, exit 3, `summary:` line, batch/grid mapping, scenario `finish` + CTF validation | 024 PR2 (`register`) | `finish_tool` passes; existing scenario tests pass after the opt-out audit (risk 1) |
| E | Compaction | `compact.rs`, `summary.rs`, `prepare` elision → summary → removal, `CompactionEvent`, summary usage, progress lines, `/clear` reset; default **off** | B | `context_compaction` passes |
| E′ | Default on | flip `compaction` default to `true` | E + SC-010 report | the SC-010 report is attached to the PR |

C and D can be swapped if 024 PR2 lands before PR3. A and B do not depend on 024 and can start now.

**Risk notes**:

1. **Finish changes every autonomous text-only ending.** Scenario-file tests and the 024 characterization
   fixtures end runs with a text turn. Phase D audits them:
   - fixtures built as struct literals set `finish: false`, because they characterize the old loop;
   - scenario TOML fixtures that pin a `completed` ending add `finish = false`;
   - new tests cover the finish path.

   The 024 progress-string pin's header line lists tools, so it stays on `finish: false`.
2. **The estimator is approximate.** The calibrated ratio and the 2% reply margin absorb error. A
   provider 400 for context length is mapped to `ContextExhausted`, not `ApiError`, as a second line of
   defence, and it is logged so the estimator can be tuned.
3. **The summary quality is the model's.** A poor summary loses facts, not safety: denials are restated
   in stubs, and the record is complete. SC-010 measures the effect before default-on.
4. **The REPL now shows the compacted conversation.** `/save` writes the transcript, so it is unaffected;
   `ReplSession.conversation` is documented as the model's view.

## Complexity Tracking

| Item | Why needed | Simpler alternative rejected because |
|---|---|---|
| R10 changes the 019 framing contract: an envelope nonce now lives as long as its tool result, not one request. | Fresh per-request nonces re-randomize every earlier child result on every turn, so prompt caching cannot cover the history. That cost grows with exactly the long runs this feature enables, and it makes compaction's cache-stability goal (FR-015) unreachable. | <ul><li>**Keep fresh nonces.** The cost above stays.</li><li>**Drop envelopes on older results.** Weakens 019's guarantee for exactly the content compaction keeps.</li><li>**Hash-derived nonces.** Need a hash crate in the default build.</li></ul>The property 019 relies on, that content cannot know its own envelope's nonce, still holds, because each nonce is drawn after its content exists. Reuse makes old nonces knowable, which is harmless because a forged old closing tag stays inside the new envelope (research R10). Reviewed as its own PR (A). |
