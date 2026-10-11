---
description: "Task list for 025-long-run-resilience"
---

# Tasks: Long-Run Resilience — Context Management, Stuck Detection, and a Finish Tool

**Input**: Design documents from `specs/025-long-run-resilience/`

**Prerequisites**: [plan.md](./plan.md), [spec.md](./spec.md), [research.md](./research.md),
[data-model.md](./data-model.md), [contracts/](./contracts/), [quickstart.md](./quickstart.md)

**Tests**: These are **required**. FR-040 requires every part to be testable without a provider, network
or kernel. The constitution requires test-first for security-relevant behaviour, which here means denial
retention, untrusted framing, and the over-budget refusal. Each phase writes its tests first and sees them
fail before implementing. Test names and expectations are in [quickstart.md](./quickstart.md).

**Organization**: Phases follow the **delivery order of FR-041 and plan.md**, not story priority. One
phase is one PR:

stable nonces (foundational) → budget and cap (US4) → stuck detection (US2) → finish tool (US3) →
compaction (US1) → compaction on by default

US1 is P1, but it is built last because it needs the budget (PR B) and is the riskiest. The cap, stuck
detection and finish are each useful on their own first. Every story is testable at its own phase's exit
gate.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: can run in parallel (different files, no dependency on an incomplete task)
- **[Story]**: US1–US4 from spec.md
- Paths are relative to the repo root (`~/git/bee-025`)

## External dependencies (024)

- **Phase 4 (US2) needs 024 PR3**: `src/call.rs::run_call` and `CallOutcome`, with `timed_out`,
  `escalations`, the final `audit`, and `proxy_events`.
- **Phase 5 (US3) needs 024 PR2**: `ToolRegistry::register(name)` and `ToolDeps`.
- **Phases 1–3 and 6 need nothing from 024.**
- When 024 PR5 has landed (`Session`), the session-owned fields named in each task go on `Session`.
  Before that, they are locals created through `context::for_session` / `StreakTracker::new` in both
  loops.
- Rebase each branch on `main` before starting a phase.

## The gate (run at the end of every phase)

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --features intercept -- -D warnings
cargo clippy --workspace --all-targets --features intercept,enforce,concurrent -- -D warnings
cargo clippy --workspace --all-targets --features intercept,test-support -- -D warnings
cargo test --workspace
cargo test --workspace --features intercept,test-support
cargo test --features test-support --test call_characterization --test episode_progress_strings
```

The 024 pins (`call_characterization`, `episode_progress_strings`) must pass unchanged. A phase that
adds a progress line lists it in its PR description and adds it to the pin as a new assertion. It never
edits an existing expected string.

---

## Phase 1: Setup

**Purpose**: module skeletons, so later phases' parallel tasks have files to land in.

- [ ] T001 Create `src/context/mod.rs` (empty `pub mod config; pub mod budget;`, plus a module doc that
  summarizes research R1–R8 and links `specs/025-long-run-resilience/contracts/context.md`). Add
  `pub mod context;` to `src/lib.rs` in alphabetical position. Create `src/context/config.rs` and
  `src/context/budget.rs` with module docs only. `cargo check` passes.
- [ ] T002 [P] Create `src/provider/limits.rs` with a module doc only. Add `pub mod limits;` in
  `src/provider.rs` beside the existing `pub mod framing;`.

---

## Phase 2: Foundational — stable envelope nonces (PR A)

**Purpose**: research R10. Tool-result envelope nonces become stable per result, so a request's bytes do
not change between turns and prompt caching covers the history. This blocks Phase 6, whose summary
envelope and FR-015 cache argument depend on it. It is independently shippable.

### Tests first

- [X] T003 [P] In `src/provider/framing.rs` `#[cfg(test)]`, add tests:
  - `frame_with_given_nonce_is_deterministic`: the same inputs and the same nonce give byte-identical
    output;
  - `frame_untrusted_wraps_with_source_and_nonce`: `frame_untrusted("bee:summary", "x", "N")` produces
    `<untrusted-data source="bee:summary" nonce="N">\nx\n</untrusted-data nonce="N">`;
  - the existing envelope tests, updated to the new signature.

  They fail to compile until T005.
- [X] T004 [P] In `src/provider/rig_model.rs` `#[cfg(test)]`, add
  `requests_are_byte_identical_across_turns`:
  - build a `Conversation` with two `ToolResult`s of `Provenance::Child`;
  - map it twice with `to_completion_request` using the same nonce cache;
  - assert the chat histories serialize identically;
  - add a third result and map again: the first two results' text is unchanged and the third has a nonce
    not seen before.

  Also add `nonce_cache_prunes_dropped_calls`: after removing a result's message, the next mapping drops
  its cache entry.

  Also add `echoed_old_nonce_cannot_escape` (research R10): give a later `Child` result content that
  includes the first result's full closing tag, `</untrusted-data nonce="{first nonce}">`, followed by
  text. Assert that the later result's framed text starts with its own opening tag, ends with its own
  closing tag, and that its nonce differs from the first.

### Implementation

- [X] T005 In `src/provider/framing.rs`:
  - change `frame_tool_result(name, content, is_error, provenance)` to
    `frame_tool_result(name, content, is_error, provenance, nonce: &str)`, using `nonce` in place of
    `fresh_nonce()`;
  - make `fresh_nonce` `pub(crate)`;
  - add `pub fn frame_untrusted(source: &str, content: &str, nonce: &str) -> String`, sharing the
    envelope-writing code with `frame_tool_result` (including `attribute_safe` on `source`);
  - update the module doc: a nonce is drawn once per result, after its content exists, and reused on
    every later request (research R10); the security argument is that content cannot know a nonce drawn
    after it.
- [X] T006 In `src/provider/rig_model.rs`:
  - add `nonces: std::sync::Mutex<std::collections::HashMap<String, String>>` to `RigModel`, and give
    `to_completion_request` a `&Mutex<HashMap<..>>` parameter;
  - when mapping `HMessage::ToolResult`, look up `call_id` and draw with `framing::fresh_nonce()` on a
    miss;
  - after mapping, retain only the keys present in this conversation;
  - pass the cache from both `complete` and `stream`;
  - keep the lock scope inside the synchronous mapping, never across an `.await`, so the future stays
    `Send`.
- [X] T007 Update `specs/019-http-intercept/contracts/model-framing.md`: a nonce lives as long as its
  result, not one request, with the R10 rationale. Run the gate.

**Checkpoint**: PR A. Commit message: `fix(019): stable envelope nonces, so the cached prefix survives the turn`.

---

## Phase 3: User Story 4 — budget, output cap and size guard (Priority: P2) (PR B)

**Goal**: every session knows its context budget, never sends a request over it, and caps each tool
result the model sees at min(24,000 bytes, 10% of budget). The record keeps the full output.

**Independent Test**: `cargo test --test context_budget` (quickstart Phase B).

### Tests first

- [ ] T008 [P] [US4] Create `tests/context_budget.rs` with the seven tests in quickstart.md Phase B.
  Notes:
  - Use `bee::provider::mock_model::MockModel` and `tests/support/fixtures.rs` (`scenario`, `call_turn`,
    `text_turn`).
  - For `record_keeps_uncapped_result`, register a tool returning 60,000 bytes. Assert that the
    `RecordedCall.result.content` length is 60,000. With `MockModel::from_fn`, assert that the model
    received at most `24_000 + marker` bytes.
  - For `oversize_request_ends_context_exhausted`, set `[context] window_tokens = 8192` with compaction
    off and feed a 200 KiB task. Assert status `ContextExhausted` and that `from_fn` was never called.
  - For `estimate_calibrates_from_usage`, unit-test `ContextManager::observe` directly.
- [ ] T009 [P] [US4] Add unit tests in `src/provider/limits.rs` for known ids, with and without the
  provider prefix (`anthropic/claude-sonnet-4-6`, `claude-opus-4-8`), and for an unknown id → `None`. Add
  tests in `src/context/config.rs` for validation: `soft ≥ hard`, a zero share, and `window` smaller than
  `4096 + max_tokens` must each be rejected.

### Implementation

- [ ] T010 [P] [US4] Implement `pub fn context_window(model_id: &str) -> Option<u32>` in
  `src/provider/limits.rs`:
  - strip the provider prefix exactly as `metrics::pricing::rates` does;
  - map the Claude ids listed in `pricing.rs` to their published windows: 200,000 for each, and
    1,000,000 for any id whose provider documents a 1M window (check the current model docs);
  - leave a `// keep in step with metrics/pricing.rs` comment.
- [ ] T011 [P] [US4] Implement `ContextConfig` (every field `Option`, `serde(deny_unknown_fields)`,
  `Default`) and `ResolvedContext` (concrete values, defaults from data-model.md) in
  `src/context/config.rs`. Add `ContextConfig::merge(self, over: ContextConfig) -> ContextConfig` (each
  `Some` in `over` wins) and `resolve(&self, max_tokens: u32) -> Result<ResolvedContext, ConfigError>`
  with the validation rules in data-model.md.
- [ ] T012 [US4] Implement `ContextBudget`, `WindowSource` and the estimator in `src/context/budget.rs`:
  - `budget_for(model_id, provider_window: Option<u32>, cfg: &ResolvedContext, max_tokens)`, following
    contracts/config.md precedence;
  - `reply_reserve = max_tokens + window / 50`;
  - `estimate_bytes(convo: &Conversation, tools: &[ToolSchema]) -> usize`: system prompt +
    `framing::UNTRUSTED_DATA_CLAUSE` + `serde_json::to_vec(tools)` length + each message's text, with a
    fixed 120 bytes per `ToolResult` for envelope overhead;
  - `tokens(bytes, ratio)`.
- [ ] T013 [US4] Implement `ContextManager` in `src/context/mod.rs` with the fields in data-model.md
  (`notes` and `summary` stay unused until Phase 6) and these methods:
  - `for_session(cfg: &ContextConfig, model_id, provider_window, max_tokens) -> Result<(Self, Option<String>), ConfigError>`.
    The `Option<String>` is the unknown-window notice from contracts/context.md.
  - `cap(&self, content: &str, original_len: Option<usize>) -> String`, with the marker from
    contracts/context.md, cutting on a char boundary (reuse `transcript::truncate`'s boundary logic by
    extracting it into a `pub(crate) fn char_floor(s, n)`).
  - `prepare(..)`: measure only in this phase, and return
    `Err(ContextExhausted { detail })` when the estimate exceeds the budget.
  - `observe(sent_bytes, usage)`: the R2 recalibration with EWMA 0.5, clamped to [2.0, 6.0].
  - `reset()`.
  - `Prepared` and `ContextExhausted` types.
- [ ] T014 [US4] Add `#[serde(default)] context_window: Option<u32>` to `ProviderConfig` in
  `src/config.rs` (its doc names `[context] window_tokens` as the override). Add
  `#[serde(default)] context: ContextConfig` to `Scenario` in `src/scenario.rs`, and fold a top-level
  `[context]` table in `ScenarioFile` into it in `from_path`, the same way `[mcp]` and `[security]` are
  folded.
- [ ] T015 [US4] Add `EpisodeStatus::ContextExhausted { detail: String }` in `src/transcript.rs`. Extend
  `status_label` (`src/episode.rs:79`) to give `"context exhausted"`. Map it to fail in
  `batch::Status::from_episode` (`src/batch.rs`) and in `src/viz/grid.rs`. Map it to exit 3 in
  `src/app/run.rs` (define `const EX_INCOMPLETE: u8 = 3` beside the other exit constants, with a doc
  comment). Add `ExchangeOutcome::ContextExhausted(String)` in `src/repl.rs` and handle it wherever
  `ExchangeOutcome` is matched (`grep -rn "ExchangeOutcome::" src`).
- [ ] T015a [US4] Add the shared note plumbing that Phases 4, 5 and 6 build on, so they do not depend on
  each other (analysis I2):
  - in `src/transcript.rs`: `NoteKind { StuckGeneral, StuckPolicy, FinishRequired, Passive }`,
    `HarnessNote` (data-model.md), and `#[serde(default, skip_serializing_if = "Vec::is_empty")]
    notes: Vec<HarnessNote>` on `TranscriptTurn`; update every `TranscriptTurn { .. }` literal
    (`grep -rn "TranscriptTurn {" src tests`);
  - in both loops, keep `pending: Vec<HarnessNote>` for the session. At the turn-notes site
    (`src/episode.rs:199`, `src/repl.rs:515`), record existing `turn_notes` as `Passive` notes, then push
    every `pending` note as `Message::User` and record it on the turn. The episode loop emits each as
    `  {text}` progress; the REPL uses `output.info`. Nothing queues a note yet in this phase;
  - when 024 PR5 has landed, `pending` is a `Session` field.
- [ ] T016 [US4] Wire the episode loop (`src/episode.rs` `run_loop`):
  - create the manager at loop start from `scenario.context` and the model id. The model's `max_tokens`
    is not on the `Model` trait, so add `LoopOptions.max_tokens: Option<u32>`, set it from
    `ProviderConfig.max_tokens` in `run_episode_with`, and default it to 4096.
  - Emit the notice once.
  - Before each `complete_with_retry`, call `prepare`; on `Err`, set `ContextExhausted` and break.
  - After the call, call `observe(prepared.sent_bytes, turn.usage.as_ref())`.
  - When pushing `Message::ToolResult`, pass the content through `ctx.cap(&result.content, result.original_len)`.
    The `RecordedCall` keeps `result` unchanged.
  - Map a provider error whose detail matches a context-length refusal (`prompt is too long`,
    `context_length_exceeded`, `maximum context length`) to `ContextExhausted` instead of `ApiError`.
    Put the match in one `fn is_context_overflow(&ModelError) -> bool` in `src/context/mod.rs`.
- [ ] T017 [US4] Wire the REPL (`src/repl.rs` `run_exchange`) the same way:
  - add `context: ContextConfig` and `max_tokens: Option<u32>` to `ReplConfig`, defaulting to off and
    4096;
  - keep a `ContextManager` across exchanges: add it to the state passed in, or to `ReplSession`
    alongside `conversation`, and pass `&mut` into `run_exchange`;
  - call `prepare` before `stream_with_retry` and `observe` after `consume_stream`;
  - cap pushed results;
  - on `Err`, `output.error(..)` and return `ContextExhausted`;
  - in `run_repl`, the `/clear` arm calls `ctx.reset()`.
- [ ] T018 [US4] Add the `[context]` table to app config:
  - `ContextSection = bee::context::config::ContextConfig` as `FileConfig.context` in
    `src/app/config/file.rs`;
  - fold the layers in `Merged::build` with `ContextConfig::merge` (`src/app/config/mod.rs`);
  - add `context: ContextConfig` to `EffectiveConfig`;
  - pass it into `ReplConfig` (`src/app/repl.rs`) and the ad-hoc scenario (`src/app/run.rs`). For a
    scenario file, the scenario's table wins: `cfg.context.merge(scenario.context)`.
  - Add parsing and layering tests to `src/app/config/tests.rs`.
- [ ] T019 [US4] Run the gate. If `episode_progress_strings` sees a new line, it can only be the
  unknown-window notice. The fixtures use the mock provider, so either add the `mock/*` ids to
  `limits.rs` with a 200,000 window (preferred: the mock is not a real model, and the notice would be
  noise in every test), or pin the line as new.

**Checkpoint**: PR B. US4 works on its own: no request over budget, capped results, full record.

---

## Phase 4: User Story 2 — stuck detection (Priority: P1) (PR C) — needs 024 PR3

**Goal**: one reminder at 5 identical calls (or 2 identical denied calls, with the policy wording); stop
at 8 identical failing calls; in the REPL, stop the exchange, not the session.

**Independent Test**: `cargo test --features test-support --test stuck_detection` and the same with
`intercept,test-support` (quickstart Phase C).

### Tests first

- [ ] T020 [P] [US2] Create `tests/stuck_detection.rs` with the ten tests in quickstart.md Phase C.
  - Add `[[test]] name = "stuck_detection" required-features = ["test-support"]` to `Cargo.toml` in the
    same change, under the 024 R1 comment block.
  - Use `tests/support/scripted.rs` (`ScriptedTool`, `Attempt`, `ev`, `refusal`) and
    `Sandbox::host_scripted` for denials and refusals.
  - Gate `proxy_refused_repeat_gets_policy_reminder` on `#[cfg(feature = "intercept")]`.
  - Assert reminder text by its stable prefix (`[bee] You have called`, `[bee] … was denied`) and by
    `TranscriptTurn.notes[..].kind`.
- [ ] T021 [P] [US2] Add unit tests in `src/stuck.rs` for the state machine in data-model.md:
  - the key is order-independent;
  - `failing` resets on success;
  - `all_denied` clears on a non-denied call;
  - each reminder fires once per streak;
  - `stop = false` never returns `Stop`;
  - the validation rule `denied_remind_after ≤ remind_after < stop_after` holds.

### Implementation

- [ ] T022 [US2] Implement `src/stuck.rs`:
  - `StuckConfig` (serde, `deny_unknown_fields`, `Option` fields, `merge`, `resolve`);
  - `StreakTracker`, `StuckSignal`, `Reminder { kind: NoteKind, text: String, call: ToolCall }`;
  - `CallKey(name, serde_json::to_string(&arguments))`;
  - `observe(&mut self, call: &ToolCall, outcome: &CallOutcome) -> StuckSignal`, with failing/denied
    defined in research R9: `denied` when the final audit has a `Deny` decision in the tool scope or the
    proxy events contain `refused_out_of_scope`, and no `escalations` entry is `Granted`;
  - reminder texts from contracts/stuck.md, with `finish_offered: bool` selecting the policy text's
    ending;
  - add `pub mod stuck;` to `src/lib.rs`.
- [ ] T023 [US2] Add the stuck record type to `src/transcript.rs` (`HarnessNote` and
  `TranscriptTurn.notes` already exist from T015a):
  - `EpisodeStatus::Stuck { tool: String, arguments: serde_json::Value, repeats: u32 }`, with
    `status_label` giving `"stuck"`, batch and grid mapping it to fail, and `app/run.rs` mapping it to
    exit 3.
- [ ] T024 [US2] Wire the episode loop:
  - create a `StreakTracker` from `scenario.stuck`;
  - after each `run_call` outcome is recorded, call `observe`:
    - `Remind` → push to `pending`;
    - `Stop` → emit
      `  stuck: {tool} repeated {n} times with the same failing result — ending run`, set
      `Stuck { .. }`, and break `'outer` after pushing the turn.
  - Add `stuck: StuckConfig` with `#[serde(default)]` to `Scenario` and its `[stuck]` table fold, as in
    T014.
- [ ] T025 [US2] Wire the REPL:
  - add `stuck: StuckConfig` to `ReplConfig`;
  - keep the tracker beside the `ContextManager` from T017;
  - `Remind` → push to the `pending` list from T015a;
  - on `Stop`, `output.error("stopped: {tool} was repeated {n} times with the same failing result")` and
    return `ExchangeOutcome::Stuck { tool, repeats }`. Add the variant and handle it in every
    `ExchangeOutcome` match.
  - `/clear` calls `tracker.reset()`.
- [ ] T026 [US2] Add the `[stuck]` table to app config (as T018) and add tests in
  `src/app/config/tests.rs`. Run the gate. Pin the two new progress lines in
  `tests/episode_progress_strings.rs` as new tests (`the_stuck_line`, `the_reminder_line`), driven by a
  scripted failing tool.

**Checkpoint**: PR C. US2 works on its own on both feature sets.

---

## Phase 5: User Story 3 — finish tool (Priority: P2) (PR D) — needs 024 PR2

**Goal**: autonomous standard-mode runs end by `finish(outcome, summary)`. A text-only turn gets one
reminder, then ends the run as `EndedWithoutFinish`. Exit 3 for every ending that is not
`finished: completed`. The REPL and CTF are unchanged.

**Independent Test**: `cargo test --test finish_tool` (quickstart Phase D).

### Tests first

- [ ] T027 [P] [US3] Create `tests/finish_tool.rs` with the nine tests in quickstart.md Phase D.
  - The exit-code test calls the status→exit mapping. Extract it from `src/app/run.rs` into
    `pub fn exit_code(status: &EpisodeStatus, finish_offered: bool) -> u8` in the library
    (`src/episode.rs`), so it is testable. `run.rs` keeps only the `ExitCode::from`.
  - `every_status_maps_in_batch_and_grid` constructs each `EpisodeStatus` variant and asserts that
    `status_label`, `batch::Status::from_episode` and the grid mapping each return a value (no panic,
    no `_` fallthrough). Make those matches exhaustive without a `_` arm in the same PR.
- [ ] T028 [P] [US3] Create `tests/fixtures/mock-finish.toml`: a `mock` provider whose script is one
  `finish` call with `{"outcome":"completed","summary":"said hello"}`. Check `MockStep` in
  `src/config.rs` for the script syntax.

### Implementation

- [ ] T029 [US3] Implement `src/tools/finish.rs`:
  - `FinishOutcome { Completed, Blocked, Abandoned }` (serde lowercase, `Display`);
  - the `Finish` tool with the exact schema and description in contracts/finish.md;
  - `call` validates (outcome known; summary non-empty after trim and ≤ 4000 chars) and returns
    `ToolResult::terminal_ok(format!("run finished: {outcome}"))`, or `ToolResult::invalid_args("finish", ..)`;
  - add `pub fn parse(arguments: &Value) -> Option<(FinishOutcome, String)>` for the loop to read the
    accepted arguments;
  - `pub mod finish;` in `src/tools.rs`;
  - add `"finish"` to `is_known_tool` and to the `register` match (024 PR2's constructor). Do **not** add
    it to `DEFAULT_TOOLS`.
- [ ] T030 [US3] Add `#[serde(default = "default_true")] finish: bool` to `Scenario`. In `validate`,
  `mode == Ctf && tools.contains("finish")` is an error: "finish is not available in ctf mode; ctf runs
  end with submit_flag or give_up". Update every `Scenario { .. }` literal
  (`grep -rn "Scenario {" src tests`), setting `finish: false` in `tests/support/fixtures.rs::scenario`
  and in any fixture that characterizes the old ending (plan risk 1).
- [ ] T031 [US3] Add the record changes to `src/transcript.rs`:
  - `EpisodeStatus::Finished { outcome: FinishOutcome, summary: String, turn: u32 }` and
    `EndedWithoutFinish`;
  - `status_label` gives `"finished ({outcome})"` and `"ended without finish"`;
  - `EpisodeTranscript.finish_offered: bool` (skip if false);
  - `RecordedCall.not_run: bool` (skip if false);
  - update the struct literals listed in data-model.md.
  - Add `tests/transcript_compat.rs` (analysis G1, FR-039). Commit a pre-025 transcript JSON fixture,
    produced by today's `main` from a scripted run, as `tests/fixtures/transcript-pre025.json`. Assert
    that it deserializes into the new `EpisodeTranscript`, and that it re-serializes byte-identically
    after a `serde_json::Value` round trip. Also assert that a scripted run with `finish: false` that
    crosses no threshold serializes without any new key: no `notes`, `compactions`, `summary_usage`,
    `finish_offered` or `not_run`.
- [ ] T032 [US3] Wire the episode loop:
  - in `run_episode_with` (and `concurrent.rs`), register `finish` when
    `scenario.mode == Standard && scenario.finish`; once 024 PR5 has landed, the Session builder does
    this for `OperatorKind::Autonomous`;
  - set `finish_offered`;
  - in the terminal branch (`src/episode.rs` around `:468`), when `tc.name == "finish"`, set `Finished`
    from `finish::parse(&tc.arguments)`;
  - record each remaining call of the turn as
    `RecordedCall { not_run: true, result: ToolResult::error("not run: the run had already finished"), .. }`
    without executing it;
  - in the text-only branch (`:250`), when `finish_offered`: on the first time, push the assistant
    message, queue `HarnessNote { kind: FinishRequired, text: <contracts/finish.md text> }` into the
    `pending` list from T015a, and `continue`; on the second, set `EndedWithoutFinish` and break;
  - when not offered, keep today's `Completed` / `NoToolCalls`;
  - after the `done:` progress line, emit `  summary: {preview(summary, 200)}` for `Finished`.
- [ ] T033 [US3] In `src/app/run.rs`, replace the status match with `bee::episode::exit_code(..)`
  (T027). Document exit 3 in `bee run`'s `--help` long text (clap `after_help` in `src/main.rs` or
  wherever `run`'s command is defined).
- [ ] T034 [US3] Audit the existing tests for the text-only ending (plan risk 1):
  `grep -rln "text_turn\|Turn::text\|EndTurn" tests src | xargs grep -l "run_loop\|run_episode"`. For each
  scenario that pins `Completed` / `NoToolCalls`, set `finish = false` (TOML) or `finish: false`
  (literal), with a one-line comment that it characterizes the pre-finish ending. Run the gate.

**Checkpoint**: PR D. US3 works on its own; REPL and CTF behaviour unchanged.

---

## Phase 6: User Story 1 — compaction (Priority: P1) (PR E)

**Goal**: with `[context] compaction = true`, history over 60% of budget has its bulky middle results
elided; over 85% the oldest middle turns fold into an untrusted-framed summary, falling back to removal.
Preamble and recent window are verbatim, the record is complete, and every compaction is recorded.
Default stays **off**.

**Independent Test**: `cargo test --features test-support --test context_compaction` (quickstart Phase E).

### Tests first

- [ ] T035 [P] [US1] Create `tests/context_compaction.rs` with the sixteen tests in quickstart.md Phase E.
  - Add its `[[test]]` entry with `required-features = ["test-support"]`.
  - Use `MockModel::from_fn`. A call with an empty `tools` slice is the summary call: reply with a fixed
    summary, or with an error to test the fallback. Otherwise script the agent.
  - Use small budgets (`window_tokens = 8192`, `max_tokens = 1024`) and a tool that returns N KiB, so
    thresholds are crossed deterministically.
  - Write a helper `assert_invariants(&Conversation, preamble_len)` implementing the four invariants in
    contracts/context.md, and call it after every turn in every test.
  - In every compacted test, assert that no offered tool schema can recover compacted content (FR-016):
    the schema names equal the session's configured tools.
  - `record_identical_with_and_without` runs the same script twice (compaction on/off, budget large
    enough for "off" to fit) and compares `serde_json::to_value` of the two transcripts, minus
    `compactions` and `summary_usage`.
- [ ] T036 [P] [US1] Add unit tests in `src/context/compact.rs`:
  - turn segmentation (R4), including notes and steering between turns;
  - recent-window sizing (floor of two turns, and everything since the last `Assistant`);
  - stub text for each `NoteOutcome`, matching contracts/context.md byte for byte;
  - removal-marker text.

### Implementation

- [ ] T037 [US1] Implement `CallNote`, `NoteOutcome` and `CallNote::from_outcome(&ToolCall, &CallOutcome)`
  in `src/context/compact.rs` (data-model.md: denials capped at 5 plus "and N more"). In both loops,
  call `ctx.note_call(id, CallNote::from_outcome(..))` beside the `cap` call from T016/T017, including
  for `not_run` calls (`NotRun`) and hook refusals.
- [ ] T038 [US1] Implement the regions in `src/context/compact.rs`:
  - `segment(&Conversation, preamble_len) -> Vec<TurnSpan>`;
  - `recent_start(spans, ratio, budget, share) -> usize`;
  - bee-inserted messages (the summary and the removal marker) always sit directly after the preamble.
    `ContextManager` tracks how many there are in `head_len`. The middle region starts at
    `preamble_len + head_len`. Messages are **never** recognised by their text, because a person in the
    REPL can type anything (analysis U2).
  - `elide(convo, notes, from, to, target) -> (u32 items, bytes)` walks only `ToolResult` messages in the
    middle region, oldest first. It replaces bulky content with the stub and sets provenance to
    `Harness`.
  - `remove(convo, spans, target) -> u32` removes whole turns and puts the marker in the head, replacing
    any earlier marker and updating `head_len`. Summarizing folds an existing marker into the new summary,
    so the head is at most one summary plus one marker.
- [ ] T039 [US1] Implement `src/context/summary.rs`:
  - the system prompt and user-message rendering from contracts/context.md, with tool results rendered
    through `framing::frame_untrusted` and capped at 2 KiB each;
  - `SummaryState`;
  - `async fn summarize(model, prev, turns, words, deadline) -> Result<(String, Option<Usage>), String>`,
    calling `model.complete(&convo, &[])` with the retry and backoff of `episode::complete_with_retry`.
    Make that function `pub(crate)`, take it as is, and do not copy it.
  - Reject a reply over `summary_share` of the budget.
  - Build the summary message text, with a stable nonce keyed `bee:summary#{generation}`. Do this
    through `frame_untrusted` with a nonce drawn once per generation and stored in `SummaryState`.
- [ ] T040 [US1] Complete `ContextManager::prepare` in `src/context/mod.rs` to the sequence in
  contracts/context.md: elide → summarize → remove on failure → `ContextExhausted`.
  - Produce at most one `CompactionEvent` per kind, with token estimates before and after.
  - Add the summary usage to `summary_usage` and return it in `Prepared`, so the loops add it to
    `usage_total` (FR-013).
  - Add `pub mod compact; pub mod summary;`.
  - `prepare` keeps no `MutexGuard` across `.await`; the future must be `Send`. Add a
    `fn _assert_send()` compile check.
- [ ] T041 [US1] Record and show compactions:
  - add `CompactionKind`, `CompactionEvent`, `EpisodeTranscript.compactions` and
    `EpisodeTranscript.summary_usage` to `src/transcript.rs`;
  - both loops drain `ctx.take_events()` each turn into the transcript (episode) or `ExchangeResult`
    (REPL);
  - emit the progress and info lines from contracts/context.md;
  - pin those lines as new tests in `tests/episode_progress_strings.rs`.
- [ ] T042 [US1] Run the gate with compaction off (the default). The full suite must be unchanged apart
  from the new tests.

**Checkpoint**: PR E. US1 works on its own when switched on.

---

## Phase 7: Polish and the default flip

- [ ] T043 [P] Update `CONTEXT.md` (repo root; the glossary 024 extended) with the spec's terms: context
  budget, preamble, recent window, middle region, elision, summarization, compaction, streak, finish
  tool.
- [ ] T044 [P] Document `[context]` and `[stuck]` in the user-facing config docs (find them with
  `grep -rln "\[session\]" docs README.md`), with the defaults table from data-model.md and the
  window precedence from contracts/config.md.
- [ ] T045 Run the SC-010 comparison (quickstart "SC-010"):
  - pair the runs by scenario id;
  - write `specs/025-long-run-resilience/sc010-report.md` with completions, `ContextExhausted` count,
    cost, summary calls and cache-read share, on and off.

  If `bee batch` lacks a way to set `[context]` per run, use per-scenario `[context]` tables in a copied
  scenario set; do not add a CLI flag only for this.
- [ ] T046 Only if T045 shows no fewer completions and fewer context failures with compaction on: change
  the `compaction` default to `true` in `src/context/config.rs`, update data-model.md and the docs from
  T044, and attach the report to the PR (E′). Otherwise record the result in the report and leave the
  default off.

---

## Dependencies & Execution Order

```text
Phase 1 (setup) ─▶ Phase 2 (A: nonces) ─▶ Phase 3 (B: US4) ─┬─▶ Phase 6 (E: US1) ─▶ Phase 7
                                                           │
             024 PR3 ─▶ Phase 4 (C: US2) ──────────────────┤
             024 PR2 ─▶ Phase 5 (D: US3) ──────────────────┘
```

- Phase 2 needs nothing. Phase 3 needs Phase 1. Phases 2 and 3 can be developed in parallel; merge A first.
- Phase 4 needs 024 PR3 and Phase 3 (the loop wiring, `ReplConfig` additions and the T015a notes list).
  Phase 5 needs 024 PR2 and Phase 3 (T015a). Phases 4 and 5 are independent of each other and may land in
  either order, as plan.md allows.
- Phase 6 needs Phases 2 and 3. Its `CallNote::from_outcome` reads 024 PR3's `CallOutcome`, so if 024 PR3
  has not landed, T037 builds `CallNote` from the loop's `RecordedCall` and result instead, with the same
  fields.
- Phase 7: T045 needs Phase 6 and a real provider; T046 needs T045.

### Within each phase

Tests first (they fail) → types → module → loop wiring (episode, then REPL) → config → gate.

## Parallel Examples

```text
Phase 2:  T003 (framing tests) ∥ T004 (rig_model tests)
Phase 3:  T008 ∥ T009 ∥ T010 ∥ T011   then T012 → T013 → T014 → T015 → T015a → T016 → T017 → T018 → T019
Phase 4:  T020 ∥ T021                 then T022 → T023 → T024 → T025 → T026
Phase 5:  T027 ∥ T028                 then T029 → T030 → T031 → T032 → T033 → T034
Phase 6:  T035 ∥ T036                 then T037 → T038 → T039 → T040 → T041 → T042
Phase 7:  T043 ∥ T044                 then T045 → T046
```

## Implementation Strategy

- **Smallest useful first**: PR A (cache fix, about 80 lines) and PR B (no over-budget request, capped
  results) need nothing from 024. They make every existing long run cheaper and remove its unexplained
  provider failure.
- **Then, as 024 lands**: stuck detection after 024 PR3, finish after 024 PR2.
- **Compaction last and off**: the largest and most model-dependent part ships switched off. It is
  turned on only by evidence (SC-010).
- **MVP** for "a long autonomous run does not die of its own history" (US1) is Phases 2, 3 and 6. Phases
  4 and 5 are independent increments.
