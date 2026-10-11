# Research: Long-Run Resilience (025)

Each decision records what was chosen, why, and what else was considered. References are to the tree at
`origin/main` 5fdaed3 (024 PR1 merged).

## What the code does today

- **The model's input is `Conversation { system, messages }`** (`src/provider.rs:44`). `messages` holds
  `Message::User { text }`, `Message::Assistant { text, tool_calls }`, and
  `Message::ToolResult { call_id, name, content, is_error, provenance }`. Both loops push one
  `Assistant { tool_calls }` and then one `ToolResult` per call, in order. Pairing is by
  `ToolCall.id == ToolResult.call_id`, and nothing checks it.
- **The session record is separate from the conversation.** The episode's `EpisodeTranscript.turns` /
  `RecordedCall` and the REPL's `ExchangeResult.turns` are built from call results, not from
  `Conversation`. Changing `Conversation` does not change the record.
- **Truncation happens inside the tools.** `transcript::truncate` with `DEFAULT_OUTPUT_CAP = 100 KiB`,
  called through `tool_result_from_output` (`src/transcript.rs:12, 16, 335`) from `exec.rs`, `files.rs`,
  `search.rs`, `astgrep.rs` and `mcp/proxy.rs`. The same capped `content` goes to the model and to the
  record.
- **Harness notes become `Message::User`.** They are pushed before the model call:
  `src/episode.rs:199-202`, `src/repl.rs:515-518`.
- **The episode ends on a text-only turn** (`src/episode.rs:250-267`): `Completed` if any tool was
  called, else `NoToolCalls`. Terminal tools end it at `:468-487`, where any terminal tool other than a
  correct `submit_flag` maps to `NotCaptured`. The REPL ignores `ToolResult::terminal`.
- **`bee run` exit codes** (`src/app/run.rs:291-295`): `InfraError` gives 70, `ApiError` gives 69, and
  everything else 0, including `Timeout`.
- **bee does not know any model's context window, and has no tokenizer.** The only size signal is the
  provider's `Usage` after a call: `input_tokens + cache_read_tokens + cache_write_tokens` is the size of
  the request just sent (Anthropic reports `input_tokens` as the uncached remainder;
  `src/metrics/pricing.rs` header). Output is capped by `max_tokens`, which defaults to 4096
  (`src/provider/rig_model.rs:32`).
- **Prompt caching is on for Anthropic** (`with_automatic_caching`, `rig_model.rs:204`). But
  `to_completion_request` re-frames every past tool result on every request
  (`rig_model.rs:316-319` → `framing::frame_tool_result`), and that wraps Child and Remote content in an
  envelope with a **fresh random nonce** each time (`framing.rs:91`). The request bytes for every
  earlier child-process result therefore change on every turn, and the cacheable prefix ends at the
  first such result. See R10.

## R1 — Compaction edits the conversation in place

- **Decision**: Compaction rewrites `Conversation.messages` itself, replacing a `ToolResult`'s `content`
  with a stub, or replacing a run of whole turns with one summary message. It does not build a separate
  per-request view.
- **Rationale**:
  - The conversation is already the model's input and nothing else. The record is built separately
    (above), so FR-011 holds by construction: compaction cannot reach the record.
  - Editing in place keeps the request stable between compactions, which is what prompt caching needs
    (FR-015).
  - It is the simplest form. A view would be recomputed every turn and would need its own cache-stability
    argument.
- **Alternatives**:
  - **A view derived from an untouched log on each request.** This keeps the full text in memory for no
    reader, since the record already has it.
  - **Compacting the record as well.** Rejected by D2.
- **Consequence**: the REPL's `/save` and `ReplSession.conversation` hand back the compacted
  conversation. `/save` writes the transcript, which is unaffected. The returned conversation is
  documented as "what the model holds".

## R2 — Size is estimated from bytes, then calibrated from usage

- **Decision**:
  - `estimate(request)` sums the bytes of the system prompt, the framing clause, the tool schemas' JSON
    and every message, then divides by a **bytes-per-token ratio**.
  - The ratio starts conservative, at 3.0 bytes per token. That over-estimates English and code, which
    are nearer 3.5–4.
  - After each model call, the ratio is recalibrated from the provider's reported size:
    `observed = (input + cache_read + cache_write)`, `ratio = bytes_sent / observed`, smoothed (EWMA,
    α = 0.5) and clamped to [2.0, 6.0].
  - Providers that report no usage (mock, some OpenAI-compatible servers) keep the initial ratio.
- **Rationale**:
  - A real tokenizer needs a per-model vocabulary that bee does not ship. Anthropic's token-count
    endpoint costs a round trip per turn.
  - Calibration converges within a turn or two, and the reply reserve has a margin (R3) to absorb the
    error.
  - The framing envelope's overhead is inside `bytes_sent`, so calibration covers it.
- **Alternatives**: `tiktoken-rs` (wrong vocabulary for Claude, plus a new dependency); the count-tokens
  API (latency and cost every turn); bytes/4 with no calibration (under-estimates code and JSON).

## R3 — Context budget: a model table, overridable, with a conservative default

- **Decision**:
  - New `src/provider/limits.rs` with `context_window(model_id) -> Option<u32>`. It matches the same
    provider-stripped ids as `pricing::rates`, covering the Claude models `pricing.rs` already lists.
  - New `ProviderConfig.context_window: Option<u32>` overrides it. So does `[context] window_tokens` in
    user or project config, or in a scenario; that wins over the provider file.
  - Unknown and unset: **32,000 tokens**, with a one-time start-up notice naming the setting.
  - `budget = window − reply_reserve`, where `reply_reserve = max_tokens (default 4096) + 2% of window`.
- **Rationale**:
  - The table matches how bee already treats per-model facts (pricing).
  - 32k is the smallest window in the study. An unknown local model on an OpenAI-compatible server is
    the likeliest to be small, so guessing low compacts early, which is safe, rather than overflowing.
- **Alternatives**:
  - **Ask the provider.** There is no such API for Anthropic; OpenAI-compatible servers vary.
  - **Learn the window from a context-length error.** That is recovery after the failure this feature
    exists to prevent.

## R4 — Where the regions begin and end

- **Preamble**: `convo.system` plus `messages[0]`, the task in an episode or the first user message in
  the REPL. In the REPL, after `/clear`, the next user message becomes the preamble.
- **Turns**: one `Assistant` message, plus its `ToolResult`s, plus any `User` notes, steering lines or
  user messages that precede the next `Assistant`. Compaction acts only on whole turns (summarization) or
  on single `ToolResult` contents (elision), so a call is never separated from its result (FR-010).
- **Recent window**: the newest turns whose estimated size fits within `recent_share` of the budget
  (default 0.30). Never fewer than two turns, and never fewer than all messages since the last
  `Assistant`.
- **Middle**: everything between them, including any earlier summary message. That message is the first
  thing in the middle and is never elided; it is replaced when the summary is extended.

## R5 — Elision

- **Decision**:
  - At the start of a turn, if `estimate ≥ soft × budget`, walk the middle region oldest first. Replace
    each `ToolResult` whose content exceeds `bulky_tokens` (default 300, estimated) with a stub.
  - Stop when `estimate ≤ target × budget`, where `target = soft − 0.10`, default 0.50 (the FR-015
    hysteresis).
  - The stub text is in [contracts/context.md](./contracts/context.md#stub). It is built from a
    `CallNote` that the loop records when the result is pushed: tool, short arguments, outcome, original
    size, and the denials and refusals taken from the call's audit and proxy events.
  - The stub keeps the message's `provenance` as `Harness`, because the stub is bee's text, not the
    tool's.
- **Why `CallNote` and not the message**: the `ToolResult` message carries no audit. The denials live in
  the call's `RecordedCall` / `CallOutcome` (024 PR3), so the loop hands the compactor what it needs once,
  at push time.

## R6 — Summarization

- **Decision**:
  - If `estimate ≥ hard × budget` after elision, fold the oldest middle turns into the running summary
    until the estimate is at or below `target × budget`.
  - The summary call is `model.complete` on a dedicated `Conversation`: a fixed system prompt
    (contracts/context.md), and one `User` message holding the previous summary and the folded turns
    rendered as text. Every tool result is rendered framed (R10), with its content capped at 2 KiB. Tools
    offered: `&[]`.
  - It goes through the same `complete_with_retry` the episode uses, within the remaining deadline.
  - The result replaces the folded turns as one `Message::User`. Its text is framed as untrusted data:
    `<untrusted-data source="bee:summary" nonce=…>` (FR-008).
  - The summary is capped at `summary_share` of the budget (default 0.10). A longer reply is treated as a
    failure.
- **Placement**: a `User` message directly after the preamble. Consecutive user-role content already
  happens today (notes after tool results), and both providers accept it.
- **Rationale for framing it, not merely labelling it**:
  - The summary is the model's rewrite of untrusted tool output.
  - The existing envelope and `UNTRUSTED_DATA_CLAUSE` already teach the model how to treat it.
  - A bare "summary:" label would give attacker-influenced text the same standing as bee's notes.

## R7 — Fallback and exhaustion

- **Decision**: if the summary call fails or comes back over its cap:
  - Remove the oldest middle turns until the estimate reaches the target, leaving
    `User("[bee] N earlier turns were removed to fit the context budget; their record is kept.")`.
  - Record a `CompactionEvent { kind: Removed, error }`.
  - If even removing the whole middle region cannot reach `hard × budget`, the loop ends with
    `EpisodeStatus::ContextExhausted { detail }`. In the REPL, the exchange ends with an error line and
    the session continues.
- **Rationale**: a run that has already done work should not die because one summary call failed. And a
  run that truly cannot fit must say so, not end in an unexplained provider 400.

## R8 — The model-facing output cap is applied when the result is pushed

- **Decision**:
  - Tools keep producing up to `DEFAULT_OUTPUT_CAP` (100 KiB), and the record keeps that (FR-022).
  - When the loop pushes `Message::ToolResult`, the content passes through
    `ContextManager::cap(content)`, which cuts it to `min(result_cap_bytes, result_cap_share × budget ×
    ratio)` bytes on a UTF-8 boundary. The defaults are 24,000 bytes and 0.10.
  - The cut appends: `[bee: showing {n} of {original} bytes — request a narrower range (line offset,
    filter, smaller search) to see more]`.
- **Rationale**:
  - The spec's 24,000 "characters" are counted as bytes, consistent with the existing cap, and identical
    for ASCII output.
  - Capping at push, not inside the tools, leaves the record unreduced without changing any tool.

## R9 — Stuck detection keys and outcomes

- **Key**: `(tool name, serde_json::to_string(&arguments))`. bee's `serde_json` is built without
  `preserve_order`, so objects are `BTreeMap`s and serialize with sorted keys. Equal structure gives an
  equal string, regardless of the model's key order or whitespace (FR-023).
- **Failing**: `result.is_error || outcome.timed_out || denied`, where
  - `denied` means the final attempt's tool-scope audit has a deny, or its proxy events have a
    `refused_out_of_scope`, and
  - no escalation in the call was `Granted`.

  All three come from 024's `CallOutcome`.
- **Order**: calls are observed in execution order, across turns. A call skipped after `finish` is not
  observed. Hook-refused and invalid-argument calls are observed and count as failing.
- **Reminder delivery**: a pending reminder is pushed as a `Message::User` note at the start of the next
  turn, beside the existing `turn_notes`, prefixed `[bee] `. Notes are bee's words, so they are not
  framed as untrusted.
- **Termination**: checked after each call. In an episode, the loop ends with `EpisodeStatus::Stuck`
  after recording that call. In the REPL, the exchange ends with `ExchangeOutcome::Stuck` and the session
  continues.

## R10 — Stable envelope nonces (prerequisite)

- **Decision**:
  - Draw each envelope nonce once, with the existing `fresh_nonce()`, the first time a given result is
    framed, and reuse it on every later request.
  - The nonces are cached on the `RigModel` in a `Mutex<HashMap<String, String>>` keyed by `call_id`.
    The summary envelope's key is `"bee:summary#" + generation`.
  - `frame_tool_result` takes the nonce as a parameter, and `rig_model` looks it up or draws it.
  - Entries for call ids no longer in the conversation are pruned on each request.
- **Rationale**:
  - A per-request fresh nonce makes every earlier child result's bytes differ on every request. That
    defeats prompt caching for the whole history after the first tool call, today, and would make
    FR-015's cache argument hollow.
  - The property 019 relies on is that content cannot know **its own** envelope's nonce, so it cannot
    close that envelope. A nonce drawn after the content exists keeps that property whether it is reused
    or not.
  - Reuse does make old nonces knowable. The model sees every nonce and could pass one on, for example
    by echoing it into an HTTP request whose response reflects it. A later result could then contain an
    earlier result's closing tag. That is harmless: the later result sits inside its own envelope, with a
    nonce drawn after it existed, so a forged tag for an older envelope is still wrapped content and
    escapes nothing. Today's per-request nonces also invalidated echoed ones; this change gives that up
    and relies on the own-envelope property alone. Test T004 shows this.
- **Dependency**: none. `sha2` is only an optional dependency of the `bee` crate, so a keyed-hash
  derivation would add a dependency to the default build. The cache does not.
- **Alternatives**:
  - **A keyed hash of the call id.** It would be stateless, but it needs a hash crate in the default
    build.
  - **Keep fresh nonces.** Cost, from reading the code: the cached prefix stops at the first child result on every
    turn.
  - **Drop the envelope for old results.** Weakens 019's framing guarantee.
- This is a fix to 019's framing contract and is listed separately in the plan, so it can be reviewed on
  its own.

## R11 — Finish tool

- **Schema**: `finish { outcome: "completed" | "blocked" | "abandoned", summary: string (1..=4000
  chars) }`. Invalid arguments give `ToolResult::invalid_args` and are not terminal.
- **Ending**: a valid call returns `ToolResult::terminal_ok("run finished: {outcome}")`.
  - The episode loop's terminal branch gains a `finish` arm:
    `EpisodeStatus::Finished { outcome, summary, turn }`.
  - Remaining calls in that turn are recorded with `RecordedCall.not_run = true` and a result of
    `not run: the run had already finished`. They are not executed, and they are not pushed to the
    conversation; the run is over.
- **Offering**:
  - `run_loop` serves only autonomous entry points: `bee run`, batch, concurrent and the harness. 024 PR5
    makes this explicit as `OperatorKind::Autonomous`.
  - Finish is registered when `scenario.mode == Standard && scenario.finish` (a new field, default
    `true`). The REPL path never registers it.
  - `is_known_tool("finish")` is true, so a scenario may list it. Listing it in CTF mode fails
    validation.
- **Text-only turn with finish offered**: the first one pushes the assistant message, then a
  `[bee] To end the run, call finish …` note, and continues. The second ends the run as
  `EpisodeStatus::EndedWithoutFinish`. When finish is not offered, today's `Completed` / `NoToolCalls`
  behaviour is unchanged.
- **Exit status (FR-036)**: when finish was offered,
  - `Finished { outcome: completed }` exits 0;
  - `Finished { blocked | abandoned }`, `EndedWithoutFinish`, `Stuck`, `ContextExhausted` and `Timeout`
    exit **3**, "run ended without completing";
  - `ApiError` and `InfraError` keep 69 and 70.

  When finish was not offered (scenario opt-out, CTF), exit codes are unchanged, `Timeout` stays 0, and
  new statuses that can still occur there (`Stuck`, `ContextExhausted`) exit 3.
  - Why 3: it is outside sysexits' 64–78, which mean usage and system failures. 1 and 2 are taken by
    clap and generic errors.
  - Why `Timeout` changes only with finish: finish is what gives a run a positive "done" signal. Without
    it, bee cannot tell a timed-out run from a finished one, so it keeps today's code.

## R12 — Configuration surface

- **Decision**:
  - Library types `ContextConfig` and `StuckConfig` (serde, `deny_unknown_fields`, every field
    optional, defaults in code), plus `Scenario { context, stuck, finish }`.
  - App config gains `[context]` and `[stuck]` tables in `FileConfig` (user and project layers), folded
    by `Merged::build` and resolved into `EffectiveConfig`, then into `ReplConfig` and the ad-hoc
    `Scenario`.
  - Neither table is user-only: a project may tune its own budget.
  - Keys are in [contracts/config.md](./contracts/config.md).
- **Compaction default**: `context.compaction = false` until the SC-010 comparison has run. The last
  task of the compaction phase flips the default, gated on that report. The cap, budget, notice and
  `ContextExhausted` refusal (the request-size guard) are on from the first phase.

## R13 — Placement relative to 024

| Part | Needs from 024 | Lives in |
|---|---|---|
| Stable nonces (R10) | nothing | `src/provider/{framing,rig_model}.rs` |
| Budget, estimator, cap, size guard | nothing; both loops call one `ContextManager` | `src/context/` |
| Stuck detection | PR3 `CallOutcome` (`timed_out`, `escalations`, final audit) | `src/stuck.rs`, fed from `run_call`'s caller |
| Finish tool | PR2 `ToolRegistry::register` | `src/tools/finish.rs`; status in `src/episode.rs` |
| Compaction | nothing beyond the budget phase | `src/context/{compact,summary}.rs` |

When 024 PR5 lands, `ContextManager` and `StreakTracker` become fields of `Session`, and the loops reach
them through it. Until then both loops construct them through one constructor,
`context::for_session(&cfg, model_id, max_tokens)`. That is shared code, not duplicated logic, the same
pattern `run_call` uses before PR5.
