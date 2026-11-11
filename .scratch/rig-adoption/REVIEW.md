# Rig adoption experiment

Decision: retain the production loops for now. The test-only prototype establishes a usable
boundary at Rig 0.40's `AgentRun`, not production parity with `AgentRunner`.

## Implemented

- `tests/rig_runner_spike.rs` drives Rig's actual state machine with scripted model responses.
  Rig owns turn progression and history; all executed tools go through Bee's `run_call`.
  It checks successful and denied tool results, audit preservation, continuation, final output,
  serialization between model response and dispatch, and explicit unknown-tool recovery.
- Provider request retry handling is shared between headless completions and REPL stream opening.
  The episode deadline remains mandatory for headless calls. Stream consumption stays outside
  retries, so a mid-stream failure cannot restart a request after output was delivered.
- Buffered responses retain Anthropic and OpenAI stop reasons, including output-token exhaustion
  and unknown provider reasons, instead of guessing exclusively from tool presence.

## What this does not prove

The prototype does not call a live model, migrate the REPL, or implement Bee's full session
policy around Rig. Existing session-parity, lifecycle, hooks, compaction, finish, and transcript
checks exercise the production Bee paths, not parity between those paths and this prototype.
Serializing AgentRun does not checkpoint Bee's grants, audit state, or durable journal.
No production execution path selects the prototype.

## Adoption gates

1. Preserve all provider assistant content, including signed reasoning, through conversation
   replay and compaction. Bee's current message format cannot represent it; adding only a display
   event would not fix replay. This needs an explicitly backward-compatible transcript change.
2. Establish streaming completion metadata parity. Rig 0.40's Anthropic
   `StreamingCompletionResponse` retains usage only; its stop reason cannot be recovered through
   that final response. Buffered metadata is fixed here; streaming still infers the stop reason.
3. Drive Bee's denial-dominant hooks, grant expiry, and tool refresh at the correct model-turn
   boundaries. Rig hook short-circuiting is not a substitute for Bee's policy aggregation.
4. Run both drivers against the same escalation/retry/deadline, context-compaction, finish,
   stuck-detection, and cancellation fixtures, including streams that fail mid-response.
5. Preserve durable recovery contracts: never replay a mutating call merely because Rig's
   serialized state says its tool results are pending.
6. Count deletable production orchestration after adapters and policies are included. The
   present prototype establishes feasibility, not a demonstrated reduction in production code.

Keep sandboxing, grants, call lifecycle, provenance framing, and durable recording in Bee.
Do not expose a production Rig-runner flag before these gates pass.

## Validation

Passed:

- `cargo test --no-default-features --features test-support --test rig_runner_spike --test session_parity --test call_lifecycle --test hooks_leases --test context_compaction --test finish_tool --test transcript_compat --lib`
- `cargo test --no-default-features --lib provider::retry --quiet` (five retry checks after adding recovery and in-flight cancellation cases)
- `cargo clippy --lib --features test-support,durable-sessions -- -D warnings`
- `rustfmt --check` on changed Rust files and `git diff --check`

No live-provider or kernel-enforcement run was performed. Durable-session code was linted/compiled;
this experiment does not claim durable runtime parity.
