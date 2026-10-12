//! The bee-owned multi-turn loop (research H2) and the `run_episode` entry point.
//!
//! The loop — not Rig — owns turn/time limits (FR-007), per-tool-call audit correlation (FR-008),
//! truncation (FR-015), malformed-arg handling (FR-016), retry/backoff (FR-017), and the terminal
//! status. [`run_loop`] is the pure loop over a ready [`Sandbox`] (host-testable with `MockModel`);
//! [`run_episode`] builds the sandbox (a real bee scope under `--features enforce`), materializes
//! the workdir, runs the loop, and tears down.

use std::time::{Duration, Instant};

use time::OffsetDateTime;

use crate::metrics::{stop_label, Recorder};
use crate::provider::{Conversation, Message, Model, ModelError, Turn, Usage};
use crate::sandbox::{self, Sandbox};
use crate::scenario::{Scenario, ScoringMode, WorkdirSetup};
use crate::tools::ToolRegistry;
use crate::transcript::{
    EpisodeStatus, EpisodeTranscript, HarnessNote, NoteKind, RecordedCall, Timing, TranscriptTurn,
};

/// A sink for human-readable live progress lines (research-agnostic; the CLI wires it to stderr).
/// The loop owns the formatting; the sink just renders. `None` ⇒ silent (the default).
pub type ProgressSink = Box<dyn Fn(&str) + Send + Sync>;

/// Loop tuning knobs.
pub struct LoopOptions {
    /// Max retries for transient (429/5xx) provider errors before `api_error` (FR-017).
    pub max_retries: u32,
    /// Optional live-progress sink (per-turn / per-tool-call / per-denial lines).
    pub progress: Option<ProgressSink>,
    /// Optional metrics recorder — one [`crate::metrics::CallRecord`] per model call. `None` (the
    /// default, and what host tests use) records nothing.
    pub metrics: Option<Recorder>,
    /// A source of tools that can change mid-session — the MCP bridge (004 FR-043). Refreshed at turn
    /// start through [`crate::turn::RefreshHook`] (024 FR-030). `None` (the default): nothing to refresh.
    pub tool_refresh: Option<std::sync::Arc<dyn crate::turn::ToolRefresh>>,
    /// Dynamic capability grants (007-dynamic-grants). `None` ⇒ escalation is off and the loop
    /// behaves exactly as before. When set, the loop builds an [`crate::grants::ActivePolicy`] and
    /// drives the escalation hooks each step.
    pub escalation: Option<crate::grants::escalate::LoopEscalation>,
    /// The context settings below the scenario: user and project `[context]`, and the provider's
    /// window and reply limit (025). The scenario's own `[context]` is merged over them.
    pub context: crate::context::ContextInputs,
    /// User and project `[stuck]` (025 US2). The scenario's own `[stuck]` is merged over it.
    pub stuck: crate::stuck::StuckConfig,
}

impl Default for LoopOptions {
    fn default() -> Self {
        LoopOptions {
            max_retries: 5,
            progress: None,
            metrics: None,
            tool_refresh: None,
            escalation: None,
            context: crate::context::ContextInputs::default(),
            stuck: crate::stuck::StuckConfig::default(),
        }
    }
}

fn emit(opts: &LoopOptions, msg: impl AsRef<str>) {
    if let Some(sink) = &opts.progress {
        sink(msg.as_ref());
    }
}

/// First meaningful line of `s`, clipped to `max` chars — for compact progress lines. Skips blank
/// lines and the `[stderr]` section marker `run_child` inserts, so a denial shows its actual message.
fn preview(s: &str, max: usize) -> String {
    let first = s
        .lines()
        .map(str::trim_end)
        .find(|l| !l.is_empty() && *l != "[stderr]")
        .unwrap_or("");
    if first.chars().count() > max {
        let clipped: String = first.chars().take(max).collect();
        format!("{clipped}…")
    } else {
        first.to_string()
    }
}

/// Progress lines for what a turn start changed — none when it changed nothing, so an episode without
/// leases prints exactly what it did before.
fn emit_turn_start(opts: &LoopOptions, report: &crate::turn::TurnStartReport) {
    if !report.released.is_empty() {
        emit(
            opts,
            format!("  lease released: {}", report.released.join(", ")),
        );
    }
    if !report.expired.is_empty() {
        emit(
            opts,
            format!("  lease expired: {}", report.expired.join(", ")),
        );
    }
    if !report.removed_tools.is_empty() {
        emit(
            opts,
            format!("  tools withdrawn: {}", report.removed_tools.join(", ")),
        );
    }
    if let Some(e) = &report.narrow_error {
        emit(opts, format!("  WARNING: scope narrowing: {e}"));
    }
}

/// The words the `done:` progress line and the batch summary use for `s`.
pub fn status_label(s: &EpisodeStatus) -> String {
    match s {
        EpisodeStatus::Completed => "completed".into(),
        EpisodeStatus::Timeout => "timeout".into(),
        EpisodeStatus::NoToolCalls => "no_tool_calls".into(),
        EpisodeStatus::ApiError { detail } => format!("api_error ({detail})"),
        EpisodeStatus::InfraError { detail } => format!("infra_error ({detail})"),
        EpisodeStatus::Captured { turn } => format!("captured (turn {turn})"),
        EpisodeStatus::NotCaptured => "not_captured".into(),
        EpisodeStatus::ContextExhausted { detail } => format!("context exhausted ({detail})"),
        EpisodeStatus::Stuck { .. } => "stuck".into(),
        EpisodeStatus::Finished { outcome, .. } => format!("finished ({outcome})"),
        EpisodeStatus::EndedWithoutFinish => "ended without finish".into(),
    }
}

/// `bee run`'s exit code: the run ended without completing its task (025, contracts/finish.md).
pub const EXIT_INCOMPLETE: u8 = 3;
/// `EX_UNAVAILABLE` (sysexits): the provider failed.
const EXIT_UNAVAILABLE: u8 = 69;
/// `EX_SOFTWARE` (sysexits): bee could not set the episode up.
const EXIT_SOFTWARE: u8 = 70;

/// The process exit code for an episode that ended with `status` (contracts/finish.md). In the
/// library, not the CLI, so the mapping is testable and an embedder gets the same answer
/// (Constitution V). When `finish` was offered, only `finish` with outcome `completed` is success: a
/// run that timed out had not finished its task.
pub fn exit_code(status: &EpisodeStatus, finish_offered: bool) -> u8 {
    use crate::tools::finish::FinishOutcome;
    match status {
        EpisodeStatus::InfraError { .. } => EXIT_SOFTWARE,
        EpisodeStatus::ApiError { .. } => EXIT_UNAVAILABLE,
        EpisodeStatus::ContextExhausted { .. }
        | EpisodeStatus::Stuck { .. }
        | EpisodeStatus::EndedWithoutFinish => EXIT_INCOMPLETE,
        EpisodeStatus::Finished { outcome, .. } => match outcome {
            FinishOutcome::Completed => 0,
            FinishOutcome::Blocked | FinishOutcome::Abandoned => EXIT_INCOMPLETE,
        },
        EpisodeStatus::Timeout if finish_offered => EXIT_INCOMPLETE,
        EpisodeStatus::Completed
        | EpisodeStatus::Timeout
        | EpisodeStatus::NoToolCalls
        | EpisodeStatus::Captured { .. }
        | EpisodeStatus::NotCaptured => 0,
    }
}

fn ms_since(t: Instant) -> u64 {
    t.elapsed().as_millis() as u64
}

fn rfc3339(t: OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// One provider round-trip with bounded exponential backoff on transient errors (FR-017). Never
/// sleeps past `deadline`. Returns a human-readable detail string on terminal failure.
pub(crate) async fn complete_with_retry(
    model: &dyn Model,
    convo: &Conversation,
    schemas: &[crate::provider::ToolSchema],
    max_retries: u32,
    deadline: Instant,
) -> Result<Turn, String> {
    let mut attempt: u32 = 0;
    loop {
        match model.complete(convo, schemas).await {
            Ok(turn) => return Ok(turn),
            Err(ModelError::Transient {
                status,
                retry_after,
            }) => {
                if attempt >= max_retries {
                    return Err(format!(
                        "transient provider error (status {status}) after {attempt} retries"
                    ));
                }
                let backoff = retry_after
                    .unwrap_or_else(|| Duration::from_millis(200 * 2u64.pow(attempt.min(6))));
                if Instant::now() + backoff >= deadline {
                    return Err(format!(
                        "transient provider error (status {status}); deadline reached before retry"
                    ));
                }
                tokio::time::sleep(backoff).await;
                attempt += 1;
            }
            Err(ModelError::Auth) => return Err("provider authentication failed".to_string()),
            Err(ModelError::Request(m)) => return Err(format!("provider rejected request: {m}")),
            Err(ModelError::Decode(m)) => return Err(format!("could not decode response: {m}")),
        }
    }
}

/// Run the loop over a ready sandbox. The sandbox is `&mut` so audit can be drained between calls.
pub async fn run_loop(
    model: &dyn Model,
    scenario: &Scenario,
    registry: &mut ToolRegistry,
    sandbox: &mut Sandbox,
    opts: &LoopOptions,
) -> EpisodeTranscript {
    let started_at = OffsetDateTime::now_utc();
    let start = Instant::now();
    let deadline = start + scenario.timeout();

    emit(
        opts,
        format!(
            "episode '{}' · {} · tools: {}",
            scenario.id,
            model.id(),
            scenario.tools.join(",")
        ),
    );

    let mut convo = Conversation::new(&scenario.system_prompt, &scenario.task);

    // The context budget (025): never send a request over it, and cap each result the model sees.
    let mut ctx = match crate::context::ContextManager::for_session(
        &opts.context,
        Some(&scenario.context),
        model.id(),
    ) {
        Ok((ctx, notice)) => {
            if let Some(n) = notice {
                emit(opts, format!("  {n}"));
            }
            ctx
        }
        Err(e) => return infra_error(scenario, model, format!("invalid [context]: {e}")),
    };
    // 025 US3: a standard run whose surface has `finish` must end through it. The surface decides,
    // so a loop driven with a hand-built registry keeps its old ending unless it registers `finish`.
    let finish_offered = scenario.mode == ScoringMode::Standard && registry.contains("finish");
    // Whether the one reminder to call `finish` has been sent (FR-035).
    let mut finish_reminded = false;

    // Stuck detection (025 US2): every call is observed, in order, across turns.
    let mut stuck = match opts.stuck.merge(scenario.stuck).resolve() {
        Ok(cfg) => crate::stuck::StreakTracker::new(cfg).with_finish_offered(finish_offered),
        Err(e) => return infra_error(scenario, model, format!("invalid [stuck]: {e}")),
    };
    // bee's notes for the next model call (025 FR-028), queued by stuck detection and the finish
    // reminder and recorded on the turn they precede.
    let mut pending: Vec<HarnessNote> = Vec::new();

    let mut turns: Vec<TranscriptTurn> = Vec::new();
    let mut audit_trail = Vec::new();
    let mut usage_total: Option<Usage> = None;
    let mut any_tool_called = false;
    let mut compactions: Vec<crate::transcript::CompactionEvent> = Vec::new();
    let mut summary_usage: Option<Usage> = None;

    // Dynamic capability grants (007-dynamic-grants): the mutable active policy, present only when
    // escalation is configured. Starts at `base`, bounded by `ceiling`.
    let mut active_policy = opts
        .escalation
        .as_ref()
        .map(|e| crate::grants::ActivePolicy::new(e.base.clone(), e.ceiling.clone()));

    // If the loop runs out of turns without the agent stopping, it hit the turn limit (FR-007). In
    // CTF mode (US3) a turn-limit-expired episode means the agent *failed* to capture the flag, so
    // it is `NotCaptured` rather than `Timeout` (which we reserve for the wall-clock deadline, set
    // explicitly at the deadline checks below — see US3 slice decision note).
    let mut status = match scenario.mode {
        ScoringMode::Ctf => EpisodeStatus::NotCaptured,
        ScoringMode::Standard => EpisodeStatus::Timeout,
    };

    'outer: for index in 0..scenario.turn_limit {
        let turn_start = Instant::now();
        if Instant::now() >= deadline {
            status = EpisodeStatus::Timeout;
            break;
        }

        // The top of the model turn (024): hooks may release leases, leases whose lifetime ran out
        // expire, the scope narrows if either happened, and the MCP tools refresh if they changed.
        // Then a fresh schema snapshot for this turn.
        let report = crate::turn::turn_start(
            index,
            opts.escalation.as_ref().map_or(&[], |e| e.hooks.as_slice()),
            active_policy.as_mut(),
            sandbox,
            registry,
            opts.tool_refresh.as_ref(),
        )
        .await;
        emit_turn_start(opts, &report);
        let schemas = registry.schemas();

        // Harness notes for this turn (019 US8: "N new passive leads", 025 reminders) — bee's own
        // words, recorded on the turn they precede.
        let mut turn_notes: Vec<HarnessNote> = Vec::new();
        for note in sandbox.turn_notes() {
            emit(opts, format!("  {note}"));
            convo.push(Message::User { text: note.clone() });
            turn_notes.push(HarnessNote::new(NoteKind::Passive, note));
        }
        for note in std::mem::take(&mut pending) {
            emit(opts, format!("  {}", note.text));
            convo.push(Message::User {
                text: note.text.clone(),
            });
            turn_notes.push(note);
        }

        // The context budget (025): compact if it is on and called for, and never send a request
        // over the budget. A summary call's cost is the session's too (FR-013).
        let prepared = ctx
            .prepare(&mut convo, &schemas, model, deadline, index)
            .await;
        for e in ctx.take_events() {
            emit(
                opts,
                format!("  {}", crate::context::describe(&e, ctx.budget().tokens())),
            );
            compactions.push(e);
        }
        let prepared = match prepared {
            Ok(p) => p,
            Err(e) => {
                status = EpisodeStatus::ContextExhausted { detail: e.detail };
                break;
            }
        };
        if let Some(u) = prepared.summary_usage {
            usage_total = Some(usage_total.map_or(u, |acc| acc + u));
            summary_usage = Some(summary_usage.map_or(u, |acc| acc + u));
        }

        let call_start = Instant::now();
        let turn =
            match complete_with_retry(model, &convo, &schemas, opts.max_retries, deadline).await {
                Ok(t) => t,
                Err(detail) => {
                    if let Some(rec) = &opts.metrics {
                        rec.record(
                            model.id(),
                            Usage::default(),
                            ms_since(call_start),
                            None,
                            "error",
                            "error",
                        );
                    }
                    // A provider refusal for length means the estimate ran low: report it as the
                    // budget it is, not as a provider fault (plan risk 2).
                    status = if crate::context::is_context_overflow(&detail) {
                        EpisodeStatus::ContextExhausted { detail }
                    } else {
                        EpisodeStatus::ApiError { detail }
                    };
                    break;
                }
            };
        // Non-streaming path, so no time-to-first-token — record the whole round-trip as latency.
        if let Some(rec) = &opts.metrics {
            rec.record(
                model.id(),
                turn.usage.unwrap_or_default(),
                ms_since(call_start),
                None,
                stop_label(&turn.stop),
                "ok",
            );
        }

        ctx.observe(prepared.sent_bytes, turn.usage.as_ref());
        if let Some(u) = turn.usage {
            usage_total = Some(usage_total.map_or(u, |acc| acc + u));
        }
        let assistant_text = turn.text.clone();

        emit(opts, format!("turn {index}"));
        if let Some(t) = &assistant_text {
            if !t.trim().is_empty() {
                emit(opts, format!("  text: {}", preview(t, 120)));
            }
        }

        // A turn with no tool calls terminates the episode: `completed` if the agent had already
        // used a tool (natural wrap-up, incl. US1 AS-1 where the op was denied), else `no_tool_calls`
        // (a model that never engages — SC-007, no hang).
        if turn.tool_calls.is_empty() {
            turns.push(TranscriptTurn {
                notes: std::mem::take(&mut turn_notes),
                index,
                assistant_text: assistant_text.clone(),
                calls: Vec::new(),
                duration_ms: ms_since(turn_start),
            });
            convo.push(Message::Assistant {
                text: assistant_text,
                tool_calls: Vec::new(),
            });
            // With `finish` offered, prose does not end the run: the first time, the model is told
            // how a run ends; the second time, the run ends without finishing (FR-035).
            if finish_offered {
                if finish_reminded {
                    status = EpisodeStatus::EndedWithoutFinish;
                    break;
                }
                finish_reminded = true;
                pending.push(HarnessNote::new(NoteKind::FinishRequired, FINISH_REMINDER));
                continue;
            }
            status = if any_tool_called {
                EpisodeStatus::Completed
            } else {
                EpisodeStatus::NoToolCalls
            };
            break;
        }

        convo.push(Message::Assistant {
            text: assistant_text.clone(),
            tool_calls: turn.tool_calls.clone(),
        });

        let mut recorded: Vec<RecordedCall> = Vec::new();
        for (at, tc) in turn.tool_calls.iter().enumerate() {
            any_tool_called = true;

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                status = EpisodeStatus::Timeout;
                turns.push(TranscriptTurn {
                    notes: std::mem::take(&mut turn_notes),
                    index,
                    assistant_text,
                    calls: recorded,
                    duration_ms: ms_since(turn_start),
                });
                break 'outer;
            }

            emit(
                opts,
                format!(
                    "  call {} {}",
                    tc.name,
                    preview(&tc.arguments.to_string(), 100)
                ),
            );

            // The call, start to finish: escalation, the timed attempt, its audit, at most one retry,
            // the proxy and late drains (024, src/call.rs). Rendering the outcome stays here.
            let outcome = crate::call::run_call(
                crate::call::CallInput {
                    call: tc,
                    turn: index,
                    origin: crate::sandbox::CallOrigin::Tool,
                    timeout: crate::call::TimeoutPolicy::Deadline(deadline),
                },
                sandbox,
                registry,
                match (opts.escalation.as_ref(), active_policy.as_mut()) {
                    (Some(config), Some(active)) => Some(crate::call::Escalation {
                        config,
                        active,
                        lease_turn: index,
                    }),
                    _ => None,
                },
            )
            .await;
            audit_trail.extend(outcome.audit_trail().cloned());
            for rec in &outcome.escalations {
                let kind = match rec.trigger {
                    crate::call::Trigger::Proactive => "proactive",
                    crate::call::Trigger::KernelDenial { .. } => "reactive",
                    crate::call::Trigger::ProxyRefusal { .. } => "proxy",
                };
                emit(opts, format!("  escalate({kind}): {:?}", rec.outcome));
            }
            for ev in &outcome.proxy_events {
                emit(opts, format!("  {}", crate::repl::render_proxy_event(ev)));
            }

            // `DENIED` is the tool's own denial only — never the proxy scope's (FR-022).
            let tag = if outcome.tool_denials() > 0 {
                "DENIED"
            } else if outcome.result.is_error {
                "ERR"
            } else {
                "ok"
            };
            let exit = outcome
                .result
                .exit_code
                .map(|c| format!(" (exit {c})"))
                .unwrap_or_default();
            emit(
                opts,
                format!(
                    "  result {tag}{exit}: {}",
                    preview(&outcome.result.content, 120)
                ),
            );
            for e in outcome.audit.iter().chain(&outcome.proxy_audit) {
                if e.decision == "denied" {
                    emit(opts, format!("  audit: {} denied {}", e.op, e.target));
                }
            }
            let timed_out = outcome.timed_out;
            let result = &outcome.result;

            convo.push(Message::ToolResult {
                call_id: tc.id.clone(),
                name: tc.name.clone(),
                // The model sees the capped result; the record keeps the tool's own (025 FR-022).
                content: ctx.cap(&result.content, result.original_len),
                is_error: result.is_error,
                provenance: result.provenance.clone(),
            });
            ctx.note_call(
                &tc.id,
                crate::context::compact::CallNote::from_outcome(tc, &outcome),
            );

            // A terminal tool (`submit_flag`/`give_up`, US3) ends the episode immediately. The loop
            // stays tool-name-agnostic except for the one distinction that decides the status:
            // `submit_flag` with a non-error (correct) result ⇒ Captured, anything else ⇒ NotCaptured.
            if result.terminal {
                status = match tc.name.as_str() {
                    "submit_flag" if !result.is_error => EpisodeStatus::Captured { turn: index },
                    // `finish` is terminal only for arguments it accepted, so they parse here.
                    "finish" => match crate::tools::finish::parse(&tc.arguments) {
                        Some((outcome, summary)) => EpisodeStatus::Finished {
                            outcome,
                            summary,
                            turn: index,
                        },
                        None => EpisodeStatus::EndedWithoutFinish,
                    },
                    _ => EpisodeStatus::NotCaptured,
                };
                recorded.push(outcome.to_recorded(tc));
                // Calls after a terminal one in the same turn are recorded, never run (FR-034).
                for skipped in &turn.tool_calls[at + 1..] {
                    recorded.push(not_run(skipped));
                }
                turns.push(TranscriptTurn {
                    notes: std::mem::take(&mut turn_notes),
                    index,
                    assistant_text,
                    calls: recorded,
                    duration_ms: ms_since(turn_start),
                });
                break 'outer;
            }

            recorded.push(outcome.to_recorded(tc));

            if timed_out {
                status = EpisodeStatus::Timeout;
                turns.push(TranscriptTurn {
                    notes: std::mem::take(&mut turn_notes),
                    index,
                    assistant_text,
                    calls: recorded,
                    duration_ms: ms_since(turn_start),
                });
                break 'outer;
            }

            match stuck.observe(tc, &outcome) {
                crate::stuck::StuckSignal::None => {}
                crate::stuck::StuckSignal::Remind(r) => pending.push(r.into_note()),
                crate::stuck::StuckSignal::Stop {
                    tool,
                    arguments,
                    repeats,
                } => {
                    emit(
                        opts,
                        format!(
                            "  stuck: {tool} repeated {repeats} times with the same failing result \
                             — ending run"
                        ),
                    );
                    status = EpisodeStatus::Stuck {
                        tool,
                        arguments,
                        repeats,
                    };
                    turns.push(TranscriptTurn {
                        notes: std::mem::take(&mut turn_notes),
                        index,
                        assistant_text,
                        calls: recorded,
                        duration_ms: ms_since(turn_start),
                    });
                    break 'outer;
                }
            }
        }

        turns.push(TranscriptTurn {
            notes: std::mem::take(&mut turn_notes),
            index,
            assistant_text,
            calls: recorded,
            duration_ms: ms_since(turn_start),
        });
    }

    emit(
        opts,
        format!(
            "done: {} · {} turns · {}ms",
            status_label(&status),
            turns.len(),
            ms_since(start)
        ),
    );
    if let EpisodeStatus::Finished { summary, .. } = &status {
        emit(opts, format!("  summary: {}", preview(summary, 200)));
    }

    let ended_at = OffsetDateTime::now_utc();
    EpisodeTranscript {
        consents: Vec::new(),
        mcp_audit: Default::default(),
        finish_offered,
        compactions,
        summary_usage,
        http_scope: None,
        scenario_id: scenario.id.clone(),
        model_id: model.id().to_string(),
        status,
        turns,
        audit_trail,
        timing: Timing {
            started_at: rfc3339(started_at),
            ended_at: rfc3339(ended_at),
            total_ms: ms_since(start),
        },
        usage: usage_total,
        score: None,
    }
}

/// What the model is told the first time it ends a turn with prose while `finish` is offered
/// (contracts/finish.md).
pub const FINISH_REMINDER: &str = "[bee] This run ends only when you call finish. If the task is \
    done, call finish with outcome \"completed\" and a summary; otherwise continue working.";

/// The record of a call that came after a terminal one in the same turn: it was never run.
fn not_run(call: &crate::provider::ToolCall) -> RecordedCall {
    RecordedCall {
        call: call.clone(),
        result: crate::tools::ToolResult::error("not run: the run had already finished"),
        audit: Vec::new(),
        proxy_events: Vec::new(),
        denied_attempt_audit: Vec::new(),
        denied_attempt_proxy_events: Vec::new(),
        escalations: Vec::new(),
        retried: false,
        timed_out: false,
        not_run: true,
        refused_by_hook: None,
    }
}

/// Build an `infra_error` transcript (setup failed; the loop never ran).
fn infra_error(scenario: &Scenario, model: &dyn Model, detail: String) -> EpisodeTranscript {
    let now = rfc3339(OffsetDateTime::now_utc());
    EpisodeTranscript {
        consents: Vec::new(),
        mcp_audit: Default::default(),
        finish_offered: false,
        compactions: Vec::new(),
        summary_usage: None,
        http_scope: None,
        scenario_id: scenario.id.clone(),
        model_id: model.id().to_string(),
        status: EpisodeStatus::InfraError { detail },
        turns: Vec::new(),
        audit_trail: Vec::new(),
        timing: Timing {
            started_at: now.clone(),
            ended_at: now,
            total_ms: 0,
        },
        usage: None,
        score: None,
    }
}

/// Create the scenario's declared dirs/files (relative to the current working directory), plus the
/// planted CTF flag (US3) when one is declared.
pub(crate) fn materialize_workdir(w: &WorkdirSetup) -> std::io::Result<()> {
    let root = workdir_root(w)?;
    for d in &w.create_dirs {
        std::fs::create_dir_all(contain(&root, d)?)?;
    }
    for f in &w.create_files {
        write_with_parents(&contain(&root, &f.path)?, f.content.as_bytes())?;
    }
    if let Some(flag) = &w.flag {
        write_with_parents(&contain(&root, &flag.path)?, flag.value.as_bytes())?;
    }
    Ok(())
}

/// The operator-declared containment root, created if missing, or a fresh per-episode temp
/// directory when the operator declared none.
fn workdir_root(w: &WorkdirSetup) -> std::io::Result<std::path::PathBuf> {
    let root = match &w.root {
        Some(r) => r.clone(),
        None => std::env::temp_dir().join(format!("bee-workdir-{}", std::process::id())),
    };
    std::fs::create_dir_all(&root)?;
    // Canonicalize *after* creating it, so the comparison in `contain` is against a real path with
    // every symlink already resolved — otherwise a symlinked root would fail its own prefix check.
    root.canonicalize()
}

/// Resolve a scenario-supplied path against `root` and refuse anything that escapes it.
///
/// A relative path is joined onto the root; an absolute path is taken as-is and must already live
/// under it. Escapes are refused rather than clamped: silently rewriting `/etc/cron.d/x` to
/// `<root>/etc/cron.d/x` would let a scenario believe it had planted something it had not, and a
/// CTF scenario would score against a file the agent was never able to find.
///
/// Containment is checked against the canonicalized deepest *existing* ancestor, so a symlink
/// planted anywhere along the path cannot be used to step outside the root. Components below that
/// ancestor do not exist yet, so they only need to be free of `..`.
fn contain(root: &std::path::Path, path: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
    use std::path::Component;

    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    };

    let refuse = |detail: &str| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "workdir path {} escapes the containment root {}: {detail}",
                path.display(),
                root.display()
            ),
        )
    };

    // Walk up to the deepest ancestor that exists, then canonicalize it. Everything below is about
    // to be created by us, so it cannot be a pre-planted symlink.
    let mut existing = joined.as_path();
    loop {
        if existing.exists() {
            break;
        }
        match existing.parent() {
            Some(p) => existing = p,
            None => return Err(refuse("no existing ancestor")),
        }
    }
    let anchor = existing.canonicalize()?;
    if !anchor.starts_with(root) {
        return Err(refuse("resolves outside the root"));
    }
    // The not-yet-existing tail must not climb back out with `..`.
    let tail = joined
        .strip_prefix(existing)
        .map_err(|_| refuse("cannot relate path to its existing ancestor"))?;
    if tail.components().any(|c| c == Component::ParentDir) {
        return Err(refuse("contains a `..` component"));
    }

    Ok(anchor.join(tail))
}

/// Write `bytes` to `path`, creating any missing parent directories first.
fn write_with_parents(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, bytes)
}

/// Operator choices for one episode that the scenario file does not carry: command-line flags, and
/// settings from the operator's own configuration.
#[derive(Debug, Clone, Copy, Default)]
pub struct EpisodeOptions {
    /// `--http-scope-advisory`: run `[policy.http]` interception even though the kernel will not
    /// block (host mode, a build without `enforce`, or an observe-mode policy) — research R17.
    pub http_scope_advisory: bool,
    /// User and project `[context]`, and the provider file's window and reply limit (025). The
    /// scenario's own `[context]` is merged over them.
    pub context: crate::context::ContextInputs,
    /// User and project `[stuck]` (025 US2). The scenario's own `[stuck]` is merged over it.
    pub stuck: crate::stuck::StuckConfig,
    /// What the episode runs under. `None`: the kernel whenever the build can enforce, else the host.
    /// `bee run --host` asks for `Host` on any build.
    pub enforcement: Option<crate::session::Enforcement>,
}

/// Run a full episode: build the sandbox (a real bee scope under `--features enforce`), materialize
/// the workdir, run the loop, tear down. `provider_key_env` names the provider key var so it (plus
/// the default key vars) is stripped from every tool child (FR-018).
pub async fn run_episode(
    model: &dyn Model,
    scenario: &Scenario,
    provider_key_env: Option<&str>,
    progress: Option<ProgressSink>,
) -> EpisodeTranscript {
    run_episode_with(
        model,
        scenario,
        provider_key_env,
        progress,
        EpisodeOptions::default(),
    )
    .await
}

/// [`run_episode`] with operator options.
#[cfg_attr(not(feature = "intercept"), allow(unused_variables))]
pub async fn run_episode_with(
    model: &dyn Model,
    scenario: &Scenario,
    provider_key_env: Option<&str>,
    progress: Option<ProgressSink>,
    eopts: EpisodeOptions,
) -> EpisodeTranscript {
    // Strip the provider key vars plus any configured MCP `token_env` names from every tool child
    // (FR-018/FR-041), so an MCP Bearer token never leaks into a sandboxed stdio server's env.
    let mut strip_env = sandbox::key_vars(provider_key_env);
    strip_env.extend(scenario.mcp.token_env_names());
    // One progress sink, shared by the loop and the operator, which reports each consent decision on
    // it (024 FR-004).
    let progress = progress.map(std::sync::Arc::new);
    let operator = crate::operator::Operator::autonomous(match &progress {
        Some(p) => std::sync::Arc::new(crate::operator::ProgressOutput(p.clone())),
        None => std::sync::Arc::new(crate::operator::NullOutput),
    });
    let mut opts = LoopOptions {
        progress: progress.map(|p| Box::new(move |line: &str| p(line)) as ProgressSink),
        metrics: Recorder::new(
            "episode",
            format!("episode:{}:{}", scenario.id, std::process::id()),
        ),
        context: eopts.context,
        stuck: eopts.stuck,
        ..LoopOptions::default()
    };

    if let Err(e) = materialize_workdir(&scenario.workdir) {
        return infra_error(scenario, model, format!("workdir setup failed: {e}"));
    }

    // The session, built the one way every entry point builds it (024 FR-006): skill grants, the
    // `[policy.http]` advisory, the sandbox, the Interceptor, the tool surface, MCP servers and
    // escalation.
    let spec = spec_from_scenario(scenario, strip_env, &eopts, operator);
    let mut session = match crate::session::build(spec, &|line| emit(&opts, line)).await {
        Ok(s) => s,
        Err(e) => return infra_error(scenario, model, e.to_string()),
    };
    opts.escalation = session.escalation.take();
    opts.tool_refresh = session.tool_refresh.clone();

    // The model is given the session's system prompt: the scenario's, plus the notes for the tools
    // the session holds — the same prompt the REPL builds (024 FR-007).
    let scenario = Scenario {
        system_prompt: session.system_prompt.clone(),
        ..scenario.clone()
    };
    let mut transcript = run_loop(
        model,
        &scenario,
        &mut session.registry,
        &mut session.sandbox,
        &opts,
    )
    .await;
    transcript.http_scope = session.http_header();
    transcript.consents = session.operator.take_log();
    transcript.mcp_audit = session.sandbox.finish_mcp_audit().await;

    // MCP servers, then the Interceptor, then the scopes (FR-012). A scope that will not empty means
    // something survived the episode and is about to lose its enforcement when the engine drops.
    opts.tool_refresh = None;
    if let Err(e) = session.shutdown().await {
        emit(
            &opts,
            format!("WARNING: {e} — a process may have outlived enforcement"),
        );
    }

    // CTF episodes carry a score derived from the audit trail (US3).
    if scenario.mode == crate::scenario::ScoringMode::Ctf {
        transcript.score = Some(crate::transcript::ScoreReport::from_transcript(&transcript));
    }
    transcript
}

/// Whether a headless run of `scenario` is offered `finish` (025 US3, contracts/finish.md): a
/// standard-mode run, unless the scenario opts out. A CTF run ends with its own terminal tools.
pub fn offers_finish(scenario: &Scenario) -> bool {
    scenario.mode == ScoringMode::Standard && scenario.finish
}

/// The session a scenario asks for. A `policy_path` that does not parse (the `/dev/null` placeholder
/// of a host run) is no policy: nothing to widen, nothing to grant. An unreadable ceiling is the
/// policy itself — widening is still on, and widens nothing.
pub(crate) fn spec_from_scenario(
    scenario: &Scenario,
    strip_env: Vec<String>,
    eopts: &EpisodeOptions,
    operator: crate::operator::Operator,
) -> crate::session::SessionSpec {
    use bee_core::Policy;
    let policy = Policy::from_path(&scenario.policy_path).ok();
    let ceiling = scenario.ceiling_policy_path.as_ref().map(|p| {
        Policy::from_path(p).unwrap_or_else(|_| {
            policy
                .clone()
                .unwrap_or_else(crate::session::parts::empty_policy)
        })
    });
    crate::session::SessionSpec {
        entry: crate::session::EntryPoint::Headless,
        label: scenario.id.clone(),
        policy,
        ceiling,
        enforcement: eopts.enforcement.unwrap_or(if cfg!(feature = "enforce") {
            crate::session::Enforcement::Kernel
        } else {
            crate::session::Enforcement::Host
        }),
        tools: {
            let mut tools = scenario.tools.clone();
            if offers_finish(scenario) && !tools.iter().any(|t| t == "finish") {
                tools.push("finish".into());
            }
            tools
        },
        ctf_flag: scenario.workdir.flag.as_ref().map(|f| f.value.clone()),
        skill_roots: scenario.skills.clone(),
        mcp: scenario.mcp.clone(),
        security: scenario.security.clone(),
        workdir: std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")),
        system_prompt: scenario.system_prompt.clone(),
        strip_env,
        http_scope_advisory: eopts.http_scope_advisory,
        lease_turns: scenario.lease_turns,
        // Autonomous: the ceiling file is the operator's reviewable pre-authorization.
        operator,
        prebuilt_sandbox: None,
    }
}

/// R3 cgroup-join spike (004-mcp-client, T016). **Constitution III gate**: proves a stdio MCP server
/// child spawned through rmcp's `TokioChildProcess` actually joins the episode's scope cgroup — i.e.
/// rmcp's `process-wrap` wrapper does NOT clobber bee's `pre_exec` cgroup-join closure. Source
/// analysis says a wrapper-less `CommandWrap` preserves the inner command's `pre_exec` (research
/// R3/§3.2); this test is the empirical proof.
///
/// Requires `--features enforce,mcp`, a BPF-LSM kernel, and root (scope creation + eBPF load).
/// `#[ignore]` so it only runs when invoked explicitly on the VM:
/// `sudo <testbin> --ignored --exact episode::mcp_cgroup_spike::child_joins_scope_cgroup`.
#[cfg(all(test, feature = "enforce", feature = "mcp"))]
mod mcp_cgroup_spike {
    use super::*;
    use crate::mcp::config::{McpServerConfig, McpTransport};

    /// Read `/proc/<pid>/cgroup` (cgroup v2: `0::<relpath>`) and resolve the cgroup dir's inode.
    fn child_cgroup_id(pid: u32) -> u64 {
        let raw = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .unwrap_or_else(|e| panic!("read /proc/{pid}/cgroup: {e}"));
        let rel = raw
            .lines()
            .find_map(|l| l.strip_prefix("0::"))
            .unwrap_or_else(|| panic!("no cgroup-v2 line in: {raw:?}"))
            .trim();
        let full = format!("/sys/fs/cgroup{rel}");
        bee_userspace::cgroup::cgroup_id(std::path::Path::new(&full))
            .unwrap_or_else(|e| panic!("cgroup_id({full}): {e}"))
    }

    fn spike_scenario() -> (Scenario, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("bee-mcp-spike-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let policy = dir.join("spike.policy.toml");
        // hello-style permissive policy: no exec allowlist (so `sleep` runs), one write grant.
        std::fs::write(
            &policy,
            "[policy]\nname = \"mcp-spike\"\nmode = \"enforce\"\n\n[policy.filesystem]\n\"/tmp\" = \"write\"\n",
        )
        .unwrap();
        let scn = Scenario {
            lease_turns: None,
            context: Default::default(),
            stuck: Default::default(),
            finish: false,
            id: "mcp-spike".into(),
            policy_path: policy,
            system_prompt: "spike".into(),
            task: "spike".into(),
            turn_limit: 1,
            timeout_secs: 30,
            tools: Vec::new(),
            mode: Default::default(),
            workdir: Default::default(),
            mcp: Default::default(),
            skills: Vec::new(),
            ceiling_policy_path: None,
            security: Default::default(),
        };
        (scn, dir)
    }

    // `#[tokio::test]` (current-thread + enable_all) provides the reactor that tokio process
    // spawning requires.
    #[tokio::test]
    #[ignore = "VM + root only: --features enforce,mcp on a BPF-LSM kernel"]
    async fn child_joins_scope_cgroup() {
        let (scenario, tmp) = spike_scenario();
        let policy =
            bee_core::Policy::from_path(&scenario.policy_path).expect("parse spike policy");
        let scope_id = format!("bee-episode-{}-{}", scenario.id, std::process::id());
        let (sandbox, _http) =
            crate::session::parts::kernel_sandbox(&policy, &scope_id, sandbox::key_vars(None))
                .expect("build enforced sandbox (need root + BPF-LSM)");

        let scope_cgid = match &sandbox {
            Sandbox::Enforced(e) => e.scope.cgroup_id,
            _ => panic!("expected an enforced sandbox"),
        };
        assert_ne!(scope_cgid, 0, "scope cgroup id must be non-zero");

        let cfg = McpServerConfig {
            name: "spike".into(),
            transport: McpTransport::Stdio,
            command: Some("sleep".into()),
            args: vec!["10".into()],
            env: Default::default(),
            url: None,
            token_env: None,
            allowed_tools: None,
            denied_tools: None,
        };

        // Control: the raw production spawn primitive (tool_command → tokio) must join the scope.
        {
            let raw = sandbox
                .tool_command("sleep", &["10".into()])
                .expect("tool_command");
            let mut raw = tokio::process::Command::from(raw);
            raw.kill_on_drop(true);
            let mut child = raw.spawn().expect("spawn raw control child");
            let pid = child.id().expect("control pid");
            assert_eq!(
                child_cgroup_id(pid),
                scope_cgid,
                "CONTROL: raw tool_command child is not in the scope cgroup — the baseline is broken"
            );
            let _ = child.start_kill();
        }

        // The real question: does the rmcp TokioChildProcess path preserve the cgroup-join pre_exec?
        {
            let (proc, _) = crate::mcp::transport::spawn_stdio(&sandbox, &cfg)
                .expect("spawn_stdio via TokioChildProcess");
            let pid = proc.id().expect("rmcp child pid");
            assert_eq!(
                child_cgroup_id(pid),
                scope_cgid,
                "R3 FAIL: the rmcp TokioChildProcess child is NOT in the scope cgroup — \
                 process-wrap clobbered bee's pre_exec; use the raw-pipe fallback (§3.3)"
            );
            drop(proc);
        }

        if let Sandbox::Enforced(e) = &sandbox {
            let _ = e.scope.teardown();
        }
        let _ = std::fs::remove_dir_all(tmp);
    }
}

#[cfg(test)]
mod workdir_containment_tests {
    use super::{materialize_workdir, WorkdirSetup};
    use crate::scenario::{FileSpec, FlagSpec};
    use std::path::PathBuf;

    /// A fresh containment root, plus a sibling directory that is deliberately *outside* it.
    fn roots(name: &str) -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("bee-contain-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        (root, outside)
    }

    fn setup(root: &std::path::Path) -> WorkdirSetup {
        WorkdirSetup {
            root: Some(root.to_path_buf()),
            ..Default::default()
        }
    }

    #[test]
    fn relative_paths_land_under_the_root() {
        let (root, _) = roots("rel");
        let mut w = setup(&root);
        w.create_dirs = vec!["project/src".into()];
        w.create_files = vec![FileSpec {
            path: "project/src/lib.rs".into(),
            content: "// source\n".into(),
        }];
        materialize_workdir(&w).expect("relative paths are contained");
        assert!(root.join("project/src/lib.rs").is_file());
    }

    #[test]
    fn absolute_path_under_the_root_is_allowed() {
        let (root, _) = roots("abs-in");
        let mut w = setup(&root);
        w.flag = Some(FlagSpec {
            path: root.join("secrets/flag.txt"),
            value: "FLAG{ok}".into(),
        });
        materialize_workdir(&w).expect("an absolute path inside the root is fine");
        assert_eq!(
            std::fs::read_to_string(root.join("secrets/flag.txt")).unwrap(),
            "FLAG{ok}"
        );
    }

    #[test]
    fn absolute_path_outside_the_root_is_refused() {
        let (root, outside) = roots("abs-out");
        let mut w = setup(&root);
        w.create_files = vec![FileSpec {
            path: outside.join("pwned"),
            content: "x".into(),
        }];
        materialize_workdir(&w).expect_err("an absolute escape must be refused");
        assert!(
            !outside.join("pwned").exists(),
            "host file was written anyway"
        );
    }

    #[test]
    fn parent_traversal_is_refused() {
        let (root, outside) = roots("dotdot");
        let mut w = setup(&root);
        w.create_files = vec![FileSpec {
            path: "../outside/pwned".into(),
            content: "x".into(),
        }];
        materialize_workdir(&w).expect_err("`..` traversal must be refused");
        assert!(
            !outside.join("pwned").exists(),
            "host file was written anyway"
        );
    }

    /// The check has to resolve symlinks, not just look at the literal path: a scenario that names
    /// a relative, `..`-free path can still land outside the root if an ancestor is a link.
    #[test]
    #[cfg(unix)]
    fn symlink_crossing_the_root_is_refused() {
        let (root, outside) = roots("symlink");
        std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();
        let mut w = setup(&root);
        w.create_files = vec![FileSpec {
            path: "escape/pwned".into(),
            content: "x".into(),
        }];
        materialize_workdir(&w).expect_err("a symlinked ancestor must be refused");
        assert!(
            !outside.join("pwned").exists(),
            "host file was written anyway"
        );
    }

    /// Without an operator-declared root the default is a temp directory — never the CWD, and never
    /// wherever the scenario happened to point.
    #[test]
    fn default_root_contains_an_absolute_escape() {
        let (_, outside) = roots("default");
        let w = WorkdirSetup {
            create_files: vec![FileSpec {
                path: outside.join("pwned"),
                content: "x".into(),
            }],
            ..Default::default()
        };
        materialize_workdir(&w).expect_err("default root must still contain");
        assert!(
            !outside.join("pwned").exists(),
            "host file was written anyway"
        );
    }
}
