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
use crate::tools::{self, ToolRegistry};
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
    /// Optional per-turn tool-refresh hook (004-mcp-client, FR-043). Called at the top of each turn
    /// with `&mut registry`; the MCP path installs a closure that re-registers tools when an MCP
    /// server sent `tools/list_changed`. rmcp-agnostic (a plain closure) so non-MCP callers are
    /// unaffected. `None` (the default) is a no-op.
    #[allow(clippy::type_complexity)]
    pub refresh_tools: Option<Box<dyn Fn(&mut ToolRegistry) + Send + Sync>>,
    /// Dynamic capability grants (007-dynamic-grants). `None` ⇒ escalation is off and the loop
    /// behaves exactly as before. When set, the loop builds an [`crate::grants::ActivePolicy`] and
    /// drives the escalation hooks each step.
    pub escalation: Option<crate::grants::escalate::LoopEscalation>,
    /// The context settings below the scenario: user and project `[context]`, and the provider's
    /// window and reply limit (025). The scenario's own `[context]` is merged over them.
    pub context: crate::context::ContextInputs,
}

impl Default for LoopOptions {
    fn default() -> Self {
        LoopOptions {
            max_retries: 5,
            progress: None,
            metrics: None,
            refresh_tools: None,
            escalation: None,
            context: crate::context::ContextInputs::default(),
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

fn status_label(s: &EpisodeStatus) -> String {
    match s {
        EpisodeStatus::Completed => "completed".into(),
        EpisodeStatus::Timeout => "timeout".into(),
        EpisodeStatus::NoToolCalls => "no_tool_calls".into(),
        EpisodeStatus::ApiError { detail } => format!("api_error ({detail})"),
        EpisodeStatus::InfraError { detail } => format!("infra_error ({detail})"),
        EpisodeStatus::Captured { turn } => format!("captured (turn {turn})"),
        EpisodeStatus::NotCaptured => "not_captured".into(),
        EpisodeStatus::ContextExhausted { detail } => format!("context exhausted ({detail})"),
    }
}

/// `bee run`'s exit code: the run ended without completing its task (025, contracts/finish.md).
pub const EXIT_INCOMPLETE: u8 = 3;
/// `EX_UNAVAILABLE` (sysexits): the provider failed.
const EXIT_UNAVAILABLE: u8 = 69;
/// `EX_SOFTWARE` (sysexits): bee could not set the episode up.
const EXIT_SOFTWARE: u8 = 70;

/// The process exit code for an episode that ended with `status`. In the library, not the CLI, so the
/// mapping is testable and an embedder gets the same answer (Constitution V).
pub fn exit_code(status: &EpisodeStatus) -> u8 {
    match status {
        EpisodeStatus::InfraError { .. } => EXIT_SOFTWARE,
        EpisodeStatus::ApiError { .. } => EXIT_UNAVAILABLE,
        EpisodeStatus::ContextExhausted { .. } => EXIT_INCOMPLETE,
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
async fn complete_with_retry(
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
    // bee's notes for the next model call (025 FR-028), queued by stuck detection and the finish
    // reminder and recorded on the turn they precede.
    let mut pending: Vec<HarnessNote> = Vec::new();

    let mut turns: Vec<TranscriptTurn> = Vec::new();
    let mut audit_trail = Vec::new();
    let mut usage_total: Option<Usage> = None;
    let mut any_tool_called = false;

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

        // Refresh MCP tools if a server sent `tools/list_changed` since last turn (FR-043), then take
        // a fresh schema snapshot for this turn.
        if let Some(refresh) = &opts.refresh_tools {
            refresh(registry);
        }
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

        let prepared = match ctx.prepare(&convo, &schemas) {
            Ok(p) => p,
            Err(e) => {
                status = EpisodeStatus::ContextExhausted { detail: e.detail };
                break;
            }
        };

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
        for tc in &turn.tool_calls {
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

            // A terminal tool (`submit_flag`/`give_up`, US3) ends the episode immediately. The loop
            // stays tool-name-agnostic except for the one distinction that decides the status:
            // `submit_flag` with a non-error (correct) result ⇒ Captured, anything else ⇒ NotCaptured.
            if result.terminal {
                status = if tc.name == "submit_flag" && !result.is_error {
                    EpisodeStatus::Captured { turn: index }
                } else {
                    EpisodeStatus::NotCaptured
                };
                recorded.push(outcome.to_recorded(tc));
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

    let ended_at = OffsetDateTime::now_utc();
    EpisodeTranscript {
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

/// Build an `infra_error` transcript (setup failed; the loop never ran).
fn infra_error(scenario: &Scenario, model: &dyn Model, detail: String) -> EpisodeTranscript {
    let now = rfc3339(OffsetDateTime::now_utc());
    EpisodeTranscript {
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
    // Fail closed (Constitution I): a scenario that asks for MCP but a binary built without the
    // `mcp` feature cannot provide it — refuse with a clear diagnostic rather than silently ignore.
    #[cfg(not(feature = "mcp"))]
    if scenario.mcp.enabled {
        return infra_error(
            scenario,
            model,
            "scenario enables [mcp] but bee was built without --features mcp".to_string(),
        );
    }

    let flag = scenario.workdir.flag.as_ref().map(|f| f.value.as_str());
    // Strip the provider key vars plus any configured MCP `token_env` names from every tool child
    // (FR-018/FR-041), so an MCP Bearer token never leaks into a sandboxed stdio server's env.
    let mut strip_env = sandbox::key_vars(provider_key_env);
    strip_env.extend(scenario.mcp.token_env_names());
    #[cfg_attr(not(feature = "mcp"), allow(unused_mut))]
    let mut opts = LoopOptions {
        progress,
        metrics: Recorder::new(
            "episode",
            format!("episode:{}:{}", scenario.id, std::process::id()),
        ),
        context: eopts.context,
        ..LoopOptions::default()
    };

    if let Err(e) = materialize_workdir(&scenario.workdir) {
        return infra_error(scenario, model, format!("workdir setup failed: {e}"));
    }

    // Discover skills from the scenario's explicit roots (006-skills). Malformed skills warn via the
    // progress sink but never abort the episode (Constitution I). The Arc is held until after the
    // loop so the `skill` tool's registry outlives it.
    let skills = std::sync::Arc::new(crate::skills::SkillRegistry::discover(&scenario.skills));
    for w in skills.warnings() {
        emit(
            &opts,
            format!("skill warning: {}: {}", w.path.display(), w.reason),
        );
    }

    // Resolve skill capability grants BEFORE the scope compiles (006-skills, step 3). Non-interactive:
    // the ceiling policy file is the operator's reviewable pre-authorization, so within-ceiling
    // requests widen the compiled policy and anything beyond is refused unpromptably. Register any
    // granted tools (Layer 1); the widened policy (Layer 2) flows into the scope below.
    let skill_refs: Vec<&crate::skills::Skill> = skills.iter().collect();
    let grants = resolve_episode_grants(scenario, &skill_refs).await;
    for name in &grants.granted {
        emit(
            &opts,
            format!("skill grant: '{name}' capabilities granted (within ceiling)"),
        );
    }
    for (name, reason) in &grants.refused {
        emit(&opts, format!("skill grant: '{name}' refused — {reason}"));
    }
    // Every tool is built from this episode's dependencies by the one constructor (024 FR-013): the
    // CTF flag, the skills, and the ledger and scanner grants (016) of the skill-widened policy. After
    // skill grants, so a scanner a skill widened the policy to include is visible; before the policy
    // is moved into the scope, which is the last point it can be read. The Interceptor joins below,
    // once it is running.
    // The struct update supplies the feature-gated fields, which a slim build does not have.
    #[allow(clippy::needless_update)]
    let deps = tools::ToolDeps {
        ctf_flag: flag.map(str::to_string),
        // Only model-facing skills make a `skill` tool worth offering (006).
        skills: skills
            .model_facing()
            .next()
            .is_some()
            .then(|| skills.clone()),
        ..tools::ToolDeps::default()
    }
    .with_security(
        &scenario.security,
        Some(&grants.policy),
        &format!("{}-{}", scenario.id, std::process::id()),
    );
    let mut registry = tools::ToolRegistry::with_deps(std::sync::Arc::new(deps));
    for tool in scenario.tools.iter().chain(&grants.tools) {
        // Scenario validation rejected unknown names; a skill-granted name is checked the same way.
        let _ = registry.register(tool);
    }
    // Keep the resolved policy as the escalation floor before it is moved into the scope (007).
    let escalation_base = grants.policy.clone();

    // HTTP interception (019). Decided before the scope compiles: the proxy port is the tool scope's
    // only network rule, so the listener is bound first.
    let wants_http = grants.policy.http.as_ref().is_some_and(|h| h.is_active());
    #[cfg(not(feature = "intercept"))]
    if wants_http {
        return infra_error(
            scenario,
            model,
            "the policy declares [policy.http] targets, but bee was built without \
             --features intercept; refusing to run its tools with an unenforced scope"
                .into(),
        );
    }
    #[cfg(feature = "intercept")]
    let http_advisory: Option<String> = if wants_http {
        match crate::intercept::session::advisory_reason(&grants.policy, cfg!(feature = "enforce"))
        {
            Some(reason) if !eopts.http_scope_advisory => {
                return infra_error(
                    scenario,
                    model,
                    crate::intercept::session::advisory_refusal(&reason),
                )
            }
            Some(reason) => {
                emit(&opts, crate::intercept::session::advisory_banner(&reason));
                Some(reason)
            }
            None => None,
        }
    } else {
        None
    };
    #[cfg(feature = "intercept")]
    let http_session_id = format!("{}-{}", sanitize_id(&scenario.id), std::process::id());

    #[cfg(feature = "enforce")]
    #[cfg_attr(not(feature = "intercept"), allow(unused_mut))]
    let (mut sandbox, http_prepared) =
        match build_enforced_sandbox(scenario, grants.policy, strip_env) {
            Ok(s) => s,
            Err(detail) => return infra_error(scenario, model, detail),
        };
    #[cfg(all(not(feature = "enforce"), feature = "intercept"))]
    let http_prepared = if wants_http {
        match crate::intercept::session::prepare(
            &grants.policy,
            &bee_userspace::SystemResolver::current(),
        ) {
            Ok(p) => p,
            Err(detail) => return infra_error(scenario, model, detail),
        }
    } else {
        None
    };
    #[cfg(not(feature = "enforce"))]
    #[cfg_attr(not(feature = "intercept"), allow(unused_mut))]
    let mut sandbox = Sandbox::host(strip_env);

    // Start the proxy worker — in its sidecar scope, or advisory — and give the HTTP tools its handle.
    #[cfg(feature = "intercept")]
    let http_session = match http_prepared {
        Some(prepared) => {
            let enforcement = match &http_advisory {
                Some(reason) => crate::intercept::sidecar::Enforcement::Advisory {
                    reason: reason.clone(),
                },
                None => crate::intercept::sidecar::Enforcement::Kernel,
            };
            let root = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
            match crate::intercept::session::start(
                prepared,
                &mut sandbox,
                &http_session_id,
                &root,
                enforcement,
            )
            .await
            {
                Ok(h) => {
                    let deps = (**registry.deps())
                        .clone()
                        .with_interceptor(h.interceptor.clone());
                    registry.set_deps(std::sync::Arc::new(deps));
                    Some(h)
                }
                Err(detail) => {
                    let _ = sandbox.teardown();
                    return infra_error(scenario, model, format!("HTTP interception: {detail}"));
                }
            }
        }
        None => None,
    };

    // Register the model-facing `skill` tool alongside the built-ins (a no-op when no skill is
    // model-facing: the deps above then hold none).
    let _ = registry.register("skill");

    // Dynamic capability grants (007-dynamic-grants). Reactive escalation on a kernel denial is
    // gated on a declared ceiling (the operator's pre-authorization); proactive skill-`requires`
    // escalation is always available. Consent is `AllowWithinCeiling` — the ceiling file IS the
    // authorization for a non-interactive episode. Both hooks are inert without their trigger, so an
    // episode with no ceiling and no capability-requesting skill behaves exactly as before.
    {
        let mut ceiling = match &scenario.ceiling_policy_path {
            Some(p) => bee_core::Policy::from_path(p).unwrap_or_else(|_| escalation_base.clone()),
            None => escalation_base.clone(),
        };
        // Keep the resolved base ⊆ ceiling: skill dirs were folded into the base as readable, so the
        // ceiling must permit them too.
        for s in skills.iter() {
            if let Some(dir) = s.dir.to_str() {
                ceiling
                    .filesystem
                    .entry(dir.to_string())
                    .or_insert(bee_core::Access::Read);
            }
        }
        let hooks: Vec<Box<dyn crate::hooks::LoopHook>> = vec![
            Box::new(crate::grants::escalate::DenialEscalationHook {
                enabled: scenario.ceiling_policy_path.is_some(),
            }),
            // 019 US3: a proxy refusal proposes exactly the refused host:port. The ceiling's
            // `[policy.http]` bounds it; the scenario's ceiling file is the authorisation.
            Box::new(crate::grants::escalate::ProxyRefusalHook {
                enabled: scenario.ceiling_policy_path.is_some(),
            }),
            Box::new(crate::grants::escalate::SkillEscalationHook::new(
                skills.clone(),
            )),
        ];
        opts.escalation = Some(crate::grants::escalate::LoopEscalation {
            base: escalation_base,
            ceiling,
            hooks,
            consent: std::sync::Arc::new(crate::skills::AllowWithinCeiling),
            timeout: std::time::Duration::from_secs(60),
            default_ttl: crate::grants::Ttl::Forever,
        });
    }

    // Connect MCP servers (if any) once the sandbox exists, register their tools alongside the
    // built-ins, and install the per-turn refresh hook (FR-043). The bridge (Arc so the hook can
    // hold a clone) owns the stdio children; dropping it at the end kills them (FR-034/42).
    #[cfg(feature = "mcp")]
    let bridge = {
        let b = std::sync::Arc::new(
            crate::mcp::McpBridge::connect(scenario.mcp.clone(), &sandbox).await,
        );
        b.register_into(&mut registry);
        let hook = b.clone();
        opts.refresh_tools = Some(Box::new(move |reg: &mut ToolRegistry| {
            if hook.take_dirty() {
                reg.remove_mcp_tools();
                hook.register_into(reg);
            }
        }));
        b
    };

    let mut transcript = run_loop(model, scenario, &mut registry, &mut sandbox, &opts).await;

    // The proxy worker goes before the scopes: its sidecar scope is torn down first (019 P4).
    #[cfg(feature = "intercept")]
    if let Some(h) = &http_session {
        h.shutdown().await;
        transcript.http_scope = Some(crate::transcript::HttpSessionHeader {
            enforcement: h.interceptor.enforcement().label().into(),
            advisory_reason: http_advisory.clone(),
            advisory_acknowledged: http_advisory.is_some(),
        });
    }

    // Drop the refresh hook (its bridge clone) then the bridge, killing the MCP children (they live in
    // the scope cgroup) before the scope itself is torn down.
    #[cfg(feature = "mcp")]
    {
        opts.refresh_tools = None;
        drop(bridge);
    }
    // A scope that will not empty means something survived the episode and is about to lose its
    // enforcement when the engine drops. Surface it on the progress sink rather than discarding it.
    if let Err(e) = sandbox.teardown() {
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

/// A minimal empty policy, used only as the never-read `GrantOutcome::policy` on the host no-op path
/// (no parseable base policy ⇒ no grants).
fn empty_policy() -> bee_core::Policy {
    bee_core::Policy {
        name: "none".to_string(),
        description: None,
        mode: bee_core::Mode::default(),
        filesystem: std::collections::BTreeMap::new(),
        exec: Default::default(),
        network: Default::default(),
        exfiltration: Default::default(),
        http: None,
    }
}

/// Resolve skill capability grants for an episode (006-skills, step 3). Non-interactive: the ceiling
/// policy file *is* the operator's reviewable pre-authorization, so within-ceiling requests widen the
/// compiled policy and beyond-ceiling ones are refused unpromptably. Also folds each discovered
/// skill's directory into the policy as readable, so the model can read bundled resources
/// (`references/…`) through the scope. A `policy_path` that can't be parsed (e.g. host-mode
/// `/dev/null`) yields a no-op outcome — instructions-only, no tool grants.
async fn resolve_episode_grants(
    scenario: &Scenario,
    skills: &[&crate::skills::Skill],
) -> crate::skills::GrantOutcome {
    use bee_core::{Access, Policy};

    let base = match Policy::from_path(&scenario.policy_path) {
        Ok(p) => p,
        Err(_) => {
            return crate::skills::GrantOutcome {
                policy: empty_policy(),
                tools: Vec::new(),
                granted: Vec::new(),
                refused: Vec::new(),
            }
        }
    };
    let ceiling = match &scenario.ceiling_policy_path {
        Some(p) => Policy::from_path(p).unwrap_or_else(|_| base.clone()),
        None => base.clone(),
    };
    let mut outcome =
        crate::skills::resolve_grants(skills, &base, &ceiling, &crate::skills::AllowWithinCeiling)
            .await;
    // Layer 2 readable-scope: declaring a skills root authorizes reading it, so each skill dir
    // becomes readable in-scope for the model to pull bundled resources via read_file.
    for s in skills {
        if let Some(dir) = s.dir.to_str() {
            outcome
                .policy
                .filesystem
                .entry(dir.to_string())
                .or_insert(Access::Read);
        }
    }
    widen_for_scanner_reports(&mut outcome.policy, scenario);
    outcome
}

/// Granting a scanner authorizes the report exchange the scan is made of (017).
///
/// The two-child pipeline has the scanner write SARIF to `.bee/scan/` and `bee sarif-worker` read it
/// back — both of them tool children, both under the scope. But `:project_root/.bee` is a
/// **default protection** (`PROTECTED_DEFAULTS`, FR-008): bee's own state is denied to tool children
/// so the model cannot reach the ledger or the transcripts. The scan report lives inside that
/// subtree, so under enforcement child 1's write and child 2's read were both refused and the scan
/// failed with `cannot read …: Permission denied` — invisible under `--host`, where nothing enforces
/// the deny at all.
///
/// So a resolved scanner grant widens the policy by exactly one subtree, in the same place and the
/// same way a skill grant does. More-specific-wins means `.bee/scan` is carved out while the rest of
/// `.bee` — `findings/` above all, where the ledger and its human verdicts live — stays denied.
fn widen_for_scanner_reports(policy: &mut bee_core::Policy, scenario: &Scenario) {
    #[cfg(feature = "scanners")]
    {
        use bee_core::Access;
        let grants = crate::scanners::grants_from_policy(Some(policy), &scenario.security);
        if grants.is_empty() {
            return;
        }
        policy
            .filesystem
            .entry(format!(":project_root/{}", crate::tools::scanner::SCAN_DIR))
            .or_insert(Access::Write);
    }
    #[cfg(not(feature = "scanners"))]
    {
        let _ = (policy, scenario);
    }
}

/// Bring up a real bee scope from the resolved policy and wrap it as an [`Sandbox::Enforced`]. The
/// policy is already widened by any approved skill grants and skill-dir reads (006-skills).
/// The interception setup an enforced sandbox was built with: `Some` when `[policy.http]` is active.
#[cfg(all(feature = "enforce", feature = "intercept"))]
type HttpPrepared = Option<crate::intercept::session::Prepared>;
#[cfg(all(feature = "enforce", not(feature = "intercept")))]
type HttpPrepared = Option<std::convert::Infallible>;

#[cfg(feature = "enforce")]
fn build_enforced_sandbox(
    scenario: &Scenario,
    policy: bee_core::Policy,
    strip_env: Vec<String>,
) -> Result<(Sandbox, HttpPrepared), String> {
    use bee_userspace::{EnforcementPlan, Engine, ScopeMode, SystemResolver};

    let resolver = SystemResolver::current();
    // 019: bind the proxy listener and compile the proxy scope *before* the tool policy, whose only
    // network rule becomes the proxy port.
    #[cfg(feature = "intercept")]
    let prepared = crate::intercept::session::prepare(&policy, &resolver)?;
    #[cfg(not(feature = "intercept"))]
    let prepared: HttpPrepared = None;
    #[cfg_attr(not(feature = "intercept"), allow(unused_mut))]
    let mut compiled = policy
        .compile(&resolver)
        .map_err(|e| format!("policy compile: {e}"))?;
    #[cfg(feature = "intercept")]
    if let Some(p) = &prepared {
        compiled = p.tool_policy(compiled);
    }
    let plan = EnforcementPlan::prepare(&compiled, ScopeMode::Enforce)
        .map_err(|e| format!("enforcement plan: {e}"))?;
    let mut engine = Engine::init().map_err(|e| format!("engine init: {e}"))?;

    let scope_id = format!(
        "bee-episode-{}-{}",
        sanitize(&scenario.id),
        std::process::id()
    );
    let scope = engine
        .create_scope(&scope_id, bee_userspace::cgroup::DEFAULT_PARENT, &plan)
        .map_err(|e| format!("create scope: {e}"))?;
    let reader = engine
        .take_audit_reader(&scope_id)
        .map_err(|e| format!("audit reader: {e}"))?;
    // The proxy scope comes from the same engine, before it moves into the sandbox (019 P4).
    #[cfg(feature = "intercept")]
    let sidecar = match &prepared {
        Some(p) => Some(
            crate::intercept::session::attach_sidecar(&mut engine, &scope_id, &p.compiled)
                .inspect_err(|_| {
                    let _ = scope.teardown();
                })?,
        ),
        None => None,
    };
    // `engine` moves into the sandbox so its eBPF programs stay attached for the whole episode.
    #[cfg_attr(not(feature = "intercept"), allow(unused_mut))]
    let mut sandbox = Sandbox::enforced(engine, scope, reader, strip_env);
    #[cfg(feature = "intercept")]
    if let Some(sc) = sidecar {
        sandbox = sandbox.with_sidecar(sc).map_err(|(sb, sc, e)| {
            let _ = sc.scope.teardown();
            let _ = sb.teardown();
            e.to_string()
        })?;
    }
    Ok((sandbox, prepared))
}

/// A scenario id reduced to `[A-Za-z0-9-]`, for session and scope names.
#[cfg_attr(not(feature = "intercept"), allow(dead_code))]
fn sanitize_id(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

#[cfg(feature = "enforce")]
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
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
            context: Default::default(),
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
        let (sandbox, _http) = build_enforced_sandbox(&scenario, policy, sandbox::key_vars(None))
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
            let proc = crate::mcp::transport::spawn_stdio(&sandbox, &cfg)
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
