use super::*;
use crate::repl::{ExchangeOutcome, ExchangeResult, ReplConfig, SteeringQueue};
use crate::transcript::{EpisodeTranscript, Timing};

pub(super) fn tool(output: &dyn ReplOutput, result: &ToolResult, audit: &[bee_core::AuditEvent]) {
    output.tool_result(result, audit);
    if let Some(spec) = &result.render_spec {
        let fx = result.inline_effect.as_ref();
        match &result.render_target {
            crate::render_spec::RenderTarget::Panel { id } => output.panel_update(id, spec),
            crate::render_spec::RenderTarget::Overlay { ttl_ms } => {
                output.overlay(spec, *ttl_ms, fx)
            }
            crate::render_spec::RenderTarget::Inline => output.render_widget(spec, fx),
        }
    }
    for op in &result.panel_ops {
        output.panel_op(op);
    }
}
/// A codemode script or one of its calls started (023). Grouped events carry a stable identity
/// so front ends can place nested calls under their script and update rows in place.
pub(super) fn start(
    output: &dyn ReplOutput,
    context: crate::repl::presentation::CallContext,
    call: &crate::provider::ToolCall,
) {
    output.tool_event(&crate::repl::presentation::CallEvent {
        context,
        call: call.clone(),
        outcome: crate::repl::presentation::CallOutcome::Running,
    });
}

/// A codemode script or one of its calls finished. Every committed inner result carries a
/// receipt; a record without one is evidence of an unresolved outcome, never success.
pub(super) fn grouped(
    output: &dyn ReplOutput,
    context: crate::repl::presentation::CallContext,
    call: &crate::provider::ToolCall,
    result: &ToolResult,
    audit: &[bee_core::AuditEvent],
) {
    let outcome = if context.parent.is_some() && result.receipt_id.is_none() {
        crate::repl::presentation::CallOutcome::Unresolved {
            detail: result.content.clone(),
        }
    } else {
        crate::repl::presentation::CallOutcome::Completed {
            result: Box::new(result.clone()),
            audit: audit.to_vec(),
        }
    };
    output.tool_event(&crate::repl::presentation::CallEvent {
        context,
        call: call.clone(),
        outcome,
    });
    if let Some(spec) = &result.render_spec {
        let fx = result.inline_effect.as_ref();
        match &result.render_target {
            crate::render_spec::RenderTarget::Panel { id } => output.panel_update(id, spec),
            crate::render_spec::RenderTarget::Overlay { ttl_ms } => {
                output.overlay(spec, *ttl_ms, fx)
            }
            crate::render_spec::RenderTarget::Inline => output.render_widget(spec, fx),
        }
    }
    for op in &result.panel_ops {
        output.panel_op(op);
    }
}

impl Driver {
    pub(super) fn call_context(
        &self,
        call: &str,
        parent: Option<&str>,
    ) -> crate::repl::presentation::CallContext {
        crate::repl::presentation::CallContext::new(
            &self.active().request_id,
            self.active().turns.last().map_or(0, |t| t.index),
            call,
            parent,
            false,
            parent
                .and_then(|id| self.active().scripts.iter().position(|s| s.outer.id == id))
                .map_or(0, |index| index + 1),
        )
    }
}

struct Progress<'a>(&'a crate::episode::LoopOptions);
impl ReplOutput for Progress<'_> {
    fn tool_event(&self, event: &crate::repl::presentation::CallEvent) {
        self.info(&event.text());
    }
    fn assistant_delta(&self, text: &str) {
        self.info(text);
    }
    fn assistant_end(&self) {}
    fn tool_call(&self, name: &str, arguments: &serde_json::Value) {
        self.info(&format!("call {name} {arguments}"));
    }
    fn tool_result(&self, result: &ToolResult, _: &[bee_core::AuditEvent]) {
        self.info(&result.content);
    }
    fn error(&self, detail: &str) {
        self.info(detail);
    }
    fn info(&self, text: &str) {
        if let Some(sink) = &self.0.progress {
            sink(text);
        }
    }
}
#[derive(Clone)]
pub struct RunBinding {
    pub session: Arc<Session>,
    pub request_id: String,
    pub resume: bool,
    pub tool_call_limit: u32,
}

pub async fn run_episode(
    model: &dyn Model,
    scenario: &crate::Scenario,
    registry: &mut ToolRegistry,
    sandbox: &mut Sandbox,
    options: &crate::episode::LoopOptions,
    binding: &RunBinding,
) -> EpisodeTranscript {
    let limits = Limits {
        turns: scenario.turn_limit,
        tool_calls: binding.tool_call_limit,
        timeout_ms: scenario.timeout_secs.saturating_mul(1000),
        tool_timeout_ms: scenario.timeout_secs.saturating_mul(1000),
        model_attempts: options.max_retries.saturating_add(1).min(10),
    };
    let result = if scenario.context != Default::default()
        || options.context.config != Default::default()
        || scenario.stuck != Default::default()
        || options.stuck != Default::default()
    {
        Err(DriverError::Refused(
            "durable sessions do not yet support context/stuck settings".into(),
        ))
    } else {
        binding
            .session
            .run(
                &binding.request_id,
                (!binding.resume).then_some(scenario.task.as_str()),
                &scenario.system_prompt,
                limits,
                model,
                registry,
                sandbox,
                &Progress(options),
                options.escalation.as_ref(),
            )
            .await
    };
    match result {
        Ok((report, _)) => transcript(report, &scenario.id, model.id(), sandbox),
        Err(error) => {
            // Committed, validated results that preceded the failure stay in the transcript.
            if let Ok(Some(mut report)) = binding
                .session
                .partial_report(&binding.request_id, registry)
                .await
            {
                report.status = match &error {
                    DriverError::Provider(_) => EpisodeStatus::ApiError {
                        detail: error.to_string(),
                    },
                    _ => EpisodeStatus::InfraError {
                        detail: error.to_string(),
                    },
                };
                return transcript(report, &scenario.id, model.id(), sandbox);
            }
            let budget = binding
                .session
                .budget(&binding.request_id)
                .await
                .ok()
                .flatten();
            EpisodeTranscript {
                consents: vec![],
                mcp_audit: Default::default(),
                finish_offered: false,
                compactions: vec![],
                summary_usage: None,
                http_scope: None,
                scenario_id: scenario.id.clone(),
                model_id: model.id().into(),
                status: match &error {
                    DriverError::Provider(_) => EpisodeStatus::ApiError {
                        detail: error.to_string(),
                    },
                    _ => EpisodeStatus::InfraError {
                        detail: error.to_string(),
                    },
                },
                turns: vec![],
                audit_trail: vec![],
                audit_health: sandbox.audit_health(),
                timing: Timing {
                    started_at: String::new(),
                    ended_at: String::new(),
                    total_ms: 0,
                },
                usage: budget.as_ref().and_then(|b| b.known_usage().ok().flatten()),
                durable_budget: budget,
                score: None,
            }
        }
    }
}
fn timestamp(ms: u64) -> String {
    time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}
fn transcript(report: Report, id: &str, model: &str, sandbox: &Sandbox) -> EpisodeTranscript {
    let audit = report
        .turns
        .iter()
        .flat_map(|t| t.calls.iter().flat_map(|c| c.audit.clone()))
        .collect();
    EpisodeTranscript {
        consents: vec![],
        mcp_audit: Default::default(),
        finish_offered: false,
        compactions: vec![],
        summary_usage: None,
        http_scope: None,
        scenario_id: id.into(),
        model_id: model.into(),
        status: report.status,
        turns: report.turns,
        audit_trail: audit,
        audit_health: sandbox.audit_health(),
        timing: Timing {
            started_at: timestamp(report.started_ms),
            ended_at: timestamp(report.ended_ms),
            total_ms: report.ended_ms.saturating_sub(report.started_ms),
        },
        usage: report.usage,
        durable_budget: Some(report.budget),
        score: None,
    }
}
#[allow(clippy::too_many_arguments)]
pub async fn exchange(
    user_message: &str,
    model: &dyn Model,
    conversation: &mut Conversation,
    registry: &mut ToolRegistry,
    sandbox: &mut Sandbox,
    config: &ReplConfig,
    output: &dyn ReplOutput,
    steering: &SteeringQueue,
    session: &Session,
) -> ExchangeResult {
    let request =
        if config.context.config != Default::default() || config.stuck != Default::default() {
            Err(DriverError::Refused(
                "durable sessions do not yet support context/stuck settings".into(),
            ))
        } else if user_message.is_empty() {
            session
                .resume_request()
                .map(str::to_owned)
                .ok_or_else(|| DriverError::Refused("no pending submission".into()))
        } else {
            request_id()
        };
    let admitted_request = request.as_ref().ok().cloned();
    let result = match request {
        Ok(request) => {
            // Queue against the known request before a fast provider can finish it.
            {
                let mut queue = steering.lock().expect("steering queue");
                while let Some(text) = queue.front() {
                    if text.len() > 16 * 1024 {
                        output.error("steering input exceeds 16 KiB; input was not admitted");
                        break;
                    }
                    if session
                        .send(Input::Steering {
                            parent: request.clone(),
                            text: text.clone(),
                        })
                        .is_err()
                    {
                        break;
                    }
                    queue.pop_front();
                }
            }
            let future = session.run(
                &request,
                (!user_message.is_empty()).then_some(user_message),
                &config.system_prompt,
                Limits {
                    turns: config.agent_turn_budget,
                    tool_calls: config.durable_tool_call_limit,
                    timeout_ms: config.durable_timeout_secs.saturating_mul(1000),
                    tool_timeout_ms: config.tool_timeout_secs.saturating_mul(1000),
                    model_attempts: config.max_retries.saturating_add(1).min(10),
                },
                model,
                registry,
                sandbox,
                output,
                config.escalation.as_ref().map(|e| &e.config),
            );
            tokio::pin!(future);
            let mut interval = tokio::time::interval(Duration::from_millis(10));
            loop {
                tokio::select! {
                    result = &mut future => break result,
                    _ = interval.tick() => {
                        let mut queue = steering.lock().expect("steering queue");
                        while let Some(text) = queue.front() {
                            match session.steer(text.clone()) { Ok(()) => { queue.pop_front(); }, Err(_) => break }
                        }
                    }
                }
            }
        }
        Err(error) => Err(error),
    };
    match result {
        Ok((report, restored)) => {
            *conversation = restored;
            let tool_calls = report.turns.iter().map(|t| t.calls.len() as u32).sum();
            let audit: Vec<_> = report
                .turns
                .iter()
                .flat_map(|t| t.calls.iter().flat_map(|c| c.audit.clone()))
                .collect();
            let outcome = match report.status {
                EpisodeStatus::Completed | EpisodeStatus::NoToolCalls => ExchangeOutcome::Responded,
                EpisodeStatus::Timeout => ExchangeOutcome::BudgetExhausted,
                other => ExchangeOutcome::Terminated(format!("{other:?}")),
            };
            ExchangeResult {
                compactions: vec![],
                durable_budget: Some(report.budget),
                outcome,
                model_calls: report.model_calls,
                tool_calls,
                denials: audit.iter().filter(|e| e.decision == "denied").count() as u32,
                turns: report.turns,
                audit,
                usage: report.usage,
            }
        }
        Err(error) => {
            output.error(&error.to_string());
            let budget = if let Some(id) = admitted_request.as_deref() {
                session.budget(id).await.ok().flatten()
            } else {
                None
            };
            // Committed, validated results that preceded the failure stay visible.
            let partial = if let Some(id) = admitted_request.as_deref() {
                session.partial_report(id, registry).await.ok().flatten()
            } else {
                None
            };
            let turns = partial.map(|report| report.turns).unwrap_or_default();
            let audit: Vec<_> = turns
                .iter()
                .flat_map(|turn| turn.calls.iter().flat_map(|call| call.audit.clone()))
                .collect();
            ExchangeResult {
                compactions: vec![],
                outcome: match &error {
                    DriverError::Provider(_) => ExchangeOutcome::ApiError(error.to_string()),
                    _ => ExchangeOutcome::Terminated(error.to_string()),
                },
                model_calls: budget.as_ref().map_or(0, |b| b.charged(WorkKind::Model)),
                tool_calls: budget.as_ref().map_or(0, |b| b.charged(WorkKind::Tool)),
                denials: audit.iter().filter(|e| e.decision == "denied").count() as u32,
                turns,
                audit,
                usage: budget.as_ref().and_then(|b| b.known_usage().ok().flatten()),
                durable_budget: budget,
            }
        }
    }
}
