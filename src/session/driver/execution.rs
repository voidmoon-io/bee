use super::*;

impl Driver {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn run(
        &mut self,
        request: &str,
        text: Option<&str>,
        system: &str,
        limits: Limits,
        model: &dyn Model,
        registry: &mut ToolRegistry,
        sandbox: &mut Sandbox,
        output: &dyn ReplOutput,
        hooks: Option<&crate::grants::escalate::LoopEscalation>,
    ) -> Result<(Report, Conversation), DriverError> {
        if !sandbox.durable_compatible()
            || registry.schemas().iter().any(|s| {
                s.name == "finish"
                    || s.name.starts_with("http_")
                    || registry.mcp_server(&s.name).is_some()
            })
            || hooks.is_some_and(|h| h.base.http.is_some())
        {
            return Err(DriverError::Refused("durable sessions do not support HTTP interception, persistent MCP transports, or finish".into()));
        }
        let enforced = !matches!(sandbox, Sandbox::Host(_));
        let policy = if enforced {
            hooks.map(|h| (&h.base, &h.ceiling))
        } else {
            None
        };
        let runtime = fingerprint(&(
            system,
            model.id(),
            codemode::schemas(registry),
            crate::python::RUNTIME_ID,
            enforced,
            policy,
        ))?;
        if let Some(report) = self.begin(request, text, system, limits, runtime).await? {
            self.replay_report(&report, registry, output)?;
            return Ok((report, self.journal().conversation.conversation().clone()));
        }
        output.info(&format!("durable submission admitted: {request}"));
        let active = self.active();
        let previous = Report {
            request_id: active.request_id.clone(),
            status: EpisodeStatus::Completed,
            turns: active.turns.clone(),
            usage: active.usage,
            started_ms: active.started_ms,
            ended_ms: active.started_ms,
            model_calls: active.model_calls,
            budget: active.budget.clone(),
        };
        self.replay_report(&previous, registry, output)?;
        if let Step::Model { chunks, .. } = &self.active().step {
            if !chunks.is_empty() {
                output.info("recovered committed text from an interrupted provider response:");
                for chunk in chunks {
                    output.assistant_delta(chunk);
                }
                output.assistant_end();
            }
        }
        let mut active_policy = hooks
            .map(|h| crate::grants::ActivePolicy::new(h.base.clone(), h.ceiling.clone()))
            .transpose()
            .map_err(DriverError::Refused)?;
        if let (Some(h), Some(active)) = (hooks, active_policy.as_ref()) {
            h.initialize(active, sandbox)
                .map_err(DriverError::Refused)?;
        }
        let result: Result<Report, DriverError> = async {
            let result = self
                .drive(model, registry, sandbox, output, hooks, &mut active_policy)
                .await;
            let report = match result {
                Ok(status) => self.finish(status, output).await?,
                // A capacity limit or a refusal recurs on every resume, so it ends the submission
                // like a cancellation instead of leaving it active and blocking the session.
                Err(
                    error @ (DriverError::Cancelled
                    | DriverError::Expired
                    | DriverError::BudgetExhausted
                    | DriverError::Core(core::Error::Limit)
                    | DriverError::Refused(_)),
                ) => {
                    self.cancel_intent().await?;
                    // A worker result may commit while cancellation is being admitted.
                    match self
                        .drive(model, registry, sandbox, output, hooks, &mut active_policy)
                        .await
                    {
                        Ok(_)
                        | Err(
                            DriverError::Cancelled
                            | DriverError::Expired
                            | DriverError::BudgetExhausted,
                        ) => {}
                        Err(error) => return Err(error),
                    }
                    self.cleanup_cancelled(sandbox).await?;
                    let status =
                        if matches!(error, DriverError::Expired | DriverError::BudgetExhausted) {
                            EpisodeStatus::Timeout
                        } else {
                            EpisodeStatus::Terminated {
                                detail: error.to_string(),
                            }
                        };
                    self.finish(status, output).await?
                }
                Err(error) => return Err(error),
            };
            Ok(report)
        }
        .await;
        // Leases are scoped to this submission; a retained REPL sandbox returns to its base.
        if let Some(active) = active_policy.as_mut() {
            let leases: Vec<_> = active.leases().iter().map(|l| l.id.clone()).collect();
            crate::grants::escalate::release_leases(&leases, active, sandbox, registry)
                .await
                .map_err(DriverError::Refused)?;
            let deps = (**registry.deps()).clone().with_policy(active.active());
            registry.set_deps(Arc::new(deps));
        }
        let report = result?;
        Ok((report, self.journal().conversation.conversation().clone()))
    }
    /// Validate every evidence-dependent entry before presenting any recovered observation.
    pub(super) fn validate_receipts(
        &self,
        report: &Report,
        registry: &ToolRegistry,
    ) -> Result<(), DriverError> {
        for turn in &report.turns {
            for call in &turn.calls {
                if call.result.receipt_id.is_none() {
                    continue;
                }
                let entry = self
                    .state
                    .committed()
                    .entries()
                    .iter()
                    .find(|entry| {
                        entry
                            .result
                            .output
                            .get("receipt_id")
                            .and_then(|id| id.as_str())
                            == call.result.receipt_id.as_deref()
                    })
                    .ok_or_else(|| {
                        DriverError::Refused("committed receipt entry missing".into())
                    })?;
                registry.deliver_durable(&self.state, entry)?;
            }
        }
        Ok(())
    }
    fn replay_report(
        &self,
        report: &Report,
        registry: &ToolRegistry,
        output: &dyn ReplOutput,
    ) -> Result<(), DriverError> {
        self.validate_receipts(report, registry)?;
        if report.budget.unreported_model_usage() > 0 {
            output.info(&format!("usage is incomplete for {} charged provider attempt(s); {} attempt(s) have unresolved outcomes",
                report.budget.unreported_model_usage(), report.budget.unresolved()));
        }
        for turn in &report.turns {
            if let Some(text) = &turn.assistant_text {
                output.assistant_delta(text);
                output.assistant_end();
            }
            let mut parents = std::collections::BTreeSet::new();
            for call in &turn.calls {
                if call.parent_call_id.is_none() && call.call.name != "codemode" {
                    output.tool_call(&call.call.name, &call.call.arguments);
                    presentation::tool(output, &call.result, &call.audit);
                    continue;
                }
                // Script calls replay grouped. A nested script is recorded after its children,
                // so its row is opened from its own record before the first child arrives.
                let context = |id: &str, parent: Option<&str>| {
                    crate::repl::presentation::CallContext::new(
                        &report.request_id,
                        turn.index,
                        id,
                        parent,
                        true,
                    )
                };
                if let Some(parent) = &call.parent_call_id {
                    if let Some(outer) = turn
                        .calls
                        .iter()
                        .find(|c| c.call.id == *parent)
                        .filter(|_| parents.insert(parent.clone()))
                    {
                        presentation::start(
                            output,
                            context(parent, outer.parent_call_id.as_deref()),
                            &outer.call,
                        );
                    }
                }
                let ctx = context(&call.call.id, call.parent_call_id.as_deref());
                presentation::start(output, ctx.clone(), &call.call);
                presentation::grouped(output, ctx, &call.call, &call.result, &call.audit);
            }
        }
        Ok(())
    }
    async fn drive(
        &mut self,
        model: &dyn Model,
        registry: &mut ToolRegistry,
        sandbox: &mut Sandbox,
        output: &dyn ReplOutput,
        hooks: Option<&crate::grants::escalate::LoopEscalation>,
        active_policy: &mut Option<crate::grants::ActivePolicy>,
    ) -> Result<EpisodeStatus, DriverError> {
        loop {
            sandbox.check_cleanup().map_err(DriverError::Refused)?;
            self.consume_inputs(output, false).await?;
            self.recover_worker(registry, sandbox, output, hooks, active_policy)
                .await?;
            let inject = matches!(
                self.active().step,
                Step::Model {
                    operation: None,
                    ..
                }
            );
            self.sync_inputs(output, inject).await?;
            if self.active().model_calls >= self.active().limits.turns {
                if let Step::Model {
                    operation: Some(id),
                    ..
                } = self.active().step
                {
                    if self.state.committed().operation(id).is_some_and(|op| {
                        matches!(op.phase, Phase::Ready | Phase::Recovering { .. })
                    }) {
                        return Err(DriverError::BudgetExhausted);
                    }
                }
            }
            if self.active().wake.is_none() {
                if let Step::Model {
                    operation: Some(id),
                    ..
                } = self.active().step
                {
                    if let Some(Operation {
                        phase: Phase::Recovering { attempt },
                        ..
                    }) = self.state.committed().operation(id)
                    {
                        let attempt = attempt.clone();
                        let delay = retry_delay(attempt.number);
                        self.schedule_retry(attempt, delay)?;
                        self.save().await?;
                    }
                }
            }
            self.retry_wait(output).await?;
            match self.active().step.clone() {
                Step::Model { operation, .. } => {
                    if operation.is_none()
                        && self.active().model_calls >= self.active().limits.turns
                    {
                        return Err(DriverError::BudgetExhausted);
                    }
                    let turn_no = self.active().model_calls;
                    let ready = operation
                        .and_then(|id| self.state.committed().operation(id))
                        .is_none_or(|op| !matches!(op.phase, Phase::Completed { .. }));
                    if let (true, Some(h), Some(active)) = (ready, hooks, active_policy.as_mut()) {
                        let future = crate::turn::turn_start(
                            turn_no,
                            &h.hooks,
                            Some(active),
                            sandbox,
                            registry,
                            None,
                        );
                        let outcome = self.wait(future, self.active().deadline_ms, output).await?;
                        if let Some(reason) = outcome.narrow_error {
                            return Err(DriverError::Refused(reason));
                        }
                    }
                    let schemas = codemode::schemas(registry);
                    let conversation = self.journal().conversation.conversation().clone();
                    if let (true, Some(h), Some(active)) = (ready, hooks, active_policy.as_mut()) {
                        let future = crate::grants::escalate::lifecycle_step(
                            h,
                            active,
                            crate::hooks::StepEvent::BeforeModelCall {
                                convo: &conversation,
                                schemas: &schemas,
                            },
                            sandbox,
                            registry,
                        );
                        let outcome = self.wait(future, self.active().deadline_ms, output).await?;
                        outcome.map_err(DriverError::Refused)?;
                    }
                    let spec = OperationSpec {
                        kind: WorkKind::Model,
                        name: model.id().into(),
                        version: 1,
                        input: json!({"request": fingerprint(&(conversation.clone(), &schemas))?}),
                        recovery: RecoveryPolicy::RetrySafe {
                            max_attempts: self.active().limits.model_attempts,
                        },
                        deadline_ms: self.active().deadline_ms,
                    };
                    let id = self.operation(spec.clone(), true, sandbox).await?;
                    if !matches!(
                        self.state.committed().operation(id).unwrap().phase,
                        Phase::Completed { .. }
                    ) && self.state.committed().operation(id).unwrap().spec != spec
                    {
                        return Err(DriverError::Incompatible);
                    }
                    let mut streamed = false;
                    if matches!(
                        self.state.committed().operation(id).unwrap().phase,
                        Phase::Ready
                    ) {
                        if self.active().model_calls >= self.active().limits.turns {
                            return Err(DriverError::BudgetExhausted);
                        }
                        for entry in self.state.committed().entries() {
                            if entry.result.receipt.is_some() {
                                registry.deliver_durable(&self.state, entry)?;
                            }
                        }
                        if let Step::Model { chunks, .. } = &mut self.active_mut().step {
                            chunks.clear();
                        }
                        let attempt = self.authorize(id).await?;
                        output.busy_start();
                        let started = std::time::Instant::now();
                        let response = self.model(model, &conversation, &schemas, output).await;
                        output.busy_stop();
                        let turn = match response {
                            Ok(turn) => turn,
                            Err(DriverError::Provider(
                                crate::provider::ModelError::Transient { retry_after, .. },
                            )) => {
                                self.active_mut().budget.interrupt();
                                self.schedule_retry(
                                    attempt.clone(),
                                    retry_after.unwrap_or_else(|| retry_delay(attempt.number)),
                                )?;
                                self.apply(Event::Interrupted {
                                    attempt: attempt.clone(),
                                })
                                .await?;
                                continue;
                            }
                            Err(error @ DriverError::Provider(_)) => {
                                self.active_mut().budget.interrupt();
                                self.apply(Event::Interrupted { attempt }).await?;
                                return Err(error);
                            }
                            Err(error) => return Err(error),
                        };
                        let duration_ms = elapsed_ms(started);
                        self.active_mut()
                            .budget
                            .settle(&attempt, turn.usage, duration_ms)?;
                        self.active_mut().usage = self.active().budget.known_usage()?;
                        self.apply(Event::Completed {
                            attempt,
                            result: Completion {
                                duration_ms,
                                audit: vec![],
                                output: serde_json::to_value(turn)?,
                                receipt: None,
                            },
                        })
                        .await?;
                        streamed = true;
                    }
                    let Phase::Completed { result, .. } =
                        &self.state.committed().operation(id).unwrap().phase
                    else {
                        return Err(DriverError::Unresolved(id.0));
                    };
                    let duration_ms = result.duration_ms;
                    let turn: Turn = serde_json::from_value(result.output.clone())?;
                    if !streamed {
                        if let Some(text) = &turn.text {
                            output.assistant_delta(text);
                            output.assistant_end();
                        }
                    }
                    self.journal_mut().conversation.push(Message::Assistant {
                        text: turn.text.clone(),
                        tool_calls: turn.tool_calls.clone(),
                    });
                    let index = self.active().turns.len() as u32;
                    self.active_mut().turns.push(TranscriptTurn {
                        notes: vec![],
                        index,
                        assistant_text: turn.text.clone(),
                        calls: vec![],
                        duration_ms,
                    });
                    self.active_mut().step = Step::Tools {
                        model_operation: id,
                        next: 0,
                        operation: None,
                        executor: None,
                        executor_activation: None,
                    };
                    self.save().await?;
                }
                Step::Tools {
                    model_operation,
                    next,
                    ..
                } => {
                    if self
                        .active()
                        .turns
                        .last()
                        .and_then(|t| t.calls.last())
                        .is_some_and(|c| c.result.terminal && c.parent_call_id.is_none())
                    {
                        return Ok(EpisodeStatus::Completed);
                    }
                    let Phase::Completed { result, .. } = &self
                        .state
                        .committed()
                        .operation(model_operation)
                        .ok_or(core::Error::NotFound)?
                        .phase
                    else {
                        return Err(core::Error::InvalidSnapshot.into());
                    };
                    let turn: Turn = serde_json::from_value(result.output.clone())?;
                    if next == turn.tool_calls.len() {
                        let any_steering = self.inbox.iter().any(|s| s.sequence > self.active().consumed_inputs && matches!(serde_json::from_value::<Input>(s.input.clone()), Ok(Input::Steering { parent, .. }) if parent == self.active().request_id));
                        if turn.tool_calls.is_empty() && !any_steering && self.controls.is_empty() {
                            let tools = self.active().turns.iter().any(|t| !t.calls.is_empty());
                            return Ok(if tools {
                                EpisodeStatus::Completed
                            } else {
                                EpisodeStatus::NoToolCalls
                            });
                        }
                        self.active_mut().step = Step::Model {
                            operation: None,
                            chunks: vec![],
                        };
                        self.save().await?;
                        continue;
                    }
                    let call = turn
                        .tool_calls
                        .get(next)
                        .ok_or(core::Error::InvalidSnapshot)?
                        .clone();
                    // A codemode call runs as a script; its leaves come back here one at a time.
                    let call = if call.name == "codemode" {
                        // Boxed: the script and overlap futures would otherwise inflate this
                        // already large state machine past a test thread's stack.
                        match Box::pin(self.script_next(call, registry, sandbox, output)).await? {
                            Some(child) => {
                                Box::pin(self.overlap_batch(
                                    registry,
                                    sandbox,
                                    output,
                                    hooks,
                                    active_policy,
                                ))
                                .await?;
                                child
                            }
                            None => continue,
                        }
                    } else {
                        call
                    };
                    let operation = self.active().step.operation();
                    let parent_call_id =
                        self.active().scripts.last().map(|s| s.parent().to_string());
                    let deadline = self
                        .time()
                        .saturating_add(self.active().limits.tool_timeout_ms)
                        .min(self.active().deadline_ms);
                    let spec = if let Some(op) =
                        operation.and_then(|id| self.state.committed().operation(id))
                    {
                        op.spec.clone()
                    } else {
                        registry.durable_spec(&call, &self.compatibility, deadline)?
                    };
                    let deadline = spec.deadline_ms;
                    let id = self.operation(spec, false, sandbox).await?;
                    let phase = self.state.committed().operation(id).unwrap().phase.clone();

                    if matches!(phase, Phase::Ready) {
                        let mut refusal = None;
                        if let (Some(h), Some(active)) = (hooks, active_policy.as_mut()) {
                            let mut escalation = crate::call::Escalation {
                                config: h,
                                active,
                                lease_turn: self.active().model_calls.saturating_sub(1),
                            };
                            let future =
                                crate::call::before_call(&mut escalation, &call, sandbox, registry);
                            match self.wait(future, deadline, output).await? {
                                crate::call::Before::Refused(reason) => {
                                    refusal = Some(ToolResult::refused_by_hook(&reason))
                                }
                                crate::call::Before::Stopped(reason) => {
                                    return Err(DriverError::Refused(reason))
                                }
                                crate::call::Before::Run(_) => {}
                            }
                        }
                        let activation = self.state.activation().0.to_string();
                        if let Step::Tools {
                            executor,
                            executor_activation,
                            ..
                        } = &mut self.active_mut().step
                        {
                            *executor = executor::Executor::capture(sandbox)?;
                            *executor_activation = Some(activation);
                        }
                        registry.check_durable_compatibility(
                            &self.state.committed().operation(id).unwrap().spec,
                            &self.compatibility,
                        )?;
                        let attempt = self.authorize(id).await?;
                        match &parent_call_id {
                            Some(parent) => presentation::start(
                                output,
                                self.call_context(&call.id, Some(parent)),
                                &call,
                            ),
                            None => output.tool_call(&call.name, &call.arguments),
                        }
                        let started = std::time::Instant::now();
                        let journaled = registry.supports_journal(&call) && refusal.is_none();
                        let mut result = if let Some(refusal) = refusal {
                            ToolRegistry::prepare_completion(
                                &self.evidence,
                                &attempt,
                                &call,
                                refusal,
                            )?
                        } else if registry.supports_journal(&call) {
                            let spec = self.state.committed().operation(id).unwrap().spec.clone();
                            let limit = spec.deadline_ms;
                            let journal = self.storage.worker(attempt.clone(), spec).await?;
                            let future = registry.execute_journaled(
                                &self.state,
                                &self.compatibility,
                                journal,
                                sandbox,
                            );
                            self.wait(future, limit, output).await??
                        } else {
                            let now = self.time();
                            let future = registry.execute_durable(
                                &self.state,
                                &attempt,
                                &self.compatibility,
                                now,
                                sandbox,
                            );
                            let limit = self
                                .state
                                .committed()
                                .operation(id)
                                .unwrap()
                                .spec
                                .deadline_ms;
                            self.wait(future, limit, output).await??
                        };
                        sandbox.settle().await;
                        let mut audit = sandbox.drain_audit(None);
                        sandbox.retain_audit(&mut audit);
                        if !journaled {
                            result.duration_ms = elapsed_ms(started);
                            result.audit.extend(audit);
                        }
                        self.active_mut()
                            .budget
                            .settle(&attempt, None, result.duration_ms)?;
                        self.apply(Event::Completed { attempt, result }).await?;
                    }
                    if let Phase::Publishing { attempt, .. } =
                        &self.state.committed().operation(id).unwrap().phase
                    {
                        let token = RecoveryToken {
                            activation: self.state.activation(),
                            attempt: attempt.clone(),
                        };
                        let event = registry.publish_durable(&self.state, &token)?;
                        self.apply(event).await?;
                    }
                    let entry = self
                        .state
                        .committed()
                        .entries()
                        .iter()
                        .find(|e| e.attempt.operation == id)
                        .ok_or(DriverError::Unresolved(id.0))?;
                    let duration_ms = entry.result.duration_ms;
                    let audit = entry.result.audit.clone();
                    let result = registry.deliver_durable(&self.state, entry)?;
                    // A script's call result goes to the script, not the model.
                    let terminal = result.terminal && parent_call_id.is_none();
                    if parent_call_id.is_none() {
                        self.journal_mut().conversation.push(Message::ToolResult {
                            provenance: result.provenance.clone(),
                            call_id: call.id.clone(),
                            name: call.name.clone(),
                            content: result.content.clone(),
                            is_error: result.is_error,
                        });
                    }
                    self.active_mut()
                        .turns
                        .last_mut()
                        .ok_or(core::Error::InvalidSnapshot)?
                        .calls
                        .push(RecordedCall {
                            parent_call_id: parent_call_id.clone(),
                            proxy_events: vec![],
                            denied_attempt_audit: vec![],
                            denied_attempt_proxy_events: vec![],
                            escalations: vec![],
                            retried: false,
                            timed_out: false,
                            not_run: false,
                            refused_by_hook: None,
                            call: call.clone(),
                            result: result.clone(),
                            audit: audit.clone(),
                        });
                    let recorded_turn = self
                        .active_mut()
                        .turns
                        .last_mut()
                        .ok_or(core::Error::InvalidSnapshot)?;
                    recorded_turn.duration_ms =
                        recorded_turn.duration_ms.saturating_add(duration_ms);
                    self.active_mut().step = Step::Tools {
                        model_operation,
                        // A script's call leaves the model's call cursor where it is.
                        next: if parent_call_id.is_some() {
                            next
                        } else {
                            next + 1
                        },
                        operation: None,
                        executor: None,
                        executor_activation: None,
                    };
                    if let Some(script) = self.active_mut().scripts.last_mut() {
                        script.child_delivered();
                    }
                    self.save().await?;
                    match &parent_call_id {
                        Some(parent) => presentation::grouped(
                            output,
                            self.call_context(&call.id, Some(parent)),
                            &call,
                            &result,
                            &audit,
                        ),
                        None => presentation::tool(output, &result, &audit),
                    }
                    if let (Some(h), Some(active)) = (hooks, active_policy.as_mut()) {
                        if let Some((op, target)) = crate::call::first_denial(&audit) {
                            let mut escalation = crate::call::Escalation {
                                config: h,
                                active,
                                lease_turn: self.active().model_calls.saturating_sub(1),
                            };
                            let future = crate::call::reactive(
                                &mut escalation,
                                &op,
                                &target,
                                &call,
                                sandbox,
                                registry,
                            );
                            let outcome =
                                self.wait(future, self.active().deadline_ms, output).await?;
                            // Grants authorize future calls; the receipted denial stays unchanged.
                            outcome.map_err(DriverError::Refused)?;
                        }
                        let future = crate::grants::escalate::lifecycle_step(
                            h,
                            active,
                            crate::hooks::StepEvent::AfterToolResult {
                                call: &call,
                                result: &result,
                                audit: &audit,
                            },
                            sandbox,
                            registry,
                        );
                        let outcome = self.wait(future, self.active().deadline_ms, output).await?;
                        outcome.map_err(DriverError::Refused)?;
                    }
                    if terminal {
                        return Ok(EpisodeStatus::Completed);
                    }
                }
            }
        }
    }
    async fn model(
        &mut self,
        model: &dyn Model,
        conversation: &Conversation,
        schemas: &[crate::provider::ToolSchema],
        output: &dyn ReplOutput,
    ) -> Result<Turn, DriverError> {
        let deadline = self.active().deadline_ms;
        let mut stream = self
            .wait(model.stream(conversation, schemas), deadline, output)
            .await??;
        let mut text = String::new();
        // Deltas coalesce into one commit per chunk or flush interval, not one per token.
        let mut pending = String::new();
        let mut flush_at: Option<tokio::time::Instant> = None;
        loop {
            let next = stream.next();
            let event = match flush_at {
                Some(at) => {
                    match self
                        .wait(tokio::time::timeout_at(at, next), deadline, output)
                        .await?
                    {
                        Ok(event) => event,
                        Err(_) => {
                            self.commit_text(std::mem::take(&mut pending), output)
                                .await?;
                            flush_at = None;
                            continue;
                        }
                    }
                }
                None => self.wait(next, deadline, output).await?,
            };
            let event = event.ok_or_else(|| {
                DriverError::Refused("provider stream ended without a complete response".into())
            })??;
            match event {
                StreamEvent::TextDelta(delta) => {
                    if text.len().saturating_add(delta.len()) > MAX_RESPONSE_BYTES {
                        return Err(core::Error::Limit.into());
                    }
                    text.push_str(&delta);
                    pending.push_str(&delta);
                    if pending.len() >= STREAM_CHUNK_BYTES {
                        self.commit_text(std::mem::take(&mut pending), output)
                            .await?;
                        flush_at = None;
                    } else if flush_at.is_none() && !pending.is_empty() {
                        flush_at = Some(tokio::time::Instant::now() + STREAM_FLUSH);
                    }
                }
                StreamEvent::ToolCall(_) => {} // Only the complete committed response can dispatch.
                StreamEvent::Done(turn) => {
                    if !text.is_empty() && turn.text.as_deref().unwrap_or("") != text {
                        return Err(DriverError::Refused(
                            "complete response differs from committed stream".into(),
                        ));
                    }
                    if text.is_empty() {
                        if let Some(full) = &turn.text {
                            if full.len() > MAX_RESPONSE_BYTES {
                                return Err(core::Error::Limit.into());
                            }
                            pending.push_str(full);
                        }
                    }
                    self.commit_text(pending, output).await?;
                    output.assistant_end();
                    return Ok(turn);
                }
            }
        }
    }
    /// Commit streamed text before presenting it, so a reopen can show exactly what was seen.
    async fn commit_text(
        &mut self,
        text: String,
        output: &dyn ReplOutput,
    ) -> Result<(), DriverError> {
        if text.is_empty() {
            return Ok(());
        }
        let parts = text_chunks(&text);
        if let Step::Model { chunks, .. } = &mut self.active_mut().step {
            chunks.extend(parts.iter().map(|part| part.to_string()));
        }
        self.save().await?;
        for part in parts {
            output.assistant_delta(part);
        }
        Ok(())
    }
}

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const STREAM_CHUNK_BYTES: usize = 4096;
const STREAM_FLUSH: Duration = Duration::from_millis(250);

fn text_chunks(mut text: &str) -> Vec<&str> {
    let mut chunks = Vec::new();
    while !text.is_empty() {
        let mut end = text.len().min(STREAM_CHUNK_BYTES);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        let (chunk, rest) = text.split_at(end);
        chunks.push(chunk);
        text = rest;
    }
    chunks
}

fn elapsed_ms(start: std::time::Instant) -> u64 {
    start.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

fn retry_delay(attempt: u32) -> Duration {
    Duration::from_millis(200 * 2u64.pow(attempt.clamp(1, 6) - 1))
}
