use super::*;

impl Driver {
    pub(super) async fn recover_worker(
        &mut self,
        registry: &mut ToolRegistry,
        sandbox: &mut Sandbox,
        output: &dyn ReplOutput,
        hooks: Option<&crate::grants::escalate::LoopEscalation>,
        active_policy: &mut Option<crate::grants::ActivePolicy>,
    ) -> Result<(), DriverError> {
        let Step::Tools {
            operation: Some(id),
            ..
        } = self.active().step
        else {
            return Ok(());
        };
        let Some(operation) = self.state.committed().operation(id).cloned() else {
            // Older checkpoints may have allocated an ID before committing admission.
            return Ok(());
        };
        let attempt = match operation.phase {
            Phase::Recovering { attempt } | Phase::Cancelling { attempt, .. } => attempt,
            _ => return Ok(()),
        };
        if operation.spec.recovery != RecoveryPolicy::Reconcile {
            return Ok(());
        }
        let call: crate::provider::ToolCall =
            serde_json::from_value(operation.spec.input["call"].clone())?;
        if !registry.supports_journal(&call) {
            return Ok(());
        }
        registry.check_durable_compatibility(&operation.spec, &self.compatibility)?;
        let mut journal = self
            .storage
            .worker(attempt.clone(), operation.spec.clone())
            .await?;
        // An intent without its result is not a resumable checkpoint, even if a PID disappeared.
        if journal.record().pending() {
            if let Some(probe) = journal.record().probes.iter().find(|p| p.result.is_none()) {
                output.error(&format!(
                    "probe {} has committed intent but no result; it will not be repeated",
                    probe.key
                ));
            }
            return Ok(());
        }
        let complete = journal.record().completion.is_some();
        let read_only = self.active().cancelling
            || self.time() >= operation.spec.deadline_ms
            || matches!(
                self.state.committed().operation(id).unwrap().phase,
                Phase::Cancelling { .. }
            );
        if read_only || complete {
            journal.read_only();
        } else {
            if let (Some(h), Some(active)) = (hooks, active_policy.as_mut()) {
                let mut escalation = crate::call::Escalation {
                    config: h,
                    active,
                    lease_turn: self.active().model_calls.saturating_sub(1),
                };
                let future = crate::call::before_call(&mut escalation, &call, sandbox, registry);
                if let crate::call::Before::Refused(reason) | crate::call::Before::Stopped(reason) =
                    self.wait(future, operation.spec.deadline_ms, output)
                        .await?
                {
                    return Err(DriverError::Refused(reason));
                }
            }
            let current_executor = executor::Executor::capture(sandbox)?;
            let now_ms = self.time();
            if now_ms >= operation.spec.deadline_ms {
                return Err(DriverError::Expired);
            }
            let activation = self.state.activation().0.to_string();
            if let Step::Tools {
                executor,
                executor_activation,
                ..
            } = &mut self.active_mut().step
            {
                *executor = current_executor;
                *executor_activation = Some(activation);
            }
            self.apply(Event::ResumeReconciliation {
                token: RecoveryToken {
                    activation: self.state.activation(),
                    attempt: attempt.clone(),
                },
                now_ms,
            })
            .await?;
        }
        let future = registry.execute_journaled(&self.state, &self.compatibility, journal, sandbox);
        let result = if read_only || complete {
            future.await?
        } else {
            self.wait(future, operation.spec.deadline_ms, output)
                .await??
        };
        self.active_mut()
            .budget
            .reconcile(&attempt, result.duration_ms)?;
        let now_ms = self.time();
        self.apply(Event::Recovered {
            token: RecoveryToken {
                activation: self.state.activation(),
                attempt,
            },
            outcome: RecoveryOutcome::Found(result),
            now_ms,
        })
        .await?;
        Ok(())
    }
}
