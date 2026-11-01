//! Overlapping execution for the never-started leaves of one admitted batch.
//!
//! Consent, authorization, budget reservation and result commits stay serialized in input
//! order; only tool execution overlaps, at most `MAX_BATCH` at once. Delivery to the script
//! remains the ordinary sequential path, which finds these operations already completed.
//!
//! Each kernel leaf owns a persisted executor slot. The parent alone drains and partitions
//! audit. Journal-aware tools and nested scripts remain sequential.
use super::core::composition::MAX_BATCH;
use super::*;
use crate::provider::ToolCall;

impl Driver {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn overlap_batch(
        &mut self,
        registry: &mut ToolRegistry,
        sandbox: &mut Sandbox,
        output: &dyn ReplOutput,
        hooks: Option<&crate::grants::escalate::LoopEscalation>,
        active_policy: &mut Option<crate::grants::ActivePolicy>,
    ) -> Result<(), DriverError> {
        let ready = self.overlap_candidates(registry)?;
        if ready.len() < 2 {
            return Ok(());
        }
        // Serialized consent and authorization. Each authorization is committed before any
        // dispatch, so a crash leaves every admitted leaf under its own recovery policy.
        let mut admitted = Vec::with_capacity(ready.len());
        let mut slots = Vec::with_capacity(ready.len());
        for (id, call) in ready {
            let mut refusal = None;
            if let (Some(h), Some(active)) = (hooks, active_policy.as_mut()) {
                let mut escalation = crate::call::Escalation {
                    config: h,
                    active,
                    lease_turn: self.active().model_calls.saturating_sub(1),
                };
                let future = crate::call::before_call(&mut escalation, &call, sandbox, registry);
                match self.wait(future, self.execution_deadline(), output).await? {
                    crate::call::Before::Refused(reason) => {
                        refusal = Some(ToolResult::refused_by_hook(&reason))
                    }
                    crate::call::Before::Stopped(reason) => {
                        return Err(DriverError::Refused(reason))
                    }
                    crate::call::Before::Run(_) => {}
                }
            }
            let spec = self
                .state
                .committed()
                .operation(id)
                .ok_or(core::Error::NotFound)?
                .spec
                .clone();
            registry.check_durable_compatibility(&spec, &self.compatibility)?;
            let attempt = self.authorize(id).await?;
            let parent = self.cursor_parent();
            presentation::start(
                output,
                self.call_context(&call.id, parent.as_deref()),
                &call,
            );
            if let Some(refusal) = refusal {
                let result =
                    ToolRegistry::prepare_completion(&self.evidence, &attempt, &call, refusal)?;
                self.active_mut().budget.settle(&attempt, None, 0)?;
                self.apply(Event::Completed { attempt, result }).await?;
                continue;
            }
            let slot = sandbox.batch_slot()?;
            if let Some(executor) = executor::Executor::capture(&slot)? {
                self.active_mut().batch_executors.insert(id, executor);
                self.save().await?;
            }
            slots.push(slot);
            admitted.push((attempt, spec.deadline_ms));
        }
        if admitted.is_empty() {
            return Ok(());
        }
        let limit = admitted
            .iter()
            .map(|(_, deadline)| *deadline)
            .min()
            .unwrap_or(0);
        let now = self.time();
        use futures_util::StreamExt;
        let futures = admitted.iter().zip(&slots).map(|((attempt, _), slot)| {
            let started = std::time::Instant::now();
            let future =
                registry.execute_durable(&self.state, attempt, &self.compatibility, now, slot);
            async move { (future.await, elapsed_ms(started)) }
        });
        // Poll every leaf concurrently, but publish completions in input order. A completed
        // prefix is durable even if a later sibling is interrupted.
        let mut futures: futures_util::stream::FuturesOrdered<_> = futures.collect();
        let mut audits: std::collections::BTreeMap<u64, Vec<bee_core::AuditEvent>> =
            Default::default();
        let mut failure = None;
        for (attempt, _) in &admitted {
            let (result, duration_ms) = self
                .wait(futures.next(), limit, output)
                .await?
                .ok_or(core::Error::InvalidSnapshot)?;
            if let Some(executor) = self.active().batch_executors.get(&attempt.operation) {
                if !executor.stop().await.unwrap_or(false) {
                    return Err(DriverError::Unresolved(attempt.operation.0));
                }
            }
            sandbox.settle().await;
            for event in sandbox.drain_audit(None) {
                audits
                    .entry(event.executor_cgroup_id.unwrap_or(0))
                    .or_default()
                    .push(event);
            }
            match result {
                Ok(mut result) => {
                    if let Some(executor) = self.active().batch_executors.get(&attempt.operation) {
                        result
                            .audit
                            .extend(audits.remove(&executor.cgroup_id()).unwrap_or_default());
                    }
                    result.duration_ms = duration_ms;
                    self.active_mut()
                        .budget
                        .settle(attempt, None, duration_ms)?;
                    self.apply(Event::Completed {
                        attempt: attempt.clone(),
                        result,
                    })
                    .await?;
                }
                Err(error) => {
                    failure.get_or_insert(error);
                }
            }
        }
        drop(futures);
        self.reconcile_batch_executors().await?;
        match failure {
            Some(error) => Err(error.into()),
            None => Ok(()),
        }
    }

    fn cursor_parent(&self) -> Option<String> {
        self.active().scripts.last().map(|s| s.parent().to_string())
    }

    /// Never-started leaves from the innermost cursor's current position in a batch.
    fn overlap_candidates(
        &self,
        registry: &ToolRegistry,
    ) -> Result<Vec<(OperationId, ToolCall)>, DriverError> {
        let Some(cursor) = self.active().scripts.last() else {
            return Ok(vec![]);
        };
        let snapshot = self.state.committed();
        let Some(last) = snapshot
            .scripts()
            .get(cursor.id())
            .and_then(|s| s.suspensions.last())
        else {
            return Ok(vec![]);
        };
        let start = cursor.delivered();
        if !last.batch || last.children.len() != cursor.pending.len() {
            return Ok(vec![]);
        }
        let mut ready = Vec::with_capacity(MAX_BATCH);
        for (id, call) in last.children.iter().zip(&cursor.pending).skip(start) {
            if call.name == "codemode" || registry.supports_journal(call) {
                return Ok(vec![]);
            }
            if matches!(
                snapshot.operation(*id).map(|op| &op.phase),
                Some(Phase::Ready)
            ) {
                ready.push((*id, call.clone()));
            }
        }
        assert!(ready.len() <= MAX_BATCH);
        Ok(ready)
    }
}

fn elapsed_ms(start: std::time::Instant) -> u64 {
    start.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}
