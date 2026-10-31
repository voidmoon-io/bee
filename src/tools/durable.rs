//! Registry/evidence adapter for the durable core. The host still owns serialized event
//! handling, commits, current policy/scopes, and executor cleanup. Call execution once per
//! released Dispatch; never infer quiescence from a missing process or receipt.

use super::{ToolRegistry, ToolResult};
use crate::evidence::{EvidenceStore, Receipt};
use crate::provider::ToolCall;
use crate::session::durable::{
    validate_completion, Attempt, Completion, Entry, Error, Event, OperationSpec, Phase,
    RecoveryToken, State, WorkKind,
};
use crate::Sandbox;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("tool registration, version, schema, or configuration is incompatible")]
    Incompatible,
    #[error("durable evidence is not configured for this session")]
    EvidenceUnavailable,
    #[error("operation deadline expired before execution")]
    Expired,
    #[error("receipt does not match the committed call and result")]
    InvalidReceipt,
    #[error(transparent)]
    Core(#[from] Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    call: ToolCall,
    schema: Value,
    /// Host-derived identity for effective configuration, tool profiles, and execution posture.
    /// This is compatibility data, never restored authority or model-selected configuration.
    compatibility: String,
}

impl ToolRegistry {
    #[cfg(feature = "durable-sessions")]
    pub(crate) fn supports_journal(&self, call: &ToolCall) -> bool {
        self.tools
            .get(call.name.as_str())
            .is_some_and(|tool| tool.supports_journal())
    }
    #[cfg(feature = "durable-sessions")]
    pub(crate) fn execute_journaled<'a>(
        &'a self,
        state: &State,
        compatibility: &str,
        mut journal: crate::session::driver::journal::Journal,
        sandbox: &'a mut Sandbox,
    ) -> impl std::future::Future<Output = Result<Completion, crate::session::driver::DriverError>> + 'a
    {
        let prepared = (|| -> Result<_, crate::session::driver::DriverError> {
            state.check_active()?;
            let record = journal.record();
            let operation = state
                .committed()
                .operation(record.attempt.operation)
                .ok_or(Error::NotFound)?;
            if !matches!(&operation.phase, Phase::Running { attempt } | Phase::Recovering { attempt } | Phase::Cancelling { attempt, .. } if attempt == &record.attempt)
            {
                return Err(Error::Stale.into());
            }
            self.check_durable_compatibility(&operation.spec, compatibility)?;
            let input: Input = serde_json::from_value(operation.spec.input.clone())?;
            if !self.supports_journal(&input.call)
                || operation.spec.recovery != crate::session::durable::RecoveryPolicy::Reconcile
            {
                return Err(AdapterError::Incompatible.into());
            }
            let evidence = self.durable_evidence(&record.attempt)?.clone();
            Ok((input.call, evidence))
        })();
        async move {
            let (call, evidence) = prepared?;
            if let Some(result) = &journal.record().completion {
                self.validate_durable_result(
                    &evidence,
                    &journal.record().spec,
                    &journal.record().attempt,
                    result,
                )?;
                return Ok(result.clone());
            }
            sandbox
                .check_cleanup()
                .map_err(crate::session::driver::DriverError::Refused)?;
            let observed = self
                .tools
                .get(call.name.as_str())
                .ok_or(AdapterError::Incompatible)?
                .call_journaled(call.arguments.clone(), sandbox, &mut journal)
                .await?;
            let mut result =
                Self::prepare_completion(&evidence, &journal.record().attempt, &call, observed)?;
            for probe in &journal.record().probes {
                let recorded = probe.result.as_ref().ok_or(Error::InvalidPhase)?;
                result.duration_ms = result.duration_ms.saturating_add(recorded.duration_ms);
                result.audit.extend(recorded.audit.clone());
            }
            sandbox.settle().await;
            let mut audit = sandbox.drain_audit(None);
            sandbox.retain_audit(&mut audit);
            result.audit.extend(audit);
            validate_completion(&result)?;
            journal.finish(result.clone()).await?;
            Ok(result)
        }
    }
    /// Construct admission from trusted registration, ignoring recovery claims in model arguments.
    /// The host must derive compatibility from current configuration again on every activation.
    pub fn durable_spec(
        &self,
        call: &ToolCall,
        compatibility: &str,
        deadline_ms: u64,
    ) -> Result<OperationSpec, AdapterError> {
        let tool = self.tools.get(call.name.as_str());
        if compatibility.is_empty() || compatibility.len() > 256 {
            return Err(AdapterError::Incompatible);
        }
        let contract = tool
            .map(|tool| tool.durable_contract())
            .unwrap_or(super::ToolContract {
                version: 1,
                recovery: crate::session::durable::RecoveryPolicy::NeverReplay,
            });
        let spec = OperationSpec {
            kind: WorkKind::Tool,
            name: call.name.clone(),
            version: contract.version,
            input: serde_json::to_value(Input {
                call: call.clone(),
                schema: tool
                    .map(|tool| serde_json::to_value(tool.schema()))
                    .transpose()?
                    .unwrap_or(Value::Null),
                compatibility: compatibility.into(),
            })?,
            recovery: contract.recovery,
            deadline_ms,
        };
        // Use the core's input limits before the host attempts admission.
        crate::session::durable::validate_spec(&spec)?;
        Ok(spec)
    }

    pub fn check_durable_compatibility(
        &self,
        spec: &OperationSpec,
        compatibility: &str,
    ) -> Result<(), AdapterError> {
        let input: Input = serde_json::from_value(spec.input.clone())?;
        if self.durable_spec(&input.call, compatibility, spec.deadline_ms)? != *spec {
            return Err(AdapterError::Incompatible);
        }
        Ok(())
    }

    /// Execute only after intent commit and fresh host authorization, using the current sandbox.
    /// Returns unpublished receipt bytes for Event::Completed. Any error after execution leaves
    /// an ambiguous attempt; it is not permission to retry an effect.
    pub fn execute_durable<'a>(
        &'a self,
        state: &State,
        attempt: &Attempt,
        compatibility: &str,
        now_ms: u64,
        sandbox: &'a Sandbox,
    ) -> impl std::future::Future<Output = Result<Completion, AdapterError>> + 'a {
        let prepared = (|| {
            state.check_active()?;
            let operation = state
                .committed()
                .operation(attempt.operation)
                .ok_or(Error::NotFound)?;
            if !matches!(&operation.phase, Phase::Running { attempt: running } if running == attempt)
            {
                return Err(Error::Stale.into());
            }
            self.check_durable_compatibility(&operation.spec, compatibility)?;
            if now_ms >= operation.spec.deadline_ms {
                return Err(AdapterError::Expired);
            }
            let evidence = self.durable_evidence(attempt)?.clone();
            let input: Input = serde_json::from_value(operation.spec.input.clone())?;
            Ok::<_, AdapterError>((evidence, input.call, attempt.clone()))
        })();
        async move {
            let (evidence, call, attempt) = prepared?;
            let observed = self.execute_unrecorded(&call, sandbox).await;
            Self::prepare_completion(&evidence, &attempt, &call, observed)
        }
    }

    pub(crate) fn prepare_completion(
        evidence: &EvidenceStore,
        attempt: &Attempt,
        call: &ToolCall,
        observed: ToolResult,
    ) -> Result<Completion, AdapterError> {
        let receipt = evidence.prepare(
            attempt,
            call,
            &observed,
            time::OffsetDateTime::now_utc().to_string(),
        )?;
        let result = Completion {
            duration_ms: 0,
            audit: vec![],
            output: serde_json::to_value(observed.with_receipt(receipt.id.clone()))?,
            receipt: Some(receipt),
        };
        validate_completion(&result)?;
        Ok(result)
    }

    /// Blocking publication of the committed result only. Feed the returned event into the core
    /// and commit its candidate before delivering. Failure leaves Publishing intact for retry.
    pub fn publish_durable(
        &self,
        state: &State,
        token: &RecoveryToken,
    ) -> Result<Event, AdapterError> {
        state.check_active()?;
        state.check_token(token)?;
        let operation = state
            .committed()
            .operation(token.attempt.operation)
            .ok_or(Error::NotFound)?;
        let Phase::Publishing { attempt, result } = &operation.phase else {
            return Err(Error::InvalidPhase.into());
        };
        if attempt != &token.attempt {
            return Err(Error::Stale.into());
        }
        let evidence = self.durable_evidence(attempt)?;
        self.validate_durable_result(evidence, &operation.spec, attempt, result)?;
        let receipt = result
            .receipt
            .as_ref()
            .ok_or(AdapterError::InvalidReceipt)?;
        evidence.publish(receipt, attempt)?;
        evidence.validate_published(receipt, attempt)?;
        Ok(Event::Published {
            token: token.clone(),
            receipt_id: receipt.id.clone(),
        })
    }

    /// Blocking read/validation on every delivery, including replay after an acknowledged
    /// publication. Missing or corrupt evidence blocks delivery; this never reruns a tool.
    pub fn deliver_durable(
        &self,
        state: &State,
        entry: &Entry,
    ) -> Result<ToolResult, AdapterError> {
        state.check_active()?;
        if !state.committed().entries().contains(entry) {
            return Err(Error::Stale.into());
        }
        let operation = state
            .committed()
            .operation(entry.attempt.operation)
            .ok_or(Error::NotFound)?;
        let evidence = self.durable_evidence(&entry.attempt)?;
        let receipt = entry
            .result
            .receipt
            .as_ref()
            .ok_or(AdapterError::InvalidReceipt)?;
        self.validate_durable_result(evidence, &operation.spec, &entry.attempt, &entry.result)?;
        evidence.validate_published(receipt, &entry.attempt)?;
        Ok(serde_json::from_value(entry.result.output.clone())?)
    }

    fn durable_evidence(&self, attempt: &Attempt) -> Result<&EvidenceStore, AdapterError> {
        self.deps
            .evidence
            .as_ref()
            .filter(|store| store.session_id() == attempt.session.0)
            .ok_or(AdapterError::EvidenceUnavailable)
    }

    fn validate_durable_result(
        &self,
        evidence: &EvidenceStore,
        spec: &OperationSpec,
        attempt: &Attempt,
        result: &Completion,
    ) -> Result<(), AdapterError> {
        let publication = result
            .receipt
            .as_ref()
            .ok_or(AdapterError::InvalidReceipt)?;
        let receipt: Receipt = evidence.validate_prepared(publication, attempt)?;
        let input: Input = serde_json::from_value(spec.input.clone())?;
        if spec.kind != WorkKind::Tool
            || spec.name != input.call.name
            || receipt.call_id != input.call.id
            || receipt.tool != input.call.name
            || receipt.arguments != input.call.arguments
            || serde_json::to_value(receipt.result.with_receipt(publication.id.clone()))?
                != result.output
        {
            return Err(AdapterError::InvalidReceipt);
        }
        Ok(())
    }
}
