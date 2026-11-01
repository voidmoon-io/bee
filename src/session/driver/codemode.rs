//! The driver owns admission and effects; Python only proposes calls. A batch is admitted
//! atomically and resumes with ordered results. A nested script runs as its parent's child.
use super::core::composition::{
    ScriptEvent, ScriptParent, ScriptPhase, ScriptResume, ScriptSpec, MAX_DEPTH,
};
use super::*;
use crate::provider::{ToolCall, ToolSchema};
use crate::python::{Request, Response, RUNTIME_ID};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// Only qualified, registered tools enter the guest catalog. Session-terminal and
// UI tools require lifecycle behavior that a script result cannot represent.
const ALLOWED: &[&str] = &[
    "read_file",
    "list_directory",
    "search",
    "write_file",
    "bash",
    "ast_grep",
    "cvss",
    "git_log",
    "record_finding",
    "list_findings",
    "receipt_get",
    "source_pin",
    "source_read",
    "hunt_checkpoint",
    "hunt_resume",
    "repro_run",
    "scan",
];
const MAX_RUNS: u32 = 64;
const MAX_CALLS: u32 = 32;

fn catalog(registry: &ToolRegistry) -> Vec<ToolSchema> {
    registry
        .schemas()
        .into_iter()
        .filter(|s| ALLOWED.contains(&s.name.as_str()))
        .collect()
}

#[cfg(test)]
mod catalog_tests {
    use super::*;

    #[test]
    fn exposes_only_registered_supported_tools() {
        let registry = crate::tools::registry_for(
            &["bash".into(), "read_file".into(), "give_up".into()],
            None,
        );
        let mut names: Vec<_> = catalog(&registry).into_iter().map(|s| s.name).collect();
        names.sort();
        assert_eq!(names, ["bash", "read_file"]);
        assert!(registry.contains("give_up"));
    }
}

pub(super) fn schemas(registry: &ToolRegistry) -> Vec<ToolSchema> {
    let mut schemas = registry.schemas();
    schemas.retain(|s| s.name != "codemode");
    schemas.push(ToolSchema {
        name: "codemode".into(),
        description: format!("Run bounded Python (Monty subset). call_tool(name, arguments) returns a tool result dict; the final expression is the result. call_tools([{{'name': ..., 'arguments': {{...}}}}, ...]) admits one to four calls together and returns their results in input order. call_tool('codemode', {{'source': ..., 'inputs': {{...}}}}) runs a nested script, at most four script levels. No imports of external packages, host I/O, time, randomness or async. Print output is discarded. Each outer call, nested script and inner attempt charges the tool budget. All levels share at most 32 inner calls and 64 interpreter invocations including recovery. Available tools: {}", serde_json::to_string(&catalog(registry)).expect("tool schemas serialize")),
        parameters: json!({"type":"object","properties":{"source":{"type":"string","maxLength":32768},"inputs":{"type":"object"}},"required":["source"],"additionalProperties":false}),
    });
    schemas
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Cursor {
    root: OperationId,
    id: String,
    pub(super) outer: ToolCall,
    spec: ScriptSpec,
    runs: u32,
    /// Interpreter invocations charged by completed nested scripts.
    descendant_runs: u32,
    worker_time_charge_ms: u64,
    worker_audit: Vec<bee_core::AuditEvent>,
    /// Calls bound to the latest suspension, in admission order.
    pub(super) pending: Vec<ToolCall>,
    delivered: usize,
}

enum Advance {
    Leaf(ToolCall),
    Done,
    Again,
}

impl Cursor {
    pub(super) fn id(&self) -> &str {
        &self.id
    }
    pub(super) fn delivered(&self) -> usize {
        self.delivered
    }
    pub(super) fn current(&self) -> Option<&ToolCall> {
        self.pending.get(self.delivered)
    }
    fn current_child(&self, snapshot: &Snapshot) -> Option<OperationId> {
        self.current()?;
        snapshot
            .scripts()
            .get(&self.id)?
            .suspensions
            .last()?
            .children
            .get(self.delivered)
            .copied()
    }
    /// Undelivered leaf calls whose operations were attempted.
    pub(super) fn attempted(&self, snapshot: &Snapshot) -> Vec<ToolCall> {
        let Some(last) = snapshot
            .scripts()
            .get(&self.id)
            .and_then(|s| s.suspensions.last())
        else {
            return vec![];
        };
        last.children
            .iter()
            .zip(&self.pending)
            .skip(self.delivered)
            .filter(|(id, call)| {
                call.name != "codemode"
                    && snapshot.operation(**id).is_some_and(|op| op.attempts > 0)
            })
            .map(|(_, call)| call.clone())
            .collect()
    }
    pub(super) fn child_delivered(&mut self) {
        self.delivered += 1;
    }
    pub(super) fn worker_audit(&self) -> &[bee_core::AuditEvent] {
        &self.worker_audit
    }
    pub(super) fn parent(&self) -> &str {
        &self.outer.id
    }
    fn total_runs(&self) -> u32 {
        self.runs.saturating_add(self.descendant_runs)
    }

    /// Validates the persisted root-to-innermost stack against committed composition state.
    pub(super) fn validate_stack(
        stack: &[Cursor],
        active: &Active,
        snapshot: &Snapshot,
        next: u64,
    ) -> Result<(), DriverError> {
        let invalid = || DriverError::Core(core::Error::InvalidSnapshot);
        if stack.is_empty() {
            return Ok(());
        }
        if stack.len() > MAX_DEPTH || stack.iter().map(Cursor::total_runs).sum::<u32>() > MAX_RUNS {
            return Err(invalid());
        }
        let Step::Tools {
            model_operation,
            next: call_index,
            operation,
            ..
        } = active.step
        else {
            return Err(invalid());
        };
        for (depth, cursor) in stack.iter().enumerate() {
            let root = snapshot.operation(cursor.root).ok_or_else(invalid)?;
            let script = snapshot.scripts().get(&cursor.id).ok_or_else(invalid)?;
            if cursor.root.0 >= next
                || cursor.id != format!("code-{}", cursor.root.0)
                || root.spec.name != "codemode"
                || cursor.outer.name != "codemode"
                || root.spec.input["call"] != serde_json::to_value(&cursor.outer)?
                || cursor.spec != script.spec
                || cursor.spec.deadline_ms > active.deadline_ms
                || cursor.delivered > cursor.pending.len()
            {
                return Err(invalid());
            }
            if !cursor.pending.is_empty() {
                let last = script.suspensions.last().ok_or_else(invalid)?;
                if last.children.len() != cursor.pending.len() {
                    return Err(invalid());
                }
                for (call, child) in cursor.pending.iter().zip(&last.children) {
                    if snapshot.operation(*child).ok_or_else(invalid)?.spec.input["call"]
                        != serde_json::to_value(call)?
                    {
                        return Err(invalid());
                    }
                }
            }
            match depth.checked_sub(1).map(|i| &stack[i]) {
                None => {
                    let Some(Operation {
                        phase: Phase::Completed { result, .. },
                        ..
                    }) = snapshot.operation(model_operation)
                    else {
                        return Err(invalid());
                    };
                    let turn: Turn = serde_json::from_value(result.output.clone())?;
                    if script.parent.is_some()
                        || turn
                            .tool_calls
                            .get(call_index)
                            .map(serde_json::to_value)
                            .transpose()?
                            != Some(serde_json::to_value(&cursor.outer)?)
                    {
                        return Err(invalid());
                    }
                }
                Some(owner) => {
                    let expected = ScriptParent {
                        script: owner.id.clone(),
                        child: cursor.root,
                    };
                    if script.parent.as_ref() != Some(&expected)
                        || owner.current_child(snapshot) != Some(cursor.root)
                        || owner.current().map(serde_json::to_value).transpose()?
                            != Some(serde_json::to_value(&cursor.outer)?)
                    {
                        return Err(invalid());
                    }
                }
            }
        }
        if let Some(innermost) = stack.last() {
            match innermost.current_child(snapshot) {
                Some(child) if operation.is_some_and(|id| id != child) => return Err(invalid()),
                None if operation.is_some_and(|id| id != stack[0].root) => return Err(invalid()),
                _ => {}
            }
        }
        Ok(())
    }
}

impl Driver {
    fn cursor(&self) -> &Cursor {
        self.active().scripts.last().expect("active script")
    }
    fn cursor_mut(&mut self) -> &mut Cursor {
        self.active_mut().scripts.last_mut().expect("active script")
    }

    pub(super) fn execution_deadline(&self) -> u64 {
        self.active()
            .scripts
            .last()
            .map_or(self.active().deadline_ms, |s| {
                s.spec.deadline_ms.min(self.active().deadline_ms)
            })
    }

    fn script_compatibility(&self, registry: &ToolRegistry) -> Result<String, DriverError> {
        let contracts = catalog(registry)
            .into_iter()
            .map(|schema| {
                registry.durable_spec(
                    &ToolCall {
                        id: "catalog".into(),
                        name: schema.name,
                        arguments: json!({}),
                    },
                    &self.compatibility,
                    1,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        fingerprint(&(RUNTIME_ID, contracts))
    }

    async fn script_event(&mut self, event: ScriptEvent) -> Result<(), DriverError> {
        let now_ms = self.time();
        if !matches!(event, ScriptEvent::Stop { .. })
            && self
                .active()
                .scripts
                .last()
                .is_some_and(|c| now_ms >= c.spec.deadline_ms)
        {
            return Err(DriverError::Expired);
        }
        self.apply(Event::Script {
            activation: self.state.activation(),
            now_ms,
            event,
        })
        .await?;
        Ok(())
    }
    fn script_step(&mut self, operation_id: Option<OperationId>) {
        if let Step::Tools {
            operation,
            executor,
            executor_activation,
            ..
        } = &mut self.active_mut().step
        {
            *operation = operation_id;
            *executor = None;
            *executor_activation = None;
        }
    }

    /// Push a cursor and commit its script. The root operation must already be admitted.
    async fn script_open(
        &mut self,
        root: OperationId,
        outer: ToolCall,
        parent: Option<ScriptParent>,
        compatibility: &str,
    ) -> Result<(), DriverError> {
        let deadline_ms = self
            .state
            .committed()
            .operation(root)
            .ok_or(core::Error::NotFound)?
            .spec
            .deadline_ms;
        let spec = ScriptSpec {
            source_input_sha256: fingerprint(&outer.arguments)?,
            runtime: RUNTIME_ID.into(),
            compatibility: compatibility.into(),
            deadline_ms,
            max_calls: MAX_CALLS,
        };
        let id = format!("code-{}", root.0);
        self.active_mut().scripts.push(Cursor {
            root,
            id: id.clone(),
            outer,
            spec: spec.clone(),
            runs: 0,
            descendant_runs: 0,
            worker_time_charge_ms: 0,
            worker_audit: vec![],
            pending: vec![],
            delivered: 0,
        });
        if let Err(error) = self
            .script_event(ScriptEvent::Start { id, spec, parent })
            .await
        {
            if matches!(error, DriverError::Expired) {
                // Start was never proposed; only the admitted operation exists.
                self.active_mut().scripts.pop();
            }
            return Err(error);
        }
        Ok(())
    }

    /// None means the outer result was committed and delivered. Some is an ordinary leaf call.
    pub(super) async fn script_next(
        &mut self,
        outer: ToolCall,
        registry: &ToolRegistry,
        sandbox: &mut Sandbox,
        output: &dyn ReplOutput,
    ) -> Result<Option<ToolCall>, DriverError> {
        let compatibility = self.script_compatibility(registry)?;
        if self.active().scripts.is_empty() {
            let deadline = self
                .time()
                .saturating_add(self.active().limits.tool_timeout_ms)
                .min(self.active().deadline_ms);
            let mut op = registry.durable_spec(&outer, &self.compatibility, deadline)?;
            op.recovery = RecoveryPolicy::Reconcile;
            let root = self.operation(op, false, sandbox).await?;
            self.script_open(root, outer, None, &compatibility).await?;
        }
        loop {
            match self
                .script_advance(&compatibility, registry, sandbox, output)
                .await?
            {
                Advance::Leaf(call) => return Ok(Some(call)),
                Advance::Done => return Ok(None),
                Advance::Again => {}
            }
        }
    }

    fn parent_call(&self) -> Option<String> {
        let scripts = &self.active().scripts;
        scripts
            .len()
            .checked_sub(2)
            .map(|i| scripts[i].outer.id.clone())
    }

    async fn script_advance(
        &mut self,
        compatibility: &str,
        registry: &ToolRegistry,
        sandbox: &mut Sandbox,
        output: &dyn ReplOutput,
    ) -> Result<Advance, DriverError> {
        let cursor = self.cursor().clone();
        if cursor.spec.runtime != RUNTIME_ID
            || cursor.spec.compatibility != compatibility
            || cursor.spec.source_input_sha256 != fingerprint(&cursor.outer.arguments)?
        {
            return Err(DriverError::Incompatible);
        }
        let parent_call = self.parent_call();
        if matches!(
            self.state
                .committed()
                .operation(cursor.root)
                .ok_or(core::Error::NotFound)?
                .phase,
            Phase::Ready
        ) {
            self.authorize(cursor.root).await?;
            presentation::start(
                output,
                self.call_context(&cursor.outer.id, parent_call.as_deref()),
                &cursor.outer,
            );
        }
        if let Some(call) = cursor.current().cloned() {
            let child = cursor
                .current_child(self.state.committed())
                .ok_or(core::Error::InvalidSnapshot)?;
            if call.name == "codemode" {
                let parent = ScriptParent {
                    script: cursor.id.clone(),
                    child,
                };
                self.script_step(None);
                self.script_open(child, call, Some(parent), compatibility)
                    .await?;
                return Ok(Advance::Again);
            }
            if self.active().step.operation() != Some(child) {
                self.script_step(Some(child));
                if let Step::Tools { executor, .. } = &mut self.active_mut().step {
                    *executor = executor::Executor::capture(sandbox)?;
                }
                self.save().await?;
            }
            return Ok(Advance::Leaf(call));
        }
        // This persisted cursor no longer points at an inner executor after its results were recorded.
        self.script_step(None);
        let now = self.time();
        let request = match self
            .state
            .committed()
            .resume_script(&cursor.id, &cursor.spec, now)?
        {
            ScriptResume::Completed(value) => {
                let result = serde_json::from_value(value.clone())?;
                return self.script_deliver(result, output).await;
            }
            ScriptResume::Start => {
                let args = &cursor.outer.arguments;
                let source = args.get("source").and_then(|v| v.as_str());
                let inputs = args.get("inputs").cloned().unwrap_or(json!({}));
                if source.is_none_or(|s| s.len() > 32 * 1024)
                    || !inputs.is_object()
                    || serde_json::to_vec(&inputs)?.len() > 8 * 1024
                {
                    return self.script_finish(ToolResult::error("codemode requires source (at most 32 KiB) and object inputs (at most 8 KiB)"), output).await;
                }
                Request::Start {
                    source: source.unwrap().into(),
                    inputs,
                    visual: false,
                }
            }
            ScriptResume::Continue {
                checkpoint,
                children,
                batch,
            } => {
                let reference = checkpoint.clone();
                let mut results = Vec::with_capacity(children.len());
                for (child, completion) in children {
                    let op = self
                        .state
                        .committed()
                        .operation(child)
                        .ok_or(core::Error::InvalidSnapshot)?;
                    // A nested script result is driver-produced data without a receipt.
                    let result: ToolResult = if op.spec.name == "codemode" {
                        serde_json::from_value(completion.output.clone())?
                    } else {
                        let entry = self
                            .state
                            .committed()
                            .entries()
                            .iter()
                            .find(|entry| entry.attempt.operation == child)
                            .ok_or(core::Error::InvalidSnapshot)?;
                        registry.deliver_durable(&self.state, entry)?
                    };
                    results.push(serde_json::to_value(result)?);
                }
                let result = if batch {
                    Value::Array(results)
                } else {
                    results.pop().ok_or(core::Error::InvalidSnapshot)?
                };
                let snapshot = self.storage.load_checkpoint(reference).await?;
                Request::Resume { snapshot, result }
            }
            ScriptResume::Waiting(id) | ScriptResume::Unresolved { child: id, .. } => {
                return Err(DriverError::Unresolved(id.0))
            }
            ScriptResume::Stopped(StopReason::Deadline) => return Err(DriverError::Expired),
            ScriptResume::Stopped(_) => return Err(DriverError::Cancelled),
        };
        if now >= cursor.spec.deadline_ms {
            return Err(DriverError::Expired);
        }
        let runs: u32 = self.active().scripts.iter().map(Cursor::total_runs).sum();
        if runs >= MAX_RUNS {
            return self
                .script_finish(
                    ToolResult::error("codemode interpreter invocation budget exhausted"),
                    output,
                )
                .await;
        }
        // Charge before spawning: a crash/lost reply cannot refund interpreter work.
        let script = self.cursor_mut();
        script.runs += 1;
        script.worker_time_charge_ms = script
            .worker_time_charge_ms
            .checked_add(4_000)
            .ok_or(core::Error::Limit)?;
        self.save().await?;
        let started = std::time::Instant::now();
        let response = self
            .wait(
                crate::python::execute(request, sandbox),
                cursor.spec.deadline_ms,
                output,
            )
            .await;
        sandbox.settle().await;
        let mut audit = sandbox.drain_audit(None);
        sandbox.retain_audit(&mut audit);
        self.cursor_mut().worker_audit.extend(audit);
        let response = response?;
        let script = self.cursor_mut();
        script.worker_time_charge_ms = script
            .worker_time_charge_ms
            .saturating_sub(4_000)
            .saturating_add(started.elapsed().as_millis().try_into().unwrap_or(u64::MAX));
        match response {
            Ok(Response::Call {
                name,
                arguments,
                snapshot,
            }) => {
                self.script_admit(vec![(name, arguments)], false, snapshot, registry, output)
                    .await
            }
            Ok(Response::Batch { calls, snapshot }) => {
                let calls = calls.into_iter().map(|c| (c.name, c.arguments)).collect();
                self.script_admit(calls, true, snapshot, registry, output)
                    .await
            }
            Ok(Response::Complete { value }) => {
                // The result is data, never an envelope that can forge a receipt or terminal signal.
                let result = ToolResult::ok(serde_json::to_string(
                    &json!({"status":"completed", "value":value}),
                )?);
                self.script_finish(result, output).await
            }
            Ok(Response::Error { message }) | Err(message) => {
                self.script_finish(ToolResult::error(format!("codemode: {message}")), output)
                    .await
            }
        }
    }

    /// Commit the checkpoint and every child admission together before any dispatch.
    async fn script_admit(
        &mut self,
        proposed: Vec<(String, Value)>,
        batch: bool,
        snapshot: Vec<u8>,
        registry: &ToolRegistry,
        output: &dyn ReplOutput,
    ) -> Result<Advance, DriverError> {
        let cursor = self.cursor().clone();
        let committed = self.state.committed();
        let script = &committed.scripts()[&cursor.id];
        let generation = script.suspensions.len() as u32;
        let local = script.calls();
        let total = committed.tree_calls(&cursor.id)?;
        let nestable = self.active().scripts.len() < MAX_DEPTH;
        if total + proposed.len() > cursor.spec.max_calls as usize
            || proposed.iter().any(|(name, _)| {
                // codemode is driver-owned rather than a registered tool.
                !(name == "codemode" && nestable
                    || ALLOWED.contains(&name.as_str()) && registry.contains(name))
            })
        {
            return self
                .script_finish(
                    ToolResult::error(
                        "codemode requested an unavailable tool or exceeded its call or nesting limit",
                    ),
                    output,
                )
                .await;
        }
        let mut calls = Vec::with_capacity(proposed.len());
        let mut children = Vec::with_capacity(proposed.len());
        for (index, (name, arguments)) in proposed.into_iter().enumerate() {
            let call = ToolCall {
                id: format!("{}/{}", cursor.outer.id, local + index + 1),
                name,
                arguments,
            };
            let mut spec =
                registry.durable_spec(&call, &self.compatibility, cursor.spec.deadline_ms)?;
            if call.name == "codemode" {
                // The nested owner reconciles its own pure worker like the root does.
                spec.recovery = RecoveryPolicy::Reconcile;
            }
            let child = OperationId(self.journal().next_operation);
            self.journal_mut().next_operation = child.0.checked_add(1).ok_or(core::Error::Limit)?;
            children.push((child, spec));
            calls.push(call);
        }
        let reference = self
            .storage
            .put_checkpoint(self.state.activation(), snapshot)
            .await?;
        self.script_step(None);
        let script = self.cursor_mut();
        script.pending = calls;
        script.delivered = 0;
        self.script_event(ScriptEvent::Suspend {
            id: cursor.id,
            generation,
            checkpoint: reference,
            children,
            batch,
        })
        .await?;
        Ok(Advance::Again)
    }

    async fn script_finish(
        &mut self,
        result: ToolResult,
        output: &dyn ReplOutput,
    ) -> Result<Advance, DriverError> {
        let cursor = self.cursor();
        let mut result = result;
        let mut body = if result.is_error {
            json!({"status":"error", "error": result.content})
        } else {
            serde_json::from_str(&result.content)?
        };
        body["worker_invocations"] = json!(cursor.total_runs());
        body["worker_time_charge_ms"] = json!(cursor.worker_time_charge_ms);
        result.content = serde_json::to_string(&body)?;
        if serde_json::to_vec(&result)?.len() > core::MAX_PAYLOAD_BYTES {
            result = ToolResult::error(serde_json::to_string(
                &json!({"status":"error","error":"codemode result exceeds 64 KiB durable payload limit", "worker_invocations": cursor.total_runs(), "worker_time_charge_ms":cursor.worker_time_charge_ms}),
            )?);
        }
        let id = cursor.id.clone();
        let generation = self.state.committed().scripts()[&id].suspensions.len() as u32;
        self.script_event(ScriptEvent::Finish {
            id,
            generation,
            output: serde_json::to_value(&result)?,
        })
        .await?;
        self.script_deliver(result, output).await
    }

    /// Complete the innermost script's operation. The root result enters the conversation;
    /// a nested result only advances its parent.
    async fn script_deliver(
        &mut self,
        result: ToolResult,
        output: &dyn ReplOutput,
    ) -> Result<Advance, DriverError> {
        let cursor = self.cursor().clone();
        let parent_call = self.parent_call();
        let phase = self
            .state
            .committed()
            .operation(cursor.root)
            .ok_or(core::Error::NotFound)?
            .phase
            .clone();
        let completion = Completion {
            output: serde_json::to_value(&result)?,
            duration_ms: cursor.worker_time_charge_ms,
            audit: cursor.worker_audit.clone(),
            receipt: None,
        };
        match phase {
            Phase::Running { attempt } => {
                self.active_mut()
                    .budget
                    .settle(&attempt, None, cursor.worker_time_charge_ms)?;
                self.apply(Event::Completed {
                    attempt,
                    result: completion,
                })
                .await?;
            }
            Phase::Recovering { attempt } => {
                self.active_mut()
                    .budget
                    .reconcile(&attempt, cursor.worker_time_charge_ms)?;
                let now_ms = self.time();
                self.apply(Event::Recovered {
                    token: RecoveryToken {
                        activation: self.state.activation(),
                        attempt,
                    },
                    outcome: RecoveryOutcome::Found(completion),
                    now_ms,
                })
                .await?;
            }
            Phase::Completed { .. } => {}
            _ => return Err(DriverError::Unresolved(cursor.root.0)),
        }
        if parent_call.is_none() {
            self.journal_mut().conversation.push(Message::ToolResult {
                provenance: result.provenance.clone(),
                call_id: cursor.outer.id.clone(),
                name: "codemode".into(),
                content: result.content.clone(),
                is_error: result.is_error,
            });
        }
        let turn = self
            .active_mut()
            .turns
            .last_mut()
            .ok_or(core::Error::InvalidSnapshot)?;
        turn.calls.push(recorded(
            parent_call.clone(),
            cursor.outer.clone(),
            result.clone(),
            cursor.worker_audit.clone(),
        ));
        turn.duration_ms = turn
            .duration_ms
            .saturating_add(cursor.worker_time_charge_ms);
        self.active_mut().scripts.pop();
        self.script_step(None);
        let advance = if let Some(owner) = self.active_mut().scripts.last_mut() {
            owner.descendant_runs = owner.descendant_runs.saturating_add(cursor.total_runs());
            owner.child_delivered();
            Advance::Again
        } else {
            if let Step::Tools { next, .. } = &mut self.active_mut().step {
                *next += 1;
            }
            Advance::Done
        };
        self.save().await?;
        if matches!(advance, Advance::Done) {
            // Delivered: nothing reads the tree again. A crash before this commit leaves it for
            // pruning, which drops finished scripts together with their operations.
            self.script_event(ScriptEvent::Forget {
                id: cursor.id.clone(),
            })
            .await?;
        }
        presentation::grouped(
            output,
            self.call_context(&cursor.outer.id, parent_call.as_deref()),
            &cursor.outer,
            &result,
            &cursor.worker_audit,
        );
        Ok(advance)
    }

    pub(super) async fn cancel_script(&mut self) -> Result<(), DriverError> {
        let stack = self.active().scripts.clone();
        let Some(root) = stack.first() else {
            return Ok(());
        };
        // Stopping the root stops every active descendant and admitted child in one commit.
        if self.state.committed().scripts()[&root.id].phase == ScriptPhase::Active {
            self.script_event(ScriptEvent::Stop {
                id: root.id.clone(),
            })
            .await?;
        }
        // A stop the deadline forced is recorded as one, not as an operator cancel.
        let event = if self.active().timed_out {
            Event::Expire { id: root.root }
        } else {
            Event::Cancel { id: root.root }
        };
        self.apply(event).await?;
        // The pure workers have no effect channel: only admitted leaves can dispatch.
        for cursor in stack.iter().rev() {
            if let Phase::Cancelling { attempt, .. } = &self
                .state
                .committed()
                .operation(cursor.root)
                .ok_or(core::Error::NotFound)?
                .phase
            {
                let token = RecoveryToken {
                    activation: self.state.activation(),
                    attempt: attempt.clone(),
                };
                self.apply(Event::Cleaned { token }).await?;
            }
        }
        Ok(())
    }

    /// Report the innermost leaf and every unfinished script level as unresolved.
    pub(super) fn report_unresolved_scripts(&self, error: &DriverError, output: &dyn ReplOutput) {
        let Some(scripts) = self
            .journal
            .as_ref()
            .and_then(|j| j.active.as_ref())
            .map(|a| &a.scripts)
        else {
            return;
        };
        let emit = |call: &ToolCall, parent: Option<&str>| {
            output.tool_event(&crate::repl::presentation::CallEvent {
                context: self.call_context(&call.id, parent),
                call: call.clone(),
                outcome: crate::repl::presentation::CallOutcome::Unresolved {
                    detail: error.to_string(),
                },
            });
        };
        if let Some(cursor) = scripts.last() {
            if let Some(child) = cursor.current().filter(|c| c.name != "codemode") {
                emit(child, Some(&cursor.outer.id));
            }
        }
        for (index, cursor) in scripts.iter().enumerate().rev() {
            let parent = index.checked_sub(1).map(|i| scripts[i].outer.id.as_str());
            emit(&cursor.outer, parent);
        }
    }

    /// On a stopped submission: every attempted, undelivered leaf (overlapped siblings
    /// included) and every unfinished nested script is recorded under its parent.
    pub(super) fn record_stopped_scripts(&mut self) -> Result<(), DriverError> {
        let scripts = self.active().scripts.clone();
        let mut records = Vec::new();
        if let Some(cursor) = scripts.last() {
            for child in cursor.attempted(self.state.committed()) {
                records.push(recorded(
                    Some(cursor.outer.id.clone()),
                    child,
                    ToolResult::error("submission stopped without a committed child result; external outcome is unresolved"),
                    vec![],
                ));
            }
        }
        for index in (1..scripts.len()).rev() {
            records.push(recorded(
                Some(scripts[index - 1].outer.id.clone()),
                scripts[index].outer.clone(),
                ToolResult::error("submission stopped; nested script did not complete"),
                scripts[index].worker_audit().to_vec(),
            ));
        }
        self.active_mut()
            .turns
            .last_mut()
            .ok_or(core::Error::InvalidSnapshot)?
            .calls
            .extend(records);
        Ok(())
    }

    /// Overlapped batch siblings ran only in this activation, inside futures that cancellation
    /// already dropped; the step operation itself may still need an executor stop.
    pub(super) async fn cleanup_script_siblings(
        &mut self,
        sandbox: &Sandbox,
    ) -> Result<(), DriverError> {
        let step = self.active().step.operation();
        let activation = self.state.activation();
        let siblings: Vec<Attempt> = self
            .state
            .committed()
            .scripts()
            .values()
            .filter_map(|s| s.suspensions.last())
            .flat_map(|s| s.children.iter())
            .filter(|id| Some(**id) != step)
            .filter_map(|id| match &self.state.committed().operation(*id)?.phase {
                Phase::Cancelling { attempt, .. } if attempt.activation == activation => {
                    Some(attempt.clone())
                }
                _ => None,
            })
            .collect();
        for attempt in siblings {
            sandbox.check_cleanup().map_err(DriverError::Refused)?;
            self.apply(Event::Cleaned {
                token: RecoveryToken {
                    activation,
                    attempt,
                },
            })
            .await?;
        }
        Ok(())
    }
}

/// A transcript record for a call inside a script.
pub(super) fn recorded(
    parent_call_id: Option<String>,
    call: ToolCall,
    result: ToolResult,
    audit: Vec<bee_core::AuditEvent>,
) -> RecordedCall {
    RecordedCall {
        parent_call_id,
        proxy_events: vec![],
        denied_attempt_audit: vec![],
        denied_attempt_proxy_events: vec![],
        escalations: vec![],
        retried: false,
        timed_out: false,
        not_run: false,
        refused_by_hook: None,
        call,
        result,
        audit,
    }
}
