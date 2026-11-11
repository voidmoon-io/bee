//! Bounded adoption experiment: Rig owns progression; Bee owns every tool attempt.
//! No production entry point selects this driver.

#[path = "support/scripted.rs"]
mod scripted;

use bee::{
    call::{run_call, CallInput, TimeoutPolicy},
    provider::ToolCall,
    sandbox::{CallOrigin, Sandbox, ScriptedAudit},
    tools::ToolRegistry,
};
use rig_core::{
    agent::run::{AgentRun, AgentRunStep, ModelTurn, ModelTurnOutcome},
    completion::{AssistantContent, Usage},
    message::{ToolResultContent, UserContent},
    OneOrMany,
};
use scripted::{Attempt, ScriptedTool, SCRIPTED};
use std::{
    collections::BTreeSet,
    sync::{atomic::Ordering, Arc},
    time::Duration,
};

fn response(content: AssistantContent) -> ModelTurn {
    let names = BTreeSet::from([SCRIPTED.to_string()]);
    ModelTurn::new(
        None,
        OneOrMany::one(content),
        Usage::default(),
        names.clone(),
        names,
    )
}

#[tokio::test]
async fn rig_progression_preserves_bee_call_result_and_audit() {
    for denied in [false, true] {
        let audit = Arc::new(ScriptedAudit::default());
        let event = scripted::ev(
            "file_open",
            "/fixture",
            if denied { "denied" } else { "allowed" },
            None,
        );
        let attempt = if denied {
            Attempt::error("permission denied")
        } else {
            Attempt::ok("file contents")
        };
        let tool = ScriptedTool::new(audit.clone(), vec![attempt.with_audit(vec![event])]);
        let counter = tool.counter();
        let mut registry = ToolRegistry::new();
        registry.insert(Box::new(tool));
        let mut sandbox = Sandbox::host_scripted(Vec::new(), audit);
        let mut run = AgentRun::new("read the fixture").max_turns(3);
        assert!(matches!(
            run.next_step().unwrap(),
            AgentRunStep::CallModel { turn: 1, .. }
        ));
        assert!(matches!(
            run.model_response(response(AssistantContent::tool_call(
                "c1",
                SCRIPTED,
                serde_json::json!({})
            )))
            .unwrap(),
            ModelTurnOutcome::Continue { .. }
        ));

        // Checkpoint only Rig progression, not Bee's grants or execution journal.
        let mut run: AgentRun =
            serde_json::from_str(&serde_json::to_string(&run).unwrap()).unwrap();
        let AgentRunStep::CallTools { calls } = run.next_step().unwrap() else {
            panic!("expected tool dispatch")
        };
        assert_eq!(calls.len(), 1);
        let pending = &calls[0];
        assert!(pending.preresolved_result.is_none());
        let call = ToolCall {
            id: pending.tool_call.id.clone(),
            name: pending.tool_call.function.name.clone(),
            arguments: pending.tool_call.function.arguments.clone(),
        };
        let outcome = run_call(
            CallInput {
                call: &call,
                turn: 0,
                origin: CallOrigin::Tool,
                timeout: TimeoutPolicy::PerCall(Duration::from_secs(1)),
            },
            &mut sandbox,
            &mut registry,
            None,
        )
        .await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(outcome.result.is_error, denied);
        assert!(outcome
            .audit
            .iter()
            .any(|e| e.target == "/fixture"
                && e.decision == if denied { "denied" } else { "allowed" }));
        let content = outcome.result.content;
        run.tool_results(vec![UserContent::tool_result(
            "c1",
            OneOrMany::one(ToolResultContent::text(content.clone())),
        )])
        .unwrap();
        let AgentRunStep::CallModel { prompt, turn, .. } = run.next_step().unwrap() else {
            panic!("expected follow-up")
        };
        assert_eq!(turn, 2);
        assert!(serde_json::to_string(&prompt).unwrap().contains(&content));
        run.model_response(response(AssistantContent::text("finished")))
            .unwrap();
        let AgentRunStep::Done(done) = run.next_step().unwrap() else {
            panic!("expected completion")
        };
        assert_eq!(done.output, "finished");
    }
}

#[test]
fn unknown_tools_require_explicit_recovery_before_dispatch() {
    let mut run = AgentRun::new("task");
    run.next_step().unwrap();
    assert!(matches!(
        run.model_response(response(AssistantContent::tool_call(
            "c1",
            "unavailable",
            serde_json::json!({})
        )))
        .unwrap(),
        ModelTurnOutcome::NeedsResolution(_)
    ));
}
