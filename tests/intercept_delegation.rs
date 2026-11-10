//! 026 T057 (019 T092): a session that intercepts may delegate. Its subagent records through a proxy
//! of its own — own worker, own credentials, own store session — attributed to the delegation, and
//! nothing it sends is recorded as the parent's.
//!
//! Host enforcement, so both proxies run advisory (the operator accepted that for the session). The
//! kernel half — the child's proxy scope, its tool scope reaching only its own proxy port, a
//! sibling's credential refused — is the VM case `subagent-intercept-attributed`.

#![cfg(feature = "intercept")]

#[path = "support/fixtures.rs"]
mod fixtures;
#[path = "support/harness.rs"]
mod harness;
#[path = "support/vuln_target.rs"]
mod vuln_target;

use std::path::Path;

use bee::episode::{run_loop, LoopOptions};
use bee::provider::mock_model::MockModel;
use bee::provider::{StopReason, ToolCall, Turn};
use bee::transcript::DelegationOutcome;
use harness::{scope, Session};
use rusqlite::params;
use serde_json::json;

fn call(id: &str, name: &str, args: serde_json::Value) -> ToolCall {
    ToolCall {
        id: id.into(),
        name: name.into(),
        arguments: args,
    }
}

fn turn(calls: Vec<ToolCall>) -> Turn {
    Turn {
        text: None,
        tool_calls: calls,
        stop: StopReason::ToolUse,
        usage: None,
    }
}

fn text(t: &str) -> Turn {
    Turn {
        text: Some(t.into()),
        tool_calls: Vec::new(),
        stop: StopReason::EndTurn,
        usage: None,
    }
}

fn agent(root: &Path, name: &str) {
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("SKILL.md"),
        format!(
            "---\nname: {name}\nkind: agent\ndescription: test agent {name}\ntools: [http_send]\n\
             turn-limit: 4\n---\nYou fetch pages.\n"
        ),
    )
    .unwrap();
}

/// Exchanges recorded under proxy session `sid`.
fn exchanges(project: &Path, sid: &str) -> i64 {
    let store = bee::intercept::store::Store::open_read(project).unwrap();
    store
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM exchanges WHERE session_id = ?1",
            params![sid],
            |r| r.get(0),
        )
        .unwrap()
}

#[tokio::test]
async fn a_subagent_of_an_intercepted_session_is_not_refused() {
    let (http, _, _fx) = vuln_target::start_with(false);
    let skills = tempfile::tempdir().unwrap();
    agent(skills.path(), "web");
    let roots = vec![skills.path().to_path_buf()];
    let mut s = Session::start_with(
        scope(&format!("targets = [\"127.0.0.1:{}\"]", http.port()), &[]),
        &[],
        &["task", "http_send"],
        |spec| spec.skill_roots = roots,
    )
    .await;
    let parent_session = s.icpt.session_id().to_string();

    let url = format!("http://127.0.0.1:{}/echo", http.port());
    let model = MockModel::scripted(vec![
        // Parent: delegate.
        turn(vec![call(
            "t1",
            "task",
            json!({"agent": "web", "prompt": "fetch /echo"}),
        )]),
        // Child: one request through its own proxy, then finish.
        turn(vec![call(
            "c1",
            "http_send",
            json!({"request": {"method": "GET", "url": url}}),
        )]),
        turn(vec![call(
            "c2",
            "finish",
            json!({"outcome": "completed", "summary": "fetched"}),
        )]),
        // Parent again.
        text("done"),
    ]);
    let opts = LoopOptions {
        escalation: s.session.escalation.take(),
        delegation: s.session.delegation(None),
        ..LoopOptions::default()
    };
    let t = run_loop(
        &model,
        &fixtures::scenario("parent", &["task", "http_send"], 4, 60),
        &mut s.session.registry,
        &mut s.session.sandbox,
        &opts,
    )
    .await;

    let record = *t.delegations().first().expect("the task call delegated");
    assert_eq!(
        record.outcome,
        DelegationOutcome::Completed,
        "not refused: {:?}",
        record.outcome
    );
    let child = record.transcript.as_deref().expect("the child ran");
    let sent = child
        .turns
        .iter()
        .flat_map(|turn| &turn.calls)
        .find(|c| c.call.name == "http_send")
        .expect("the child sent");
    assert!(!sent.result.is_error, "{}", sent.result.content);

    // The child's proxy session is the one attributed to this delegation's `task` call.
    let store = bee::intercept::store::Store::open_read(s.dir.path()).unwrap();
    let child_session: String = store
        .conn()
        .query_row(
            "SELECT session_id FROM attribution WHERE delegation_id = 't1'",
            [],
            |r| r.get(0),
        )
        .expect("the child's proxy recorded its attribution");
    let parent_of: String = store
        .conn()
        .query_row(
            "SELECT parent_session FROM attribution WHERE session_id = ?1",
            params![child_session],
            |r| r.get(0),
        )
        .unwrap();
    assert_ne!(child_session, parent_session);
    assert_eq!(parent_of, parent_session);
    assert_eq!(exchanges(s.dir.path(), &child_session), 1, "the child's");
    assert_eq!(
        exchanges(s.dir.path(), &parent_session),
        0,
        "none the parent's"
    );
}
