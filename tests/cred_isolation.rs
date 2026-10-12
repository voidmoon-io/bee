//! FR-018 host test (T011): a spawned tool child must NOT inherit the provider key env var, even
//! though the harness process holds it — nor any other ambient credential the operator's shell
//! happens to carry. `PATH` is the control: it *is* visible, so the test proves the child got a
//! real (if narrow) environment rather than an empty one.

use bee::provider::mock_model::MockModel;
use bee::provider::{ToolCall, Turn};
use bee::sandbox::{self, Sandbox};
use bee::scenario::Scenario;
use bee::tools::registry_for;
use bee::{run_loop, LoopOptions};

fn scenario() -> Scenario {
    Scenario {
        lease_turns: None,
        context: Default::default(),
        stuck: Default::default(),
        id: "cred".into(),
        policy_path: "/dev/null".into(),
        system_prompt: "sys".into(),
        task: "task".into(),
        turn_limit: 3,
        timeout_secs: 30,
        tools: vec!["bash".into()],
        mode: Default::default(),
        workdir: Default::default(),
        mcp: Default::default(),
        skills: Vec::new(),
        ceiling_policy_path: None,
        security: Default::default(),
    }
}

#[tokio::test]
async fn tool_child_cannot_read_provider_key() {
    // SAFETY: single-threaded within this test's control. `FAKE_PROVIDER_KEY` is the configured
    // provider key; `AWS_SECRET_ACCESS_KEY` stands for every ambient credential the old four-name
    // denylist never knew about and therefore handed straight to the model.
    std::env::set_var("FAKE_PROVIDER_KEY", "sk-super-secret-value");
    std::env::set_var("AWS_SECRET_ACCESS_KEY", "ambient-cloud-credential");

    let model = MockModel::scripted(vec![
        Turn::calls(vec![ToolCall {
            id: "1".into(),
            name: "bash".into(),
            arguments: serde_json::json!({
                "command": "echo KEY=[$FAKE_PROVIDER_KEY] AMB=[$AWS_SECRET_ACCESS_KEY] PATH_SET=[${PATH:+yes}]"
            }),
        }]),
        Turn::text("done"),
    ]);

    let scn = scenario();
    let mut registry = registry_for(&scn.tools, None);
    // Strip list = default provider vars + the configured key var name.
    let mut sb = Sandbox::host(sandbox::key_vars(Some("FAKE_PROVIDER_KEY")));

    let t = run_loop(
        &model,
        &scn,
        &mut registry,
        &mut sb,
        &LoopOptions::default(),
    )
    .await;

    let out = &t.turns[0].calls[0].result.content;
    assert!(
        !out.contains("sk-super-secret-value"),
        "provider key leaked to tool child: {out}"
    );
    assert!(
        out.contains("KEY=[]"),
        "key var should be empty in the child: {out}"
    );
    // An ambient credential the strip list never named must be gone too — the allowlist, not the
    // denylist, is what makes this hold.
    assert!(
        !out.contains("ambient-cloud-credential"),
        "ambient credential leaked to tool child: {out}"
    );
    assert!(
        out.contains("AMB=[]"),
        "ambient credential should be empty in the child: {out}"
    );
    // Control: an allowlisted var IS present, proving the child has a usable environment and the
    // assertions above are not just measuring an empty one.
    assert!(
        out.contains("PATH_SET=[yes]"),
        "allowlisted PATH missing from the child: {out}"
    );

    std::env::remove_var("FAKE_PROVIDER_KEY");
    std::env::remove_var("AWS_SECRET_ACCESS_KEY");
}
