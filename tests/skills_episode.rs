//! Episode-path skill discovery (006-skills, step a). A scenario that declares skill roots must get
//! the `skill` tool registered so the model can load a skill's instructions mid-episode. Offline,
//! `MockModel`-driven, host sandbox — no kernel scope needed (loading a skill is instructions-only).

use std::path::PathBuf;

use bee::provider::mock_model::MockModel;
use bee::provider::{ToolCall, Turn};
use bee::run_episode;
use bee::scenario::Scenario;
use bee::transcript::EpisodeStatus;

/// Write a skills root under a unique temp dir holding one `greet` skill, and return the root.
fn skills_root(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("bee-skills-ep-{}-{tag}", std::process::id()));
    let d = root.join("greet");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(
        d.join("SKILL.md"),
        "---\nname: greet\ndescription: greet the user warmly\n---\nAlways say hello first.\n",
    )
    .unwrap();
    root
}

/// Write a skills root holding one skill with a `requires:` block, and return the root.
fn skills_root_requiring(tag: &str, requires_yaml: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("bee-skills-req-{}-{tag}", std::process::id()));
    let d = root.join("builder");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(
        d.join("SKILL.md"),
        format!("---\nname: builder\ndescription: builds things\n{requires_yaml}---\nUse bash.\n"),
    )
    .unwrap();
    root
}

/// Write a bee policy file and return its path.
fn write_policy(tag: &str, contents: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bee-skills-pol-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(format!("{tag}.policy.toml"));
    std::fs::write(&p, contents).unwrap();
    p
}

fn scenario(skills: Vec<PathBuf>) -> Scenario {
    Scenario {
        lease_turns: None,
        context: Default::default(),
        id: "skills-ep".into(),
        policy_path: "/dev/null".into(),
        system_prompt: "You are a test agent.".into(),
        task: "greet".into(),
        turn_limit: 4,
        timeout_secs: 30,
        tools: vec![],
        mode: Default::default(),
        workdir: Default::default(),
        mcp: Default::default(),
        skills,
        ceiling_policy_path: None,
        security: Default::default(),
    }
}

#[tokio::test]
async fn scenario_skill_roots_register_the_skill_tool() {
    let root = skills_root("present");
    // The model loads the skill on turn 1, then wraps up with a text turn.
    let model = MockModel::scripted(vec![
        Turn::calls(vec![ToolCall {
            id: "1".into(),
            name: "skill".into(),
            arguments: serde_json::json!({ "name": "greet" }),
        }]),
        Turn::text("done"),
    ]);

    let t = run_episode(&model, &scenario(vec![root]), None, None).await;

    assert_eq!(t.status, EpisodeStatus::Completed);
    let call = t
        .turns
        .iter()
        .flat_map(|turn| &turn.calls)
        .find(|c| c.call.name == "skill")
        .expect("skill tool was called");
    assert!(!call.result.is_error, "skill load should succeed");
    assert!(call.result.content.contains("# Skill loaded: greet"));
    assert!(call.result.content.contains("Always say hello first."));
}

#[tokio::test]
async fn no_skill_roots_means_no_skill_tool() {
    // With no roots declared, the `skill` tool is never registered — a call to it errors as unknown.
    let model = MockModel::scripted(vec![
        Turn::calls(vec![ToolCall {
            id: "1".into(),
            name: "skill".into(),
            arguments: serde_json::json!({ "name": "greet" }),
        }]),
        Turn::text("done"),
    ]);

    let t = run_episode(&model, &scenario(vec![]), None, None).await;

    let call = t
        .turns
        .iter()
        .flat_map(|turn| &turn.calls)
        .find(|c| c.call.name == "skill")
        .expect("model attempted the call");
    assert!(call.result.is_error);
    assert!(call.result.content.contains("unknown tool"));
}

/// A model that calls `bash` once, then stops. Reused by the grant tests.
fn bash_then_stop() -> MockModel {
    MockModel::scripted(vec![
        Turn::calls(vec![ToolCall {
            id: "1".into(),
            name: "bash".into(),
            arguments: serde_json::json!({ "command": "echo granted" }),
        }]),
        Turn::text("done"),
    ])
}

#[tokio::test]
async fn skill_requiring_a_tool_grants_it_within_ceiling() {
    // The scenario enables NO tools; a skill's `requires: tools: [bash]` must add bash. The base
    // policy parses (so grant resolution runs) and a tool-only request sits within any ceiling.
    let root = skills_root_requiring("grant", "requires:\n  tools: [bash]\n");
    let policy = write_policy("base", "[policy]\nname = \"base\"\nmode = \"enforce\"\n");
    let mut scn = scenario(vec![root]);
    scn.policy_path = policy;

    let t = run_episode(&bash_then_stop(), &scn, None, None).await;

    let call = t
        .turns
        .iter()
        .flat_map(|turn| &turn.calls)
        .find(|c| c.call.name == "bash")
        .expect("bash was called");
    assert!(
        !call.result.is_error,
        "granted bash should run: {}",
        call.result.content
    );
    assert!(call.result.content.contains("granted"));
}

#[tokio::test]
async fn grant_beyond_ceiling_is_refused_and_tool_withheld() {
    // The skill also demands write to /etc, which the (base == ceiling) policy does not permit. The
    // whole request is refused, so its bundled `bash` tool is NOT registered either.
    let root = skills_root_requiring(
        "greedy",
        "requires:\n  tools: [bash]\n  filesystem:\n    /etc: write\n",
    );
    let policy = write_policy("tight", "[policy]\nname = \"tight\"\nmode = \"enforce\"\n");
    let mut scn = scenario(vec![root]);
    scn.policy_path = policy;

    let t = run_episode(&bash_then_stop(), &scn, None, None).await;

    let call = t
        .turns
        .iter()
        .flat_map(|turn| &turn.calls)
        .find(|c| c.call.name == "bash")
        .expect("model attempted bash");
    assert!(
        call.result.is_error,
        "bash must be withheld when the grant is refused"
    );
    assert!(call.result.content.contains("unknown tool"));
}
