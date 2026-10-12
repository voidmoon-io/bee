//! Plain test fixtures shared by the 024 orchestration tests: policies, scenarios and model turns.
//! No feature requirements, so any test target can include it with
//! `#[path = "support/fixtures.rs"] mod fixtures;`.

#![allow(dead_code)]

use bee::provider::{StopReason, ToolCall, Turn};
use bee::scenario::Scenario;
use bee_core::{Access, Mode, Policy};

/// An enforce-mode policy granting exactly `fs`.
pub fn policy(fs: &[(&str, Access)]) -> Policy {
    let mut p = Policy {
        name: "p".into(),
        description: None,
        mode: Mode::Enforce,
        filesystem: Default::default(),
        exec: Default::default(),
        network: Default::default(),
        exfiltration: Default::default(),
        http: None,
    };
    for (path, a) in fs {
        p.filesystem.insert(path.to_string(), *a);
    }
    p
}

/// [`policy`] with no filesystem grants and a `[policy.http]` holding `targets` (`host:port`).
pub fn http_policy(targets: &[&str]) -> Policy {
    let mut p = policy(&[]);
    p.http = Some(bee_core::HttpPolicy {
        targets: targets
            .iter()
            .map(|t| bee_core::HostPort::try_from(t.to_string()).unwrap())
            .collect(),
        ..Default::default()
    });
    p
}

/// A host scenario: no policy file, no MCP, no skills, no ceiling.
pub fn scenario(id: &str, tools: &[&str], turn_limit: u32, timeout_secs: u64) -> Scenario {
    Scenario {
        lease_turns: None,
        context: Default::default(),
        stuck: Default::default(),
        finish: false,
        id: id.into(),
        policy_path: "/dev/null".into(),
        system_prompt: "You are a test agent.".into(),
        task: "go".into(),
        turn_limit,
        timeout_secs,
        tools: tools.iter().map(|t| t.to_string()).collect(),
        mode: Default::default(),
        workdir: Default::default(),
        mcp: Default::default(),
        skills: Vec::new(),
        ceiling_policy_path: None,
        security: Default::default(),
    }
}

/// A model turn with optional prose and one call per `(id, tool)`, each with `{}` arguments.
pub fn tool_turn(text: Option<&str>, calls: &[(&str, &str)]) -> Turn {
    Turn {
        text: text.map(str::to_string),
        tool_calls: calls
            .iter()
            .map(|(id, tool)| ToolCall {
                id: id.to_string(),
                name: tool.to_string(),
                arguments: serde_json::json!({}),
            })
            .collect(),
        stop: StopReason::ToolUse,
        usage: None,
    }
}

/// A model turn calling `tool` once, as `id`.
pub fn call_turn(id: &str, tool: &str) -> Turn {
    tool_turn(None, &[(id, tool)])
}

/// A text-only model turn, which ends an episode or an exchange.
pub fn text_turn(text: &str) -> Turn {
    Turn {
        text: Some(text.into()),
        tool_calls: Vec::new(),
        stop: StopReason::EndTurn,
        usage: None,
    }
}
