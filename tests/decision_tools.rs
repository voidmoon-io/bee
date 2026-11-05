//! Tool discovery remains stable when the optional HTTP client is compiled out.
use bee::tools::{is_known_tool, registry_for, sec_tool_family};

#[tokio::test]
async fn decision_tool_is_known_and_registered_in_every_build() {
    assert!(is_known_tool("decision_evaluate"));
    assert_eq!(sec_tool_family("decision_evaluate"), Some("decisions"));
    let registry = registry_for(&["decision_evaluate".into()], None);
    assert!(registry.contains("decision_evaluate"));
    let result = registry
        .execute(
            &bee::provider::ToolCall {
                id: "invalid".into(),
                name: "decision_evaluate".into(),
                arguments: serde_json::json!({"backend":"arbitrary", "url":"http://localhost"}),
            },
            &bee::sandbox::Sandbox::host(Vec::new()),
        )
        .await;
    assert!(result.is_error);
    #[cfg(not(feature = "decisions"))]
    assert!(result.content.contains("decisions"));
}
