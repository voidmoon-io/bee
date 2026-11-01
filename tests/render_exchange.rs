//! End-to-end US6 (003-visual-render, SC-008): a `MockModel` turn calls the `render` tool; the
//! capturing [`ReplOutput`] receives `render_widget` with the `RenderSpec`, and the `ToolResult`
//! content handed back to the model is the text summary — never the ANSI art.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use bee::provider::mock_model::MockModel;
use bee::render_spec::{EffectSpec, RenderSpec};
use bee::repl::{run_exchange, ReplOutput, SteeringQueue};
use bee::sandbox::{self, Sandbox};
use bee::tools::registry_for;
use bee::{Conversation, ReplConfig, ToolCall, Turn};

/// A minimal [`ReplOutput`] that records the widgets drawn via `render_widget`.
#[derive(Default)]
struct WidgetCapture {
    widgets: Mutex<Vec<RenderSpec>>,
}

impl ReplOutput for WidgetCapture {
    fn assistant_delta(&self, _chunk: &str) {}
    fn assistant_end(&self) {}
    fn tool_call(&self, _name: &str, _arguments: &serde_json::Value) {}
    fn tool_result(&self, _result: &bee::ToolResult, _audit: &[bee_core::AuditEvent]) {}
    fn error(&self, _msg: &str) {}
    fn info(&self, _msg: &str) {}
    fn render_widget(&self, spec: &RenderSpec, _effect: Option<&EffectSpec>) {
        self.widgets.lock().unwrap().push(spec.clone());
    }
}

#[tokio::test]
async fn agent_render_call_draws_widget_and_summarizes_to_model() {
    let script = r#"
        c = bar_chart("File Sizes");
        c.bar("main.rs", 340);
        c.bar("lib.rs", 120);
        c.bar("tools.rs", 88);
        c.bar("repl.rs", 210);
        c.bar("viz.rs", 64);
        render(c);
    "#;
    let model = MockModel::scripted(vec![
        Turn::calls(vec![ToolCall {
            id: "1".into(),
            name: "render".into(),
            arguments: serde_json::json!({ "script": script }),
        }]),
        Turn::text("Rendered the chart."),
    ]);

    let mut registry = registry_for(&["render".to_string()], None);
    let mut sb = Sandbox::host(sandbox::key_vars(None));
    let mut convo = Conversation {
        system: String::new(),
        messages: Vec::new(),
    };
    let out = WidgetCapture::default();
    let steering: SteeringQueue = Arc::new(Mutex::new(VecDeque::new()));
    let config = ReplConfig::default();

    let res = run_exchange(
        "show me the file sizes",
        &model,
        &mut convo,
        &mut registry,
        &mut sb,
        &config,
        &out,
        &steering,
        None,
    )
    .await;

    // (a) The Collector received a BarChart with the 5 expected bars.
    let widgets = out.widgets.lock().unwrap();
    assert_eq!(widgets.len(), 1, "one widget rendered");
    match &widgets[0] {
        RenderSpec::BarChart { title, bars, .. } => {
            assert_eq!(title, "File Sizes");
            assert_eq!(bars.len(), 5);
            assert_eq!(bars[0].label, "main.rs");
            assert_eq!(bars[0].value, 340);
            assert_eq!(bars[4].value, 64);
        }
        other => panic!("expected BarChart, got {other:?}"),
    }

    // (b)+(c) The tool result carried a render_spec, and its content (sent to the model) is the text
    // summary — no ANSI.
    let call = &res.turns[0].calls[0];
    assert!(call.result.render_spec.is_some(), "result carries the spec");
    assert!(
        !call.result.content.contains('\u{1b}'),
        "content is ANSI-free"
    );
    assert!(
        call.result.content.contains("bar chart") && call.result.content.contains("5 bars"),
        "summary names the chart + bar count: {}",
        call.result.content
    );
}
