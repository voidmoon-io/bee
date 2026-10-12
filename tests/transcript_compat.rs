//! Transcripts written before 025 still read, and a run that uses none of 025's features writes
//! none of its keys (025 analysis G1, FR-039).
//!
//! `fixtures/transcript-pre025.json` was written by `bee run` at `5fdaed3`, the last `main` before
//! 025's first PR, from a scripted host run (one `list_directory` call, then text).

#[path = "support/fixtures.rs"]
mod fixtures;
#[path = "support/scripted.rs"]
mod scripted;

use std::sync::Arc;

use bee::episode::{run_loop, LoopOptions};
use bee::provider::mock_model::MockModel;
use bee::sandbox::{Sandbox, ScriptedAudit};
use bee::tools::ToolRegistry;
use bee::transcript::{EpisodeStatus, EpisodeTranscript};
use fixtures::*;
use scripted::*;

const PRE_025: &str = include_str!("fixtures/transcript-pre025.json");

#[test]
fn a_pre_025_transcript_reads_and_writes_back_unchanged() {
    let t: EpisodeTranscript = serde_json::from_str(PRE_025).expect("a pre-025 transcript reads");
    assert_eq!(t.status, EpisodeStatus::Completed);
    assert!(!t.finish_offered);

    let original: serde_json::Value = serde_json::from_str(PRE_025).unwrap();
    let again = serde_json::to_value(&t).unwrap();
    assert_eq!(
        serde_json::to_string_pretty(&again).unwrap(),
        serde_json::to_string_pretty(&original).unwrap()
    );
}

/// The keys 025 adds. Each must be absent unless its feature did something.
const NEW_KEYS: &[&str] = &[
    "notes",
    "compactions",
    "summary_usage",
    "finish_offered",
    "not_run",
];

#[tokio::test]
async fn a_run_without_025_features_writes_no_new_key() {
    let audit = Arc::new(ScriptedAudit::default());
    let mut sb = Sandbox::host_scripted(Vec::new(), audit.clone());
    let mut registry = ToolRegistry::new();
    registry.insert(Box::new(ScriptedTool::new(audit, Vec::new())));
    // `finish: false` via the fixture; two distinct calls, so no streak; a small result, so no cap.
    let t = run_loop(
        &MockModel::scripted(vec![
            call_turn("c0", SCRIPTED),
            tool_turn(None, &[("c1", SCRIPTED)]),
            text_turn("done"),
        ]),
        &scenario("compat", &[SCRIPTED], 5, 30),
        &mut registry,
        &mut sb,
        &LoopOptions::default(),
    )
    .await;
    assert_eq!(t.status, EpisodeStatus::Completed);
    let json = serde_json::to_string(&t).unwrap();
    for key in NEW_KEYS {
        assert!(
            !json.contains(&format!("\"{key}\"")),
            "{key} written: {json}"
        );
    }
}
