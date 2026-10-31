#![cfg(feature = "source")]

use std::path::Path;
use std::process::Command;

use bee::evidence::EvidenceStore;
use bee::provider::ToolCall;
use bee::source::{query, Request, SourcePin, SourceRange};
use bee::tools::{registry_for, source::SourceTool};
use bee::Sandbox;
use serde_json::json;
use sha2::{Digest, Sha256};

fn git(root: &Path, args: &[&str]) -> String {
    let result = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "Fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap().trim().into()
}

fn fixture() -> (tempfile::TempDir, String) {
    let root = tempfile::tempdir().unwrap();
    git(root.path(), &["init", "--quiet"]);
    std::fs::create_dir(root.path().join("src")).unwrap();
    std::fs::write(root.path().join("src/a.txt"), "first\r\nsecond λ\nlast").unwrap();
    std::fs::write(root.path().join("empty"), "").unwrap();
    std::fs::write(root.path().join("binary"), [0xff, 0]).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", root.path().join("escape")).unwrap();
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "--quiet", "-m", "fixture"]);
    let commit = git(root.path(), &["rev-parse", "HEAD"]);
    (root, commit)
}

fn pin(root: &Path, commit: &str) -> SourcePin {
    serde_json::from_value(
        query(Request::Pin {
            repository: root.to_str().unwrap().into(),
            commit: commit.into(),
        })
        .unwrap(),
    )
    .unwrap()
}

fn read(
    pin: SourcePin,
    path: &str,
    start_line: usize,
    end_line: usize,
) -> Result<serde_json::Value, String> {
    query(Request::Read {
        pin,
        path: path.into(),
        start_line,
        end_line,
    })
}

#[test]
fn pin_ignores_dirty_worktree_and_new_head_and_preserves_exact_bytes() {
    let (root, commit) = fixture();
    let pin = pin(root.path(), &commit);
    std::fs::write(root.path().join("src/a.txt"), "new head").unwrap();
    git(root.path(), &["add", "."]);
    git(root.path(), &["commit", "--quiet", "-m", "new"]);
    std::fs::write(root.path().join("src/a.txt"), "dirty").unwrap();
    let range: SourceRange = serde_json::from_value(read(pin, "src/a.txt", 1, 2).unwrap()).unwrap();
    assert_eq!(range.pin.commit, commit);
    assert_eq!(range.content, "first\r\nsecond λ\n");
    assert_eq!(range.total_lines, 3);
    assert_eq!(
        range.range_sha256,
        format!("{:x}", Sha256::digest(range.content.as_bytes()))
    );
    assert_eq!(
        range.file_sha256,
        format!("{:x}", Sha256::digest("first\r\nsecond λ\nlast".as_bytes()))
    );
    assert_eq!(
        std::fs::read_to_string(root.path().join("src/a.txt")).unwrap(),
        "dirty"
    );
}

#[test]
fn invalid_paths_objects_and_ranges_fail_explicitly() {
    let (root, commit) = fixture();
    let pin = pin(root.path(), &commit);
    for path in [
        "../outside",
        "/etc/passwd",
        "src/../empty",
        "src//a.txt",
        "escape",
        "escape/child",
        "src",
        "missing",
        "binary",
    ] {
        assert!(read(pin.clone(), path, 1, 2).is_err(), "{path}");
    }
    for (start, end) in [(0, 1), (2, 1), (1, 401), (4, 4), (usize::MAX, usize::MAX)] {
        assert!(read(pin.clone(), "src/a.txt", start, end).is_err());
    }
    assert!(read(pin.clone(), "empty", 1, 1)
        .unwrap_err()
        .contains("0 lines"));
    assert!(query(Request::Pin {
        repository: root.path().display().to_string(),
        commit: "HEAD".into()
    })
    .is_err());
    let mut wrong = pin;
    wrong.tree = "0".repeat(40);
    assert!(read(wrong, "src/a.txt", 1, 2)
        .unwrap_err()
        .contains("tree does not match"));
}

#[tokio::test]
async fn scoped_worker_pin_to_read_to_finding_is_native_and_receipted() {
    let (root, commit) = fixture();
    let state = tempfile::tempdir().unwrap();
    let store = EvidenceStore::new(state.path().join("evidence"), "source-test");
    let mut registry = registry_for(
        &[
            "source_pin".into(),
            "source_read".into(),
            "record_finding".into(),
            "hunt_checkpoint".into(),
            "hunt_resume".into(),
        ],
        None,
    );
    registry.enable_evidence(store.clone());
    registry.set_deps(std::sync::Arc::new(
        (**registry.deps()).clone().with_security(
            &bee::security::SecurityConfig {
                findings_dir: Some(state.path().join("findings")),
                ..Default::default()
            },
            None,
            "source-test",
        ),
    ));
    for name in ["source_pin", "source_read"] {
        registry.insert(Box::new(
            SourceTool::new(name, Some(store.clone()))
                .with_executable(env!("CARGO_BIN_EXE_bee").into()),
        ));
    }
    let sandbox = Sandbox::host(Vec::new());
    let call = |name: &str, arguments| ToolCall {
        id: "fixture".into(),
        name: name.into(),
        arguments,
    };
    let pinned = registry
        .execute(
            &call(
                "source_pin",
                json!({"repository":root.path(),"commit":commit}),
            ),
            &sandbox,
        )
        .await;
    assert!(!pinned.is_error, "{}", pinned.content);
    let snapshot = pinned.receipt_id.unwrap();
    let read = registry
        .execute(
            &call(
                "source_read",
                json!({"snapshot":snapshot,"path":"src/a.txt","start_line":2,"end_line":3}),
            ),
            &sandbox,
        )
        .await;
    assert!(!read.is_error, "{}", read.content);
    let id = read.receipt_id.unwrap();
    let range: SourceRange = serde_json::from_str(&store.get(&id).unwrap().result.content).unwrap();
    assert_eq!(range.content, "second λ\nlast");
    let recorded = registry.execute(&call("record_finding", json!({"path":"src/a.txt","class":"fixture","title":"Observation","evidence":"This is source evidence only","evidence_refs":[id]})), &sandbox).await;
    assert!(!recorded.is_error, "{}", recorded.content);
    let checkpoint = registry.execute(&call("hunt_checkpoint", json!({
        "snapshot":snapshot,"title":"Fixture investigation","actor":"Caller",
        "invariant":"Guard before effect","hypothesis":"The guard may be bypassed",
        "countercheck":"Trace upstream caller","observation":"Read the committed source",
        "next_action":"Inspect registration","unknowns":["Reachability"],"status":"exploring",
        "evidence":[{"receipt_id":id,"role":"guard"}]
    })), &sandbox).await;
    assert!(!checkpoint.is_error, "{}", checkpoint.content);
    let checkpoint_id = checkpoint.receipt_id.unwrap();
    // Losing the object database does not erase observed evidence or silently fall back to HEAD.
    drop(root);
    assert!(store.get(&id).is_ok());
    let resumed = registry
        .execute(&call("hunt_resume", json!({"id":checkpoint_id})), &sandbox)
        .await;
    assert!(!resumed.is_error, "{}", resumed.content);
    let page: serde_json::Value = serde_json::from_str(
        &store
            .get(&resumed.receipt_id.unwrap())
            .unwrap()
            .result
            .content,
    )
    .unwrap();
    assert_eq!(
        page["history"][0]["checkpoint"]["anchors"][0]["path"],
        "src/a.txt"
    );
    assert!(page["history"][0]["evidence_problems"]
        .as_array()
        .unwrap()
        .is_empty());
    let unavailable = registry
        .execute(
            &call(
                "source_read",
                json!({"snapshot":snapshot,"path":"src/a.txt","start_line":1,"end_line":1}),
            ),
            &sandbox,
        )
        .await;
    assert!(unavailable.is_error);
    let forged = registry
        .execute(
            &call(
                "source_read",
                json!({"snapshot":id,"path":"src/a.txt","start_line":1,"end_line":1}),
            ),
            &sandbox,
        )
        .await;
    assert!(forged.is_error);
    assert!(forged.content.contains("source_pin receipt"));
}

#[test]
fn altered_git_objects_and_oversized_ranges_are_refused() {
    let (root, commit) = fixture();
    let snapshot = pin(root.path(), &commit);
    let blob = git(root.path(), &["rev-parse", &format!("{commit}:src/a.txt")]);
    std::fs::write(root.path().join("replacement"), "replacement bytes").unwrap();
    let replacement = git(root.path(), &["hash-object", "-w", "replacement"]);
    let object_path = |id: &str| {
        root.path()
            .join(".git/objects")
            .join(&id[..2])
            .join(&id[2..])
    };
    std::fs::remove_file(object_path(&blob)).unwrap();
    std::fs::copy(object_path(&replacement), object_path(&blob)).unwrap();
    assert!(read(snapshot, "src/a.txt", 1, 1)
        .unwrap_err()
        .contains("digest mismatch"));

    std::fs::write(root.path().join("long"), "x".repeat(65 * 1024)).unwrap();
    git(root.path(), &["add", "long"]);
    git(root.path(), &["commit", "--quiet", "-m", "long line"]);
    let snapshot = pin(root.path(), &git(root.path(), &["rev-parse", "HEAD"]));
    assert!(read(snapshot, "long", 1, 1).unwrap_err().contains("64 KiB"));
}
