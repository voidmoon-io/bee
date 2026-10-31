//! US2 — findings survive the session (016-native-tools).
//!
//! The property under test is that a security finding outlives the episode that found it, and that
//! a *human's* judgement about it outlives every subsequent automated re-discovery. Both are
//! properties of the ledger's shape rather than of any tool: an append-only event log folded into a
//! view can merge, and cannot clobber.
//!
//! Run with `cargo test --test finding_ledger --features findings`.

#![cfg(feature = "findings")]

use bee::findings::{
    fold, record, Finding, FindingSource, Ledger, LedgerEvent, Sighting, Verdict, VerdictState,
};

/// A finding fixture. `line` varies independently of identity — that is the point of T026.
fn finding(path: &str, class: &str, title: &str) -> Finding {
    Finding::new(
        path.to_string(),
        class.to_string(),
        title.to_string(),
        "evidence: the call is reached with attacker-controlled input".to_string(),
        FindingSource::Tool("ast_grep".to_string()),
    )
}

fn sighting(run: &str, line: Option<u32>) -> Sighting {
    Sighting {
        evidence_refs: Vec::new(),
        run_id: run.to_string(),
        at: time::OffsetDateTime::UNIX_EPOCH,
        line,
        end_line: None,
        rule_id: None,
    }
}

fn ledger(dir: &std::path::Path) -> Ledger {
    Ledger::at(dir.join("findings"))
}

// ── T023 · a repeat sighting merges rather than duplicating (FR-019, SC-003) ─────────────────────

#[test]
fn the_same_finding_seen_in_two_runs_is_one_entry_with_two_sightings() {
    let tmp = tempfile::tempdir().unwrap();
    let led = ledger(tmp.path());

    let f = finding(
        "src/db.rs",
        "sql-injection",
        "Query built by string concatenation",
    );
    let id = record(&led, f.clone(), sighting("run-1", Some(42))).expect("first record");
    let again = record(&led, f, sighting("run-2", Some(42))).expect("second record");
    assert_eq!(id, again, "the same finding must keep the same identity");

    let view = fold(&led).expect("fold");
    assert_eq!(
        view.findings.len(),
        1,
        "expected one finding, got {view:#?}"
    );
    let entry = &view.findings[0];
    assert_eq!(entry.sightings.len(), 2, "both runs should be recorded");
    assert_eq!(entry.sightings[0].run_id, "run-1");
    assert_eq!(entry.sightings[1].run_id, "run-2");
}

// ── T024 · a human verdict survives automated re-discovery (FR-020, SC-004) ──────────────────────

#[test]
fn a_false_positive_verdict_survives_rediscovery() {
    let tmp = tempfile::tempdir().unwrap();
    let led = ledger(tmp.path());

    let f = finding(
        "src/auth.rs",
        "path-traversal",
        "User input reaches fs::read",
    );
    let id = record(&led, f.clone(), sighting("run-1", Some(10))).unwrap();

    led.append(&LedgerEvent::Adjudicated {
        id: id.clone(),
        verdict: Verdict {
            state: VerdictState::FalsePositive,
            note: Some("sanitised upstream".to_string()),
            by: "jg".to_string(),
            at: time::OffsetDateTime::UNIX_EPOCH,
        },
    })
    .expect("adjudicate");

    // A later run finds it again. The scanner has no power to overturn a human.
    record(&led, f, sighting("run-2", Some(10))).unwrap();

    let view = fold(&led).unwrap();
    let entry = view.get(&id).expect("finding present");
    assert_eq!(
        entry.verdict.as_ref().map(|v| v.state.clone()),
        Some(VerdictState::FalsePositive),
        "re-discovery must not clear a human verdict"
    );
    assert_eq!(entry.sightings.len(), 2, "the sighting still appends");
}

// ── T025 · an incomplete record is rejected, ledger unchanged (FR-021) ───────────────────────────

#[test]
fn a_record_missing_required_evidence_is_rejected_and_writes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let led = ledger(tmp.path());

    // Establish a baseline so "unchanged" is a meaningful assertion rather than "still absent".
    record(
        &led,
        finding("src/ok.rs", "class", "A complete finding"),
        sighting("run-1", None),
    )
    .unwrap();
    let before = std::fs::read(led.log_path()).unwrap();

    let cases: [(&str, Finding); 4] = [
        ("path", finding("", "class", "title")),
        ("class", finding("src/a.rs", "", "title")),
        ("title", finding("src/a.rs", "class", "")),
        ("evidence", {
            let mut f = finding("src/a.rs", "class", "title");
            f.evidence = String::new();
            f
        }),
    ];

    for (field, f) in cases {
        let err = record(&led, f, sighting("run-2", None))
            .expect_err("an incomplete record must be refused");
        assert!(
            err.to_string().contains(field),
            "the diagnostic must name the missing field `{field}`, got: {err}"
        );
        let after = std::fs::read(led.log_path()).unwrap();
        assert_eq!(
            before, after,
            "the ledger must be byte-identical after a rejected `{field}` record"
        );
    }
}

// ── T026 · a finding whose line moved still merges (identity excludes the line) ──────────────────

#[test]
fn a_finding_that_moved_lines_merges_rather_than_duplicating() {
    let tmp = tempfile::tempdir().unwrap();
    let led = ledger(tmp.path());

    let f = finding(
        "src/db.rs",
        "sql-injection",
        "Query built by string concatenation",
    );
    // Run 1 sees it at line 42. Someone adds an import; run 2 sees the same defect at line 57.
    record(&led, f.clone(), sighting("run-1", Some(42))).unwrap();
    record(&led, f, sighting("run-2", Some(57))).unwrap();

    let view = fold(&led).unwrap();
    assert_eq!(
        view.findings.len(),
        1,
        "code movement alone must not mint a duplicate"
    );
    let lines: Vec<_> = view.findings[0].sightings.iter().map(|s| s.line).collect();
    assert_eq!(lines, vec![Some(42), Some(57)], "both locations recorded");
}

#[test]
fn title_normalisation_collapses_cosmetic_differences() {
    let tmp = tempfile::tempdir().unwrap();
    let led = ledger(tmp.path());

    // Same defect, two producers phrasing it with different case, spacing, and a trailing period.
    let a = finding(
        "src/db.rs",
        "sql-injection",
        "Query built by string concatenation",
    );
    let b = finding(
        "src/db.rs",
        "sql-injection",
        "query built  by   string concatenation.",
    );
    let id_a = record(&led, a, sighting("run-1", None)).unwrap();
    let id_b = record(&led, b, sighting("run-2", None)).unwrap();

    assert_eq!(id_a, id_b);
    assert_eq!(fold(&led).unwrap().findings.len(), 1);
}

#[test]
fn identity_separates_its_components() {
    // Bare concatenation would let ("a/b", "c") and ("a", "b/c") hash alike. The separator is what
    // stops a path/class boundary shift from merging two unrelated findings.
    let tmp = tempfile::tempdir().unwrap();
    let led = ledger(tmp.path());
    record(&led, finding("a/b", "c", "t"), sighting("r", None)).unwrap();
    record(&led, finding("a", "b/c", "t"), sighting("r", None)).unwrap();
    assert_eq!(fold(&led).unwrap().findings.len(), 2);
}

// ── T034 · concurrent appends lose nothing (FR-022) ──────────────────────────────────────────────

#[test]
fn concurrent_writers_lose_no_events() {
    let tmp = tempfile::tempdir().unwrap();
    let led = ledger(tmp.path());
    led.ensure_dir().unwrap();

    const WRITERS: usize = 8;
    const EACH: usize = 40;

    std::thread::scope(|scope| {
        for w in 0..WRITERS {
            let led = &led;
            scope.spawn(move || {
                for i in 0..EACH {
                    record(
                        led,
                        finding(
                            &format!("src/f{w}.rs"),
                            "class",
                            &format!("finding {w}-{i}"),
                        ),
                        sighting(&format!("run-{w}"), Some(i as u32)),
                    )
                    .expect("append");
                }
            });
        }
    });

    // Every line must be present AND individually parseable: an interleaved write that tore would
    // show up here as a short count or a parse failure, not as a subtly wrong view.
    let raw = std::fs::read_to_string(led.log_path()).unwrap();
    let lines: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), WRITERS * EACH, "no event may be lost");
    for (n, line) in lines.iter().enumerate() {
        serde_json::from_str::<LedgerEvent>(line)
            .unwrap_or_else(|e| panic!("line {n} did not survive intact: {e}\n{line}"));
    }
    assert_eq!(fold(&led).unwrap().findings.len(), WRITERS * EACH);
}

// ── Constitution IV · the log round-trips through a text diff (T065) ─────────────────────────────

#[test]
fn the_ledger_round_trips_through_a_text_diff_without_loss() {
    let tmp = tempfile::tempdir().unwrap();
    let led = ledger(tmp.path());

    let id = record(
        &led,
        finding("src/db.rs", "sql-injection", "Query built by concatenation"),
        sighting("run-1", Some(42)),
    )
    .unwrap();
    led.append(&LedgerEvent::Adjudicated {
        id,
        verdict: Verdict {
            state: VerdictState::Confirmed,
            note: None,
            by: "jg".to_string(),
            at: time::OffsetDateTime::UNIX_EPOCH,
        },
    })
    .unwrap();

    let raw = std::fs::read_to_string(led.log_path()).unwrap();
    // Reviewable: one self-contained JSON object per line, no line continuations.
    for line in raw.lines() {
        assert!(!line.is_empty());
        let event: LedgerEvent = serde_json::from_str(line).expect("each line parses alone");
        let reserialised = serde_json::to_string(&event).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&reserialised).unwrap(),
            serde_json::from_str::<serde_json::Value>(line).unwrap(),
            "a line must survive a decode/encode round trip"
        );
    }

    // Copying the text and re-folding yields the same view — the file *is* the state.
    let copy = tempfile::tempdir().unwrap();
    let copied = ledger(copy.path());
    copied.ensure_dir().unwrap();
    std::fs::write(copied.log_path(), &raw).unwrap();
    assert_eq!(
        serde_json::to_value(fold(&copied).unwrap()).unwrap(),
        serde_json::to_value(fold(&led).unwrap()).unwrap()
    );
}

// ── Folding is total: an unknown event kind is skipped, never fatal ──────────────────────────────

#[test]
fn an_unrecognised_event_is_skipped_and_counted_not_fatal() {
    let tmp = tempfile::tempdir().unwrap();
    let led = ledger(tmp.path());
    record(
        &led,
        finding("src/a.rs", "class", "A finding"),
        sighting("run-1", None),
    )
    .unwrap();

    // A future bee wrote an event kind this build does not know. Forward compatibility means the
    // rest of the ledger still folds.
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(led.log_path())
        .unwrap();
    writeln!(f, r#"{{"event":"quarantined","id":"deadbeef"}}"#).unwrap();
    writeln!(f, "not json at all").unwrap();
    drop(f);

    let view = fold(&led).expect("folding must not fail on an unknown event");
    assert_eq!(view.findings.len(), 1);
    assert_eq!(view.skipped, 2, "unreadable events are counted, not hidden");
}

// ── 019-http-intercept US8 (T084): findings cite exchanges as evidence ─────────────────────────────

#[cfg(feature = "intercept")]
mod http_evidence {
    use bee::findings::{fold, Ledger};
    use bee::intercept::control::{
        now_rfc3339, ExchangeRecord, Origin, OriginKind, Outcome, SendPath, Timing, TlsInfo,
    };
    use bee::intercept::store::{ExchangeBytes, Store};
    use bee::tools::Tool;
    use bee_core::policy::HttpLimits;
    use serde_json::json;

    fn rec() -> ExchangeRecord {
        ExchangeRecord {
            req_id: None,
            call_id: Some("c".into()),
            turn: Some(1),
            origin: Origin {
                kind: OriginKind::Tool,
                path: SendPath::Raw,
                parent: None,
                fuzz_run: None,
                rule_ids: vec![],
            },
            scheme: "http".into(),
            host: "app.test".into(),
            port: 80,
            method: Some("GET".into()),
            target: Some("/".into()),
            status: Some(200),
            tls: TlsInfo::None,
            timing: Timing {
                started: now_rfc3339(),
                ..Default::default()
            },
            req_bytes: 0,
            resp_bytes: 300,
            req_truncated: false,
            resp_truncated: false,
            has_original: false,
            outcome: Outcome::Completed,
            tags: vec![],
        }
    }

    fn body(b: u8) -> ExchangeBytes {
        ExchangeBytes {
            resp_head: b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
            resp_body: vec![b; 300],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn evidence_refs_are_validated_stored_and_resolved_on_review() {
        let project = tempfile::tempdir().unwrap();
        let limits = HttpLimits {
            store_cap_bytes: 1000,
            ..HttpLimits::default()
        };
        let mut store = Store::open(project.path(), "s", &limits).unwrap();
        let first = store.insert_exchange(&rec(), &body(b'a')).unwrap();

        let ledger = Ledger::at(project.path().join(".bee/findings"));
        let tool = bee::tools::finding::RecordFinding::new(ledger.clone(), "run");
        let sandbox = bee::sandbox::Sandbox::host(Vec::new());
        let args = |refs: serde_json::Value| json!({ "path": "app.test/", "class": "xss", "title": "reflected q", "evidence": "see the exchange", "evidence_refs": refs });

        // An unknown id is refused, and nothing is written.
        let r = tool.call(args(json!(["http:E0000-99"])), &sandbox).await;
        assert!(
            r.is_error && r.content.contains("E0000-99"),
            "{}",
            r.content
        );
        let r = tool.call(args(json!(["E-not-http"])), &sandbox).await;
        assert!(r.is_error, "{}", r.content);
        assert!(fold(&ledger).map(|v| v.findings.is_empty()).unwrap_or(true));

        // A real one is stored with the sighting.
        let r = tool
            .call(args(json!([format!("http:{first}")])), &sandbox)
            .await;
        assert!(!r.is_error, "{}", r.content);
        let view = fold(&ledger).unwrap();
        assert_eq!(
            view.findings[0].sightings[0].evidence_refs,
            vec![format!("http:{first}")]
        );

        let listed = bee::tools::finding::ListFindings::new(ledger.clone())
            .call(json!({}), &sandbox)
            .await;
        assert!(!listed.is_error, "{}", listed.content);
        assert!(
            listed
                .content
                .contains(&format!("HTTP evidence: http:{first}")),
            "{}",
            listed.content
        );
        assert!(!listed.content.contains("prose-only"), "{}", listed.content);

        let review = || {
            let out = std::process::Command::new(env!("CARGO_BIN_EXE_bee"))
                .args(["findings", "--dir"])
                .arg(project.path().join(".bee/findings"))
                .arg("list")
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).into_owned()
        };
        assert!(
            review().contains(&format!("evidence http:{first} — present")),
            "{}",
            review()
        );

        // Push the store over its cap: the first body is evicted, and review says so.
        for b in b'b'..=b'f' {
            store.insert_exchange(&rec(), &body(b)).unwrap();
        }
        assert!(
            review().contains(&format!("evidence http:{first} — missing")),
            "{}",
            review()
        );
    }
}
