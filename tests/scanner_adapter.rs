//! US3 — borrow someone else's rule corpus (016-native-tools).
//!
//! The external tier's whole risk profile is in the failure modes, not the happy path. A scanner
//! that is absent, ungranted, swapped, slow, or broken must each produce an outcome the operator can
//! act on, and **none of them may read like a clean scan** (FR-012, SC-002) — because a security
//! tool that reports "no issues" when it did not run is worse than one that was never installed.
//!
//! Run with `cargo test --test scanner_adapter --features scanners`. No external scanner is needed:
//! the pipeline is exercised with a stub binary, which is what makes these cases testable at all
//! (a real scanner cannot be made to fail its inode pin on demand).

#![cfg(feature = "scanners")]

use std::path::{Path, PathBuf};

use bee::sarif;
use bee::scanners::{self, ScanRequest, ScannerGrant};
use bee::security::{ScannerConfig, SecurityConfig};
use bee::tools::outcome::{UnavailableReason, CLEAN_PREFIX};
use bee::tools::scanner::ScanTool;
use bee::tools::Tool;

const FIXTURE: &str = include_str!("fixtures/sarif/opengrep-shell-true.json");

fn bee_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bee"))
}

fn sandbox() -> bee::Sandbox {
    bee::Sandbox::host(Vec::new())
}

/// A stub scanner: a shell script that writes `body` to the `--sarif-output=<path>` it was handed,
/// and records the argv it saw so a test can assert what bee built.
fn stub_scanner(dir: &Path, name: &str, body: &str, extra: &str) -> PathBuf {
    let path = dir.join(name);
    let report = dir.join("written.json");
    let argv_log = dir.join("argv.log");
    std::fs::write(
        &path,
        format!(
            r#"#!/bin/sh
printf '%s\n' "$@" > {argv}
{extra}
out=""
for a in "$@"; do
  case "$a" in
    --sarif-output=*) out="${{a#--sarif-output=}}" ;;
  esac
done
cat > "$out" <<'SARIF_EOF'
{body}
SARIF_EOF
cp "$out" {copy} 2>/dev/null || true
exit 0
"#,
            argv = argv_log.display(),
            copy = report.display(),
            extra = extra,
            body = body,
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    path
}

/// A policy granting `path` with the `!` inode pin — the shape `contracts/scanner-adapter.md`
/// documents.
fn policy_granting(path: &Path) -> bee_core::Policy {
    bee_core::Policy {
        name: "scan".to_string(),
        description: None,
        mode: bee_core::Mode::default(),
        filesystem: std::collections::BTreeMap::new(),
        exec: bee_core::ExecPolicy {
            allow: vec![format!("!{}", path.display())],
        },
        network: Default::default(),
        exfiltration: Default::default(),
        http: None,
    }
}

fn security_with_rules(rules: &Path) -> SecurityConfig {
    let mut cfg = SecurityConfig::default();
    cfg.scanners.insert(
        "opengrep".to_string(),
        ScannerConfig {
            rules: Some(rules.to_path_buf()),
            timeout_secs: Some(30),
            ..Default::default()
        },
    );
    cfg
}

/// The whole wiring: a granted stub scanner, a rules file, a ledger, and a target.
struct Fixture {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    grants: Vec<ScannerGrant>,
    ledger: bee::findings::Ledger,
    target: PathBuf,
}

fn fixture_with(body: &str, extra: &str) -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let bin = stub_scanner(&dir, "opengrep", body, extra);
    let rules = dir.join("rules.yml");
    std::fs::write(&rules, "rules: []\n").unwrap();
    let target = dir.join("src");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("vuln.py"), "import subprocess\n").unwrap();

    let grants =
        scanners::grants_from_policy(Some(&policy_granting(&bin)), &security_with_rules(&rules));
    Fixture {
        _tmp: tmp,
        dir: dir.clone(),
        grants,
        ledger: bee::findings::Ledger::at(dir.join("findings")),
        target,
    }
}

fn tool(f: &Fixture) -> ScanTool {
    ScanTool::new(f.grants.clone(), f.ledger.clone(), "run-1").with_bee_exe(bee_exe())
}

async fn scan(f: &Fixture) -> bee::ToolResult {
    tool(f)
        .call(
            serde_json::json!({"scanner": "opengrep", "target": f.target.to_str().unwrap()}),
            &sandbox(),
        )
        .await
}

// ── T036 · every fail-closed case is distinguishable from a clean scan ───────────────────────────

#[tokio::test]
async fn a_scanner_with_no_grant_refuses_rather_than_reporting_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    // The binary exists and is on disk — it is simply not granted. Presence confers nothing (FR-008).
    let bin = stub_scanner(tmp.path(), "opengrep", FIXTURE, "");
    assert!(bin.exists());

    let tool = ScanTool::new(Vec::new(), bee::findings::Ledger::at(tmp.path()), "run-1")
        .with_bee_exe(bee_exe());
    let r = tool
        .call(
            serde_json::json!({"scanner": "opengrep", "target": tmp.path().to_str().unwrap()}),
            &sandbox(),
        )
        .await;

    assert!(r.is_error, "an ungranted scanner must not succeed");
    assert!(r.content.contains("not granted"), "{}", r.content);
    assert!(!r.content.contains(CLEAN_PREFIX), "{}", r.content);
}

#[tokio::test]
async fn a_granted_but_absent_binary_reports_its_absence() {
    let f = fixture_with(FIXTURE, "");
    std::fs::remove_file(f.dir.join("opengrep")).unwrap();

    let r = scan(&f).await;
    assert!(r.is_error);
    assert!(r.content.contains("no binary at"), "{}", r.content);
    assert!(!r.content.contains(CLEAN_PREFIX));
}

#[tokio::test]
async fn a_binary_substituted_after_the_grant_is_never_executed() {
    // SC-010. The stub writes a sentinel when it runs; after substitution it must never run.
    let f = fixture_with(FIXTURE, "");
    let sentinel = f.dir.join("EXECUTED");
    let bin = f.dir.join("opengrep");

    // Swap via rename rather than remove-then-create: deleting and immediately recreating a file
    // often *reuses* the inode, which would leave the pin matching and quietly stop this test from
    // testing anything. A rename always installs a different inode at the path.
    let replacement = stub_scanner(
        &f.dir,
        "opengrep.new",
        FIXTURE,
        &format!("touch {}", sentinel.display()),
    );
    std::fs::rename(&replacement, &bin).unwrap();

    let r = scan(&f).await;
    assert!(r.is_error);
    assert!(r.content.contains("pinned identity"), "{}", r.content);
    assert!(
        !sentinel.exists(),
        "the substituted binary was executed — the pin re-check did not happen before spawn"
    );
    assert!(!r.content.contains(CLEAN_PREFIX));
}

#[tokio::test]
async fn an_unparseable_report_fails_rather_than_reading_as_empty() {
    let f = fixture_with("this is not json", "");
    let r = scan(&f).await;
    assert!(r.is_error);
    assert!(r.content.contains("failed:"), "{}", r.content);
    assert!(!r.content.contains(CLEAN_PREFIX), "{}", r.content);
}

#[tokio::test]
async fn a_scanner_that_writes_no_report_fails() {
    // Exits 0, produces nothing. Trusting the exit status would call this a clean scan.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let bin = dir.join("opengrep");
    std::fs::write(&bin, "#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let rules = dir.join("rules.yml");
    std::fs::write(&rules, "rules: []\n").unwrap();
    let grants =
        scanners::grants_from_policy(Some(&policy_granting(&bin)), &security_with_rules(&rules));

    let r = ScanTool::new(grants, bee::findings::Ledger::at(dir.join("f")), "run-1")
        .with_bee_exe(bee_exe())
        .call(
            serde_json::json!({"scanner": "opengrep", "target": dir.to_str().unwrap()}),
            &sandbox(),
        )
        .await;
    assert!(r.is_error, "{}", r.content);
    assert!(!r.content.contains(CLEAN_PREFIX), "{}", r.content);
}

#[tokio::test]
async fn a_scanner_that_exceeds_its_budget_fails_with_no_partial_findings() {
    let f = fixture_with(FIXTURE, "sleep 30");
    // One second is enough to prove the budget bites without making the suite slow.
    let r = tool(&f)
        .call(
            serde_json::json!({
                "scanner": "opengrep",
                "target": f.target.to_str().unwrap(),
                "timeout_secs": 1
            }),
            &sandbox(),
        )
        .await;
    assert!(r.is_error);
    assert!(r.content.contains("timed out"), "{}", r.content);
    assert!(!r.content.contains(CLEAN_PREFIX));
    // Nothing reached the ledger: a partial answer presented as whole is the same lie as an empty one.
    assert!(!f.ledger.log_path().exists());
}

#[test]
fn a_compiled_out_scanner_family_is_still_a_known_tool() {
    // The stub that refuses with `NotCompiledIn` can only be registered for a name the harness
    // knows, so the mapping is what keeps a slimmed build from silently dropping `scan`.
    assert!(bee::tools::is_known_tool("scan"));
    assert_eq!(bee::tools::sec_tool_family("scan"), Some("scanners"));
}

// ── T037 · `--config auto` is refused at argv construction, not at runtime ───────────────────────

#[test]
fn config_auto_is_refused_when_the_command_is_built() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("src");
    std::fs::create_dir_all(&target).unwrap();

    let grant =
        ScannerGrant::for_test("opengrep", tmp.path().join("opengrep"), Some("auto".into()));
    let adapter = scanners::adapter_for("opengrep").expect("opengrep adapter");
    let err = adapter
        .steps(
            &grant,
            &ScanRequest::new(target),
            tmp.path(),
            &tmp.path().join("out.sarif"),
        )
        .expect_err("`auto` must be refused");
    assert!(err.contains("auto"), "{err}");
    // The reason matters: a scanning scope has no egress, so `auto` could only fail opaquely.
    assert!(err.contains("network") || err.contains("egress"), "{err}");
}

#[test]
fn a_scanner_with_no_ruleset_configured_refuses_rather_than_defaulting_to_auto() {
    let tmp = tempfile::tempdir().unwrap();
    let grant = ScannerGrant::for_test("opengrep", tmp.path().join("opengrep"), None);
    let adapter = scanners::adapter_for("opengrep").unwrap();
    let err = adapter
        .steps(
            &grant,
            &ScanRequest::new(tmp.path().to_path_buf()),
            tmp.path(),
            &tmp.path().join("out.sarif"),
        )
        .expect_err("no rules ⇒ no scan");
    assert!(err.contains("rules"), "{err}");
}

#[test]
fn the_model_cannot_smuggle_a_flag_through_the_target() {
    let tmp = tempfile::tempdir().unwrap();
    let rules = tmp.path().join("rules.yml");
    std::fs::write(&rules, "rules: []\n").unwrap();
    let grant = ScannerGrant::for_test("opengrep", tmp.path().join("opengrep"), Some(rules));
    let adapter = scanners::adapter_for("opengrep").unwrap();

    for hostile in ["--config=auto", "-e", "--pro"] {
        let err = adapter
            .steps(
                &grant,
                &ScanRequest::new(PathBuf::from(hostile)),
                tmp.path(),
                &tmp.path().join("out.sarif"),
            )
            .expect_err("a target that is really a flag must be refused");
        assert!(!err.is_empty());
    }
}

// ── T038 · untrusted scanner text cannot drive the terminal ─────────────────────────────────────

#[test]
fn control_and_bidi_characters_in_a_report_render_inert() {
    // `message.text` and `snippet.text` are verbatim attacker-controlled source.
    let hostile = "\\u001b[2J\\u001b[1;1H PWNED \\u202egnp.txt";
    let report = format!(
        r#"{{"version":"2.1.0","runs":[{{"invocations":[{{"executionSuccessful":true}}],
        "results":[{{"ruleId":"r1","level":"error",
        "message":{{"text":"{hostile}"}},
        "locations":[{{"physicalLocation":{{"artifactLocation":{{"uri":"src/a.py"}},
        "region":{{"startLine":3,"snippet":{{"text":"{hostile}"}}}}}}}}]}}]}}]}}"#
    );

    let findings = sarif::normalise(&report, "opengrep", 200).expect("parses");
    let f = &findings.findings[0];
    // The finding holds the raw bytes — it is evidence, and mangling evidence at ingest would
    // corrupt the record the model reasons over.
    assert!(f.title.contains('\u{1b}'), "the ledger keeps the raw text");

    // The operator's terminal never sees them.
    let rendered = bee::safe_text::safe_line(&f.title);
    assert!(!rendered.contains('\u{1b}'), "{rendered:?}");
    assert!(!rendered.contains('\u{202e}'), "{rendered:?}");
    assert!(
        rendered.contains("PWNED"),
        "escaped, not dropped: {rendered}"
    );

    let evidence = bee::safe_text::safe_line(&f.evidence);
    assert!(!evidence.contains('\u{1b}'), "{evidence:?}");
}

// ── T039 · success comes from the report, never the exit code ────────────────────────────────────

#[tokio::test]
async fn exit_zero_with_findings_is_a_successful_scan() {
    // Measured (research R6): `opengrep scan --sarif --quiet` exits 0 *with* a finding present.
    let f = fixture_with(FIXTURE, "");
    let r = scan(&f).await;
    assert!(!r.is_error, "{}", r.content);
    assert!(r.content.contains("subprocess"), "{}", r.content);
    assert!(
        !r.content.contains(CLEAN_PREFIX),
        "a finding is not a clean scan"
    );
}

#[tokio::test]
async fn exit_zero_with_execution_unsuccessful_is_a_failure() {
    let body = r#"{"version":"2.1.0","runs":[{"invocations":[{"executionSuccessful":false}],"results":[]}]}"#;
    let f = fixture_with(body, "");
    let r = scan(&f).await;
    assert!(r.is_error, "{}", r.content);
    assert!(!r.content.contains(CLEAN_PREFIX), "{}", r.content);
}

#[tokio::test]
async fn a_genuinely_clean_scan_reads_as_clean() {
    // The other half of FR-012: "ran and found nothing" must be reportable as exactly that.
    let body = r#"{"version":"2.1.0","runs":[{"invocations":[{"executionSuccessful":true}],"results":[]}]}"#;
    let f = fixture_with(body, "");
    let r = scan(&f).await;
    assert!(!r.is_error, "{}", r.content);
    assert!(r.content.contains(CLEAN_PREFIX), "{}", r.content);
}

// ── T048 · normalised findings land in the ledger ────────────────────────────────────────────────

#[tokio::test]
async fn findings_are_merged_into_the_ledger_sourced_by_scanner() {
    let f = fixture_with(FIXTURE, "");
    let r = scan(&f).await;
    assert!(!r.is_error, "{}", r.content);

    let view = bee::findings::fold(&f.ledger).unwrap();
    assert_eq!(view.findings.len(), 1, "{view:#?}");
    let finding = &view.findings[0];
    assert_eq!(finding.source.to_string(), "scanner:opengrep");
    assert_eq!(finding.path, "vuln.py");
    assert_eq!(finding.sightings[0].line, Some(3));
    assert_eq!(
        finding.sightings[0].rule_id.as_deref(),
        Some("subprocess-shell-true")
    );
    // A scanner's own severity is advisory only — it never becomes a computed `Severity` (FR-005).
    assert!(finding.severity.is_none(), "no asserted severity");

    // Re-scanning merges rather than duplicating (the US2 property, through the US3 path).
    scan(&f).await;
    let view = bee::findings::fold(&f.ledger).unwrap();
    assert_eq!(view.findings.len(), 1);
    assert_eq!(view.findings[0].sightings.len(), 2);
}

// ── SC-006 · the exec surface a scanning episode opens ───────────────────────────────────────────

#[test]
fn a_grant_is_only_ever_an_inode_pinned_exec_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = stub_scanner(tmp.path(), "opengrep", FIXTURE, "");
    let rules = tmp.path().join("rules.yml");
    std::fs::write(&rules, "rules: []\n").unwrap();

    let policy = policy_granting(&bin);
    let grants = scanners::grants_from_policy(Some(&policy), &security_with_rules(&rules));
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].name, "opengrep");
    // The allowlist contains exactly what the operator wrote — the tool adds nothing to it.
    assert_eq!(policy.exec.allow.len(), 1);
    assert!(policy.exec.allow[0].starts_with('!'));
}

#[test]
fn the_compiled_exec_surface_is_bee_plus_the_granted_scanner_and_nothing_else() {
    // SC-006, asserted where it actually lands: the *compiled* allowlist the kernel is handed.
    // Everything above this reasons about policy text; this checks what the text lowers to, which
    // is the artefact that decides what a scanning episode may execute.
    let tmp = tempfile::tempdir().unwrap();
    let bin = stub_scanner(tmp.path(), "opengrep", FIXTURE, "");
    let bee = std::env::current_exe().expect("the test binary stands in for bee's own entry");

    let mut policy = policy_granting(&bin);
    policy.exec.allow.push(format!("!{}", bee.display()));

    let resolver = bee_userspace::SystemResolver::current();
    let compiled = policy.compile(&resolver).expect("the policy compiles");

    let paths: Vec<String> = compiled
        .exec
        .iter()
        .map(|e| String::from_utf8_lossy(&e.path).into_owned())
        .collect();
    assert_eq!(paths.len(), 2, "exactly two executables, got {paths:?}");
    assert!(paths.contains(&bin.display().to_string()), "{paths:?}");
    assert!(paths.contains(&bee.display().to_string()), "{paths:?}");
    // And both are pinned: a scanning episode that could run a *substituted* binary at either path
    // would satisfy the count above while failing the property it stands for.
    assert!(
        compiled.exec.iter().all(|e| e.pin_inode),
        "every entry must carry its inode pin"
    );
}

#[test]
fn an_unpinned_allow_entry_is_not_a_scanner_grant() {
    // An unpinned entry lets a swapped binary through, which is precisely what SC-010 forbids. bee
    // requires the pin for a *scanner* specifically, and says so rather than running unpinned.
    let tmp = tempfile::tempdir().unwrap();
    let bin = stub_scanner(tmp.path(), "opengrep", FIXTURE, "");
    let mut policy = policy_granting(&bin);
    policy.exec.allow = vec![bin.display().to_string()]; // no `!`

    let rules = tmp.path().join("rules.yml");
    std::fs::write(&rules, "rules: []\n").unwrap();
    let grants = scanners::grants_from_policy(Some(&policy), &security_with_rules(&rules));
    assert!(
        grants.is_empty(),
        "an unpinned entry must not grant a scanner"
    );
}

#[test]
fn no_policy_at_all_grants_no_scanner() {
    let grants = scanners::grants_from_policy(None, &SecurityConfig::default());
    assert!(grants.is_empty());
}

// ── The normaliser ───────────────────────────────────────────────────────────────────────────────

#[test]
fn the_measured_fixture_normalises_to_one_finding() {
    let out = sarif::normalise(FIXTURE, "opengrep", 200).expect("the real fixture parses");
    assert!(out.execution_successful);
    assert_eq!(out.findings.len(), 1);
    let f = &out.findings[0];
    assert_eq!(f.path, "vuln.py");
    assert!(f.title.contains("shell=True"));
    assert!(f.evidence.contains("subprocess.call"));
    assert_eq!(f.class, "subprocess-shell-true");
    // Opengrep puts severity on the rule, not the result. The normaliser reaches it through the
    // streaming id→level pass over the catalogue (T070) rather than materialising the catalogue.
    assert_eq!(f.advisory_level.as_deref(), Some("error"));
    assert!(!out.truncated);
}

#[test]
fn a_rule_level_reaches_the_ledger_without_becoming_a_severity() {
    // The whole point of populating `advisory_level`: it is carried, attributed, and still never a
    // score. FR-005 holds on the path that now has something to carry.
    let out = sarif::normalise(FIXTURE, "opengrep", 200).unwrap();
    let f = out.findings[0].to_finding("opengrep");
    assert_eq!(f.advisory_level.as_deref(), Some("error"));
    assert!(
        f.severity.is_none(),
        "a scanner's own level must never become a computed severity"
    );
}

#[test]
fn the_finding_set_is_bounded_before_rendering() {
    let results: Vec<String> = (0..50)
        .map(|i| {
            format!(
                r#"{{"ruleId":"r{i}","message":{{"text":"finding {i}"}},
                "locations":[{{"physicalLocation":{{"artifactLocation":{{"uri":"src/f{i}.py"}},
                "region":{{"startLine":1}}}}}}]}}"#
            )
        })
        .collect();
    let report = format!(
        r#"{{"runs":[{{"invocations":[{{"executionSuccessful":true}}],"results":[{}]}}]}}"#,
        results.join(",")
    );

    let out = sarif::normalise(&report, "opengrep", 10).unwrap();
    assert_eq!(out.findings.len(), 10);
    assert!(out.truncated, "the cap biting must be stated, not inferred");
}

#[test]
fn a_report_without_the_invocation_block_is_not_assumed_successful() {
    // Absence of evidence is not evidence of success (Constitution I).
    let report = r#"{"runs":[{"results":[]}]}"#;
    let out = sarif::normalise(report, "opengrep", 10).unwrap();
    assert!(
        !out.execution_successful,
        "a missing executionSuccessful must not read as true"
    );
}

#[test]
fn a_result_with_no_location_is_kept_rather_than_dropped() {
    // A whole-program finding has no line. Dropping it would lose a real result silently.
    let report = r#"{"runs":[{"invocations":[{"executionSuccessful":true}],
        "results":[{"ruleId":"r1","message":{"text":"global issue"}}]}]}"#;
    let out = sarif::normalise(report, "opengrep", 10).unwrap();
    assert_eq!(out.findings.len(), 1);
    assert_eq!(out.findings[0].path, "(whole program)");
}

#[test]
fn unavailable_reasons_all_render_distinguishably_from_a_clean_scan() {
    for reason in [
        UnavailableReason::NotGranted {
            name: "opengrep".into(),
        },
        UnavailableReason::BinaryMissing {
            path: "/x/opengrep".into(),
        },
        UnavailableReason::PinMismatch {
            path: "/x/opengrep".into(),
        },
        UnavailableReason::NotCompiledIn {
            family: "scanners".into(),
        },
    ] {
        let rendered = reason.to_string();
        assert!(!rendered.contains(CLEAN_PREFIX), "{rendered}");
    }
}
