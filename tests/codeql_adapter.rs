//! US6 — deep whole-program analysis (016-native-tools).
//!
//! CodeQL is the one adapter whose *availability* is a real question. Opengrep either runs or is
//! absent; a CodeQL bundle can be present, correctly pinned, and still be the wrong answer, because
//! the language asked for can only be extracted by watching a build. So these cases are about the
//! two refusals US6 turns on — a bundle that is not what was pinned (scenario 2), and a language bee
//! declines on purpose (scenario 3) — and about the thing both refusals share: **nothing runs**.
//!
//! Run with `cargo test --test codeql_adapter --features scanners`. No CodeQL bundle is needed. A
//! stub stands in for the CLI, which is what makes these testable at all: a real bundle cannot be
//! asked to report the wrong version on demand, and half of what is asserted here is that a
//! particular child was *never spawned*.
//!
//! What a stub cannot prove is that CodeQL, handed these arguments, produces useful results. That is
//! a walkthrough against a provisioned bundle, not a unit test — what is proven here is bee's half:
//! the argv it authors, the order it runs, and every path on which it refuses.

#![cfg(feature = "scanners")]

use std::path::{Path, PathBuf};

use bee::scanners::{self, ScannerGrant};
use bee::security::{ScannerConfig, SecurityConfig};
use bee::tools::outcome::{CLEAN_PREFIX, UNAVAILABLE_PREFIX};
use bee::tools::scanner::ScanTool;
use bee::tools::Tool;

const FIXTURE: &str = include_str!("fixtures/sarif/opengrep-shell-true.json");

/// The pin `codeql-action` v4.37.3 carries in `src/defaults.json`.
const PINNED: &str = "codeql-bundle-v2.26.1";
const PINNED_CLI: &str = "2.26.1";

fn bee_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bee"))
}

fn sandbox() -> bee::Sandbox {
    bee::Sandbox::host(Vec::new())
}

/// A stub CodeQL CLI: answers `version`, creates a database directory, and writes a SARIF report
/// from `database analyze`. Every invocation is appended to `argv.log`, so a test can assert both
/// what bee built and — more often — that bee built nothing at all.
fn stub_codeql(dir: &Path, reported_version: &str) -> PathBuf {
    stub_codeql_taking(dir, reported_version, 0)
}

/// The same stub, but every invocation takes `secs` first. A CodeQL scan is three children, so this
/// is what makes the difference between a budget that bounds the *scan* and one each child draws
/// afresh observable at all.
fn stub_codeql_taking(dir: &Path, reported_version: &str, secs: u32) -> PathBuf {
    let path = dir.join("codeql");
    let log = dir.join("argv.log");
    let version_json = format!(r#"{{"version":"{reported_version}"}}"#);
    let delay = if secs > 0 {
        format!("sleep {secs}\n")
    } else {
        String::new()
    };
    std::fs::write(
        &path,
        format!(
            r#"#!/bin/sh
printf '%s\n' "$@" >> {log}
printf -- '--- end of invocation\n' >> {log}
{delay}

if [ "$1" = "version" ]; then
  printf '%s\n' '{version}'
  exit 0
fi

if [ "$1" = "database" ] && [ "$2" = "create" ]; then
  mkdir -p "$3"
  exit 0
fi

if [ "$1" = "database" ] && [ "$2" = "analyze" ]; then
  out=""
  for a in "$@"; do
    case "$a" in
      --output=*) out="${{a#--output=}}" ;;
    esac
  done
  cat > "$out" <<'SARIF_EOF'
{body}
SARIF_EOF
  exit 0
fi

exit 1
"#,
            log = log.display(),
            version = version_json,
            delay = delay,
            body = FIXTURE,
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
        defaults: Default::default(),
        exfiltration: Default::default(),
    }
}

struct Fixture {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    grants: Vec<ScannerGrant>,
    ledger: bee::findings::Ledger,
    target: PathBuf,
}

/// `reported_version` is what the stub CLI claims to be; `pinned` is what the operator configured;
/// `bundle` is the optional bundle root. Every case below is a combination of those three.
fn fixture(reported_version: &str, pinned: Option<&str>, bundle: Option<PathBuf>) -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let bin = stub_codeql(&dir, reported_version);
    let target = dir.join("src");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("vuln.py"), "import subprocess\n").unwrap();

    let mut security = SecurityConfig::default();
    security.scanners.insert(
        "codeql".to_string(),
        ScannerConfig {
            bundle,
            bundle_version: pinned.map(str::to_string),
            timeout_secs: Some(30),
            ..Default::default()
        },
    );

    let grants = scanners::grants_from_policy(Some(&policy_granting(&bin)), &security);
    assert_eq!(
        grants.len(),
        1,
        "the pinned codeql entry must become a grant"
    );
    Fixture {
        _tmp: tmp,
        dir: dir.clone(),
        grants,
        ledger: bee::findings::Ledger::at(dir.join("findings")),
        target,
    }
}

/// The ordinary case: a correctly pinned bundle.
fn pinned_fixture() -> Fixture {
    fixture(PINNED_CLI, Some(PINNED), None)
}

/// A correctly pinned bundle whose every child takes `secs`, under a `budget`-second ceiling.
fn slow_fixture(secs: u32, budget: u64) -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let bin = stub_codeql_taking(&dir, PINNED_CLI, secs);
    let target = dir.join("src");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("vuln.py"), "import subprocess\n").unwrap();

    let mut security = SecurityConfig::default();
    security.scanners.insert(
        "codeql".to_string(),
        ScannerConfig {
            bundle: None,
            bundle_version: Some(PINNED.to_string()),
            timeout_secs: Some(budget),
            ..Default::default()
        },
    );
    let grants = scanners::grants_from_policy(Some(&policy_granting(&bin)), &security);
    Fixture {
        _tmp: tmp,
        dir: dir.clone(),
        grants,
        ledger: bee::findings::Ledger::at(dir.join("findings")),
        target,
    }
}

async fn scan_lang(f: &Fixture, lang: &str) -> bee::ToolResult {
    ScanTool::new(f.grants.clone(), f.ledger.clone(), "run-1")
        .with_bee_exe(bee_exe())
        .call(
            serde_json::json!({
                "scanner": "codeql",
                "target": f.target.to_str().unwrap(),
                "lang": lang,
            }),
            &sandbox(),
        )
        .await
}

/// Everything the stub was asked to do, one invocation per entry.
fn invocations(f: &Fixture) -> Vec<Vec<String>> {
    let log = f.dir.join("argv.log");
    if !log.exists() {
        return Vec::new();
    }
    let text = std::fs::read_to_string(log).unwrap();
    text.split("--- end of invocation\n")
        .filter(|chunk| !chunk.trim().is_empty())
        .map(|chunk| chunk.lines().map(str::to_string).collect())
        .collect()
}

// ── US6 scenario 2 · a bundle that is not the pinned bundle ──────────────────────────────────────

#[tokio::test]
async fn a_version_mismatch_names_both_versions_and_analyses_nothing() {
    let f = fixture("2.20.0", Some(PINNED), None);
    let r = scan_lang(&f, "python").await;

    assert!(r.is_error, "a mismatched bundle must not succeed");
    assert!(r.content.contains(PINNED), "{}", r.content);
    assert!(r.content.contains("2.20.0"), "{}", r.content);
    assert!(!r.content.contains(CLEAN_PREFIX), "{}", r.content);

    // The load-bearing half: the version check ran, and then nothing else did. A mismatch that
    // still analysed would be reporting results from a bundle nobody authorised.
    let calls = invocations(&f);
    assert_eq!(
        calls.len(),
        1,
        "only the version check may have run: {calls:?}"
    );
    assert_eq!(calls[0][0], "version");
}

#[tokio::test]
async fn a_bundle_that_is_not_there_is_refused_before_the_cli_is_run_at_all() {
    let f = fixture(
        PINNED_CLI,
        Some(PINNED),
        Some(PathBuf::from("/nonexistent/codeql-bundle")),
    );
    let r = scan_lang(&f, "python").await;

    assert!(r.is_error);
    // Scenario 2 asks for the expected version by name, so an operator can compare it with what
    // they provisioned without going to read bee's source.
    assert!(r.content.contains(PINNED), "{}", r.content);
    assert!(!r.content.contains(CLEAN_PREFIX), "{}", r.content);
    assert!(
        invocations(&f).is_empty(),
        "an absent bundle is answerable without spawning anything"
    );
}

#[tokio::test]
async fn a_cli_that_cannot_say_what_it_is_does_not_get_the_benefit_of_the_doubt() {
    // Not a mismatch and not a crash — a version check that answers with something unreadable. The
    // pin is unverified either way, so the scan does not proceed.
    let f = fixture("not-json-at-all\", oops", Some(PINNED), None);
    let r = scan_lang(&f, "python").await;

    assert!(r.is_error, "{}", r.content);
    assert!(!r.content.contains(CLEAN_PREFIX), "{}", r.content);
    let calls = invocations(&f);
    assert_eq!(
        calls.len(),
        1,
        "nothing may run after an unverified pin: {calls:?}"
    );
}

#[tokio::test]
async fn an_unpinned_bundle_yields_no_scan_and_says_which_setting_is_missing() {
    let f = fixture(PINNED_CLI, None, None);
    let r = scan_lang(&f, "python").await;

    assert!(r.is_error);
    assert!(r.content.contains("bundle_version"), "{}", r.content);
    assert!(!r.content.contains(CLEAN_PREFIX), "{}", r.content);
    // "could not run", not "ran and broke". Nothing executed — the invocation log below says so —
    // and the two states carry different audit slugs, so an operator grepping for setup problems
    // must not have to look among the crashes to find this one.
    assert!(
        r.content.starts_with(UNAVAILABLE_PREFIX),
        "an unpinned bundle is a refusal to run, not a failed run: {}",
        r.content
    );
    assert!(
        invocations(&f).is_empty(),
        "with nothing to verify against, there is nothing to run"
    );
}

/// The operator's `timeout_secs` bounds the **scan**, not each child of it.
///
/// A CodeQL scan is three children — version, create, analyze. Given the budget afresh, each of
/// them fits inside it comfortably and the scan runs to three times the ceiling while every
/// individual child looks well-behaved. That is not a ceiling; it is a ceiling per child, which is
/// a different and much weaker promise than the one `timeout_secs` makes.
#[tokio::test]
async fn the_budget_bounds_the_whole_scan_not_each_child_of_it() {
    // Two seconds a child, three children, a three-second ceiling: comfortably within budget
    // per-child, comfortably over it in total.
    let f = slow_fixture(2, 3);
    let started = std::time::Instant::now();
    let r = scan_lang(&f, "python").await;
    let elapsed = started.elapsed();

    assert!(r.is_error, "the scan outran its budget: {}", r.content);
    assert!(!r.content.contains(CLEAN_PREFIX), "{}", r.content);
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "the scan took {elapsed:?} under a 3s budget — the budget is being handed to each child \
         afresh rather than bounding the scan"
    );
    // And nothing partial was kept: the report a half-finished scan leaves behind is not a result.
    assert!(!f.ledger.log_path().exists());
}

// ── US6 scenario 3 · a language that can only be analysed by watching a build ────────────────────

#[tokio::test]
async fn a_traced_language_is_declined_explicitly_rather_than_half_analysed() {
    for lang in ["cpp", "c++", "go", "swift", "rust"] {
        let f = pinned_fixture();
        let r = scan_lang(&f, lang).await;

        assert!(r.is_error, "{lang} must be declined");
        // "Declined", not "found nothing" — the distinction the whole feature exists to keep.
        assert!(!r.content.contains(CLEAN_PREFIX), "{lang}: {}", r.content);
        assert!(r.content.contains("build"), "{lang}: {}", r.content);
        // And it says what *can* be analysed, so the refusal is actionable.
        assert!(r.content.contains("python"), "{lang}: {}", r.content);
        assert!(
            invocations(&f).is_empty(),
            "{lang}: a declined language must not start a database"
        );
    }
}

#[tokio::test]
async fn typescript_is_analysed_because_the_javascript_extractor_handles_it() {
    // CodeQL's own alias table maps it (`src/languages/builtin.json`). Declining TypeScript because
    // bee's list happens to spell it `javascript` would be a refusal with no reason behind it.
    let f = pinned_fixture();
    let r = scan_lang(&f, "TypeScript").await;
    assert!(!r.is_error, "{}", r.content);

    let calls = invocations(&f);
    let create = calls
        .iter()
        .find(|c| c.get(1).map(String::as_str) == Some("create"));
    let create = create.expect("a database should have been created");
    assert!(
        create.contains(&"--language=javascript".to_string()),
        "{create:?}"
    );
}

// ── US6 scenario 1 · the analysis bee actually drives ────────────────────────────────────────────

#[tokio::test]
async fn a_buildless_language_is_created_then_analysed_and_lands_in_the_ledger() {
    let f = pinned_fixture();
    let r = scan_lang(&f, "python").await;
    assert!(!r.is_error, "{}", r.content);

    let calls = invocations(&f);
    assert_eq!(
        calls.len(),
        3,
        "version, create, analyze — in that order: {calls:?}"
    );
    assert_eq!(calls[0][0], "version");
    assert_eq!(
        calls[1][0..2],
        ["database".to_string(), "create".to_string()]
    );
    assert_eq!(
        calls[2][0..2],
        ["database".to_string(), "analyze".to_string()]
    );

    assert!(
        calls[1].contains(&"--build-mode=none".to_string()),
        "{:?}",
        calls[1]
    );
    assert!(
        calls[1].contains(&"--language=python".to_string()),
        "{:?}",
        calls[1]
    );
    assert!(
        calls[2].contains(&"--format=sarif-latest".to_string()),
        "{:?}",
        calls[2]
    );
    assert_eq!(calls[2].last().unwrap(), "codeql/python-queries");

    // Both database commands name the same database, or the second analysed nothing.
    assert_eq!(calls[1][2], calls[2][2]);

    // The finding reached the ledger under CodeQL's name, which is what makes the tier worth having.
    let view = bee::findings::fold(&f.ledger).unwrap();
    assert_eq!(view.findings.len(), 1, "{view:#?}");
    assert_eq!(view.findings[0].source.to_string(), "scanner:codeql");
}

#[tokio::test]
async fn bee_never_asks_codeql_to_observe_a_build() {
    // SC-006 at the argv level. Tracing is the one thing that would force the scope open, and there
    // is no request — no language, no flag combination — that makes bee write it.
    let f = pinned_fixture();
    assert!(!scan_lang(&f, "python").await.is_error);

    for call in invocations(&f) {
        for arg in &call {
            assert!(
                !arg.contains("trace") && !arg.contains("autobuild"),
                "argv must never ask for tracing: {arg}"
            );
        }
    }
}

#[tokio::test]
async fn the_database_does_not_outlive_the_call() {
    // A CodeQL database is large and is built from the code under analysis. Leaving it behind would
    // accumulate copies of the target in the project for no further benefit.
    let f = pinned_fixture();
    assert!(!scan_lang(&f, "python").await.is_error);

    let calls = invocations(&f);
    let db = calls
        .iter()
        .find(|c| c.get(1).map(String::as_str) == Some("create"))
        .map(|c| PathBuf::from(&c[2]))
        .expect("a database should have been created");
    assert!(
        !db.exists(),
        "the scratch database {} should have been removed",
        db.display()
    );
}

// ── The grant itself ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_ungranted_codeql_refuses_however_much_of_it_is_installed() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = stub_codeql(tmp.path(), PINNED_CLI);
    assert!(bin.exists());

    let r = ScanTool::new(Vec::new(), bee::findings::Ledger::at(tmp.path()), "run-1")
        .with_bee_exe(bee_exe())
        .call(
            serde_json::json!({
                "scanner": "codeql",
                "target": tmp.path().to_str().unwrap(),
                "lang": "python",
            }),
            &sandbox(),
        )
        .await;

    assert!(r.is_error);
    assert!(r.content.contains("not granted"), "{}", r.content);
    assert!(!r.content.contains(CLEAN_PREFIX), "{}", r.content);
}
