//! The `scan` tool (016-native-tools US3): run a granted external scanner, in scope, fail-closed.
//!
//! ## The pipeline, and why the report is a file rather than a stream
//!
//! ```text
//!   ScannerGrant ──▶ preflight (optional)        what is this binary? verified before it is used
//!   (inode-pinned)   │
//!                    ▼
//!                    the scan: one child per step, argv built by the adapter, never by the model
//!                    │ Opengrep needs one step; CodeQL needs create-then-analyse
//!                    │ writes
//!                    ▼
//!                    <scan dir>/report.sarif     inside the scope
//!                    │
//!                    `bee sarif-worker` reads and normalises IN SCOPE, bounded
//!                    ▼
//!                    ToolOutcome<Vec<Finding>>
//! ```
//!
//! Every one of those is a child. The harness never runs a scanner, never reads a report, and never
//! asks a binary what version it is — all three would be the harness reaching around the sandbox it
//! is meant to be imposing (Constitution III).
//!
//! Forced by measurement (research R4): an Opengrep SARIF over one file is 1,912,546 bytes against a
//! 102,400-byte `DEFAULT_OUTPUT_CAP`. Capturing it on stdout truncates it into unparseable JSON,
//! which surfaces as "the scanner found nothing" — the failure FR-012 exists to prevent. Writing a
//! file solves that; normalising it in a *second child* rather than in the harness is what keeps the
//! promise that the harness never opens a file inside the sandbox (Constitution III).
//!
//! ## Success is decided by the report, never the exit status
//!
//! Measured: `opengrep scan --sarif --quiet` exits **0 with a finding present** — it only returns
//! non-zero on findings when `--error` is passed (research R6). An exit status conflates "findings
//! exist" with "run failed" and is wrong in both directions, so the ladder is: finished within
//! budget → report parses → `executionSuccessful` → only then a result.

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use serde_json::json;

use crate::findings::{record, Ledger, Sighting};
use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;
use crate::sarif::{ScanFinding, MAX_FINDINGS_PER_SCAN};
use crate::scanners::{self, ScanRequest, ScannerGrant};
use crate::tools::exec::{run_child_timed, ChildError};
use crate::tools::outcome::{
    audit_failure, audit_refusal, clean_scan, ToolOutcome, UnavailableReason,
};
use crate::tools::{Tool, ToolResult};

/// Where a scanner's report is written, relative to the working directory.
///
/// Project-local rather than `/tmp`: the file has to be writable by child 1 and readable by child 2
/// while both are inside the scope, and a scanning policy need not admit `/tmp` at all. Under
/// enforcement this path is covered by the same writable root the episode already has.
pub const SCAN_DIR: &str = ".bee/scan";

#[derive(Deserialize)]
struct Args {
    scanner: String,
    target: String,
    #[serde(default)]
    lang: Option<String>,
    /// Lets a caller shorten the budget. It cannot *lengthen* it past the operator's — the grant's
    /// timeout is a ceiling, not a default.
    #[serde(default)]
    timeout_secs: Option<u64>,
}

/// `{ scanner, target, lang?, timeout_secs? }` → normalised findings, merged into the ledger.
pub struct ScanTool {
    grants: Vec<ScannerGrant>,
    ledger: Ledger,
    run_id: String,
    /// The bee executable to exec for child 2. Resolved from `current_exe` in production; injectable
    /// so an integration test can point at the built binary rather than the test harness.
    bee_exe: Option<PathBuf>,
}

impl Default for ScanTool {
    /// **No grants.** A scan tool nobody configured refuses every call with `NotGranted`, so
    /// forgetting to wire the episode's grants fails closed (Constitution I).
    fn default() -> Self {
        ScanTool {
            grants: Vec::new(),
            ledger: Ledger::resolve(None),
            run_id: format!("run-{}", std::process::id()),
            bee_exe: None,
        }
    }
}

impl ScanTool {
    pub fn new(grants: Vec<ScannerGrant>, ledger: Ledger, run_id: impl Into<String>) -> Self {
        ScanTool {
            grants,
            ledger,
            run_id: run_id.into(),
            bee_exe: None,
        }
    }

    /// Point child 2 at a specific bee binary. Tests only.
    pub fn with_bee_exe(mut self, path: PathBuf) -> Self {
        self.bee_exe = Some(path);
        self
    }

    fn grant(&self, name: &str) -> Option<&ScannerGrant> {
        self.grants.iter().find(|g| g.name == name)
    }

    fn exe(&self) -> Result<String, String> {
        match &self.bee_exe {
            Some(p) => Ok(p.to_string_lossy().into_owned()),
            None => std::env::current_exe()
                .map(|p| p.to_string_lossy().into_owned())
                .map_err(|e| format!("cannot locate the bee executable: {e}")),
        }
    }
}

#[async_trait::async_trait]
impl Tool for ScanTool {
    fn name(&self) -> &'static str {
        "scan"
    }

    fn schema(&self) -> ToolSchema {
        let granted: Vec<String> = self.grants.iter().map(|g| g.name.clone()).collect();
        ToolSchema {
            name: "scan".to_string(),
            description: format!(
                "Run an external security scanner over a path and record what it finds. The \
                 scanner's rule corpus covers patterns bee does not implement itself, so this is \
                 the tool for broad coverage; `ast_grep` is the one for a specific structural \
                 question. Findings are merged into the project's finding ledger automatically. \
                 Scanners granted to this session: {}. A scanner that is not granted, not \
                 installed, or unable to run reports that explicitly — it never returns an empty \
                 result to mean failure.",
                if granted.is_empty() {
                    "(none — no scanner is granted, so every call will refuse)".to_string()
                } else {
                    granted.join(", ")
                }
            ),
            parameters: json!({
                "type": "object",
                "properties": {
                    "scanner": {
                        "type": "string",
                        "description": "Which scanner to run.",
                        "enum": granted,
                    },
                    "target": {
                        "type": "string",
                        "description": "Directory or file to scan."
                    },
                    "lang": {
                        "type": "string",
                        "description": "Language hint, where the scanner needs one."
                    },
                    "timeout_secs": {
                        "type": "integer",
                        "description": "Shorten the wall-clock budget for this scan. Cannot extend it beyond the configured limit."
                    }
                },
                "required": ["scanner", "target"]
            }),
        }
    }

    async fn call(&self, arguments: serde_json::Value, sandbox: &Sandbox) -> ToolResult {
        let args: Args = match serde_json::from_value(arguments) {
            Ok(a) => a,
            Err(e) => return ToolResult::invalid_args("scan", e),
        };

        // ── 1. Is this scanner granted, and does bee know how to drive it? ──────────────────────
        let Some(grant) = self.grant(&args.scanner) else {
            return unavailable(UnavailableReason::NotGranted {
                name: args.scanner.clone(),
            });
        };
        let Some(adapter) = scanners::adapter_for(&args.scanner) else {
            return unavailable(UnavailableReason::NotGranted {
                name: args.scanner.clone(),
            });
        };

        // ── 2. What is being asked, and within what budget? ─────────────────────────────────────
        let budget = match args.timeout_secs {
            // The operator's budget is a ceiling. A caller may ask for less, never for more.
            Some(secs) => Duration::from_secs(secs).min(grant.timeout),
            None => grant.timeout,
        };
        let req = ScanRequest {
            target: PathBuf::from(&args.target),
            lang: args.lang,
            timeout: budget,
        };
        // The budget is a ceiling on the *scan*, not an allowance each child draws afresh. A CodeQL
        // scan is a version check plus two children; handing each one the full budget would let a
        // scan run to three times the limit its operator set, which is not a limit. So the budget
        // becomes a deadline here, and every child gets what is left of it.
        let deadline = std::time::Instant::now() + budget;
        let remaining = || deadline.saturating_duration_since(std::time::Instant::now());

        // ── 3. Can this scanner answer this request at all? ─────────────────────────────────────
        // Before argv construction and before any spawn, so unavailability costs no process — and,
        // more importantly, so a swapped binary is never executed (FR-009, SC-010).
        if let Err(reason) = adapter.probe(grant, &req) {
            return unavailable(reason);
        }

        // Unique per *call*, not per run: two scans in one episode, or two episodes sharing a
        // project, would otherwise write the same path and each would read a file the other was
        // still writing — producing a mid-document parse failure that looks like a broken scanner.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let stem = format!(
            "{}-{}-{}-{}",
            args.scanner,
            self.run_id.replace(['/', ' ', '.'], "_"),
            std::process::id(),
            seq
        );
        let report_path = PathBuf::from(SCAN_DIR).join(format!("{stem}.sarif"));
        // Intermediate state an adapter needs mid-scan — a CodeQL database, for instance — lives
        // here and nowhere else, so it is bounded to the call and cleaned up with it.
        let scratch = PathBuf::from(SCAN_DIR).join(&stem);
        if let Err(e) = std::fs::create_dir_all(&scratch) {
            return failed(format!(
                "cannot create the scan directory {}: {e}",
                scratch.display()
            ));
        }
        // A stale report from an earlier call must never be mistaken for this call's output.
        let _ = std::fs::remove_file(&report_path);
        let cleanup = || {
            let _ = std::fs::remove_dir_all(&scratch);
        };

        let steps = match adapter.steps(grant, &req, &scratch, &report_path) {
            Ok(s) => s,
            Err(e) => {
                cleanup();
                return failed(e);
            }
        };

        let program = grant.path.to_string_lossy().into_owned();

        // ── 4. Preflight: ask the binary what it is, in scope, before trusting its answers ──────
        if let Some(argv) = adapter.preflight(grant) {
            let probe = match run_child_timed(sandbox, &program, &argv, remaining()).await {
                Ok(r) => r,
                Err(ChildError::TimedOut(_)) => {
                    cleanup();
                    // The budget, not the slice of it this child got: the operator set the former
                    // and would have to work backwards from the latter.
                    return failed(format!(
                        "{} timed out on a version check within its {}s scan budget",
                        args.scanner,
                        budget.as_secs()
                    ));
                }
                Err(ChildError::Spawn(e)) => {
                    cleanup();
                    return failed(e);
                }
            };
            // A check that did not run has not passed. Handing its empty stdout to the verifier
            // would let a crashing binary look like an unreadable version — the right refusal by
            // luck rather than by construction, so it is stated here instead.
            if !probe.success {
                cleanup();
                return failed(format!(
                    "{} could not report its version{}",
                    args.scanner,
                    stderr_tail(&probe.stderr)
                ));
            }
            if let Err(reason) = adapter.verify_preflight(grant, &probe.stdout) {
                cleanup();
                return unavailable(reason);
            }
        }

        // ── 5. The scan itself, one child per step, in order ────────────────────────────────────
        // Every step must succeed before the next runs: a database that failed to build cannot be
        // analysed, and analysing it anyway would produce an empty report — a clean scan by
        // accident, which is the one outcome this tool may never manufacture (FR-012).
        for (i, argv) in steps.iter().enumerate() {
            let run = match run_child_timed(sandbox, &program, argv, remaining()).await {
                Ok(r) => r,
                Err(ChildError::TimedOut(_)) => {
                    // No partial answer: whatever it wrote is by definition incomplete, and
                    // presenting an incomplete scan as a scan is the failure this feature is built
                    // against.
                    let _ = std::fs::remove_file(&report_path);
                    cleanup();
                    return failed(format!(
                        "{} timed out within its {}s scan budget; no partial findings are reported",
                        args.scanner,
                        budget.as_secs()
                    ));
                }
                Err(ChildError::Spawn(e)) => {
                    cleanup();
                    return failed(e);
                }
            };

            // A signal kill (`code == None`) is not an ordinary non-zero exit and is never a clean
            // scan.
            if run.code.is_none() {
                cleanup();
                return failed(format!(
                    "{} was killed by a signal{}",
                    args.scanner,
                    stderr_tail(&run.stderr)
                ));
            }
            // Intermediate steps are judged by their exit status because they have no report to be
            // judged by; the final step is judged by the report, below, because an exit status
            // conflates "findings exist" with "run failed" (research R6).
            if i + 1 < steps.len() && !run.success {
                cleanup();
                return failed(format!(
                    "{} step {} of {} exited {}{}",
                    args.scanner,
                    i + 1,
                    steps.len(),
                    run.code.unwrap_or(-1),
                    stderr_tail(&run.stderr)
                ));
            }
            if i + 1 == steps.len() && !report_path.exists() {
                cleanup();
                return failed(format!(
                    "{} exited {} without writing a report{}",
                    args.scanner,
                    run.code.unwrap_or(-1),
                    stderr_tail(&run.stderr)
                ));
            }
        }
        // The database, or whatever else the scan needed on the way, has served its purpose. The
        // report has not yet — child 2 still has to read it.
        cleanup();

        // ── 6. Child 2: normalise in scope ──────────────────────────────────────────────────────
        let exe = match self.exe() {
            Ok(e) => e,
            Err(e) => return failed(e),
        };
        let worker_argv = vec![
            "sarif-worker".to_string(),
            "--report".to_string(),
            report_path.to_string_lossy().into_owned(),
            "--source".to_string(),
            args.scanner.clone(),
            "--limit".to_string(),
            MAX_FINDINGS_PER_SCAN.to_string(),
        ];
        let normalised =
            match run_child_timed(sandbox, &exe, &worker_argv, Duration::from_secs(120)).await {
                Ok(r) => r,
                Err(ChildError::TimedOut(d)) => {
                    return failed(format!(
                        "normalising the report timed out after {}s",
                        d.as_secs()
                    ))
                }
                Err(ChildError::Spawn(e)) => return failed(e),
            };
        // The report has served its purpose; leaving it around would accumulate scan artefacts in
        // the project and leave attacker-influenced text on disk for no further benefit.
        let _ = std::fs::remove_file(&report_path);

        if !normalised.success {
            return failed(format!(
                "could not normalise {}'s report{}",
                args.scanner,
                stderr_tail(&normalised.stderr)
            ));
        }

        let (outcome, findings) = match parse_worker_output(&normalised.stdout) {
            Ok(pair) => pair,
            Err(e) => return failed(e),
        };

        // ── 7. Did the scan actually run? ───────────────────────────────────────────────────────
        if !outcome.execution_successful {
            return failed(format!(
                "{} reported that its run did not complete successfully; its results are not \
                 trustworthy and nothing was recorded",
                args.scanner
            ));
        }

        // ── 8. Merge into the ledger ────────────────────────────────────────────────────────────
        let mut recorded = 0usize;
        let mut rejected = Vec::new();
        for f in &findings {
            let finding = f.to_finding(&args.scanner);
            let sighting = Sighting {
                evidence_refs: Vec::new(),
                run_id: self.run_id.clone(),
                at: time::OffsetDateTime::now_utc(),
                line: f.line,
                end_line: f.end_line,
                rule_id: f.rule_id.clone(),
            };
            match record(&self.ledger, finding, sighting) {
                Ok(_) => recorded += 1,
                // One malformed finding does not sink the scan — but it is never silent either.
                Err(e) => rejected.push(e.to_string()),
            }
        }

        let body = render(&args.scanner, &findings, recorded, &rejected);
        // Scanner messages quote the scanned code: child output, framed as untrusted data (019 P1).
        ToolOutcome::completed_truncated(body, outcome.truncated)
            .into_tool_result(|b| b)
            .with_provenance(crate::tools::Provenance::Child)
    }
}

/// The worker's header line plus its findings.
struct WorkerOutcome {
    execution_successful: bool,
    truncated: bool,
}

/// Parse the JSONL the worker printed: one header object, then one finding per line.
fn parse_worker_output(stdout: &str) -> Result<(WorkerOutcome, Vec<ScanFinding>), String> {
    let mut lines = stdout.lines().filter(|l| !l.trim().is_empty());
    let header = lines
        .next()
        .ok_or_else(|| "the report normaliser produced no output".to_string())?;
    let header: serde_json::Value =
        serde_json::from_str(header).map_err(|e| format!("unreadable normaliser output: {e}"))?;

    let outcome = WorkerOutcome {
        // Absent means false: a header that does not say the run succeeded has not said it did.
        execution_successful: header["execution_successful"].as_bool().unwrap_or(false),
        truncated: header["truncated"].as_bool().unwrap_or(false),
    };

    let mut findings = Vec::new();
    for line in lines {
        match serde_json::from_str::<ScanFinding>(line) {
            Ok(f) => findings.push(f),
            Err(e) => return Err(format!("unreadable finding in normaliser output: {e}")),
        }
    }
    Ok((outcome, findings))
}

fn render(scanner: &str, findings: &[ScanFinding], recorded: usize, rejected: &[String]) -> String {
    if findings.is_empty() {
        let mut s = clean_scan(1, &format!("target with {scanner}"));
        if !rejected.is_empty() {
            s.push_str(&format!("\n{} record(s) rejected", rejected.len()));
        }
        return s;
    }

    let mut out = format!(
        "{scanner}: {} finding(s), {recorded} recorded in the ledger\n",
        findings.len()
    );
    for f in findings {
        let loc = match f.line {
            Some(line) => format!("{}:{line}", f.path),
            None => f.path.clone(),
        };
        out.push_str(&format!("{loc} [{}] {}\n", f.class, f.title));
    }
    for r in rejected {
        out.push_str(&format!("not recorded: {r}\n"));
    }
    out
}

/// The tail of a child's stderr, for a diagnostic. Bounded — a scanner that fails verbosely should
/// not push the reason for its failure out of the model's view.
fn stderr_tail(stderr: &str) -> String {
    let trimmed = stderr.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let tail: String = trimmed
        .chars()
        .rev()
        .take(400)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!(": {tail}")
}

fn unavailable(reason: UnavailableReason) -> ToolResult {
    audit_refusal("scan", &reason);
    ToolOutcome::<String>::unavailable(reason).into_tool_result(|b| b)
}

fn failed(reason: impl std::fmt::Display) -> ToolResult {
    let reason = reason.to_string();
    audit_failure("scan", &reason);
    ToolOutcome::<String>::failed(reason).into_tool_result(|b| b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_that_omits_success_is_not_read_as_successful() {
        let (outcome, findings) = parse_worker_output(r#"{"kind":"scan_outcome"}"#).unwrap();
        assert!(!outcome.execution_successful);
        assert!(findings.is_empty());
    }

    #[test]
    fn empty_normaliser_output_is_an_error_not_a_clean_scan() {
        assert!(parse_worker_output("").is_err());
        assert!(parse_worker_output("   \n").is_err());
    }

    #[test]
    fn a_damaged_finding_line_fails_rather_than_being_skipped() {
        // Skipping it would under-report a scan that ran, which reads as "less was found".
        let out = "{\"execution_successful\":true,\"truncated\":false}\n{not json}\n";
        assert!(parse_worker_output(out).is_err());
    }

    #[test]
    fn a_clean_scan_renders_with_the_shared_phrase() {
        let body = render("opengrep", &[], 0, &[]);
        assert!(body.contains(crate::tools::outcome::CLEAN_PREFIX));
    }

    #[test]
    fn an_ungranted_scanner_is_refused_before_anything_runs() {
        let tool = ScanTool::default();
        assert!(tool.grant("opengrep").is_none());
    }

    #[test]
    fn the_schema_advertises_only_granted_scanners() {
        let tmp = tempfile::tempdir().unwrap();
        let tool = ScanTool::new(
            vec![ScannerGrant::for_test(
                "opengrep",
                tmp.path().join("opengrep"),
                None,
            )],
            Ledger::at(tmp.path()),
            "run-1",
        );
        let schema = tool.schema();
        let enumerated = schema.parameters["properties"]["scanner"]["enum"]
            .as_array()
            .unwrap();
        assert_eq!(enumerated.len(), 1);
        assert_eq!(enumerated[0], "opengrep");
    }
}
