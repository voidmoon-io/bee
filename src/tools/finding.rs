//! The `record_finding` and `list_findings` tools (016-native-tools US2).
//!
//! These are the model's window onto [`crate::findings`]. Two properties shape their surface:
//!
//! **The model may state a finding, never a score.** `record_finding` takes a *vector* when the
//! caller wants severity attached, and the number is computed from it (FR-005). A record arriving
//! with a pre-populated score is refused rather than quietly recomputed — silently accepting it
//! would let a fabricated number pass review as a measured one.
//!
//! **Neither tool spawns a child.** They touch `.bee/findings/`, which is bee's own state, not
//! target source — the same category as the episode transcript. The sandboxed-child seam exists to
//! put *target* reads under the LSM, and there is no target read here to mediate.
//!
//! Both carry their run id and ledger location from construction, because [`Tool::call`] receives
//! only a [`Sandbox`] and neither is derivable from it. The default construction points at
//! `.bee/findings` under the working directory; a caller that knows the episode id replaces it.

use serde::Deserialize;
use serde_json::json;
use time::OffsetDateTime;

use crate::findings::{
    fold, record, Finding, FindingId, FindingSource, Ledger, LedgerError, Sighting, View,
};
use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;
use crate::tools::outcome::{audit_failure, ToolOutcome};
use crate::tools::{Tool, ToolResult};

/// The cap on findings one `list_findings` call returns.
const LIST_LIMIT: usize = 200;

/// A run identifier for a ledger written outside an episode (a REPL session, a direct CLI call).
/// The pid and the wall clock together are enough to tell two local runs apart in the log.
fn default_run_id() -> String {
    format!(
        "run-{}-{}",
        std::process::id(),
        OffsetDateTime::now_utc().unix_timestamp()
    )
}

/// `deny_unknown_fields` because the `severity_score` trap below only catches the spelling it
/// names. A caller who nests `severity = { score: … }` instead would otherwise have the whole object
/// dropped by serde — no score reaches the ledger, so FR-005 is not *violated*, but the caller is
/// silently ignored rather than told, which is the exact failure the trap exists to prevent. Every
/// unrecognised field is now a refusal, so there is no spelling of "here is my score" that bee
/// accepts quietly.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordArgs {
    path: String,
    class: String,
    title: String,
    evidence: String,
    #[serde(default)]
    line: Option<u32>,
    #[serde(default)]
    end_line: Option<u32>,
    #[serde(default)]
    rule_id: Option<String>,
    /// A CVSS vector to score. Deliberately a *vector*, not a score.
    #[serde(default)]
    severity_vector: Option<String>,
    /// Present only so a caller that supplies it gets an explicit refusal (FR-005) rather than
    /// having it silently ignored — which would leave them believing bee accepted their number.
    #[serde(default)]
    severity_score: Option<serde_json::Value>,
}

/// `{ path, class, title, evidence, line?, rule_id?, severity_vector? }` → a finding id.
#[derive(Clone)]
pub struct RecordFinding {
    ledger: Ledger,
    run_id: String,
}

impl RecordFinding {
    fn run(&self, arguments: serde_json::Value) -> ToolResult {
        let args: RecordArgs = match serde_json::from_value(arguments) {
            Ok(a) => a,
            Err(e) => return ToolResult::invalid_args("record_finding", e),
        };

        // FR-005, stated at the surface: refuse an asserted score rather than dropping it. A caller
        // whose number was silently discarded would go on believing the ledger holds it.
        if args.severity_score.is_some() {
            return failed(
                "record_finding",
                "a severity score may not be supplied: state `severity_vector` instead and the \
                 score is computed from it",
            );
        }

        let mut finding = Finding::new(
            args.path,
            args.class,
            args.title,
            args.evidence,
            FindingSource::Tool("model".to_string()),
        );
        finding.reidentify();

        let sighting = Sighting {
            run_id: self.run_id.clone(),
            at: OffsetDateTime::now_utc(),
            line: args.line,
            end_line: args.end_line,
            rule_id: args.rule_id,
        };

        let id = match record(&self.ledger, finding, sighting) {
            Ok(id) => id,
            Err(e) => return failed("record_finding", e),
        };

        let mut body = format!("recorded finding {id}");
        if let Some(vector) = args.severity_vector {
            body.push_str(&score_and_attach(&self.ledger, &id, &vector));
        }
        // Report the merge, because it is the thing the model cannot otherwise see: a second
        // sighting means an earlier run — or an earlier turn — already knew about this.
        if let Ok(view) = fold(&self.ledger) {
            if let Some(f) = view.get(&id) {
                if f.sightings.len() > 1 {
                    body.push_str(&format!(
                        "\nalready known: {} sightings, first seen in run {}",
                        f.sightings.len(),
                        f.sightings[0].run_id
                    ));
                }
                if let Some(v) = &f.verdict {
                    body.push_str(&format!(
                        "\na human already adjudicated this: {} (by {})",
                        v.state, v.by
                    ));
                }
            }
        }
        ToolOutcome::completed(body).into_tool_result(|b| b)
    }

    pub fn new(ledger: Ledger, run_id: impl Into<String>) -> Self {
        RecordFinding {
            ledger,
            run_id: run_id.into(),
        }
    }
}

impl Default for RecordFinding {
    fn default() -> Self {
        RecordFinding::new(Ledger::resolve(None), default_run_id())
    }
}

#[async_trait::async_trait]
impl Tool for RecordFinding {
    fn name(&self) -> &'static str {
        "record_finding"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "record_finding".to_string(),
            description: "Record a security finding in the project's durable finding ledger. Use \
                          this the moment a finding is established, not at the end of the session: \
                          the ledger survives the episode, merges with what earlier runs found, and \
                          preserves any human verdict already attached. Recording the same finding \
                          twice is safe — it appends a sighting rather than duplicating. Every \
                          field is required except the optional location and severity vector; a \
                          record without evidence is refused."
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Repo-relative path of the affected file."
                    },
                    "class": {
                        "type": "string",
                        "description": "Issue class slug, e.g. \"sql-injection\", \"path-traversal\"."
                    },
                    "title": {
                        "type": "string",
                        "description": "One-line statement of the defect."
                    },
                    "evidence": {
                        "type": "string",
                        "description": "What makes this real: the code, the reachable path, the reason it matters."
                    },
                    "line": { "type": "integer", "description": "1-indexed line, when the finding has one." },
                    "end_line": { "type": "integer", "description": "1-indexed end line, when the finding spans a range." },
                    "rule_id": { "type": "string", "description": "The rule identifier that fired, when one did." },
                    "severity_vector": {
                        "type": "string",
                        "description": "A CVSS vector (e.g. \"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\"). \
                                        State the vector only — the score is computed from it. Do NOT supply a score."
                    }
                },
                "required": ["path", "class", "title", "evidence"]
            }),
        }
    }

    async fn call(&self, arguments: serde_json::Value, _sandbox: &Sandbox) -> ToolResult {
        let owned = self.clone();
        match crate::findings::run_ledger_work(move || owned.run(arguments)).await {
            Ok(result) => result,
            Err(error) => failed("record_finding", error),
        }
    }
}

/// Score `vector` and append a `Scored` event — the only path that may write a severity (FR-005).
///
/// Returns the line to append to the tool's reply. A vector that does not parse is reported and the
/// finding stands without a severity: the record is already durable, and refusing the whole call
/// over an unscoreable vector would throw away the part that worked.
#[cfg(feature = "cvss")]
fn score_and_attach(ledger: &Ledger, id: &FindingId, vector: &str) -> String {
    use crate::findings::LedgerEvent;

    match crate::tools::cvss::score(vector) {
        Ok(scored) => {
            let severity = scored.into_severity();
            let line = format!("\nseverity {:.1} ({})", severity.score, severity.band);
            match ledger.append(&LedgerEvent::Scored {
                id: id.clone(),
                severity,
            }) {
                Ok(()) => {
                    crate::findings::refresh_view(ledger);
                    line
                }
                Err(e) => format!("\nseverity not attached: {e}"),
            }
        }
        Err(detail) => format!("\nseverity not attached: `{vector}` did not parse: {detail}"),
    }
}

#[cfg(not(feature = "cvss"))]
fn score_and_attach(_ledger: &Ledger, _id: &FindingId, _vector: &str) -> String {
    // Fail-closed at the level that matters here: say the severity is absent rather than let the
    // caller assume a vector they supplied was scored and stored.
    "\nseverity not attached: this build has no `cvss` feature".to_string()
}

#[derive(Deserialize)]
struct ListArgs {
    #[serde(default)]
    class: Option<String>,
    #[serde(default)]
    verdict: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

/// `{ class?, verdict?, path?, limit? }` → the folded ledger, filtered and bounded.
#[derive(Clone)]
pub struct ListFindings {
    ledger: Ledger,
}

impl ListFindings {
    fn run(&self, arguments: serde_json::Value) -> ToolResult {
        let args: ListArgs = match serde_json::from_value(arguments) {
            Ok(a) => a,
            Err(e) => return ToolResult::invalid_args("list_findings", e),
        };

        let view = match fold(&self.ledger) {
            Ok(v) => v,
            Err(e) => return failed("list_findings", e),
        };

        let limit = args.limit.unwrap_or(LIST_LIMIT).min(LIST_LIMIT);
        let matched: Vec<&Finding> = view
            .findings
            .iter()
            .filter(|f| args.class.as_ref().is_none_or(|c| &f.class == c))
            .filter(|f| {
                args.path
                    .as_ref()
                    .is_none_or(|p| f.path.starts_with(p.as_str()))
            })
            .filter(|f| match args.verdict.as_deref() {
                None => true,
                Some("none") => f.verdict.is_none(),
                Some(want) => f
                    .verdict
                    .as_ref()
                    .is_some_and(|v| v.state.to_string() == want),
            })
            .collect();

        let truncated = matched.len() > limit;
        let shown: Vec<&Finding> = matched.into_iter().take(limit).collect();
        let body = render_list(&shown, &view);
        ToolOutcome::completed_truncated(body, truncated).into_tool_result(|b| b)
    }

    pub fn new(ledger: Ledger) -> Self {
        ListFindings { ledger }
    }
}

impl Default for ListFindings {
    fn default() -> Self {
        ListFindings::new(Ledger::resolve(None))
    }
}

#[async_trait::async_trait]
impl Tool for ListFindings {
    fn name(&self) -> &'static str {
        "list_findings"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "list_findings".to_string(),
            description: format!(
                "List findings already recorded for this project, including ones from earlier \
                 sessions and any human verdicts attached to them. Check this BEFORE investigating \
                 an area: a finding already marked false-positive does not need rediscovering, and \
                 one already confirmed does not need re-arguing. Capped at {LIST_LIMIT}."
            ),
            parameters: json!({
                "type": "object",
                "properties": {
                    "class": { "type": "string", "description": "Only findings of this issue class." },
                    "verdict": {
                        "type": "string",
                        "description": "Only findings with this human verdict: confirmed, false-positive, fixed, deferred, or \"none\" for unadjudicated."
                    },
                    "path": { "type": "string", "description": "Only findings whose path starts with this prefix." },
                    "limit": { "type": "integer", "description": "Maximum findings to return." }
                }
            }),
        }
    }

    async fn call(&self, arguments: serde_json::Value, _sandbox: &Sandbox) -> ToolResult {
        let owned = self.clone();
        match crate::findings::run_ledger_work(move || owned.run(arguments)).await {
            Ok(result) => result,
            Err(error) => failed("list_findings", error),
        }
    }
}

/// Render the folded findings for the model. Raw text: the model sees the record as **data**
/// (FR-016), and the escaping that protects the *operator's terminal* happens at the front-end
/// (FR-015), not here — sanitizing on this path would corrupt the evidence the model reasons over.
fn render_list(findings: &[&Finding], view: &View) -> String {
    if findings.is_empty() {
        let mut s = crate::tools::outcome::clean_scan(view.findings.len(), "recorded findings");
        if view.skipped > 0 {
            s.push_str(&format!(
                " ({} ledger events unreadable by this build)",
                view.skipped
            ));
        }
        return s;
    }

    let mut out = String::new();
    for f in findings {
        let loc = match f.sightings.last().and_then(|s| s.line) {
            Some(line) => format!("{}:{line}", f.path),
            None => f.path.clone(),
        };
        out.push_str(&format!("{} [{}] {loc} — {}", f.id, f.class, f.title));
        if let Some(sev) = &f.severity {
            out.push_str(&format!(" · {:.1} {}", sev.score, sev.band));
        }
        if let Some(v) = &f.verdict {
            out.push_str(&format!(" · verdict: {}", v.state));
        }
        out.push_str(&format!(
            " · {} sighting(s) · {}",
            f.sightings.len(),
            f.source
        ));
        out.push('\n');
    }
    if view.skipped > 0 {
        out.push_str(&format!(
            "note: {} ledger events were unreadable by this build\n",
            view.skipped
        ));
    }
    out
}

/// A failed ledger operation, audited then rendered. Never a `Completed` with nothing in it.
fn failed(tool: &str, reason: impl std::fmt::Display) -> ToolResult {
    let reason = reason.to_string();
    audit_failure(tool, &reason);
    ToolOutcome::<String>::failed(reason).into_tool_result(|b| b)
}

/// Widen a [`LedgerError`] into the tool-facing text. Kept as a named conversion so every caller
/// renders a refusal the same way.
impl From<LedgerError> for ToolOutcome<FindingId> {
    fn from(e: LedgerError) -> Self {
        ToolOutcome::failed(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{FindingId, VerdictState};

    fn sandbox() -> Sandbox {
        Sandbox::host(Vec::new())
    }

    fn tmp_ledger(dir: &std::path::Path) -> Ledger {
        Ledger::at(dir.join("findings"))
    }

    #[tokio::test]
    async fn recording_the_same_finding_twice_reports_the_merge() {
        let tmp = tempfile::tempdir().unwrap();
        let tool = RecordFinding::new(tmp_ledger(tmp.path()), "run-1");
        let args = json!({
            "path": "src/db.rs",
            "class": "sql-injection",
            "title": "Query built by concatenation",
            "evidence": "format!(\"select … {}\", user)",
            "line": 42
        });

        let first = tool.call(args.clone(), &sandbox()).await;
        assert!(!first.is_error, "{}", first.content);
        assert!(first.content.contains("recorded finding"));
        assert!(!first.content.contains("already known"));

        let second = tool.call(args, &sandbox()).await;
        assert!(
            second.content.contains("already known"),
            "{}",
            second.content
        );
    }

    #[tokio::test]
    async fn a_supplied_score_is_refused_rather_than_recomputed() {
        let tmp = tempfile::tempdir().unwrap();
        let tool = RecordFinding::new(tmp_ledger(tmp.path()), "run-1");
        let result = tool
            .call(
                json!({
                    "path": "src/db.rs",
                    "class": "sql-injection",
                    "title": "t",
                    "evidence": "e",
                    "severity_score": 9.8
                }),
                &sandbox(),
            )
            .await;
        assert!(result.is_error);
        assert!(result
            .content
            .contains("severity score may not be supplied"));
        // And nothing was written: the refusal is total, not partial.
        assert!(!tmp_ledger(tmp.path()).log_path().exists());
    }

    /// The trap field catches one spelling. A caller who nests the score under a `severity` object
    /// used to have it dropped in silence — believing bee had taken their number when it had not.
    #[tokio::test]
    async fn a_score_nested_under_another_name_is_refused_too() {
        let tmp = tempfile::tempdir().unwrap();
        let tool = RecordFinding::new(tmp_ledger(tmp.path()), "run-1");
        let result = tool
            .call(
                json!({
                    "path": "src/db.rs",
                    "class": "sql-injection",
                    "title": "t",
                    "evidence": "e",
                    "severity": { "score": 9.8, "band": "critical" }
                }),
                &sandbox(),
            )
            .await;
        assert!(result.is_error, "{}", result.content);
        assert!(
            result.content.contains("severity"),
            "the refusal must name the field it did not understand: {}",
            result.content
        );
        assert!(!tmp_ledger(tmp.path()).log_path().exists());
    }

    #[tokio::test]
    async fn a_missing_field_is_refused_with_the_field_named() {
        let tmp = tempfile::tempdir().unwrap();
        let tool = RecordFinding::new(tmp_ledger(tmp.path()), "run-1");
        let result = tool
            .call(
                json!({"path": "src/db.rs", "class": "c", "title": "t", "evidence": "  "}),
                &sandbox(),
            )
            .await;
        assert!(result.is_error);
        assert!(result.content.contains("evidence"), "{}", result.content);
    }

    #[tokio::test]
    async fn an_empty_ledger_lists_as_a_clean_scan_not_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let tool = ListFindings::new(tmp_ledger(tmp.path()));
        let result = tool.call(json!({}), &sandbox()).await;
        assert!(!result.is_error);
        assert!(result.content.contains(crate::tools::outcome::CLEAN_PREFIX));
    }

    #[tokio::test]
    async fn listing_surfaces_the_human_verdict() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger = tmp_ledger(tmp.path());
        let rec = RecordFinding::new(ledger.clone(), "run-1");
        rec.call(
            json!({"path": "src/a.rs", "class": "sqli", "title": "t", "evidence": "e"}),
            &sandbox(),
        )
        .await;

        let id = FindingId::derive("src/a.rs", "sqli", "t");
        ledger
            .append(&crate::findings::LedgerEvent::Adjudicated {
                id,
                verdict: crate::findings::Verdict {
                    state: VerdictState::FalsePositive,
                    note: None,
                    by: "jg".into(),
                    at: OffsetDateTime::now_utc(),
                },
            })
            .unwrap();

        let list = ListFindings::new(ledger).call(json!({}), &sandbox()).await;
        assert!(list.content.contains("false-positive"), "{}", list.content);

        // …and filtering by it works, which is what makes the list usable once it is long.
        let filtered = ListFindings::new(tmp_ledger(tmp.path()))
            .call(json!({"verdict": "confirmed"}), &sandbox())
            .await;
        assert!(filtered
            .content
            .contains(crate::tools::outcome::CLEAN_PREFIX));
    }

    #[cfg(feature = "cvss")]
    #[tokio::test]
    async fn a_vector_is_scored_by_the_crate_and_stored() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger = tmp_ledger(tmp.path());
        let result = RecordFinding::new(ledger.clone(), "run-1")
            .call(
                json!({
                    "path": "src/a.rs", "class": "sqli", "title": "t", "evidence": "e",
                    "severity_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                }),
                &sandbox(),
            )
            .await;
        assert!(result.content.contains("9.8"), "{}", result.content);
        let view = fold(&ledger).unwrap();
        let sev = view.findings[0].severity.as_ref().expect("severity stored");
        assert!((sev.score - 9.8).abs() < 0.05);
    }

    #[cfg(feature = "cvss")]
    #[tokio::test]
    async fn an_unparseable_vector_leaves_the_finding_recorded_and_unscored() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger = tmp_ledger(tmp.path());
        let result = RecordFinding::new(ledger.clone(), "run-1")
            .call(
                json!({
                    "path": "src/a.rs", "class": "sqli", "title": "t", "evidence": "e",
                    "severity_vector": "CVSS:3.1/nonsense"
                }),
                &sandbox(),
            )
            .await;
        assert!(result.content.contains("recorded finding"));
        assert!(result.content.contains("severity not attached"));
        let view = fold(&ledger).unwrap();
        assert!(view.findings[0].severity.is_none(), "no guessed score");
    }
}
