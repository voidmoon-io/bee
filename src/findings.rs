//! The finding ledger (016-native-tools US2): an append-only event log, folded into a view.
//!
//! A security finding that lives only in an episode's transcript dies with the episode. The next run
//! rediscovers it, the operator re-reads it, and any judgement they formed about it — *this one is a
//! false positive, we sanitise upstream* — has to be formed again. That is the failure this module
//! exists to prevent, and its whole shape follows from two requirements that pull against each other:
//!
//! * **Re-runs must merge** (FR-018/019). Finding the same defect twice is one entry with two
//!   sightings, never two entries.
//! * **A human's verdict outranks a machine's rediscovery** (FR-020). An automated sighting can
//!   never clear an adjudication, no matter how many times it fires.
//!
//! A mutable `findings.json` satisfies neither safely: merging becomes read-modify-write, which
//! races, and a rediscovery that rewrites an entry can silently drop the verdict attached to it. So
//! the log is the source of truth and is only ever **appended** to; [`fold`] derives the current
//! state. Merging is then a property of the fold rather than of a write, and a verdict cannot be
//! overwritten because nothing is ever overwritten (contract `finding-ledger.md`).
//!
//! ## What is trusted here, and what is not
//!
//! `title` and `evidence` are attacker-reachable: they come from a model reading target source, or
//! verbatim out of a third-party scanner's report. They enter the ledger as **data**. Every front-end
//! runs them through [`crate::safe_text`] before display (FR-015), and nothing in this module
//! interprets them.
//!
//! ## Where this runs
//!
//! In the harness, not in a sandboxed child. That is deliberate and is not the seam
//! [`crate::search`]/[`crate::astgrep`] protect: those read *target* files, which must be mediated by
//! the LSM, whereas `.bee/findings/` is bee's own state — the same category as the episode
//! transcript, which the harness has always written directly.

use std::collections::HashMap;
use std::io::{BufRead, Read};

pub(crate) mod storage;
use std::path::{Path, PathBuf};
use storage::Storage;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

/// The largest serialised event, in bytes, before its newline.
///
/// Records are bounded before writing; a descriptor-held writer lock serializes appends.
pub const MAX_EVENT_BYTES: usize = 4000;

/// The ledger directory relative to the project root, when nothing overrides it.
pub const DEFAULT_LEDGER_DIR: &str = ".bee/findings";

// ── Identity ─────────────────────────────────────────────────────────────────────────────────────

/// A finding's stable identity: `sha256(path ␟ class ␟ title)`, first 16 bytes, hex.
///
/// **The line number is deliberately absent.** Code moves; a defect whose line shifted because
/// someone added an import above it is the same defect, and an identity that included the line would
/// mint a duplicate every time the file was edited. Lines are attributes of a [`Sighting`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FindingId(String);

impl FindingId {
    /// Derive an id from the three components identity is made of.
    pub fn derive(path: &str, class: &str, title: &str) -> Self {
        let mut h = Sha256::new();
        // U+001F (unit separator) between components rather than bare concatenation: without it
        // `("a/b", "c")` and `("a", "b/c")` hash alike, and two unrelated findings merge into one.
        h.update(normalise_path(path).as_bytes());
        h.update([0x1f]);
        h.update(class.trim().to_lowercase().as_bytes());
        h.update([0x1f]);
        h.update(normalise_title(title).as_bytes());
        let digest = h.finalize();
        FindingId(hex16(&digest[..16]))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// An id as written in the ledger or typed on the command line. Deliberately not validating the
    /// shape: an id that names nothing simply matches nothing when folded, and rejecting "malformed"
    /// ids here would only add a second, redundant way to be wrong.
    pub fn parse(s: &str) -> FindingId {
        FindingId(s.trim().to_string())
    }
}

impl std::fmt::Display for FindingId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn hex16(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Repo-relative, forward-slashed, `./`-stripped. Purely lexical — no filesystem access, because
/// this runs over a path the model or a scanner supplied and resolving it would be a read.
pub fn normalise_path(path: &str) -> String {
    let p = path.trim().replace('\\', "/");
    let p = p.strip_prefix("./").unwrap_or(&p);
    p.trim_matches('/').to_string()
}

/// Lowercase, whitespace-collapsed, trailing-period-stripped.
///
/// Two producers describing one defect rarely phrase it identically — `"Query built by string
/// concatenation"` and `"query built  by string concatenation."` are the same finding, and a strict
/// comparison would file them separately and make the ledger noisier every time a scanner reworded a
/// message.
pub fn normalise_title(title: &str) -> String {
    let collapsed = title.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed.trim_end_matches('.').trim().to_lowercase()
}

// ── Entities (data-model.md) ─────────────────────────────────────────────────────────────────────

/// Who produced a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "name", rename_all = "snake_case")]
pub enum FindingSource {
    /// A native bee tool, by name (`ast_grep`, `git_log`, …), or `model` for a hand-recorded one.
    Tool(String),
    /// An external scanner, by adapter name. Renders as `scanner:<name>`.
    Scanner(String),
}

impl std::fmt::Display for FindingSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingSource::Tool(n) => write!(f, "{n}"),
            FindingSource::Scanner(n) => write!(f, "scanner:{n}"),
        }
    }
}

/// The qualitative band a score falls in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeverityBand {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityBand {
    /// The CVSS v3.1/v4.0 qualitative ranges. Used to map a computed score onto a band, and to parse
    /// the `cvss` crate's own textual severity back into this enum.
    pub fn from_score(score: f64) -> SeverityBand {
        match score {
            s if s <= 0.0 => SeverityBand::None,
            s if s < 4.0 => SeverityBand::Low,
            s if s < 7.0 => SeverityBand::Medium,
            s if s < 9.0 => SeverityBand::High,
            _ => SeverityBand::Critical,
        }
    }
}

impl std::fmt::Display for SeverityBand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SeverityBand::None => "none",
            SeverityBand::Low => "low",
            SeverityBand::Medium => "medium",
            SeverityBand::High => "high",
            SeverityBand::Critical => "critical",
        };
        f.write_str(s)
    }
}

/// A computed severity. **`score` and `band` are only ever written by the scoring path** (FR-005) —
/// a caller-supplied score is rejected rather than recomputed, so the violation stays visible.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Severity {
    /// The model's structured judgement — the part it is good at.
    pub vector: String,
    /// Computed by the `cvss` crate from `vector`. Never asserted.
    pub score: f64,
    pub band: SeverityBand,
}

/// One observation of a finding at one moment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sighting {
    pub run_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    /// 1-indexed. `None` for a whole-file or whole-program finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    /// The producing tool's own rule identifier, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// Recorded exchanges this sighting cites as evidence, `http:<exchange-id>` (019 US8, FR-027) —
    /// at most [`MAX_EVIDENCE_REFS`]. Ids only, so the event stays within [`MAX_EVENT_BYTES`]; review
    /// resolves each against the exchange store, and one evicted since reads as `missing`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
}

/// Most evidence references one sighting may carry.
pub const MAX_EVIDENCE_REFS: usize = 16;

impl Sighting {
    /// A sighting of `run_id`, now.
    pub fn now(run_id: impl Into<String>) -> Sighting {
        Sighting {
            evidence_refs: Vec::new(),
            run_id: run_id.into(),
            at: OffsetDateTime::now_utc(),
            line: None,
            end_line: None,
            rule_id: None,
        }
    }
}

/// Human adjudication state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum VerdictState {
    Confirmed,
    FalsePositive,
    Fixed,
    Duplicate { of: FindingId },
    Deferred,
}

impl VerdictState {
    /// Parse the CLI spelling (`false-positive`, `duplicate:<id>`, …).
    pub fn parse(s: &str) -> Result<VerdictState, String> {
        let s = s.trim();
        if let Some(of) = s.strip_prefix("duplicate:") {
            if of.is_empty() {
                return Err("duplicate:<id> needs the id it duplicates".to_string());
            }
            return Ok(VerdictState::Duplicate {
                of: FindingId(of.to_string()),
            });
        }
        match s {
            "confirmed" => Ok(VerdictState::Confirmed),
            "false-positive" => Ok(VerdictState::FalsePositive),
            "fixed" => Ok(VerdictState::Fixed),
            "deferred" => Ok(VerdictState::Deferred),
            other => Err(format!(
                "unknown verdict `{other}` (expected confirmed | false-positive | fixed | \
                 deferred | duplicate:<id>)"
            )),
        }
    }
}

impl std::fmt::Display for VerdictState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerdictState::Confirmed => f.write_str("confirmed"),
            VerdictState::FalsePositive => f.write_str("false-positive"),
            VerdictState::Fixed => f.write_str("fixed"),
            VerdictState::Duplicate { of } => write!(f, "duplicate:{of}"),
            VerdictState::Deferred => f.write_str("deferred"),
        }
    }
}

/// A human's judgement about a finding. An *event*, never a mutable field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    #[serde(flatten)]
    pub state: VerdictState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub by: String,
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
}

/// A reviewable observation about the code — the unit of work for this whole feature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: FindingId,
    /// Repo-relative and normalised.
    pub path: String,
    /// What kind of issue: `sql-injection`, `path-traversal`, …
    pub class: String,
    /// One-line statement of the defect. **Untrusted.**
    pub title: String,
    /// What makes it real. **Untrusted.**
    pub evidence: String,
    /// Harness-issued receipts. These establish provenance, not verification or impact.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
    pub source: FindingSource,
    /// Computed only, never asserted (FR-005).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    /// A producing scanner's own `level`, kept verbatim as advisory context. Deliberately separate
    /// from `severity`: it is what someone else's rule asserted, not what bee computed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advisory_level: Option<String>,
    /// Every time this finding has been seen, oldest first. Empty on the wire (the event carries the
    /// sighting beside the record); never empty in a folded view.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sightings: Vec<Sighting>,
    /// Human adjudication. Survives automated re-discovery (FR-020).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
}

impl Finding {
    /// A finding with its identity derived from `path`/`class`/`title`.
    pub fn new(
        path: String,
        class: String,
        title: String,
        evidence: String,
        source: FindingSource,
    ) -> Finding {
        Finding {
            id: FindingId::derive(&path, &class, &title),
            path: normalise_path(&path),
            class,
            title,
            evidence,
            evidence_refs: Vec::new(),
            source,
            severity: None,
            advisory_level: None,
            sightings: Vec::new(),
            verdict: None,
        }
    }

    /// Re-derive the identity after a field that feeds it was changed.
    pub fn reidentify(&mut self) {
        self.id = FindingId::derive(&self.path, &self.class, &self.title);
    }
}

// ── Events ───────────────────────────────────────────────────────────────────────────────────────

/// One line of the ledger.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum LedgerEvent {
    /// A finding was observed.
    ///
    /// The contract describes `finding` as present only on first sight. bee always populates it, and
    /// the fold ignores it for an id already seen. Deciding "am I the first?" would mean reading the
    /// log before writing — a read-modify-write cycle, which is exactly what the append-only design
    /// exists to avoid, and which two concurrent first-sights would both lose. Carrying the record
    /// every time costs bytes and buys a writer that never has to consult the log.
    Observed {
        id: FindingId,
        run_id: String,
        #[serde(with = "time::serde::rfc3339")]
        at: OffsetDateTime,
        sighting: Sighting,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        finding: Option<Box<Finding>>,
    },
    /// A human adjudicated. Only a later `Adjudicated` supersedes an earlier one.
    Adjudicated { id: FindingId, verdict: Verdict },
    /// A severity vector was scored. Written only by the scoring path (FR-005).
    Scored { id: FindingId, severity: Severity },
}

impl LedgerEvent {
    pub fn id(&self) -> &FindingId {
        match self {
            LedgerEvent::Observed { id, .. }
            | LedgerEvent::Adjudicated { id, .. }
            | LedgerEvent::Scored { id, .. } => id,
        }
    }
}

// ── Errors ───────────────────────────────────────────────────────────────────────────────────────

/// Why a ledger operation could not be performed. Every variant is a refusal — none of them is ever
/// rendered as a completed write.
#[derive(Debug)]
pub enum LedgerError {
    /// A required field was empty or malformed. Names the field (FR-021).
    Invalid { field: &'static str, detail: String },
    /// The event does not fit in `MAX_EVENT_BYTES` even after bounding `evidence`.
    TooLarge { bytes: usize },
    /// The ledger directory or file could not be written.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LedgerError::Invalid { field, detail } => {
                write!(
                    f,
                    "finding rejected: `{field}` {detail}; nothing was written"
                )
            }
            LedgerError::TooLarge { bytes } => write!(
                f,
                "finding rejected: the record is {bytes} bytes, over the {MAX_EVENT_BYTES}-byte \
                 event limit even after bounding the evidence; nothing was written"
            ),
            LedgerError::Io { path, source } => {
                write!(f, "ledger at {} is not writable: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for LedgerError {}

// ── The ledger ───────────────────────────────────────────────────────────────────────────────────

/// A ledger directory: `ledger.jsonl` (the truth) beside `view.json` (a cache).
#[derive(Debug, Clone)]
pub struct Ledger {
    dir: PathBuf,
}

impl Ledger {
    /// A ledger rooted at `dir`.
    pub fn at(dir: impl Into<PathBuf>) -> Ledger {
        Ledger { dir: dir.into() }
    }

    /// The ledger for the current project: `<cwd>/.bee/findings`, or `override_dir` when the
    /// operator configured one.
    ///
    /// The override exists for the case where the analysed project is read-only (research open
    /// question 2): the ledger is bee's own record, not a target artefact, so it must be able to
    /// live somewhere else rather than force the project writable. When neither location can be
    /// written, recording **fails** — a finding that could not be persisted is never reported as
    /// recorded.
    pub fn resolve(override_dir: Option<&Path>) -> Ledger {
        match override_dir {
            Some(d) => Ledger::at(d),
            None => Ledger::at(PathBuf::from(DEFAULT_LEDGER_DIR)),
        }
    }

    /// The project directory whose `.bee/` holds this ledger — where the exchange store lives too
    /// (019 US8). For a ledger outside any `.bee/`, the working directory.
    pub fn project_root(&self) -> PathBuf {
        let d = self.dir();
        match d.parent() {
            Some(p) if p.file_name().is_some_and(|n| n == ".bee") => p
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from(".")),
            _ => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn log_path(&self) -> PathBuf {
        self.dir.join("ledger.jsonl")
    }

    pub fn view_path(&self) -> PathBuf {
        self.dir.join("view.json")
    }

    fn io_error(&self, source: std::io::Error) -> LedgerError {
        LedgerError::Io {
            path: self.dir.clone(),
            source,
        }
    }

    fn storage(&self) -> Result<Storage, LedgerError> {
        Storage::open(&self.dir).map_err(|e| self.io_error(e))
    }

    pub fn ensure_dir(&self) -> Result<(), LedgerError> {
        self.storage().map(|_| ())
    }

    /// Append a bounded event while holding the cross-process writer lock.
    pub fn append(&self, event: &LedgerEvent) -> Result<(), LedgerError> {
        let line = bounded_line(event)?;
        self.storage()?.append(&line).map_err(|e| self.io_error(e))
    }

    /// Read bounded records; unknown or malformed complete lines count as skipped events.
    fn visit(
        &self,
        storage: &Storage,
        mut visit: impl FnMut(LedgerEvent),
    ) -> Result<usize, LedgerError> {
        let Some(file) = storage.reader().map_err(|e| self.io_error(e))? else {
            return Ok(0);
        };
        let mut reader = std::io::BufReader::new(file);
        let mut skipped = 0;
        loop {
            let mut line = Vec::new();
            let n = reader
                .by_ref()
                .take((MAX_EVENT_BYTES + 1) as u64)
                .read_until(b'\n', &mut line)
                .map_err(|e| self.io_error(e))?;
            if n == 0 {
                break;
            }
            if line.last() != Some(&b'\n') {
                // Drain oversized records in fixed chunks rather than growing the line buffer.
                while !line.ends_with(b"\n") {
                    line.clear();
                    if reader
                        .by_ref()
                        .take((MAX_EVENT_BYTES + 1) as u64)
                        .read_until(b'\n', &mut line)
                        .map_err(|e| self.io_error(e))?
                        == 0
                    {
                        break;
                    }
                }
                skipped += 1;
                continue;
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            match serde_json::from_slice(&line) {
                Ok(event) if n <= MAX_EVENT_BYTES => visit(event),
                _ => skipped += 1,
            }
        }
        Ok(skipped)
    }

    pub fn events(&self) -> Result<(Vec<LedgerEvent>, usize), LedgerError> {
        let storage = self.storage()?;
        let mut events = Vec::new();
        let skipped = self.visit(&storage, |event| events.push(event))?;
        Ok((events, skipped))
    }

    fn publish(&self, storage: &Storage, view: &View) -> Result<(), LedgerError> {
        let json = serde_json::to_vec_pretty(view).map_err(|e| LedgerError::Invalid {
            field: "view",
            detail: e.to_string(),
        })?;
        storage.publish(&json).map_err(|e| self.io_error(e))
    }

    /// Publish a derived cache through an exclusively created temporary.
    pub fn materialise(&self, view: &View) -> Result<(), LedgerError> {
        self.publish(&self.storage()?, view)
    }
}

/// Serialise `event`, bounding `evidence` until the line fits.
fn bounded_line(event: &LedgerEvent) -> Result<String, LedgerError> {
    const MARKER: &str = "…[evidence truncated]";

    let mut event = event.clone();
    let mut line = serde_json::to_string(&event).map_err(|e| LedgerError::Invalid {
        field: "finding",
        detail: format!("could not be serialised: {e}"),
    })?;

    if line.len() < MAX_EVENT_BYTES {
        line.push('\n');
        return Ok(line);
    }

    // Evidence is the only unbounded field, and the only one safe to shorten: `path`, `class`, and
    // `title` all feed the identity, so trimming one of those would change what the finding *is*.
    if let LedgerEvent::Observed {
        finding: Some(f), ..
    } = &mut event
    {
        let overflow = line.len() - MAX_EVENT_BYTES + MARKER.len() + 8;
        let keep = f.evidence.len().saturating_sub(overflow);
        let mut cut = keep.min(f.evidence.len());
        while cut > 0 && !f.evidence.is_char_boundary(cut) {
            cut -= 1;
        }
        f.evidence.truncate(cut);
        f.evidence.push_str(MARKER);
        line = serde_json::to_string(&event).map_err(|e| LedgerError::Invalid {
            field: "finding",
            detail: format!("could not be serialised: {e}"),
        })?;
    }

    if line.len() >= MAX_EVENT_BYTES {
        // Everything left is identity-bearing. Refusing is the honest answer: a silently mangled
        // title would produce a finding that never merges with itself again.
        return Err(LedgerError::TooLarge { bytes: line.len() });
    }
    line.push('\n');
    Ok(line)
}

// ── Validation (FR-021) ──────────────────────────────────────────────────────────────────────────

/// Check a finding carries the evidence that makes it reviewable. A record failing this is refused
/// with the field named, and **nothing is written** — a partially-written finding is worse than none.
pub fn validate(finding: &Finding) -> Result<(), LedgerError> {
    if finding.path.trim().is_empty() {
        return Err(LedgerError::Invalid {
            field: "path",
            detail: "is empty; a finding must say where it is".to_string(),
        });
    }
    if finding.path.starts_with('/') {
        return Err(LedgerError::Invalid {
            field: "path",
            detail: "is absolute; findings are recorded scope-relative".to_string(),
        });
    }
    if finding.path.split('/').any(|c| c == "..") {
        return Err(LedgerError::Invalid {
            field: "path",
            detail: "escapes the scope with `..`".to_string(),
        });
    }
    if finding.class.trim().is_empty() {
        return Err(LedgerError::Invalid {
            field: "class",
            detail: "is empty; a finding must say what kind of issue it is".to_string(),
        });
    }
    if finding.title.trim().is_empty() {
        return Err(LedgerError::Invalid {
            field: "title",
            detail: "is empty; a finding must state the defect".to_string(),
        });
    }
    if finding.evidence.trim().is_empty() {
        return Err(LedgerError::Invalid {
            field: "evidence",
            detail: "is empty; a finding without evidence is not reviewable".to_string(),
        });
    }
    if finding.severity.is_some() {
        // Belt and braces with the tool-level check (FR-005): a severity may only ever arrive
        // through `Scored`, so a record carrying one is refused here too.
        return Err(LedgerError::Invalid {
            field: "severity",
            detail: "may not be supplied with a record; score it with the `cvss` tool".to_string(),
        });
    }
    Ok(())
}

/// Validate `finding`, then append an `Observed` event carrying it and `sighting`.
///
/// Returns the finding's identity — the same value for a re-discovery, which is what makes the merge
/// visible to the caller.
pub fn record(
    ledger: &Ledger,
    finding: Finding,
    sighting: Sighting,
) -> Result<FindingId, LedgerError> {
    record_batch(ledger, vec![(finding, sighting)])?
        .pop()
        .expect("one input has one result")
}

fn observed_line(
    mut finding: Finding,
    sighting: Sighting,
) -> Result<(FindingId, String), LedgerError> {
    finding.path = normalise_path(&finding.path);
    finding.reidentify();
    validate(&finding)?;
    let id = finding.id.clone();
    finding.sightings.clear();
    let line = bounded_line(&LedgerEvent::Observed {
        id: id.clone(),
        run_id: sighting.run_id.clone(),
        at: sighting.at,
        sighting,
        finding: Some(Box::new(finding)),
    })?;
    Ok((id, line))
}

/// One locked append/fold/publication transaction. Per-record errors identify partial persistence;
/// already appended events stay authoritative if a later record or cache refresh fails.
pub fn record_batch(
    ledger: &Ledger,
    records: Vec<(Finding, Sighting)>,
) -> Result<Vec<Result<FindingId, LedgerError>>, LedgerError> {
    if records.len() > 200 {
        return Err(LedgerError::Invalid {
            field: "batch",
            detail: "at most 200 findings per batch".into(),
        });
    }
    let lines: Vec<_> = records
        .into_iter()
        .map(|(f, s)| observed_line(f, s))
        .collect();
    if lines.iter().all(Result::is_err) {
        return Ok(lines.into_iter().map(|r| r.map(|(id, _)| id)).collect());
    }
    let storage = ledger.storage()?;
    let mut appended = false;
    let results = lines
        .into_iter()
        .map(|line| {
            let (id, line) = line?;
            storage.append(&line).map_err(|e| ledger.io_error(e))?;
            appended = true;
            Ok(id)
        })
        .collect();
    if appended {
        report_cache_error(
            fold_locked(ledger, &storage).and_then(|view| ledger.publish(&storage, &view)),
        );
    }
    Ok(results)
}

/// Only one blocking batch runs at a time. The blocking task owns its data and admission permit
/// until it finishes, even if its async waiter is canceled; Tokio waits for it at runtime shutdown.
pub async fn record_batch_async(
    ledger: Ledger,
    records: Vec<(Finding, Sighting)>,
) -> Result<Vec<Result<FindingId, LedgerError>>, LedgerError> {
    run_ledger_work(move || record_batch(&ledger, records)).await?
}

pub(crate) async fn run_ledger_work<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, LedgerError> {
    static WRITER: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
    let permit = WRITER.acquire().await.map_err(|e| LedgerError::Invalid {
        field: "ledger",
        detail: e.to_string(),
    })?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    .map_err(|e| LedgerError::Invalid {
        field: "ledger",
        detail: e.to_string(),
    })
}

/// Re-fold and re-materialise the view, reporting failure without propagating it. The log has
/// already been written by the time this runs, so the finding *is* recorded; failing the caller here
/// would tell them otherwise.
pub fn refresh_view(ledger: &Ledger) {
    let result = (|| {
        let storage = ledger.storage()?;
        let view = fold_locked(ledger, &storage)?;
        ledger.publish(&storage, &view)
    })();
    report_cache_error(result);
}

fn report_cache_error(result: Result<(), LedgerError>) {
    if let Err(e) = result {
        eprintln!(
            "{}",
            serde_json::json!({"event": "ledger_view_stale", "detail": e.to_string()})
        );
    }
}

// ── The view ─────────────────────────────────────────────────────────────────────────────────────

/// The folded current state of a ledger. Regenerable from the log; never hand-edited.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct View {
    /// In first-observation order, which keeps the file's diff stable as the log grows.
    pub findings: Vec<Finding>,
    /// Events this build could not read. Surfaced rather than hidden: a non-zero count means the
    /// view is a partial picture of the log, and the operator should know which way it is partial.
    #[serde(default)]
    pub skipped: usize,
}

impl View {
    pub fn get(&self, id: &FindingId) -> Option<&Finding> {
        self.findings.iter().find(|f| &f.id == id)
    }
}

/// Fold the log into the current state.
///
/// Pure and total: unreadable events are counted and skipped, and no event is ever partially
/// applied. The four rules (contract `finding-ledger.md`):
///
/// | Event | Effect |
/// |---|---|
/// | `Observed`, id unseen | insert the record with its first sighting |
/// | `Observed`, id known | append the sighting; **never** overwrite `title`/`evidence`/`path` |
/// | `Adjudicated` | set the verdict; a later event replaces an earlier one |
/// | `Scored` | set the severity |
pub fn fold(ledger: &Ledger) -> Result<View, LedgerError> {
    fold_locked(ledger, &ledger.storage()?)
}

fn fold_locked(ledger: &Ledger, storage: &Storage) -> Result<View, LedgerError> {
    let mut skipped = 0;
    let mut order: Vec<FindingId> = Vec::new();
    let mut by_id: HashMap<FindingId, Finding> = HashMap::new();

    let unreadable = ledger.visit(storage, |event| {
        match event {
            LedgerEvent::Observed {
                id,
                sighting,
                finding,
                ..
            } => match by_id.get_mut(&id) {
                Some(existing) => {
                    if let Some(finding) = finding {
                        for reference in finding.evidence_refs {
                            if !existing.evidence_refs.contains(&reference) {
                                existing.evidence_refs.push(reference);
                            }
                        }
                    }
                    // The record is deliberately *not* re-applied. The first sight is the canonical
                    // description; letting a later one rewrite it would be the overwrite this whole
                    // structure exists to prevent, and would give a scanner a way to reword a
                    // finding a human had already read and judged.
                    existing.sightings.push(sighting);
                }
                None => match finding {
                    Some(f) => {
                        let mut f = *f;
                        f.id = id.clone();
                        f.sightings = vec![sighting];
                        order.push(id.clone());
                        by_id.insert(id, f);
                    }
                    // A bare sighting for an id never introduced. There is no record to attach it
                    // to, and inventing one would fabricate a finding.
                    None => skipped += 1,
                },
            },
            LedgerEvent::Adjudicated { id, verdict } => match by_id.get_mut(&id) {
                Some(f) => f.verdict = Some(verdict),
                None => skipped += 1,
            },
            LedgerEvent::Scored { id, severity } => match by_id.get_mut(&id) {
                Some(f) => f.severity = Some(severity),
                None => skipped += 1,
            },
        }
    })?;
    skipped += unreadable;

    let findings = order
        .into_iter()
        .filter_map(|id| by_id.remove(&id))
        .collect();
    Ok(View { findings, skipped })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(path: &str, class: &str, title: &str) -> Finding {
        Finding::new(
            path.into(),
            class.into(),
            title.into(),
            "evidence".into(),
            FindingSource::Tool("test".into()),
        )
    }

    #[test]
    fn identity_ignores_the_line_but_not_the_substance() {
        // Line is not an input at all, so it cannot affect the id.
        let a = FindingId::derive("src/a.rs", "sqli", "Concatenated query");
        let b = FindingId::derive("./src/a.rs", "sqli", "concatenated  query.");
        assert_eq!(a, b, "cosmetic differences must not fork identity");

        let c = FindingId::derive("src/b.rs", "sqli", "Concatenated query");
        assert_ne!(a, c, "a different file is a different finding");
    }

    #[test]
    fn evidence_is_bounded_before_the_line_is_written() {
        let mut finding = f("src/a.rs", "class", "title");
        finding.evidence = "x".repeat(MAX_EVENT_BYTES * 2);
        let event = LedgerEvent::Observed {
            id: finding.id.clone(),
            run_id: "r".into(),
            at: OffsetDateTime::UNIX_EPOCH,
            sighting: Sighting::now("r"),
            finding: Some(Box::new(finding)),
        };
        let line = bounded_line(&event).expect("bounding should make it fit");
        assert!(
            line.len() <= MAX_EVENT_BYTES,
            "line is {} bytes, over the record byte budget",
            line.len()
        );
        assert!(line.ends_with('\n'));
        assert!(line.contains("evidence truncated"), "the cut is marked");
    }

    #[test]
    fn an_unbounded_title_is_refused_rather_than_mangled() {
        // Trimming a title would change the identity, so the only honest answer is refusal.
        let mut finding = f("src/a.rs", "class", "t");
        finding.title = "t".repeat(MAX_EVENT_BYTES * 2);
        finding.reidentify();
        let event = LedgerEvent::Observed {
            id: finding.id.clone(),
            run_id: "r".into(),
            at: OffsetDateTime::UNIX_EPOCH,
            sighting: Sighting::now("r"),
            finding: Some(Box::new(finding)),
        };
        assert!(matches!(
            bounded_line(&event),
            Err(LedgerError::TooLarge { .. })
        ));
    }

    #[test]
    fn validation_names_the_field_it_refused() {
        let mut bad = f("src/a.rs", "class", "title");
        bad.evidence = "  ".into();
        let err = validate(&bad).unwrap_err().to_string();
        assert!(err.contains("evidence"), "{err}");
    }

    #[test]
    fn a_caller_supplied_severity_is_refused() {
        let mut bad = f("src/a.rs", "class", "title");
        bad.severity = Some(Severity {
            vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".into(),
            score: 1.0,
            band: SeverityBand::Low,
        });
        let err = validate(&bad).unwrap_err().to_string();
        assert!(err.contains("severity"), "{err}");
    }

    #[test]
    fn bands_follow_the_cvss_ranges() {
        assert_eq!(SeverityBand::from_score(0.0), SeverityBand::None);
        assert_eq!(SeverityBand::from_score(3.9), SeverityBand::Low);
        assert_eq!(SeverityBand::from_score(6.9), SeverityBand::Medium);
        assert_eq!(SeverityBand::from_score(8.9), SeverityBand::High);
        assert_eq!(SeverityBand::from_score(9.8), SeverityBand::Critical);
    }

    #[test]
    fn verdict_states_round_trip_through_their_cli_spelling() {
        for s in ["confirmed", "false-positive", "fixed", "deferred"] {
            assert_eq!(VerdictState::parse(s).unwrap().to_string(), s);
        }
        assert!(matches!(
            VerdictState::parse("duplicate:abc").unwrap(),
            VerdictState::Duplicate { .. }
        ));
        assert!(VerdictState::parse("benign").is_err());
    }
}
