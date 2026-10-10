//! The fail-closed result type every 016 security tool returns (contract `tool-outcome.md`).
//!
//! This is the constitution's Principle I made structural rather than a matter of discipline, and it
//! is the direct descendant of `a32e156` — *a hook that cannot evaluate an operation refuses it* —
//! applied one layer up, at the tool surface.
//!
//! The invariant it exists to hold:
//!
//! > [`ToolOutcome::Completed`] with an empty payload means **ran and found nothing** — a real,
//! > trustworthy, negative result. It is unreachable from any error path.
//!
//! A security harness whose missing scanner reports "no issues" is worse than one with no scanner at
//! all, because the operator reads the silence as assurance. So every way a tool can fail to produce
//! an answer lands in [`ToolOutcome::Unavailable`] (it could not run) or [`ToolOutcome::Failed`] (it
//! ran and broke), and the renderings of those two share no phrasing with a clean result.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::tools::ToolResult;

/// The phrase a clean scan renders with. Kept as a constant so the test that asserts no failure
/// rendering contains it cannot drift away from the thing it guards.
pub const CLEAN_PREFIX: &str = "no findings";
/// The phrase every "could not run" renders with.
pub const UNAVAILABLE_PREFIX: &str = "did not run:";
/// The phrase every "ran and broke" renders with.
pub const FAILED_PREFIX: &str = "failed:";

/// The `expected` an adapter reports when the operator pinned no version at all.
///
/// A missing pin is a *kind* of bundle mismatch — there is no version the bundle is allowed to be —
/// so it travels as [`UnavailableReason::BundleMismatch`] rather than a variant of its own
/// (contract `scanner-adapter.md`: "mismatch, unreadable, or unpinned ⇒ `BundleMismatch`"). It reads
/// nothing like a version, so it cannot be confused with one, and [`UnavailableReason`]'s `Display`
/// gives it the sentence an operator can act on.
pub const UNPINNED: &str = "(unpinned)";

/// The outcome of one security-tool invocation. `T` is the tool's success payload — `Vec<Finding>`,
/// `Vec<Match>`, `Severity`, and so on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ToolOutcome<T> {
    /// The tool ran to completion. An empty `value` is a genuine negative result.
    ///
    /// `truncated` means *the result set was bounded before rendering* — distinct from
    /// [`ToolResult::truncated`], which means the transport capped the rendered string. Both can be
    /// true at once; the rendering distinguishes them.
    Completed { value: T, truncated: bool },
    /// The tool could not run at all. Never conflatable with a clean scan.
    Unavailable { reason: UnavailableReason },
    /// The tool ran and broke partway. Any partial output is discarded rather than reported, because
    /// a partial answer presented as whole is the same lie as an empty one (FR-013).
    Failed { reason: String },
}

/// Why a tool could not run. Each variant names something an operator can act on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UnavailableReason {
    /// The Cargo feature for this tool family was not compiled into this binary.
    NotCompiledIn { family: String },
    /// No binary at the granted path.
    BinaryMissing { path: PathBuf },
    /// The episode holds no grant for this scanner. Presence on `PATH` confers nothing (FR-008).
    NotGranted { name: String },
    /// The binary at the granted path no longer matches its pinned identity (FR-009, SC-010).
    PinMismatch { path: PathBuf },
    /// A required provisioned artefact is absent or the wrong version (FR-011).
    BundleMismatch {
        expected: String,
        found: Option<String>,
    },
    /// The requested language has no grammar compiled into this build. Carries what *is* available,
    /// so the caller can retry usefully instead of guessing.
    LanguageUnsupported {
        lang: String,
        compiled_in: Vec<String>,
    },
    /// The path is not inside a repository (US5 scenario 3).
    NotARepository { path: PathBuf },
    /// The requested language can only be analysed by observing a build, which bee will not do
    /// (FR-011, US6 scenario 3). Carries the languages that *are* analysable, so a caller can retry
    /// usefully. Distinct from [`UnavailableReason::LanguageUnsupported`], which is about a grammar
    /// this binary was not built with: this one is a deliberate refusal, and no rebuild changes it.
    LanguageRequiresBuild {
        lang: String,
        supported: Vec<String>,
    },
    /// The interception proxy is not running (019): the session has no `[policy.http]`, or its worker
    /// died. An HTTP tool never falls back to direct egress.
    InterceptorUnavailable { detail: String },
    /// The destination is outside the target scope (019). `layer` names who refused: `proxy` (a
    /// user-space check) or `kernel`.
    OutOfScope {
        host: String,
        port: u16,
        layer: String,
    },
    /// The host is reachable only as a tunnel; no model-originated request may test it (019).
    EgressOnly { host: String },
    /// A `[policy.http.limits]` bound would be exceeded (019, FR-021).
    LimitExceeded { limit: String, value: u64 },
}

impl std::fmt::Display for UnavailableReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnavailableReason::NotCompiledIn { family } => {
                write!(
                    f,
                    "tool family `{family}` is not compiled into this build (rebuild with `--features {family}`)"
                )
            }
            UnavailableReason::BinaryMissing { path } => {
                write!(f, "no binary at {}", path.display())
            }
            UnavailableReason::NotGranted { name } => {
                write!(
                    f,
                    "scanner `{name}` is not granted to this episode (a binary on PATH is not a grant)"
                )
            }
            UnavailableReason::PinMismatch { path } => {
                write!(
                    f,
                    "the binary at {} no longer matches its pinned identity; refusing to execute it",
                    path.display()
                )
            }
            // No pin at all comes first: with nothing to compare against, neither of the two
            // sentences below is true — a bundle may well be present, and there is no expected
            // version to name.
            UnavailableReason::BundleMismatch { expected, .. } if expected == UNPINNED => {
                write!(
                    f,
                    "no bundle version is pinned: set the scanner's `bundle_version` to the \
                     provisioned bundle's version (for example `codeql-bundle-v2.26.1`). Running \
                     an unverified analysis bundle is refused, because its queries decide what \
                     counts as a finding"
                )
            }
            UnavailableReason::BundleMismatch { expected, found } => match found {
                Some(found) => write!(
                    f,
                    "bundle version {found} does not match the pinned {expected}"
                ),
                None => write!(f, "no bundle found; expected version {expected}"),
            },
            UnavailableReason::LanguageUnsupported { lang, compiled_in } => {
                if compiled_in.is_empty() {
                    write!(
                        f,
                        "language `{lang}` is unsupported; no grammars are compiled into this build"
                    )
                } else {
                    write!(
                        f,
                        "language `{lang}` is unsupported; compiled in: {}",
                        compiled_in.join(", ")
                    )
                }
            }
            UnavailableReason::NotARepository { path } => {
                write!(f, "{} is not inside a repository", path.display())
            }
            UnavailableReason::InterceptorUnavailable { detail } => {
                write!(f, "the HTTP interception proxy is unavailable: {detail}")
            }
            UnavailableReason::OutOfScope { host, port, layer } => write!(
                f,
                "{host}:{port} is outside the target scope (refused by the {layer} layer); \
                 widening the scope requires operator approval"
            ),
            UnavailableReason::EgressOnly { host } => write!(
                f,
                "{host} is an egress host: reachable as a tunnel for other tools, never testable"
            ),
            UnavailableReason::LimitExceeded { limit, value } => {
                write!(f, "would exceed [policy.http.limits] {limit} ({value})")
            }
            UnavailableReason::LanguageRequiresBuild { lang, supported } => {
                write!(
                    f,
                    "`{lang}` can only be analysed by observing its build, which would mean \
                     admitting every compiler and build tool that build happens to invoke; bee \
                     will not widen a scope that far, so this is declined rather than half-run. \
                     Analysable without a build: {}",
                    if supported.is_empty() {
                        "(none)".to_string()
                    } else {
                        supported.join(", ")
                    }
                )
            }
        }
    }
}

impl UnavailableReason {
    /// A stable slug for audit records, so an operator can grep for a refusal class over time.
    pub fn slug(&self) -> &'static str {
        match self {
            UnavailableReason::NotCompiledIn { .. } => "not_compiled_in",
            UnavailableReason::BinaryMissing { .. } => "binary_missing",
            UnavailableReason::NotGranted { .. } => "not_granted",
            UnavailableReason::PinMismatch { .. } => "pin_mismatch",
            UnavailableReason::BundleMismatch { .. } => "bundle_mismatch",
            UnavailableReason::LanguageUnsupported { .. } => "language_unsupported",
            UnavailableReason::NotARepository { .. } => "not_a_repository",
            UnavailableReason::LanguageRequiresBuild { .. } => "language_requires_build",
            UnavailableReason::InterceptorUnavailable { .. } => "interceptor_unavailable",
            UnavailableReason::OutOfScope { .. } => "out_of_scope",
            UnavailableReason::EgressOnly { .. } => "egress_only",
            UnavailableReason::LimitExceeded { .. } => "limit_exceeded",
        }
    }

    /// Whether this refusal is security-relevant rather than mere absence. These two are the ones an
    /// operator should look at twice: something was granted, and then the thing on disk changed or
    /// was never authorised (contract `tool-outcome.md` §Audit obligation).
    pub fn is_security_relevant(&self) -> bool {
        matches!(
            self,
            UnavailableReason::PinMismatch { .. } | UnavailableReason::NotGranted { .. }
        )
    }
}

impl<T> ToolOutcome<T> {
    /// A completed run whose result set was not bounded.
    pub fn completed(value: T) -> Self {
        ToolOutcome::Completed {
            value,
            truncated: false,
        }
    }

    /// A completed run whose result set hit its cap. `truncated` propagates into the rendering as
    /// the *first* line, so incompleteness is stated rather than inferred (FR-013).
    pub fn completed_truncated(value: T, truncated: bool) -> Self {
        ToolOutcome::Completed { value, truncated }
    }

    pub fn unavailable(reason: UnavailableReason) -> Self {
        ToolOutcome::Unavailable { reason }
    }

    pub fn failed(reason: impl std::fmt::Display) -> Self {
        ToolOutcome::Failed {
            reason: reason.to_string(),
        }
    }

    /// True when the tool produced an answer. False for both refusal states.
    pub fn is_completed(&self) -> bool {
        matches!(self, ToolOutcome::Completed { .. })
    }

    /// Render into the transport type the loop carries (contract `tool-outcome.md` §Mapping).
    ///
    /// `render_value` turns the payload into the model-facing body, and is called **only** on the
    /// `Completed` arm — there is deliberately no way to render a payload out of a refusal, because
    /// there is no payload to render.
    pub fn into_tool_result(self, render_value: impl FnOnce(T) -> String) -> ToolResult {
        match self {
            ToolOutcome::Completed { value, truncated } => {
                let body = render_value(value);
                if truncated {
                    // First line, before the results: an operator scanning the top of the output
                    // must not have to reach the bottom to learn the set was cut.
                    ToolResult::ok(format!(
                        "results were bounded before rendering — this set is incomplete\n{body}"
                    ))
                } else {
                    ToolResult::ok(body)
                }
            }
            ToolOutcome::Unavailable { reason } => {
                ToolResult::error(format!("{UNAVAILABLE_PREFIX} {reason}"))
            }
            ToolOutcome::Failed { reason } => {
                ToolResult::error(format!("{FAILED_PREFIX} {reason}"))
            }
        }
    }
}

/// The body a tool renders when it ran and found nothing. Every tool routes its empty case through
/// this, so "clean" has exactly one phrasing across the whole feature and the guard test has one
/// string to check against.
pub fn clean_scan(scanned: usize, unit: &str) -> String {
    format!("scanned {scanned} {unit}, {CLEAN_PREFIX}")
}

/// Emit the audit record for a refusal (FR-014). Called on every `Unavailable` and `Failed` before
/// the outcome is returned to the loop.
///
/// Audit is stderr-shaped here for the same reason the rest of the harness's diagnostics are: the
/// structured kernel audit stream carries *kernel* decisions, and a tool-layer refusal is not one.
/// What matters for the requirement is that the refusal is machine-readable and never silent.
pub fn audit_refusal(tool: &str, reason: &UnavailableReason) {
    eprintln!(
        r#"{{"event":"tool_unavailable","tool":"{tool}","reason":"{}","security_relevant":{},"detail":{}}}"#,
        reason.slug(),
        reason.is_security_relevant(),
        serde_json::to_string(&reason.to_string()).unwrap_or_else(|_| "\"\"".to_string()),
    );
}

/// Emit the audit record for a failed run (FR-014).
pub fn audit_failure(tool: &str, reason: &str) {
    eprintln!(
        r#"{{"event":"tool_failed","tool":"{tool}","detail":{}}}"#,
        serde_json::to_string(reason).unwrap_or_else(|_| "\"\"".to_string()),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clean_scan_and_an_unavailable_never_read_alike() {
        let clean: ToolOutcome<Vec<String>> = ToolOutcome::completed(Vec::new());
        let clean = clean.into_tool_result(|v| clean_scan(v.len(), "files"));

        let unavailable: ToolOutcome<Vec<String>> =
            ToolOutcome::unavailable(UnavailableReason::NotGranted {
                name: "opengrep".into(),
            });
        let unavailable = unavailable.into_tool_result(|v| clean_scan(v.len(), "files"));

        assert!(!clean.is_error);
        assert!(unavailable.is_error);
        assert!(clean.content.contains(CLEAN_PREFIX));
        assert!(!unavailable.content.contains(CLEAN_PREFIX));
        assert!(unavailable.content.starts_with(UNAVAILABLE_PREFIX));
    }

    #[test]
    fn truncation_is_stated_on_the_first_line() {
        let outcome = ToolOutcome::completed_truncated(vec!["a".to_string()], true);
        let rendered = outcome.into_tool_result(|v| v.join("\n"));
        let first = rendered.content.lines().next().unwrap();
        assert!(first.contains("incomplete"), "got: {first}");
    }

    #[test]
    fn a_refusal_carries_no_payload_to_render() {
        // The renderer closure must never run on a refusal — there is nothing to render. If this
        // ever fires, some arm grew a payload it should not have.
        let outcome: ToolOutcome<Vec<String>> = ToolOutcome::failed("boom");
        let rendered = outcome.into_tool_result(|_| panic!("renderer ran on a refusal"));
        assert!(rendered.content.starts_with(FAILED_PREFIX));
    }

    #[test]
    fn security_relevant_refusals_are_flagged_for_audit() {
        assert!(UnavailableReason::PinMismatch { path: "/x".into() }.is_security_relevant());
        assert!(UnavailableReason::NotGranted { name: "x".into() }.is_security_relevant());
        // Mere absence is not a security event — it is a setup problem.
        assert!(!UnavailableReason::BinaryMissing { path: "/x".into() }.is_security_relevant());
        assert!(!UnavailableReason::NotCompiledIn {
            family: "astgrep".into()
        }
        .is_security_relevant());
    }

    #[test]
    fn unsupported_language_names_what_is_available() {
        let reason = UnavailableReason::LanguageUnsupported {
            lang: "python".into(),
            compiled_in: vec!["rust".into()],
        };
        let msg = reason.to_string();
        assert!(msg.contains("python"), "{msg}");
        assert!(msg.contains("rust"), "{msg}");
    }
}
