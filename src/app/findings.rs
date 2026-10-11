//! `bee findings` — read the finding ledger, and adjudicate what is in it (016-native-tools US2).
//!
//! **Adjudication is deliberately not a tool.** The whole value of a verdict is that a *person*
//! formed it: `record_finding` lets the agent say what it saw, and this command lets the operator
//! say what they concluded. If the agent could write verdicts, "a human marked this a false
//! positive" would stop meaning anything, and FR-020's guarantee — that automated rediscovery can
//! never clear a human's judgement — would protect nothing, since the same actor would sit on both
//! sides of it. So the model-facing surface is append-a-sighting; the operator-facing surface,
//! reachable only from a terminal, is append-a-verdict.
//!
//! Everything printed here is untrusted: `title` and `evidence` come from a model reading target
//! source, or verbatim out of a third-party scanner's report. This is a **new output channel** —
//! it does not pass through the tool-result rendering the front-ends already sanitize — so it does
//! its own [`safe_text`] escaping (FR-015, extending the 014 treatment).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Subcommand};

use bee::findings::{fold, Ledger, LedgerEvent, Verdict, VerdictState, View};
use bee::safe_text::safe_line;

use crate::app::session::{EX_IOERR, EX_USAGE};

const CMD: &str = "bee findings";

#[derive(Args, Debug)]
pub struct FindingsArgs {
    /// Ledger directory (default: `.bee/findings` under the current directory).
    #[arg(long, global = true)]
    pub dir: Option<PathBuf>,
    #[command(subcommand)]
    pub cmd: FindingsCmd,
}

#[derive(Subcommand, Debug)]
pub enum FindingsCmd {
    /// List recorded findings, newest sighting first within each entry.
    List {
        /// Only findings of this issue class.
        #[arg(long)]
        class: Option<String>,
        /// Only findings with this verdict (`confirmed`, `false-positive`, `fixed`, `deferred`,
        /// or `none` for unadjudicated).
        #[arg(long)]
        verdict: Option<String>,
        /// Print the folded view as JSON instead of the summary.
        #[arg(long)]
        json: bool,
    },
    /// Record a human verdict against a finding.
    Adjudicate {
        /// The finding id, as shown by `bee findings list`.
        id: String,
        /// `confirmed` | `false-positive` | `fixed` | `deferred` | `duplicate:<id>`.
        #[arg(long)]
        state: String,
        /// Why. Recorded verbatim beside the verdict.
        #[arg(long)]
        note: Option<String>,
        /// Who adjudicated (default: `$USER`).
        #[arg(long)]
        by: Option<String>,
    },
}

pub fn main(args: FindingsArgs) -> ExitCode {
    let ledger = Ledger::resolve(args.dir.as_deref());
    match args.cmd {
        FindingsCmd::List {
            class,
            verdict,
            json,
        } => list(&ledger, class.as_deref(), verdict.as_deref(), json),
        FindingsCmd::Adjudicate {
            id,
            state,
            note,
            by,
        } => adjudicate(&ledger, &id, &state, note, by),
    }
}

fn list(ledger: &Ledger, class: Option<&str>, verdict: Option<&str>, json: bool) -> ExitCode {
    let view = match fold(ledger) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{CMD}: {e}");
            return ExitCode::from(EX_IOERR);
        }
    };

    if json {
        // The JSON form is for piping into something else, which is not a terminal, so it carries
        // the record unescaped. `serde_json` already escapes control characters as `\uXXXX`.
        match serde_json::to_string_pretty(&view) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("{CMD}: {e}");
                return ExitCode::from(EX_IOERR);
            }
        }
        return ExitCode::SUCCESS;
    }

    print!("{}", render(&view, class, verdict, &ledger.project_root()));
    ExitCode::SUCCESS
}

/// Render the view for a terminal. Every untrusted field is escaped here — see the module note.
fn render(
    view: &View,
    class: Option<&str>,
    verdict: Option<&str>,
    project: &std::path::Path,
) -> String {
    let mut out = String::new();
    let mut shown = 0usize;

    for f in &view.findings {
        if class.is_some_and(|c| f.class != c) {
            continue;
        }
        let matches_verdict = match verdict {
            None => true,
            Some("none") => f.verdict.is_none(),
            Some(want) => f
                .verdict
                .as_ref()
                .is_some_and(|v| v.state.to_string() == want),
        };
        if !matches_verdict {
            continue;
        }
        shown += 1;

        let loc = match f.sightings.last().and_then(|s| s.line) {
            Some(line) => format!("{}:{line}", safe_line(&f.path)),
            None => safe_line(&f.path).into_owned(),
        };
        out.push_str(&format!(
            "{}  [{}]  {loc}\n    {}\n",
            f.id,
            safe_line(&f.class),
            safe_line(&f.title)
        ));
        if let Some(sev) = &f.severity {
            out.push_str(&format!(
                "    severity {:.1} ({}) — {}\n",
                sev.score,
                sev.band,
                safe_line(&sev.vector)
            ));
        }
        if let Some(level) = &f.advisory_level {
            out.push_str(&format!(
                "    scanner level (advisory): {}\n",
                safe_line(level)
            ));
        }
        if let Some(v) = &f.verdict {
            out.push_str(&format!(
                "    verdict: {} by {}{}\n",
                v.state,
                safe_line(&v.by),
                v.note
                    .as_deref()
                    .map(|n| format!(" — {}", safe_line(n)))
                    .unwrap_or_default()
            ));
        }
        out.push_str(&format!(
            "    {} sighting(s), first {} — source {}\n",
            f.sightings.len(),
            f.sightings
                .first()
                .map(|s| safe_line(&s.run_id).into_owned())
                .unwrap_or_default(),
            safe_line(&f.source.to_string())
        ));
        out.push_str(&format!("    {}\n", safe_line(&f.evidence)));
        // Cited exchanges (019 US8), resolved now: one evicted or gone since reads as `missing`.
        let mut refs: Vec<&String> = f.sightings.iter().flat_map(|s| &s.evidence_refs).collect();
        refs.sort();
        refs.dedup();
        for r in refs {
            out.push_str(&format!(
                "    evidence {} — {}\n",
                safe_line(r),
                ref_state(project, r)
            ));
        }
    }

    if shown == 0 {
        out.push_str("no findings match\n");
    }
    if view.skipped > 0 {
        out.push_str(&format!(
            "note: {} ledger event(s) could not be read by this build\n",
            view.skipped
        ));
    }
    out
}

fn adjudicate(
    ledger: &Ledger,
    id: &str,
    state: &str,
    note: Option<String>,
    by: Option<String>,
) -> ExitCode {
    let state = match VerdictState::parse(state) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{CMD}: {e}");
            return ExitCode::from(EX_USAGE);
        }
    };

    let id = bee::findings::FindingId::parse(id);
    // Refuse to adjudicate something the ledger has never seen. Folding drops a verdict for an
    // unknown id, so accepting it would report success and record nothing.
    match fold(ledger) {
        Ok(view) if view.get(&id).is_none() => {
            eprintln!(
                "{CMD}: no finding `{id}` in {}",
                ledger.log_path().display()
            );
            return ExitCode::from(EX_USAGE);
        }
        Err(e) => {
            eprintln!("{CMD}: {e}");
            return ExitCode::from(EX_IOERR);
        }
        Ok(_) => {}
    }

    let verdict = Verdict {
        state,
        note,
        by: by
            .or_else(|| std::env::var("USER").ok())
            .unwrap_or_else(|| "operator".to_string()),
        at: time::OffsetDateTime::now_utc(),
    };

    if let Err(e) = ledger.append(&LedgerEvent::Adjudicated {
        id: id.clone(),
        verdict: verdict.clone(),
    }) {
        eprintln!("{CMD}: {e}");
        return ExitCode::from(EX_IOERR);
    }
    bee::findings::refresh_view(ledger);
    println!("{id}: {} by {}", verdict.state, verdict.by);
    ExitCode::SUCCESS
}

/// How a cited exchange resolves now: `present` or `missing` (019 US8, FR-027).
#[cfg_attr(not(feature = "intercept"), allow(unused_variables))]
fn ref_state(project: &std::path::Path, r: &str) -> &'static str {
    #[cfg(feature = "intercept")]
    {
        match r
            .strip_prefix("http:")
            .map(|id| bee::intercept::store::resolve_ref(project, id))
        {
            Some(bee::intercept::store::RefState::Present) => "present",
            _ => "missing",
        }
    }
    #[cfg(not(feature = "intercept"))]
    {
        let _ = r;
        "missing (this build has no exchange store)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bee::findings::{record, Finding, FindingSource, Sighting};

    fn ledger(dir: &std::path::Path) -> Ledger {
        Ledger::at(dir.join("findings"))
    }

    #[test]
    fn untrusted_finding_text_cannot_drive_the_operators_terminal() {
        let tmp = tempfile::tempdir().unwrap();
        let led = ledger(tmp.path());
        // A scanner snippet lifted verbatim from attacker-controlled source: a screen clear, a
        // cursor home, and a bidi override that reorders what is drawn after the fact.
        let hostile = "\x1b[2J\x1b[1;1H PWNED \u{202e}gnp.txt";
        let mut f = Finding::new(
            "src/a.rs".into(),
            "injection".into(),
            format!("title {hostile}"),
            format!("evidence {hostile}"),
            FindingSource::Scanner("opengrep".into()),
        );
        f.reidentify();
        record(&led, f, Sighting::now("run-1")).unwrap();

        let rendered = render(&fold(&led).unwrap(), None, None, std::path::Path::new("."));
        assert!(
            !rendered.contains('\u{1b}'),
            "an escape survived into the operator's terminal: {rendered:?}"
        );
        assert!(
            !rendered.contains('\u{202e}'),
            "a bidi override survived: {rendered:?}"
        );
        // The text is still legible as data — escaped, not dropped.
        assert!(rendered.contains("\\x1b"), "{rendered}");
        assert!(rendered.contains("PWNED"), "{rendered}");
    }

    #[test]
    fn an_empty_ledger_says_so_rather_than_printing_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let view = fold(&ledger(tmp.path())).unwrap();
        assert!(render(&view, None, None, std::path::Path::new(".")).contains("no findings match"));
    }

    #[test]
    fn filtering_by_verdict_and_class_narrows_the_list() {
        let tmp = tempfile::tempdir().unwrap();
        let led = ledger(tmp.path());
        for (path, class) in [("src/a.rs", "sqli"), ("src/b.rs", "xss")] {
            let f = Finding::new(
                path.into(),
                class.into(),
                "t".into(),
                "e".into(),
                FindingSource::Tool("test".into()),
            );
            record(&led, f, Sighting::now("run-1")).unwrap();
        }
        let view = fold(&led).unwrap();
        assert!(render(&view, Some("sqli"), None, std::path::Path::new(".")).contains("src/a.rs"));
        assert!(!render(&view, Some("sqli"), None, std::path::Path::new(".")).contains("src/b.rs"));
        // Nothing is adjudicated yet, so every entry is `none` and no entry is `confirmed`.
        assert!(
            render(&view, None, Some("confirmed"), std::path::Path::new("."))
                .contains("no findings match")
        );
        assert!(render(&view, None, Some("none"), std::path::Path::new(".")).contains("src/a.rs"));
    }
}
