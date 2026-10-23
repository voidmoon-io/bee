//! Fuzz a target from a marker template (019 T079, FR-035): run inside the worker under the policy's
//! limits, and answered with **clusters and outliers** — a bounded summary whatever the variant count
//! (019 SC-006).
//!
//! A run over `max_requests_per_run` is refused before the first request (019 FR-021). `rps` and
//! `concurrency` can only lower the policy's.

use std::time::Duration;

use serde_json::{json, Value};

use super::{CallCtx, OpError, Refusal};
use crate::intercept::control::RawTarget;
use crate::intercept::fuzz::{self, Mode, Observed, Template};
use crate::intercept::sidecar::Interceptor;

/// A fuzz exchange as read back: id, status, response blob, total ms, tags, outcome.
type FuzzRow = (
    String,
    Option<u16>,
    Option<String>,
    Option<i64>,
    Option<String>,
    String,
);

#[derive(Debug, Clone)]
pub struct FuzzSpec {
    pub target: RawTarget,
    pub template: Template,
    pub mode: Mode,
    /// The payload sets, expanded.
    pub sets: Vec<Vec<String>>,
    /// Lowers the policy's rate; `None` keeps it.
    pub rps: Option<u32>,
    /// Lowers the policy's concurrency; `None` keeps it.
    pub concurrency: Option<u32>,
    pub timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct FuzzResult {
    pub run_id: String,
    /// Clusters, outliers, counts and the effective pacing (contracts/http-tools.md#http_fuzz).
    pub summary: Value,
}

/// Run `spec`, then cluster the responses and record the run.
pub async fn fuzz(
    icpt: &Interceptor,
    ctx: &CallCtx,
    spec: FuzzSpec,
) -> Result<FuzzResult, OpError> {
    let FuzzSpec {
        target,
        template: tpl,
        mode,
        sets,
        rps,
        concurrency,
        timeout,
    } = spec;
    // The limit is checked on the planned count — before anything is expanded or sent.
    let limits = icpt.http_scope().limits;
    let planned = fuzz::planned(mode, tpl.positions(), &sets).map_err(OpError::Invalid)?;
    if planned > u64::from(limits.max_requests_per_run) {
        return Err(OpError::Refused {
            reason: Refusal::LimitExceeded {
                limit: format!("max_requests_per_run ({})", limits.max_requests_per_run),
                value: planned,
            },
            note: None,
        });
    }
    let rps = rps.unwrap_or(limits.rps).clamp(1, limits.rps);
    let concurrency = concurrency
        .unwrap_or(limits.concurrency)
        .clamp(1, limits.concurrency);

    let variants = fuzz::expand(&tpl, mode, &sets);
    let payloads: Vec<Vec<String>> = variants.iter().map(|v| v.payloads.clone()).collect();
    let bytes: Vec<Vec<u8>> = variants.iter().map(|v| fuzz::fix_length(&v.text)).collect();
    let run_id = icpt
        .with_store(|s| s.next_fuzz_run_id())
        .map_err(|e| OpError::Failed(e.to_string()))?;
    // The wall-clock budget follows from the pacing, plus room for the slowest responses.
    let budget = Duration::from_secs(planned / u64::from(rps) + 30) + timeout;
    let counts = icpt
        .fuzz(
            &run_id,
            target,
            bytes,
            ctx.clone(),
            rps,
            concurrency,
            timeout,
            budget,
        )
        .await?;

    // Gather the run's responses and cluster them.
    let rows = icpt.with_store(|s| -> rusqlite::Result<Vec<FuzzRow>> {
        let mut stmt = s.conn().prepare(
            "SELECT id, status, resp_body, total_ms, tags, outcome FROM exchanges WHERE fuzz_run = ?1",
        )?;
        let it = stmt.query_map([&run_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))?;
        it.collect()
    })
    .map_err(|e| OpError::Failed(e.to_string()))?;
    let mut obs = Vec::new();
    for (id, status, sha, ms, tags, outcome) in rows {
        if outcome.starts_with("refused") {
            continue; // counted as refused, never as a response
        }
        let idx = tags
            .and_then(|t| serde_json::from_str::<Vec<String>>(&t).ok())
            .and_then(|t| {
                t.iter()
                    .find_map(|x| x.strip_prefix('v').and_then(|n| n.parse::<usize>().ok()))
            });
        let body = match &sha {
            Some(sha) => {
                let raw = icpt
                    .with_store(|s| s.read_blob(sha))
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                let enc = icpt
                    .with_store(|s| s.blob_meta(sha))
                    .ok()
                    .flatten()
                    .map(|m| m.encoding)
                    .unwrap_or_else(|| "identity".into());
                crate::intercept::slice::decode(&raw, &enc, 1024 * 1024)
                    .map(|d| d.bytes)
                    .unwrap_or(raw)
            }
            None => Vec::new(),
        };
        obs.push(Observed {
            exchange_id: id,
            status,
            body,
            elapsed_ms: ms.unwrap_or(0) as u64,
            payloads: idx
                .and_then(|i| payloads.get(i).cloned())
                .unwrap_or_default(),
        });
    }
    let mut summary = fuzz::cluster(&run_id, &obs);
    summary["counts"] = json!({
        "planned": planned,
        "sent": counts.sent,
        "refused": counts.refused,
        "failed": counts.failed,
    });
    summary["state"] = json!(counts.state);
    summary["effective"] = json!({ "rps": rps, "concurrency": concurrency, "mode": mode });
    summary["enforcement"] = json!(icpt.enforcement().label());
    let spec = json!({ "mode": mode, "positions": tpl.positions(), "sets": sets.len(), "rps": rps, "concurrency": concurrency });
    let _ = icpt.with_store(|s| {
        s.insert_fuzz_run(
            &run_id,
            Some(&ctx.call_id),
            &spec,
            &counts.state,
            planned,
            counts.sent,
            counts.refused,
            counts.failed,
            &summary,
        )
    });
    Ok(FuzzResult { run_id, summary })
}

/// A template from recorded exchange `id`: its request text with each of `marks` (the literal
/// text(s) to fuzz) wrapped in `marker`, and where it went.
pub fn template_from(
    icpt: &Interceptor,
    id: &str,
    marks: &[String],
    marker: char,
) -> Result<(RawTarget, String), OpError> {
    let (target, head, body) = super::stored_request(icpt, id)?;
    let mut text = String::from_utf8(head)
        .map_err(|_| OpError::Invalid("the stored request is not text".into()))?;
    text.push_str(&String::from_utf8_lossy(&body));
    if marks.is_empty() && !text.contains(marker) {
        return Err(OpError::Invalid(
            "a `from` template needs `mark`: the literal text(s) to make into positions".into(),
        ));
    }
    for m in marks {
        let at = text
            .find(m.as_str())
            .ok_or_else(|| OpError::Invalid(format!("`{m}` does not occur in {id}")))?;
        text.replace_range(at..at + m.len(), &format!("{marker}{m}{marker}"));
    }
    Ok((target, text))
}
