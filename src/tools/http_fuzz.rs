//! `http_fuzz` (019 T079, contracts/http-tools.md#http_fuzz): marker templates over payload sets,
//! run inside the worker under the policy's limits, answered with **clusters and outliers** — a
//! bounded summary whatever the variant count (SC-006).
//!
//! A run over `max_requests_per_run` is refused before the first request (FR-021). `rps` and
//! `concurrency` arguments can only lower the policy's. A `project_file` payload set is read through
//! a `cat` child in the tool scope, so the kernel decides whether the file is readable — the harness
//! never opens a project file (016 rule).

use std::time::Duration;

use serde_json::{json, Value};

use crate::intercept::control::RawTarget;
use crate::intercept::fuzz::{self, Mode, Observed, PayloadSet, Template};
use crate::intercept::sidecar::{InterceptError, Interceptor};
use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;
use crate::tools::http::{bounded_json, invalid, live, with_notices};
use crate::tools::http_send::call_ctx;
use crate::tools::{Provenance, Tool, ToolOutcome, ToolResult, UnavailableReason};

pub const BOUND: usize = 16 * 1024;

/// A fuzz exchange as read back: id, status, response blob, total ms, tags, outcome.
type FuzzRow = (
    String,
    Option<u16>,
    Option<String>,
    Option<i64>,
    Option<String>,
    String,
);

pub struct HttpFuzz {
    pub(crate) icpt: Option<Interceptor>,
}

#[async_trait::async_trait]
impl Tool for HttpFuzz {
    fn name(&self) -> &'static str {
        "http_fuzz"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "http_fuzz".into(),
            description: "Fuzz an in-scope target: a request template with positions marked §…§ \
                          (or a recorded exchange plus `mark`, the literal text(s) to turn into \
                          positions), payload sets (builtin: sqli-basic, xss-basic, path-traversal, \
                          common-paths; range; inline; project_file), and a mode (sniper, \
                          battering_ram, pitchfork, cluster_bomb). Runs within the policy's rate, \
                          concurrency and per-run limits, and returns response clusters with the \
                          outliers flagged — not every response."
                .into(),
            parameters: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["template", "payloads"],
                "properties": {
                    "template": {
                        "type": "object",
                        "description": "{\"from\": \"E…\", \"mark\": [\"text\"]} or {\"raw\": {\"scheme\", \"host\", \"port\", \"bytes\"}}"
                    },
                    "markers": { "type": "string", "description": "position delimiter, default §" },
                    "payloads": { "type": "array", "items": { "type": "object" } },
                    "mode": { "type": "string", "enum": ["sniper", "battering_ram", "pitchfork", "cluster_bomb"] },
                    "rps": { "type": "integer", "minimum": 1 },
                    "concurrency": { "type": "integer", "minimum": 1 },
                    "timeout_ms": { "type": "integer", "minimum": 1 }
                }
            }),
        }
    }

    async fn call(&self, args: Value, sandbox: &Sandbox) -> ToolResult {
        let icpt = match live(&self.icpt).await {
            Ok(i) => i,
            Err(r) => return r,
        };
        match run(icpt, sandbox, &args).await {
            Ok((run_id, v)) => ToolResult::ok(with_notices(bounded_json(&v, BOUND), icpt))
                .with_provenance(Provenance::Remote {
                    source: format!("http:fuzz:{run_id}"),
                }),
            Err(Fail::Invalid(e)) => invalid("http_fuzz", e),
            Err(Fail::Refused(r)) => {
                ToolOutcome::<()>::unavailable(r).into_tool_result(|_| String::new())
            }
            Err(Fail::Failed(e)) => {
                ToolOutcome::<()>::failed(e).into_tool_result(|_| String::new())
            }
        }
    }
}

enum Fail {
    Invalid(String),
    Refused(UnavailableReason),
    Failed(String),
}

impl From<InterceptError> for Fail {
    fn from(e: InterceptError) -> Fail {
        match e {
            InterceptError::Unavailable(d) => {
                Fail::Refused(UnavailableReason::InterceptorUnavailable { detail: d })
            }
            other => Fail::Failed(other.to_string()),
        }
    }
}

async fn run(icpt: &Interceptor, sandbox: &Sandbox, args: &Value) -> Result<(String, Value), Fail> {
    let obj = args
        .as_object()
        .ok_or(Fail::Invalid("arguments must be an object".into()))?;
    for k in obj.keys() {
        if ![
            "template",
            "markers",
            "payloads",
            "mode",
            "rps",
            "concurrency",
            "timeout_ms",
        ]
        .contains(&k.as_str())
        {
            return Err(Fail::Invalid(format!("unknown argument `{k}`")));
        }
    }
    let marker = match obj.get("markers").and_then(Value::as_str) {
        None => '§',
        Some(m) if m.chars().count() == 1 => m.chars().next().unwrap(),
        Some(_) => return Err(Fail::Invalid("markers is a single character".into())),
    };
    let mode: Mode = match obj.get("mode") {
        None => Mode::default(),
        Some(m) => {
            serde_json::from_value(m.clone()).map_err(|e| Fail::Invalid(format!("mode: {e}")))?
        }
    };
    let (target, text) = template(
        icpt,
        obj.get("template")
            .ok_or(Fail::Invalid("`template` is required".into()))?,
        marker,
    )?;
    let tpl = Template::parse(&text, marker).map_err(Fail::Invalid)?;

    let specs: Vec<PayloadSet> =
        serde_json::from_value(obj.get("payloads").cloned().unwrap_or(json!([])))
            .map_err(|e| Fail::Invalid(format!("payloads: {e}")))?;
    if specs.is_empty() {
        return Err(Fail::Invalid("at least one payload set is required".into()));
    }
    let mut sets = Vec::with_capacity(specs.len());
    for s in &specs {
        sets.push(match s {
            PayloadSet::ProjectFile(path) => read_project_file(sandbox, path).await?,
            other => fuzz::expand_set(other).map_err(Fail::Invalid)?,
        });
    }

    // The limit is checked on the planned count — before anything is expanded or sent.
    let limits = icpt.http_scope().limits;
    let planned = fuzz::planned(mode, tpl.positions(), &sets).map_err(Fail::Invalid)?;
    if planned > u64::from(limits.max_requests_per_run) {
        return Err(Fail::Refused(UnavailableReason::LimitExceeded {
            limit: format!("max_requests_per_run ({})", limits.max_requests_per_run),
            value: planned,
        }));
    }
    let rps = obj
        .get("rps")
        .and_then(Value::as_u64)
        .map(|v| v as u32)
        .unwrap_or(limits.rps)
        .clamp(1, limits.rps);
    let concurrency = obj
        .get("concurrency")
        .and_then(Value::as_u64)
        .map(|v| v as u32)
        .unwrap_or(limits.concurrency)
        .clamp(1, limits.concurrency);
    let timeout = Duration::from_millis(
        obj.get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(15_000)
            .clamp(1, 120_000),
    );

    let variants = fuzz::expand(&tpl, mode, &sets);
    let payloads: Vec<Vec<String>> = variants.iter().map(|v| v.payloads.clone()).collect();
    let bytes: Vec<Vec<u8>> = variants.iter().map(|v| fuzz::fix_length(&v.text)).collect();
    let run_id = icpt
        .with_store(|s| s.next_fuzz_run_id())
        .map_err(|e| Fail::Failed(e.to_string()))?;
    let ctx = call_ctx(sandbox);
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
    .map_err(|e| Fail::Failed(e.to_string()))?;
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
    let spec = json!({ "mode": mode, "positions": tpl.positions(), "sets": specs.len(), "rps": rps, "concurrency": concurrency });
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
    Ok((run_id, summary))
}

/// The template's target and text, markers in place.
fn template(icpt: &Interceptor, t: &Value, marker: char) -> Result<(RawTarget, String), Fail> {
    if let Some(raw) = t.get("raw") {
        let scheme = raw.get("scheme").and_then(Value::as_str).unwrap_or("http");
        let host = raw
            .get("host")
            .and_then(Value::as_str)
            .ok_or(Fail::Invalid("template.raw.host is required".into()))?;
        let port = raw
            .get("port")
            .and_then(Value::as_u64)
            .filter(|p| (1..=65535).contains(p))
            .ok_or(Fail::Invalid("template.raw.port must be 1–65535".into()))?
            as u16;
        let bytes = raw
            .get("bytes")
            .and_then(Value::as_str)
            .ok_or(Fail::Invalid("template.raw.bytes is required".into()))?;
        return Ok((
            RawTarget {
                scheme: scheme.into(),
                host: bee_core::pattern::normalize_host(host),
                port,
            },
            bytes.to_string(),
        ));
    }
    let id = t
        .get("from")
        .and_then(Value::as_str)
        .ok_or(Fail::Invalid("template needs `from` or `raw`".into()))?;
    let (target, head, body) = match crate::tools::http_replay::stored_request(icpt, id) {
        Ok(v) => v,
        Err(crate::tools::http_replay::Fail::Invalid(e)) => return Err(Fail::Invalid(e)),
        Err(crate::tools::http_replay::Fail::Unavailable(d)) => {
            return Err(Fail::Refused(UnavailableReason::InterceptorUnavailable {
                detail: d,
            }))
        }
        Err(crate::tools::http_replay::Fail::Failed(e)) => return Err(Fail::Failed(e)),
    };
    let mut text = String::from_utf8(head)
        .map_err(|_| Fail::Invalid("the stored request is not text".into()))?;
    text.push_str(&String::from_utf8_lossy(&body));
    let marks: Vec<String> = t
        .get("mark")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|m| m.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if marks.is_empty() && !text.contains(marker) {
        return Err(Fail::Invalid(
            "a `from` template needs `mark`: the literal text(s) to make into positions".into(),
        ));
    }
    for m in marks {
        let at = text
            .find(&m)
            .ok_or_else(|| Fail::Invalid(format!("`{m}` does not occur in {id}")))?;
        text.replace_range(at..at + m.len(), &format!("{marker}{m}{marker}"));
    }
    Ok((target, text))
}

/// A project payload file, read by a `cat` child in the tool scope (016 rule).
async fn read_project_file(sandbox: &Sandbox, path: &str) -> Result<Vec<String>, Fail> {
    let r = crate::tools::exec::run_child(
        sandbox,
        "cat",
        &["--".to_string(), path.to_string()],
        None,
        fuzz::MAX_FILE_BYTES + 1,
    )
    .await;
    match r.exit_code {
        Some(0) if !r.truncated => fuzz::file_lines(&r.content).map_err(Fail::Invalid),
        Some(0) => Err(Fail::Invalid(format!(
            "payload file exceeds {} bytes",
            fuzz::MAX_FILE_BYTES
        ))),
        // No exit code: the child never ran — `cat` is not in this scope's exec allowlist.
        None | Some(126) | Some(127) => Err(Fail::Refused(UnavailableReason::NotGranted {
            name: "cat".into(),
        })),
        Some(_) => Err(Fail::Failed(format!(
            "reading {path} was refused in the tool scope: {}",
            r.content.lines().last().unwrap_or("")
        ))),
    }
}
