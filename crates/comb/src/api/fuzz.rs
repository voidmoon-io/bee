//! `http_fuzz` (019 T079, contracts/http-tools.md#http_fuzz): marker templates over payload sets,
//! run by [`ops::fuzz`] under the policy's limits and answered with clusters and outliers.
//!
//! A `project_file` payload set is read here, through a `cat` child in the tool scope, so the kernel
//! decides whether the file is readable — the harness never opens a project file (016 rule).

use std::time::Duration;

use serde_json::{json, Value};

use super::{invalid, only_keys, CallError, PayloadFiles, Reply, ToolDef};
use crate::control::RawTarget;
use crate::fuzz::{self, Mode, PayloadSet, Template};
use crate::ops::{self, CallCtx, FuzzSpec, OpError};
use crate::sidecar::Interceptor;

pub const BOUND: usize = 16 * 1024;

pub(super) fn def() -> ToolDef {
    ToolDef {
        name: "http_fuzz",
        description: "Fuzz an in-scope target: a request template with positions marked §…§ \
                          (or a recorded exchange plus `mark`, the literal text(s) to turn into \
                          positions), payload sets (builtin: sqli-basic, xss-basic, path-traversal, \
                          common-paths; range; inline; project_file), and a mode (sniper, \
                          battering_ram, pitchfork, cluster_bomb). Runs within the policy's rate, \
                          concurrency and per-run limits, and returns response clusters with the \
                          outliers flagged — not every response.",
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

pub(super) async fn call(
    icpt: &Interceptor,
    ctx: &CallCtx,
    args: &Value,
    files: &dyn PayloadFiles,
) -> Result<Reply, CallError> {
    let spec = parse(icpt, args, files).await?;
    let r = ops::fuzz(icpt, ctx, spec).await?;
    Ok(Reply::json(
        &r.summary,
        BOUND,
        Some(format!("http:fuzz:{}", r.run_id)),
    ))
}

/// The arguments as a [`FuzzSpec`]: the template (from `raw`, or a recorded exchange through
/// [`ops::template_from`]) parsed, and every payload set expanded.
async fn parse(
    icpt: &Interceptor,
    args: &Value,
    files: &dyn PayloadFiles,
) -> Result<FuzzSpec, CallError> {
    only_keys(
        args,
        &[
            "template",
            "markers",
            "payloads",
            "mode",
            "rps",
            "concurrency",
            "timeout_ms",
        ],
    )?;
    let marker = match args.get("markers").and_then(Value::as_str) {
        None => '§',
        Some(m) if m.chars().count() == 1 => m.chars().next().unwrap_or('§'),
        Some(_) => return Err(invalid("markers is a single character")),
    };
    let mode: Mode = match args.get("mode") {
        None => Mode::default(),
        Some(m) => serde_json::from_value(m.clone()).map_err(|e| invalid(format!("mode: {e}")))?,
    };
    let (target, text) = template(
        icpt,
        args.get("template")
            .ok_or_else(|| invalid("`template` is required"))?,
        marker,
    )?;
    let template = Template::parse(&text, marker).map_err(invalid)?;

    let specs: Vec<PayloadSet> =
        serde_json::from_value(args.get("payloads").cloned().unwrap_or(json!([])))
            .map_err(|e| invalid(format!("payloads: {e}")))?;
    if specs.is_empty() {
        return Err(invalid("at least one payload set is required"));
    }
    let mut sets = Vec::with_capacity(specs.len());
    for s in &specs {
        sets.push(match s {
            PayloadSet::ProjectFile(path) => files.read_lines(path).await?,
            other => fuzz::expand_set(other).map_err(invalid)?,
        });
    }
    Ok(FuzzSpec {
        target,
        template,
        mode,
        sets,
        rps: args.get("rps").and_then(Value::as_u64).map(|v| v as u32),
        concurrency: args
            .get("concurrency")
            .and_then(Value::as_u64)
            .map(|v| v as u32),
        timeout: Duration::from_millis(
            args.get("timeout_ms")
                .and_then(Value::as_u64)
                .unwrap_or(15_000)
                .clamp(1, 120_000),
        ),
    })
}

/// The template's target and text, markers in place.
fn template(icpt: &Interceptor, t: &Value, marker: char) -> Result<(RawTarget, String), OpError> {
    let bad = |e: &str| OpError::Invalid(e.into());
    if let Some(raw) = t.get("raw") {
        let scheme = raw.get("scheme").and_then(Value::as_str).unwrap_or("http");
        let host = raw
            .get("host")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("template.raw.host is required"))?;
        let port = raw
            .get("port")
            .and_then(Value::as_u64)
            .filter(|p| (1..=65535).contains(p))
            .ok_or_else(|| bad("template.raw.port must be 1–65535"))? as u16;
        let bytes = raw
            .get("bytes")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("template.raw.bytes is required"))?;
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
        .ok_or_else(|| bad("template needs `from` or `raw`"))?;
    let marks: Vec<String> = t
        .get("mark")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|m| m.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    ops::template_from(icpt, id, &marks, marker)
}
