//! `http_fuzz` (019 T079, contracts/http-tools.md#http_fuzz): marker templates over payload sets,
//! run by [`ops::fuzz`] under the policy's limits and answered with clusters and outliers.
//!
//! A `project_file` payload set is read here, through a `cat` child in the tool scope, so the kernel
//! decides whether the file is readable — the harness never opens a project file (016 rule).

use std::time::Duration;

use serde_json::{json, Value};

use crate::intercept::control::RawTarget;
use crate::intercept::fuzz::{self, Mode, PayloadSet, Template};
use crate::intercept::ops::{self, FuzzSpec, OpError};
use crate::intercept::sidecar::Interceptor;
use crate::provider::ToolSchema;
use crate::sandbox::Sandbox;
use crate::tools::http::{call_ctx, invalid, live, op_error, respond};
use crate::tools::{Provenance, Tool, ToolOutcome, ToolResult, UnavailableReason};

pub const BOUND: usize = 16 * 1024;

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
        let spec = match parse(icpt, sandbox, &args).await {
            Ok(s) => s,
            Err(r) => return r,
        };
        let result = ops::fuzz(icpt, &call_ctx(sandbox), spec).await;
        let provenance = result.as_ref().ok().map(|r| Provenance::Remote {
            source: format!("http:fuzz:{}", r.run_id),
        });
        respond(
            "http_fuzz",
            icpt,
            result.map(|r| r.summary),
            BOUND,
            provenance,
        )
    }
}

/// The arguments as a [`FuzzSpec`]: the template (from `raw`, or a recorded exchange through
/// [`ops::template_from`]) parsed, and every payload set expanded.
async fn parse(
    icpt: &Interceptor,
    sandbox: &Sandbox,
    args: &Value,
) -> Result<FuzzSpec, ToolResult> {
    let bad = |e: String| invalid("http_fuzz", e);
    let obj = args
        .as_object()
        .ok_or_else(|| bad("arguments must be an object".into()))?;
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
            return Err(bad(format!("unknown argument `{k}`")));
        }
    }
    let marker = match obj.get("markers").and_then(Value::as_str) {
        None => '§',
        Some(m) if m.chars().count() == 1 => m.chars().next().unwrap(),
        Some(_) => return Err(bad("markers is a single character".into())),
    };
    let mode: Mode = match obj.get("mode") {
        None => Mode::default(),
        Some(m) => serde_json::from_value(m.clone()).map_err(|e| bad(format!("mode: {e}")))?,
    };
    let (target, text) = template(
        icpt,
        obj.get("template")
            .ok_or_else(|| bad("`template` is required".into()))?,
        marker,
    )
    .map_err(|e| op_error("http_fuzz", e))?;
    let template = Template::parse(&text, marker).map_err(bad)?;

    let specs: Vec<PayloadSet> =
        serde_json::from_value(obj.get("payloads").cloned().unwrap_or(json!([])))
            .map_err(|e| bad(format!("payloads: {e}")))?;
    if specs.is_empty() {
        return Err(bad("at least one payload set is required".into()));
    }
    let mut sets = Vec::with_capacity(specs.len());
    for s in &specs {
        sets.push(match s {
            PayloadSet::ProjectFile(path) => read_project_file(sandbox, path).await?,
            other => fuzz::expand_set(other).map_err(bad)?,
        });
    }
    Ok(FuzzSpec {
        target,
        template,
        mode,
        sets,
        rps: obj.get("rps").and_then(Value::as_u64).map(|v| v as u32),
        concurrency: obj
            .get("concurrency")
            .and_then(Value::as_u64)
            .map(|v| v as u32),
        timeout: Duration::from_millis(
            obj.get("timeout_ms")
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

/// A project payload file, read by a `cat` child in the tool scope (016 rule).
async fn read_project_file(sandbox: &Sandbox, path: &str) -> Result<Vec<String>, ToolResult> {
    let r = crate::tools::exec::run_child(
        sandbox,
        "cat",
        &["--".to_string(), path.to_string()],
        None,
        fuzz::MAX_FILE_BYTES + 1,
    )
    .await;
    match r.exit_code {
        Some(0) if !r.truncated => {
            fuzz::file_lines(&r.content).map_err(|e| invalid("http_fuzz", e))
        }
        Some(0) => Err(invalid(
            "http_fuzz",
            format!("payload file exceeds {} bytes", fuzz::MAX_FILE_BYTES),
        )),
        // No exit code: the child never ran — `cat` is not in this scope's exec allowlist.
        None | Some(126) | Some(127) => Err(ToolOutcome::<()>::unavailable(
            UnavailableReason::NotGranted { name: "cat".into() },
        )
        .into_tool_result(|_| String::new())),
        Some(_) => Err(ToolOutcome::<()>::failed(format!(
            "reading {path} was refused in the tool scope: {}",
            r.content.lines().last().unwrap_or("")
        ))
        .into_tool_result(|_| String::new())),
    }
}
