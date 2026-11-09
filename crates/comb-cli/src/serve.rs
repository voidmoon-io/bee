//! `comb serve`: one interception session, its tools over JSON lines (crates/comb/README.md).
//!
//! stdin carries requests, one JSON object per line; stdout carries responses and events, one per
//! line. Requests run concurrently — a long fuzz run does not block a history query — so responses
//! may arrive out of order and carry the request's `id`. EOF on stdin ends the session.

use std::sync::Arc;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use comb::api::{self, CallError, NoPayloadFiles};
use comb::control::WireCtx;
use comb::ops::{OpError, Refusal};
use comb::sidecar::{Enforcement, Interceptor, InterceptorConfig, SpawnFn};

use crate::ServeOptions;

/// Why every result is labelled advisory.
pub const ADVISORY_REASON: &str =
    "standalone comb: the proxy enforces scope by host name; no kernel scope confines clients";

/// Longest request line accepted.
const MAX_LINE: usize = 4 << 20;

pub async fn run(opts: ServeOptions) -> Result<(), String> {
    let port = opts
        .listener
        .local_addr()
        .map_err(|e| format!("listener: {e}"))?
        .port();
    let exe = opts.worker_exe.clone();
    let sid = opts.session_id.clone();
    let spawn: SpawnFn = Box::new(move || {
        let mut c = std::process::Command::new(&exe);
        c.args(["worker", "--session", &sid]);
        Ok(c)
    });
    let icpt = Interceptor::start(
        InterceptorConfig {
            session_id: opts.session_id.clone(),
            project_root: opts.project_root.clone(),
            http_scope: opts.http_scope,
            enforcement: Enforcement::Advisory {
                reason: ADVISORY_REASON.into(),
            },
            resolver: comb::sidecar::system_resolver(),
        },
        opts.listener,
        spawn,
    )
    .await?;

    let ca_bundle = match icpt.ca_cert_pem() {
        Some(pem) => match comb::client::write_ca_bundle(&opts.ca_bundle, &pem) {
            Ok(()) => Some(opts.ca_bundle.clone()),
            Err(e) => {
                icpt.shutdown().await;
                return Err(e);
            }
        },
        None => None,
    };

    let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
    // `Value::Null` ends the writer: the event sink keeps a sender alive inside the interceptor, so
    // waiting for every sender to drop would never return.
    let writer = tokio::spawn(async move {
        let mut out = tokio::io::stdout();
        while let Some(v) = rx.recv().await {
            if v.is_null() {
                break;
            }
            let mut line = serde_json::to_vec(&v).unwrap_or_default();
            line.push(b'\n');
            if out.write_all(&line).await.is_err() || out.flush().await.is_err() {
                break;
            }
        }
    });
    {
        let tx = tx.clone();
        icpt.set_event_sink(Box::new(move |ev| {
            let _ = tx.send(json!({ "event": "proxy_event", "data": ev }));
        }));
    }
    let _ = tx.send(json!({
        "event": "ready",
        "session": opts.session_id,
        "port": port,
        "proxy": format!("http://127.0.0.1:{port}"),
        "store": opts.project_root.join(".bee/http"),
        "ca_bundle": ca_bundle,
        "enforcement": icpt.enforcement().label(),
        "enforcement_reason": ADVISORY_REASON,
        "tools": api::TOOL_NAMES,
    }));

    let ctx = Arc::new(Ctx {
        icpt: icpt.clone(),
        ca_bundle: ca_bundle.clone(),
        tx: tx.clone(),
    });
    let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        let line = match lines.next_line().await {
            Ok(Some(l)) => l,
            Ok(None) => break,
            Err(e) => {
                let _ = tx.send(json!({ "event": "error", "message": format!("stdin: {e}") }));
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        if line.len() > MAX_LINE {
            let _ = tx.send(error(Value::Null, "bad_request", "request line too long"));
            continue;
        }
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let _ = tx.send(error(Value::Null, "bad_request", &format!("not JSON: {e}")));
                continue;
            }
        };
        if req.get("op").and_then(Value::as_str) == Some("shutdown") {
            let _ = tx.send(json!({ "id": req.get("id").cloned().unwrap_or(Value::Null), "ok": true, "result": {} }));
            break;
        }
        let ctx = ctx.clone();
        tasks.spawn(async move {
            let id = req.get("id").cloned().unwrap_or(Value::Null);
            let resp = handle(&ctx, id, &req).await;
            let _ = ctx.tx.send(resp);
            for n in ctx.icpt.take_notices() {
                let _ = ctx.tx.send(json!({ "event": "notice", "text": n }));
            }
        });
    }
    tasks.shutdown().await;
    icpt.shutdown().await;
    if let Some(b) = &ca_bundle {
        let _ = std::fs::remove_file(b);
    }
    let _ = tx.send(Value::Null);
    let _ = writer.await;
    Ok(())
}

struct Ctx {
    icpt: Interceptor,
    ca_bundle: Option<std::path::PathBuf>,
    tx: mpsc::UnboundedSender<Value>,
}

async fn handle(ctx: &Ctx, id: Value, req: &Value) -> Value {
    let call_id = req
        .get("call_id")
        .and_then(Value::as_str)
        .unwrap_or("comb")
        .to_string();
    let wire = WireCtx {
        call_id: call_id.clone(),
        turn: req.get("turn").and_then(Value::as_u64).unwrap_or(0) as u32,
        origin: "tool".into(),
    };
    match req.get("op").and_then(Value::as_str).unwrap_or("") {
        "tools" => ok(id, json!(api::tools())),
        "call" => {
            let Some(tool) = req.get("tool").and_then(Value::as_str) else {
                return error(id, "bad_request", "`call` needs `tool`");
            };
            let args = req.get("args").cloned().unwrap_or(Value::Null);
            match api::call(&ctx.icpt, tool, args, &wire, &NoPayloadFiles).await {
                Ok(r) => ok(
                    id,
                    json!({ "text": r.text, "source": r.source, "is_error": r.is_error }),
                ),
                Err(e) => call_error(id, e),
            }
        }
        // A per-call credential for the client's own tools: route their traffic through the
        // proxy with this environment, then `revoke` when the call ends.
        "credential" => match ctx.icpt.issue(wire).await {
            Ok(token) => {
                let url = comb::client::proxy_url(ctx.icpt.port(), Some((&call_id, &token)));
                let env: serde_json::Map<String, Value> =
                    comb::client::child_env(&url, ctx.ca_bundle.as_deref())
                        .into_iter()
                        .map(|(k, v)| (k, Value::String(v)))
                        .collect();
                ok(
                    id,
                    json!({ "call_id": call_id, "proxy_url": url, "env": env }),
                )
            }
            Err(e) => error(id, "interceptor_unavailable", &e.to_string()),
        },
        "revoke" => {
            ctx.icpt.revoke(&call_id).await;
            let events = ctx.icpt.take_events(&call_id);
            ok(id, json!({ "call_id": call_id, "proxy_events": events }))
        }
        other => error(id, "bad_request", &format!("unknown op `{other}`")),
    }
}

fn ok(id: Value, result: Value) -> Value {
    json!({ "id": id, "ok": true, "result": result })
}

fn error(id: Value, code: &str, message: &str) -> Value {
    json!({ "id": id, "ok": false, "error": { "code": code, "message": message } })
}

fn call_error(id: Value, e: CallError) -> Value {
    match e {
        CallError::Op(OpError::Unavailable(m)) => error(id, "interceptor_unavailable", &m),
        CallError::Op(OpError::Invalid(m)) => error(id, "invalid_args", &m),
        CallError::Op(OpError::Failed(m)) => error(id, "failed", &m),
        CallError::Op(OpError::Refused { reason, note }) => {
            let refusal = match reason {
                Refusal::OutOfScope { host, port, layer } => {
                    json!({ "kind": "out_of_scope", "host": host, "port": port, "layer": layer })
                }
                Refusal::EgressOnly { host } => json!({ "kind": "egress_only", "host": host }),
                Refusal::LimitExceeded { limit, value } => {
                    json!({ "kind": "limit_exceeded", "limit": limit, "value": value })
                }
            };
            json!({ "id": id, "ok": false, "error": {
                "code": "refused", "message": note.unwrap_or_default(), "refusal": refusal } })
        }
        CallError::NotGranted { name } => error(id, "not_granted", &name),
        CallError::UnknownTool(n) => error(id, "unknown_tool", &n),
    }
}
