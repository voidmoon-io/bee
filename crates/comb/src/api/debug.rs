//! `http_debug` — **VM-test builds only** (019 T048). Asks the proxy worker to `connect` or `open`
//! from inside the proxy scope and reports the errno, so the VM matrix can show the kernel confines
//! the proxy itself. It exists in no shipping build: the control frames it sends do not decode
//! outside `vm-test` (asserted in `control.rs`).

use serde_json::{json, Value};

use super::{CallError, Reply, ToolDef};
use crate::ops::OpError;
use crate::sidecar::Interceptor;

pub(super) fn def() -> ToolDef {
    ToolDef {
        name: "http_debug",
        description: "VM-test only: probe the proxy scope with a raw connect or open.",
        parameters: json!({
            "type": "object",
            "properties": { "connect": { "type": "string" }, "read": { "type": "string" } }
        }),
    }
}

pub(super) async fn call(icpt: &Interceptor, args: &Value) -> Result<Reply, CallError> {
    let connect = args
        .get("connect")
        .and_then(Value::as_str)
        .map(str::to_string);
    let read = args.get("read").and_then(Value::as_str).map(str::to_string);
    let errno = icpt
        .debug_probe(connect, read)
        .await
        .map_err(|e| OpError::Failed(e.to_string()))?;
    Ok(Reply {
        text: format!("errno={errno}"),
        source: None,
        is_error: false,
    })
}
