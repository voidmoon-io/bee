//! Replay a stored request with edits, and measure the difference (019 T073, FR-035).
//!
//! With `noise_probe` the unmodified original is sent once more first; whatever differs between
//! original and probe is volatile and suppressed from the diff, reported as a count plus paths
//! (research R10). Both new exchanges are linked to the original by `parent`.

use std::time::Duration;

use serde_json::Value;

use super::{CallCtx, OpError};
use crate::intercept::control::{OriginKind, Outcome, RawTarget};
use crate::intercept::diff::{self, Edit, Side};
use crate::intercept::sidecar::Interceptor;

#[derive(Debug, Clone)]
pub struct ReplaySpec {
    /// The exchange to replay.
    pub id: String,
    pub edits: Vec<Edit>,
    pub noise_probe: bool,
    pub timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct ReplayResult {
    /// The edited exchange.
    pub id: String,
    /// The original.
    pub parent: String,
    /// The unmodified re-send, when a noise probe ran.
    pub probe: Option<String>,
    pub diff: Value,
}

/// Replay `spec.id` with its edits, and diff the response against the original's.
pub async fn replay(
    icpt: &Interceptor,
    ctx: &CallCtx,
    spec: ReplaySpec,
) -> Result<ReplayResult, OpError> {
    let id = spec.id.as_str();
    let (target, head, body) = stored_request(icpt, id)?;
    let mut original_bytes = head.clone();
    original_bytes.extend_from_slice(&body);

    let probe_id = if spec.noise_probe {
        let sent = icpt
            .send(
                target.clone(),
                original_bytes,
                ctx.clone(),
                OriginKind::Replay,
                Some(id.to_string()),
                vec!["noise-probe".into()],
                spec.timeout,
            )
            .await?;
        Some(sent.exchange_id)
    } else {
        None
    };

    let (new_head, new_body) =
        diff::apply_edits(&head, &body, &spec.edits).map_err(OpError::Invalid)?;
    let mut bytes = new_head;
    bytes.extend_from_slice(&new_body);
    let sent = icpt
        .send(
            target.clone(),
            bytes,
            ctx.clone(),
            OriginKind::Replay,
            Some(id.to_string()),
            Vec::new(),
            spec.timeout,
        )
        .await?;
    if let Outcome::Refused { kind } = &sent.record.outcome {
        return Err(OpError::Invalid(format!(
            "the replay was refused by the proxy ({}); edits cannot move a request out of scope",
            kind.as_str()
        )));
    }

    let original = side_of(icpt, id)?;
    let new = side_of(icpt, &sent.exchange_id)?;
    let probe_side = match &probe_id {
        Some(p) => Some(side_of(icpt, p)?),
        None => None,
    };
    Ok(ReplayResult {
        diff: diff::diff(&original, &new, probe_side.as_ref()),
        id: sent.exchange_id,
        parent: spec.id,
        probe: probe_id,
    })
}

/// The stored request `id` as raw head and body bytes, and where it went.
pub fn stored_request(
    icpt: &Interceptor,
    id: &str,
) -> Result<(RawTarget, Vec<u8>, Vec<u8>), OpError> {
    let e = icpt
        .with_store(|s| s.get_exchange(id))
        .map_err(|e| OpError::Failed(e.to_string()))?
        .ok_or_else(|| OpError::Invalid(format!("no exchange `{id}`")))?;
    let body = match &e.req_body {
        None => Vec::new(),
        Some(sha) => {
            let meta = icpt
                .with_store(|s| s.blob_meta(sha))
                .map_err(|e| OpError::Failed(e.to_string()))?;
            if meta.as_ref().is_some_and(|m| m.truncated) {
                return Err(OpError::Invalid(format!(
                    "the request body of {id} was stored truncated; it cannot be replayed exactly"
                )));
            }
            icpt.with_store(|s| s.read_blob(sha))
                .map_err(|e| OpError::Failed(e.to_string()))?
                .ok_or_else(|| OpError::Invalid(format!("the request body of {id} was evicted")))?
        }
    };
    let scheme = match e.tls.as_deref() {
        Some("inspected") | Some("client") => "https",
        _ => e.scheme.as_deref().unwrap_or("http"),
    };
    Ok((
        RawTarget {
            scheme: scheme.to_string(),
            host: e.host.clone(),
            port: e.port,
        },
        e.req_head.clone(),
        body,
    ))
}

/// The response side of exchange `id`, decoded, for the diff.
pub fn side_of(icpt: &Interceptor, id: &str) -> Result<Side, OpError> {
    let e = icpt
        .with_store(|s| s.get_exchange(id))
        .map_err(|e| OpError::Failed(e.to_string()))?
        .ok_or_else(|| OpError::Invalid(format!("no exchange `{id}`")))?;
    let body = match &e.resp_body {
        None => Vec::new(),
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
            crate::intercept::slice::decode(&raw, &enc, 4 * 1024 * 1024)
                .map(|d| d.bytes)
                .unwrap_or(raw)
        }
    };
    Ok(Side {
        status: e.status,
        head: e.resp_head,
        body,
        elapsed_ms: e.total_ms,
    })
}
