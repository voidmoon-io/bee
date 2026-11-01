//! Harness-owned tool receipts. A receipt proves what a tool returned, not that a claim is true.

use std::collections::BTreeSet;
use std::ffi::CString;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::findings::storage::Storage;
use crate::provider::ToolCall;
use crate::session::durable::{Attempt, ReceiptPublication, SessionId};
use crate::tools::ToolResult;

pub use crate::session::durable::MAX_RECEIPT_BYTES;
static NEXT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema_version: u32,
    pub session_id: String,
    pub sequence: u64,
    pub observed_at: String,
    pub call_id: String,
    pub tool: String,
    pub arguments: serde_json::Value,
    pub result: ToolResult,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<Attempt>,
}

#[derive(Debug, Clone)]
pub struct EvidenceStore {
    root: PathBuf,
    session_id: String,
    /// Durable only: receipt IDs the session store committed. A file on disk is not provenance;
    /// the sandbox may be able to write there, so a durable citation must name a committed ID.
    committed: Option<Arc<Mutex<BTreeSet<String>>>>,
}

impl EvidenceStore {
    /// Reattach only using the identity loaded from the owned durable session store.
    pub fn for_session(root: impl Into<PathBuf>, session: &SessionId) -> io::Result<Self> {
        if session.0.is_empty() || session.0.len() > 256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid session identity",
            ));
        }
        Ok(Self {
            root: root.into(),
            session_id: session.0.clone(),
            committed: Some(Arc::default()),
        })
    }

    /// Durable only: these IDs were committed by the owned session store and may be cited. The
    /// session driver calls this; a caller driving the store directly vouches for the same.
    pub fn admit_committed<'a>(&self, ids: impl IntoIterator<Item = &'a String>) {
        if let Some(committed) = &self.committed {
            let mut committed = committed.lock().expect("committed receipts lock");
            committed.extend(ids.into_iter().cloned());
        }
    }

    /// Durable only: an ID evicted from the bounded committed set is no longer citable.
    #[cfg(feature = "durable-sessions")]
    pub(crate) fn forget_committed(&self, id: &str) {
        if let Some(committed) = &self.committed {
            committed
                .lock()
                .expect("committed receipts lock")
                .remove(id);
        }
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn new(root: impl Into<PathBuf>, run_id: &str) -> Self {
        Self {
            root: root.into(),
            session_id: format!(
                "{run_id}:{}:{}:{}",
                std::process::id(),
                time::OffsetDateTime::now_utc().unix_timestamp_nanos(),
                NEXT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ),
            committed: None,
        }
    }

    pub fn record(&self, call: &ToolCall, result: &ToolResult) -> io::Result<String> {
        let receipt = Receipt {
            schema_version: 1,
            session_id: self.session_id.clone(),
            sequence: NEXT_SEQUENCE.fetch_add(1, Ordering::Relaxed),
            observed_at: time::OffsetDateTime::now_utc().to_string(),
            call_id: call.id.clone(),
            tool: call.name.clone(),
            arguments: call.arguments.clone(),
            result: result.clone(),
            attempt: None,
        };
        let bytes = serde_json::to_vec(&receipt)?;
        if bytes.len() > MAX_RECEIPT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "receipt exceeds size limit",
            ));
        }
        let id = format!("sha256:{:x}", Sha256::digest(&bytes));
        Storage::open(&self.root)?.publish_blob(&filename(&id)?, &bytes)?;
        Ok(id)
    }

    /// Pure preparation: persist these exact bytes with the result before publishing them.
    pub fn prepare(
        &self,
        attempt: &Attempt,
        call: &ToolCall,
        result: &ToolResult,
        observed_at: String,
    ) -> io::Result<ReceiptPublication> {
        if attempt.session.0 != self.session_id
            || attempt.number == 0
            || result.receipt_id.is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid receipt provenance",
            ));
        }
        let receipt = Receipt {
            schema_version: 2,
            session_id: self.session_id.clone(),
            sequence: attempt.operation.0,
            observed_at,
            call_id: call.id.clone(),
            tool: call.name.clone(),
            arguments: call.arguments.clone(),
            result: result.clone(),
            attempt: Some(attempt.clone()),
        };
        let bytes = serde_json::to_string(&receipt)?;
        let publication = ReceiptPublication {
            id: format!("sha256:{:x}", Sha256::digest(bytes.as_bytes())),
            bytes,
        };
        self.validate_prepared(&publication, attempt)?;
        Ok(publication)
    }

    pub fn validate_prepared(
        &self,
        publication: &ReceiptPublication,
        attempt: &Attempt,
    ) -> io::Result<Receipt> {
        let receipt = decode(&publication.id, publication.bytes.as_bytes())?;
        if receipt.session_id != self.session_id || receipt.attempt.as_ref() != Some(attempt) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "receipt belongs to a different session or attempt",
            ));
        }
        Ok(receipt)
    }

    /// Idempotently publish committed bytes; a conflicting existing blob is never overwritten.
    pub fn publish(&self, publication: &ReceiptPublication, attempt: &Attempt) -> io::Result<()> {
        self.validate_prepared(publication, attempt)?;
        Storage::open(&self.root)?
            .publish_blob(&filename(&publication.id)?, publication.bytes.as_bytes())
    }

    /// Delivery checks disk even after publication was acknowledged in an earlier activation.
    pub fn validate_published(
        &self,
        publication: &ReceiptPublication,
        attempt: &Attempt,
    ) -> io::Result<Receipt> {
        let receipt = self.validate_prepared(publication, attempt)?;
        let bytes = Storage::open(&self.root)?
            .read_blob(&filename(&publication.id)?, MAX_RECEIPT_BYTES as u64)?;
        if bytes != publication.bytes.as_bytes() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "published receipt differs from committed bytes",
            ));
        }
        Ok(receipt)
    }

    pub fn get(&self, id: &str) -> io::Result<Receipt> {
        let name = filename(id)?;
        let bytes = Storage::open(&self.root)?.read_blob(&name, MAX_RECEIPT_BYTES as u64)?;
        decode(id, &bytes)
    }

    pub fn validate_citations(&self, ids: &[String]) -> io::Result<()> {
        if ids.len() > 20 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "at most 20 evidence references are allowed",
            ));
        }
        for id in ids {
            let receipt = self.get(id)?;
            if receipt.session_id != self.session_id {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "evidence belongs to a different session",
                ));
            }
            let Some(committed) = &self.committed else {
                continue;
            };
            // The ID is the digest of the bytes, so a committed ID pins exactly what was observed.
            let known = committed
                .lock()
                .expect("committed receipts lock")
                .contains(id);
            if !known || receipt.schema_version != 2 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "evidence was not committed by this durable session",
                ));
            }
        }
        Ok(())
    }
}

fn decode(id: &str, bytes: &[u8]) -> io::Result<Receipt> {
    filename(id)?;
    if bytes.len() > MAX_RECEIPT_BYTES || format!("sha256:{:x}", Sha256::digest(bytes)) != id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "receipt size or digest mismatch",
        ));
    }
    let receipt: Receipt = serde_json::from_slice(bytes)?;
    let valid = match (receipt.schema_version, &receipt.attempt) {
        (1, None) => true,
        (2, Some(attempt)) => {
            attempt.session.0 == receipt.session_id
                && attempt.operation.0 == receipt.sequence
                && attempt.number > 0
                && receipt.result.receipt_id.is_none()
        }
        _ => false,
    };
    if !valid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported receipt version or invalid provenance",
        ));
    }
    Ok(receipt)
}

fn filename(id: &str) -> io::Result<CString> {
    let digest = id
        .strip_prefix("sha256:")
        .filter(|s| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid receipt id"))?;
    Ok(CString::new(format!("{digest}.json")).expect("hex filename"))
}
