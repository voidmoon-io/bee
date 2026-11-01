//! Bounded opaque continuations in the session's private SQLite database.
use super::*;
use crate::session::durable::composition::{CheckpointRef, MAX_CHECKPOINT_BYTES};

const MAX_CHECKPOINTS: i64 = 1024;
const MAX_TOTAL_BYTES: i64 = 64 * 1024 * 1024;
pub(super) const SCHEMA: &str = "CREATE TABLE checkpoints (
    digest TEXT PRIMARY KEY, bytes BLOB NOT NULL
) STRICT;";

impl Store {
    /// Store bytes before proposing a Script::Suspend transition. An unreferenced blob is safe;
    /// a child cannot be admitted by commit unless its referenced bytes are already present.
    /// Only a trusted runtime producer may supply bytes; this store does not authenticate Monty.
    pub fn put_checkpoint(
        &mut self,
        activation: ActivationId,
        bytes: &[u8],
    ) -> Result<CheckpointRef, StoreError> {
        let result = (|| {
            self.check()?;
            if activation != self.activation {
                return Err(StoreError::Stale);
            }
            if bytes.is_empty() || bytes.len() > MAX_CHECKPOINT_BYTES {
                return Err(StoreError::Limit);
            }
            let reference = CheckpointRef {
                sha256: format!("{:x}", Sha256::digest(bytes)),
                bytes: bytes.len() as u32,
            };
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let owner: String =
                tx.query_row("SELECT owner FROM session WHERE singleton=1", [], |r| {
                    r.get(0)
                })?;
            if owner != activation.0.to_string() {
                return Err(StoreError::Stale);
            }
            let snapshot = read_snapshot(&tx, &self.session)?;
            reclaim(&tx, &snapshot, &self.staged_checkpoints)?;
            let existing: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT bytes FROM checkpoints WHERE digest=?1",
                    [&reference.sha256],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(existing) = existing {
                if existing != bytes {
                    return Err(StoreError::Corrupt);
                }
            } else {
                let (count, total): (i64, i64) = tx.query_row(
                    "SELECT count(*), coalesce(sum(length(bytes)),0) FROM checkpoints",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                if count >= MAX_CHECKPOINTS || total + bytes.len() as i64 > MAX_TOTAL_BYTES {
                    return Err(StoreError::Limit);
                }
                tx.execute(
                    "INSERT INTO checkpoints(digest,bytes) VALUES(?1,?2)",
                    params![reference.sha256, bytes],
                )?;
            }
            tx.commit()?;
            self.staged_checkpoints.insert(reference.sha256.clone());
            self.directory.verify()?;
            Ok(reference)
        })();
        self.finish(result)
    }

    pub fn load_checkpoint(&mut self, reference: &CheckpointRef) -> Result<Vec<u8>, StoreError> {
        let result = self.check().and_then(|_| read(&self.conn, reference));
        self.finish(result)
    }
}

fn read(conn: &Connection, reference: &CheckpointRef) -> Result<Vec<u8>, StoreError> {
    reference.validate().map_err(|_| StoreError::InvalidInput)?;
    let size: Option<i64> = conn
        .query_row(
            "SELECT length(bytes) FROM checkpoints WHERE digest=?1",
            [&reference.sha256],
            |r| r.get(0),
        )
        .optional()?;
    if size != Some(i64::from(reference.bytes)) {
        return Err(StoreError::Corrupt);
    }
    let bytes: Vec<u8> = conn.query_row(
        "SELECT bytes FROM checkpoints WHERE digest=?1",
        [&reference.sha256],
        |r| r.get(0),
    )?;
    if format!("{:x}", Sha256::digest(&bytes)) != reference.sha256 {
        return Err(StoreError::Corrupt);
    }
    Ok(bytes)
}

pub(super) fn validate_references(
    conn: &Connection,
    snapshot: &Snapshot,
) -> Result<(), StoreError> {
    for reference in snapshot.required_checkpoints() {
        read(conn, reference)?;
    }
    Ok(())
}

/// Runs only under the writer's transaction. An interruption rolls back both
/// the snapshot transition and deletions, preserving the prior continuation.
pub(super) fn reclaim(
    conn: &Connection,
    snapshot: &Snapshot,
    staged: &std::collections::BTreeSet<String>,
) -> Result<(), StoreError> {
    let required: std::collections::BTreeSet<_> = snapshot
        .required_checkpoints()
        .map(|reference| reference.sha256.as_str())
        .collect();
    let digests = conn
        .prepare("SELECT digest FROM checkpoints LIMIT ?1")?
        .query_map([MAX_CHECKPOINTS + 1], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    if digests.len() > MAX_CHECKPOINTS as usize {
        return Err(StoreError::Corrupt);
    }
    for digest in digests {
        if !required.contains(digest.as_str()) && !staged.contains(&digest) {
            conn.execute("DELETE FROM checkpoints WHERE digest=?1", [&digest])?;
        }
    }
    Ok(())
}

impl Store {
    /// Release this owner's uncommitted staging protection. Live continuations
    /// remain protected by authoritative state even when they share this digest.
    pub fn abandon_checkpoint(
        &mut self,
        activation: ActivationId,
        reference: &CheckpointRef,
    ) -> Result<(), StoreError> {
        let result = (|| {
            self.check()?;
            if activation != self.activation {
                return Err(StoreError::Stale);
            }
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let owner: String =
                tx.query_row("SELECT owner FROM session WHERE singleton=1", [], |r| {
                    r.get(0)
                })?;
            if owner != activation.0.to_string() {
                return Err(StoreError::Stale);
            }
            let snapshot = read_snapshot(&tx, &self.session)?;
            let mut staged = self.staged_checkpoints.clone();
            staged.remove(&reference.sha256);
            reclaim(&tx, &snapshot, &staged)?;
            tx.commit()?;
            self.staged_checkpoints = staged;
            Ok(())
        })();
        self.finish(result)
    }
}
