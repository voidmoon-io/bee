//! Opt-in SQLite adapter. A successful commit is the only acknowledgement of persistence.
//! One Store owns one private session directory for its entire lifetime. All methods are
//! blocking; asynchronous callers must use a dedicated blocking owner, not hold runtime threads.

mod files;
pub mod journal;
#[cfg(test)]
mod tests;

use super::{
    validate_payload, validate_snapshot, ActivationId, Commit, CommitId, SessionId, Snapshot,
};
use files::Directory;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

const APPLICATION_ID: i64 = 0x42454553;
const STORE_VERSION: i64 = 5;
const MAX_SNAPSHOT_BYTES: usize = 256 * 1024 * 1024;
const MAX_SUBMISSIONS: i64 = 1024;
const SCHEMA_V1: &str = "CREATE TABLE session (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    session_id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>=0),
    snapshot BLOB NOT NULL, owner TEXT NOT NULL
) STRICT;
CREATE TABLE submissions (
    sequence INTEGER PRIMARY KEY CHECK(sequence>0), request_id TEXT NOT NULL UNIQUE,
    input BLOB NOT NULL, digest TEXT NOT NULL
) STRICT;
CREATE TABLE workers (operation INTEGER PRIMARY KEY CHECK(operation>0), payload BLOB NOT NULL, digest TEXT NOT NULL) STRICT;";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("session already has an active writer")]
    Locked,
    #[error(
        "session directory/files must be private, owned, regular, and free of links or traversal"
    )]
    UnsafePath,
    #[error("unsupported or foreign session database")]
    Unsupported,
    #[error("session identity does not match the stored session")]
    WrongSession,
    #[error("stale activation or revision")]
    Stale,
    #[error("request or commit identity conflicts with existing content")]
    Conflict,
    #[error("invalid or oversized input")]
    InvalidInput,
    #[error("session storage limit reached")]
    Limit,
    #[error("stored session data is corrupt or inconsistent")]
    Corrupt,
    #[error("store suspended after an uncertain storage failure; drop and reopen it")]
    Suspended,
    #[error("operating system randomness unavailable: {0}")]
    Entropy(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Submission {
    pub sequence: u64,
    pub request_id: String,
    pub input: Value,
    pub input_sha256: String,
}

pub struct Store {
    // Field order closes SQLite (and its WAL) before releasing the directory lock.
    conn: Connection,
    directory: Directory,
    session: SessionId,
    activation: ActivationId,
    suspended: bool,
}

impl Store {
    /// Opens an explicit absolute private directory. Does not activate or dispatch a session.
    pub fn open(path: &Path, session: SessionId) -> Result<Self, StoreError> {
        let empty = Snapshot::empty(session.clone());
        validate_snapshot(&empty).map_err(|_| StoreError::InvalidInput)?;
        let directory = Directory::open(path)?;
        let mut conn = Connection::open_with_flags(
            directory.database(),
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NOFOLLOW
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(std::time::Duration::ZERO)?;
        conn.set_db_config(rusqlite::config::DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
        conn.set_limit(
            rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
            (MAX_SNAPSHOT_BYTES + 4096) as i32,
        )?;
        conn.execute_batch(
            "PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON; PRAGMA temp_store=MEMORY;",
        )?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        let app: i64 = conn.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        let fresh = app == 0 && version == 0;
        if (!fresh && (app != APPLICATION_ID || version != STORE_VERSION))
            || (fresh
                && conn.query_row("SELECT count(*) FROM sqlite_schema", [], |r| {
                    r.get::<_, i64>(0)
                })? != 0)
        {
            return Err(StoreError::Unsupported);
        }
        let mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        if mode != "wal" {
            return Err(StoreError::Unsupported);
        }
        conn.execute_batch("PRAGMA synchronous=FULL; PRAGMA wal_autocheckpoint=1000; PRAGMA journal_size_limit=16777216;")?;
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|e| StoreError::Entropy(e.to_string()))?;
        let activation = ActivationId(u128::from_le_bytes(random));
        {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if fresh {
                tx.execute_batch(SCHEMA_V1)?;
                tx.execute(
                    "INSERT INTO session VALUES(1, ?1, 0, ?2, ?3)",
                    params![
                        session.0,
                        serde_json::to_vec(&empty)?,
                        activation.0.to_string()
                    ],
                )?;
                tx.pragma_update(None, "application_id", APPLICATION_ID)?;
                tx.pragma_update(None, "user_version", STORE_VERSION)?;
            } else {
                let stored: String = tx.query_row(
                    "SELECT session_id FROM session WHERE singleton=1",
                    [],
                    |r| r.get(0),
                )?;
                if stored != session.0 {
                    return Err(StoreError::WrongSession);
                }
                // Validate before claiming this activation; unsupported/corrupt snapshots never advance.
                read_snapshot(&tx, &session)?;
                tx.execute(
                    "UPDATE session SET owner=?1 WHERE singleton=1",
                    [activation.0.to_string()],
                )?;
            }
            tx.commit()?;
        }
        directory.verify()?;
        directory.sync()?;
        Ok(Self {
            conn,
            directory,
            session,
            activation,
            suspended: false,
        })
    }

    pub fn activation(&self) -> ActivationId {
        self.activation
    }
    pub fn is_suspended(&self) -> bool {
        self.suspended
    }

    fn check(&self) -> Result<(), StoreError> {
        if self.suspended {
            return Err(StoreError::Suspended);
        }
        self.directory.verify()
    }

    fn finish<T>(&mut self, result: Result<T, StoreError>) -> Result<T, StoreError> {
        if matches!(
            &result,
            Err(StoreError::Io(_)
                | StoreError::Sqlite(_)
                | StoreError::Json(_)
                | StoreError::Corrupt
                | StoreError::UnsafePath)
        ) {
            self.suspended = true;
        }
        result
    }

    pub fn load(&mut self) -> Result<Snapshot, StoreError> {
        let result = self
            .check()
            .and_then(|_| read_snapshot(&self.conn, &self.session));
        self.finish(result)
    }

    /// Stores the exact candidate atomically. On error the host must send CommitFailed
    /// to the core; it must never release the candidate's pending effects.
    pub fn commit(&mut self, commit: &Commit) -> Result<CommitId, StoreError> {
        let result = self.commit_inner(commit);
        self.finish(result)
    }

    fn commit_inner(&mut self, commit: &Commit) -> Result<CommitId, StoreError> {
        self.check()?;
        if commit.id.session != self.session || commit.snapshot.session != self.session {
            return Err(StoreError::WrongSession);
        }
        if commit.id.activation != self.activation {
            return Err(StoreError::Stale);
        }
        if commit.expected_revision.checked_add(1) != Some(commit.id.revision)
            || commit.id.revision != commit.snapshot.revision
            || commit.snapshot.activation != Some(self.activation)
        {
            return Err(StoreError::InvalidInput);
        }
        validate_snapshot(&commit.snapshot).map_err(|_| StoreError::InvalidInput)?;
        let revision = i64::try_from(commit.id.revision).map_err(|_| StoreError::Limit)?;
        let bytes = serde_json::to_vec(&commit.snapshot)?;
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(StoreError::Limit);
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (current, previous, owner): (i64, Vec<u8>, String) = tx.query_row(
            "SELECT revision, snapshot, owner FROM session WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        if owner != self.activation.0.to_string() {
            return Err(StoreError::Stale);
        }
        if current == revision {
            if previous != bytes {
                return Err(StoreError::Conflict);
            }
        } else {
            if u64::try_from(current).ok() != Some(commit.expected_revision) {
                return Err(StoreError::Stale);
            }
            tx.execute(
                "UPDATE session SET revision=?1, snapshot=?2 WHERE singleton=1",
                params![revision, bytes],
            )?;
        }
        tx.commit()?;
        self.directory.verify()?;
        Ok(commit.id.clone())
    }

    /// Acknowledges admission only after commit. The inbox is not a tool dispatcher.
    pub fn admit(&mut self, request_id: &str, input: &Value) -> Result<Submission, StoreError> {
        let result = self.admit_inner(request_id, input);
        self.finish(result)
    }

    fn admit_inner(&mut self, request_id: &str, input: &Value) -> Result<Submission, StoreError> {
        self.check()?;
        if request_id.is_empty() || request_id.len() > 256 {
            return Err(StoreError::InvalidInput);
        }
        validate_payload(input).map_err(|_| StoreError::InvalidInput)?;
        let bytes = serde_json::to_vec(&canonical(input))?;
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(i64, Vec<u8>, String)> = tx
            .query_row(
                "SELECT sequence, input, digest FROM submissions WHERE request_id=?1",
                [request_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let sequence = if let Some((sequence, original, stored_digest)) = existing {
            if stored_digest != format!("{:x}", Sha256::digest(&original)) {
                return Err(StoreError::Corrupt);
            }
            if bytes != original {
                return Err(StoreError::Conflict);
            }
            sequence
        } else {
            let count: i64 = tx.query_row("SELECT count(*) FROM submissions", [], |r| r.get(0))?;
            if count >= MAX_SUBMISSIONS {
                return Err(StoreError::Limit);
            }
            tx.execute(
                "INSERT INTO submissions(request_id,input,digest) VALUES(?1,?2,?3)",
                params![request_id, bytes, digest],
            )?;
            tx.last_insert_rowid()
        };
        tx.commit()?;
        self.directory.verify()?;
        Ok(Submission {
            sequence: u64::try_from(sequence).map_err(|_| StoreError::Corrupt)?,
            request_id: request_id.into(),
            input: input.clone(),
            input_sha256: digest,
        })
    }

    /// Ascending admission order, strictly after the cursor. Empty means no more admissions.
    pub fn submissions(&mut self, after: u64, limit: u32) -> Result<Vec<Submission>, StoreError> {
        let result = (|| {
            self.check()?;
            if !(1..=100).contains(&limit) {
                return Err(StoreError::InvalidInput);
            }
            let after = i64::try_from(after).map_err(|_| StoreError::InvalidInput)?;
            let mut statement = self.conn.prepare("SELECT sequence, request_id, input, digest FROM submissions WHERE sequence>?1 ORDER BY sequence LIMIT ?2")?;
            let mut rows = statement.query(params![after, limit])?;
            let mut result = Vec::new();
            while let Some(row) = rows.next()? {
                let sequence: i64 = row.get(0)?;
                let bytes: Vec<u8> = row.get(2)?;
                let digest: String = row.get(3)?;
                if bytes.len() > super::MAX_PAYLOAD_BYTES
                    || format!("{:x}", Sha256::digest(&bytes)) != digest
                {
                    return Err(StoreError::Corrupt);
                }
                result.push(Submission {
                    sequence: u64::try_from(sequence).map_err(|_| StoreError::Corrupt)?,
                    request_id: row.get(1)?,
                    input: serde_json::from_slice(&bytes)?,
                    input_sha256: digest,
                });
            }
            Ok(result)
        })();
        self.finish(result)
    }
}

fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let sorted: std::collections::BTreeMap<_, _> =
                map.iter().map(|(k, v)| (k.clone(), canonical(v))).collect();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(values) => Value::Array(values.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

fn read_snapshot(conn: &Connection, session: &SessionId) -> Result<Snapshot, StoreError> {
    let (revision, bytes): (i64, Vec<u8>) = conn.query_row(
        "SELECT revision, snapshot FROM session WHERE singleton=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(StoreError::Corrupt);
    }
    let snapshot: Snapshot = serde_json::from_slice(&bytes)?;
    validate_snapshot(&snapshot).map_err(|_| StoreError::Corrupt)?;
    if &snapshot.session != session || u64::try_from(revision).ok() != Some(snapshot.revision) {
        return Err(StoreError::Corrupt);
    }
    Ok(snapshot)
}
