//! The exchange store: `.bee/http/index.sqlite` plus content-addressed body blobs
//! (contracts/store.md, research R8).
//!
//! The harness is the only writer per session; the worker writes nothing to disk, and neither tool
//! children nor the proxy scope can open `.bee/` (`PROTECTED_DEFAULTS` and the proxy scope's
//! project read-deny — FR-014). Bodies are stored still-encoded, as they crossed the wire, under
//! `blobs/<aa>/<sha256>`; identical bodies share a file. When blob bytes exceed `store_cap_bytes`
//! the least recently referenced blobs are evicted — the file removed, the row kept and marked — and
//! the caller is told, never silently.

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use sha2::{Digest, Sha256};

use bee_core::policy::HttpLimits;

use super::control::{ExchangeRecord, ProxyEvent, TlsInfo, TunnelRecord};

/// The schema this build writes. A store carrying a newer one is opened read-only.
pub const SCHEMA_VERSION: u32 = 1;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta      (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions  (id TEXT PRIMARY KEY, started TEXT, enforcement TEXT, policy_digest TEXT);
CREATE TABLE IF NOT EXISTS exchanges (
  id TEXT PRIMARY KEY, session_id TEXT NOT NULL, seq INTEGER NOT NULL,
  call_id TEXT, turn INTEGER, origin_kind TEXT NOT NULL, origin_path TEXT NOT NULL,
  parent_id TEXT, fuzz_run TEXT, rule_ids TEXT,
  scheme TEXT, host TEXT NOT NULL, port INTEGER NOT NULL, method TEXT, target TEXT,
  path TEXT, status INTEGER, tls TEXT, upstream_verified INTEGER,
  started TEXT NOT NULL, connect_ms INTEGER, ttfb_ms INTEGER, total_ms INTEGER,
  req_bytes INTEGER, resp_bytes INTEGER, resp_decoded INTEGER,
  req_head BLOB, resp_head BLOB, req_original_head BLOB,
  req_body TEXT, resp_body TEXT, req_original_body TEXT,
  outcome TEXT NOT NULL, tags TEXT
);
CREATE INDEX IF NOT EXISTS ex_host_time ON exchanges(host, started);
CREATE INDEX IF NOT EXISTS ex_status    ON exchanges(status);
CREATE INDEX IF NOT EXISTS ex_method    ON exchanges(method);
CREATE INDEX IF NOT EXISTS ex_call      ON exchanges(call_id);
CREATE INDEX IF NOT EXISTS ex_session   ON exchanges(session_id, seq);
CREATE INDEX IF NOT EXISTS ex_fuzz      ON exchanges(fuzz_run);
CREATE TABLE IF NOT EXISTS blobs     (sha256 TEXT PRIMARY KEY, len INTEGER, stored_len INTEGER, encoding TEXT,
                                      truncated INTEGER, evicted INTEGER DEFAULT 0, last_ref TEXT);
CREATE TABLE IF NOT EXISTS tunnels   (id TEXT PRIMARY KEY, session_id TEXT, call_id TEXT, host TEXT, port INTEGER,
                                      sni TEXT, started TEXT, ended TEXT, bytes_up INTEGER, bytes_down INTEGER, outcome TEXT);
CREATE TABLE IF NOT EXISTS refusals  (id INTEGER PRIMARY KEY, session_id TEXT, ts TEXT, call_id TEXT, kind TEXT,
                                      host TEXT, port INTEGER, detail TEXT);
CREATE TABLE IF NOT EXISTS fuzz_runs (id TEXT PRIMARY KEY, session_id TEXT, call_id TEXT, spec TEXT, state TEXT,
                                      planned INTEGER, sent INTEGER, refused INTEGER, failed INTEGER, summary TEXT);
CREATE TABLE IF NOT EXISTS leads     (id TEXT PRIMARY KEY, session_id TEXT, kind TEXT, summary TEXT,
                                      exchange_ids TEXT, created TEXT, announced INTEGER DEFAULT 0);
"#;

/// The bytes of one exchange, as the worker's segments carry them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExchangeBytes {
    pub req_head: Vec<u8>,
    pub req_body: Vec<u8>,
    pub resp_head: Vec<u8>,
    pub resp_body: Vec<u8>,
    /// The request before an intercept rule rewrote it (US7).
    pub original: Option<(Vec<u8>, Vec<u8>)>,
}

impl ExchangeBytes {
    /// From an `exchange` frame's segments (contracts/proxy-control.md order). Missing segments are
    /// empty; an `original` pair is present only when the record says so.
    pub fn from_segments(mut segs: Vec<Vec<u8>>, has_original: bool) -> Self {
        segs.resize(if has_original { 6 } else { 4 }, Vec::new());
        let mut it = segs.into_iter();
        let mut next = || it.next().unwrap_or_default();
        let (req_head, req_body, resp_head, resp_body) = (next(), next(), next(), next());
        let original = if has_original {
            Some((next(), next()))
        } else {
            None
        };
        ExchangeBytes {
            req_head,
            req_body,
            resp_head,
            resp_body,
            original,
        }
    }
}

/// An exchange as stored: the row, with bodies as blob references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredExchange {
    pub id: String,
    pub session_id: String,
    pub seq: u64,
    pub call_id: Option<String>,
    pub turn: Option<u32>,
    pub origin_kind: String,
    pub origin_path: String,
    pub parent_id: Option<String>,
    pub fuzz_run: Option<String>,
    pub scheme: Option<String>,
    pub host: String,
    pub port: u16,
    pub method: Option<String>,
    pub target: Option<String>,
    pub path: Option<String>,
    pub status: Option<u16>,
    pub tls: Option<String>,
    pub upstream_verified: Option<bool>,
    pub started: String,
    pub connect_ms: Option<u64>,
    pub ttfb_ms: Option<u64>,
    pub total_ms: Option<u64>,
    pub req_bytes: Option<u64>,
    pub resp_bytes: Option<u64>,
    pub req_head: Vec<u8>,
    pub resp_head: Vec<u8>,
    pub req_original_head: Option<Vec<u8>>,
    pub req_body: Option<String>,
    pub resp_body: Option<String>,
    pub req_original_body: Option<String>,
    pub resp_body_truncated: bool,
    pub resp_body_evicted: bool,
    pub outcome: String,
    pub tags: Vec<String>,
}

/// What eviction removed since it was last reported. Surfaced to the operator and on the next tool
/// result — never silent (contracts/store.md).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvictionSummary {
    pub blobs: u64,
    pub bytes: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("exchange store: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("exchange store I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error(
        "exchange store has schema version {found}, newer than this build's {SCHEMA_VERSION}; \
         it is open read-only"
    )]
    ReadOnly { found: u32 },
}

/// One handle on the store. Each session opens its own; WAL lets them write concurrently.
pub struct Store {
    conn: Connection,
    dir: PathBuf,
    session_id: String,
    short: String,
    next_seq: u64,
    read_only: Option<u32>,
    limits: HttpLimits,
    eviction: Option<EvictionSummary>,
}

impl Store {
    /// Open (creating if needed) `<project_root>/.bee/http/`.
    pub fn open(
        project_root: &Path,
        session_id: &str,
        limits: &HttpLimits,
    ) -> Result<Store, StoreError> {
        let dir = project_root.join(".bee").join("http");
        create_dir(&project_root.join(".bee"), false)?;
        create_dir(&dir, true)?;
        create_dir(&dir.join("blobs"), true)?;
        let db = dir.join("index.sqlite");

        let conn = Connection::open(&db)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;

        // Version check before touching the schema: a newer store is never migrated down.
        let existing: Option<u32> = conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .unwrap_or(None)
            .and_then(|v| v.parse().ok());
        let (conn, read_only) = match existing {
            Some(v) if v > SCHEMA_VERSION => {
                drop(conn);
                let ro = Connection::open_with_flags(&db, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
                ro.busy_timeout(std::time::Duration::from_secs(5))?;
                (ro, Some(v))
            }
            _ => {
                conn.execute_batch(SCHEMA)?;
                conn.execute(
                    "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?1)",
                    params![SCHEMA_VERSION.to_string()],
                )?;
                (conn, None)
            }
        };

        let next_seq = conn
            .query_row(
                "SELECT COALESCE(MAX(seq), 0) FROM exchanges WHERE session_id = ?1",
                params![session_id],
                |r| r.get::<_, i64>(0),
            )
            .unwrap_or(0) as u64
            + 1;
        let store = Store {
            conn,
            dir,
            session_id: session_id.to_string(),
            short: short_id(session_id),
            next_seq,
            read_only,
            limits: *limits,
            eviction: None,
        };
        if store.read_only.is_none() {
            store.conn.execute(
                "INSERT OR IGNORE INTO sessions (id, started) VALUES (?1, ?2)",
                params![session_id, super::control::now_rfc3339()],
            )?;
        }
        Ok(store)
    }

    pub fn schema_version(&self) -> Result<u32, StoreError> {
        let v: String = self.conn.query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |r| r.get(0),
        )?;
        Ok(v.parse().unwrap_or(0))
    }

    /// Test hook: pretend a newer bee wrote this store.
    #[doc(hidden)]
    pub fn force_schema_version_for_test(&self, v: u32) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE meta SET value = ?1 WHERE key = 'schema_version'",
            params![v.to_string()],
        )?;
        Ok(())
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only.is_some()
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// The store's directory (`.bee/http`).
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The underlying connection, for the query layer.
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    fn writable(&self) -> Result<(), StoreError> {
        match self.read_only {
            Some(found) => Err(StoreError::ReadOnly { found }),
            None => Ok(()),
        }
    }

    /// Record an exchange and its bodies; returns its id, `E<session-short>-<seq>`.
    pub fn insert_exchange(
        &mut self,
        rec: &ExchangeRecord,
        bytes: &ExchangeBytes,
    ) -> Result<String, StoreError> {
        self.writable()?;
        let encoding = content_encoding(&bytes.resp_head);
        let req_body = self.put_blob(&bytes.req_body, rec.req_truncated, "identity")?;
        let resp_body = self.put_blob(&bytes.resp_body, rec.resp_truncated, &encoding)?;
        let (orig_head, orig_body) = match &bytes.original {
            Some((h, b)) => (Some(h.clone()), self.put_blob(b, false, "identity")?),
            None => (None, None),
        };

        let seq = self.next_seq;
        let id = format!("E{}-{}", self.short, seq);
        let path = rec.target.as_deref().map(path_of);
        let (tls, upstream_verified) = match &rec.tls {
            TlsInfo::None => ("none", None),
            TlsInfo::Tunnel => ("tunnel", None),
            TlsInfo::Inspected {
                upstream_verified, ..
            } => ("inspected", Some(*upstream_verified)),
            TlsInfo::Client { upstream_verified } => ("client", Some(*upstream_verified)),
        };
        self.conn.execute(
            "INSERT INTO exchanges (
               id, session_id, seq, call_id, turn, origin_kind, origin_path, parent_id, fuzz_run,
               rule_ids, scheme, host, port, method, target, path, status, tls, upstream_verified,
               started, connect_ms, ttfb_ms, total_ms, req_bytes, resp_bytes, resp_decoded,
               req_head, resp_head, req_original_head, req_body, resp_body, req_original_body,
               outcome, tags)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
                     ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, NULL, ?26, ?27, ?28, ?29, ?30, ?31,
                     ?32, ?33)",
            params![
                id,
                self.session_id,
                seq as i64,
                rec.call_id,
                rec.turn,
                rec.origin.kind.as_str(),
                rec.origin.path.as_str(),
                rec.origin.parent,
                rec.origin.fuzz_run,
                serde_json::to_string(&rec.origin.rule_ids).ok(),
                rec.scheme,
                rec.host,
                rec.port,
                rec.method,
                rec.target,
                path,
                rec.status,
                tls,
                upstream_verified,
                rec.timing.started,
                rec.timing.connect_ms.map(|v| v as i64),
                rec.timing.ttfb_ms.map(|v| v as i64),
                rec.timing.total_ms.map(|v| v as i64),
                rec.req_bytes as i64,
                rec.resp_bytes as i64,
                bytes.req_head,
                bytes.resp_head,
                orig_head,
                req_body,
                resp_body,
                orig_body,
                rec.outcome.label(),
                serde_json::to_string(&rec.tags).ok(),
            ],
        )?;
        self.next_seq += 1;
        self.evict_if_needed()?;
        Ok(id)
    }

    /// Record an uninspected tunnel; returns its id, `T<session-short>-<n>`.
    pub fn insert_tunnel(&mut self, t: &TunnelRecord) -> Result<String, StoreError> {
        self.writable()?;
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM tunnels WHERE session_id = ?1",
            params![self.session_id],
            |r| r.get(0),
        )?;
        let id = format!("T{}-{}", self.short, n + 1);
        self.conn.execute(
            "INSERT INTO tunnels (id, session_id, call_id, host, port, sni, started, ended,
                                  bytes_up, bytes_down, outcome)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                id,
                self.session_id,
                t.call_id,
                t.host,
                t.port,
                t.sni,
                t.started,
                t.ended,
                t.bytes_up as i64,
                t.bytes_down as i64,
                t.outcome
            ],
        )?;
        Ok(id)
    }

    /// Record a proxy-layer refusal (research R14).
    pub fn insert_refusal(&mut self, ev: &ProxyEvent) -> Result<(), StoreError> {
        self.writable()?;
        self.conn.execute(
            "INSERT INTO refusals (session_id, ts, call_id, kind, host, port, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                ev.session_id,
                ev.ts,
                ev.call_id,
                ev.kind.as_str(),
                ev.host,
                ev.port,
                ev.detail.to_string()
            ],
        )?;
        Ok(())
    }

    pub fn get_exchange(&self, id: &str) -> Result<Option<StoredExchange>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT e.id, e.session_id, e.seq, e.call_id, e.turn, e.origin_kind, e.origin_path,
                        e.parent_id, e.fuzz_run, e.scheme, e.host, e.port, e.method, e.target,
                        e.path, e.status, e.tls, e.upstream_verified, e.started, e.connect_ms,
                        e.ttfb_ms, e.total_ms, e.req_bytes, e.resp_bytes, e.req_head, e.resp_head,
                        e.req_original_head, e.req_body, e.resp_body, e.req_original_body,
                        COALESCE(b.truncated, 0), COALESCE(b.evicted, 0), e.outcome, e.tags
                 FROM exchanges e LEFT JOIN blobs b ON b.sha256 = e.resp_body
                 WHERE e.id = ?1",
                params![id],
                |r| {
                    Ok(StoredExchange {
                        id: r.get(0)?,
                        session_id: r.get(1)?,
                        seq: r.get::<_, i64>(2)? as u64,
                        call_id: r.get(3)?,
                        turn: r.get(4)?,
                        origin_kind: r.get(5)?,
                        origin_path: r.get(6)?,
                        parent_id: r.get(7)?,
                        fuzz_run: r.get(8)?,
                        scheme: r.get(9)?,
                        host: r.get(10)?,
                        port: r.get(11)?,
                        method: r.get(12)?,
                        target: r.get(13)?,
                        path: r.get(14)?,
                        status: r.get(15)?,
                        tls: r.get(16)?,
                        upstream_verified: r.get(17)?,
                        started: r.get(18)?,
                        connect_ms: r.get::<_, Option<i64>>(19)?.map(|v| v as u64),
                        ttfb_ms: r.get::<_, Option<i64>>(20)?.map(|v| v as u64),
                        total_ms: r.get::<_, Option<i64>>(21)?.map(|v| v as u64),
                        req_bytes: r.get::<_, Option<i64>>(22)?.map(|v| v as u64),
                        resp_bytes: r.get::<_, Option<i64>>(23)?.map(|v| v as u64),
                        req_head: r.get::<_, Option<Vec<u8>>>(24)?.unwrap_or_default(),
                        resp_head: r.get::<_, Option<Vec<u8>>>(25)?.unwrap_or_default(),
                        req_original_head: r.get(26)?,
                        req_body: r.get(27)?,
                        resp_body: r.get(28)?,
                        req_original_body: r.get(29)?,
                        resp_body_truncated: r.get::<_, i64>(30)? != 0,
                        resp_body_evicted: r.get::<_, i64>(31)? != 0,
                        outcome: r.get(32)?,
                        tags: r
                            .get::<_, Option<String>>(33)?
                            .and_then(|t| serde_json::from_str(&t).ok())
                            .unwrap_or_default(),
                    })
                },
            )
            .optional()?)
    }

    /// Whether an exchange id exists (finding evidence refs, US8).
    pub fn exchange_exists(&self, id: &str) -> Result<bool, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT 1 FROM exchanges WHERE id = ?1", params![id], |_| {
                Ok(())
            })
            .optional()?
            .is_some())
    }

    /// A blob's bytes, or `None` when it has been evicted (or never existed).
    pub fn read_blob(&self, sha: &str) -> Result<Option<Vec<u8>>, StoreError> {
        if !is_hex_sha(sha) {
            return Ok(None);
        }
        match std::fs::read(self.blob_path(sha)) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// A blob's recorded metadata.
    pub fn blob_meta(&self, sha: &str) -> Result<Option<BlobMeta>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT len, stored_len, encoding, truncated, evicted FROM blobs WHERE sha256 = ?1",
                params![sha],
                |r| {
                    Ok(BlobMeta {
                        len: r.get::<_, i64>(0)? as u64,
                        stored_len: r.get::<_, i64>(1)? as u64,
                        encoding: r.get(2)?,
                        truncated: r.get::<_, i64>(3)? != 0,
                        evicted: r.get::<_, i64>(4)? != 0,
                    })
                },
            )
            .optional()?)
    }

    pub fn count_exchanges(&self) -> Result<u64, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM exchanges", [], |r| r.get::<_, i64>(0))?
            as u64)
    }

    pub fn count_refusals(&self) -> Result<u64, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM refusals", [], |r| r.get::<_, i64>(0))?
            as u64)
    }

    /// Bytes held by non-evicted blobs.
    pub fn blob_bytes(&self) -> Result<u64, StoreError> {
        Ok(self.conn.query_row(
            "SELECT COALESCE(SUM(stored_len), 0) FROM blobs WHERE evicted = 0",
            [],
            |r| r.get::<_, i64>(0),
        )? as u64)
    }

    /// The eviction summary since the last call, if any blob was evicted.
    pub fn take_eviction_summary(&mut self) -> Option<EvictionSummary> {
        self.eviction.take()
    }

    fn blob_path(&self, sha: &str) -> PathBuf {
        self.dir.join("blobs").join(&sha[..2]).join(sha)
    }

    /// Store `body` content-addressed; `None` for an empty body. Bodies over `max_body_bytes` are
    /// stored truncated and flagged.
    fn put_blob(
        &mut self,
        body: &[u8],
        already_truncated: bool,
        encoding: &str,
    ) -> Result<Option<String>, StoreError> {
        if body.is_empty() {
            return Ok(None);
        }
        let cap = usize::try_from(self.limits.max_body_bytes).unwrap_or(usize::MAX);
        let (stored, truncated) = if body.len() > cap {
            (&body[..cap], true)
        } else {
            (body, already_truncated)
        };
        let sha = hex(&Sha256::digest(stored));
        let path = self.blob_path(&sha);
        if !path.exists() {
            let shard = path.parent().expect("blob path has a shard");
            create_dir(shard, true)?;
            let tmp = shard.join(format!(".{sha}.{}.tmp", std::process::id()));
            std::fs::write(&tmp, stored)?;
            std::fs::rename(&tmp, &path)?;
        }
        self.conn.execute(
            "INSERT INTO blobs (sha256, len, stored_len, encoding, truncated, evicted, last_ref)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)
             ON CONFLICT(sha256) DO UPDATE SET evicted = 0, last_ref = ?6,
               truncated = MAX(truncated, excluded.truncated)",
            params![
                sha,
                body.len() as i64,
                stored.len() as i64,
                encoding,
                truncated as i64,
                super::control::now_rfc3339()
            ],
        )?;
        Ok(Some(sha))
    }

    /// Evict least recently referenced blobs until under 90% of the cap.
    fn evict_if_needed(&mut self) -> Result<(), StoreError> {
        let cap = self.limits.store_cap_bytes;
        let mut total = self.blob_bytes()?;
        if total <= cap {
            return Ok(());
        }
        let target = cap / 10 * 9;
        let victims: Vec<(String, i64)> = {
            let mut stmt = self.conn.prepare(
                "SELECT sha256, stored_len FROM blobs WHERE evicted = 0
                 ORDER BY last_ref ASC, rowid ASC",
            )?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<Result<_, _>>()?
        };
        let mut summary = self
            .eviction
            .take()
            .unwrap_or(EvictionSummary { blobs: 0, bytes: 0 });
        for (sha, len) in victims {
            if total <= target {
                break;
            }
            match std::fs::remove_file(self.blob_path(&sha)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            self.conn.execute(
                "UPDATE blobs SET evicted = 1 WHERE sha256 = ?1",
                params![sha],
            )?;
            total = total.saturating_sub(len as u64);
            summary.blobs += 1;
            summary.bytes += len as u64;
        }
        self.eviction = Some(summary);
        Ok(())
    }
}

/// A blob's recorded metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobMeta {
    /// Wire length before any truncation.
    pub len: u64,
    pub stored_len: u64,
    /// `Content-Encoding` the body was stored with (still encoded).
    pub encoding: String,
    pub truncated: bool,
    pub evicted: bool,
}

/// The path part of a request-target: absolute-form `http://h/p?q` → `/p`, origin-form `/p?q` → `/p`.
pub fn path_of(target: &str) -> String {
    let rest = match target.split_once("://") {
        Some((_, after)) => match after.find('/') {
            Some(i) => &after[i..],
            None => "/",
        },
        None => target,
    };
    let end = rest.find(['?', '#']).unwrap_or(rest.len());
    rest[..end].to_string()
}

/// `Content-Encoding` of a response head, lowercased; `identity` when absent.
pub fn content_encoding(head: &[u8]) -> String {
    let text = String::from_utf8_lossy(head);
    for line in text.split('\n').skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-encoding") {
                return v.trim().to_ascii_lowercase();
            }
        }
    }
    "identity".into()
}

/// 8 hex characters identifying a session within ids.
///
/// FNV-1a: stable across builds (unlike `DefaultHasher`) and dependency-free. A collision between two
/// sessions' ids would fail the primary key loudly; it can never merge two exchanges silently.
fn short_id(session_id: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in session_id.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{:08x}", h as u32)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn is_hex_sha(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Create `p` with mode 0700. `private` dirs (the store's own) are tightened if they already exist;
/// `.bee/` itself is shared with the finding ledger and left as the operator made it.
fn create_dir(p: &Path, private: bool) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    match std::fs::DirBuilder::new().mode(0o700).create(p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            if private {
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))?;
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_of_strips_query_and_authority() {
        assert_eq!(path_of("/a/b?x=1"), "/a/b");
        assert_eq!(path_of("http://h:80/a?x"), "/a");
        assert_eq!(path_of("http://h"), "/");
        assert_eq!(path_of("/a#frag"), "/a");
    }

    #[test]
    fn content_encoding_is_read_case_insensitively() {
        assert_eq!(
            content_encoding(b"HTTP/1.1 200 OK\r\ncontent-ENCODING: GZip\r\n\r\n"),
            "gzip"
        );
        assert_eq!(content_encoding(b"HTTP/1.1 200 OK\r\n\r\n"), "identity");
    }

    #[test]
    fn segments_map_to_bytes_in_contract_order() {
        let b = ExchangeBytes::from_segments(
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()],
            false,
        );
        assert_eq!(
            (b.req_head, b.req_body, b.resp_head, b.resp_body),
            (b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec())
        );
        assert!(b.original.is_none());
        let short = ExchangeBytes::from_segments(vec![b"h".to_vec()], true);
        assert_eq!(short.original, Some((vec![], vec![])));
    }
}
