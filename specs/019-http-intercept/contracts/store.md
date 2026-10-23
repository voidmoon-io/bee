# Contract: `.bee/http/` store

Rationale: [research R8, R9](../research.md#r8--store-sqlite-index--content-addressed-body-blobs-harness-owned).

## Layout

```text
.bee/http/
├── index.sqlite          # WAL mode; busy_timeout 5 s; harness is the only writer per session
├── index.sqlite-wal
├── index.sqlite-shm
└── blobs/<aa>/<sha256>   # raw (still-encoded) body bytes; write temp + rename; immutable
```

Protected: `:project_root/.bee` is in `PROTECTED_DEFAULTS` (DENY) for every tool scope; the proxy
scope is compiled with read-deny on `:project_root` (and write-default-deny), so it cannot reach the
store either. Neither may read or write the store (FR-014).

## Schema (version 1)

```sql
CREATE TABLE meta      (key TEXT PRIMARY KEY, value TEXT NOT NULL);           -- schema_version=1
CREATE TABLE sessions  (id TEXT PRIMARY KEY, started TEXT, enforcement TEXT, policy_digest TEXT);
CREATE TABLE exchanges (
  id TEXT PRIMARY KEY, session_id TEXT NOT NULL, seq INTEGER NOT NULL,
  call_id TEXT, turn INTEGER, origin_kind TEXT NOT NULL, origin_path TEXT NOT NULL,
  parent_id TEXT, fuzz_run TEXT, rule_ids TEXT,
  scheme TEXT, host TEXT NOT NULL, port INTEGER NOT NULL, method TEXT, target TEXT,
  path TEXT, status INTEGER, tls TEXT, upstream_verified INTEGER,
  started TEXT NOT NULL, connect_ms INTEGER, ttfb_ms INTEGER, total_ms INTEGER,
  req_bytes INTEGER, resp_bytes INTEGER, resp_decoded INTEGER,
  req_head BLOB, resp_head BLOB, req_original_head BLOB,
  req_body TEXT, resp_body TEXT, req_original_body TEXT,   -- sha256 or NULL
  outcome TEXT NOT NULL, tags TEXT
);
CREATE INDEX ex_host_time  ON exchanges(host, started);
CREATE INDEX ex_status     ON exchanges(status);
CREATE INDEX ex_method     ON exchanges(method);
CREATE INDEX ex_call       ON exchanges(call_id);
CREATE INDEX ex_session    ON exchanges(session_id, seq);
CREATE INDEX ex_fuzz       ON exchanges(fuzz_run);
CREATE TABLE blobs     (sha256 TEXT PRIMARY KEY, len INTEGER, stored_len INTEGER, encoding TEXT,
                        truncated INTEGER, evicted INTEGER DEFAULT 0, last_ref TEXT);
CREATE TABLE tunnels   (id TEXT PRIMARY KEY, session_id TEXT, call_id TEXT, host TEXT, port INTEGER,
                        sni TEXT, started TEXT, ended TEXT, bytes_up INTEGER, bytes_down INTEGER, outcome TEXT);
CREATE TABLE refusals  (id INTEGER PRIMARY KEY, session_id TEXT, ts TEXT, call_id TEXT, kind TEXT,
                        host TEXT, port INTEGER, detail TEXT);
CREATE TABLE fuzz_runs (id TEXT PRIMARY KEY, session_id TEXT, call_id TEXT, spec TEXT, state TEXT,
                        planned INTEGER, sent INTEGER, refused INTEGER, failed INTEGER, summary TEXT);
CREATE TABLE leads     (id TEXT PRIMARY KEY, session_id TEXT, kind TEXT, summary TEXT,
                        exchange_ids TEXT, created TEXT, announced INTEGER DEFAULT 0,
                        listed INTEGER DEFAULT 0,     -- http_leads only_new
                        dedupe_key TEXT);             -- kind|host:port|path: repeats fold into one lead
```

## Rules

- Schema changes bump `meta.schema_version`; an unknown newer version → the store is opened
  read-only and the tools say so (never silently migrated down).
- Bodies > `max_body_bytes` are stored truncated with `blobs.truncated = 1`.
- When total blob bytes exceed `store_cap_bytes`, the least recently referenced blobs are evicted
  (`evicted = 1`, file removed) until under 90 % of the cap; an eviction summary is emitted as a
  `SessionEvent` and on the next tool result (never silent).
- Concurrent sessions: distinct `session_id`s; exchange ids embed a session short id, so ids never
  collide across sessions.
- Session CA material is **never** stored (SC-008).
