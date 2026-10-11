# Data Model: Agent-First HTTP(S) Interception

**Feature**: [spec.md](./spec.md) · **Research**: [research.md](./research.md)

Types are grouped by the crate that owns them. `bee-core` gains only data and pure logic (no new
dependencies, Constitution V). Everything else lives in the application package behind the
`intercept` feature.

---

## bee-core

### `HttpPolicy` (in `Policy`, section `[policy.http]`)

| Field | Type | Default | Meaning |
|---|---|---|---|
| `targets` | `Vec<HostPort>` | `[]` | Hosts that may be **tested**. Non-empty ⇔ interception is active. |
| `egress` | `Vec<HostPort>` | `[]` | Hosts that may be **reached** through the proxy as tunnels only; refused by model-originated tools. |
| `inspect` | `Vec<HostPattern>` | `[]` | Hosts (subset of `targets`) whose TLS is decrypted. |
| `insecure_upstream` | `Vec<HostPattern>` | `[]` | Hosts (subset of `inspect`) whose upstream certificate is not verified. |
| `limits` | `HttpLimits` | see below | Pacing and volume. |

`HostPort` = `host:port` where host is a DNS name or IP literal, port a single `u16` — the same
shape as `network.allow` (`crates/core/src/compiler.rs:253`). `HostPattern` = exact name or
`*.suffix` (wildcard never matches the apex), case-insensitive, trailing dot ignored — the
`DomainPattern` semantics already used for MCP (`src/mcp/policy.rs:11-70`), lifted into core.

`HttpLimits`:

| Field | Type | Default | Ceiling semantics |
|---|---|---|---|
| `rps` | `u32` | 10 | child ≤ parent |
| `concurrency` | `u32` | 4 | child ≤ parent |
| `max_requests_per_run` | `u32` | 2 000 | child ≤ parent |
| `max_body_bytes` | `u64` | 16 MiB | child ≤ parent; larger bodies stored truncated + flagged |
| `store_cap_bytes` | `u64` | 2 GiB | child ≤ parent |

**Validation** (compile errors, all fail closed):
- `deny_unknown_fields` on `HttpPolicy` and `HttpLimits`.
- `inspect ⊆ targets` (each pattern must match at least one target host); `insecure_upstream ⊆ inspect`.
- A host may not appear in both `targets` and `egress`.
- `targets` non-empty **and** `network.allow` non-empty → error naming both (research R4).
- Every `targets`/`egress` entry must resolve (`Resolver::resolve_host`); unresolvable → error.
- No limit may be zero.

### Attenuation rules

Added to `crates/core/src/attenuation.rs`, property-tested (Constitution II):
- `child.targets ⊆ parent.targets` (exact `HostPort` equality, as for `network.allow`).
- `child.egress ⊆ parent.egress ∪ parent.targets`.
- `child.inspect`: every child pattern must be covered by a parent pattern; `*.a.b` covers `x.a.b`
  and `*.x.a.b`; an exact name never covers a wildcard. Undecidable → reject.
- `child.insecure_upstream` likewise ⊆ parent.
- Every `child.limits.*` ≤ parent's.
- An **absent** child `[policy.http]` inherits the parent's (consistent with the f012 fix for
  `network.allow`, `attenuation.rs:130-133`) — never "no limits".

### `CompiledHttp`

Output of compiling `HttpPolicy` against a `Resolver`:

```text
CompiledHttp {
  proxy_scope: CompiledPolicy,   // network = resolve(targets ∪ egress); fs = write-default-deny + read-deny project/home/creds (research R2); exec = bee binary
  http_scope:  HttpScope,        // what the worker enforces in user space
}

HttpScope {
  targets:  Vec<ScopeEntry>,     // { host, port, resolved: Vec<IpAddr>, role: Target }
  egress:   Vec<ScopeEntry>,     //   role: Egress
  inspect:  Vec<HostPattern>,
  insecure_upstream: Vec<HostPattern>,
  limits:   HttpLimits,
}
```

Each `ScopeEntry` carries `enforced_by: [Kernel(ip,port)…, Proxy(host)]` so `http_scope` can label
every rule with its layer (FR-011).

---

## Application package (`src/intercept/`, `src/tools/http.rs`)

### `CallContext` / `CallCredential`

```text
CallContext   { call_id: String, turn: u32, origin: CallOrigin }   // CallOrigin = Tool | Mcp(server) | Fuzz(run_id)
CallCredential{ token: [u8;16], ctx: CallContext, issued_at, revoked_at: Option<ts> }
```

State: `Issued → Revoked`. A credential used after `Revoked` → `refused_bad_credential`. Tokens are
never written to the store or transcript; exchanges reference `call_id` only.

### `Exchange`

| Field | Notes |
|---|---|
| `id` | `E<session-short>-<seq>`; monotonically increasing per session; the handle every tool uses |
| `session_id`, `call_id`, `turn` | Attribution (FR-008, FR-013) |
| `origin` | `{ kind: tool \| replay \| fuzz \| forwarded, path: raw \| forwarded, parent: Option<ExchangeId>, fuzz_run: Option<RunId>, rule_ids: Vec<RuleId> }` |
| `scheme`, `host`, `port`, `method`, `target` | `target` = request-target as sent (path + query, or absolute-form) |
| `req_head` | Raw request head bytes as sent (byte-exact for `path = raw`) |
| `req_body` | `BlobRef?` |
| `req_original` | `Option<{ head, body }>` when an intercept rule modified the request (US7 acc. 1) |
| `status`, `resp_head`, `resp_body` | `BlobRef?`; absent when refused or failed |
| `tls` | `None \| Tunnel \| Inspected { sni, upstream_verified: bool }` |
| `timing` | `{ started, connect_ms, ttfb_ms, total_ms }` |
| `sizes` | `{ req_bytes, resp_bytes, resp_decoded: Option<u64> }` |
| `outcome` | `Completed \| Refused(ProxyEventKind) \| Failed(reason) \| Truncated` |
| `tags` | model- or system-applied labels (`fuzz`, `noise-probe`, …) |

### `BlobRef`

`{ sha256, len, stored_len, encoding: identity|gzip|deflate|br|zstd, truncated: bool, evicted: bool }`.
Content-addressed; identical bodies share a file. Eviction removes the file and sets `evicted`; the
exchange row stays (spec edge case "store growth").

### `TunnelRecord`

`{ id, call_id, host, port, sni, started, ended, bytes_up, bytes_down, outcome }` — for uninspected
TLS (FR-024).

### `ProxyEvent` (research R14)

`{ ts, session_id, call_id?, layer: "proxy", kind, host, port, detail }`. `kind` is one of
`refused_out_of_scope`, `refused_sni_mismatch`, `refused_bad_credential`, `refused_egress_only`,
`refused_limit`, `refused_address_drift` (with `detail = { now_resolves_to, compiled }`), `rule_fired`,
`held` and `auto_forwarded`. Never merged with kernel `AuditEvent`.

### `FuzzRun`

```text
FuzzRun { id, template: ExchangeId | RawTemplate, positions: Vec<Marker>, payload_sets: Vec<PayloadSet>,
          mode: sniper | battering_ram | pitchfork | cluster_bomb,
          limits: HttpLimits (effective), state, counts { planned, sent, refused, failed } }
PayloadSet = Builtin(name) | Range{from,to,step} | Inline(Vec<String>) | ProjectFile(path)
```

State: `Planned → Running → (Completed | Cancelled | Failed)`. `Planned` is rejected (never `Running`)
when `planned > limits.max_requests_per_run`. `ProjectFile` is read by a scoped worker
(`bee search-worker`-style read through the tool scope), never by the harness — it is a project file
(016 rule).

### `ClusterSummary`

`{ run_id, groups: Vec<{ key: {status, length_bucket, word_bucket, reflected, slow}, size, outlier: bool,
samples: Vec<ExchangeId> (≤3) }>, omitted_groups: u32 }`.

### `InterceptRule`

```text
InterceptRule { id, matcher: { host?, method?, path_prefix?, path_regex?, header_present?, body_contains? },
                action: Modify(Vec<Edit>) | Drop | Hold { timeout_s (default 30, max 300) },
                hits: u32, created_by_call }
```

Lifetime: worker memory, session only (FR-022). A `HeldRequest { hold_id, exchange_draft, deadline }`
transitions `Held → (Forwarded | ForwardedEdited | Dropped | AutoForwarded)`.

### `Edit` (shared by replay and rules)

`SetHeader{name,value}` · `RemoveHeader{name}` · `SetQuery{name,value}` · `RemoveQuery{name}` ·
`SetPath{value}` · `SetMethod{value}` · `JsonSet{pointer,value}` · `JsonRemove{pointer}` ·
`FormSet{name,value}` · `Replace{in: head|body, find, replace, regex: bool}` · `SetBody{text|base64}`.

### `Lead`

`{ id, kind, exchange_ids, summary (≤200 chars, from bee's own template — never target text),
created_at, announced: bool }`. Never written to the finding ledger.

### `GrantDelta` (extended, `src/grants/mod.rs:30-35`)

Adds `http_targets: Vec<HostPort>`. Folding: unions into the **target-scope** `ActivePolicy`.
`GrantRequest` (`src/skills/grant.rs:25-32`) gains `net`, `exec`, `http_targets` display fields
(research R13).

### `Finding` evidence (extended, `src/findings.rs`)

`Observed` events gain `evidence_refs: Vec<String>` with entries `http:<ExchangeId>`. Size stays within
`MAX_EVENT_BYTES` (4000) because only ids are stored. Review resolves each ref against the store;
missing → reported as `missing` (FR-027).

### `ToolResult.provenance` (research R12)

`Harness | Child | Remote { source: String }`.

---

## Relationships

```text
Session 1─* CallContext 1─* Exchange *─1 BlobRef (req/resp, shared)
                 │              │
                 │              ├─ parent ─> Exchange (replay / noise probe)
                 │              └─ fuzz_run ─> FuzzRun 1─1 ClusterSummary
                 ├─* TunnelRecord
                 └─* ProxyEvent
Exchange *─* Lead
Finding.evidence_refs ─> Exchange (by id, may dangle → "missing")
HttpPolicy ─compile─> CompiledHttp{ proxy_scope (kernel), http_scope (worker) }
```
