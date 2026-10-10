# Phase 0 Research: Agent-First HTTP(S) Interception

**Feature**: [spec.md](./spec.md) · **Plan**: [plan.md](./plan.md) · **Date**: 2026-10-10

Every decision below is grounded in either the current tree (file:line on branch
`fix/f001-reload-transactional`, which is `main` + the F-001 reload fix) or crate metadata pulled
from crates.io on 2026-10-10. Behavioural claims about third-party crates that were not re-read from
source this session are marked *(from documentation)*.

---

## R1 — Proxy engine: hand-rolled on hyper 1.x, plus a raw HTTP/1.1 writer

**Decision**: Build the proxy on `hyper` 1.x (`http1::Builder` with `.with_upgrades()`),
`hyper-util` 0.1, `tokio-rustls` 0.26 / `rustls` 0.23, and `httparse` 1.10. Build a **separate raw
writer** — bee-formatted bytes written with `write_all` to a `TcpStream` / `TlsStream`, response
parsed incrementally with `httparse`, body framed by bee (Content-Length, chunked via
`httparse::parse_chunk_size`, read-to-close; 1xx/HEAD/204/304 handled) — and use it for every
request the *model* originates (`http_send`, `http_replay`, `http_fuzz`).

**Rationale**:
- Every one of these crates is already in `Cargo.lock` (hyper 1.10.1, hyper-util 0.1.20,
  rustls 0.23.42, tokio-rustls 0.26.4, httparse 1.10.1) through the optional `rmcp`/`reqwest` path, so
  an `intercept` build that also enables `mcp` adds no new versions.
- hyper and the `http` crate validate method, URI, header names and values, and impose their own
  framing. Malformed, duplicated-length, obs-fold or smuggling-shaped requests are **unrepresentable**
  through them. FR-018 requires byte-exact raw requests, so the model-originated path cannot go
  through hyper. Forwarded traffic from other tools *can* — a normalising forwarder is acceptable
  for traffic whose bytes the model did not author — and hyper's `preserve_header_case(true)` keeps
  casing on that path.
- Two paths are honest about which guarantee holds where: the raw path is byte-exact; the forwarding
  path is case-preserving but may reorder across header names. `http_get` reports which path
  produced an exchange (`origin.path = "raw" | "forwarded"`).

**Alternatives considered**:
- **hudsucker 0.25** (MSRV 1.86): good per-host MITM-or-tunnel hook (`should_intercept`), but routes
  everything through `HeaderMap` (lower-cased names, cross-name order lost, no case preservation),
  pools upstream connections, and adds moka, tungstenite and rand. Fine as a prototype; wrong for a
  pentest tool's replay path. Rejected.
- **Hyper for both paths**: rejected by FR-018 (above).
- **Raw writer for both paths**: rejected — re-implementing a correct, streaming, forward proxy server
  side by hand is the riskiest code in the feature and buys nothing for traffic the model did not
  author.

## R2 — Where the proxy runs: a scoped sidecar child, not the harness

**Decision**: The proxy is `bee proxy-worker`, a hidden subcommand (pattern: `bee search-worker`,
`src/main.rs:90`) spawned once per session as a **long-lived child in its own kernel scope** — the
*proxy scope* — created from the same `Engine` as the tool scope. Its network reach is the resolved
target scope. The harness never opens a socket to a target.

**Filesystem posture — what the kernel actually offers.** `file_open` is enforced from a per-scope
**deny list** (`FS_DENY`, `crates/ebpf/src/main.rs:220-222`; `fs_should_block`): reads are permitted
unless a rule denies them; writes can be made default-deny with `FLAG_FS_WRITE_DEFAULT_DENY`. There is
no "empty filesystem grant". A proxy worker compromised through its TLS/HTTP parsing could therefore
read anything the deny list does not cover and send it to an in-scope target. The proxy scope is
compiled with:
- `FLAG_FS_WRITE_DEFAULT_DENY` set (the worker writes nothing — R3);
- read-deny rules for `:project_root`, `$HOME`, `/root`, `/home`, and the protected credential
  directories already in `PROTECTED_DEFAULTS` (`crates/core/src/compiler.rs:179-184`);
- an **exact-path read rule for the worker binary itself** (`current_exe()`, canonicalised). `file_open`
  fires on exec, and the worker is exec'd after joining the scope. Dev builds (`target/debug/bee`
  under `:project_root`) and the VM matrix (`/home/ubuntu/bee`) both sit under denied prefixes, and
  without this rule the worker could not start. Rules are sorted most-specific-first and the first
  match decides (`crates/common/src/matcher.rs:74-93`), so the exact rule outranks the prefix denies
  without opening its siblings;
- nothing else denied, because the worker must still read the loader, libc, and
  `/etc/ssl` / `/etc/resolv.conf` / `/etc/hosts` / `/etc/nsswitch.conf` for resolution and roots.

This is documented as a **reduced** read surface, not an empty one, and a VM case
(`http-proxy-fs-deny`) proves the worker cannot read a file under `:project_root`. A true
allow-list file model is a kernel-side change outside this feature.

**Rationale**:
- Constitution III: the only component that talks to targets must itself be kernel-confined, or the
  proxy is a confused deputy with the harness's unscoped egress (threat-model T1).
- `Engine::create_scope` already supports many scopes per engine (`crates/userspace/src/lib.rs:113-177`;
  `src/concurrent.rs:178` does it per episode). What is missing is *ownership*: the session's engine
  is moved into `EnforcedSandbox` and is private (`src/sandbox.rs:58,153-166`).
- The long-lived child pattern exists: MCP stdio servers are spawned through `tool_command`,
  `kill_on_drop(true)`, and owned RAII-style by the bridge (`src/mcp/transport.rs:24-56`,
  `src/mcp/bridge.rs:93-100`). The proxy worker reuses it but joins the proxy scope via
  `Scope::join_closure()` (`lib.rs:350-355`) instead of the tool scope.

**Pre-018 mechanism (M1)**: `EnforcedSandbox` gains an optional **sidecar scope** created in
`build_sandbox` (`src/app/session.rs:296-330`) *before* the engine moves, holding its `Scope`, cgroup
id and `EnforcementPlan`. Three changes follow:
1. The synchronous audit drain stops discarding non-tool cgroups (`src/sandbox.rs:254-257`) and
   instead keeps events for the tool scope **and** the sidecar, tagging each with its scope label.
   Discarding proxy-scope denials would violate "a denial that is not recorded is not enforced".
2. `Sandbox::reload_sidecar(&CompiledPolicy)` calls `engine.reload_scope(sidecar_cgid, plan)`
   (transactional since F-001, `crates/userspace/src/reload.rs:72-150`).
3. Teardown order: proxy worker killed → sidecar scope removed → tool scope removed.

**Concurrent runner**: `Sandbox::Concurrent` cannot reload (`sandbox.rs:97`) and owns no engine. An
`intercept` session under the concurrent runner is **refused at construction** in M1–M3 (fail closed,
Constitution I) with a message pointing at 018.

**After 018**: the sidecar becomes an ordinary `ScopeRecord` under the Supervisor
(`specs/018-subagent-scopes/data-model.md:104-136`); the sidecar field is deleted. M4's per-subagent
proxy scopes (FR-031) are built only on the Supervisor and are blocked on 018. No 018 code exists
on any branch today; 019 M1 does not wait for it.

**Alternatives considered**:
- **Proxy inside the harness process**: no kernel confinement on the component with the most
  authority over targets. Rejected (Constitution III).
- **Proxy in the tool scope**: then tool children could reach targets directly (same cgroup, same
  NET_ALLOW). Rejected — defeats US1.
- **Wait for 018**: blocks the whole feature on an unimplemented restructuring. Rejected; the sidecar
  is a small, deletable bridge.

## R3 — Harness ↔ worker control channel

**Decision**: Length-prefixed JSON frames over the worker's stdin/stdout (stderr remains diagnostic).
The harness is the only peer. Model-facing tools run in the harness and ask the worker to send
(`send_raw`, `send_structured`, `fuzz_batch`); the worker reports every exchange back as an
`exchange` frame with bodies inline (length-prefixed binary segment, capped per R8). Full contract:
[contracts/proxy-control.md](./contracts/proxy-control.md).

**Rationale**: stdio is how MCP children already talk to bee; it needs no additional network rule,
no port, and no filesystem path. Because the worker writes nothing to disk, the proxy scope needs
no write grant — the store stays bee's harness-owned state (same reasoning as the findings ledger,
`src/findings.rs:26-30`).

**Alternatives considered**: a second loopback port for control (needs a NET rule from the harness —
which is unscoped anyway — and authentication, for nothing); a Unix socket (AF_UNIX `connect` is
denied by the hook, `crates/ebpf/src/main.rs:193-199`, and would need a carve-out).

## R4 — Port ordering and the tool scope's network rule

**Decision**: The **harness binds** `127.0.0.1:0` *before* compiling the tool policy, reads the
assigned port, and passes the listening socket to the worker as an inherited descriptor (fd 3, the
only non-stdio descriptor left open across exec; the worker refuses to start if fd 3 is not a
listening TCP socket on loopback). The tool scope's network rule is then synthesised as exactly
`127.0.0.1:<port>`.

**Rationale**:
- `resolve_host` accepts IP literals (`crates/userspace/src/resolve.rs:67-70`) and the hook is an
  exact `{cgroup, family, addr, port}` lookup (`crates/ebpf/src/main.rs:160-211`), so the rule is
  expressible today with no kernel change.
- Binding first removes the ordering problem (no ephemeral-port handling exists anywhere) and avoids
  a reload of the tool scope at session start.
- A non-empty tool-scope rule list sets `FLAG_NET_ENFORCED` (`crates/userspace/src/plan.rs:44-47`).
  This matters: an **empty** list means unenforced egress (F-004), so an `intercept` session can
  never accidentally run tool children with open network.
- Only IPv4 loopback is allowed. `::1` and `::ffff:127.0.0.1` do not match the v4 key and stay
  denied; `HTTP_PROXY` always names `127.0.0.1`.

**Interaction with existing `network.allow`** (decision): when a policy declares `[policy.http]`,
its tool-scope `network.allow` **must be empty** — compile error otherwise, naming both sections.
Non-target egress the session genuinely needs (package registries) is declared as
`[policy.http].egress`: reachable only through the proxy, as a tunnel, recorded, and **refused by
every model-originated tool** (`http_send`/`http_replay`/`http_fuzz`). Everything leaves through one
gate, and "may be tested" stays distinct from "may be reached".

## R5 — Policy schema: `[policy.http]` in bee-core

**Decision**: Add `HttpPolicy` to `bee-core` (`crates/core/src/policy.rs`) as plain data: `targets`,
`egress`, `inspect`, `insecure_upstream`, and `limits`. Use `#[serde(deny_unknown_fields)]` on
the new structs — unlike the existing sections, which silently ignore typos (TRIAGE, ~line 299). The
compiler (`crates/core/src/compiler.rs`) produces **two** compiled halves: the proxy-scope
`CompiledPolicy` (network = resolved `targets ∪ egress`; filesystem = write-default-deny + read-deny of project/home/credential paths (R2); exec = the bee
binary) and a `HttpScope` value handed to the worker for the proxy-layer checks. Attenuation
(`crates/core/src/attenuation.rs`) gains the subset rules in
[data-model.md](./data-model.md#attenuation-rules). Schema:
[contracts/policy-http.md](./contracts/policy-http.md).

**Rationale**: Constitution IV (policy-as-data) and II (attenuation) apply to scope as to any
capability; putting the types in core keeps `bee validate --parent` working for HTTP scope with no
new code path. Core gains **no** dependencies — only types and pure logic — so Constitution V and
`tests/core_deps_guard.rs` are untouched.

**Not in policy**: the advisory-scope acknowledgement for non-enforced sessions (FR-010) is a CLI
flag (`--http-scope-advisory`), because it is operator intent and a project file could otherwise
set it on the operator's behalf (CONTEXT.md: project configuration is untrusted input).

## R6 — Per-call credentials and environment injection

**Decision**:
- `Sandbox` gains a harness-only `set_call_context(Option<CallContext>)` called around each
  `ToolRegistry::execute` (`src/episode.rs:307,343`; `src/repl.rs:637,675`) — the call id is available
  there (`src/provider.rs:101-108`) even though `Tool::call` does not receive it (`src/tools.rs:244`).
- At call start the harness mints a 128-bit token (read from `/dev/urandom`; no new dependency),
  registers `{token → call_id, turn}` with the worker (`creds.issue`), and revokes it at call end
  (`creds.revoke`). Long-lived MCP stdio servers receive a credential bound to `mcp:<server>` for the
  server's lifetime.
- `tool_command` (`src/sandbox.rs:196-230`) injects, **after** `restrict_env` (`:306-318`):
  `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy`, `ALL_PROXY` =
  `http://<call_id>:<token>@127.0.0.1:<port>`, and `NO_PROXY=""` / `no_proxy=""`. When `inspect` is
  non-empty, also `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`,
  `GIT_SSL_CAINFO` (see R7).

**Rationale**: The model supplies no environment to any tool today (`src/tools/bash.rs:35-38`,
`src/tools/exec.rs:18-29`), so harness-set values cannot be authored by it. A child *can* unset
them (`sh -c 'HTTP_PROXY= curl …'`) — which is exactly why the **kernel** loopback-only rule (R4) is
the control and the environment is only the routing hint. A child that strips the variables reaches
nothing. Credentials end with the call, so a token leaked into a file or transcript is useless later
(spec edge case "credential reuse").

## R7 — TLS: tunnel by default, opt-in MITM, per-session CA

**Decision**:
- **CONNECT authority decides**. Host not in `targets ∪ egress` → `403` from the proxy, no upstream
  connection. Host in scope but not in `inspect` → tunnel.
- **Tunnel SNI check**: before splicing, the worker reads the ClientHello into a buffer, parses it
  with `rustls::server::Acceptor` to extract SNI, compares SNI to the CONNECT host (case-insensitive,
  trailing dot ignored), and on match writes the **buffered bytes** upstream then splices with
  `copy_bidirectional`. Mismatch → close and record `refused: sni_mismatch`. A ClientHello with no
  SNI is accepted only when the CONNECT authority is an IP literal that is itself a target.
- **MITM** (host ∈ `inspect`): `LazyConfigAcceptor` → leaf certificate for the SNI, minted by
  `rcgen` 0.14 and cached per host for the session; ALPN offered is `http/1.1` only (HTTP/2 is out of
  scope; FR edge case). Upstream TLS uses `webpki-roots` verification unless the host is listed in
  `insecure_upstream` (lab targets with self-signed certs), which is recorded on every exchange.
- **CA lifecycle**: generated in the worker at start (`KeyPair::generate`, `IsCa::Ca`), key held in
  memory with rcgen's `zeroize` feature, never serialised. Only the CA **certificate** crosses the
  control channel (`hello.ca_cert_pem`). The harness writes a **bundle** = system roots
  (`/etc/ssl/certs/ca-certificates.crt`, or the first existing of the usual paths) + session CA to
  `$XDG_RUNTIME_DIR/bee/<session>/ca-bundle.pem` (falling back to a `0700` dir under `TMPDIR`), adds
  a read rule for that one file to the tool policy, and deletes it at teardown. The bundle *must*
  include system roots: tunnelled hosts present their real certificates.
- **Crypto provider**: `aws-lc-rs` — it is what `rustls` already resolves to in the lockfile
  (`Cargo.lock:4035-4040`), so ring is not added; the worker calls
  `CryptoProvider::install_default` explicitly at start rather than relying on feature inference.

**Rationale**: FR-024–FR-026; the CA key never leaves worker memory, so SC-008 is structural. Putting
the bundle outside `.bee/` avoids carving an exception into `PROTECTED_DEFAULTS`
(`crates/core/src/compiler.rs:179-184`).

**Alternatives considered**: trusting only the session CA via `SSL_CERT_FILE` (breaks every tunnelled
host); a long-lived per-project CA (a persistent MITM key on disk is exactly what SC-008 forbids);
OpenSSL (new system dependency; rustls is already present).

## R8 — Store: SQLite index + content-addressed body blobs, harness-owned

**Decision**: `.bee/http/index.sqlite` (rusqlite 0.40, `bundled`, WAL, `busy_timeout = 5 s`) holds
exchanges, tunnels, fuzz runs, leads and refusals. Bodies are files at
`.bee/http/blobs/<aa>/<sha256>`, written once via write-to-temp-then-rename and shared across exchanges
with identical content. The **harness** is the sole writer within a session; concurrent sessions in
one project are separate processes, which WAL handles. Schema:
[contracts/store.md](./contracts/store.md).

**Rationale**:
- `http_history` filters on host, method, path prefix, status, size, time, call id, tags — a
  multi-column indexed query. Over ~100k exchanges, JSONL means full scans or a hand-built index.
  SQLite handles two-process writers properly; `redb` 4.3 takes an exclusive file lock (one
  process), which fails the "concurrent sessions" edge case.
- Bodies outside the database keep the index small and make eviction (store size cap) a file delete
  plus a column update.
- `.bee/` is already denied to every tool scope by `PROTECTED_DEFAULTS`
  (`crates/core/src/compiler.rs:179-184`) — FR-014 holds with no new rule, in enforced sessions.
  (Kernel mediation covers `file_open` only; unlink/rename are not hooked — threat-model T4 — and the
  store is no different from the finding ledger in that respect.)

**Cost acknowledged**: `bundled` compiles C SQLite (~20–40 s cold, needs a C toolchain). The
`astgrep-*` features already compile C grammars, so this is not a new class of build requirement, and
it is confined to the default-off `intercept` feature.

**Alternatives considered**: JSONL + blobs (matches the ledger's style, but querying is the core of
`http_history`; the ledger's needs are append-and-fold, which is different); redb (single process).

## R9 — Bodies, slices and decoding

**Decision**: Decoding (`gzip`/`deflate` via `flate2` 1.1 already in tree; `br` via
`brotli-decompressor` 6.0; `zstd` via `ruzstd` 0.9, pure Rust, MSRV 1.87) happens **in the harness on
stored blobs**, with a hard decoded-output cap (default 64 MiB; beyond it the slice reports
`decoded_truncated`). Slicing: byte range on decoded body; `grep` with the `regex` crate (linear time,
size-limited compiled regex); JSON Pointer via `serde_json::Value::pointer`. Every response is capped
by `DEFAULT_OUTPUT_CAP` before return.

**Rationale**: 016 moved *file reading* into workers because reading target paths is a filesystem
authority. Here the harness reads its **own** store; the risk is parsing attacker-chosen bytes, which
is bounded by memory-safe crates and explicit caps (decompression-bomb cap, regex size limit). Live
TLS/HTTP parsing — the protocol-state-heavy part — stays in the scoped worker.

## R10 — Diff and volatility

**Decision**: Text diff with `similar` 2.7 (in tree; stay on 2.x to avoid a second version). JSON
bodies diffed structurally with `json-patch` 4.2 (`json_patch::diff`) and reported as JSON Pointer
paths. **Volatility** is measured, not guessed: `http_replay` with `noise_probe: true` (default) first
re-sends the *unmodified* original once; anything that differs between original and probe is
labelled volatile and suppressed from the edit-vs-original diff (reported as a count plus paths).
Header volatility uses a fixed list (`date`, `expires`, `age`, `x-request-id`, `set-cookie` values,
etc.) in addition to the probe.

**Rationale**: US5 acceptance 2 requires volatile values be identified; a probe is target-specific
and needs no heuristics about token formats.

## R11 — Filter language: structured JSON, not an HTTPQL-like string

**Decision**: `http_history` takes a JSON filter object (all fields optional, AND-combined, each field
a scalar or list meaning OR) validated by serde with `deny_unknown_fields`.

**Rationale**: the tool schema *is* the grammar, so the model gets schema-guided arguments and precise
`invalid_args` errors instead of a parse error in a mini-language. A string syntax can be layered
later as sugar that compiles to the same struct. Contract:
[contracts/http-tools.md](./contracts/http-tools.md#http_history).

## R12 — Model-facing framing (FR-001, FR-002)

**Finding**: `src/provider/rig_model.rs:306-309` maps a `ToolResult` to `Message::tool_result(call_id,
content)`, dropping `is_error`. rig-core 0.40's `ToolResult` has no error flag at all (`id, call_id,
content`), and its Anthropic provider hard-codes `is_error: None`. No tool output is marked as
untrusted anywhere; `safe_text.rs` is terminal-only.

**Decision**:
1. `ToolResult` gains `provenance: Provenance` (`Harness` | `Child` | `Remote { source }`). The
   provider layer — one place — renders content for the model:
   - errors: content prefixed `[tool error]` (rig cannot carry the flag; an upstream rig change to
     pass `is_error` is filed separately and adopted when available);
   - `Child`/`Remote` content is wrapped in an envelope
     `<untrusted-data source="…" nonce="N">…</untrusted-data nonce="N">` where `N` is a per-result
     random nonce, so content cannot forge the closing tag. A short fixed system-prompt clause
     explains the envelope once.
2. All HTTP tools build results as `Remote { source: "http:<exchange-id>" }`; existing child tools
   (bash, search, …) become `Child`. This is the prerequisite slice P1 and ships first, independent
   of interception.

**Contract**: [contracts/model-framing.md](./contracts/model-framing.md).

## R13 — Escalation (US3) and the two 007 defects it depends on

**Findings** (verified in source this session):
- **The consent prompt cannot show network.** `GrantRequest` (`src/skills/grant.rs:25-32`) carries only
  `tools` and `filesystem`; `escalate()` builds it from those two fields (`src/grants/escalate.rs:96-104`).
  A `GrantDelta.net` entry is approved **without being displayed**.
- **Reactive network/exec escalation never fires.** Kernel events carry `op = "connect"` / `"exec"`
  (`crates/core/src/audit.rs:31`), but `delta_from_denial` matches `"socket_connect"` /
  `"bprm_check_security"` (`src/grants/escalate.rs:263-280`); and the connect audit carries no target
  (`crates/ebpf/src/main.rs:206`). Tests cover only `file_open`.

**Decision**:
- **P2 (prerequisite)**: `GrantRequest` gains `net`, `exec` and a new `http_targets` field, and every
  `ConsentSink` renders them; a test asserts every non-empty `GrantDelta` field is rendered. The op
  name mismatch is fixed by matching on the `audit.rs` vocabulary, with a test per op.
- **P5 (prerequisite) — kernel connect target.** FR-009 requires every refusal, kernel ones included,
  to name the destination, but the connect hook emits `target = None`
  (`crates/ebpf/src/main.rs:206`). The hook has already decoded `family`, `port`, and `addr` into the
  `NetKey`; it writes them as a fixed 20-byte binary target (`family: u16 LE`, `port: u16 BE`,
  `addr: [u8;16]`, laid out exactly like `NetKey.addr`: IPv4 in `addr[0..4]` with the rest zero,
  `crates/ebpf/src/main.rs:184`) into the existing `AuditRecord.target` with `target_len = 20`. **No map or record
  layout changes.** `AuditEvent::from_record` (`crates/core/src/audit.rs:48`) formats it as `ip:port`
  (`[v6]:port` for IPv6) when `op == Connect`. This also makes reactive network escalation
  (`delta_from_denial("connect", …)`) produce a real delta for the first time.
- **Scope widening** does **not** go through kernel denials. A proxy refusal already knows
  `host:port`. A new escalation origin `ProxyRefusal { host, port, call }` produces a
  `GrantDelta.http_targets` entry; `escalate()` checks it against the ceiling's `[policy.http]`,
  asks consent (now displaying it), then applies **atomically** (see below): compile the new proxy-scope policy;
  `reload_sidecar` (kernel, transactional); `scope.update` to the worker; if the worker update fails,
  reload the sidecar back to the previous plan and report the escalation as failed. A second
  `ActivePolicy` instance tracks the target scope alongside the tool policy.
- The retry is the existing "once, only if widened" rule (`escalate.rs` reactive path, SC-005 of 007).

## R14 — Proxy-layer audit is a distinct event type

**Decision**: `ProxyEvent { ts, session, call_id, layer: "proxy", kind, host, port, detail }` with
`kind ∈ {refused_out_of_scope, refused_sni_mismatch, refused_bad_credential, refused_egress_only,
refused_limit, refused_address_drift, rule_fired, held, auto_forwarded}`. `refused_address_drift` is
emitted when a scope host resolves at connect time to no address in its compiled set. The proxy
refuses before connecting, so the operator sees *why* instead of an anonymous kernel deny (spec edge
case "DNS changes mid-session"). It is recorded in the store (`refusals` table),
attached to the call's transcript record next to — never merged into — kernel `AuditEvent`s
(`src/transcript.rs:55-60`), and surfaced as a new `SessionEvent::Proxy` for the REPL/TUI. Kernel
denials from the proxy scope keep the `AuditEvent` shape, tagged `scope = "proxy"`.

**Rationale**: the spec requires the two layers to stay distinguishable (FR-009, FR-011). Reusing
`AuditEvent` with an invented `op` would conflate a kernel decision with a user-space one.

## R15 — Fuzz clustering

**Decision**: deterministic grouping key per response:
`(status, length_bucket, word_bucket, reflected, slow)` where `length_bucket` = length rounded to the
nearest 2 % of the run's median length (min bucket width 16 bytes), `word_bucket` likewise on
whitespace-separated token count, `reflected` = the payload (raw or URL/HTML-decoded) occurs in the
decoded body, and `slow` = elapsed > median + 3 × MAD. Groups are sorted by size; a group is an
**outlier** if its size ≤ max(1, 0.5 % of variants). The summary lists every outlier group and the top
N common groups, each with up to 3 sample exchange ids, within the output cap.

**Limits**: `limits.rps` (token bucket), `limits.concurrency`, `limits.max_requests_per_run`. A run
whose `payload_count × positions` exceeds the cap is refused before the first request (FR-021).
Pacing is enforced in the **worker**, so a harness bug cannot exceed it.

## R16 — Intercept rules and passive leads

**Decision**: rules live only in worker memory (FR-022: never persisted). Match = host, method, path
prefix/regex, header presence, body substring. Actions = `modify` (set/remove header, replace
substring/regex in path or body), `drop`, `hold` (timeout default 30 s, max 300 s, auto-forward
unchanged). Rewritten requests re-enter the scope check. A held request becomes a `held` control
frame; `http_intercept { action: "release" }` decides it.

Passive checks run in the **harness** on store insert (cheap, bounded, on decoded bodies capped at
1 MiB for this purpose): reflected query parameter, missing `HttpOnly`/`Secure`/`SameSite` on
session-like cookies, verbose server error signatures, missing security headers on HTML responses,
credentials in URL. Results go to the `leads` table. New leads are announced via the `TurnStart`
hook (`src/hooks.rs`), which **is** dispatched today; `BeforeModelCall`/`AfterToolResult` are not.

## R17 — Non-enforced sessions

**Decision**: with `[policy.http]` present and no *blocking* kernel enforcement, session construction
**refuses** unless `--http-scope-advisory` is passed. "No blocking enforcement" means any of: host
mode, a non-`enforce` build, or a policy with `mode = "observe"` — in observe mode the connect and
file hooks audit and then **allow** (`crates/ebpf/src/main.rs:205-209, 258-263`), so presenting the
scope as kernel-enforced would violate Constitution III. When the flag is passed, when it is, a
banner prints at start, every scope tool's output carries `enforcement: "advisory"`, and the
transcript header records the acknowledgement (FR-010). In host mode / non-`enforce` builds the
proxy runs as an **unscoped hardened child**: `hardened_command` with no cgroup join, the same fd-3
listener handoff, and the same control channel. In observe mode it runs in its (observing) proxy
scope as usual. Either way the tools work and nothing claims kernel enforcement.

## R18 — Unsupported protocols

**Decision**: `Upgrade: websocket` → proxy returns `501` with a body naming the limitation; inspected
hosts negotiate `http/1.1` only; an upstream that refuses HTTP/1.1 fails the exchange with
`upstream_protocol_unsupported`. Never pass-through-uninspected on an inspected host.

## R19 — SC-005 evaluation harness

**Decision**: a test fixture server (`tests/support/vuln_target.rs`, hyper-based, in-process) with
three planted issues: reflected `q` parameter on `/search`; `/admin` that grants access when
`X-Forwarded-For: 127.0.0.1`; `/item?id=` that 500s on a quote. Host tests drive the tools with
`MockModel` for correctness. The **token-reduction comparison** in SC-005 is an *evaluation* run
against a live provider (bash+curl-only tool set vs the HTTP tool set), recorded in
`specs/019-http-intercept/eval/` and **not** a CI gate, because it needs a live model.

## R19a — Latency gate placement (SC-007)

**Decision**: the SC-007 budget is gated in the **VM matrix** (`http-latency` case, dedicated VM), not
on shared CI runners, where scheduling noise exceeds the 50 ms budget's resolution. Host CI
compiles the bench (`--no-run`) so it cannot rot.

## R20 — Dependencies (all optional, application package only, behind `intercept`)

| Crate | Version | MSRV | Status | Used for |
|---|---|---|---|---|
| hyper | 1.x | 1.63 | in lockfile | forwarding proxy server |
| hyper-util | 0.1 | — | in lockfile | tokio IO adapters |
| http-body-util | 0.1 | — | in lockfile | body collection |
| rustls / tokio-rustls | 0.23 / 0.26 | — | in lockfile | TLS server + client |
| webpki-roots | 1.0 | — | in lockfile | upstream verification |
| httparse | 1.10 | — | in lockfile | raw writer response parsing |
| flate2 | 1.1 | — | in lockfile | gzip/deflate |
| similar | 2.7 | — | in lockfile | text diff |
| rcgen | 0.14 (`aws_lc_rs`, `zeroize`) | 1.88 | **new** (M2) | session CA, leaf certs |
| rusqlite | 0.40 (`bundled`) | — | **new** | store index |
| brotli-decompressor | 6.0 | — | **new** | `br` decoding |
| ruzstd | 0.9 | 1.87 | **new** | `zstd` decoding |
| json-patch | 4.2 | — | **new** (M2) | JSON diff |
| regex | 1.13 | — | in lockfile | grep slices, rules |

HAR export (M4) uses bee's own serde structs (~150 lines) rather than `har` 0.9 (low adoption).
`tests/core_deps_guard.rs` gains `hyper`, `rustls`, `rcgen`, `rusqlite`, `json-patch`. App MSRV stays
1.88 (rcgen's floor equals it).
