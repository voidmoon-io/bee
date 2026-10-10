---
description: "Task list for 019-http-intercept implementation"
---

# Tasks: Agent-First HTTP(S) Interception Under Kernel-Enforced Scope

**Input**: Design documents from `/specs/019-http-intercept/`

**Prerequisites**: plan.md, spec.md, research.md (R1–R20), data-model.md,
contracts/{policy-http,http-tools,proxy-control,store,model-framing}.md, quickstart.md

**Tests**: REQUIRED. The constitution mandates test-first for the security boundary: enforcement
behaviour "MUST have tests written and failing before implementation", and "a denial that no test
exercises is not considered enforced". Within each phase, test tasks come before the implementation
they cover and must be observed failing first.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: parallelizable (different files, no dependency on an incomplete task)
- **[Story]**: US1–US9 for user-story phases. Setup, Foundational and Polish carry no story label.
- Paths are repo-relative. `#[cfg(feature = "intercept")]` is implied for everything under
  `src/intercept/` and `src/tools/http.rs`.

**Scope note**: M1 = Setup + Foundational + US1 + US2 is the MVP and must pass the VM tier (T048).
US9's per-subagent part (T092) is **blocked on 018** and must not be started before the Supervisor
lands.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Manifest, feature flag, scaffolding, fixture. No behaviour yet.

- [X] T001 Add optional dependencies to the `[dependencies]` section of `Cargo.toml`, each with a comment in the file's existing style naming 019 and its research entry:
  - Already in the lockfile, declared here directly: `hyper = { version = "1", features = ["http1", "server", "client"], optional = true }`, `hyper-util = { version = "0.1", features = ["tokio"], optional = true }`, `http-body-util = { version = "0.1", optional = true }`, `tokio-rustls = { version = "0.26", default-features = false, features = ["aws_lc_rs", "tls12"], optional = true }`, `rustls = { version = "0.23", default-features = false, features = ["aws_lc_rs", "std", "tls12"], optional = true }`, `webpki-roots = { version = "1", optional = true }`, `httparse = { version = "1.10", optional = true }`, `flate2 = { version = "1.1", optional = true }`, `similar = { version = "2.7", optional = true }`, `regex = { version = "1", optional = true }`.
  - New: `rcgen = { version = "0.14", default-features = false, features = ["aws_lc_rs", "pem", "zeroize"], optional = true }`, `rusqlite = { version = "0.40", features = ["bundled"], optional = true }`, `brotli-decompressor = { version = "6", optional = true }`, `ruzstd = { version = "0.9", optional = true }`, `json-patch = { version = "4.2", optional = true }`.
  - Research R20.
- [X] T002 Add the `intercept` feature to the `[features]` section of `Cargo.toml`. It enables every dep from T001 plus `tokio/net`, `tokio/sync` and `tokio/io-util`. Leave `default` unchanged. Add a comment block stating it is default-off (SC-009) and that `rcgen`'s MSRV equals the app's 1.88 (depends: T001).
- [X] T003 [P] Extend `FORBIDDEN` in `tests/core_deps_guard.rs` with `hyper`, `rustls`, `tokio-rustls`, `rcgen`, `rusqlite`, `json-patch`, `brotli-decompressor` and `ruzstd` (Constitution V gate).
- [X] T004 Create gated module scaffolding:
  - `src/intercept/mod.rs` declaring `control`, `sidecar`, `creds`, `store`, `query`, `slice`, `diff`, `fuzz`, `passive`, `har` and `worker`.
  - `src/intercept/worker/mod.rs` declaring `listen`, `connect`, `mitm`, `forward`, `raw`, `scope`, `pace` and `rules`.
  - `src/tools/http.rs`, empty.
  - Register `pub mod intercept` in `src/lib.rs` and `pub mod http` in `src/tools.rs`, both `#[cfg(feature = "intercept")]`.
  - (depends: T002)
- [X] T005 Add a hidden `ProxyWorker { #[arg(long)] session: String }` subcommand to `src/main.rs`, gated like `SearchWorker` at `src/main.rs:90-112`, dispatching to `bee::intercept::worker::run(session)`, which is a stub that exits 2 for now (depends: T004).
- [X] T006 [P] Write the fixture target `tests/support/vuln_target.rs`: an in-process hyper HTTP/1.1 server on `127.0.0.1:0` with an optional rustls listener using a test-generated self-signed cert. `pub fn start() -> (SocketAddr, Option<SocketAddr>, ShutdownHandle)`. Routes:
  - `/search?q=` reflects `q` unescaped.
  - `/admin` returns 200 only with `X-Forwarded-For: 127.0.0.1`, else 403.
  - `/item?id=` returns 500 when `id` contains `'`.
  - `/json` returns `{"user":{"role":"guest"},"meta":{"request_id":<random>}}` plus a `Date` header.
  - `/gzip` returns a gzip-encoded body.
  - `/big` streams 100 MB.
  - `/redirect?to=` returns a 302 to `to`.
  - `/echo` echoes the raw request head bytes as the body.
  - Expose the same server as `examples/vuln_target.rs`, which prints its ports (quickstart M1).

**Checkpoint**: `cargo build` is unchanged and `cargo build --features intercept` compiles the stubs. `cargo test --test core_deps_guard` passes.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: P1–P5 from plan.md, plus the policy types, control codec and store that every story uses.

**⚠️ CRITICAL**: No user-story work begins until this phase is complete. P1, P2 and P5 are independently
shippable and SHOULD land as their own PRs (git-pr-workflow).

### P1 — model framing (FR-001, FR-002; contracts/model-framing.md)

- [X] T007 [P] Write `tests/tool_output_framing.rs` (fails first). It checks that:
  - an `is_error` result reaches the provider request prefixed `[tool error] `;
  - `Child` content is wrapped in `<untrusted-data source=… nonce=N>…</untrusted-data nonce=N>`;
  - content containing a bare `</untrusted-data>` does not terminate the envelope;
  - `Harness` content is not wrapped;
  - nonces differ between two results.
- [X] T008 Add `pub enum Provenance { Harness, Child, Remote { source: String } }` and a `provenance` field defaulting to `Harness` to `ToolResult` in `src/tools.rs:115-152`. Update every constructor at `:154-231`. Set `Child` in `src/tools/exec.rs` `run_child`/`run_child_timed` results, and `Remote { source: "mcp:<server>" }` in the MCP proxy tool `src/mcp/proxy.rs` (depends: T007).
- [X] T009 Implement the rendering in `src/provider/rig_model.rs:306-309`: error prefix, plus a nonce'd envelope for `Child`/`Remote`. The nonce is 12 bytes from `/dev/urandom`, base64url. Add the fixed system-prompt clause from contracts/model-framing.md §Rendering.3 where the system prompt is assembled. Make `HMessage::ToolResult` carry `is_error` and `provenance` through `src/provider.rs`. Update affected snapshot tests (depends: T008).

### P2 — 007 defects (research R13)

- [X] T010 [P] Extend `tests/dynamic_grants.rs` (fails first):
  - (a) a `GrantDelta` with only `net` produces a consent request whose rendered text contains the `host:port`;
  - (b) the same for `exec`;
  - (c) a test asserting every non-empty `GrantDelta` field is rendered by the console `ConsentSink`;
  - (d) `delta_from_denial("connect", "1.2.3.4:443")` yields `net = ["1.2.3.4:443"]`;
  - (e) `delta_from_denial("exec", "/usr/bin/x")` yields `exec = ["/usr/bin/x"]`.
- [X] T011 Add `net: &'a [String]`, `exec: &'a [String]` and `http_targets: &'a [String]` to `GrantRequest` in `src/skills/grant.rs:25-32`. Render them in every `ConsentSink` impl (console, REPL, TUI). Populate them in `escalate()` at `src/grants/escalate.rs:96-104` (depends: T010).
- [X] T012 Change `delta_from_denial` in `src/grants/escalate.rs:263-280` to match the kernel's op vocabulary from `crates/core/src/audit.rs` `op_str`: `"file_open"`, `"exec"` and `"connect"`. Fix the doc comment. Add a comment that kernel connect audits currently carry no target (`crates/ebpf/src/main.rs:206`), so reactive network escalation still yields an empty delta until that tracked gap closes (depends: T010).

### P3 — call context and environment injection (research R6)

- [X] T013 [P] Write unit tests in `src/sandbox.rs` `#[cfg(test)]` (fail first):
  - `tool_command` with an `EnvOverlay` set emits those variables after `restrict_env`;
  - a stripped key such as `ANTHROPIC_API_KEY` placed in the overlay is rejected at overlay construction;
  - with no overlay, the environment is byte-identical to today.
- [X] T014 Add `pub struct CallContext { call_id: String, turn: u32, origin: CallOrigin }` and `pub struct EnvOverlay(Vec<(String, String)>)` in `src/sandbox.rs`. Add `Sandbox::set_call_context(&mut self, Option<CallContext>)` and a harness-only `Sandbox::set_env_provider(Box<dyn Fn(&CallContext) -> EnvOverlay + Send + Sync>)`. Apply the overlay after `restrict_env` in all `tool_command` variants (`src/sandbox.rs:196-230`). Refuse an overlay key that is in `strip_env` or matches `LD_*` (depends: T013).
- [X] T015 Call `sandbox.set_call_context(Some(..))` before and `set_call_context(None)` after each `ToolRegistry::execute` in `src/episode.rs:307,343` and `src/repl.rs:637,675`, with the provider `ToolCall.id` and the current turn (depends: T014).

### P4 — sidecar scope (research R2)

- [X] T016 [P] Write tests (fail first):
  - Extract the drain filter at `src/sandbox.rs:247-270` into a pure function, `fn route_audit(ev: &AuditEvent, tool_cg: u64, sidecar: Option<(u64, &str)>) -> Option<TaggedAudit>`, and unit-test it in `src/sandbox.rs` `#[cfg(test)]`. It returns tool-scope events untagged, sidecar events tagged with the sidecar label, and `None` for every other cgroup. The existing single-scope behaviour is unchanged when `sidecar` is `None`.
  - Unit-test that `reload_sidecar` targets the sidecar cgroup id. Factor the cgroup-id choice into a pure helper so this test needs no engine; no mock engine exists in `crates/userspace`, and none is added.
  - The live kernel half is covered by the `http-proxy-scope` VM case (T048).
- [X] T017 Add `sidecar: Option<SidecarScope { label, scope: Scope, cgroup_id, plan }>` to `EnforcedSandbox` in `src/sandbox.rs:58`. Add `Sandbox::with_sidecar(...)`, used before the engine moves (`src/sandbox.rs:153-166`). Change the drain filter at `src/sandbox.rs:254-257` to keep events whose cgroup is the tool scope **or** the sidecar, and add `scope_label: Option<String>` to the drained event wrapper. Add `Sandbox::reload_sidecar(&CompiledPolicy)` via `Engine::reload_scope`, plus `Sandbox::sidecar_join_closure()`. Teardown order: sidecar process (caller), sidecar scope, then tool scope (depends: T016).
- [X] T018 Make `Sandbox::Concurrent` refuse sidecar creation with a typed error, `SidecarUnsupported { reason: "concurrent runner; see specs/018" }` (fail closed). Add a unit test.

### P5 — kernel connect target (FR-009; research R13)

- [X] T019 [P] Write tests (fail first):
  - in `crates/core/src/audit.rs` `#[cfg(test)]`: an `AuditRecord` with `op = Connect`, `target_len = 20` and a v4 encoding (`family = AF_INET`, address in `addr[0..4]`, rest zero) formats as `"10.0.0.5:443"`; a v4 encoding with non-zero trailing bytes is rejected and formatted as `"<malformed>"`; a v6 encoding formats as `"[2001:db8::1]:443"`; a connect record with `target_len = 0` (old kernels/objects) formats as `""`; a file record is unchanged;
  - extend `tests/dynamic_grants.rs`: `delta_from_denial("connect", "10.0.0.5:443")` from a formatted event yields that net entry.
- [X] T020 Encode the connect destination in `crates/ebpf/src/main.rs`. In `socket_connect` (`:160-211`) pass the decoded `family`/`port`/`addr` to a new `emit_audit_connect(cgid, observe, errno, &key)`, which writes `family: u16 LE`, `port: u16 BE` and `addr: [u8;16]` into `AuditRecord.target` with `target_len = 20`. The address layout is identical to `NetKey.addr`: IPv4 in `addr[0..4]` with the remaining 12 bytes zero (`crates/ebpf/src/main.rs:184`), IPv6 in all 16. Leave `emit_audit`'s path variant unchanged; there is no map or `AuditRecord` layout change. Format the target in `AuditEvent::from_record` (`crates/core/src/audit.rs:48`) when `op == Connect`. Add a `connect-target-audited` case to `test/vm/remote-matrix.sh` (depends: T019).

### Core policy types (contracts/policy-http.md; data-model.md §bee-core)

- [X] T021 [P] Write `tests/http_policy.rs` (fails first):
  - Parsing the contracts/policy-http.md example.
  - Each compile error in the contract table.
  - `CompiledHttp.proxy_scope` network = resolved `targets ∪ egress`, using a stub `Resolver`.
  - The tool scope's network is replaced by exactly `127.0.0.1:<port>`.
  - Each `ScopeEntry.enforced_by` lists both layers.
  - `bee validate` exits non-zero naming the field for a typo'd key.
- [X] T022 [P] Write attenuation property tests in `crates/core/tests/http_attenuation.rs` (fail first). They check that:
  - a derived child policy is never outside the parent for targets, egress, inspect, insecure_upstream or limits;
  - an absent child `[policy.http]` inherits the parent's;
  - a wildcard child under an exact parent is rejected;
  - undecidable pattern containment is rejected.
- [X] T023 Create `crates/core/src/pattern.rs` with `HostPattern`. Lift the semantics from `DomainPattern` in `src/mcp/policy.rs:11-70`: exact or `*.suffix`, wildcard ≠ apex, case-insensitive, trailing dot ignored. Add `fn covers(&self, other: &HostPattern) -> Option<bool>` (None = undecidable). Re-point `src/mcp/policy.rs` at it and keep `tests/mcp_domain_gating.rs` green.
- [X] T024 Add `HttpPolicy`, `HttpLimits` and `HostPort` with `#[serde(deny_unknown_fields)]` and the defaults from data-model.md to `crates/core/src/policy.rs`. Add an `http: Option<HttpPolicy>` field on `Policy` (depends: T023).
- [X] T025 Add `compile_http` to `crates/core/src/compiler.rs`. It returns `CompiledHttp { proxy_scope: CompiledPolicy, http_scope: HttpScope }` and implements every validation in contracts/policy-http.md §Compile-time guarantees as new `CompileError` variants. Add `fn with_proxy_loopback(tool: CompiledPolicy, port: u16) -> CompiledPolicy`, which sets network to exactly `127.0.0.1:port`. The proxy scope's filesystem is **not** empty, because the kernel file model is a deny list (research R2). Compile it with `FLAG_FS_WRITE_DEFAULT_DENY` and read-deny rules for `:project_root`, `$HOME`, `/home`, `/root` and every credential directory in `PROTECTED_DEFAULTS`. Leave the loader, libc, `/etc/ssl`, `/etc/resolv.conf`, `/etc/hosts` and `/etc/nsswitch.conf` readable. Add an **exact-path read rule for the resolved worker binary** (`std::env::current_exe()`, canonicalised). `file_open` fires on exec, the worker is exec'd after joining the scope, and dev builds (`target/debug/bee` under `:project_root`) and the VM matrix (`/home/ubuntu/bee`) both sit under denied prefixes. Rules are sorted most-specific-first and the first match decides (`crates/common/src/matcher.rs:74-93`), so the exact rule outranks the prefix denies. Grant exec only for the bee binary. Add `http_policy.rs` assertions for exactly these rules, including a case with the binary path under `:project_root` and under `/home`, where the binary is readable and its siblings are denied. Mirror the case with the host-side reference matcher in `crates/common/src/matcher.rs` tests (depends: T024).
- [X] T026 Add the `[policy.http]` subset rules from data-model.md §Attenuation rules to `crates/core/src/attenuation.rs`. Include inheritance of an absent child section, consistent with `attenuation.rs:130-133` (depends: T024, T023).

### Control channel and store (contracts/proxy-control.md, contracts/store.md)

- [ ] T027 [P] Write codec tests in `src/intercept/control.rs` `#[cfg(test)]` (fail first): round-trip every frame type; reject over-size JSON and segments; close on malformed length; segments delivered in order.
- [ ] T028 Implement `src/intercept/control.rs` (depends: T027):
  - frame types for both directions per contracts/proxy-control.md;
  - an async `FrameReader`/`FrameWriter` over `tokio` stdio and child pipes;
  - a 4-byte big-endian length prefix;
  - declared binary segments;
  - limits: 1 MiB JSON and `max_body_bytes` segments.
- [ ] T029 [P] Write `tests/intercept_store.rs` (fails first):
  - schema v1 is created;
  - insert and read an exchange with blobs;
  - identical bodies share one blob file;
  - two `Store` handles in two threads/processes writing concurrently lose nothing (WAL);
  - an unknown newer `schema_version` opens read-only;
  - eviction above `store_cap_bytes` removes the oldest blobs, sets `evicted`, keeps the rows, and reports an eviction summary;
  - over-`max_body_bytes` bodies are stored truncated with the flag set.
- [ ] T030 Implement `src/intercept/store.rs` per contracts/store.md (depends: T029):
  - `Store::open(project_root)` creating `.bee/http/` with `0700`;
  - WAL and `busy_timeout(5s)`;
  - `insert_exchange` and `insert_tunnel`, `insert_refusal`;
  - content-addressed blobs using write-temp-then-rename under `blobs/<aa>/<sha256>`;
  - the eviction policy;
  - exchange id = `E<session-short>-<seq>`.

**Checkpoint**: P1 and P2 are mergeable on their own; `cargo test` passes with and without `--features intercept`; `bee validate` understands `[policy.http]`.

---

## Phase 3: User Story 1 — Rules of engagement the agent cannot step outside (Priority: P1) 🎯 MVP

**Goal**: The proxy worker runs in its own scope. Tool children reach only it. Out-of-scope requests,
SNI mismatches and bad credentials are refused and recorded, and non-enforced sessions refuse
without acknowledgement.

**Independent Test**: spec US1. Host tier: `tests/intercept_proxy.rs`. Kernel half: VM cases in T048.

### Tests for User Story 1 ⚠️ write first, observe failing

- [ ] T031 [P] [US1] Write `tests/intercept_proxy.rs` against `vuln_target`, running the worker in advisory mode. It checks that:
  - an in-scope `GET` through the proxy with valid credentials yields 200 and an `exchange` frame with the `call_id`;
  - an out-of-scope absolute-form request yields `403` and `ProxyEvent refused_out_of_scope`, with no connection made to the destination (assert the fixture's second listener saw zero accepts);
  - a CONNECT to an out-of-scope host is refused;
  - a request without credentials, with a wrong token, or with a token revoked after `creds.revoke` yields `407` and `refused_bad_credential`;
  - an `egress` host via CONNECT tunnels and is recorded as `TunnelRecord`;
  - `Upgrade: websocket` yields 501.
  - DNS drift: the scope compiles `drift.test` → 127.0.0.2 via a stub resolver, and the worker's resolver then returns 127.0.0.3. The request is refused with `refused_address_drift` naming both addresses, and no connect is attempted.
- [ ] T032 [P] [US1] Add an SNI test to `tests/intercept_proxy.rs`: a rustls client CONNECTs to the in-scope TLS port but sends SNI `other.test`. Expect the tunnel closed and `refused_sni_mismatch`. A matching SNI splices, and the client completes the handshake against the fixture's real cert.
- [ ] T033 [P] [US1] Add a fail-closed test to `tests/intercept_proxy.rs`: kill the worker mid-session. Then `bash` running `curl` through the proxy fails, and an `http_*` tool returns `Unavailable { interceptor_unavailable }`. Exactly one restart is attempted and announced; a second death leaves the tools unavailable.
- [ ] T034 [P] [US1] Write session-construction tests in `tests/intercept_session.rs`:
  - `[policy.http]` in host mode without `--http-scope-advisory` refuses with a message naming the flag;
  - with the flag, the banner is printed and the transcript header records the acknowledgement;
  - with the concurrent runner, it refuses;
  - in an `enforce` build with `mode = "observe"` and no flag, it refuses exactly as host mode does; with the flag, `http_scope` reports `enforcement: "advisory"`;
  - a tool child's environment contains `HTTP_PROXY=http://<call_id>:<token>@127.0.0.1:<port>`, `HTTPS_PROXY`, the lowercase variants, `ALL_PROXY`, and an empty `NO_PROXY`.

### Implementation for User Story 1

- [ ] T035 [US1] Implement the worker entry in `src/intercept/worker/mod.rs::run`:
  - verify fd 3 is a listening IPv4-loopback TCP socket (`getsockname`, `SO_ACCEPTCONN`) or exit 2;
  - call `rustls::crypto::aws_lc_rs::default_provider().install_default()`;
  - read the `init` frame from stdin and reply `hello`;
  - run the accept loop and the control loop on a current-thread tokio runtime with a `LocalSet`.
- [ ] T036 [US1] Implement `src/intercept/worker/scope.rs`:
  - `resolve_checked(host, port) -> Result<SocketAddr, Refusal>`: resolve at connect time and keep only addresses in the entry's compiled `resolved` set. If none remain, refuse with `ProxyEvent refused_address_drift { host, now_resolves_to, compiled }` **before** attempting a connect, instead of letting the kernel deny an anonymous connect. Every upstream connect, in `connect.rs`, `forward.rs` and `raw.rs`, goes through it. Add the new `kind` to data-model.md's `ProxyEvent` and research R14.
  - `HttpScope` checks: `check_target(host, port) -> Result<Role, Refusal>` and `check_sni(connect_host, sni) -> Result<(), Refusal>`, with case-insensitive, trailing-dot-insensitive matching;
  - IP-literal targets match only themselves, and a `Host` header that disagrees with the authority is refused;
  - `update(HttpScope)` for `scope.update`.
- [ ] T037 [US1] Implement credential state in `src/intercept/worker/listen.rs`: a map from token to `CallContext` fed by `creds.issue`/`creds.revoke`. Parse `Proxy-Authorization: Basic` (curl and most clients send userinfo this way) and also userinfo in absolute-form URIs. Respond `407` with `Proxy-Authenticate: Basic realm="bee"` on failure and emit `ProxyEvent refused_bad_credential` (depends: T035).
- [ ] T038 [US1] Implement the hyper http1 server in `src/intercept/worker/listen.rs`: `.with_upgrades()` and `preserve_header_case(true)`. Route `CONNECT` to `connect.rs` and absolute-form requests to `forward.rs`. Return `501` for `Upgrade: websocket`. Scope-check before any upstream connect (depends: T036, T037).
- [ ] T039 [US1] Implement `src/intercept/worker/connect.rs` (depends: T036):
  - after the role check, reply 200 and `hyper::upgrade::on`;
  - for non-inspected hosts, buffer the client's ClientHello (up to 16 KiB), parse SNI with `rustls::server::Acceptor`, apply `check_sni`, connect upstream, write the buffered bytes, then `copy_bidirectional`;
  - emit a `tunnel` frame with byte counts on close.
  - A ClientHello without SNI is allowed only when the CONNECT authority is an IP-literal target.
- [ ] T040 [US1] Implement `src/intercept/worker/forward.rs` for plain-HTTP absolute-form requests: connect upstream with a hyper client conn (no pool), strip `Proxy-Authorization`, forward, collect bodies up to `max_body_bytes`, and emit an `exchange` frame with `origin.path = "forwarded"` and segments (depends: T038).
- [ ] T041 [US1] Implement `src/intercept/sidecar.rs` (depends: T028, T035):
  - bind `TcpListener` on `127.0.0.1:0` in the harness;
  - spawn `current_exe() proxy-worker --session <id>` through a new `Sandbox::sidecar_command` that uses the sidecar join closure plus the hardening from `hardened_command`;
  - `dup2` the listener to fd 3 in `pre_exec`, clearing `CLOEXEC` on fd 3 only;
  - use `kill_on_drop`;
  - own the control `FrameWriter`/`FrameReader`;
  - run a reader task that writes `exchange`/`tunnel`/`proxy_event` frames into `Store` and forwards `ProxyEvent`s to the session;
  - apply the restart-once policy.
  - In host mode / non-`enforce` builds (advisory, research R17), spawn the worker with `hardened_command` and **no** cgroup join, keeping the same fd-3 handoff and control channel. In observe mode, use the sidecar path as normal.
- [ ] T042 [US1] Implement `src/intercept/creds.rs`: mint 16 random bytes from `/dev/urandom`, encode the token hex, send `creds.issue` and `creds.revoke`. Register the `EnvOverlay` provider from T014 that produces the proxy variables for the current `CallContext`. For MCP stdio servers, issue an `mcp:<server>` credential at spawn and revoke it at drop, with the hook in `src/mcp/transport.rs:24-56` (depends: T014, T041). Extend `tests/mcp_stdio.rs`: with `[policy.http]` present, an MCP stdio server child receives the proxy variables and an `mcp:<server>` credential, and its traffic is attributed to `mcp:<server>` in the store.
- [ ] T043 [US1] Wire session construction in `src/app/session.rs:296-330` `build_sandbox` (depends: T017, T025, T041, T042):
  - when `policy.http` is present, run `compile_http`;
  - bind the listener and apply `with_proxy_loopback(tool_policy, port)`;
  - create the sidecar scope from `proxy_scope` before the engine moves;
  - build the sandbox `with_sidecar`;
  - spawn the worker, then send `init`.
  - Require `--http-scope-advisory` whenever enforcement does not block: host mode, a non-`enforce` build, or `policy.mode == Observe`. Record the reason in the transcript header.
  - Refuse the concurrent runner (T018).
  - Mirror this on the episode path at `src/episode.rs:870-876`.
- [ ] T044 [US1] Add the `--http-scope-advisory` flag to the `run` and `repl` commands in `src/app/` (clap). It is not readable from any config file; assert that in a test in `tests/command_surface.rs`. Print the banner and record the acknowledgement in the transcript header (`src/transcript.rs`).
- [ ] T045 [US1] Add `ProxyEvent` (data-model.md) to `src/transcript.rs` as `RecordedCall.proxy_events: Vec<ProxyEvent>`, kept separate from `audit`. Add `SessionEvent::Proxy(ProxyEvent)` in `src/session/event.rs`. Render refusals in the REPL and TUI as `refused by proxy: <host>:<port> (<kind>)`, distinct from kernel denial rendering.
- [ ] T046 [US1] Implement the `http_scope` tool in `src/tools/http.rs` per contracts/http-tools.md#http_scope: read-only, every entry with `enforced_by` layers, plus `enforcement: kernel|advisory`. `advisory` whenever the session started under `--http-scope-advisory`, which includes observe mode. Register it in `HTTP_TOOLS` and `register_named` in `src/tools.rs`, with a `NotCompiledIn` arm (`src/tools.rs:367-408`) and a `sec_tool_family`-style mapping to `intercept` (depends: T043).
- [ ] T047 [US1] Make the drained sidecar-scope kernel events from T017 flow into the call's `RecordedCall.audit` tagged `scope = "proxy"` in `src/episode.rs` and `src/repl.rs`.
- [ ] T048 [US1] Add VM cases to `test/vm/remote-matrix.sh`, exactly as in the quickstart.md M1 VM table, each emitting a `RESULT|…` line:
  - `http-in-scope`, `http-out-of-scope`, `http-direct-target`, `http-direct-other`, `http-proxy-scope` and `http-sni-mismatch`;
  - `http-store-protected` (FR-014): a tool child's read and write of `.bee/http/` are kernel-denied;
  - `http-proxy-fs-deny` (research R2): the worker cannot open a file under `:project_root`.

  Add a `vm-test` feature to `Cargo.toml` (`vm-test = ["intercept"]`) and switch `test/vm/matrix.sh:30` to build `concurrent,sec,vm-test`. Under `#[cfg(feature = "vm-test")]` only, add two control frames to `src/intercept/control.rs` and the worker: `debug.connect {addr}`, a raw connect to the given address, and `debug.read {path}`, a raw `open` of the given path. Both report the errno. They are absent from every other build; assert that with a `#[cfg(not(feature = "vm-test"))]` unit test in `src/intercept/control.rs` that fails to decode both frame names. Document both in `test/vm/README.md`.

**Checkpoint**: US1 passes on the host tier and all eight US1 VM cases pass, plus `connect-target-audited` from P5. Do not proceed to call M1 done without them.

---

## Phase 4: User Story 2 — Send, find and read traffic without drowning in it (Priority: P1) 🎯 MVP

**Goal**: `http_send` (structured or raw, byte-exact), `http_history` (structured filter, compact
rows), and `http_get` (bounded slices), all wrapped as untrusted data.

**Independent Test**: spec US2 against `vuln_target`, in `tests/intercept_tools.rs`.

### Tests for User Story 2 ⚠️ write first

- [ ] T049 [P] [US2] Write `tests/intercept_tools.rs` (send):
  - structured `POST` to `/echo` returns id, status, size, elapsed and a 1 KiB preview;
  - raw bytes with duplicate headers, odd casing and a bare `\n` appear byte-identical in `/echo`'s body;
  - `follow_redirects: 2` to an out-of-scope `to` stops and reports the hop;
  - an `egress` host is refused with `egress_only`;
  - the result bound is ≤ 4 KiB.
- [ ] T050 [P] [US2] Add `http_history` tests to `tests/intercept_tools.rs`:
  - seed 20 mixed exchanges;
  - filter by method, status list, status range, path prefix, `since: "-10m"`, call id and origin;
  - `total_matched` is correct when it exceeds `limit`;
  - unknown filter keys give `invalid_args`;
  - rows include `call_id`;
  - a forwarded `curl` exchange and a tool exchange carry different call ids;
  - the bound is ≤ 24 KiB.
- [ ] T051 [P] [US2] Add `http_get` tests to `tests/intercept_tools.rs`:
  - headers only;
  - a byte range on the decoded `/gzip` body;
  - `grep` with context;
  - JSON pointer `/user/role`;
  - `raw_head`;
  - `/big` never returns more than 32 KiB and reports `total_decoded_bytes`;
  - a decompression bomb (gzip of 1 GiB of zeros) stops at the decode cap with `decoded_truncated`;
  - every target-derived slice is `Provenance::Remote { source: "http:<id>" }`.

### Implementation for User Story 2

- [ ] T052 [US2] Implement the raw HTTP/1.1 writer in `src/intercept/worker/raw.rs`: connect over TCP or TLS (rustls client, webpki roots, `insecure_upstream` honoured), `write_all` the exact bytes, then parse the response with `httparse` in a loop over `BytesMut`. Body framing: Content-Length, chunked via `parse_chunk_size`, or close-delimited. Handle 1xx skip, HEAD and 204/304. Enforce the `max_body_bytes` cap, `timeout_ms`, and timing (connect/ttfb/total). Emit an `exchange` with `origin.path = "raw"`.
- [ ] T053 [US2] Handle the `send` control frame in the worker (`src/intercept/worker/mod.rs`): re-check scope and role (proxy-control invariant 2, defence in depth), then go through `pace.rs` (T054) and `raw.rs` (depends: T052, T036).
- [ ] T054 [P] [US2] Implement `src/intercept/worker/pace.rs`: a token bucket at `limits.rps` and a semaphore at `limits.concurrency`. Unit-test pacing with tokio's paused clock.
- [ ] T055 [US2] Implement request serialisation in `src/tools/http.rs`: the structured `request` becomes raw bytes, preserving header order and case, adding `Host` and `Content-Length` only when absent, and handling `body_base64`. Raw input passes through untouched. Follow redirects with a per-hop scope check (FR-023).
- [ ] T056 [US2] Implement the `http_send` tool in `src/tools/http.rs` per contracts/http-tools.md#http_send. It sends via the sidecar control client, awaits the `exchange`, and stores it. The result has `Harness` provenance for bee's fields and `Remote` for the preview. The `baseline` diff is deferred to US5 and returns `invalid_args: "baseline requires http_replay (M2)"` until then (depends: T055, T053, T030).
- [ ] T057 [US2] Implement `src/intercept/query.rs`: map the filter struct (`deny_unknown_fields`) to parameterised SQL over the schema indexes. `since`/`until` accept RFC 3339 or a relative `-Nm/-Nh`. Return compact rows plus `total_matched` (depends: T030).
- [ ] T058 [US2] Implement the `http_history` tool in `src/tools/http.rs` (depends: T057).
- [ ] T059 [US2] Implement `src/intercept/slice.rs`:
  - decode identity, gzip and deflate (`flate2`), `br` (`brotli-decompressor`) and `zstd` (`ruzstd`), with a 64 MiB decoded cap;
  - byte range;
  - grep with `regex` (`RegexBuilder::size_limit(1 << 20)`), context lines and a match cap;
  - JSON pointer through `serde_json`;
  - raw head.
- [ ] T060 [US2] Implement the `http_get` tool in `src/tools/http.rs` with `Remote` provenance for content (depends: T059).
- [ ] T061 [US2] Register `http_send`, `http_get` and `http_history` in `HTTP_TOOLS` and `register_named` with `NotCompiledIn` arms in `src/tools.rs`. Add them to `is_known_tool` so scenarios can name them. Add a `NotCompiledIn` test to `tests/fail_closed_tools.rs`.

**Checkpoint**: M1 complete. Quickstart M1 host and VM steps pass; MVP is demonstrable.

---

## Phase 5: User Story 3 — Widening scope is a human decision (Priority: P2)

**Goal**: A proxy refusal becomes a consented, ceiling-checked widening of exactly one `host:port`,
applied atomically to the kernel and proxy layers, then retried once.

**Independent Test**: spec US3, in `tests/intercept_escalation.rs`.

- [ ] T062 [P] [US3] Write `tests/intercept_escalation.rs` (fails first). It checks that:
  - a refusal with escalation enabled produces a consent request whose `http_targets` is exactly the refused `host:port`;
  - approve leads to a successful retry, and the transcript records the decision and the approver;
  - decline or timeout leaves the scope unchanged, and the model is told so;
  - a beyond-ceiling request is refused without consent;
  - a worker `scope.update` failure after a kernel reload rolls the sidecar back to the previous plan and reports failure;
  - the model has no tool that widens scope (registry scan);
  - proptest: no sequence of grants yields a scope outside the ceiling (SC-010).
- [ ] T063 [US3] Add `http_targets: Vec<String>` to `GrantDelta` in `src/grants/mod.rs:30-35`, folded into a second, target-scope `ActivePolicy`. `try_apply` checks it against the ceiling's `[policy.http]` with the core attenuation from T026.
- [ ] T064 [US3] Add an escalation origin `ProxyRefusal { host, port, call }` and a `ProxyRefusalHook` in `src/grants/escalate.rs`. The episode and REPL loops (`src/episode.rs`, `src/repl.rs`) dispatch it when a tool result carries a `refused_out_of_scope` `ProxyEvent` and escalation is enabled. On a granted widen, retry once (existing rule).
- [ ] T065 [US3] Implement the atomic apply in `src/intercept/sidecar.rs` (depends: T063, T017):
  - recompile `proxy_scope`;
  - call `Sandbox::reload_sidecar` (kernel, transactional);
  - send `scope.update` to the worker;
  - on error, reload the sidecar with the previous plan, then return `EscalateOutcome::Failed`.

**Checkpoint**: Quickstart M2 escalation step passes; the consent prompt visibly shows `http_targets`.

---

## Phase 6: User Story 4 — Look inside HTTPS where, and only where, the operator says (Priority: P2)

**Goal**: Hosts listed in `inspect` are decrypted with a per-session CA whose key never leaves worker
memory. All other hosts are tunnelled.

**Independent Test**: spec US4, in `tests/intercept_tls.rs`.

- [ ] T066 [P] [US4] Write `tests/intercept_tls.rs` (fails first). It checks that:
  - an inspected host gets a full exchange recorded, and a rustls client trusting the bundle verifies the minted leaf;
  - a non-inspected in-scope host is recorded as a tunnel only;
  - the CA private key is absent from every control frame (scan for the key DER and for `PRIVATE KEY`), from `.bee/http/`, from the transcript, and from the bundle file;
  - the bundle contains the system roots plus exactly one session CA;
  - the bundle file is deleted at teardown;
  - an upstream offering only h2 fails with `upstream_protocol_unsupported` instead of being passed through;
  - `insecure_upstream` accepts the fixture's self-signed cert and records `upstream_verified = false`.
- [ ] T067 [US4] Implement `src/intercept/worker/mitm.rs`:
  - a session CA at worker start (`rcgen` `KeyPair::generate`, `IsCa::Ca(Unconstrained)`, key usages `keyCertSign`/`cRLSign`, 1-day validity), held in memory and zeroized on drop;
  - a leaf cache `HashMap<String, Arc<CertifiedKey>>`;
  - `LazyConfigAcceptor` with ALPN `http/1.1` only;
  - an upstream rustls client honouring `insecure_upstream`;
  - inner HTTP/1.1 served with hyper and forwarded through `forward.rs`, with `tls = Inspected`.
- [ ] T068 [US4] Route CONNECT to MITM when the host matches `inspect` in `src/intercept/worker/connect.rs`. Include `ca_cert_pem` in `hello` only when `inspect` is non-empty (depends: T067).
- [ ] T069 [US4] Write the CA bundle in `src/intercept/sidecar.rs`:
  - start from the first existing system bundle (`/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`, `/etc/ssl/cert.pem`) and append the session CA certificate;
  - write it to `$XDG_RUNTIME_DIR/bee/<session>/ca-bundle.pem`, falling back to `TMPDIR` with directory mode `0700`;
  - add a read rule for that file to the tool policy before compile;
  - extend the `EnvOverlay` with `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS` and `GIT_SSL_CAINFO`;
  - delete the file at teardown.
  - (depends: T068, T042)

**Checkpoint**: Quickstart M2 TLS step passes; SC-008 grep finds nothing.

---

## Phase 7: User Story 5 — Replay with a diff, and a map of what has been seen (Priority: P2)

**Goal**: `http_replay` sends edits and returns a measured diff with volatile values suppressed;
`http_sitemap` returns a bounded host and path tree.

**Independent Test**: spec US5, in `tests/intercept_replay.rs`.

- [ ] T070 [P] [US5] Write `tests/intercept_replay.rs` (fails first):
  - replay `/json` with `JsonSet /user/role "admin"` yields a new exchange linked by `parent` and a `probe` exchange;
  - the `Date` header and `/meta/request_id` are reported under `volatile_suppressed`, not as changes;
  - replay `/admin` with `SetHeader X-Forwarded-For 127.0.0.1` yields a status diff of `[403, 200]`;
  - `noise_probe: false` sends exactly one request;
  - `http_send` with `baseline` returns the same diff shape;
  - sitemap after 10 requests lists every path and query parameter name;
  - bounds: replay ≤ 16 KiB, sitemap ≤ 24 KiB.
- [ ] T071 [US5] Implement `Edit` application in `src/intercept/diff.rs` (or `edits.rs` beside it) over a stored raw request head and body. Every `Edit` variant from data-model.md is required; `JsonSet` and `JsonRemove` re-serialise the body and fix `Content-Length`.
- [ ] T072 [US5] Implement the diff in `src/intercept/diff.rs`:
  - status, length, elapsed and header diffs;
  - a text body diff with `similar` as bounded unified hunks;
  - a JSON diff with `json_patch::diff` reported as pointer paths;
  - volatility = paths and headers differing between original and probe, plus the fixed header list from research R10.
- [ ] T073 [US5] Implement the `http_replay` tool and enable `baseline` in `http_send` in `src/tools/http.rs` (depends: T071, T072).
- [ ] T074 [US5] Implement the `http_sitemap` tool in `src/tools/http.rs`: an aggregate SQL query over `exchanges` (host, path segments, methods, statuses, counts). Query parameter names come from `target`; body parameter names come from form and JSON request bodies, decoded and capped at 256 KiB each.

---

## Phase 8: User Story 6 — Fuzz and see only what stands out (Priority: P3)

**Goal**: Marker templates and payload sets run within worker-enforced limits, and the results come
back clustered with outliers flagged.

**Independent Test**: spec US6, in `tests/intercept_fuzz.rs` (SC-006).

- [ ] T075 [P] [US6] Write `tests/intercept_fuzz.rs` (fails first):
  - 1,000 variants against a fixture route that 500s for 2 specific payloads: both appear as outlier groups, 10 of 10 runs;
  - the summary stays ≤ 16 KiB;
  - the planned count above `max_requests_per_run` is refused before any send (fixture saw zero requests);
  - observed request rate ≤ `rps` (paused clock);
  - an out-of-scope variant, made by a payload in the `Host` position, is recorded as refused and not counted as a response;
  - `rps` arguments can only lower the policy limit;
  - `project_file` payloads are read through a `cat` child in the tool scope, not the harness. A path the scope denies yields a kernel-denied refusal, and a scope without `cat` granted yields `NotGranted`.
- [ ] T076 [US6] Implement template expansion in `src/intercept/fuzz.rs`:
  - `sniper`, `battering_ram`, `pitchfork` and `cluster_bomb` modes over `§`-delimited markers;
  - payload sets: `builtin` (ship `sqli-basic`, `xss-basic`, `path-traversal` and `common-paths` as `include_str!` lists under `src/intercept/payloads/`), `range`, `inline`, and `project_file`;
  - `project_file` is read exactly as `read_file` does (`src/tools/files.rs:44-57`): `run_child(sandbox, "cat", ["--", path], None, 1 MiB)` in the **tool scope**, so the kernel decides whether the file is readable (016 rule: the harness never opens project files). If `cat` is not in the scope's exec allowlist, return `Unavailable { NotGranted }`. Payload files are capped at 1 MiB and 100,000 lines; above that, `invalid_args` names the limit.
- [ ] T077 [US6] Handle `fuzz.start`/`fuzz.cancel` in the worker in `src/intercept/worker/mod.rs`: batches of ≤ 256, each variant through `scope.rs` and `pace.rs`, emitting `exchange` frames tagged with `fuzz_run`, then `fuzz.done`.
- [ ] T078 [US6] Implement clustering in `src/intercept/fuzz.rs` per research R15 (length and word buckets, reflection including URL/HTML-decoded payloads, MAD-based `slow`, outlier rule) producing `ClusterSummary`. Persist the `fuzz_runs` row.
- [ ] T079 [US6] Implement the `http_fuzz` tool in `src/tools/http.rs` and register it (depends: T076–T078).

---

## Phase 9: User Story 7 — Shape other tools' traffic with rules, not clicks (Priority: P3)

**Goal**: Session-scoped modify, drop and hold rules over forwarded traffic, with time-bounded holds.

**Independent Test**: spec US7, in `tests/intercept_rules.rs`.

- [ ] T080 [P] [US7] Write `tests/intercept_rules.rs` (fails first):
  - a modify rule adds a header, and the stored exchange has both `req_original_head` and the modified head;
  - a drop rule leaves the client receiving a 502 with a body naming the rule, recorded as `rule_fired`;
  - a hold rule followed by `release forward_edited` causes the edit to be applied;
  - a second hold auto-forwards at a 1 s test timeout and is recorded as `auto_forwarded`;
  - a rule rewriting toward an out-of-scope host has the result refused;
  - rules are gone in a new session;
  - a timeout above 300 s gives `invalid_args`.
- [ ] T081 [US7] Implement `src/intercept/worker/rules.rs`: matcher evaluation, `Edit` application (shared with T071 via a common module), holds with deadline timers, and a scope re-check after rewrite. Hook it into `forward.rs` for plain HTTP. Hook it into the MITM inner path (T067) for HTTPS, which requires US4.
- [ ] T082 [US7] Handle `rule.add`, `rule.remove` and `hold.release` frames, plus the `held` frame to the harness, in the worker (`src/intercept/worker/mod.rs`) and the harness (`src/intercept/sidecar.rs`).
- [ ] T083 [US7] Implement the `http_intercept` tool in `src/tools/http.rs` (add_rule, remove_rule, list, release) and register it.

---

## Phase 10: User Story 8 — Evidence, leads and findings stay separate (Priority: P3)

**Goal**: Findings cite exchanges as evidence. Passive leads are recorded separately and announced at
turn start.

**Independent Test**: spec US8, in `tests/intercept_leads.rs` and `tests/finding_ledger.rs`.

- [ ] T084 [P] [US8] Write tests (fail first):
  - in `tests/finding_ledger.rs`: `record_finding` with `evidence: ["http:<id>"]` stores the refs, an unknown id is rejected, and after eviction review shows `missing`;
  - a new `tests/intercept_leads.rs`: a reflected `/search?q=` produces a `reflected_parameter` lead, the ledger is unchanged, the next `TurnStart` injects "N new leads", and `http_leads only_new` lists them once;
  - lead summaries are bee templates containing no target bytes.
- [ ] T085 [US8] Add `evidence_refs: Vec<String>` (≤ 16, each `http:<ExchangeId>`) to `Observed` events in `src/findings.rs`, keeping events within `MAX_EVENT_BYTES`. Validate the refs against `Store` at record time in `src/tools/finding.rs`, and resolve them on review in `src/app/findings.rs`, showing `missing` for evicted or unknown ones.
- [ ] T086 [US8] Implement passive checks in `src/intercept/passive.rs`, run on store insert with bodies decoded and capped at 1 MiB: reflected query parameter, session-like cookies missing `HttpOnly`/`Secure`/`SameSite`, verbose error signatures, missing security headers on `text/html`, and credentials in the URL. Write the results to `leads`.
- [ ] T087 [US8] Add a `TurnStart` hook in `src/hooks.rs`/`src/intercept/` that announces unannounced leads in one harness line and marks them announced. Implement the `http_leads` tool in `src/tools/http.rs` and register it.
- [ ] T088 [US8] Write `specs/019-http-intercept/eval/README.md` describing the SC-005 paired live-provider evaluation (shell+curl tool set vs HTTP tool set against `vuln_target`, recording calls and tool-output tokens), plus a runner `scenarios/eval-http-*.toml` for each arm.

---

## Phase 11: User Story 9 — Watch it live, delegate it narrowly, take it with you (Priority: P4)

**Goal**: A live history pane, HAR export, and per-subagent proxy scopes after 018.

**Independent Test**: spec US9.

- [ ] T089 [P] [US9] Write tests (fail first):
  - an `insta` snapshot in `tests/grid.rs` of the history pane with three exchanges, one containing ANSI and bidi characters in a header, which must render escaped through `safe_text`;
  - `tests/intercept_har.rs`: the export of selected exchanges is valid HAR 1.2 JSON, contains no `PRIVATE KEY`, no proxy token and no `Proxy-Authorization` header, and flags `Authorization`/`Cookie` headers in a `_bee.sensitive` field.
- [ ] T090 [US9] Add `SessionEvent::HttpExchange(summary)` in `src/session/event.rs`, emitted from the sidecar reader. Add the history pane in `src/tui/panels.rs` (PanelRegistry upsert, TTL), `src/tui/app.rs` (update) and `src/tui/view.rs` (draw), with all target-derived text through `safe_text::safe_line`.
- [ ] T091 [US9] Implement HAR export in `src/intercept/har.rs` (own serde structs) and a `bee http export --har <file> [--filter <json>]` command in `src/app/`. Exclude CA material and bee credentials, and flag sensitive headers.
- [ ] T092 [US9] **BLOCKED on 018**: migrate the sidecar scope to a Supervisor `ScopeRecord`; delete `EnforcedSandbox.sidecar` and the T018 refusal. Give subagents declaring `[policy.http]` their own proxy scope plus worker credential namespace, attenuation-checked by T026, with refusals attributed to the subagent scope. Add the validation to 018's quickstart.

---

## Phase 12: Polish & Cross-Cutting Concerns

- [ ] T093 [P] Add `benches/intercept_latency.rs` (criterion): direct vs proxied in-scope GET against `vuln_target`, 1,000 iterations after a 100-request warm-up. **Gate SC-007 in the VM matrix**, not on shared CI runners: add an `http-latency` case to `test/vm/remote-matrix.sh` that runs the bench on the dedicated VM and fails if added latency exceeds 50 ms median or 200 ms p95. Host CI runs the bench with `--no-run` (compile-only) so it cannot rot. Record the VM numbers in `checklists/validation.md`.
- [ ] T094 [P] Update `THREAT_MODEL.md`:
  - a new entry point E13 for the proxy worker and the store;
  - T6-style redirect revalidation, now addressed for HTTP tools;
  - target-response prompt injection, mitigated by P1;
  - the proxy-layer vs kernel-layer distinction;
  - the CA key lifecycle.
- [ ] T095 [P] Add **Target scope**, **Exchange**, **Lead**, **Proxy scope** and **Interceptor** to `CONTEXT.md`, with `_Avoid_` lines, for example "Lead — _Avoid_: finding, alert".
- [ ] T096 [P] Add an `intercept` row to the workspace and feature docs in `README.md` and a usage section pointing to the quickstart.
- [ ] T097 Run `cargo clippy --workspace --all-targets --features intercept,enforce,sec` and `cargo fmt`, and fix findings. Confirm `cargo tree` for the default build is unchanged against `main` (SC-009).
- [ ] T098 Run the full quickstart (host tier and `./test/vm/matrix.sh`) and record the results in `specs/019-http-intercept/checklists/validation.md`.

---

## Dependencies & Execution Order

### Phase dependencies

- **Setup (T001–T006)** has no dependencies. T006 (fixture) can start immediately.
- **Foundational (T007–T030)** depends on Setup and blocks all stories.
  - P1 (T007–T009) and P2 (T010–T012) are independent of each other and of everything else in Phase 2. Ship each as its own PR.
  - P3 (T013–T015) and P4 (T016–T018) are independent of each other.
  - Policy (T021–T026), control (T027–T028) and store (T029–T030) are mutually independent.
- **US1 (T031–T048)** depends on all of Foundational.
- **US2 (T049–T061)** depends on Foundational plus T035–T043 from US1, because it needs a running worker and sidecar. It can run in parallel with T044–T048.
- **US3** depends on US1 (refusals) and T026.
- **US4** depends on US1 (connect path).
- **US5** depends on US2 (store, raw send).
- **US6** depends on US2 and US5's `Edit`/diff module (T071), for templates from exchanges.
- **US7** depends on US1 (forward path), T071 (shared `Edit`) and **US4** (rules over HTTPS run on the MITM inner path, T067).
- **US8** depends on US2 (store). It is independent of US5–US7.
- **US9** depends on US2. T092 is additionally blocked on 018.
- **Polish** comes after the stories in scope.

### Story completion order

```text
Setup → Foundational ─┬─> US1 ─┬─> US2 ─┬─> US5 ─┬─> US6
                      │        │        │        └─> US7 (also needs US1 forward path + US4 MITM)
                      │        │        ├─> US8
                      │        │        └─> US9 (T092 also blocked on 018)
                      │        ├─> US3
                      │        └─> US4
                      └─(P1, P2 shippable immediately)
```

### Within each story

Tests are written and observed failing first. Then come types and state, then the worker side, then
the harness side, then the tool, then registration.

## Parallel Opportunities

- **Setup**: T003 and T006 run alongside T001–T002.
- **Foundational**: four parallel lanes:
  1. P1: T007 → T008 → T009.
  2. P2: T010 → T011, T012.
  3. P3, P4 and P5: T013 → T014 → T015 ‖ T016 → T017 → T018 ‖ T019 → T020.
  4. Core, control and store: T021 ‖ T022 → T023 → T024 → T025, T026 ‖ T027 → T028 ‖ T029 → T030.
- **US1**: tests T031–T034 all in parallel. T036, T037 and T039 can proceed together once T035 lands.
- **US2**: tests T049–T051 in parallel. T052, T054, T057 and T059 are in different files and run in parallel.
- **After US2**: US3, US4 and US8 can be staffed in parallel. US5 → (US6 ‖ US7).

### Parallel example: US2

```text
Task: "T049 [US2] http_send tests in tests/intercept_tools.rs"
Task: "T050 [US2] http_history tests in tests/intercept_tools.rs"   # same file — coordinate or sequence
Task: "T052 [US2] raw writer in src/intercept/worker/raw.rs"
Task: "T054 [US2] pacing in src/intercept/worker/pace.rs"
Task: "T057 [US2] query in src/intercept/query.rs"
Task: "T059 [US2] slicing/decoding in src/intercept/slice.rs"
```

## Implementation Strategy

### MVP first (M1 = US1 + US2)

1. Land **P1**, **P2** and **P5** as standalone PRs. They are value on their own and de-risk US1 and US3.
2. Finish the rest of Foundational: P3, P4, policy, control, store.
3. US1, then **run the VM matrix** (T048). M1 is not done on host tests alone.
4. US2, then the quickstart M1 manual smoke. Demo the MVP.

### Incremental delivery

- **M2**: US3, US4, US5, each demonstrable on its own against `vuln_target`.
- **M3**: US6, US7, US8, then the SC-005 evaluation (T088).
- **M4**: US9's pane and HAR, then T092 once 018 merges.

### Notes

- Every new refusal path needs a test that exercises it before the code exists (constitution quality gate).
- Keep proxy-layer events and kernel audit events distinct in every new type and renderer (FR-009/FR-011).
- Commit per task or per logical group, on feature branches via PR (repository workflow).
