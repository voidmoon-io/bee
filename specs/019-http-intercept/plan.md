# Implementation Plan: Agent-First HTTP(S) Interception Under Kernel-Enforced Scope

**Branch**: `019-http-intercept` | **Date**: 2026-10-10 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/019-http-intercept/spec.md`

## Summary

Give bee an interception proxy the agent drives through first-class tools, and make the target scope
a property the kernel holds rather than a filter on a history view.

Topology. One long-lived `bee proxy-worker` per session runs in its **own kernel scope** (the *proxy
scope*), whose network rules are the resolved target and egress hosts and whose filesystem posture is
write-default-deny with reads of the project, home directories and credential paths denied (the
kernel file model is a deny list, so this is a *reduced* read surface, not an empty one — research R2). Tool children run in the tool scope as today, but when `[policy.http]` is present, their only
network rule is `127.0.0.1:<proxy-port>`. The harness binds that port itself before compiling the tool
policy and hands the listening socket to the worker as fd 3. A child that ignores `HTTP_PROXY` reaches
nothing, so proxy-unaware clients fail closed, and the proxy cannot reach anything the operator did
not name (research R2, R4).

Two enforcement layers, kept apart. The kernel enforces IP:port for both scopes. The proxy enforces
host names, CONNECT-host = SNI, egress-vs-target role, and pacing in user space. Every scope rule
shown to the model is labelled with the layer that enforces it (Constitution III; spec FR-011).

Agent-first surface. Model-originated traffic (`http_send`, `http_replay`, `http_fuzz`) goes through
a **raw HTTP/1.1 writer** in the worker, so requests are byte-exact. Traffic forwarded from other tools
goes through a hyper 1.x proxy that preserves header case (R1). Every exchange is attributed to
the tool call that caused it by a per-call credential in `HTTP_PROXY` userinfo (R6). It lands in a
harness-owned SQLite index plus content-addressed body blobs under `.bee/http/` (R8). The tools return
identifiers, compact rows, bounded slices, measured diffs (with a noise probe for volatility, R10),
and clustered fuzz summaries (R15), never raw dumps.

Prerequisites carry their own value and ship first:
- **P1**: tool output is enveloped as untrusted data and error status reaches the model (R12).
- **P2**: the consent prompt actually displays network/exec grants, and reactive denial escalation
  matches the kernel's op names. Both are verified defects in 007 (R13).
- **P3**: call context plus harness-controlled environment injection.
- **P4**: a sidecar scope on `EnforcedSandbox`, a small bridge that 018's Supervisor later absorbs.
- **P5**: kernel connect denials record their destination (`ip:port`) in the existing audit target
  field, with no layout change (research R13). FR-009 needs it, and it also revives reactive network escalation.

## Technical Context

**Language/Version**: Rust stable (1.96 locally/CI). App package MSRV stays **1.88** (`rcgen` 0.14's
floor equals it); core crates stay 1.85 and gain only types.

**Primary Dependencies**: all optional, application package only, behind `intercept`.
- **Already in `Cargo.lock`**: hyper 1.x, hyper-util 0.1, http-body-util 0.1, rustls 0.23 +
  tokio-rustls 0.26 (crypto provider `aws-lc-rs`, as already resolved), webpki-roots 1.0,
  httparse 1.10, flate2 1.1, similar 2.7, regex 1.13.
- **New**: rcgen 0.14 (`aws_lc_rs`, `zeroize`), rusqlite 0.40 (`bundled`), brotli-decompressor 6.0,
  ruzstd 0.9, json-patch 4.2.
- tokio is already an app dependency.
- A second, test-only feature `vm-test` (implies `intercept`) compiles the worker's `debug.connect`
  control frame used by the `http-proxy-scope` VM case. It is never in a shipping build: only
  `test/vm/matrix.sh` enables it.
- Full table: research R20.

**Storage**: `.bee/http/index.sqlite` (WAL) + `.bee/http/blobs/<aa>/<sha256>`; harness is the sole
writer per session ([contracts/store.md](./contracts/store.md)). Session CA bundle (certificate only)
at `$XDG_RUNTIME_DIR/bee/<session>/ca-bundle.pem`, deleted at teardown.

**Testing**: `cargo test` host tier for tools/store/proxy-layer logic against an in-repo fixture
target (`tests/support/vuln_target.rs`). Property tests for `[policy.http]` attenuation. VM tier:
ten new cases in `test/vm/remote-matrix.sh`, which are mandatory for M1 ([quickstart.md](./quickstart.md)).

**Target Platform**: Linux, BPF-LSM for enforcement. Host mode / non-`enforce` builds run only with
`--http-scope-advisory` (R17).

**Project Type**: Rust workspace, library-first; new code in the application package (`src/intercept/`,
`src/tools/http.rs`), plus types and pure logic in `bee-core`.

**Performance Goals**:
- SC-007: ≤ 50 ms median / ≤ 200 ms p95 added latency on a local target.
- `http_history` over 100k exchanges answers in < 200 ms (indexed).
- Fuzz pacing is exact to the token bucket.

**Constraints**:
- Every tool response is bounded: 100 KiB global cap plus per-tool bounds in [http-tools](./contracts/http-tools.md).
- The CA private key exists only in worker memory.
- HTTP/1.1 only; WebSocket → 501 (R18).
- The concurrent runner is refused with `intercept` until 018 (R2).

**Scale/Scope**: M1 = P1–P4 + US1 + US2. M2 = US3–US5. M3 = US6–US8. M4 = US9 (per-subagent part
blocked on 018).

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **I — Deny-by-Default & Fail-Closed** ✅
  - `[policy.http]` present ⇒ the tool scope gets exactly one network rule, so `FLAG_NET_ENFORCED`
    is always set and an "empty list = open" scope cannot occur (R4).
  - Unknown keys, role conflicts, `inspect ⊄ targets`, and direct `network.allow` alongside
    `[policy.http]` are all compile errors.
  - A dead worker means `Unavailable` and no traffic at all, never direct egress.
  - The concurrent runner is refused. Sessions without *blocking* enforcement are refused unless
    explicitly acknowledged: host mode, non-`enforce` builds **and `mode = "observe"` policies**,
    because observe mode audits and then allows (research R17).
  - An over-limit fuzz is refused before the first request.
  - Consent timeout means denied (existing).
  - **Gates**: `intercept_proxy.rs` covers each refusal kind; `http_policy.rs` covers each compile
    error; a fail-closed test kills the worker mid-session and asserts `bash`+`curl` fails and no
    `http_*` tool reports success.
- **II — Capability Attenuation** ✅
  - `[policy.http]` subset rules (targets, egress, inspect patterns, insecure_upstream, limits)
    live in `attenuation.rs`, and an absent child section inherits the parent's.
  - Scope widening goes through the existing ceiling check before consent.
  - **Gate**: proptest that no derivation and no sequence of `http_targets` grants yields a scope
    outside the ceiling (reusing the 007 grant-sequence harness).
- **III — Kernel Enforcement Is Authoritative** ✅ *with labelling*
  - The kernel enforces both reachability claims: tool → proxy only, and proxy → resolved targets
    only.
  - Host name, SNI, role and pacing are user-space checks. They are **not presented as kernel
    guarantees**: each scope entry carries `enforced_by`, `http_scope` shows the layer, refusals say
    which layer refused, and proxy events are a distinct type from kernel `AuditEvent`s (R14).
  - Proxy-scope kernel denials are recorded, not discarded: the drain change in P4.
  - Kernel connect denials name their destination (P5), so FR-009 holds for both layers.
  - The proxy scope's filesystem boundary is stated as it really is. The kernel file model is a
    deny list, so the proxy scope is write-default-deny with reads of the project, home and
    credential paths denied: a *reduced* read surface, not an empty one (research R2).
  - The store is protected from tool children by `PROTECTED_DEFAULTS`, and that is now tested.
  - The proxy scope keeps an exact read rule for the worker binary, so the deny prefixes cannot
    block its own exec (research R2).
  - **Gates** add the VM cases `http-store-protected` and `http-proxy-fs-deny`, plus an
    observe-mode refusal test.
  - **Gate**: the VM cases `http-direct-target`, `http-direct-other` and `http-proxy-scope`.
- **IV — Policy-as-Data** ✅
  - Scope, inspection list and limits are declarative TOML in `[policy.http]`, reviewable without
    running bee.
  - Model-installed intercept rules are session-only runtime state, not policy. They cannot widen
    scope, because rewritten requests are re-checked.
  - **Gate**: `bee validate` round-trips the section, and its error messages name fields.
- **V — Library-First, Runtime-Free Core** ✅
  - `bee-core` gains types and pure functions only, with no dependency and no async.
  - All network/TLS/SQLite/async code is in the application package behind a default-off feature.
  - **Gate**: `tests/core_deps_guard.rs` extended with hyper, rustls, rcgen, rusqlite, json-patch.
    A default build's `cargo tree` is unchanged (SC-009).
- **Platform constraints** ✅
  - The worker gets the same process hardening as every child: non-dumpable, no core,
    `LD_*` stripped. That also matters for the in-memory CA key.
  - `.bee/` stays protected; the store is harness-owned.
- **Quality gates** ✅
  - Enforcement tests (proxy refusals, attenuation, VM cases) are written failing first.
  - SC-007 latency is a benchmark (`benches/intercept_latency.rs`), gated in the VM matrix
    (`http-latency`) rather than on shared CI runners (research R19a).

**Result: PASS.** No principle violations. The structural choices listed under Complexity Tracking are
recorded because they add moving parts, not because they deviate.

*Post-design re-check (after Phase 1)*: PASS. The contracts preserve every gate above. Two points
were re-verified against the design:
1. The control channel carries the CA certificate but never the key (proxy-control invariant 1).
2. Structured `http_send` is serialised in the harness, so the worker has a single send path, and it
   re-checks scope on `send` even though the harness already did (invariant 2, defence in depth).

## Project Structure

### Documentation (this feature)

```text
specs/019-http-intercept/
├── spec.md
├── plan.md              # This file
├── research.md          # Phase 0 — R1–R20
├── data-model.md        # Phase 1
├── quickstart.md        # Phase 1
├── contracts/
│   ├── policy-http.md       # [policy.http] schema, compile errors, layer table
│   ├── http-tools.md        # model-facing tool schemas + bounds
│   ├── proxy-control.md     # harness ↔ proxy-worker framing and invariants
│   ├── store.md             # .bee/http layout + SQLite schema v1
│   └── model-framing.md     # provenance, untrusted envelope, error prefix (P1)
├── checklists/
│   └── requirements.md
└── tasks.md             # Phase 2 (/speckit-tasks — not created here)
```

### Source Code (repository root)

```text
crates/ebpf/src/main.rs  # P5: socket_connect writes the decoded family/port/addr into the audit target
crates/core/src/
├── audit.rs             # P5: format a Connect target as ip:port / [v6]:port
├── policy.rs            # + HttpPolicy, HttpLimits, HostPort, HostPattern (deny_unknown_fields)
├── compiler.rs          # + compile_http → CompiledHttp { proxy_scope, http_scope }; tool-scope loopback rule
├── attenuation.rs       # + http subset rules
└── pattern.rs           # NEW: HostPattern (DomainPattern semantics lifted from src/mcp/policy.rs)

src/
├── sandbox.rs           # P3: CallContext, env injection after restrict_env; P4: sidecar scope,
│                        #     tagged multi-scope drain, reload_sidecar
├── provider/rig_model.rs# P1: provenance rendering, [tool error] prefix, untrusted envelope
├── tools.rs             # + Provenance on ToolResult; HTTP_TOOLS; NotCompiledIn arms
├── tools/http.rs        # NEW: http_scope/send/get/history/replay/sitemap/fuzz/intercept/leads
├── skills/grant.rs      # P2: GrantRequest + net, exec, http_targets
├── grants/              # P2: op-name fix; + GrantDelta.http_targets; ProxyRefusal origin; target-scope ActivePolicy
├── episode.rs, repl.rs  # P3: set_call_context around execute; ProxyRefusal escalation path
├── app/session.rs       # P4: bind loopback listener, compile http, create sidecar scope, spawn worker
├── app/                 # --http-scope-advisory flag; refuse concurrent + intercept
├── main.rs              # hidden `proxy-worker` subcommand
├── findings.rs          # M3: evidence_refs on Observed
├── session/event.rs     # SessionEvent::Proxy, ::HttpExchange (M4 pane)
├── tui/                 # M4: live history pane (panels.rs / app.rs / view.rs)
└── intercept/           # NEW, #[cfg(feature = "intercept")]
    ├── mod.rs
    ├── control.rs       # frame codec + message types (both sides)
    ├── sidecar.rs       # harness: spawn worker on fd 3, control client, restart-once policy
    ├── creds.rs         # harness: token mint/issue/revoke
    ├── store.rs         # harness: SQLite + blobs, eviction, schema version
    ├── query.rs         # harness: history filter → SQL
    ├── slice.rs         # harness: decode (capped), range/grep/json-pointer
    ├── diff.rs          # harness: text/JSON diff, volatility
    ├── fuzz.rs          # harness: template expansion, clustering
    ├── passive.rs       # harness: lead checks on insert
    ├── har.rs           # M4: export
    └── worker/          # runs inside the proxy scope
        ├── mod.rs       # entry: fd 3 checks, crypto provider, control loop
        ├── listen.rs    # hyper http1 server with upgrades; credential check; attribution
        ├── connect.rs   # CONNECT gate, ClientHello buffering + SNI check, tunnel splice
        ├── mitm.rs      # session CA (rcgen), leaf cache, LazyConfigAcceptor, upstream TLS
        ├── forward.rs   # forwarded-traffic path (hyper, case-preserving)
        ├── raw.rs       # raw HTTP/1.1 writer + httparse response framing
        ├── scope.rs     # HttpScope checks (host/role/SNI), re-check on rewrite
        ├── pace.rs      # token bucket + concurrency
        └── rules.rs     # intercept rules, holds, auto-forward

tests/
├── tool_output_framing.rs   # P1
├── dynamic_grants.rs        # P2 (extended)
├── http_policy.rs           # schema, compile errors, attenuation proptests
├── intercept_proxy.rs       # refusals, credentials, SNI, egress-only, worker death
├── intercept_tools.rs       # M1 tools vs fixture
├── intercept_store.rs
├── intercept_tls.rs         # M2
├── intercept_replay.rs      # M2
├── intercept_fuzz.rs        # M3
├── intercept_rules.rs       # M3
├── intercept_har.rs         # M4
├── core_deps_guard.rs       # extended
└── support/vuln_target.rs   # fixture server (also `examples/vuln_target.rs` for manual smoke)

test/vm/remote-matrix.sh     # + http-in-scope, http-out-of-scope, http-direct-target,
                             #   http-direct-other, http-proxy-scope, http-sni-mismatch,
                             #   http-store-protected, http-proxy-fs-deny, connect-target-audited,
                             #   http-latency (SC-007)
benches/intercept_latency.rs # SC-007
```

**Structure Decision**: Follow the 016 native-tool pattern: a feature-gated module, a hidden worker
subcommand, a `Tool` impl per tool, and `NotCompiledIn` stubs. The worker lives under
`src/intercept/worker/` rather than a separate crate, because it shares the control types with the
harness side and has exactly one consumer (ADR-0002's reasoning). Policy types go in `bee-core`
because attenuation and `bee validate` must see them.

### Delivery order

| Slice | Contents | Independently valuable? |
|---|---|---|
| **P1** | provenance + untrusted envelope + error prefix | Yes: hardens every existing tool against injected output |
| **P2** | GrantRequest shows net/exec; op-name fix + tests | Yes: fixes two verified 007 defects |
| **P3** | CallContext; env injection hook in `tool_command` | Enables attribution; no behaviour change without `intercept` |
| **P4** | sidecar scope; multi-scope tagged drain; `reload_sidecar` | Enables any second scope; deleted when 018 lands |
| **P5** | kernel connect audit carries `ip:port` | Yes: every kernel network denial becomes actionable, and reactive network escalation works |
| **M1** | `[policy.http]` + worker (CONNECT/SNI gate, forward path, raw writer) + store + `http_scope/send/get/history` + VM cases | The MVP: US1 + US2 |
| **M2** | MITM + CA bundle; `http_replay`, `http_sitemap`; ProxyRefusal escalation | US3–US5 |
| **M3** | `http_fuzz`, `http_intercept`, passive leads + `http_leads`, finding evidence refs; SC-005 eval | US6–US8 |
| **M4** | TUI pane, HAR export; per-subagent scopes after 018 | US9 |

## Complexity Tracking

> No constitution violations. Recorded: structural choices that add moving parts, and why the simpler
> option was rejected.

| Choice | Why Needed | Simpler Alternative Rejected Because |
|---|---|---|
| Second kernel scope per session (sidecar, P4) before 018 | The proxy must be kernel-confined separately from tool children (Constitution III; US1) | Proxy in harness: unconfined deputy. Proxy in tool scope: children could reach targets directly. Waiting for 018: blocks the feature on an unimplemented restructuring |
| Two HTTP send paths (raw writer + hyper forwarder) | FR-018 byte-exact requests are unrepresentable in hyper/`http` | Raw-only forwarder: a hand-written streaming proxy server is the highest-risk code for no gain on traffic the model didn't author |
| SQLite (C, `bundled`) for the store index | Multi-column filtered history queries over ~100k rows, two-process writers | JSONL: full scans for every query. redb: single-process file lock |
| Harness-bound listener passed as fd 3 | Port must be known before the tool policy compiles | Worker binds and reports the port: needs a tool-scope reload at start, plus an ordering window |
| `http_leads` tool (not in the spec's tool list) | US8 acc. 2 needs leads listable on request | Overloading `http_history` mixes exchanges with observations |
