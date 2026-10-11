# Quickstart: Agent-First HTTP(S) Interception

Runnable validation, milestone by milestone. Contracts:
[policy-http](./contracts/policy-http.md) · [http-tools](./contracts/http-tools.md) ·
[proxy-control](./contracts/proxy-control.md) · [store](./contracts/store.md) ·
[model-framing](./contracts/model-framing.md).

Two tiers, as in 016:
- **Host tier** (laptop, no kernel enforcement): correctness of tools, store, framing, proxy-layer
  scope checks. Sessions run with `--http-scope-advisory` and every result says
  `enforcement: "advisory"`.
- **VM tier** (BPF-LSM VM, see `test/vm/README.md`): the kernel half of US1. Not optional for M1 to be
  called done — a denial no test exercises is not enforced (constitution, quality gates).

## Prerequisites

- Rust 1.88+ (unchanged app MSRV; `rcgen` 0.14's floor equals it).
- A C toolchain (`cc`) for `rusqlite`'s bundled SQLite — the same requirement the `astgrep-*` grammars
  already have.
- `curl` on the host for the manual checks.

## Build

```bash
cargo build                                   # default: unchanged dependency graph (SC-009)
cargo test --test core_deps_guard             # hyper/rustls/rcgen/rusqlite absent from core crates
cargo build --features intercept              # host tier
cargo build --features intercept,enforce      # what the VM matrix ships (plus concurrent,sec)
```

## P1 — model framing (ships first, independent of interception)

```bash
cargo test --test tool_output_framing
```
Expected: an error result carries `[tool error]` in the provider request; child output is wrapped in a
nonce'd `untrusted-data` envelope; a forged closing tag inside content does not close it.

## M1 — scoped channel (US1, US2)

### Host tier

```bash
cargo test --features intercept --test http_policy        # schema, compile errors, attenuation proptests
cargo test --features intercept --test intercept_proxy    # CONNECT gate, SNI mismatch, bad credential, egress-only
cargo test --features intercept --test intercept_tools    # http_send/get/history/scope vs tests/support/vuln_target.rs
cargo test --features intercept --test intercept_store    # WAL, two-session writers, eviction, schema version
```

Manual smoke, against the in-repo fixture target (prints its port):

```bash
cargo run --features intercept --example vuln_target            # listens on 127.0.0.1:<T>
cat > /tmp/http-scope.toml <<EOF
[policy]
name = "smoke"
mode = "enforce"
[policy.exec]
allow = ["curl", "sh"]
[policy.http]
targets = ["127.0.0.1:<T>"]
EOF
./target/debug/bee repl --policy /tmp/http-scope.toml --provider <provider.toml> --http-scope-advisory
```
In the session, ask the model to fetch `/search?q=hello` with `http_send`, then with `bash` +
`curl`, then to query `http_history` for both. Expected: two rows, attributed to two different call
ids, `origin` = `tool` and `forwarded`. Ask it to fetch `http://example.com/`: refused with
`out_of_scope … layer: proxy`.

Without the flag:
```bash
./target/debug/bee repl --policy /tmp/http-scope.toml --provider <provider.toml>
```
Expected: refuses to start, naming `--http-scope-advisory` and the missing kernel enforcement (FR-010).
The same refusal happens in an enforce build when the policy says `mode = "observe"`.

### VM tier — new cases in `test/vm/remote-matrix.sh`

| Case | Action (from a tool child) | Expected |
|---|---|---|
| `http-in-scope` | `curl` via proxy to the in-VM target | 200, exchange recorded with call id |
| `http-out-of-scope` | `curl` via proxy to an out-of-scope host | proxy `403`, `ProxyEvent refused_out_of_scope`, no upstream SYN |
| `http-direct-target` | `curl --noproxy '*'` to the **in-scope** target | kernel deny on `connect`, `AuditEvent` scope=tool |
| `http-direct-other` | `curl --noproxy '*'` to any other address | kernel deny |
| `http-proxy-scope` | worker asked (via a test-only control frame) to connect off-scope | kernel deny, `AuditEvent` scope=proxy — **recorded, not discarded** |
| `http-sni-mismatch` | `openssl s_client -proxy … -connect target:443 -servername other` | tunnel closed, `refused_sni_mismatch` |
| `http-store-protected` | `cat .bee/http/index.sqlite`; `echo x > .bee/http/blobs/x` | both kernel-denied, `AuditEvent` scope=tool (FR-014) |
| `http-proxy-fs-deny` | worker asked (via `debug.read`, `vm-test` only) to open a file under `:project_root` | kernel deny, `AuditEvent` scope=proxy |
| `connect-target-audited` | any denied `connect` from a tool child | `AuditEvent.target` = `ip:port` (P5, FR-009) |

```bash
./test/vm/matrix.sh      # builds with --features concurrent,sec,vm-test (vm-test implies intercept)
```

## M2 — inspection, replay, escalation (US3, US4, US5)

```bash
cargo test --features intercept --test intercept_tls        # MITM for inspect hosts, tunnel otherwise, CA key never in frames/store
cargo test --features intercept --test intercept_replay     # edits, noise probe, volatile suppression, JSON paths
cargo test --features intercept --test dynamic_grants       # extended: GrantRequest renders net/exec/http_targets; atomic widen
```
Manual: with `inspect = ["127.0.0.1"]` against the fixture's TLS port, `curl https://…` from `bash`
succeeds **without** `-k` (the session bundle is trusted) and the body appears in `http_get`. After
the session, `grep -r "PRIVATE KEY" .bee/ $XDG_RUNTIME_DIR/bee/` finds nothing (SC-008).

Escalation: scope one fixture port, ask for the other; approve at the consent prompt — the prompt
**shows** `http_targets: 127.0.0.1:<T2>` — and the retry succeeds; decline and it stays refused (SC-010).

## M3 — fuzz, rules, evidence, leads (US6, US7, US8)

```bash
cargo test --features intercept --test intercept_fuzz       # 1,000 variants, 2 planted outliers, 10/10 runs (SC-006)
cargo test --features intercept --test intercept_rules      # modify/drop/hold, auto-forward, rewritten-out-of-scope refused
cargo test --features intercept,findings --test finding_ledger   # evidence refs resolve; evicted → "missing"
```

## M4 — surfaces (US9)

```bash
cargo test --features intercept,tui --test grid             # live history pane snapshot (insta)
cargo test --features intercept --test intercept_har        # export excludes CA key + bee credentials
```
Per-subagent scopes are validated with 018's quickstart once the Supervisor lands.

## SC-007 latency (Polish, T093)

Gated in the VM matrix, not on shared CI runners (research R19a): the `http-latency` case runs
`benches/intercept_latency.rs` on the dedicated VM and fails above 50 ms median / 200 ms p95 added
latency. Host CI only compiles the bench (`cargo bench --features intercept --no-run`).

## SC-005 evaluation (not a CI gate)

`specs/019-http-intercept/eval/README.md` (written in M3) describes the paired live-provider run against
`vuln_target`: shell+curl tool set vs. HTTP tool set, recording tool-call counts and tool-output tokens.
