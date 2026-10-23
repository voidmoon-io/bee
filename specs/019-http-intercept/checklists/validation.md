# 019-http-intercept — validation record

Recorded 2026-10-10, branch `019-http-intercept`.

## Host tier — PASS

Linux 6.6 (WSL2), Rust 1.96, no BPF-LSM. The interception sessions ran in advisory mode
(`--http-scope-advisory`), as the quickstart's host tier prescribes.

| Check | Command | Result |
|---|---|---|
| Default build unchanged (SC-009) | `cargo tree -e normal,build` vs `origin/main` | identical except local paths |
| Core stays runtime-free (Constitution V) | `cargo test --test core_deps_guard` | pass |
| Full suite, default features | `cargo test --workspace` | 740 passed, 0 failed |
| Full suite, `intercept` | `cargo test --workspace --features intercept` | 859 passed, 0 failed |
| Full suite, `mcp,sec,intercept,tui` | `cargo test --workspace --features mcp,sec,intercept,tui` | 1003 passed, 0 failed, 4 ignored (Node-dependent MCP smoke, pre-existing) |
| Clippy, three configurations | `cargo clippy --workspace --all-targets` with none / `intercept` / `intercept,enforce,sec,mcp,tui` | clean |
| P1 framing | `tests/tool_output_framing.rs` | pass |
| `[policy.http]` schema, compile errors, attenuation | `tests/http_policy.rs`, `crates/core/tests/http_attenuation.rs` | pass |
| US1 proxy refusals, SNI, drift, fail-closed | `tests/intercept_proxy.rs` (11) | pass |
| Session construction, `--http-scope-advisory` | `tests/intercept_session.rs` | pass |
| US2 tools | `tests/intercept_tools.rs` (9) | pass |
| Store | `tests/intercept_store.rs` (9) | pass |
| US3 escalation | `tests/intercept_escalation.rs` (6, including the SC-010 proptest) | pass |
| US4 TLS, SC-008 | `tests/intercept_tls.rs` (5) | pass |
| US5 replay, sitemap | `tests/intercept_replay.rs` (5) | pass |
| US6 fuzz, SC-006 | `tests/intercept_fuzz.rs` (6) | pass |
| US7 rules | `tests/intercept_rules.rs` (5) | pass |
| US8 leads, evidence refs | `tests/intercept_leads.rs`, `tests/finding_ledger.rs` | pass |
| US9 pane snapshot, HAR | `tests/grid.rs`, `tests/intercept_har.rs` | pass |

### SC-007 latency, host (informational, not the gate)

`BEE_LATENCY_REPORT=1 cargo bench --features intercept --bench intercept_latency` (release, loopback,
advisory worker):

| | criterion mean | 
|---|---|
| direct GET | 228 µs |
| proxied GET | 953 µs |
| **added, median of 1,000** | **0.41 ms** |
| **added, p95 of 1,000** | **0.98 ms** |

This is well inside the 50 ms median / 200 ms p95 budget. The gate is the `http-latency` VM case
(research R19a).

## VM tier — NOT RUN

The matrix VM (`ac-matrix-vm` in `ac-matrix`) did not exist when this was recorded: no VM,
DataVolume or launcher pod. The 019 cases are written and syntax-checked, and
`test/vm/matrix.sh` builds the `vm-test` feature they need:

`connect-target-audited`, `http-in-scope`, `http-out-of-scope`, `http-direct-target`,
`http-direct-other`, `http-proxy-scope`, `http-sni-mismatch`, `http-store-protected`,
`http-proxy-fs-deny`, `http-latency`.

**M1 is not done until these pass** (tasks.md, T048 checkpoint). Run `./test/vm/matrix.sh` once the
VM is re-provisioned, and record the results here.

## Manual quickstart smoke — NOT RUN

The M1/M2 manual steps need a live provider in an interactive REPL, which needs an operator.
