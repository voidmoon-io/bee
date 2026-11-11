# Slice 1 baseline and gate (2026-11-09, `bee-build`, kernel 6.8.0-147, BPF-LSM armed)

| Check | origin/main (`846084b` tree) | Slice 1 |
|---|---|---|
| `cargo check --features enforce --tests` | OK | OK |
| `cargo check --features concurrent,mcp,sec,astgrep-rust,intercept,durable-sessions --tests` | OK | OK |
| `cargo clippy --features concurrent,mcp,sec,astgrep-rust,intercept --all-targets -D warnings` | **FAIL** — 2× `result_large_err` (`tools/repro.rs:90`, `tools/http.rs:80`), pre-existing; fixed on `feat/file-tools` (563d353) | same 2 only; clean with `-A clippy::result_large_err` |
| `cargo test --workspace` | OK | OK |
| `cargo test --features intercept,test-support` (CI target list) | OK | OK |
| `cargo test --features concurrent,sec,intercept --lib` | OK | OK |
| VM matrix (`--features concurrent,sec,vm-test` release) | 50/50 | **51/51** incl. new `concurrent-reload` |
| Root kernel suites (`--ignored`, as root): `hardening` | — | 6/6 |
| `codemode_kernel` | — | 20/20 (+ `subprocess_fixture`, a fixture that panics standalone by design) |
| `durable_kernel` | — | 4/4 (+ `kernel_child`, same) |

`concurrent-reload` on main: not executed against a main binary. It fails there by construction —
`session/spec.rs` refused any concurrent-batch scenario with a ceiling, so both episodes end as setup
errors and the case's first status check fails.

## PR 2 — MVP delegation (US3 + US1 + US2), 2026-11-09

| Check | Result |
|---|---|
| `cargo check` (default, `--no-default-features`, `enforce`, `concurrent,mcp,sec,astgrep-rust,intercept,durable-sessions,test-support`) | OK |
| clippy (`concurrent,mcp,sec,astgrep-rust,intercept`, all targets, `-A clippy::result_large_err`) | OK |
| `cargo test --workspace`, CI `test-support`/`intercept` list, `concurrent,sec,intercept --lib` | OK (incl. 9 new `tests/delegation.rs`, 4 new agent unit tests) |
| VM matrix | **53/53** — new `subagent-net-denied`, `subagent-overgrant-no-cgroup` |
| Root kernel suites | `hardening` 6/6, `codemode_kernel` 20/20, `durable_kernel` 4/4 |

Negative control: `subagent-net-denied` with the agent declaring both destinations (no narrowing)
**FAILs** (child reaches B, no denial) — the case tests attenuation, not setup.

## PR 3 — bounds and fan-out (US4 + US5, US6 closed), 2026-11-09

| Check | Result |
|---|---|
| `cargo check` (`enforce`, `concurrent,mcp,sec,astgrep-rust,intercept,durable-sessions`) | OK |
| clippy (`concurrent,mcp,sec,astgrep-rust,intercept` and default, all targets, `-A clippy::result_large_err`) | OK |
| host suites (workspace, CI `test-support`/`intercept` list, `concurrent` lib) | OK — `tests/delegation.rs` 15/15, 3 new `[delegation]` config tests |
| VM matrix | **54/54** — new `subagent-siblings-isolated` |

## PR 4 — child escalation (US7), 2026-11-09

| Check | Result |
|---|---|
| `cargo check` (`enforce`, `concurrent,mcp,sec,astgrep-rust,intercept,durable-sessions`) | OK |
| clippy (`concurrent,mcp,sec,astgrep-rust,intercept,durable-sessions,test-support`, all targets, `-D warnings -A clippy::result_large_err`) | OK |
| host suites (workspace, headless, CI `test-support`/`intercept` list) | OK — 4 new `delegate::tests`, 2 new `operator` tests, the delegation-tree property test, and `a_subagent_delegates_from_its_own_policy` |
| `--features mcp,sec,astgrep-rust` | 1 failure, environmental: `mcp_stdio::the_builder_registers_each_servers_process_with_the_sandbox` needs `node` on PATH, which `bee-build` lacks |
| VM matrix | **56/56** — new `subagent-escalate`, `subagent-escalate-beyond` |

Negative control: with the child's ceiling set to the *session* ceiling instead of the parent's
policy at spawn, `subagent-escalate-beyond` **FAILs** (the grant is given and the write lands), so
the case tests FR-015 rather than its setup.
