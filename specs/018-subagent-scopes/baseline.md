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
