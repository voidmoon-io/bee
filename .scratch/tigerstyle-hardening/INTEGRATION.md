# Integration with current main

Merged `50e0ee19a969e47644d6bb7a7fe2352774f3d088` into `fix/tigerstyle-hardening` on 2026-10-23.
All conflicts were resolved in merge commit `37ec9fb`. GitHub reports the branch mergeable.

The integration retains the shared `Session`, `run_call`, `turn_start` and operator protocols from
main, including proxy credentials, retry evidence, hook composition, MCP attribution, and the
context/stuck/finish behavior. Hardening uses those shared boundaries. HTTP policy cancellation
poisons further dispatch until the session shuts down. Empty initial HTTP scopes in test fixtures
were replaced with valid subsets, and the expired-deadline regression now requires zero dispatch.

## Verification

| Check | Result |
| --- | --- |
| Workspace with `NO_COLOR=1` | 855 passed |
| Headless | 545 passed |
| MCP/security/Rust grammar | 888 passed; 5 explicitly ignored |
| Shared session/call/turn/operator/context/finish suites | 80 passed |
| Shared suites plus live HTTP/TLS interception fixtures | 134 passed |
| Transcript compatibility, operator, CTF and hardening follow-up | 25 passed |
| Clippy: workspace, headless and all combined features | Passed with warnings denied on Rust 1.96 |
| Finding-ledger follow-up after the Rust 1.99 fix | 9 passed |
| VM parser fixtures | 3 methods passed |
| Live BPF-LSM VM matrix | All 50 cases passed on the final merged binary |
| Dedicated live kernel regressions | All 5 passed |

Counts are executions per command, not distinct tests across commands. Five kernel regressions ran
serially as root on the existing KubeVirt test VM. They cover attenuation defaults, canceled detached
descendants with sibling/service isolation, failed mandatory narrowing, finite lease expiry, and
executable inode pins. Host tests do not substitute for these kernel checks.

The full shared suites run with and without `intercept`, including the cancellation regression that
holds a proxy update pending, cancels it, and confirms no lease/tool was committed and no later
command executes. The legacy transcript suites require unchanged serialization of healthy old data;
audit-loss metadata remains explicit when non-default.

CI uses Rust 1.99, whereas the initial local toolchain was 1.96. Its additional `never_loop` finding
in the build without interception was fixed by checking feature availability after reference syntax
validation. Rust 1.99 Clippy for `mcp,sec,astgrep-rust` also passes with warnings denied. The initial remote CI
run passed build/tests, formatting and enforcement checks. The corrected Clippy path is included in
the follow-up commit; see the PR checks for the final remote result.

Fresh logs are captured under `evidence/integration/`; the older logs directly under `evidence/`
remain the original audited-baseline results. No production deployment was performed.

## Commands

```sh
NO_COLOR=1 cargo test --workspace --locked --offline
NO_COLOR=1 cargo test --no-default-features --locked --offline
NO_COLOR=1 cargo test --features mcp,sec,astgrep-rust --locked --offline
# Run both test-support commands exactly as listed in .github/workflows/ci.yml.
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo clippy --no-default-features --all-targets --locked --offline -- -D warnings
cargo clippy --features concurrent,mcp,sec,astgrep-rust,intercept,test-support,vm-test --all-targets --locked --offline -- -D warnings
cargo +1.99.0 clippy --features mcp,sec,astgrep-rust --all-targets --locked --offline -- -D warnings
cargo fmt --all -- --check
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/vm -p 'test_*.py'
cargo build --features concurrent,sec,vm-test --release --locked --offline
BEE_SKIP_BUILD=1 bash test/vm/matrix.sh
# On the reference VM, using the host-built test executable:
sudo ./bee-hardening-test kernel:: --ignored --test-threads=1 --nocapture
```
