#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test --offline --features repro --test controlled_reproduction --test pinned_reproduction --test pinned_source --test evidence_receipts --test fail_closed_tools
cargo test --offline --features repro --test episode_loop --test hardening
cargo test --offline --features repro --bin bee project_configuration_may_not_set_operator_only_sections
cargo test --offline --no-default-features --test fail_closed_tools
cargo clippy --offline --features repro,source --all-targets -- -D warnings
