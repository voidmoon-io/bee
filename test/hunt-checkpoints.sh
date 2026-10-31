#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test --offline --features source --test hunt_checkpoints --test pinned_source --test evidence_receipts --test fail_closed_tools
cargo test --offline --no-default-features --test fail_closed_tools
cargo clippy --offline --features source --all-targets -- -D warnings
