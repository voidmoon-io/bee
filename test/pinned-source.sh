#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test --offline --features source --test pinned_source --test evidence_receipts --test fail_closed_tools
cargo check --offline --no-default-features
cargo check --offline --no-default-features --features gitlog
