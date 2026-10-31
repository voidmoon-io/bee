#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test --offline --features findings --test evidence_receipts --test finding_ledger --test episode_loop --test fail_closed_tools
cargo check --offline --no-default-features
