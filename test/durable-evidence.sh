#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test --offline --no-default-features --test durable_sessions
cargo test --offline --no-default-features --features durable-store,findings --test durable_evidence --test evidence_receipts
cargo test --offline --no-default-features --features durable-store --lib session::durable::store::tests
cargo test --offline --features durable-store,repro --lib session::durable::store::tests
cargo test --offline --features durable-store,repro --test durable_sessions --test durable_evidence --test evidence_receipts --test finding_ledger --test episode_loop --test fail_closed_tools --test pinned_source --test hunt_checkpoints --test controlled_reproduction --test pinned_reproduction --test hardening
cargo test --offline --features durable-store,repro --lib session::tests
cargo clippy --offline --features durable-store,repro --all-targets -- -D warnings
