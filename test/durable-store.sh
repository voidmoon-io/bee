#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test --offline --no-default-features --features durable-store --lib session::durable::store::tests
cargo test --offline --features durable-store --lib session::durable::store::tests
cargo test --offline --features durable-store --test durable_sessions --test episode_loop
cargo test --offline --no-default-features --test durable_sessions
cargo clippy --offline --features durable-store,repro --all-targets -- -D warnings
