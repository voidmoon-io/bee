#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test --offline --no-default-features --test durable_sessions
cargo test --offline --test durable_sessions --test episode_loop
cargo test --offline --lib session::tests
cargo clippy --offline --all-targets -- -D warnings
