#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
bash test/durable-driver.sh
cargo test --offline --features durable-sessions,repro --test durable_investigation
cargo test --offline --no-default-features --features durable-sessions,repro --test durable_investigation
cargo test --offline --features repro --test controlled_reproduction --test pinned_reproduction
# Kernel recovery is a separate gate: bash test/vm/durable.sh (requires the running VM).
