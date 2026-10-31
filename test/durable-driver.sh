#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test --offline --no-default-features --features durable-sessions --test durable_driver --test durable_command --test durable_sessions --test durable_evidence
cargo test --offline --features durable-sessions,repro --test durable_driver --test durable_command --test durable_sessions --test durable_evidence
cargo test --offline --features durable-sessions,repro --lib session::
cargo test --offline --features durable-sessions,repro --lib repl::
cargo test --offline --features durable-sessions,repro --test episode_loop --test run_command --test repl_command --test hardening --test fail_closed_tools --test evidence_receipts --test finding_ledger --test pinned_source --test hunt_checkpoints --test controlled_reproduction --test pinned_reproduction --test dynamic_grants --test descendant_cleanup --test panel_replay --test tui_restore --test tui_fallback
cargo test --offline --no-default-features --test durable_sessions --test episode_loop --test fail_closed_tools
cargo clippy --offline --features durable-sessions,repro --all-targets -- -D warnings
