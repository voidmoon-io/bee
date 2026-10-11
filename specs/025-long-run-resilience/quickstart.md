# Quickstart: validating Long-Run Resilience (025)

Every check below runs on a host with no model provider, network or BPF-LSM kernel (FR-040). Scripted
models are `MockModel::scripted` / `MockModel::from_fn`. A summary call is recognisable inside `from_fn`
because it is offered no tools. Denials come from 024's `test-support` scripted audit.

## Phase A — Stable envelope nonces

```sh
cargo test --lib provider::framing
cargo test --lib provider::rig_model -- nonce
```

Expected:

- Framing the same conversation twice gives byte-identical requests.
- A new tool result gets a nonce not seen before.
- A result's nonce never appears in any tool content that existed when the nonce was drawn.

## Phase B — Budget, output cap and size guard

```sh
cargo test --test context_budget
```

| Test | Shows |
|---|---|
| `window_from_table_provider_and_config` | precedence of R3 / contracts/config.md |
| `unknown_model_uses_default_and_says_so_once` | FR-001 notice, once |
| `cap_is_min_of_bytes_and_share` | FR-020, both branches (US4 AS-1, AS-2) |
| `cap_marker_states_original_size` | FR-021, including a result already cut by the tool |
| `record_keeps_uncapped_result` | FR-022: the transcript holds the tool's full output |
| `oversize_request_ends_context_exhausted` | FR-002 / FR-014 with compaction off: no request over budget is sent |
| `estimate_calibrates_from_usage` | R2: the ratio moves toward the observed bytes/token and stays clamped |

## Phase C — Stuck detection

```sh
cargo test --features test-support --test stuck_detection
cargo test --features intercept,test-support --test stuck_detection
```

| Test | Shows |
|---|---|
| `reminder_once_at_five` | US2 AS-1 |
| `stops_at_eight_failing` | US2 AS-2, SC-006: `Stuck{tool, arguments, repeats: 8}`, turn limit not reached |
| `different_call_resets` | US2 AS-3 |
| `key_order_is_irrelevant` | FR-023 |
| `alternating_success_does_not_stop` | edge case: only consecutive failures count |
| `denied_repeat_gets_policy_reminder_at_two` | US2 AS-4, SC-007 (scripted kernel denial) |
| `proxy_refused_repeat_gets_policy_reminder` | FR-026, proxy layer (intercept build) |
| `granted_retry_is_not_a_denied_repeat` | edge case |
| `repl_stop_ends_exchange_not_session` | US2 AS-5, FR-029 |
| `reminders_are_recorded` | FR-028: `TranscriptTurn.notes` |

## Phase D — Finish tool

```sh
cargo test --test finish_tool
cargo run -- run --task "say hello" --provider tests/fixtures/mock-finish.toml; echo "exit=$?"   # expect exit=0
```

| Test | Shows |
|---|---|
| `finish_completed_ends_run` | US3 AS-1: status, summary in record |
| `text_turn_gets_one_reminder` | US3 AS-2 |
| `second_text_turn_ends_without_finish` | US3 AS-3 |
| `calls_after_finish_not_run` | US3 AS-4, FR-034: `not_run` recorded, not executed |
| `invalid_finish_continues` | FR-032 |
| `repl_and_ctf_do_not_offer_finish` | US3 AS-5, AS-6, FR-037 |
| `scenario_opt_out_keeps_old_endings` | FR-031, FR-038 |
| `exit_codes` | contracts/finish.md table |
| `every_status_maps_in_batch_and_grid` | SC-008: `status_label`, `batch::Status`, `viz::grid` |

## Phase E — Compaction

```sh
cargo test --features test-support --test context_compaction
```

| Test | Shows |
|---|---|
| `below_soft_is_untouched` | US1 AS-5, SC-009 |
| `elides_before_summarizing` | US1 AS-1, FR-006, SC-003: zero summary calls when elision suffices |
| `summarizes_above_hard` | US1 AS-2: the summary call offered `[]` tools |
| `preamble_and_recent_window_verbatim` | FR-003, invariants in contracts/context.md |
| `calls_and_results_stay_paired` | FR-010 |
| `stub_keeps_denial` | US1 AS-3, SC-004 (scripted kernel denial and proxy refusal) |
| `summary_is_framed_untrusted_after_preamble` | FR-008 |
| `summary_failure_removes_with_marker` | FR-014 |
| `cannot_fit_ends_context_exhausted` | FR-014 |
| `no_compaction_next_turn` | FR-015 |
| `record_identical_with_and_without` | FR-011, SC-005 |
| `five_x_budget_run_completes` | SC-001 |
| `budgets_matrix_zero_overflow` | SC-002 (32k/64k/128k scripted budgets) |
| `summary_usage_counted_separately` | FR-012, FR-013 |
| `repl_clear_resets` | FR-019 |
| `progress_lines` | FR-018: pinned strings from contracts/context.md |

## SC-010 — Paired comparison before compaction is on by default

```sh
cargo run --release -- batch scenarios/ --provider <real provider> --set context.window_tokens=32000 --set context.compaction=false --out runs/off
cargo run --release -- batch scenarios/ --provider <real provider> --set context.window_tokens=32000 --set context.compaction=true  --out runs/on
```

Pair the runs by scenario id. Report: completed (finish `completed`) on/off, `ContextExhausted` count,
cost, and summary-call count. The default flips only when "on" has no fewer completions and fewer
context failures. If `batch` has no `--set`, the task adds one or uses per-scenario `[context]` tables.

## Regression gate (every phase)

```sh
cargo fmt --check
cargo clippy --all-targets --features intercept,test-support -- -D warnings
cargo test
cargo test --features intercept,test-support
cargo test --test call_characterization --test episode_progress_strings --features test-support
```

The 024 characterization and progress-string pins must pass unchanged. The only exceptions are the
additive lines listed in contracts/context.md and contracts/finish.md, each recorded in the PR.
