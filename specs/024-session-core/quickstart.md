# Quickstart: validating 024-session-core

How to prove each phase works. The contracts are in [contracts/](./contracts/) and the types in
[data-model.md](./data-model.md).

## Prerequisites

- A stable Rust toolchain, run from the worktree root (`~/git/bee-024`).
- No BPF-LSM kernel is needed for anything below except the last section.

## Every phase: the full gate

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --features intercept -- -D warnings
cargo clippy --workspace --all-targets --features intercept,enforce,concurrent -- -D warnings
cargo test --workspace                                   # default features
cargo test --workspace --features intercept,test-support
```

Every PR must keep all five green (FR-041, SC-008).

## PR1: characterization (before any refactor)

```bash
cargo test --features intercept,test-support --test call_characterization
cargo test --features intercept,test-support --test session_parity -- --include-ignored
cargo test --test episode_progress_strings
cargo test --test test_support_absent    # the guard: default/release builds lack the feature
```

**Expected**:

- `call_characterization` passes. Every drift assertion is marked `// DRIFT FR-0xx` and asserts *today's*
  behaviour.
- `session_parity` lists its known differences: scanner dir, `--task` MCP/skills, concurrent drops,
  teardown order, system prompt.

## PR2: tool surface

```bash
cargo test --features intercept,test-support --test tool_surface
```

**Expected**:

- An `http_*` tool granted mid-session reaches the running Interceptor.
- A granted `record_finding` writes to the session ledger.
- A granted `scan` sees the session's scanner grants.
- `surface()` is identical for granted and start-up tools.

## PR3: call lifecycle

```bash
cargo test --features intercept,test-support --test call_lifecycle
```

This runs the SC-004 matrix directly against `run_call`:

- no denial;
- kernel denial → granted → retry;
- kernel denial → refused;
- kernel denial → already held;
- proxy refusal → granted → retry;
- retry timed out (`Deadline` and `PerCall`, where the retry gets only the remaining time);
- late audit.

**Expected**: all pass. In `call_characterization`, the FR-021/022/024/025 drift assertions are flipped,
and both loops now record identical normalized audits.

## PR4: hooks and leases

```bash
cargo test --features test-support --test hooks_leases
```

**Expected**:

- A `Deny` hook stops a call before it runs.
- `Deescalate` narrows the scope.
- A `Ttl::Turns(2)` lease expires after two *model* turns, even when one turn makes three tool calls.
- MCP refresh fires at turn start.
- Deny beats Escalate.

## PR5: Session builder and Operator

```bash
cargo test --features intercept,test-support --test session_parity      # no longer ignored
cargo test --features test-support --test operator
```

**Expected**:

- Snapshots from `Headless`, `Repl`, `Tui` and `Batch{concurrent:false}` are identical.
- `Batch{concurrent:true}` with MCP or `[policy.http]` is refused, naming the feature.
- The Autonomous operator run makes zero prompts and records two `ConsentRecord`s: one `Granted`, one
  `BeyondCeiling` (SC-005).
- An Interactive `ChannelConsent` with no reply is recorded as `TimedOut` after the timeout. This uses a
  paused clock.

Manual check (interactive):

```bash
# .bee/config.toml: a policy (e.g. policies/subagent.toml) and a wider ceiling (e.g. policies/parent.toml)
cargo run -- repl
# Ask the model to read a file outside the policy but inside the ceiling.
# Expected: the request is shown above the `bee>` prompt. Typing "y" grants it; the call retries.
# Typing anything else is queued as steering and the question is shown again.
```

```bash
cargo run -- run --task "list the files"   # with an MCP server configured in .bee/config.toml
# Expected: the MCP tools appear in the episode header's tool list (FR-009).
```

## PR6: Interceptor operations

```bash
cargo test --features intercept,test-support --test intercept_ops
cargo test --features intercept --test intercept_tools --test intercept_replay --test intercept_fuzz \
  --test intercept_rules --test intercept_leads --test fail_closed_tools --test tool_output_framing
```

**Expected**: the op-level tests pass (redirect stop, sitemap, replay diff), and every existing tool test
passes unchanged.

## VM tier (kernel enforcement; Constitution III)

Lease expiry and release newly narrow the kernel scope (FR-042), so the matrix gains `lease-expiry` and
`lease-release` cases in PR4. They must pass before PR5 starts. The rest of the matrix is a regression
check:

```bash
test/vm/remote-matrix.sh                 # includes lease-expiry, lease-release
```

**Expected**: during the lease, the granted read succeeds. After the next turn starts (expiry), or after
the `Deescalate` hook fires (release), the same read is denied by the kernel, and an audit event
`file_open denied` is recorded.
