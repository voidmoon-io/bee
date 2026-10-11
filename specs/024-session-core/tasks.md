---
description: "Task list for 024-session-core"
---

# Tasks: One Session Core for Autonomous and Interactive bee

**Input**: Design documents from `specs/024-session-core/`

**Prerequisites**: [plan.md](./plan.md), [spec.md](./spec.md), [research.md](./research.md),
[data-model.md](./data-model.md), [contracts/](./contracts/), [quickstart.md](./quickstart.md)

**Tests**: These are **required**. The spec mandates characterization before refactoring (FR-040), a
host-testable call lifecycle (FR-026, SC-004), and a test for every drift fix (SC-003). The constitution
requires test-first for the security boundary. Every phase writes its tests first and sees them fail (or,
for characterization, sees them pin today's behaviour) before implementing.

**Organization**: Phases follow the **delivery order mandated by FR-041 and D6**, not story priority. One
phase is one PR:

characterization → tool surface (US4) → call lifecycle (US3) → hooks (US5) → Session builder (US1) →
Operator (US2) → Interceptor operations (US6)

Each later phase builds on the earlier owners: the builder wires the tool surface and the call
lifecycle, and the Operator plugs into the builder. Each story is still testable independently at its
phase's exit gate.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: can run in parallel (different files, no dependency on an incomplete task)
- **[Story]**: US1–US6 from spec.md
- Paths are relative to the repo root (`~/git/bee-024`)

## The gate (run at the end of every phase)

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --features intercept -- -D warnings
cargo clippy --workspace --all-targets --features intercept,enforce,concurrent -- -D warnings
cargo test --workspace
cargo test --workspace --features intercept,test-support
```

---

## Phase 1: Setup (shared test infrastructure)

**Purpose**: the `test-support` feature and its guard (research R1).

- [X] T001 Add the `test-support = []` feature to `Cargo.toml` `[features]`, with a comment in the `vm-test`
  style ("NEVER in a shipping build; host-only scripted audit for orchestration tests"). Test targets that need it
  are declared as `[[test]] name = "…" path = "tests/….rs" required-features = ["test-support"]`
  (research R1). Each task that creates such a test file adds its own entry in the same change, because
  Cargo rejects a `[[test]]` whose file does not exist yet; this task adds only PR1's entries
  (`call_characterization`). Do not use a self dev-dependency.
- [X] T002 [P] Create `tests/test_support_absent.rs` with two tests:
  - an always-on test that parses `Cargo.toml` (with the `toml` crate already in the tree) and asserts
    that the `default` feature list, and any `release`/`dist` sets, do not contain `test-support`,
    directly or through another feature;
  - a `#[cfg(not(feature = "test-support"))]` test asserting `!cfg!(feature = "test-support")`. It runs in
    the default-features gate step and compiles away in the `--features …,test-support` step, so the gate
    never fails on it.
- [X] T003 [P] Add the `test-support` and `intercept,test-support` test invocations to the CI workflow
  (`.github/workflows/*.yml`, whichever runs `cargo test`) without removing existing jobs.

---

## Phase 2: Foundational — characterization (PR 1, FR-040)

**Purpose**: pin today's behaviour through both loops before anything moves. ⚠️ No refactoring task in
any later phase may start until this phase is merged.

- [X] T004 In `src/sandbox.rs`, add `#[cfg(feature = "test-support")] pub struct ScriptedAudit { tool:
  Mutex<VecDeque<Vec<AuditEvent>>>, proxy: Mutex<VecDeque<Vec<AuditEvent>>> }` with `push_tool(batch)`,
  `push_proxy(batch)`. Add the field `#[cfg(feature = "test-support")] scripted:
  Option<Arc<ScriptedAudit>>` to `HostSandbox` (currently `src/sandbox.rs:183-185`) and the constructor
  `#[cfg(feature = "test-support")] pub fn host_scripted(strip_env: Vec<String>, audit:
  Arc<ScriptedAudit>) -> Sandbox`. In `drain_audit` (Host arm, `:773`) and `drain_sidecar_audit` (`:679`),
  pop one batch when `scripted` is set; otherwise behaviour is unchanged.
- [X] T005 [P] Create `tests/support/scripted.rs` (and declare it in `tests/support/mod.rs`, creating that
  if needed), containing:
  - an `ev(op, target, decision, scope_id)` `AuditEvent` builder;
  - a `FakeCallHooks` implementing `CallHooks` (`src/sandbox.rs:134-146`), returning scripted
    `ProxyEvent`s per call id;
  - a `FakeHttpScope` implementing `HttpScopeHook` (`:114-125`) that records updates;
  - a `RecordingConsent` (`ConsentSink`) with a scripted answer and a log;
  - a `ScriptedTool` (`impl Tool`) returning scripted `ToolResult`s with an optional delay (for
    timeouts under `tokio::time::pause`).
- [X] T006 Create `tests/call_characterization.rs` (gated on `test-support`; add its `[[test]] … required-features = ["test-support"]` entry to `Cargo.toml` in this task). For each scenario, run the
  **same** script through `bee::run_loop` (`src/episode.rs`) and `bee::repl::run_exchange`
  (`src/repl.rs`) with `MockModel::scripted` issuing one `ScriptedTool` call, then normalize each recorded
  call to `(call_id, content, is_error, [(op,target,decision,scope_id)], [proxy kind])`. Scenarios:
  1. no denial;
  2. kernel denial → `AllowWithinCeiling` → retry succeeds;
  3. kernel denial → beyond ceiling → refused;
  4. kernel denial, delta already held;
  5. proxy refusal → granted → retry (`FakeCallHooks` + `FakeHttpScope`);
  6. retry times out (paused clock);
  7. a proxy-scope denial present (scope_id `"proxy"`);
  8. a late tool-scope batch delivered on the sidecar drain.

  Assert today's results, and tag every place the loops differ with `// DRIFT FR-021`, `FR-022`, `FR-024`,
  `FR-025` or `FR-029`, asserting each loop's *current* value.
- [X] T007 [P] Create `tests/episode_progress_strings.rs`. Run `run_loop` with a recording `ProgressSink`
  across scenarios that emit every line listed in `contracts/operator.md` (header, turn, text, call,
  escalate, proxy event, result ok/ERR/DENIED, audit, done), and assert the exact strings.
- [X] T008 [P] Create `tests/session_parity.rs`. Write a test helper that builds a session the current way
  for the two entry points that can be built on a host today:
  - `bee::run_episode_with` setup (`src/episode.rs:689-963`), stopping before `run_loop` via a `MockModel`
    that ends at once;
  - the test harness `tests/support/harness.rs::Session::start`.

  The concurrent path needs `enforce` and a BPF-LSM kernel, and the REPL setup lives in the binary, so
  their parity is added in T047 and T061 once both go through the library builder. Capture the registry tool names (`registry.schemas()`), the effective policy filesystem keys, the
  escalation timeout, and the system prompt. Assert equality across paths, mark it `#[ignore = "known drift
  until phase 5: scanner dir, --task MCP/skills, concurrent drops, system prompt, teardown order"]`, and
  list each known difference in a comment. (The REPL setup lives in the binary; parity for it is added in
  T061.)
- [X] T009 Update the comment at `tests/dynamic_grants.rs:14-20` to record that the replay seam now exists
  behind `test-support` (research R1, plan Complexity Tracking), and that host reactive-retry coverage
  lives in `tests/call_characterization.rs` and `tests/call_lifecycle.rs`.
- [X] T010 Run the gate, and confirm `call_characterization` and `episode_progress_strings` pass and
  `session_parity` is ignored-with-reason. Open PR 1.

**Checkpoint**: today's behaviour is pinned. Every intended change in later phases shows up as a flipped
`// DRIFT` assertion.

---

## Phase 3: User Story 4 — Every granted tool works the moment it is granted (P2, PR 2)

**Goal**: one constructor builds every tool with its session dependencies (FR-013–FR-016).

**Independent Test**: grant `http_send`, `record_finding` and `scan` mid-session. Each uses the session's
Interceptor, ledger and scanner grants, and `surface()` matches a session that held them from the start.

### Tests (write first, see them fail)

- [ ] T011 [P] [US4] Create `tests/tool_surface.rs`, with:
  - (a) a registry built with `ToolDeps { ledger: Some(tmp) }`, where `register("record_finding")` writes
    to `tmp` (cfg `findings`);
  - (b) `register("http_send")` with `deps.interceptor = None` yields the 016 `InterceptorUnavailable`
    outcome, and with a running harness Interceptor reaches it (cfg `intercept`, use `tests/support/harness.rs`);
  - (c) `register("scan")` sees `deps.scanner_grants` (cfg `scanners`);
  - (d) a disabled feature yields `NotCompiledIn`;
  - (e) `register("submit_flag")` is a no-op unless `deps.ctf_flag` is set;
  - (f) `surface()` is identical for a tool registered at start and one registered after `escalate()`
    grants it (drive `bee::grants::escalate::escalate` on `Sandbox::host` with `AllowWithinCeiling`).

### Implementation

- [ ] T012 [US4] In `src/tools.rs`, add `pub struct ToolDeps` with:
  - `ctf_flag`
  - `#[cfg(feature="findings")] ledger, run_id`
  - `#[cfg(feature="scanners")] scanner_grants`
  - `#[cfg(feature="intercept")] interceptor: Option<Interceptor>`
  - `skills: Option<Arc<SkillRegistry>>`

  Add `deps: Arc<ToolDeps>` to `ToolRegistry`, plus `ToolRegistry::with_deps`, `set_deps`, `deps()`.
  Keep `ToolRegistry::new()` as `with_deps(Default)`.
- [ ] T013 [US4] In `src/tools.rs`, replace `register_named(r, name, flag)` (`:348-422`) with
  `ToolRegistry::register(&mut self, name) -> Result<(), UnknownTool>`, which builds each tool configured
  from `self.deps`:
  - security tools take their ledger, run id and grants, absorbing `configure_security_tools` (`:491`);
  - HTTP tools take the interceptor, absorbing `src/tools/http.rs::configure_http_tools` (`:25`);
  - `skill` is built from `deps.skills`.

  Delete `configure_security_tools` and `configure_http_tools`. Keep `registry_for(names, deps)` as a thin
  loop over `register`.
- [ ] T014 [US4] In `src/tools.rs`, add `pub struct SurfaceEntry { name, schema: ToolSchema, deps: DepsSummary
  }` and `ToolRegistry::surface()`. `DepsSummary` lists which dependencies the tool was built with, as
  booleans or ids, never secrets.
- [ ] T015 [US4] In `src/grants/escalate.rs` (`:147-149`), register granted tools via `registry.register(t)`.
  Before registering, if the delta changed the policy and cfg `scanners` is on, call
  `registry.set_deps(..)` with scanner grants recomputed from `active.active()`.
- [ ] T016 [US4] Update every caller to build `ToolDeps` first and register through it:
  - `src/episode.rs` (`:708` registry_for, `:754` skill grants, `:759` configure_security_tools, `:861`
    SkillTool insert, the `configure_http_tools` call);
  - `src/app/session.rs:150`;
  - `src/app/repl.rs` (`:160`, `:196-203`, the http configure);
  - `src/concurrent.rs:216`;
  - `tests/support/harness.rs`.

  Start the Interceptor **before** the first registration in the episode, the REPL and the harness (it
  is a dependency now).
- [ ] T017 [US4] Run the gate. `tool_surface` passes; `call_characterization` and every existing test are
  unchanged. Open PR 2.

**Checkpoint**: there is one tool constructor, and granted tools are configured.

---

## Phase 4: User Story 3 — One tool call means the same thing everywhere (P1, PR 3)

**Goal**: one call lifecycle with one outcome (FR-017–FR-027, D1–D3).

**Independent Test**: the SC-004 matrix runs against `run_call` with no model or VM, and both loops
record identical normalized audits.

### Tests (write first, see them fail)

- [ ] T018 [P] [US3] Create `tests/call_lifecycle.rs` (gated on `test-support`; add its `[[test]] … required-features = ["test-support"]` entry to `Cargo.toml` in this task). It calls `bee::call::run_call`
  directly with `Sandbox::host_scripted`, a `ScriptedTool`, `FakeCallHooks` and `FakeHttpScope`, covering:
  - no denial;
  - kernel → granted → retry (`retried`, `denied_attempt_audit` holds the denial — FR-021);
  - kernel → refused (no retry);
  - kernel → `AlreadyHeld` (no retry — FR-020);
  - proxy refusal → granted → retry in a new call (`denied_attempt_proxy_events` holds the refusal —
    FR-021);
  - kernel and proxy in the same call (one retry total — FR-019);
  - retry timeout under `Deadline` and under `PerCall`: in both, the retry gets only the time the first
    attempt left and is not started when none remains (FR-024), and `result` and `audit` come from the same
    attempt (FR-025);
  - a proxy-scope denial (`tool_denials() == 0`, `proxy_audit` non-empty — FR-022);
  - a late tool batch (attributed to this call — FR-023);
  - `escalations` order and triggers.
- [ ] T019 [P] [US3] In `tests/call_characterization.rs`, flip every `// DRIFT FR-021/022/024/025`
  assertion to the single expected value for both loops. Do not touch the FR-029 assertions yet; they flip
  in phase 5. These tests must fail until T024.

### Implementation

- [ ] T020 [US3] Create the `src/operator.rs` skeleton so `run_call` gets its final signature now
  (research R2):
  - `OperatorKind`, `SessionOutput` (extends `ReplOutput` with the default methods in
    `contracts/operator.md`), `ConsentRequest`, `ConsentRecord`, `Reason`;
  - `Operator` wrapping today's `ConsentSink` and output, applying the timeout in `consent()`;
  - a `ProgressOutput` that forwards to the existing `ProgressSink` lines unchanged.

  Recording and the Interactive channel come in T054. Then create `src/call.rs` (declare both in
  `src/lib.rs`) with the types from `contracts/call-lifecycle.md`: `TimeoutPolicy { Deadline, PerCall }`,
  `CallInput`, `Escalation`, `CallOutcome`, `EscalationRecord`, `Trigger`, plus
  `CallOutcome::tool_denials()` and `CallOutcome::to_recorded()`.
- [ ] T021 [US3] In `src/call.rs`, implement `pub async fn run_call(...)` following the contract's 7-step
  sequence exactly. It absorbs the sequencing from `src/episode.rs:299-463` and `src/repl.rs:632-813`. Move
  `proactive_step`, `reactive_step`, `proxy_refusal_step` and `first_denial` from `src/grants/escalate.rs`
  (`:164-313`) into `src/call.rs` as private helpers returning `(Trigger, EscalateOutcome)`. Leave
  `escalate()` and the hooks in `escalate.rs`. Add a compile-time `Send` assertion:
  `fn _assert_send() { fn s<T: Send>(_: T) {} s(run_call(..)) }`, or the equivalent static check.
- [ ] T022 [US3] In `src/transcript.rs`, extend `RecordedCall` (`:55-66`) with `denied_attempt_audit`,
  `denied_attempt_proxy_events`, `proxy_audit`, `escalations` (serialized form of `EscalationRecord`), `retried` and `timed_out`, all
  `#[serde(default, skip_serializing_if = ...)]`. Fix the doc at `:117` so `audit_trail` is described as
  the concatenation of every call's `denied_attempt_audit + audit + proxy_audit`.
- [ ] T023 [US3] Replace the per-call block in `src/episode.rs::run_loop` (`:299-463`) with `run_call(...,
  TimeoutPolicy::Deadline(deadline))`, then:
  - render the `CallOutcome` through the existing `emit` lines (escalate lines from `outcome.escalations`
    in order);
  - derive `DENIED` from `outcome.tool_denials() > 0` (FR-022);
  - push `audit_trail` in the order described in T022;
  - keep the terminal and timeout handling at `:465-505`.
- [ ] T024 [US3] Replace the per-call block in `src/repl.rs::run_exchange` (`:632-813`) with `run_call(...,
  TimeoutPolicy::PerCall(tool_timeout))`, so a retry shares the first attempt's budget (FR-024), locking `esc.active` once per call and passing `&mut *guard`.
  Render through `ReplOutput` as today (`report_escalation` from `outcome.escalations`). Count
  `denials += outcome.tool_denials()`, and make `audit_all` include `denied_attempt_audit` (FR-021).
- [ ] T025 [US3] Delete the now-unused `pub` step functions and any dead imports in `src/grants/escalate.rs`.
  Update the module docs at `:159-163` to point at `src/call.rs`.
- [ ] T026 [US3] Run the gate. `call_lifecycle` passes, the flipped `call_characterization` assertions
  pass, and `episode_progress_strings` passes (lines changed only as FR-022 permits — update just that
  expectation, with a comment citing FR-022). Record the line deltas of `episode.rs` and `repl.rs` for
  SC-009. Open PR 3.

**Checkpoint**: the call protocol exists once (SC-002).

---

## Phase 5: User Story 5 — Hooks do what they say (P2, PR 4)

**Goal**: dispatch-all with precedence, `TurnStart`, lease expiry, deescalation, and MCP refresh through
hooks (FR-028–FR-034, D3).

**Independent Test**: a Deny hook stops a call, Deescalate narrows the scope, `Ttl::Turns(2)` expires
after two model turns however many calls each turn makes, MCP refresh happens at turn start, and Deny
beats Escalate.

### Tests (write first, see them fail)

- [ ] T027 [P] [US5] Rewrite `first_non_continue_wins` in `src/hooks.rs` (`:139`) as unit tests of the new
  `dispatch`:
  - Deny beats Escalate regardless of registration order;
  - Escalate deltas from two hooks merge;
  - Deescalates accumulate;
  - `RefreshTools` accumulates alongside the winning flow.
- [ ] T028 [P] [US5] Create `tests/hooks_leases.rs` (gated on `test-support`; add its `[[test]] … required-features = ["test-support"]` entry to `Cargo.toml` in this task). Through `run_loop` and through
  `run_exchange`, cover:
  - (a) a `BeforeToolCall` Deny hook — the tool never runs (`ScriptedTool` call count is 0), the model sees
    `refused by hook:` and `CallOutcome.refused_by_hook` is set;
  - (b) a lease granted with `Ttl::Turns(2)` in turn 1, where turn 2 makes three tool calls — the lease is
    still active in turn 2 and released at the start of turn 3, `Sandbox::reload` is called, and lease-only
    tools are removed;
  - (c) a TurnStart hook returning `Deescalate(id)` narrows the scope;
  - (d) a fake `McpRefreshHook` returning `RefreshTools` triggers re-registration before the model call;
  - (e) **VM tier (FR-042, SC-010)**: add `lease-expiry` and `lease-release` cases to
    `test/vm/remote-matrix.sh`. Grant read of a file with `Ttl::Turns(1)` (and, separately, release it
    with a `Deescalate` hook). Assert the read succeeds during the lease and is denied by the kernel, with a
    `file_open denied` audit event, after the next turn starts. Host tests (a)–(d) only show that narrowing
    is requested.
- [ ] T029 [P] [US5] In `tests/call_characterization.rs`, flip the `// DRIFT FR-029` assertions (the REPL's
  lease turn now counts model turns).

### Implementation

- [ ] T030 [US5] In `src/hooks.rs`:
  - trim `StepEvent` to `TurnStart{turn}`, `BeforeToolCall`, `KernelDenial`, `ProxyRefusal`, and delete
    `BeforeModelCall` and `AfterToolResult`;
  - trim `Flow` to `Continue | Deny(String) | Escalate(GrantDelta) | Deescalate(GrantId) | RefreshTools`,
    deleting `Terminate`;
  - add `pub struct Dispatch` and rewrite `dispatch` to consult every observing hook and combine per
    `contracts/hooks.md`;
  - update the module doc (`:8`), which currently claims refresh is a TurnStart hook.
- [ ] T031 [US5] In `src/call.rs`, act on `Dispatch.deny` for `BeforeToolCall`: skip execution and return
  `ToolResult::refused_by_hook(reason)`. Add that constructor in `src/tools.rs`, with a distinct outcome
  tag and `is_error = true`. Use `Dispatch.escalate` for the existing triggers.
- [ ] T032 [US5] Add `pub async fn turn_start(turn, hooks, active: Option<&mut ActivePolicy>, sandbox, registry,
  mcp: Option<&McpBridge>) -> TurnStartReport` in a new `src/turn.rs`. It is moved into `Session` in phase 6.
  It runs these steps:
  1. dispatch `TurnStart`;
  2. release every `Deescalate` id;
  3. `active.expire(turn)`;
  4. if anything was dropped: `sandbox.reload(active.active())`, `sandbox.apply_http_scope(..)` when a
     dropped lease had `http_targets`, and remove from `registry` the tools that only a dropped lease
     granted;
  5. on `refresh_tools`: the MCP re-registration (from `src/episode.rs:914-926`).
- [ ] T033 [US5] Add `McpRefreshHook { bridge: Arc<McpBridge> }` (cfg `mcp`) in `src/mcp/bridge.rs`. It
  observes `TurnStart` and returns `RefreshTools` when `bridge.take_dirty()`. Remove `refresh_tools` from
  `LoopOptions` (`src/episode.rs:38`) and `ReplConfig` (`src/repl.rs:74`), along with their call sites
  (`:193`, `:509`). Register the hook where the bridge is connected (episode and REPL setup).
- [ ] T034 [US5] Call `turn_start` at the top of each model turn in `src/episode.rs::run_loop` (turn =
  `index`) and in `src/repl.rs::run_exchange` (top of the `for _step` loop, `:505`).
  - Replace `ReplEscalation::next_turn()` per-call increments (`:122`, `:635`) with a session-monotonic
    model-turn counter incremented once per step.
  - Pass that counter as the lease turn and as `CallInput.turn`.
- [ ] T035 [US5] Run the gate. `hooks_leases` and the `hooks.rs` unit tests pass, and the flipped FR-029
  characterization passes. Run the T028e VM cases. If `ac-matrix-vm` is unavailable, PR 4 may merge with
  the cases written and marked pending in its description, but **phase 6 does not start until they have
  passed** (FR-042). Open PR 4.

**Checkpoint**: the hook interface offers nothing it ignores (SC-007).

---

## Phase 6: User Story 1 — The same session, whoever started it (P1, PR 5a)

**Goal**: one library Session builder for every entry point and the harness (FR-006–FR-012).

**Independent Test**: `session_parity` (enabled) shows identical snapshots for every entry point, and the
drift cases behave as specified.

### Tests (write first, see them fail)

- [ ] T036 [P] [US1] Rewrite `tests/session_parity.rs` against the new API, and add its `[[test]] …
  required-features = ["test-support"]` entry to `Cargo.toml` (it now uses `TeardownLog`). Build one `SessionSpec` and call
  `bee::session::build` for each `EntryPoint` (`Headless`, `Repl`, `Tui`, `Batch{concurrent:false}`) with
  a recording operator; assert the `snapshot()`s are equal. Remove `#[ignore]`.
- [ ] T037 [P] [US1] Add to `tests/session_parity.rs`:
  - (a) `Batch{concurrent:true}` plus MCP servers → `BuildError` naming "MCP"; the same for
    `[policy.http]` and for a ceiling wider than the policy;
  - (b) the scanner report dir is writable in the snapshot policy for every entry when `scan` is granted
    (FR-010);
  - (c) the snapshot system prompt includes the render/skill notes for every entry where those tools are
    present;
  - (d) `shutdown()` appends `["mcp", "interceptor", "scopes"]` to the session's `TeardownLog`
    (test-support, research R1) for every entry, including the `Drop` path;
  - (e) the `[policy.http]` advisory string in the snapshot is identical for every entry (FR-011, SC-003).
- [ ] T038 [P] [US1] Create `tests/run_task_config.rs`. Building the `SessionSpec` the way `bee run --task`
  does, from an effective configuration with MCP servers and skills, keeps both. Test the mapping
  function, not the binary.

### Implementation

- [ ] T039 [US1] Move `src/session/mod.rs` and `src/session/event.rs` (`SessionSink`, `SessionEvent`) to
  `src/tui/events.rs`. Update the importers `src/tui/app.rs:20`, `src/tui/mod.rs:36`,
  `src/tui/message.rs:9`, and `src/lib.rs:70`. This is a pure move with no behaviour change; commit it on
  its own.
- [ ] T040 [US1] Create `src/session/spec.rs`, containing:
  - `SessionSpec` and `EntryPoint` (data-model.md);
  - `BuildError`;
  - `fn refuse_unsupported(&SessionSpec) -> Result<(), BuildError>`, implementing the refusal table in
    `contracts/session-builder.md`.
- [ ] T041 [US1] Create `src/session/parts.rs`, containing:
  - `#[cfg(feature="intercept")] HttpPart` (Interceptor, prepared scope), with a stand-in type when the
    feature is off;
  - `#[cfg(feature="mcp")] McpPart` (bridge), likewise with a stand-in;
  - `pub fn http_advisory(&SessionSpec) -> Option<String>`, the single replacement for
    `src/episode.rs:782-800`, `src/app/repl.rs:247-268` and `src/app/run.rs:300-335`.
- [ ] T042 [US1] Create `src/session/mod.rs` with `pub async fn build(spec, operator) -> Result<Session,
  BuildError>`, implementing the 13-step pipeline in `contracts/session-builder.md`. Move logic, don't
  copy it, from:
  - `src/app/session.rs`: `resolve_enforcement`, `require_kernel_support`, `resolve_grants`,
    `build_sandbox`;
  - `src/episode.rs`: `resolve_episode_grants` `:986`, `widen_for_scanner_reports` `:1021-1055`,
    `build_enforced_sandbox` `:1066-1126` (merged with `build_sandbox`; scope-id prefix from
    `EntryPoint`);
  - `effective_system_prompt` (`src/repl.rs:1059`).

  The `operator` parameter uses the `Operator` skeleton from T020, which wraps today's consent sinks and
  outputs; phase 7 completes it (plan risk note 5a).
- [ ] T043 [US1] In `src/session/mod.rs`, implement:
  - `Session` (data-model.md);
  - `snapshot()` (serializable `SessionSnapshot`);
  - `turn_start()` (moves `src/turn.rs` in and deletes it);
  - `call()` (delegates to `run_call`);
  - `system_prompt()`, `tool_schemas()`;
  - `shutdown()` (MCP → Interceptor → `Sandbox::teardown`), plus a `Drop` guard running the same order
    when `shutdown` was not called. Under `test-support`, both append each stage to a `TeardownLog`
    (data-model.md).
- [ ] T044 [US1] Rewrite `src/episode.rs::run_episode_with` to call `session::build` and then `run_loop`
  through the `Session`. Delete the setup code and helpers moved in T042. Map `Scenario` to `SessionSpec`
  in a `fn spec_from_scenario` in `src/episode.rs`.
- [ ] T045 [US1] Rewrite `src/app/repl.rs::repl` (`:123-412`) to map `EffectiveConfig` →
  `SessionSpec { entry: Repl | Tui }` in a new `src/app/spec.rs::spec_from_config`, call `session::build`,
  and hand the `Session` to `run_repl` / `tui::run`. Delete `src/app/session.rs`.
- [ ] T046 [US1] Rewrite `src/app/run.rs` so `--task` and `--scenario` build their spec through
  `spec_from_config`, keeping user/project MCP servers and skills (FR-009; today `:115`, `:161-162` drop
  them). Remove the third advisory copy (`:300-335`) and the `--host` asymmetry (`:227-241`). Headless now
  honours `Enforcement::Host` where the build allows it.
- [ ] T047 [US1] Rewrite `src/concurrent.rs` to build each pair's session via `session::build` with
  `EntryPoint::Batch{concurrent:true}`, so it gets the explicit refusals and keeps its shared-engine
  sandbox constructor through a `SandboxSource::Shared(..)` option on the spec. Delete the silent
  `scenario.mcp` drop and the `[policy.http]` special case at `:39`, which the builder's refusal now
  covers.
- [ ] T048 [US1] Rewrite `tests/support/harness.rs::Session::start` (`:79-120`) to call `session::build`
  with `Enforcement::Host` and `[policy.http]`, deleting its hand copy of the Interceptor start-up. Update
  `tests/intercept_escalation.rs:67` (the hand-built `LoopEscalation`) to use the built session's
  escalation.
- [ ] T049 [US1] Implement MCP attribution (research R8):
  - record each MCP server child's `tgid` at spawn in `src/mcp/transport.rs`;
  - expose `McpBridge::server_tgids()`;
  - in the session's drain path, route tool-scope events whose `tgid` belongs to an MCP server into a
    per-server session record instead of the open call's audit.

  Add a host test in `tests/session_parity.rs`, using scripted audit with that tgid. State the
  limitation (FR-027) in the `src/session/mod.rs` and `src/mcp/bridge.rs` module docs: processes an MCP
  server spawns stay in the tool scope's stream until 018.
- [ ] T050 [US1] Run the gate. `session_parity`, `run_task_config` and every existing test pass, including
  the `intercept_*` suites over the rebuilt harness. Record line deltas for SC-009. Open PR 5a.

**Checkpoint**: there is one builder. Constitution V's violation is closed.

---

## Phase 7: User Story 2 — An autonomous agent that decides within its ceiling and leaves a record (P1, PR 5b)

**Goal**: the Operator seam with Interactive and Autonomous adapters, and every consent decision recorded
(FR-001–FR-005, D4).

**Independent Test**: an autonomous scripted run with one within-ceiling and one beyond-ceiling request
issues zero prompts and records both. An interactive request with no answer is refused as `TimedOut`.

### Tests (write first, see them fail)

- [ ] T051 [P] [US2] Create `tests/operator.rs` (gated on `test-support`, paused clock; add its `[[test]]` entry to `Cargo.toml` in this task):
  - (a) `Operator::autonomous`: one kernel denial inside the ceiling and one outside, via `run_call` →
    exactly two `ConsentRecord`s (`Granted`, `BeyondCeiling`), with no call to any interactive adapter. A
    following `skill` call whose `requires` are already held adds **no** record;
  - (b) `Operator::interactive(ChannelConsent)` with a receiver that never answers → `TimedOut` after the
    timeout, and the call is not retried. An answer delivered after the timeout is dropped with a
    "consent already timed out" notice, and is neither applied nor queued as steering;
  - (c) a dropped receiver → `DeniedByOperator`;
  - (d) a start-up skill grant with `net`/`exec`/`http_targets` → the request carries all kinds;
  - (e) the episode transcript JSON contains `consents` only when non-empty, and an unchanged session's
    transcript is byte-identical to the phase-1 golden output (store one under `tests/fixtures/`).
- [ ] T052 [P] [US2] Add to `tests/episode_progress_strings.rs`: a new `  consent: …` line per decision under
  the Autonomous operator, with every pre-existing line unchanged.
- [ ] T053 [P] [US2] Create `src/repl/consent_input.rs` unit tests for the answer rule: `y/yes/n/no`
  (trimmed, case-insensitive) answer; anything else returns `NotAnAnswer`.

### Implementation

- [ ] T054 [US2] Complete `src/operator.rs` (skeleton from T020) with the types and impls from
  `contracts/operator.md`:
  - `OperatorKind`, `Consent`, `ConsentRequest` (owned, every capability kind), `ConsentRecord`,
    `Reason`, `ConsentLog`;
  - `Operator { consent, output, timeout, log }` with `consent()` (applies the timeout, records, notifies
    output) and `record_unasked()`;
  - adapters `AllowWithinCeiling` (moved from `src/skills/grant.rs:120-127`), `ChannelConsent`
    (mpsc + oneshot), and `ProgressOutput(ProgressSink)` reproducing the episode strings.

  Add the `SessionOutput` trait extending `ReplOutput` with default methods.
- [ ] T055 [US2] In `src/grants/escalate.rs::escalate`:
  - take `&Operator` instead of `&dyn ConsentSink` plus a timeout;
  - record `BeyondCeiling` via `record_unasked` before returning `Refused`. `AlreadyHeld` is **not**
    recorded (no decision was made);
  - map `TimedOut` and `DeniedByOperator` to distinct `Refused` reasons, so they no longer collapse into
    "denied by operator".

  Remove `consent` and `timeout` from `LoopEscalation` (`:26-40`); the Operator owns them.
- [ ] T056 [US2] Add `GrantOrigin::Startup { skill }` in `src/grants/mod.rs`. In
  `src/skills/grant.rs::resolve_grants` (`:180-235`), consult `&Operator` for start-up grants with that
  origin and the full capability kinds (fixing the hard-coded empties at `:213-220`). Delete the blanket
  `impl ConsentSink for Fn`, or move it under `#[cfg(test)]`, and delete `DenyAll` if unused.
- [ ] T057 [US2] In `src/transcript.rs`, add `consents: Vec<ConsentRecord>` to `EpisodeTranscript` (`:112-129`)
  with `serde(default, skip_serializing_if = "Vec::is_empty")`. Fill it from `operator.take_log()` at
  episode end. Add the same to the REPL exchange result in `src/repl.rs`.
- [ ] T058 [US2] Inline REPL: in `src/repl.rs::run_repl` (`:1207-1364`), add a `consent_rx` arm to the
  `select!`:
  - on a request, print `render_lines()` through the output and store `awaiting:
    Option<oneshot::Sender<Decision>>`;
  - a submitted line goes to the oneshot only if `consent_input::parse` accepts it; otherwise it goes to
    steering as today and the question is re-shown.

  Create `src/repl/consent_input.rs` holding the parser.
- [ ] T059 [US2] TUI:
  - add a `ConsentModal` state to `src/tui/app.rs` (`App`) and render it in the TUI draw code;
  - add a `consent_rx` arm to `run_turn`'s `select!` (`src/tui/mod.rs:262-285`) that opens the modal;
  - in the reducer (`src/tui/app.rs:329`), route `y`/`n` keys to the oneshot while the modal is open,
    leaving the input buffer untouched.
- [ ] T060 [US2] Start-up consent for Interactive (research R3). There is never a second terminal reader:
  - **Inline REPL**: start the front-end's line reader (`issue_read`, `src/repl.rs:1207`) *before*
    `session::build`, and serve start-up consent from that one pending read through the same
    `consent_rx` path as T058. Hand the still-pending read to `run_repl` as its first outstanding read,
    instead of starting another.
  - **TUI**: enter the alternate screen first, then run start-up consent as the first `ConsentModal`
    (T059) before the first turn.
  - **Late answers**: an answer that arrives after the Operator's timeout is shown as "consent already
    timed out" and dropped; it is neither applied nor steered.

  Delete `prompt_consent` (`src/app/repl.rs:532-549`) and the `println!`/`eprintln!` at the old
  session.rs `:143-148`; output goes through `operator.output()`.
- [ ] T061 [US2] Wire the operators:
  - `src/app/run.rs` and batch → `Operator::autonomous(ProgressOutput(stderr sink))` with a 60 s timeout;
  - `src/app/repl.rs` → `Operator::interactive(ChannelConsent, TerminalOutput | SessionSink)` with a 120 s
    timeout;
  - the test harness → a recording operator.

  Extend `tests/session_parity.rs` to include the REPL and TUI specs built by `spec_from_config`, asserting
  the snapshots differ only in operator kind.
- [ ] T062 [US2] Run the gate. `operator`, the extended `session_parity` and `episode_progress_strings`
  pass. Do the manual interactive check in `quickstart.md` (phase 4 section) and paste its result into the
  PR description. Open PR 5b.

**Checkpoint**: autonomous and interactive bee differ only in the Operator (SC-001, SC-005).

---

## Phase 8: User Story 6 — The Interceptor's operations are usable without its tools (P3, PR 6)

**Goal**: typed Interceptor operations, with the tools as thin adapters (FR-035–FR-038).

**Independent Test**: the ops tests pass when called directly, and every existing `intercept_*` test passes
unchanged.

### Tests (write first, see them fail)

- [ ] T063 [P] [US6] Create `tests/intercept_ops.rs` (cfg `intercept`, using `tests/support/harness.rs` and
  `examples/vuln_target.rs`). Call `bee::intercept::ops::{send, replay, sitemap, read_exchange}` directly
  with an explicit `CallCtx`:
  - an out-of-scope redirect stops at that hop;
  - an in-scope redirect is followed;
  - replay with an edit yields the same diff shape as `tests/intercept_replay.rs`;
  - the sitemap matches `http_sitemap`'s output for the same store.

### Implementation

- [ ] T064 [US6] Create `src/intercept/ops/mod.rs` (declared in `src/intercept/mod.rs`) with `OpError`
  (`From<InterceptError>`, absorbing the three mappings at `http_send.rs:131`, `http_replay.rs:112` and
  `http_fuzz.rs:103`) and `pub type CallCtx = WireCtx`.
- [ ] T065 [P] [US6] Create `src/intercept/ops/bound.rs`, moving `bounded_json`, `text_or_binary`, `clip` and
  `b64` from `src/tools/http.rs` and `src/tools/http_send.rs`. Repoint `src/intercept/diff.rs:272` to
  `ops::bound::b64`, which removes the intercept → tools dependency.
- [ ] T066 [P] [US6] Create `src/intercept/ops/send.rs` with `StructuredRequest`, `build_request` (from
  `http_send.rs:277-384`), and `send` with redirect following and the Target-scope stop (from
  `http_send.rs:114-182, 388-415`), returning `SendResult`.
- [ ] T067 [P] [US6] Create `src/intercept/ops/replay.rs` with `ReplaySpec`, `replay` (`http_replay.rs:194-262`),
  `stored_request` (`:122-159`) and `side_of` (`:162-192`).
- [ ] T068 [P] [US6] Create `src/intercept/ops/fuzz_run.rs` with `FuzzSpec`, `fuzz` (`http_fuzz.rs:114-290`,
  including the store read-back and `insert_fuzz_run`) and `template_from` (`:293-357`). The payload-file
  read stays in the tool.
- [ ] T069 [P] [US6] Create `src/intercept/ops/sitemap.rs` (`http_sitemap.rs:25-242`) and
  `src/intercept/ops/read.rs`, holding `read_exchange` (`http_get.rs:103-161`) and `scope_view`
  (`http.rs:192-240`).
- [ ] T070 [US6] In `src/tools/http.rs`, add `pub(crate) fn respond(icpt, Result<Value, OpError>, bound,
  provenance) -> ToolResult`, absorbing `live`/`unavailable`/`with_notices`. Rewrite each of
  `src/tools/http_{send,replay,fuzz,sitemap,get,history,leads,intercept}.rs` and `http_scope` as: schema +
  argument parsing into the op spec + one op call + `respond`. Remove the imports between tools.
- [ ] T071 [US6] Delete `CallOrigin::Fuzz` (`src/sandbox.rs:69-70`), its arm in `src/intercept/creds.rs:146`,
  and the "or `fuzz:<run>`" text in `src/intercept/control.rs:31` (FR-038).
- [ ] T072 [US6] Run the gate plus `cargo test --features intercept --test intercept_tools --test
  intercept_replay --test intercept_fuzz --test intercept_rules --test intercept_leads --test
  fail_closed_tools --test tool_output_framing`, all unchanged. Open PR 6.

**Checkpoint**: Interceptor logic lives in one module (US6).

---

## Phase 9: Polish and cross-cutting

- [ ] T073 [P] Measure SC-009: compare the line counts of `src/episode.rs`, `src/repl.rs`,
  `src/app/repl.rs` and `src/concurrent.rs` against `430640c`, and record the result in the final PR
  description.
- [ ] T074 [P] Confirm `CONTEXT.md`'s Operator, Session builder, Tool surface and Call lifecycle entries
  match what shipped. Adjust the wording if names changed during implementation.
- [ ] T075 [P] Update `specs/023-codemode/research.md` (on branch `023-codemode`) R4 to reference
  `src/call.rs::run_call` and `ToolRegistry::surface()` as the codemode seams.
- [ ] T076 Run the full feature-combination build: `cargo check` with `--no-default-features`, `mcp`,
  `scanners`, `vm-test`, and `intercept,enforce,concurrent`. Fix any cfg gaps.
- [ ] T077 Run the full `test/vm/remote-matrix.sh` on `ac-matrix-vm`, including the T028e lease cases, as
  the final enforcement check (Constitution III, SC-010). This task is not complete until it has run;
  if the VM is unavailable, the feature stays open.

---

## Dependencies & Execution Order

### Phase dependencies

- **Setup (Phase 1)** → **Characterization (Phase 2)**. Phase 2 blocks every later phase (FR-040).
- **US4 tool surface (Phase 3)** → **US3 call lifecycle (Phase 4)**. `run_call` registers granted tools
  through `register`.
- **US3 (Phase 4)** → **US5 hooks (Phase 5)**. Deny and `TurnStart` act inside `run_call` and the loop
  tops.
- **US5 (Phase 5)** → **US1 builder (Phase 6)**. The builder wires `McpRefreshHook` and owns `turn_start`.
  Phase 6 also waits for the T028e VM lease cases to pass (FR-042).
- **US1 (Phase 6)** → **US2 Operator (Phase 7)**. Phase 7 completes the Operator skeleton landed in T020
  (adapters, recording, front-end consent).
- **US6 ops (Phase 8)** depends only on Phase 2 and can run in parallel with Phases 3–7 on its own branch.
  It merges last, per FR-041.
- **Polish** comes after everything else.

### Within each phase

Write the tests first and see them fail, or for characterization see them pin today's behaviour. Then
work through types → logic → callers, and finish with the gate.

## Parallel Opportunities

- Phase 1: T002 ∥ T003.
- Phase 2: T005 ∥ T007 ∥ T008, after T004. T006 depends on T004 and T005.
- Phase 3: T011 can be written while T012 is in progress.
- Phase 4: T018 ∥ T019.
- Phase 5: T027 ∥ T028 ∥ T029.
- Phase 6: T036 ∥ T037 ∥ T038. T039, the pure move, can land first in parallel with test writing.
- Phase 7: T051 ∥ T052 ∥ T053. T058 (REPL) ∥ T059 (TUI) after T054.
- Phase 8: T065 ∥ T066 ∥ T067 ∥ T068 ∥ T069 after T064.

### Parallel example: Phase 8

```text
Task: "Create src/intercept/ops/send.rs (T066)"
Task: "Create src/intercept/ops/replay.rs (T067)"
Task: "Create src/intercept/ops/fuzz_run.rs (T068)"
Task: "Create src/intercept/ops/sitemap.rs and read.rs (T069)"
```

## Implementation Strategy

### MVP

Phases 1–4: characterization, the tool surface, and the call lifecycle. Together they deliver:

- **US3:** one call protocol, testable on host, and the prerequisite for 023-codemode;
- **US4:** granted tools work;
- the drift fixes for FR-021/022/024/025.

Stop and validate at the Phase 4 checkpoint.

### Incremental delivery

Each phase is one PR that leaves the gate green.

- After Phase 4, codemode work can begin on the `run_call` and `surface()` seams.
- After Phase 7, bee can run autonomously with a full consent record.
- Phase 8 is independent and can be scheduled whenever review bandwidth allows.

## Notes

- `// DRIFT FR-0xx` assertions are the audit trail of intended behaviour changes. Never delete one;
  flip it.
- If a phase-1 characterization exposes behaviour this spec did not list as drift, stop and raise it. Do
  not silently fold it into a fix.
- Commit after each task or logical group. Each phase's PR targets `main` (feature branch per phase off
  `024-session-core`, or stacked).
