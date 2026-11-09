---
description: "Task list for 018-subagent-scopes"
---

# Tasks: Subagent Delegation Under Attenuated Scopes

**Input**: Design documents from `/specs/018-subagent-scopes/`

**Prerequisites**: plan.md (read its **Refresh — 2026-11-09** section first; it overrides the body),
spec.md, research.md (R2 is superseded), data-model.md, contracts/, quickstart.md

**Tests**: Required. The constitution's test-first gate applies to every enforcement claim, and an
enforcement claim proven only by host mocks does not count — each kernel claim has a VM case in
`test/vm/remote-matrix.sh` + `test/vm/cases.txt`, which must FAIL against a binary without the change
before it is trusted (see the false-PASS trap in `test/vm/README.md`).

**Build/test location**: never on the laptop. Rsync the worktree to `bee-build` and run cargo there
(`--features concurrent,sec,vm-test` release for the matrix).

**Organization**: Phase 2 is plan slice 1 (supervisor) and blocks everything. Stories follow in spec
priority order; US3 (audit) lands before US1's VM proof because US1's denial must be recorded to be
proven.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: Which user story the task belongs to (US1–US7)

---

## Phase 1: Setup

**Purpose**: Feature wiring and the regression baseline slice 1 is measured against.

- [x] T001 Record the baseline on `bee-build`: host `cargo test --workspace --all-features` result list and VM matrix result (50/50 expected) for origin/main into `specs/018-subagent-scopes/baseline.md`, including the 7 known REPL test failures noted in `.scratch/repl-visibility/` so they are not misattributed to this feature
- [x] T002 In `Cargo.toml`, make `concurrent = ["enforce"]` (plan Refresh §1a: no tokio needed); leave `crates/userspace/Cargo.toml` features unchanged
- [x] T003 [P] Add a `018` row to the feature map in `docs/reconnaissance-workflows.md` (status: in progress) and remove the "No 018 code exists" sentence from `specs/019-http-intercept/research.md:101`

---

## Phase 2: Foundational — Supervisor (plan slice 1, no behaviour change)

**Purpose**: One session-owned owner of the engine and the audit demux; every scope created through it.

**⚠️ CRITICAL**: No user story work begins until the gate at the end of this phase passes.

### Tests first

- [x] T004 Add VM case `concurrent-reload` to `test/vm/remote-matrix.sh` and `test/vm/cases.txt`: two concurrent episodes, one widens via a grant, the widened read succeeds only in that episode's scope. Confirm it FAILS on main (today: "reload unsupported on a concurrent sandbox")
- [x] T005 [P] Add host unit tests in `src/supervisor.rs` for the pure teardown ordering (children first, siblings untouched, unknown id empty); the kernel paths are covered by the VM matrix

### Implementation

- [x] T006 Create `src/supervisor.rs`: `Supervisor(Arc<Inner>)`, `Inner { scopes, audit: Router{AuditReader, pending}, engine }` each behind a `Mutex`, engine declared last. `start()`, `create_scope(id, label, parent: Option<&ScopeHandle>, plan)` (flat under `cgroup::DEFAULT_PARENT` — R5 — registered for audit before return; nothing left behind on error), reload, synchronous drain-time routing (plan Refresh §1a), children-first `teardown`. Module docs carry the R5 "do not nest" warning
- [x] T007 Define `ScopeHandle { supervisor, id, cgroup_id, path }` with `join_closure()`, `reload(plan)`, `drain() -> Drained { events, dropped, limited }`, `teardown()`
- [x] T008 Rework `EnforcedSandbox` in `src/sandbox.rs`: replace `engine`, `scope`, `reader`, `tool_audit`, `sidecar_audit` with `scope: ScopeHandle` and `sidecar: Option<SidecarScope>` where `SidecarScope` now wraps a `ScopeHandle` + `plan`; `reload`/`install_sidecar_plan` call `Supervisor::reload`; keep `poisoned`, `proxy_port`, `ca_bundle` semantics identical; `drain_scope_audit` and `drain_sidecar_audit` each read their own subscription
- [x] T009 Delete `route_audit`, `TaggedAudit`, `drain_into_buffers` and `sidecar_reload_target` from `src/sandbox.rs` and their tests, now that each scope has its own subscription (keep a test that a sidecar event never appears in `drain_audit`)
- [x] T010 Remove `Sandbox::Concurrent` and `ConcurrentSandbox` from `src/sandbox.rs`; every match arm that handled it goes away
- [x] T011 Update `src/session/parts.rs` `kernel_sandbox`: start a `Supervisor` and create the tool scope through it. No `Session` field or explicit `shutdown` was needed: the sandbox's handle keeps the supervisor alive, `Session::shutdown` tears the scopes down as before, and the engine drops last with the last handle (its `Drop` kills any scope still alive before detaching)
- [x] T012 Update `src/intercept/session.rs` `attach_sidecar` to take `&Supervisor` and create the proxy scope with `parent = Some(tool scope id)` (019 T092 migration half; leave the 019 tasks.md checkbox for the per-subagent half open)
- [x] T013 Rewrite `src/concurrent.rs` engine/demux setup to one `Supervisor` per batch: sequential `create_scope` per episode, each episode's `Sandbox::Enforced` built from its `ScopeHandle`; lift the concurrent-batch ceiling refusal in `src/session/spec.rs` and update `tests/session_parity.rs`
- [x] T014 Keep `bee exec` in `src/main.rs` on the direct `Engine` + sync reader path; add a comment saying why (single process, single scope, no runtime)
- [x] T015 Verify `_assert_send` in `src/call.rs:583` still compiles under `--features concurrent,sec,vm-test`, plus `_assert_send_sync(Supervisor, ScopeHandle)` in `src/supervisor.rs`; port the kernel test fixtures in `tests/{hardening,codemode_kernel,durable_kernel}.rs` to the supervisor
- [x] T016 Gate: on `bee-build`, host `cargo test --workspace --all-features` matches T001's baseline; `cargo clippy --workspace --all-targets --all-features -D warnings` clean; VM matrix 50/50 plus `concurrent-reload` PASS. Record results in `specs/018-subagent-scopes/baseline.md`

**Checkpoint**: Supervisor in place, behaviour unchanged, concurrent reload repaired (SC-007, FR-021).

---

## Phase 3: User Story 3 — The audit trail stays whole across the scope tree (P1)

**Goal**: Every kernel decision recorded exactly once, attributed to its scope, across a parent and its children.

**Independent Test**: quickstart S6 (host) and S4's attribution half (VM).

**Note (resolved in slice 1, plan Refresh §1b)**: every scope's events already carry `scope_id` — the session scope's id, or `"proxy"` — and the supervisor stamps each scope's label the same way, so a child is attributed by its own id with no special case.

### Tests first

- [x] T017 [US3] Amend `specs/018-subagent-scopes/contracts/delegation-record.md` §Audit attribution: stamping is done by the supervisor at routing time, by scope label (plan Refresh §1b)
- [x] T018 [P] [US3] Add `tests/transcript_compat.rs` case: a non-delegating transcript serializes byte-identically to the committed fixture after `RecordedCall.child` exists (SC-006) — covered by the existing `tests/transcript_compat.rs` fixture (passes unchanged) plus `tests/delegation.rs::the_record_round_trips_and_a_non_delegating_call_has_no_child`
- [ ] T019 [P] [US3] Add `tests/delegation_audit.rs` (host, scripted audit via `Sandbox::host_scripted`): parent and child both produce denials; each appears once, child's stamped with its scope id and only in the child transcript; `audit_tree()` yields both — **deferred**: attribution is proven with the real kernel by VM case `subagent-net-denied` (the child's denial is in its own record, stamped with its scope id; the parent's trail is empty); a host test over scripted audit adds little

### Implementation

- [x] T020 [US3] Add `DelegationRecord`, `DelegationOutcome`, `CutShortReason`, `RefusalReason` in `src/transcript.rs` per data-model.md, and `RecordedCall.child: Option<Box<DelegationRecord>>` with `serde(default, skip_serializing_if)`
- [ ] T021 [US3] Add `EpisodeTranscript::audit_tree()` and `delegations()` in `src/transcript.rs`; leave `denials()` and `ScoreReport::from_transcript` own-scope, and make `ScoreReport` state the scopes it counted (US3 AS-4) — `audit_tree()` and `delegations()` done; **ScoreReport scope statement deferred** (a new field would change every CTF transcript; revisit with US5)
- [x] T022 [US3] Create child scopes with their own scope id as label so `drain_audit` attributes them (no sandbox change needed after slice 1)

**Checkpoint**: The record can hold a delegation tree and attribute it.

---

## Phase 4: User Story 1 — Delegate work to an attenuated subagent (P1) 🎯 MVP

**Goal**: The `task` tool delegates to an operator-authored agent that runs in its own kernel scope under a derived policy and returns a report.

**Independent Test**: quickstart S3 — an agent omitting network, delegated from a session holding it, is denied `connect` in the kernel; the denial is in the child's record; the parent's report says so.

### Tests first

- [x] T023 [P] [US1] Extend `tests/skills_episode.rs` with `agent_` tests: `kind: agent` loads as an agent, ordinary skills unaffected, project shadows user with a warning naming both paths, `turn-limit: 0` / bad `requires.filesystem` / non-empty `requires.tools` on an agent each warn and omit (quickstart S1) — written as unit tests in `src/skills.rs` (`an_agent_loads_apart_from_skills`, `…shadows…`, `a_malformed_agent_warns_and_is_not_offered`, `an_unknown_kind_is_refused`); also refuses an explicit empty `requires.net`/`exec` (see contracts/agent-definition.md)
- [x] T024 [P] [US1] Create `tests/delegation.rs` (host, `MockModel`): happy path returns `subagent '<name>' — completed (N turns)` + the child's finish summary; the parent conversation never contains a child tool call (FR-027); every `ToolResult` entering the conversation has `delegate == None`; unknown agent and a tool the parent lacks are refusals with no scope (US1 AS-3, FR-004)
- [x] T025 [US1] Add VM case `subagent-net-denied` to `test/vm/remote-matrix.sh` + `cases.txt`: parent policy allows a local listener; agent declares `net: []`; scripted model delegates and the child runs `bash -c 'exec 3<>/dev/tcp/…'`; expect EPERM in the child's record and the parent's own connect succeeding. Confirm FAIL on the Phase 2 binary

### Implementation

- [x] T026 [P] [US1] Extend `src/skills.rs`: `Frontmatter` gains `kind`, `tools`, `turn_limit` (`turn-limit`); `SkillRequires` gains `exec: Vec<String>` and `net: Vec<String>`; `SkillRegistry` partitions into skills and `agents()` with the validation rules in `contracts/agent-definition.md`; `requires_to_policy` (or equivalent) produces a `bee_core::Policy` covering all four dimensions — as built: agents live in a separate map in `SkillRegistry` (so start-up grants/escalation never read an agent's `requires`), with their own `AgentRequires`; `SkillRequires` is unchanged
- [x] T027 [P] [US1] Add `DelegationRequest { agent, prompt }` and `ToolResult.delegate: Option<DelegationRequest>` (`serde(default, skip_serializing_if)`) in `src/tools.rs`; add `TASK_TOOLS = &["task"]`, not in `DEFAULT_TOOLS`
- [x] T028 [US1] Create `src/tools/task.rs`: schema per `contracts/task-tool.md` with an `enum` and descriptions generated from the agent registry; `run` resolves the name and returns a `DelegationRequest`, never touching the sandbox; register it in `src/session/` tool-surface construction only when `task` is asked for and at least one agent was discovered
- [x] T029 [US1] Create `src/delegate.rs` with `run_delegation(req, ctx: DelegationCtx, parent: &ParentView) -> (String /*report*/, DelegationRecord)`: (1) intersect agent tools with the parent registry, refusing by name; (2) `parent.active.derive(agent_policy)` before any cgroup; (3) refuse when the parent's `[policy.http]` is active (plan Refresh §5); (4) compile → `EnforcementPlan` → `Supervisor::create_scope(id, Some(parent_scope))` with `stamp_scope` set, or a host sandbox when the parent has none; (5) build the child tool registry, system prompt from the agent body, `finish` offered, autonomous `Operator`; (6) `episode::run_loop`; (7) `Supervisor::teardown`; (8) build the report per `task-tool.md` (finish outcome/summary, fallback last text) and the record. A teardown error makes the outcome `Failed` (FR-022)
- [x] T030 [US1] Hook fulfilment into the call lifecycle in `src/call.rs`: `run_call` takes an `Option<Delegator<'_>>` (supervisor, active policy, registry snapshot, `DelegationCtx`) parallel to `Escalation`; when the tool's result carries `delegate`, run `run_delegation`, replace `content`, clear `delegate`, attach the record to the outcome; with no delegator, refuse ("delegation is not available here") — this covers codemode, which never passes one (plan Refresh §5)
- [x] T031 [US1] Thread the delegator from `src/episode.rs` `run_loop` and `src/repl.rs` `run_exchange` into `run_call` (R7: one helper, two call sites), and store `CallOutcome`'s record into `RecordedCall.child`
- [x] T032 [US1] Progress lines per `contracts/delegation-record.md` §Progress output: `delegate '<agent>' → scope … (enforced, depth N)`, child lines indented by depth, `delegate '<agent>' ← <outcome>` via `ProgressSink` in `src/delegate.rs` — headless only; the REPL shows the report but not the child's live progress
- [x] T033 [US1] Add a `kind: agent` example under `examples/agents/dep-auditor/SKILL.md` matching `contracts/agent-definition.md` — at `specs/018-subagent-scopes/examples/dep-auditor/SKILL.md` (not `examples/`, which holds Cargo examples)

**Checkpoint**: MVP — `subagent-net-denied` passes on the VM; host tests green.

---

## Phase 5: User Story 2 — Refuse an over-broad agent before it can run (P1)

**Goal**: Over-grant is refused before any scope exists, naming the violated rule.

**Independent Test**: quickstart S2 — agent declares write where the session has read; refusal names the path and access levels; no cgroup is created.

- [ ] T034 [P] [US2] In `tests/delegation.rs`: write-over-read refused with path + both levels in the message; undecidable (overlapping) rules refused (FR-013); an omitted region the parent denies stays denied in the derived policy (FR-011); after a runtime escalation the child may receive up to the parent's *current* active policy (US2 AS-4) — partly: write-over-read refusal naming the path, FR-011 inheritance, and refusal of an agent reaching over a parent deny are tested; "child gets the parent's *current* policy after escalation" is wired (`ParentView.policy` is the active policy) but not yet tested
- [x] T035 [US2] Add a supervisor-level assertion test that a refused delegation calls no `create_scope` (count via the fake engine from T005) — **replaced** by VM case `subagent-overgrant-no-cgroup`, which watches `/sys/fs/cgroup/bee` throughout the run
- [x] T036 [US2] Make `run_delegation` map `bee_core` attenuation errors to `RefusalReason::OverGrant { detail }` and the model-facing text `subagent '<name>' — REFUSED: <rule>` in `src/delegate.rs`
- [x] T037 [US2] Add VM case `subagent-overgrant-no-cgroup`: after the refused delegation, `/sys/fs/cgroup/bee` contains no `*-sub-*` directory

---

## Phase 6: User Story 4 — Delegation is bounded (P2)

**Goal**: Shared turn/time/token pool, depth bound, report size cap.

**Independent Test**: quickstart S5.

- [ ] T038 [P] [US4] Tests in `tests/delegation.rs`: `sum(turns_used) + parent turns <= initial` on a run that hits the cap (SC-005); a deadline cut produces `CUT SHORT` text and `CutShort { Deadline }`; depth 2 at `max_depth = 1` refused naming the limit; an oversized report truncated with the visible marker
- [ ] T039 [US4] Add `Budget { turns: Arc<AtomicU32>, tokens: Arc<AtomicU64>, deadline: Instant }` in `src/delegate.rs` (or `src/budget.rs`); `run_loop` in `src/episode.rs` debits it before each model call when present, initialised from the scenario so non-delegating runs are unchanged
- [ ] T040 [US4] `DelegationCtx { depth, max_depth, parent_scope_id, spawn_ceiling, budget }` in `src/delegate.rs`; omit `task` from a child registry at `depth >= max_depth` and refuse in `run_delegation` anyway (R10)
- [ ] T041 [US4] Debit tokens from `metrics::Recorder` records with run id `<parent-run-id>/<agent>@<depth>` in `src/metrics.rs`
- [ ] T042 [US4] Apply the existing per-result cap to the report in `src/delegate.rs`
- [ ] T043 [US4] Config: `[delegation] max_depth`, `max_concurrent` (default 1 and 4) in `src/app/config/` with user-config ceiling semantics (project config may lower, never raise)

---

## Phase 7: User Story 5 — Several subagents at once (P2)

**Goal**: Fan-out with sibling isolation.

**Independent Test**: quickstart S4 on the VM.

- [ ] T044 [US5] Allow several `task` calls in one turn to run concurrently in `src/delegate.rs` (bounded by `max_concurrent`), each with its own scope; scope creation stays serialised by the supervisor mutex
- [ ] T045 [P] [US5] Host test: one sibling fails to start, the others complete, the parent's results name the failure (FR-031); shared budget exhaustion stops all siblings (US5 AS-4)
- [ ] T046 [US5] VM case `subagent-siblings-isolated`: three agents with mutually exclusive file grants; each is denied the others' paths; each denial is attributed to its own scope only

---

## Phase 8: User Story 6 — Honest degradation (P2)

**Goal**: Unenforced delegation announces itself.

**Independent Test**: quickstart S8.

- [ ] T047 [P] [US6] Host test: a host-mode delegation's report carries the WARNING block from `task-tool.md`, the progress line says `unenforced`, `DelegationRecord.enforced == false`, and an over-broad declaration is still refused (FR-033)
- [ ] T048 [US6] Set `enforced` from the sandbox at spawn in `src/delegate.rs` and emit the warning text and progress line

---

## Phase 9: User Story 7 — Child escalation within the parent's authority (P3)

**Goal**: A child may escalate up to its parent's active policy at spawn; prompts name it.

**Independent Test**: quickstart S7-style host test plus a VM reload in a child scope.

- [ ] T049 [US7] Add `GrantOrigin::Subagent { agent: String, inner: Box<GrantOrigin> }` in `src/grants/mod.rs`; render it in the REPL/TUI consent prompt as "subagent '<agent>' asks: …"
- [ ] T050 [US7] Give the child a `LoopEscalation` whose ceiling is `DelegationCtx.spawn_ceiling` and whose reload goes through the child's `ScopeHandle`; consent through the session's one `Operator`
- [ ] T051 [P] [US7] Tests in `tests/dynamic_grants.rs`: child escalation within spawn ceiling granted; beyond it refused without consulting the operator; parent narrowing after spawn leaves the child unchanged (FR-016)
- [ ] T052 [US7] Extend the 007 property test in `src/grants/mod.rs` to a delegation tree (FR-014, SC-003)

---

## Phase 10: Polish & cross-cutting

- [ ] T053 [P] VM case `subagent-migrate-stays-child` (quickstart S9): a child that `mkdir`s a sub-cgroup and migrates is still held to the child's rules, not the parent's (R5)
- [ ] T054 [P] Durable sessions: on recovery, a delegation without a closing record is written as `Failed (interrupted)` and its cgroup reclaimed, in `src/session/durable/`; test in `tests/durable_sessions.rs`
- [ ] T055 [P] Benchmark delegation spawn (derive → compile → plan → create_scope → subscribe) in `benches/`; ≤ 50 ms p95 on `bee-build`
- [ ] T056 [P] Glossary: add **Subagent**, **Agent definition**, **Delegation**, **Supervisor** to `CONTEXT.md`
- [ ] T057 Run every quickstart scenario S1–S9 on `bee-build` and record results in `specs/018-subagent-scopes/quickstart.md`

---

## Dependencies & execution order

- **Phase 1 → Phase 2** (T002 is needed to compile the supervisor). **Phase 2 blocks everything.**
- **US3 (Phase 3)** before US1's VM proof: the child's denial has to land in a record.
- **US1** needs US3. **US2** needs US1's `run_delegation`. **US4–US7** each need US1 and are otherwise independent of each other, except **US5** uses US4's `Budget` and `max_concurrent`.
- Polish after the stories it touches.

```
Setup ─► Supervisor (slice 1) ─► US3 ─► US1 (MVP) ─┬─► US2
                                                   ├─► US4 ─► US5
                                                   ├─► US6
                                                   └─► US7
```

## Parallel opportunities

- Phase 2: T005 alongside T004; T012/T013/T014 after T008–T011 touch different files.
- US1: T023, T024, T026, T027 in parallel; T028–T031 are sequential.
- After US1: US2, US4, US6, US7 can proceed in parallel worktrees.

## Implementation strategy

1. **PR 1 — Supervisor** (Phases 1–2). Lands alone, behaviour unchanged, plus the concurrent-reload fix. This is the risky change; it gets its own review.
2. **PR 2 — MVP delegation** (US3 + US1 + US2). One attenuated subagent, refused when over-broad, recorded.
3. **PR 3+** — bounds/fan-out (US4+US5), honest degradation (US6), child escalation (US7), polish.
4. After 018: the ACP agent runtime (an agent definition whose body runs as an external harness in the child scope) as a separate spec.
