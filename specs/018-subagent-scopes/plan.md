# Implementation Plan: Subagent Delegation Under Attenuated Scopes

**Branch**: `018-subagent-scopes` | **Date**: 2026-08-09 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/018-subagent-scopes/spec.md`

## Refresh — 2026-11-09 (resumed after 024, 019, 023, 025, durable sessions)

The design below was written against the August tree. The *what* (spec, FR/SC, R5 flat layout, R9
derivation, the `task` contract) stands. The *how* of slice 1 changed, because the code it targeted
changed. Where this section and the body disagree, this section wins.

**1. The engine is `Send`; the supervisor is not an actor.** R2's premise was "`aya::Ebpf` is not
`Send`". It is now: `src/call.rs:583` asserts `run_call`'s future is `Send` while it holds
`&mut Sandbox`, and `Sandbox::Enforced` owns the `Engine` (`src/sandbox.rs:388`). So the supervisor
is a shared struct — `Supervisor(Arc<Inner>)`, `Inner { scopes, audit, engine }`, each behind a
`Mutex` — with methods, not a command channel. The engine mutex is what serializes BPF map writes.
The rest of `contracts/supervisor-api.md` stands: plan-only `create_scope`, flat cgroups,
children-first teardown, engine dropped last (by field order; `Engine`'s own `Drop` kills any scope
still alive before it detaches).

**1a. Audit is routed synchronously, at drain time — not by `AuditDemux`.** (Decided while
implementing slice 1.) The async demux delivers events through a background task, so a drain right
after a call may not yet hold that call's events; the concurrent runner papered over this with a
5 ms `settle` sleep. Moving the *single-session* path onto it would have made reactive escalation —
which must see a call's denial in that call — racy. Instead the supervisor owns the one sync
`AuditReader`; a scope's drain reads the whole ring, files every event under its scope's pending
buffer (stamping `scope_id` with the scope's label), and returns its own. Race-free, and it needs no
tokio: **R4's feature change and its Complexity Tracking deviation are void.** `concurrent` is now
just `["enforce"]`; `bee-userspace`'s demux stays in the library for embedders.

**1b. `scope_id` attribution already existed.** `AuditReader` has always stamped every event with
the session scope's id, and 019 restamped proxy events `"proxy"`. The supervisor keeps exactly that
(tool scope label = scope id, proxy label = `"proxy"`), so SC-006 holds without special-casing the
root scope. Concurrent episodes change from the shared `"bee-concurrent"` to their own scope id.

**2. `Sandbox` keeps its enum; the engine-owning variants collapse.** Collapsing to one struct
(contract §"Sandbox as a handle") would now also have to absorb `Batch` (codemode/durable slots) and
the MCP `tgid` attribution, for no gain. Instead:

| Today (main) | After slice 1 |
|---|---|
| `Enforced { engine, scope, reader, sidecar, tool_audit, sidecar_audit, … }` | `Enforced { scope: ScopeHandle, sidecar: Option<ScopeHandle>, … }` |
| `Concurrent { scope, subscription }` (no reload) | removed — a concurrent episode is an `Enforced` on the shared supervisor, and gains reload (SC-007) |
| `Batch`, `Host` | unchanged |

`ScopeHandle { supervisor, id, cgroup_id, path }`. Because every scope drains its own pending
buffer, `drain_into_buffers`/`route_audit`/`tool_audit` (the sidecar sharing one ring reader with the
tool scope, 019 P4) are deleted rather than ported. A full pending buffer counts into
`queue_dropped`; an unfinished ring read sets `drain_limited`.

**3. Construction sites moved.** `episode.rs:876` and `app/session.rs:296–347` are gone; 024 put
sandbox construction in the Session builder:

| Site | Change |
|---|---|
| `src/session/parts.rs:183` `kernel_sandbox` | `Supervisor::start()` → `create_scope` for the tool scope → `Sandbox::Enforced`; the `Session` owns the supervisor and calls `shutdown` at the end |
| `src/intercept/session.rs:367` `attach_sidecar` | takes `&Supervisor`; the proxy scope is a `ScopeRecord` with `parent = tool scope` (this **is** 019 T092's migration half) |
| `src/concurrent.rs:116–219` | one `Supervisor` per batch replaces its engine + demux; each episode's sandbox is a `ScopeHandle` |
| `src/main.rs:421` (`bee exec`) | unchanged — one process, one scope, sync reader |
| 189 `Sandbox::host(..)` fixtures | unchanged |

**4. Feature wiring.** See 1a: `enforce` is unchanged, `concurrent = ["enforce"]`. The concurrent
batch's refusal of a ceiling policy (`session/spec.rs`, 024 FR-008) is lifted, since its episodes
can now reload.

**5. New seams the August plan predates, and how delegation meets them.** Defaults chosen here; each
is a named refusal (Constitution I), not a silent omission:

- **Operator (024).** Delegation itself is not a consent request (spec Assumption "authoring is the
  authorization"). US7's child escalation goes through the session's one `Operator` with a new
  `GrantOrigin::Subagent { agent, inner: Box<GrantOrigin> }`, so the prompt names the subagent.
- **Call lifecycle (024, `src/call.rs`).** The `task` call opens and closes like any call; the
  delegation runs between them, and the child's own calls go through `run_call` on the child's
  sandbox. The parent call's audit is the parent scope's only.
- **Finish tool (025).** A child is a headless autonomous loop: it is offered `finish`, and its report
  is built from the finish outcome + summary (`completed` / `blocked` / `abandoned`), falling back to
  the last assistant text and "ended without finish".
- **Context budget / compaction (025).** The child gets its own conversation and context budget; turns
  and wall-clock come from the shared pool (R8). Token spend is debited when the provider reports it.
- **Interception (019).** A parent with active `[policy.http]` **refuses** `task` in this feature
  ("subagents of an intercepted session need their own proxy scope — 019 T092"). Sharing the parent's
  proxy would attribute a child's exchanges to the parent.
- **Codemode (023).** `task` is not in the codemode catalog; `call_tool('task', …)` is refused by
  name. A delegation is a loop, not a call a script can checkpoint.
- **Durable sessions.** A durable session may delegate; a delegation in flight at a crash is recorded
  as `Failed (interrupted)` on recovery and its scope reclaimed, never resumed.
- **MCP.** Unchanged from Out of Scope: a child gets no MCP servers.

**6. Revised slice 1 gate.** No behaviour change: host `cargo test` (all features) green, VM matrix
50/50 on `bee-build`, plus one new VM case — reload of a concurrent episode's scope — which fails on
main today.

## Summary

Give the harness a `task` tool that delegates work to operator-authored agents, each running in its
own kernel scope under a policy proven `⊆` the parent's active policy. This is the first runtime use
of 001's US2 attenuation guarantee, which has existed only as a manual `bee validate --parent` check.

The approach in one line: **lift `Engine` + `AuditDemux` out of `Sandbox` into a session-owned
`Supervisor` actor**, so `Sandbox` becomes a movable `Send` handle onto one scope; then delegation is
a `DelegationRequest` returned on a `ToolResult` (the `render` idiom), which the loop fulfils by
calling `parent.active().derive(agent_policy)`, asking the supervisor for a child scope, and running
a nested `run_loop`.

Everything security-relevant reuses machinery that is already property-tested: `Policy::derive` for
attenuation, `AuditDemux` for per-scope event routing, `AuditEvent.scope_id` (declared since 001,
populated nowhere) for attribution, and `SkillRegistry` for discovering and warning about definitions.

## Technical Context

**Language/Version**: Rust 2021, workspace `rust-version = 1.85` (the `astgrep` family already
requires 1.88; unchanged by this feature). eBPF crate stays on the nightly bpf toolchain.

**Primary Dependencies**: `aya` 0.14 (engine, unchanged), `tokio` 1.x (supervisor actor, demux),
`rig-core` 0.40 behind the `Model` seam (unchanged), `serde_yaml_ng` (agent frontmatter),
`proptest` (attenuation-tree property test). **No new third-party dependencies.**

**Storage**: None new. Agent definitions are files under the existing skill roots; transcripts gain a
nested field; the findings ledger is unchanged.

**Testing**: `cargo test` host-side (loop, derivation, registry, budget, property tests with
`MockModel`), plus the BPF-LSM VM enforcement matrix (`test/vm/remote-matrix.sh`) for every claim that
the kernel denied something. Per the constitution, an enforcement claim proven only by unit mocks does
not count.

**Target Platform**: Linux, `CONFIG_BPF_LSM=y`, cgroup v2. Unchanged.

**Project Type**: Rust library + thin CLI (`bee`), single workspace.

**Performance Goals**: Delegation spawn overhead — derive, compile, plan, `create_scope`, subscribe —
budgeted at **≤ 50 ms p95**, in line with 007's per-reload cost, validated by benchmark. A session
that never delegates must show **no measurable per-tool-call regression** from the supervisor
indirection; the handle round-trip is one mpsc send + oneshot recv per scope *lifecycle* event, not
per tool call.

**Constraints**: The engine must stay attached for the session's lifetime or every scope silently
loses enforcement. Scope creation and map writes must remain serialized on one task (BPF map writes
are not concurrent — already the concurrent runner's rule, `src/concurrent.rs:3`). Teardown must be
children-first.

**Scale/Scope**: Default delegation depth 1; simultaneous subagents bounded by an operator-configured
cap (default 4). ~8 source files touched, 2 added; the supervisor restructuring is the bulk.

## Constitution Check

*GATE: evaluated before Phase 0 and re-evaluated after Phase 1.*

| Principle | Verdict | Evidence |
|---|---|---|
| **I. Deny-by-default & fail-closed** | **PASS** | An unstated rule in an agent declaration inherits the parent's restriction (`derive`'s `inherit_restrictions`, R9). Unknown agent, over-broad declaration, tool not held by the parent, depth exceeded, budget exhausted, and failed teardown are all refusals with named causes — never degraded successes. Depth is enforced twice (tool omitted *and* loop refuses, R10). A delegation with no kernel scope announces itself (US6). |
| **II. Capability attenuation** | **PASS — and this is the point** | `child = parent.active().derive(declared)` before any cgroup exists (FR-009/FR-010). Child escalation ceiling is the parent's active policy at spawn, never the session ceiling (FR-015). Undecidable containment is invalid (FR-013). The property test extends 007's from one `ActivePolicy` to a delegation tree (FR-014, SC-003). This is the first runtime exercise of 001 FR-005. |
| **III. Kernel enforcement is authoritative** | **PASS** | Each subagent is confined by its own scope; user space only derives, validates, installs, observes. The audit restructuring exists so the kernel's decisions about a child are *recorded*, which is what makes the claim testable. Where nothing can enforce, US6 requires saying so rather than presenting delegation as a guarantee. **Load-bearing detail**: child scopes are **flat siblings**, not nested — `resolve_scope`'s ancestor walk returns the *shallowest* registered scope, so a nested child that migrated into a sub-cgroup would silently acquire its **parent's** broader rules (R5). Flat layout has no such path and needs no eBPF change. |
| **IV. Policy-as-data** | **PASS** | Agent definitions are declarative, diffable frontmatter reviewable in a PR; the model cannot author capabilities (FR-003). Derived policies and every delegation are recorded as structured events; `AuditEvent.scope_id` starts carrying the attribution the schema already declared. |
| **V. Library-first, runtime-free core** | **PASS with a recorded deviation** | `bee-core`/`bee-common` untouched; attenuation stays synchronous. The `Supervisor` lives in the harness, not in `bee-userspace`, and **`bee-userspace`'s own features are unchanged** — its sync `AuditReader` path remains for embedders. What changes is that the *application's* `enforce` feature now pulls `bee-userspace/tokio`. See Complexity Tracking. |

**Additional gates from Security & Platform Constraints:**

- *Scope isolation* — satisfied: one bee-managed cgroup per subagent, lifecycle owned and reclaimed,
  children-first (R5).
- *Process hardening* — unchanged: children spawn through the same `hardened_command` + env-allowlist
  path (`src/sandbox.rs:290`).
- *Protected paths* — unchanged: `.bee` defaults still deny; a subagent inherits them by omission.
- *Auditability* — strengthened: every denial is attributed to its scope and recorded exactly once
  (FR-018, SC-004), which is currently false for anything but a single flat scope.

**Test-first gate**: the enforcement behaviours (attenuation refusal, denial inside a child, no
cross-attribution, unenforced announcement) get failing tests before implementation, and the VM matrix
gains cases before the code lands.

**Result: PASS.** One deviation recorded below; no unjustified violations. Proceed.

## Project Structure

### Documentation (this feature)

```text
specs/018-subagent-scopes/
├── plan.md              # This file
├── spec.md              # Feature specification
├── research.md          # Phase 0 — R1..R10
├── data-model.md        # Phase 1 — entities, fields, state, invariants
├── quickstart.md        # Phase 1 — runnable validation scenarios
├── checklists/
│   └── requirements.md  # Spec quality checklist
├── contracts/           # Phase 1
│   ├── agent-definition.md   # frontmatter schema, discovery, precedence
│   ├── task-tool.md          # tool schema, result semantics, refusal taxonomy
│   ├── supervisor-api.md     # Supervisor/handle command set + ordering rules
│   └── delegation-record.md  # transcript nesting, scope tagging, budget accounting
└── tasks.md             # Phase 2 — created by /speckit-tasks, NOT here
```

### Source Code (repository root)

```text
src/
├── supervisor.rs        # NEW — owns Engine + AuditDemux; actor task + Send handle
├── delegate.rs          # NEW — run_delegation(): derive → scope → child loop → report
├── sandbox.rs           # REWORKED — one Send struct; Host/Enforced/Concurrent variants collapse
├── episode.rs           # loop calls run_delegation; budget in LoopOptions; nested transcript
├── repl.rs              # same delegation call site in run_exchange (R7)
├── concurrent.rs        # REWORKED — runner becomes a thin caller of Supervisor
├── skills.rs            # `kind: skill|agent`; SkillRequires gains exec/net; registry partitions
├── grants/
│   ├── mod.rs           # ActivePolicy unchanged; property test extended to a tree
│   └── escalate.rs      # reload goes through the supervisor handle, not the sandbox
├── tools.rs             # TASK_TOOLS const; ToolResult.delegate field
├── tools/
│   └── task.rs          # NEW — resolves the agent name, emits DelegationRequest
├── transcript.rs        # RecordedCall.child; scope_id stamped on drained events
└── app/
    ├── session.rs       # build_sandbox → build_supervisor + session scope
    └── run.rs, repl.rs  # own the Supervisor for the session's lifetime

tests/
├── delegation.rs        # NEW — host: happy path, refusals, depth, budget, report bounds
├── delegation_audit.rs  # NEW — host: attribution, no cross-contamination, nesting
├── concurrent.rs        # extended: reload under concurrency (SC-007)
└── skills_episode.rs    # extended: kind: agent discovery, warnings, precedence

test/vm/
└── remote-matrix.sh     # extended: child-denial, over-broad refusal, sibling isolation
```

**Structure Decision**: Single workspace, unchanged. Two new harness modules (`supervisor.rs`,
`delegate.rs`) and one new tool (`tools/task.rs`); the rest are edits. `crates/core`,
`crates/common`, and `crates/ebpf` are **not touched**. `crates/userspace` is not touched either —
the supervisor composes its existing `Engine`, `AuditDemux`, and `Scope` types rather than adding to
them, which keeps the library's sync path available to embedders (R4).

## Implementation Sequence

Ordered so each step is independently testable and the risky restructuring lands with its own proof
before anything depends on it.

| # | Slice | Delivers | Gate |
|---|---|---|---|
| 1 | **Supervisor + sandbox collapse** | US3 | Existing suites pass unchanged; VM matrix unchanged; reload works under concurrency (SC-007) |
| 2 | **Agent definitions** | US1 (part) | `kind: agent` discovery, precedence, warnings; malformed never aborts |
| 3 | **`task` tool + `run_delegation`** | US1, US2 | Attenuation refusal before scope creation; denial inside a child on the VM |
| 4 | **Nested transcript + scope tagging** | US3 | Exactly-once attribution; SC-006 compatibility |
| 5 | **Budget, depth, report bounds** | US4 | A delegating session cannot exceed its non-delegating budget |
| 6 | **Fan-out** | US5 | Sibling isolation on the VM |
| 7 | **Unenforced announcement** | US6 | Host-mode delegation is distinguishable in the record |
| 8 | **Child escalation** | US7 | Bounded at parent-at-spawn; prompts name the subagent |

Slice 1 is the one to schedule carefully: it touches every `Sandbox` construction site
(`src/episode.rs:664,876`, `src/app/session.rs:305,329,347`, `src/concurrent.rs:200`, and the
`Sandbox::host` test fixtures in `tools/finding.rs`, `tools/skill.rs`, `grants/escalate.rs`,
`mcp/bridge.rs`, `repl.rs`) and must land with **no behaviour change** — its entire success criterion
is that the existing tests and the VM matrix still pass.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|---|---|---|
| The application's `enforce` feature now pulls `bee-userspace/tokio`, so a plain enforce build of the **binary** is no longer async-runtime-free | The supervisor must own the single audit ring and fan it out per scope; that is `AuditDemux`, which is behind `bee-userspace/tokio`. Without it a subagent's denials are discarded and US1's guarantee is untestable (Constitution's own "a denial no test exercises is not enforced") | Keeping the sync `AuditReader` for the parent and adding a second reader for children was rejected: two readers on one ring race for the same records, so events would be lost or double-counted — directly violating FR-018/SC-004. **Mitigation**: `bee-userspace`'s own features are unchanged and its sync path stays, so a library embedder is unaffected; only the `bee` binary — which has required tokio since 002 — changes, and it already compiled this exact path under `concurrent`. |
| `Sandbox` gains a supervisor handle, so a tool's `&Sandbox` transitively reaches scope-lifecycle commands | Children must be created and torn down from the loop, and reload must work from a spawned task | Passing the handle separately through `run_loop` was rejected: `grants::escalate` already calls `sandbox.reload(...)` (`src/grants/escalate.rs:125`), and splitting the two would leave two ways to reach the same engine. **Mitigation**: the handle's command set is scope-lifecycle only — no tool can create a scope, because creation requires a validated `EnforcementPlan` a tool has no way to produce, and the `task` tool never touches the sandbox at all (R1). |

## Post-Design Constitution Re-Check

Re-evaluated after Phase 1 artifacts (`data-model.md`, `contracts/`, `quickstart.md`):

- **I** — the contracts enumerate a closed refusal taxonomy (`contracts/task-tool.md`), each with a
  named cause and a "no scope created" guarantee. No degraded-success path exists in the design.
- **II** — `contracts/supervisor-api.md` makes `CreateScope` accept only a pre-validated
  `EnforcementPlan`, so there is no route to a scope that skipped derivation. The derivation itself is
  one call to the existing validator.
- **III** — `contracts/delegation-record.md` requires the enforced/unenforced distinction to be
  readable from the record without inspecting the build. The flat-layout rule and *why* it is not the
  obvious nested choice are stated in `research.md` R5, `contracts/supervisor-api.md`, and
  `quickstart.md` rather than in one place a reader may miss — a future change to nesting would
  reintroduce a silent attenuation escape, so the reasoning has to travel with the decision.
- **IV** — `contracts/agent-definition.md` is a text schema with fixed precedence and warning
  behaviour; nothing in it is model-writable.
- **V** — no new crate, no core change, no new dependency; the one deviation is recorded above.

**Result: PASS.** Ready for `/speckit-tasks`.
