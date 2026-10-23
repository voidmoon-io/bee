# Implementation Plan: One Session Core for Autonomous and Interactive bee

**Branch**: `024-session-core` | **Date**: 2026-10-10 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/024-session-core/spec.md`

## Summary

bee has to run both as an autonomous agent and as an interactive one. The only difference between those
modes should be an **Operator** (consent plus output). Everything else is consolidated behind single
owners. Each owner below is one module, delivered as one phase, each a PR:

1. **Characterization.** Pin today's behaviour through both loops. A `test-support` feature gives the
   host sandbox a scripted audit source (R1).
2. **Tool surface.** `ToolRegistry` holds `ToolDeps`, and `register(name)` is the only constructor. The
   `configure_*` re-passes are deleted (R4).
3. **Call lifecycle.** `src/call.rs::run_call` owns the per-call protocol both loops copy today. It
   returns a `CallOutcome`, and the timeout policy is a parameter (R2).
4. **Hooks and leases.** All hooks are consulted and Deny wins. `TurnStart` drives lease expiry,
   deescalation and MCP refresh. Events and flows nothing uses are removed (R6).
5. **Session builder and Operator.** One library builder serves every entry point and the test harness.
   The Operator has Interactive and Autonomous adapters. Every consent decision is recorded, and the
   interactive prompt goes through the front-end's input path (R3, R5, R8).
6. **Interceptor operations.** Typed operations live in `src/intercept/ops/`, and the `http_*` tools
   become thin adapters (R7).

## Technical Context

**Language/Version**: Rust (stable). Workspace `rust-version = 1.85`; the `bee` crate is 1.88, edition 2021.

**Primary Dependencies**: Existing only: tokio (rt-multi-thread, sync, time, process), async-trait,
serde, rustyline (inline REPL), ratatui/crossterm (TUI, cfg `tui`), rmcp (cfg `mcp`), and hyper/rustls
(cfg `intercept`). **No new dependencies.**

**Storage**: Transcripts are JSON. They gain `consents` and per-call `denied_attempt_audit`,
`proxy_audit`, `escalations`, `retried` and `timed_out`. Every new field is
`serde(default, skip_serializing_if = empty)`, so unchanged sessions serialize byte-identically. The
exchange store (`.bee/http/`) is unchanged.

**Testing**: `cargo test`, with `MockModel`, tokio `test-util` (paused clock), and the new `test-support`
feature (scripted audit). Existing seams are reused: fake `CallHooks` and `HttpScopeHook`. The VM matrix
(`test/vm/remote-matrix.sh`) is the regression check for enforcement.

**Target Platform**: Linux. Host builds for all orchestration tests; BPF-LSM for the VM tier.

**Project Type**: A Rust library (`bee`) with a thin CLI binary (`src/main.rs`, `src/app/`).

**Performance Goals**: No regression. `run_call` must add no allocation-heavy work per call beyond
today's. Lease expiry at turn start is O(leases).

**Constraints**:

- Behaviour is preserved apart from the listed drift fixes (FR-039).
- Episode progress strings stay byte-identical, as listed in [contracts/operator.md](./contracts/operator.md).
- The code must compile under every feature combination in CI: default, `intercept`,
  `intercept,enforce,concurrent`, `mcp`, `scanners`, `vm-test`.
- The `run_call` future must be `Send`, because the concurrent runner spawns `run_loop`.
- `test-support` must never be in a shipping feature set.

**Scale/Scope**:

- About 5.8k lines across the files touched, from `wc -l` on `episode.rs`, `repl.rs`, `app/repl.rs`,
  `app/session.rs`, `concurrent.rs`, `hooks.rs`, `escalate.rs` and `tools.rs`, plus `src/tools/http*.rs`.
- The two loops each lose about 150 lines (SC-009).
- Six PRs.

All unknowns are resolved in [research.md](./research.md) (R1–R9).

## Constitution Check

*GATE: checked before Phase 0 and re-checked after Phase 1 design.*

| Principle | Assessment |
|---|---|
| **I. Deny-by-default & fail-closed** | **Pass, and improves it.** <ul><li>A consent timeout now actually fires and refuses. Today the blocking prompt prevents it (R3).</li><li>The builder refuses unsupported combinations instead of silently dropping them (FR-008).</li><li>A Deny hook is honoured instead of ignored (FR-031).</li><li>A granted tool whose dependency is absent fails closed through 016 (FR-016).</li><li>The `test-support` scripted audit can fabricate denials that drive grants. It is a cargo feature excluded from every shipping set, with a guard test asserting its absence (R1). See Complexity Tracking.</li></ul> |
| **II. Capability attenuation** | **Pass, unchanged.** Every widening still goes through `ActivePolicy::check_widen` / `try_apply` against the ceiling before consent. The Autonomous operator grants only *within* the ceiling, as `AllowWithinCeiling` does today (D4). `BeyondCeiling` is recorded, never offered. The attenuation property tests are untouched. |
| **III. Kernel enforcement is authoritative** | **Pass, with one new claim that needs VM proof.** No enforcement *point* moves, and proxy-scope events still never drive tool-scope escalation (FR-022). But lease expiry and release (FR-029, FR-032) newly **narrow the kernel scope** at turn start. That is an enforcement claim, so it gets a BPF-LSM case in `test/vm/remote-matrix.sh` (FR-042, SC-010, task T028e). Host tests verify only that narrowing is requested. The tgid-based MCP attribution (R8) is labelled observational, and its limitation is documented (FR-027). |
| **IV. Policy-as-data** | **Pass, unchanged.** No policy format changes. Consent records are additive transcript data. |
| **V. Library-first** | **Pass, and fixes a current violation.** Today `src/app/session.rs` holds session-construction logic that only the binary has, which the principle forbids. It moves into the library (R5), and the CLI shrinks to mapping `EffectiveConfig` → `SessionSpec`. The core policy engine (`bee-core`) gains no async requirement; the builder lives in the `bee` harness crate, which is already async. |
| **Test-first for the security boundary** | **Pass.** PR1 characterizes before any change (FR-040). Each drift fix flips a pre-written `// DRIFT` assertion. The SC-004 retry matrix is written against `run_call` before the loops switch to it. |
| **Every security-relevant behavior is a testable requirement** | **Pass.** These behaviours each get a named test in [quickstart.md](./quickstart.md): consent recording, timeout refusal, deny precedence, lease expiry, and the audit retention of denials. |

**Post-design re-check**: the design artifacts (data model, contracts, quickstart) introduce no new
violations. The one justified item is below.

## Project Structure

### Documentation (this feature)

```text
specs/024-session-core/
├── spec.md
├── plan.md              # this file
├── research.md          # R1–R9
├── data-model.md
├── quickstart.md
├── contracts/
│   ├── operator.md
│   ├── call-lifecycle.md
│   ├── session-builder.md
│   ├── tool-surface.md
│   ├── hooks.md
│   └── intercept-ops.md
├── checklists/requirements.md
└── tasks.md             # /speckit-tasks
```

### Source Code (repository root)

```text
src/
├── call.rs                    # NEW  run_call, CallInput, CallOutcome, TimeoutPolicy        (phase 3)
├── operator.rs                # NEW  Operator, Consent, ConsentRequest/Record, adapters      (3 skeleton, 5 complete)
├── session/                   # NEW library home of the Session builder                     (phase 5)
│   ├── mod.rs                 #      Session, build, turn_start, call, snapshot, shutdown
│   ├── spec.rs                #      SessionSpec, EntryPoint, refusals
│   └── parts.rs               #      HttpPart, McpPart (feature-gated), http_advisory
├── tui/events.rs              # MOVED from src/session/{mod,event}.rs (SessionSink/SessionEvent)
├── hooks.rs                   # CHANGED dispatch-all + precedence; events/flows trimmed      (phase 4)
├── grants/escalate.rs         # CHANGED takes &Operator; step fns become call.rs-private      (3, 5)
├── grants/mod.rs              # CHANGED expire/release driven from turn_start                 (4)
├── tools.rs                   # CHANGED ToolDeps, register(), surface(); configure_* removed  (2)
├── tools/http.rs              # CHANGED respond(); configure_http_tools removed               (2, 6)
├── tools/http_*.rs            # SHRUNK to adapters                                            (6)
├── intercept/ops/             # NEW  send, replay, fuzz_run, sitemap, read, bound              (6)
├── sandbox.rs                 # CHANGED test-support scripted audit (1); CallOrigin::Fuzz removed (6); MCP tgid routing (5)
├── episode.rs                 # SHRUNK per-call code → run_call; setup → session::build       (3, 5)
├── repl.rs                    # SHRUNK per-call code → run_call; consent_rx arm; model-turn counter (3, 4, 5)
├── concurrent.rs              # CHANGED uses session::build with explicit refusals            (5)
├── skills/grant.rs            # CHANGED start-up grants through Operator, all capability kinds (5)
├── transcript.rs              # CHANGED consents + RecordedCall fields (additive)              (3, 5)
└── app/
    ├── session.rs             # REMOVED (logic moved to src/session/)                         (5)
    ├── repl.rs                # SHRUNK EffectiveConfig → SessionSpec + Interactive operator    (5)
    └── run.rs                 # SHRUNK EffectiveConfig → SessionSpec + Autonomous operator; --task keeps MCP/skills (5)

tests/
├── call_characterization.rs   # NEW (1), drift assertions flipped in (3)
├── session_parity.rs          # NEW (1, ignored) → enabled (5)
├── episode_progress_strings.rs# NEW (1)
├── test_support_absent.rs     # NEW (1)
├── tool_surface.rs            # NEW (2)
├── call_lifecycle.rs          # NEW (3)
├── hooks_leases.rs            # NEW (4)
├── operator.rs                # NEW (5)
├── intercept_ops.rs           # NEW (6)
└── support/harness.rs         # CHANGED uses session::build (5)
```

**Structure Decision**: a single crate, layout unchanged. New modules sit beside the ones they
consolidate. The only move is the TUI event sink (`bee::session` → `bee::tui::events`), which frees the
`session` name for the builder; its three importers are all in `src/tui/`.

## Phases (delivery order, FR-041)

Phases are named by PR number (PR1–PR6) in every document: plan, quickstart and tasks. In tasks.md, PR1
is preceded by a small setup phase, and PR5 is split into PR5a (builder) and PR5b (Operator).

| # | PR | Scope | Exit gate |
|---|---|---|---|
| 1 | Characterization | `test-support` feature and `Sandbox::host_scripted`; `call_characterization` through both loops, with drift tagged; `session_parity` (ignored, with known differences); progress-string pin; absence guard; update the `tests/dynamic_grants.rs:14-20` note (R1) | The quickstart phase-0 commands pass |
| 2 | Tool surface | `ToolDeps`, `register`, `surface`, `set_deps`; delete `configure_*`; start the Interceptor before registration; escalation registers via `register` | `tool_surface` passes; all existing tests pass |
| 3 | Call lifecycle | `src/operator.rs` skeleton (`Operator`, `SessionOutput`, `ConsentRequest`/`ConsentRecord`, with today's consent sinks and outputs wrapped) so `run_call` has its final signature; `src/call.rs`; both loops call `run_call`; step functions become private; transcript fields; REPL locks the active policy once per call | The `call_lifecycle` matrix passes; FR-021/022/024/025 drift flipped |
| 4 | Hooks and leases | dispatch-all and precedence; `TurnStart` from both loops; expiry and deescalation narrowing; `McpRefreshHook` replaces `refresh_tools`; model-turn counter in the REPL; remove unused events and flows; VM matrix case for narrowing | `hooks_leases` passes; the VM narrowing case is written and passes when the VM is available — the PR may merge before the VM exists, but phase 6 does not start until the case has run (FR-042) |
| 5 | Session builder and Operator | `src/session/`, the full Operator (adapters, recording) on the phase-3 skeleton, TUI event-sink move; every entry point and the harness use `build`; Interactive `ChannelConsent` (REPL arm, TUI modal, start-up consent served from the front-end's single reader); Autonomous `ProgressOutput`; consent records; refusal table; one advisory; teardown owner; `--task` MCP/skills; scanner dir; system prompt everywhere; MCP tgid routing; delete `app/session.rs` and `prompt_consent` | `session_parity` (enabled) and `operator` pass |
| 6 | Interceptor operations | `src/intercept/ops/`; tools become adapters; `respond`; delete `CallOrigin::Fuzz`; move `b64` | `intercept_ops` passes, and every existing `intercept_*` test passes unchanged |

**Risk notes**:

- **Phase 5 is the largest.** If review size is a problem, split it into 5a (builder, with today's consent
  adapters wrapped as Operators) and 5b (Interactive channel consent in the front-ends). The order within
  the phase is unchanged.
- **Phase 3 is the most behaviour-sensitive.** The `// DRIFT` assertions make every intended behaviour
  change explicit in the diff.

## Complexity Tracking

| Violation | Why needed | Simpler alternative rejected because |
|---|---|---|
| A test-only feature (`test-support`) adds a scripted audit source to `HostSandbox`. This revises the earlier decision at `tests/dynamic_grants.rs:14-20` not to add a seam to the type that mediates enforcement. | FR-026/SC-004 require the retry path to be testable without a VM. Kernel audit is the only call input with no existing seam. | <ul><li>A production-visible trait object is a seam a shipping build could misuse.</li><li>A `Sandbox::Scripted` variant needs about 12 more cfg'd arms across every match.</li><li>VM-only coverage leaves the most drift-prone code untested on every PR.</li></ul>Mitigation: feature-gated, excluded from default and release sets, with an absence guard test, following the `vm-test` precedent. |
