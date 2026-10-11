# Phase 0 Research: One Session Core for Autonomous and Interactive bee

**Feature**: [spec.md](./spec.md) · **Plan**: [plan.md](./plan.md) · **Date**: 2026-10-10

Every decision is grounded in the tree at `430640c` (main with #22). File references are to that
commit. Nothing here adds a third-party dependency.

---

## R1 — Host-testable call lifecycle: a `test-support` feature with a scripted audit source

**Decision**: Add a cargo feature `test-support`, following the `vm-test` precedent ("NEVER in a
shipping build"). Behind it, `HostSandbox` gains `scripted: Option<Arc<ScriptedAudit>>`, which holds two
queues of audit batches, one for the tool scope and one for the proxy scope. `drain_audit` and
`drain_sidecar_audit` each pop one batch. It is installed only by
`#[cfg(feature = "test-support")] Sandbox::host_scripted(..)`. Integration tests that need it declare
`[[test]] … required-features = ["test-support"]`; a self dev-dependency is avoided, because cargo's
cyclic-dependency check makes it unreliable. A guard test asserts that the default and release feature
sets exclude it. The same feature also provides a `TeardownLog` — an `Arc<Mutex<Vec<&'static str>>>`
that `Session::shutdown` appends each stage name to (`"mcp"`, `"interceptor"`, `"scopes"`) — so teardown
order is assertable on host.

The other inputs a scripted call needs already have seams, so none of them change:

- proxy events come through `CallHooks` (`src/sandbox.rs:134-146`, installed with `set_call_hooks`);
- Target-scope widening comes through `HttpScopeHook` (`src/sandbox.rs:114-125`);
- the tool is any `impl Tool` (`src/tools.rs:285`);
- timeouts use tokio `test-util` with `time::pause` (already a dev-dependency, `Cargo.toml:359`).

**Rationale**: Kernel audit is the only input with no seam. `Sandbox::Host` drains nothing
(`src/sandbox.rs:773`, `:679`), which is why no host test covers the retry path. `Host` enforces
nothing, so a scripted batch can only add audit; it cannot weaken a kernel decision. It can, however,
*fabricate denials that drive grants*, so it must never compile into a shipping build. Hence a feature,
not a public trait object.

**This revises a recorded decision**: `tests/dynamic_grants.rs:14-20` declined a replay seam on Host
because "it would put a test seam in the type that mediates enforcement". FR-026/SC-004 now require host
coverage. The feature gate and the absence guard answer that concern, and the comment there is updated.

**Alternatives rejected**: a `Sandbox::Scripted` variant needs about 12 more cfg'd match arms. A
production-visible `AuditSource` trait object on `HostSandbox` is the seam the earlier decision rightly
refused. Leaving the retry path VM-only fails SC-004.

---

## R2 — The call lifecycle module: `src/call.rs`, one `run_call`

**Decision**: A new module `src/call.rs` exposes one async function, `run_call`. It owns the whole
sequence:

1. proactive escalation
2. open the call
3. timed execute
4. settle and drain
5. kernel-denial escalation, and a retry inside the same call
6. close the call
7. proxy-refusal escalation, and a retry in a new call
8. proxy-scope drain
9. late drain

It returns a `CallOutcome` ([contracts/call-lifecycle.md](./contracts/call-lifecycle.md)). The timeout
is a `TimeoutPolicy { Deadline(Instant), PerCall(Duration) }`. `PerCall(t)` is turned into a deadline of
`now + t` when the call starts, so the first attempt and any retry share it, and both policies follow one
rule: a retry gets only the remaining time and does not start when none is left (FR-024). This fixes the
REPL's current behaviour, where a retry gets a fresh `tool_timeout`.

`run_call` takes `&Operator` and `&dyn SessionOutput` from the start. PR3 therefore lands an
`src/operator.rs` skeleton that wraps today's consent sinks and outputs; PR5 fills in the adapters
and recording without changing `run_call`'s signature.

The REPL locks its `ActivePolicy` once per call and passes `&mut *guard`. Today it locks up to three
times (`src/repl.rs:637,685,727`).

`escalate()`, `LoopEscalation`, the hooks and the `delta_from_*` helpers stay in `src/grants/escalate.rs`
as the widen cycle, which has its own unit tests. `proactive_step`, `reactive_step`, `proxy_refusal_step`
and `first_denial` become private helpers of `call.rs`, each returning `(Trigger, EscalateOutcome)`.

The future must be `Send`, because `run_loop` is spawned by the concurrent runner
(`src/concurrent.rs:215-224`). Every trait involved is already `Send + Sync`.

**Rationale**: The two copies (`src/episode.rs:299-463`, `src/repl.rs:632-813`) differ in exactly the
places FR-021–025 fix:

- the pre-retry denial is kept in one loop and dropped in the other;
- proxy denials are counted as the tool's in one loop and not the other;
- a timed-out proxy retry pairs the old result with the new audit;
- the REPL has no deadline on retries.

Deleting either copy loses nothing that the other does not also do. That makes it a pure duplicate,
so one owner is the deepening.

**Alternatives rejected**: putting the sequence on `Sandbox`. The sequence needs the registry and the
escalation state, and `Sandbox` would become a god-object. A trait with one implementation per loop
would rebuild the duplication behind an interface.

---

## R3 — The Operator: a struct of two trait objects, with consent recorded in one place

**Decision**:

```text
Operator { kind: OperatorKind, consent: Arc<dyn Consent>, output: Arc<dyn SessionOutput>,
           timeout: Duration, log: ConsentLog }
```

- `Consent::decide(&ConsentRequest) -> Decision` is async. `ConsentRequest` is owned so it can cross a
  channel, and it carries every capability kind plus a typed `GrantOrigin`.
- `Operator::consent(&self, req)` is the only entry point bee calls. It applies the timeout itself
  (uniform for both adapters), computes the reason (`Granted | DeniedByOperator | TimedOut`), records a
  `ConsentRecord`, and tells the output.
- Refusals beyond the ceiling are recorded through `Operator::record_unasked(..)` before consent would
  be asked. They are never offered to anyone, so every decision is logged (FR-004). A request whose
  capabilities are all already held is **not** recorded: no decision was made, and a skill's `requires`
  is re-proposed on every `skill` call, so recording it would flood the log.
- `SessionOutput` is `ReplOutput` (`src/repl.rs:152-227`) plus default methods: `turn_started`,
  `assistant_text`, `header`, `escalation`, and `consent_decided`.
- **Autonomous** = `AllowWithinCeiling` consent plus `ProgressOutput(ProgressSink)`. `ProgressOutput`
  reproduces the episode's progress strings byte for byte (the full list is in
  [contracts/operator.md](./contracts/operator.md)). The default timeout is 60 s.
- **Interactive** = `ChannelConsent` (an `mpsc` of `(ConsentRequest, oneshot::Sender<Decision>)`; a
  dropped sender means Denied) plus `TerminalOutput` or `SessionSink`. The default timeout is 120 s.
- Consent records go into a new `EpisodeTranscript.consents` field and the REPL's exchange result. The
  field is `#[serde(default, skip_serializing_if = "Vec::is_empty")]`, so existing transcripts serialize
  byte-identically when there are no decisions. They never go into `AuditEvent`, which is kernel-shaped
  (`crates/core/src/audit.rs:11`).

**Front-end changes for Interactive**:

- **Inline REPL**: `run_repl`'s `select!` (`src/repl.rs:1341-1364`) gains a `consent_rx` arm. On a request
  it prints `GrantRequest::render_lines()` through the output and sets `awaiting`.
  - The next submitted line answers the request only if it is `y`/`yes`/`n`/`no`.
  - Any other line goes to steering as it does today, and the question is shown again.
  - This meets the spec's mid-input edge case: rustyline cannot cancel an in-flight `readline`, so a
    partial line is never taken as the answer and never lost.
- **TUI**: `run_turn`'s `select!` (`src/tui/mod.rs:262-285`) gains a `consent_rx` arm that opens a consent
  modal in `App`. The reducer (`src/tui/app.rs:329`) routes y/n keys to the oneshot while the modal is
  open and leaves the input buffer alone. The existing `Overlay` is a timed takeover, not an input
  surface, so it is not reused.
- **Start-up grants** (before the first turn): there must never be two readers on the terminal. A
  `spawn_blocking` readline is rejected because `tokio::time::timeout` cannot cancel it. After a timeout
  the thread would still be reading when `run_repl` starts its own read, which is the race this feature
  removes. Instead, the front-end starts its line reader *before* the session is built, and start-up
  consent is served from that single pending read through the same `consent_rx` path as in-loop consent.
  The still-pending read is then handed to `run_repl` as its first outstanding read. The TUI enters the
  alternate screen first and shows start-up consent as its first consent modal.
- **Late answers**: in both front-ends, an answer that arrives after the Operator's timeout has refused
  the request is reported as "consent already timed out" and dropped. It is never applied, and never
  queued as steering.

**Rationale**: Consent and output vary independently. Tests use a recording output with either consent
policy, so two trait objects are better than one Operator trait with four implementations.

The research also confirmed the bug the PR #19 review reported. `prompt_consent`
(`src/app/repl.rs:532-549`) blocks the polling task, so the `tokio::time::timeout` in `escalate`
(`src/grants/escalate.rs:113`) can never fire. It competes with rustyline for stdin and draws over the
TUI. A timeout and a "no" also collapse into the same `Refused("denied by operator")`. All of this is
fixed by construction.

**Alternatives rejected**: keeping `ProgressSink` and `ReplOutput` separate. The loops would keep two
output vocabularies, which is the drift this feature removes. One `Operator` trait would couple consent
policy to front-end. Keeping the blanket `impl ConsentSink for Fn` would keep the blocking-closure
foot-gun, so it becomes test-only.

---

## R4 — Tool surface: dependencies held by the registry, one constructor

**Decision**:

- `ToolRegistry` holds `deps: Arc<ToolDeps>`, containing:
  - `ctf_flag`
  - `ledger` and `run_id` (cfg `findings`)
  - `scanner_grants` (cfg `scanners`)
  - `interceptor` (cfg `intercept`)
  - `skills`
- `registry.register(name)` is the one constructor. It always builds the tool configured from `deps`, and
  a missing dependency yields the 016 fail-closed outcome (`InterceptorUnavailable`, `NotCompiledIn`).
- Startup, skill grants, and `escalate()`'s tool registration (`src/grants/escalate.rs:148`) all call it.
- `configure_security_tools` (`src/tools.rs:491`) and `configure_http_tools` (`src/tools/http.rs:25`) are
  deleted. The Interceptor therefore starts before any tool is registered.
- Scanner grants derive from the active policy, so `ActivePolicy` changes refresh `deps` before a granted
  tool registers.
- MCP proxies keep their own constructor (`McpBridge::register_into`); they are a separate family keyed
  `mcp__*`.
- `ToolRegistry::surface()` returns `(name, schema, deps-summary)` for every tool. It is the single
  answer for FR-015 and the source 023-codemode generates its catalog from.

**Rationale**: Seven sites mutate the registry, and last-insert wins (`src/tools.rs:308`). Configuration
by replacement is the reason escalation produces unconfigured tools. With the dependencies held by the
registry, there is nothing left to forget.

**Alternatives rejected**: making escalation call the `configure_*` passes. That keeps the
remember-to-re-pass invariant that already failed once.

---

## R5 — The Session builder: a library module, part-wise and feature-gated

**Decision**:

- Move `src/app/session.rs`'s logic into the library as `src/session/` (`builder.rs`, `spec.rs`,
  `parts.rs`).
- Free the name by moving the TUI event sink (`bee::session` → `bee::tui::events`). Its only importers
  are `src/tui/{app,mod,message}.rs`.
- The binary maps `EffectiveConfig` (`src/app/config/mod.rs:81`, which already has no clap types) to a
  library `SessionSpec`.
- `Session::build(spec, operator) -> Result<Session, BuildError>` runs one ordered pipeline (the step
  list is in [contracts/session-builder.md](./contracts/session-builder.md)). Each optional part is
  `Option<HttpPart>` or `Option<McpPart>` behind its feature, which removes the scattered
  `cfg_attr(allow(unused_mut))`.
- The concurrent runner calls the same builder with `EntryPoint::Batch { concurrent: true }`. The
  builder refuses `[policy.http]`, MCP servers, and escalation-with-widening for it, by name, before any
  scope exists (FR-008). Today `scenario.mcp` is silently ignored and `[policy.http]` is refused only at
  `src/concurrent.rs:39`.
- `Session::shutdown(self)` owns teardown in one order: MCP servers → Interceptor → scopes (proxy scope,
  then tool scope, as `Sandbox::teardown` already does at `src/sandbox.rs:802`). It is backed by a
  `Drop` guard for error paths.
- One `http_advisory(&spec)` replaces the three copies (`src/episode.rs:782`, `src/app/repl.rs:247`,
  `src/app/run.rs:300`).
- `effective_system_prompt` moves into the builder, and every entry point uses it.
- `bee run --task` builds its `SessionSpec` from the effective configuration, so MCP and skills are
  honoured (FR-009). Today `src/app/run.rs:115,161-162` drop them.
- `widen_for_scanner_reports` (`src/episode.rs:1021-1055`) runs in the builder for every entry point
  (FR-010).

**Rationale**: Constitution V says "the CLI MUST NOT contain … logic the library lacks", and
`app/session.rs` violates it. That violation is why the library's episode path rebuilt its own copy.
Once the builder is in the library, the four paths collapse to one.

**Alternatives rejected**: sharing helper functions while leaving the paths separate. That is what
`app/session.rs` already attempts, and the paths still drifted.

---

## R6 — Hooks: pure hooks, a shared turn-start step, a precedence rule

**Decision**:

- Hooks stay pure: `&StepEvent → Flow`.
- `dispatch` consults **every** observing hook and combines their results with the rule
  `Deny > Escalate > Continue`. Escalate deltas from several hooks are merged, and `Deescalate`s
  accumulate. Today the first non-Continue wins (`src/hooks.rs:105`), which can let a grant outrank a
  refusal (FR-034).
- **Events kept**: `TurnStart`, `BeforeToolCall`, `KernelDenial`, `ProxyRefusal`.
- **Deleted**: `BeforeModelCall` and `AfterToolResult`, which have no consumer.
- **Flows kept**: `Continue`, `Deny`, `Escalate`, `Deescalate(GrantId)`, and the new `RefreshTools`.
- **Deleted**: `Terminate`, which has no consumer.
- A shared `Session::turn_start(turn)` step, called by both loops at the top of each model turn:
  1. dispatches `TurnStart`;
  2. releases every `Deescalate`;
  3. runs `ActivePolicy::expire(turn)`;
  4. if anything was dropped: `sandbox.reload`, `apply_http_scope` when Target-scope entries were
     dropped, and removal of lease-only tools from the registry;
  5. on `RefreshTools`, re-registers MCP tools.
- A built-in `McpRefreshHook { bridge }` returns `RefreshTools` when `bridge.take_dirty()`. This replaces
  the `refresh_tools` closures (`src/episode.rs:38,193`; `src/repl.rs:74,509`) and satisfies FR-030
  "through the hook mechanism" without giving hooks mutable access.
- `BeforeToolCall → Deny` makes `run_call` skip execution and return
  `ToolResult::refused_by_hook(reason)`, which is distinct from a tool failure (FR-031).
- **Turns are model turns** (D3). The REPL's `ReplEscalation` keeps a monotonic model-turn counter that
  increments at the top of each step of `run_exchange` (`src/repl.rs:505`), not per tool call (`:635`).

**Enforcement proof**: narrowing at turn start is a new kernel-enforcement claim. Host tests can only
show that `reload` was requested with the narrower policy. `test/vm/remote-matrix.sh` gains two cases:
`lease-expiry` (grant `Ttl::Turns(1)`, read succeeds, next turn starts, read is denied by the kernel)
and `lease-release` (the same with a `Deescalate` hook) (FR-042, SC-010).

**Rationale**: `ActivePolicy::expire` has no production caller, so `Ttl::Turns` leases never expire. This
is masked today only because both loops default to `Forever`. Three of six events and three of five flows
are accepted and then ignored, which gives false assurance (Constitution I).

**Alternatives rejected**: a mutable `TurnContext` passed to hooks. It would widen hook authority to the
registry and policy. Keeping `Terminate` and `BeforeModelCall` "for later" would leave the interface
offering what nothing honours (FR-033).

---

## R7 — Typed Interceptor operations: `src/intercept/ops/`

**Decision**: Create `src/intercept/ops/` with these files:

- `mod.rs`: `OpError` (with `From<InterceptError>`), and the call context `CallCtx` (= `WireCtx`), passed
  explicitly.
- `send.rs`: `build_request`, `send` with redirect following and the Target-scope stop.
- `replay.rs`: `replay`, `stored_request`, `side_of`.
- `fuzz_run.rs`: `fuzz`, `template_from`.
- `sitemap.rs`
- `read.rs`: `read_exchange`, `scope_view`.
- `bound.rs`: `bounded_json`, `text_or_binary`, `clip`, `b64`.

The `http_*` tools shrink to: schema, parse arguments into a spec, one op call, and a shared
`respond(icpt, Result<Value, OpError>, bound, provenance)` in `src/tools/http.rs`.

`history`, `leads` and `intercept` already call typed store and sidecar APIs, and stay as they are apart
from using `respond`.

The fuzz payload-file read (a `cat` child, `src/tools/http_fuzz.rs:360`) stays in the adapter. Ops never
see a `Sandbox`; the adapter computes the `CallCtx` once.

Moving `b64` removes the reverse dependency `src/intercept/diff.rs:272 → crate::tools::http_send::b64`.

**`CallOrigin::Fuzz` is deleted** (FR-038). Nothing constructs it. Fuzz traffic is already marked by the
worker's `OriginKind::Fuzz` plus `fuzz_run` (`src/intercept/worker/mod.rs:674-677`). Changing the call id
would break refusal attribution to the model's call. The `src/intercept/creds.rs:146` arm and the
`src/intercept/control.rs:31` doc mention go with it.

**Rationale**: the logic is locked behind `Tool::call(Value)` in seven places. The imports between tools
(`http_send::call_ctx`, `http_replay::{stored_request, side_of}`) and three copies of the
`InterceptError` mapping (`http_send.rs:131`, `http_replay.rs:112`, `http_fuzz.rs:103`) show that the
operations module is already there implicitly.

**Guards**: `tests/intercept_tools.rs`, `intercept_replay.rs`, `intercept_fuzz.rs`, `intercept_rules.rs`,
`intercept_leads.rs`, `fail_closed_tools.rs:268`, and `tool_output_framing.rs:65` must pass unchanged.

---

## R8 — Attributing MCP server activity (FR-027)

**Decision**:

- Record each MCP server child's `tgid` at spawn (`src/mcp/transport.rs`).
- `drain_audit` routes events whose `tgid` belongs to an MCP server to an `Mcp(name)` origin. They are
  recorded in the session record under that server, not in the open tool call's audit. The routing uses
  the `tgid` field that `AuditEvent` already carries (`crates/core/src/audit.rs:19`).
- **Documented limitation** (accepted in FR-027): grandchildren of an MCP server are not tracked by tgid and still land in
  the tool scope's stream. Full separation needs the MCP server in its own scope, which belongs to
  018-subagent-scopes.

**Rationale**: MCP servers run in the tool scope for their whole lifetime under one `begin_side_call`
(`src/mcp/transport.rs:20-27`), so cgroup-based draining cannot tell them apart. `tgid` is the only
signal available today without a new scope.

**Alternatives rejected**: a scope per MCP server now. It is the right end state, but it depends on
018's scope-per-subagent machinery.

---

## R9 — Characterization and cross-entry-point comparison (FR-040, SC-001)

**Decision**:

- **PR1, through both loops.** Script the same scenarios through `run_loop` and `run_exchange` using
  `host_scripted` (R1), a fake `CallHooks`/`HttpScopeHook`, `MockModel`, and a recording consent sink.
  Normalize per call to `(call_id, content, is_error, [(op, target, decision, scope_id)], proxy kinds)`.
  Ignore durations and turn numbering.
- **PR1 asserts today's behaviour, drift included.** The drift assertions are tagged `// DRIFT
  FR-0xx`, and each phase that fixes one flips its assertion. That turns SC-003's "failed before, passes
  after" into a visible diff.
- **Session comparison.** The builder exposes `Session::snapshot() -> SessionSnapshot`: policy, grants,
  tool surface (names plus deps summary), escalation settings, system prompt, and part presence. The
  snapshot is serializable, so the comparison test builds one spec through every `EntryPoint` and diffs
  them, excluding the Operator.
- **Before the builder exists**, PR1 writes the same comparison against the current four paths. It is
  marked `#[ignore]` with its known differences listed, and un-ignored in PR5.
- **Episode progress strings** are pinned by a test over a recording `ProgressSink` before the Operator
  phase moves them.

**Rationale**: Without PR1, "behaviour unchanged except listed fixes" (FR-039) cannot be checked.
