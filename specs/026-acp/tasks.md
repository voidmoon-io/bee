---
description: "Task list for 026 ACP"
---

# Tasks: ACP — bee as an Agent, and Foreign Harnesses as Scoped Subagents

**Input**: Design documents from `specs/026-acp/` (spec, plan, research R1–R16, data-model, contracts,
quickstart S1–S10)

**Tests**: Included. The constitution requires enforcement behaviour to have failing tests before
implementation, and every kernel claim a VM case (quickstart). Write each story's tests first and
watch them fail; run a negative control for every new VM case.

**Organization**: by user story. PR slices (plan "Implementation Sequence"): **PR1** = Phases 1–4
(US1+US2), **PR2** = Phase 6's proxy-scope tasks + Phase 7 (T092, US5), **PR3** = Phase 5 + Phase 6's
harness tasks (US3+US4), **PR4** = Phase 8.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: can run in parallel (different files, no dependency on an unfinished task)
- **[Story]**: US1–US5 from spec.md
- Build and test on `bee-build`, never on the laptop (memory `bee-build-vm`). Gate per PR: `cargo
  check` (`enforce`; `concurrent,mcp,sec,astgrep-rust,intercept,durable-sessions`), clippy `-D
  warnings -A clippy::result_large_err`, `cargo test --workspace`, the CI `test-support`/`intercept`
  list, headless, and the VM matrix (copy `test/vm/cases.txt` beside `remote-matrix.sh`).

---

## Phase 1: Setup

- [x] T001 Add `agent-client-protocol = "5.1"` (default-features = false) and `tokio-util` (`compat`) to `[dependencies]` in `Cargo.toml`, behind a new feature `acp = ["dep:agent-client-protocol", "dep:tokio-util", "tokio/io-std"]`; add `acp` to the CI feature lists in `.github/workflows/ci.yml` (check + clippy + test steps)
- [x] T002 [P] Create `src/acp/mod.rs` (module docs naming both directions, `PROTOCOL_VERSION = 1`) and wire `#[cfg(feature = "acp")] pub mod acp;` in `src/lib.rs`
- [x] T003 [P] Create the test binary `tests/bin/acp_fake_harness.rs` (registered as `[[bin]] required-features = ["acp", "test-support"]` or a `[[test]]` helper per repo convention): an ACP v1 agent that, on `session/prompt`, executes the action script in env `FAKE_HARNESS_SCRIPT` (JSON list: `write`, `read`, `connect_via_proxy {host,port}`, `fork_sleeper`, `call_fs_read`, `ask_permission`, `say {text}`, `sleep {secs}`) and reports each action's outcome as an `agent_message_chunk`

---

## Phase 2: Foundational (blocks US1–US5)

- [x] T004 Add `cwd: Option<PathBuf>` to `ChildEnv` in `src/sandbox.rs`, applied via `Command::current_dir` in `tool_command_for` and `invocation_command`; a child sandbox inherits it in `delegate::child_sandbox` (`src/delegate.rs`); `None` keeps today's behaviour
- [x] T005 [P] Unit test in `src/sandbox.rs` tests: a host sandbox with `cwd = Some(tmp)` runs `pwd` → `tmp`; `None` → bee's cwd
- [x] T006 Add `EntryPoint::Acp` in `src/session/spec.rs`; in `src/session/mod.rs` derive the scope id and run id from `SessionSpec.label` for `Acp` (not `bee-session-{pid}`), and allow `prebuilt_sandbox` for `Acp` (the concurrent-batch path, `src/concurrent.rs:112`); keep `refuse_unsupported` permitting MCP for `Acp`
- [x] T007 [P] Add the operator-only `[acp]` section (`client_mcp: bool`, `max_sessions: u32` default 8 clamp 1..=32, `harness_env_passthrough: Vec<String>`) to `src/app/config/file.rs` and `EffectiveConfig` in `src/app/config/mod.rs`; reject `[acp]` in a project layer in `FileConfig::user_only_sections`; tests beside the existing `[mcp]` rejection test
- [x] T008 Make `DelegationRecord.turns_used` and `tokens_used` `Option<_>` (`None` = not counted) in `src/transcript.rs`, with `skip_serializing_if`; keep reading old records (add a round-trip test with a pre-026 JSON fixture in `tests/transcript_compat.rs`); update `src/delegate.rs` and the progress line to print "not counted"

**Checkpoint**: foundation ready — US1/US2 and US3 can proceed in parallel.

---

## Phase 3: User Story 1 — Drive bee from t3code (P1) 🎯 MVP

**Goal**: `bee acp` serves ACP v1 sessions; prompts stream; tool calls are reported; denials shown on their call; cancel works; several sessions per process.

**Independent Test**: quickstart S2 (host), S3, S5, S6 (VM).

### Tests (write first, must fail)

- [x] T009 [P] [US1] Host test `tests/acp_agent.rs::initialize_advertises_v1_and_no_client_methods`: a scripted client over in-memory duplex pipes calls `initialize`; assert the response fields in contracts/acp-agent.md (protocolVersion 1, loadSession false, mcp http/sse false, authMethods empty)
- [x] T010 [P] [US1] Host test `tests/acp_agent.rs::a_prompt_streams_and_reports_its_tool_call`: `MockModel` script = one `write_file` then text; assert the update order (tool_call in_progress → tool_call_update completed → agent_message_chunk) and `stopReason: end_turn`; assert bee sent no `fs/*`/`terminal/*` request though the client advertised both (SC-002)
- [x] T011 [P] [US1] Host test `tests/acp_agent.rs::session_new_refuses_a_bad_cwd`: relative, missing and file cwd → error naming the cause; no scope created
- [x] T012 [P] [US1] Host test `tests/acp_agent.rs::client_mcp_servers_are_dropped_unless_allowed`: stdio + http servers in `session/new`; default config → both dropped and announced; `client_mcp = true` → stdio admitted (fixture server), http still dropped
- [x] T013 [P] [US1] Host test `tests/acp_agent.rs::cancel_ends_the_turn_cancelled`: a tool call that sleeps; `session/cancel` → `stopReason: cancelled` within 2 s, conversation truncated (next prompt's model input lacks the cancelled user message)
- [x] T014 [P] [US1] VM cases in `test/vm/remote-matrix.sh` + `test/vm/cases.txt`: `acp-denial-reported` (S3), `acp-two-sessions-isolated` (S5), `acp-cancel` (S6), using a small Python ACP client script embedded in the case (newline-delimited JSON over the `bee acp` process's pipes)

### Implementation

- [x] T015 [US1] `src/acp/output.rs`: `AcpOutput` implementing `ReplOutput` by sending `SessionNotification`s on an mpsc to the connection task, mapping per contracts/acp-agent.md (`kind` table, denial lines from audit, `info`/`error` as `bee: ` chunks, all text through `safe_text`); `tool_call` ids = bee call ids
- [x] T016 [US1] `src/acp/agent.rs`: the connection (`Agent.v1()` over `tokio::io::stdin/stdout` via `tokio-util` compat), handlers for `initialize`, `session/new`, `session/prompt` (spawned with `cx.spawn`, responder kept — research R1 ordering trap), `session/cancel`; `method_not_found` for the rest; session table bounded by `max_sessions`
- [x] T017 [US1] `session/new` in `src/acp/agent.rs`: validate cwd (absolute, exists, dir); `config::resolve(cwd, flags)`; build the session with `EntryPoint::Acp`, label `acp-<id>`, `prebuilt_sandbox` from the process supervisor (T018), `ChildEnv.cwd = cwd`; check the policy can read cwd (else shutdown + refuse); client MCP per `[acp] client_mcp` (convert stdio entries to `McpServerConfig`, merge into the session's `McpPolicy`); announce dropped servers
- [x] T018 [US1] `src/app/acp.rs` + `Cmd::Acp` in `src/main.rs`: tokio runtime, process setup shared with `bee repl` (`app::session::build`: non-dumpable, provider), one `Supervisor::start()` for the process (kernel mode) handing each session a scope via `create_scope`; stdin EOF → cancel all, `shutdown()` each session, non-zero exit if a scope would not empty; stdout is protocol-only (all logging to stderr)
- [x] T019 [US1] Prompt execution in `src/acp/agent.rs`: build the user message from text + embedded text resources; refuse image/audio; run `run_exchange` with `AcpOutput` and the session's `ReplConfig` (delegation progress sink → `tool_call_update` lines on the `task` call); map `ExchangeOutcome` → `stopReason` per the contract; refuse a second concurrent prompt in one session
- [x] T020 [US1] Cancel in `src/acp/agent.rs`: abort the exchange task (dropping it kills tool children — `tools/exec.rs` `ChildOwner`), truncate the conversation (as `tui/mod.rs` `/cancel`), refuse pending consent for that session, answer `cancelled`
- [x] T021 [US1] Make T009–T014 pass; record the VM results in `specs/026-acp/quickstart.md` Results

**Checkpoint**: bee is usable from t3code with a fixed policy (consent refuses until US2).

---

## Phase 4: User Story 2 — Consent questions answered in the client (P1)

**Goal**: every consent ask becomes `session/request_permission`; the answer decides it; timeouts and disconnects refuse.

**Independent Test**: quickstart S4.

### Tests (write first, must fail)

- [x] T022 [P] [US2] Host test `tests/acp_agent.rs::permission_allow_widens_and_reject_does_not` (test-support scripted audit for the denial): two prompts; client answers allow then reject; assert scope reload on the first, none on the second; consent log = Granted, DeniedByOperator, `operator: interactive`
- [x] T023 [P] [US2] Host test `tests/acp_agent.rs::permission_request_lists_every_capability_and_names_a_subagent`: request content contains every `render_lines()` line; a subagent's request (018 US7 origin) is titled `subagent '<name>' asks: …`
- [x] T024 [P] [US2] Host tests `tests/acp_agent.rs::unanswered_and_cancelled_permission_requests_refuse`: no answer within a short operator timeout → TimedOut; client answers `cancelled` → Denied; connection closed → Denied
- [ ] T025 [P] [US2] Host test `tests/acp_agent.rs::startup_grants_are_asked_during_session_new`: a skill with `requires` → a permission request arrives before the `session/new` response
- [x] T026 [P] [US2] VM case `acp-consent` (S4) in `test/vm/remote-matrix.sh` + `cases.txt`, with a never-answer variant

### Implementation

- [x] T027 [US2] `src/acp/consent.rs`: per-session task servicing the `ConsentReceiver` (from `ChannelConsent::new()` used for `Operator::interactive`) → `cx.send_request(RequestPermissionRequest)` with options `allow`(allow_once) / `reject`(reject_once), `toolCall` = triggering call id or `consent-<seq>`, content = `render_lines()`; reply `Granted` only on `selected: allow`; handled with `on_receiving_result`, never `block_task` inside a handler
- [x] T028 [US2] Service consent during `session::build` in `src/acp/agent.rs` (start-up grants, as `serve_startup` does for the REPL) and for the session's lifetime; on cancel/disconnect drop pending asks (→ Denied)
- [x] T029 [US2] Make T022–T026 pass; record S4

> **PR1 as built (2026-11-09).**
> - **Deferred:** T003 (fake harness binary) and T008 (counts that can be "not counted") move to PR3, where only harnesses need them. T025 (a start-up grant asked during `session/new`) is not tested: the consent servicer runs before `build`, so it works the same way, but no test covers it yet.
> - **Narrower than planned:** T017 does not check that the session's policy can read the cwd. A cwd the scope cannot enter makes every tool start fail, visibly, rather than refusing the session. T019 shows no live progress for subagents; a `task` call shows its report when it ends, as in the REPL. T023 checks the rendered capability lines; the subagent prefix is covered by the operator unit test. T024 covers a `cancelled` answer; the timeout and closed-connection cases rely on the operator's existing tests.
> - **Seams:** `session::build_on(spec, report, supervisor)` creates a session's scope on a shared supervisor (`SystemParts.supervisor`). `EntryPoint::Acp` names scopes `bee-acp-<session id>` and starts children in `SessionSpec.workdir`. The build functions' `report` callback is now `&(dyn Fn(&str) + Sync)` so a build future is `Send`. `ChildEnv` keeps its size: `strip_env` is an `Arc<[String]>` and the new `cwd` an `Option<Arc<Path>>`, because `Sandbox::Host` holds it unboxed.
> - **VM:** 60/60, with four new cases (`acp-denial-reported`, `acp-two-sessions-isolated`, `acp-cancel`, `acp-consent`). Negative controls: giving session A session B's policy fails the isolation pair; allowing both requests fails `acp-consent`. Host tests were checked by mutation (grant on any answer; ignore cancel).

**Checkpoint (PR1)**: US1 + US2 complete — open PR1.

---

## Phase 5: User Story 3 — Run a foreign harness as a scoped subagent (P2)

**Goal**: `runtime.acp` agents run in a child scope; bee is their ACP client; permissions auto-allowed and recorded; report from the final turn; everything reaped.

**Independent Test**: quickstart S7 with `acp_fake_harness`, no network.

### Tests (write first, must fail)

- [x] T030 [P] [US3] Unit tests in `src/skills.rs`: `runtime.acp` parses (absolute command, args, env); relative command, non-empty `tools`, a stripped credential key in `env` → malformed-definition warnings; absent `runtime` → `AgentRuntime::Loop`
- [x] T031 [P] [US3] Host test (`test-support`) `tests/acp_harness.rs::a_harness_reports_its_final_turn_and_its_calls_stay_in_its_record`: delegate to `acp_fake_harness` (`say`, one permission ask); assert the parent's result is the final text + the FR-021 note, `HarnessRecord.permissions` has one `allow_once`, the parent's conversation has no harness tool calls
- [x] T032 [P] [US3] Host test `tests/acp_harness.rs::fs_and_terminal_calls_are_refused_and_recorded`: `call_fs_read` → `method_not_found`, `refused_methods` lists it, harness continues
- [x] T033 [P] [US3] Host test `tests/acp_harness.rs::a_harness_is_refused_without_a_kernel_scope`: host sandbox → `Refused` naming the reason, nothing spawned (FR-017)
- [x] T034 [P] [US3] Host tests `tests/acp_harness.rs::deadline_cancels_then_cuts_short` and `::a_harness_that_exits_early_fails_with_its_stderr`
- [x] T035 [P] [US3] VM case `harness-contained` (S7) in `test/vm/remote-matrix.sh` + `cases.txt`: in-scope write ok; outside write kernel-denied in the delegation's audit with the child scope id; `fs/read_text_file` refused; detached sleeper gone; child scope gone

### Implementation

- [x] T036 [US3] `AgentRuntime` (`Loop` | `Acp{command,args,env}`) on `Agent` in `src/skills.rs`, parsed in `load_as_agent` with the T030 validation; `runtime` added to the `Frontmatter` struct; document in `specs/018-subagent-scopes/contracts/agent-definition.md` (pointer to 026's harness-runtime contract)
- [x] T037 [US3] `HarnessRecord`, `HarnessTurn`, `HarnessToolCall`, `PermissionRecord` in `src/transcript.rs`; `DelegationRecord.harness: Option<Box<HarnessRecord>>` with `skip_serializing_if`; compat fixture test
- [x] T038 [US3] `src/acp/harness.rs` spawn: from the child `Sandbox`, `tool_command_as` with the harness command/args, env = cleared env + agent `env` + passthrough keys valued from bee's env (`[acp] harness_env_passthrough`), `cwd` from `ChildEnv`; convert to tokio `Command`, pipe stdin/stdout, capture stderr tail (4 KiB ring), `kill_on_drop(true)`
- [x] T039 [US3] `src/acp/harness.rs` client: `Client.v1()` over the pipes (`ByteStreams` via compat); `initialize` (v1, fs/terminal false, `clientInfo` bee) — reject other versions; `session/new { cwd, mcpServers: [] }`; `session/prompt` with the task text; handlers: `SessionNotification` → `HarnessRecord.turns` + progress sink; `RequestPermissionRequest` → research R11 choice, recorded; any other client request → `method_not_found` + `refused_methods`
- [x] T040 [US3] Bounds in `src/acp/harness.rs`: race the prompt against the shared deadline (`ParentView.deadline` ∧ `Budget.deadline`); on deadline send `session/cancel`, answer pending permissions `cancelled`, 5 s grace, then teardown; map stop reasons / exits to `DelegationOutcome` per contracts/harness-runtime.md
- [x] T041 [US3] Branch in `delegate::run_inner` (`src/delegate.rs`): for `AgentRuntime::Acp` — refuse when `child_sandbox` reports no kernel scope; skip the tool-surface checks (tools empty); run `acp::harness::run` instead of `run_loop`; drain the child scope's audit on each update and at the end into the record; teardown as today (a scope that will not empty → `Failed`); report header `(harness, <stopReason>)` + FR-021 note
- [x] T042 [US3] Make T030–T035 pass; record S7

**Checkpoint**: harnesses run contained (no network yet).

---

## Phase 6: User Story 4 — Provider by name, credentials, and per-subagent proxy scopes (P2)

**Goal**: a harness reaches exactly its declared provider hosts — tunnelled by name through a proxy scope of its own, addresses admitted as they resolve — and exactly its declared credential stores.

**Independent Test**: quickstart S8, S9(a).

### Tests (write first, must fail)

- [x] T043 [P] [US4] Property test in `crates/core/src/attenuation.rs` (extend the derive property suite): a harness derivation routes `requires.net` names only when each is held by the parent by exact name (non-intercepting parent: `network.allow`; intercepting: `http.targets ∪ http.egress`); never yields a kernel net rule other than the proxy port
- [x] T044 [P] [US4] Unit tests in `crates/core/src/compiler.rs`: a harness policy compiles the harness protected list (`~/.claude`, `~/.claude.json`, `~/.codex`, `~/.local/share/opencode`, `~/.config/opencode`) as DENY unless named in the child **and** the parent; the global `PROTECTED_DEFAULTS` are unchanged for non-harness policies
- [x] T045 [P] [US4] Unit tests for resolve-and-admit in `src/intercept/session.rs`: a non-declared host → error, no reload; a declared host with a new address → exactly one reload, then answer; the same address again → no reload; >16 addresses → oldest evicted
- [x] T046 [P] [US4] VM cases `harness-egress-by-name` (S8, incl. the `/etc/hosts` address change) and `harness-credentials` (S9a) in `test/vm/remote-matrix.sh` + `cases.txt`
- [x] T047 [P] [US4] VM case `proxy-admit-on-resolve`: a session (not a harness) with `[policy.http]` egress `prov.test:8443` whose address changes mid-session still reaches it, and the proxy scope's reload is recorded

### Implementation — proxy scopes per sandbox (019 T092; PR2)

- [x] T048 [US4] Move the sidecar onto the supervisor in `src/supervisor.rs` / `src/sandbox.rs`: a scope record may own an optional proxy scope (`ProxyScope { scope_id, interceptor, namespace, admitted }`); delete `EnforcedSandbox.sidecar`'s one-per-session assumption; teardown order proxy-before-tool, children-first (keep `Supervisor::teardown`'s ordering tests green)
- [x] T049 [US4] Generalize `attach_sidecar` in `src/intercept/session.rs` to attach a proxy scope to any enforced `Sandbox` from a compiled `[policy.http]` (targets, egress, inspect), spawning `bee proxy-worker` into it with a per-sandbox credential namespace; the tool scope's kernel net becomes `with_proxy_loopback`
- [x] T050 [US4] Resolve-and-admit in `src/intercept/session.rs`: the `resolver` for each proxy scope refuses undeclared names, resolves, reloads the proxy scope's net with new addresses (bounded 16/host), records the reload, then answers `Resolved` (contracts/proxy-scopes.md)
- [x] T051 [US4] Recording attribution: tag `ExchangeRecord`/`TunnelRecord`/`ProxyEvent` from a subagent's worker with its scope id and delegation id in the 019 store (`src/intercept/store*` / `crates/comb` store schema); migration-free (new nullable columns)

### Implementation — harness network and credentials (PR3)

- [x] T052 [US4] Harness derivation in `crates/core/src/attenuation.rs` (or a `derive_harness` beside `derive`): check `requires.net` names against the parent per T043; produce the child policy with `network.allow` empty and an `http` section `{ targets: parent's targets if intercepting, egress: requires.net }`
- [x] T053 [US4] Harness protected list in `crates/core/src/compiler.rs` (applied when compiling a harness child), overridable only by an explicit child rule the parent also names (reuse `check_protected`)
- [x] T054 [US4] In `src/acp/harness.rs` / `src/delegate.rs`: create the harness's proxy scope (T049) before spawning; add `comb::client::child_env` proxy variables with the harness's credential; add the CA bundle variables only if the harness's `inspect` is non-empty
- [x] T055 [US4] Make T043–T047 pass; record S8, S9a

---

## Phase 7: User Story 5 — A harness's (and any subagent's) web traffic is recorded (P3)

**Goal**: intercepted sessions may delegate; each subagent's exchanges and tunnels are attributed to it.

**Independent Test**: quickstart S9(b).

- [x] T056 [P] [US5] VM case `subagent-intercept-attributed` (S9b) in `test/vm/remote-matrix.sh` + `cases.txt`: an intercepting session delegates to a bee-loop subagent that fetches `app.test`; the exchange is attributed to the subagent's scope, none to the parent; a sibling's credential is refused by the other's worker
- [x] T057 [P] [US5] Host test in `tests/delegation.rs`: `a_subagent_of_an_intercepted_session_is_not_refused` (replaces the expectation of the 018 refusal)
- [x] T058 [US5] Remove the intercepted-session refusal in `src/delegate.rs` (`run_inner`); for a bee-loop child whose derived policy has active `[policy.http]`, attach a proxy scope (T049); update `specs/019-http-intercept/tasks.md` T092 to done with a pointer to 026
- [x] T059 [US5] Make T056–T057 pass; record S9b

> **PR2 as built (2026-11-10).**
> - **Proxy scope (T048):** `src/proxy_scope.rs`. `ProxyScope` (its scope handle, compiled base, installed plan and `Admissions`) is created on the supervisor as the tool scope's userspace child, as before, and owned by the sandbox as `Arc<ProxyScope>` (`SidecarScope` is now that alias). It is not a field of the supervisor's `Record`: the supervisor already holds it as a scope record whose parent link orders teardown, and the sandbox already exists once per tool scope, so "one per session" was never in the type. The worker's resolver holds a `Weak` to it. Every rule change (admit, widening, rollback) runs under its lock, so they apply one at a time. A reload that cannot be rolled back poisons the proxy scope, and the tool sandbox it serves then refuses every child.
> - **Child proxies (T049, T058):** `intercept::session::ChildProxies` (worker binary, test host names, project root and the session's enforcement) rides in `ToolDeps`, so every child inherits it. `delegate::child_sandbox` binds the child's listener, compiles its tool scope with `with_proxy_loopback`, and attaches its proxy scope under kernel enforcement. `run_inner` starts its worker and sets the child's `ToolDeps.interceptor`. The parent's interceptor is never handed to a child: until the child's own proxy starts, its HTTP tools refuse. The worker is shut down before the child's scope is torn down. A cancelled delegation's `HttpSession` stops its worker on drop.
> - **Resolve-and-admit (T050):** comb's `InterceptorConfig.admit` (trait `Admit`) is called after resolution and before the reply. `ToWorker::Resolved` gained `admitted`, and the worker connects to an admitted address without checking it against the compile-time set (`resolve_checked`). Advisory sessions have no hook and keep the drift refusal. Each admit that adds addresses is recorded in the store's `admits` table.
> - **Attribution (T051):** a new `attribution` table, not new columns. Every child proxy has its own store session id, which every exchange, tunnel and refusal row already carries. The table maps that id to the child's `scope_id`, `delegation_id` (the parent's `task` call id, now on `ParentView` and `PendingDelegation`), `parent_session` and agent, indexed by scope and delegation. Both tables are `CREATE TABLE IF NOT EXISTS`, so no migration is needed.
> - **Tests:** T045 is covered by unit tests in `src/proxy_scope.rs` and by the end-to-end host test `tests/intercept_proxy.rs::a_moved_address_is_admitted_once_then_reached`. The reload there is counted, not made. T057 is `tests/intercept_delegation.rs`, which needs the intercept harness that `tests/delegation.rs` does not build with.
> - **VM:** `proxy-admit-on-resolve` and `subagent-intercept-attributed` both pass. Negative control: a build with no admit hook and no child attribution fails both.

> **PR3 as built (2026-11-10).**
> - **Fake harness (T003):** a hidden `bee acp-fake-harness` subcommand (`src/acp/fake_harness.rs`, built with `test-support` or `vm-test`) rather than a separate test binary, so the VM matrix can run it from the one release build. Its script is the JSON in `FAKE_HARNESS_SCRIPT`.
> - **Counts (T008):** `tokens_used` / `turns_used` are `Option`. A loop child always has `Some`; a harness has `None` ("not counted"). Records written before 026 read and write back byte-for-byte (`tests/transcript_compat.rs`).
> - **Runtime (T036–T041):** a harness needs a bee built with `acp`, `intercept` and `enforce`; any other build refuses it as `Unavailable`. Kernel network rules that are empty mean unrestricted egress, so a harness always gets its own proxy. One with no provider hosts, under a parent that does not intercept, is refused. Its audit is drained once, at the end, not on every update: the supervisor buffers it until then. The proxy events from its side call are not stored on the record, because the store already keeps the refusals.
> - **Derivation (T052, T053):** `Policy::derive_harness`. The harness protected list is applied at the policy level (deny entries in the child's filesystem), not in the compiler, and `PROTECTED_DEFAULTS` is unchanged. Unmatched reads are allowed, so each denied store is a kernel rule, and the eBPF backend holds 8. Only the stores present on the machine are denied. A store created after the scope is built is therefore not covered.
> - **Tests:** T031–T034 call `acp::harness::run` directly on a host sandbox. T033 goes through `run_loop`. T043/T044 are in `crates/core/tests/harness_attenuation.rs`.

**Checkpoint (PR2 = T048–T051 + Phase 7; PR3 = Phase 5 + T052–T055)**

---

## Phase 8: Polish & cross-cutting (PR4)

- [ ] T060 Real harness on `bee-build` (S10, SC-004): install the `claude-agent-acp` Linux binary; agent per contracts/harness-runtime.md; `[acp] harness_env_passthrough = ["ANTHROPIC_API_KEY"]`; record the transcript highlights and every tunnel host in `specs/026-acp/quickstart.md`
- [ ] T061 [P] Codex and OpenCode adapters on `bee-build`: does each honour `HTTPS_PROXY` and run inside a bee scope (Codex's own sandbox nested)? Record findings and any required agent `env` in `specs/026-acp/research.md` (open risk)
- [ ] T062 [P] Benchmark harness spawn (derive → scopes → spawn → `initialize`) in `benches/`; ≤ 500 ms p95 excluding harness start-up
- [ ] T063 [P] Docs: `docs/acp.md` (t3code setup, `[acp]`, writing a harness agent, what bee does and does not confine — FR-021); glossary entries **ACP session**, **Harness**, **Proxy scope** in `CONTEXT.md`
- [ ] T064 [P] SC-006 timing check: VM case `acp-cancel` and `harness-contained` assert no process survives within 5 s (tighten if T014/T035 used looser bounds)
- [ ] T065 Run quickstart S1 manually in t3code (SC-001) and record it; run `/code-review` per PR

---

## Dependencies & Execution Order

- **Phase 1 → Phase 2** → stories.
- **US1 (Phase 3)** → **US2 (Phase 4)**: US2's consent task needs US1's connection and session table.
- **US3 (Phase 5)** depends on Phase 2 only (T004 cwd, T008 Option counts); independent of US1/US2.
- **US4 (Phase 6)**: T048–T051 (proxy scopes) depend on Phase 2 only; T052–T054 depend on US3 (T038–T041) and T048–T049.
- **US5 (Phase 7)** depends on T048–T051.
- **Polish** after US4 (T060 needs the network path).

```text
Setup → Foundational ─┬─ US1 → US2                  (PR1)
                      ├─ T048–T051 → US5             (PR2)
                      └─ US3 → T052–T055 (US4)       (PR3, needs PR2's T048–T049)
                                         └→ Polish   (PR4)
```

## Parallel Opportunities

- Phase 2: T005 and T007 alongside T004/T006.
- PR1 and PR2 in parallel worktrees (`~/git/bee-acp` and a second worktree for T048–T051).
- Within each story, all test tasks marked [P] together (different files or test functions).
- US3's T030–T035 together; then T036 ∥ T037; T038–T041 sequential (one file + delegate.rs).

## Implementation Strategy

1. **MVP = PR1 (US1 + US2)**: bee usable from t3code with consent. Validate S1–S6, ship.
2. **PR2 (T092)**: per-subagent proxy scopes + resolve-and-admit — useful alone (intercepted
   sessions can delegate; CDN-backed egress hosts stop breaking).
3. **PR3 (US3 + US4)**: harnesses, first with the fake harness (S7–S9), then a real one in PR4.
4. Each PR: VM matrix green with negative controls; `baseline.md`-style record in the PR body.
