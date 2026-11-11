# Research: 026 ACP

Facts checked 2026-11-09 against main at `75ced14` (018 US7 merged), the `agent-client-protocol`
crate 5.1.0 source, `@agentclientprotocol/claude-agent-acp` 0.102.0, `@agentclientprotocol/codex-acp`
2.6.0, `opencode-ai` 1.19.5 (dev branch), and t3code main `3e4d4493`.

## R1 — The ACP library

**Decision**: depend on `agent-client-protocol = "5.1"` with **no features**: bee supplies its own
byte streams on both sides (tokio stdin/stdout for `bee acp`, the harness's pipes for a harness — see
R2), so neither `stdio` nor `process` is needed. Target ACP **v1** only; no `unstable_*` features.

**Rationale**:
- The crate is runtime-neutral (`futures`, `futures-concurrency`); bee's tokio runtime drives the
  connection future. Bridging tokio pipes needs `tokio-util`'s `compat` (`TokioAsyncReadCompatExt`).
- MSRV 1.88; bee's package floor is 1.96 (`Cargo.toml:83`). No conflict.
- Apache-2.0.
- API shape (5.x): builders, not traits — `Agent.v1().on_receive_request(..).connect_to(transport)`
  and `Client.v1()...connect_with(transport, |cx| ..)`. Client methods are called from the agent with
  `cx.send_request(req)` and session updates sent with `cx.send_notification(..)`.
- **Ordering trap** (crate `src/concepts/ordering.rs`): handlers run on one dispatch loop, so a
  handler that awaits a request it sent (`block_task`) deadlocks. A `session/prompt` handler must
  start the exchange with `cx.spawn(..)` and answer through its `Responder` later; that is also what
  lets `session/cancel` arrive mid-turn.
- t3code negotiates v1 with agents that do not offer v2 (`docs/user/providers-acp.md`).

**Alternatives**: hand-rolled JSON-RPC (the `comb-cli serve.rs` newline-JSON pattern). Rejected: ACP
has many typed messages and versioned capability negotiation; the schema crate is the reference
implementation. v2 preview: unstable API, may change in minor releases.

## R2 — Spawning a harness into a child scope

**Decision**: bee spawns the harness itself through the delegation's child `Sandbox`
(`tool_command_as`, the same path a stdio MCP server takes — `src/mcp/transport.rs:33-70`), converts
it to `tokio::process::Command` with piped stdin/stdout, `kill_on_drop(true)`, and hands the pipes to
the crate as a `ByteStreams` transport. The crate's `AcpAgent` (`process` feature) is **not** used.

**Rationale**: `AcpAgentConfig` has only `command`, `args`, `env`: no cwd, no `pre_exec`, and it
*inherits* bee's environment, overlaying rather than clearing it. bee's spawn joins the scope's
cgroup in `pre_exec` before exec, refuses setuid binaries, disables core dumps, sets non-dumpable,
clears the environment to an allowlist and strips `strip_env` keys (`sandbox.rs:246-256, 824-862`;
`crates/userspace/src/spawn.rs:66-106`). Every descendant the harness forks inherits the cgroup.
Teardown is `cgroup.kill` + wait for `populated 0` + `rmdir` (`crates/userspace/src/cgroup.rs:51-67`),
which reaps the whole tree regardless of process groups.

**Alternatives**: a wrapper launcher that moves itself into the cgroup and execs the harness. Rejected:
it duplicates the hardened spawn, and the join would happen after bee loses control of the child.

## R3 — Several ACP sessions in one process

**Decision**: `bee acp` starts **one** `Supervisor` and creates each ACP session's tool scope on it
(the concurrent batch pattern, `src/concurrent.rs:112`, passed in as `SessionSpec.prebuilt_sandbox`).
Scope ids and run ids derive from the ACP session id, not the pid.

**Rationale**: `Supervisor::start()` loads and attaches its own eBPF object (`loader.rs:18-35`); the
engine is documented as process-wide and has never been exercised twice in a process. REPL scope ids
are `bee-session-{pid}` (`session/mod.rs:300-305`), which would collide on a second session.

## R4 — Each session's working directory

**Decision**: add a per-session working directory to the sandbox's child environment (`ChildEnv`),
applied as `Command::current_dir` for every tool child, MCP server and harness. `bee acp` resolves
configuration with `config::resolve(cwd, flags)` per session, exactly as `bee repl` does for
`current_dir()`.

**Rationale**: today tool children start with `cwd: None` and inherit bee's own cwd
(`tools/exec.rs:160`); every front-end so far ran one session per process, launched in the project.
An ACP client sends a different `cwd` per session.

**Validation** (spec Edge Cases): the cwd must be absolute (ACP requires it), exist, be a directory,
and be readable under the session's resolved policy; otherwise `session/new` fails with the reason
before any scope exists.

## R5 — Consent over ACP

**Decision**: the session's operator is `Operator::interactive(ChannelConsent, sink)`. An ACP
front-end task services the `ConsentReceiver` for each session — during `build()` (start-up grants)
and during every exchange — and turns each `ConsentAsk` into `session/request_permission` with two
options: `allow_once` and `reject_once`. `selected(allow)` → `Granted`; anything else (`reject`,
`cancelled`, an error, a dropped connection) → `Denied`. The operator's timeout (120 s) applies as in
the REPL.

The request's `toolCall` field carries the call that triggered it when there is one (reactive denial,
skill), else a synthetic `tool_call` titled from `ConsentRequest::render_lines()[0]`; the full rendered
lines go in its content, so every capability is visible (operator.rs invariant: no field approved
unseen).

**Rationale**: the seam already exists (`src/operator.rs:315-351`); the REPL and TUI front-ends do the
same with a line prompt and a modal (`repl/consent_input.rs`, `tui/mod.rs:330-333`).

**Alternatives**: offer `allow_always`. Rejected for v1: bee's leases have their own TTLs; "always" in
a client's vocabulary would need mapping to `Ttl::Forever` and a way to show it. Recorded as a
follow-up.

## R6 — Cancellation

**Decision**: `session/cancel` drops the running exchange future (the TUI's `/cancel`,
`tui/mod.rs:347, 391-401`), truncates the conversation to before the prompt, refuses any pending
consent ask, and answers the prompt with `stopReason: "cancelled"`. A client disconnect cancels every
session and shuts each down in its teardown order.

**Rationale**: dropping the future already kills running tool processes: `ChildOwner::drop`
SIGKILLs the process group, writes `cgroup.kill` on the per-call cgroup and waits
(`tools/exec.rs:27-79`). A delegation in flight drops its child `Sandbox`, whose `ScopeHandle::drop`
tears the child scope down (`supervisor.rs:332-337`).

ACP sessions are non-durable in this feature (durable sessions refuse `task` today, `episode.rs:243`).

## R7 — Client-supplied MCP servers

**Decision**: refused by default. A new operator-only config key `[acp] client_mcp = true` (rejected
in a project layer like `[mcp]`, `app/config/file.rs:186-190`) admits a client's **stdio** servers,
converted to `McpServerConfig` and subject to the operator's `McpPolicy` (server cap, tool allow/deny,
domain gates). They run in the session's tool scope like any configured server
(`mcp/transport.rs:35`). HTTP/SSE client servers stay refused (they would be reached from bee itself,
outside the scope). Dropped servers are named in an `agent_message_chunk` notice at session start.

**Rationale**: t3code passes its own MCP servers to agents (orchestration tools). A project file may
not add MCP servers to bee; a client is no more trusted than a project.

## R8 — A harness reaches its model provider: tunnelled by name

**Decision**: a harness scope's **kernel** network is the loopback proxy port only
(`with_proxy_loopback`, `compiler.rs:385`). Its model-provider hosts are the `egress` of a **proxy
scope of its own** (R9): the proxy tunnels them without decryption after checking the CONNECT host
equals the TLS server name (`crates/comb/src/worker/connect.rs:86, 130-160`). bee sets `HTTPS_PROXY`
and friends with a per-delegation credential (`comb::client::child_env`). The harness needs no bee CA
for its provider, and the record holds a `TunnelRecord` (host, port, timing, size) — never content
(spec Clarification 1).

**Which hosts**: the agent's ordinary `requires.net` entries. `derive`'s `check_network` matches
them against the parent's allowlist as exact strings (`attenuation.rs:385-395`), so a parent rule
`api.anthropic.com:443` is name authority. For a harness, bee compiles those entries as its proxy
scope's `egress` instead of kernel address rules. Under an intercepting parent (which has no
`network.allow`, `HttpWithDirectNetwork`), the check is against the parent's `[policy.http]` targets
and egress — a harness-specific branch of the derivation, property-tested with the rest.

**Rationale**: kernel rules match addresses, never names (`crates/ebpf/src/main.rs:160-212`); the
only name check in bee is the proxy's. Claude Code reads `HTTPS_PROXY` natively and needs only
`api.anthropic.com` for inference (`platform.claude.com` for OAuth refresh); setting
`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` drops telemetry hosts. OpenCode runs on Bun, which honours
`HTTPS_PROXY`. Codex's proxy support is not documented officially — **risk, verify in the VM**.

**Alternatives**: address rules for provider hosts (breaks on CDN rotation; or must be wide);
kernel-side SNI matching (eBPF cannot see TLS reliably). Both rejected.

## R9 — Per-subagent proxy scopes (019 T092) and keeping kernel rules honest as addresses move

**Decision**:
1. Move the sidecar scope onto the `Supervisor` as an ordinary scope record and allow **one proxy
   scope per sandbox that needs one**: the session's tool scope, and each subagent scope whose
   derived policy has an active `[policy.http]` or that is a harness. This deletes
   `EnforcedSandbox.sidecar`'s one-per-session limit and the delegation refusal
   (`delegate.rs:322-330`). Each subagent's worker records under its own credential namespace;
   exchanges and tunnels are attributed to that subagent.
2. **Resolve-and-admit**: the worker already asks bee to resolve names (`FromWorker::Resolve`,
   `crates/comb/src/sidecar.rs:914`), because DNS is not in the proxy scope's kernel rules. bee's
   resolver for a proxy scope resolves the declared host, and when the answer contains addresses its
   kernel rules do not hold, **reloads that proxy scope's network rules** to admit them (bounded per
   host) before answering. The worker then connects only to addresses bee resolved for a declared
   name, and the kernel holds exactly those.

**Rationale**: compile-time pinning (`compiler.rs:139-145`, `resolve.rs:67-83`) is what breaks CDN
hosts. Admitting at resolution time keeps the kernel authoritative over every upstream address (no
"any address on 443" rule for the worker) and keeps name checking in one place.

**Alternatives**: a port-wide kernel rule for the proxy scope, trusting the worker's name check
(weakens Principle III for the worker); periodic re-resolution (races, and admits addresses never
used). Rejected.

## R10 — Harness credentials

**Decision**: when compiling a **harness** child's policy, add a second protected list — the known
harness credential stores: `~/.claude`, `~/.claude.json`, `~/.codex`, `~/.local/share/opencode`,
`~/.config/opencode` — as DENY, overridable only by an explicit rule in the agent's `requires` that
its parent also names (`check_protected`, `attenuation.rs:331-360`). The global `PROTECTED_DEFAULTS`
(`compiler.rs:451-456`) are unchanged, so existing sessions behave as before.

**Rationale**: today only `~/.ssh` and `~/.aws` are denied; reads are allowed by default, so one
harness could read another's sign-in. Claude Code writes `~/.claude.json` and several directories
under `~/.claude/` and refreshes OAuth tokens in `~/.claude/.credentials.json`, so its agent needs
write on its own store. Answering permission requests `allow_once` (R11) means Claude never writes
"always allow" rules to `.claude/settings.local.json` in the project.

**Alternatives**: extend the global defaults. Rejected for now: a one-way change to every session's
policy, and bee's own skill roots live under `~/.claude/skills`.

## R11 — The harness's permission requests

**Decision**: answer each with the first option of kind `allow_once`; if none, the first
`allow_always`; if no allow option exists, `cancelled`. Record request + option chosen in the
delegation record. Mid-cancel (deadline), answer pending requests `cancelled` as the protocol
requires.

**Rationale**: Claude's adapter offers `allow-once`, `allow-with-updates` (`allow_always`, persists a
rule) and `reject` (`permissions/options/*.js`); Codex and OpenCode offer `allow_once`/`allow_always`.
Choosing once keeps every request a separate recorded decision and avoids persisting rules.

## R12 — What bee advertises to a harness, and what it refuses

**Decision**: `clientCapabilities` with `fs.readTextFile=false`, `fs.writeTextFile=false`,
`terminal=false`. Any `fs/*` or `terminal/*` request is answered with a method error and recorded.
`session/new` sends `cwd` = the session's working directory and `mcpServers = []`.

**Rationale**: none of the three adapters calls client fs/terminal methods (Claude's built-in tools
do their own I/O; terminal output arrives in `_meta`), so nothing is lost.

## R13 — The harness's record and report

**Decision**: a `DelegationRecord` gains `harness: Option<HarnessRecord>` (data-model.md), holding
the harness command, protocol version, `agent_message_chunk` text by turn, tool-call updates
(`toolCallId`, title, kind, status, raw input/output, capped), permission requests and answers, the
stop reason and any protocol errors. `transcript` stays `None` for a harness. The report is the text
of the harness's final turn, capped by `transcript::truncate` like any result. Kernel audit of the
child scope is drained by the supervisor router when each update is handled and at teardown, and
attached to the record.

## R14 — Bounds on a harness

**Decision**: the shared deadline (018 FR-023) applies. At the deadline bee sends `session/cancel`,
waits a 5 s grace for the prompt to resolve, then tears the scope down (`cgroup.kill`). Outcome:
`CutShort { Deadline }`. A harness's model turns and tokens are not visible in ACP v1, so
`turns_used`/`tokens_used` become "not counted" (`Option`), never zero; the shared turn budget is
charged one turn for the delegation (it consumes the delegating call's turn only).

## R15 — Harness binaries

**Decision**: the agent's `command` must be an absolute path to an installed executable; bee does
not run `npx`/`uvx` (they would need the npm/PyPI registry in the scope and download code at
delegation time). Claude's adapter ships standalone Linux binaries; Codex's and OpenCode's are
installed packages.

## R16 — Exec rules for a harness

**Decision**: no special handling. An agent that omits `requires.exec` inherits its parent's list
(018 semantics). The delegation record and docs state that a harness allowed a shell can start
anything that shell can (spec FR-021).

**Rationale**: `bprm_check_security` checks every exec by resolved path (`main.rs:269-321`); a
harness execs node, its native binary, bash, coreutils, git… An empty list installs no rule (exec
unenforced), and `exec: []` is refused for agents (`skills.rs:485-497`).

## Open risks

- **Codex behind `HTTPS_PROXY`** and its own Landlock/bubblewrap sandbox nested in a bee scope:
  unverified. VM-test before claiming SC-004 for Codex; Claude is the SC-004 target.
- **Engine multi-scope load**: many ACP sessions × subagents × proxy scopes on one supervisor. The
  concurrent batch has exercised many scopes; per-proxy-scope reloads (R9) add reload traffic.
