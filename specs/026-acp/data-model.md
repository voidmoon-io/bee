# Data Model: 026 ACP

Types are sketched at the level a reviewer needs; names are provisional.

## AcpSession (`src/acp/agent.rs`) — one per client `session/new`

| Field | Meaning |
|---|---|
| `id: SessionId` | The ACP session id bee issues (`acp-<uuid>`). Scope id and run id derive from it (research R3). |
| `cwd: PathBuf` | The client's working directory, validated (absolute, exists, directory, readable under the resolved policy). |
| `session: bee::session::Session` | Built by `session::build` with `EntryPoint::Acp`, on the process supervisor. |
| `conversation: Conversation` | The multi-prompt conversation. |
| `consent: ConsentReceiver` | Serviced by a per-session task → `session/request_permission`. |
| `running: Option<Exchange>` | The in-flight prompt: its abort handle and its `Responder`. At most one (a second `session/prompt` while one runs is refused with an error). |
| `dropped_mcp: Vec<(String, String)>` | Client MCP servers not started, with the reason; announced once. |

**States**: `Building` (start-up consent may be asked) → `Idle` ⇄ `Prompting` → `Closed`.
`session/cancel` in `Prompting` → abort → `Idle` (prompt answered `cancelled`). Client disconnect from
any state → every session `Closed` via `Session::shutdown` (its one teardown order).

**Validation**: `cwd` failures, config resolution failures (`EffectiveConfig` missing fields), a
policy refused by the ceiling, an enforcement mode the build cannot provide, or `max_sessions`
reached → `session/new` returns a JSON-RPC error naming the cause; nothing is created.

## `[acp]` configuration (operator-only)

| Key | Default | Meaning |
|---|---|---|
| `client_mcp` | `false` | Start a client's **stdio** MCP servers (under the operator's `McpPolicy`). HTTP/SSE client servers are always refused. |
| `max_sessions` | `8` (hard cap 32) | Sessions one `bee acp` process serves at once. |
| `harness_env_passthrough` | `[]` | Credential-bearing environment keys (e.g. `ANTHROPIC_API_KEY`) a harness agent may receive; the value always comes from bee's own environment, never from an agent file. |

A project `.bee/config.toml` containing `[acp]` is rejected, as `[mcp]` is.

## Sandbox child environment (`src/sandbox.rs`)

`ChildEnv` gains `cwd: Option<PathBuf>`, applied as `current_dir` on every command the sandbox
builds (tool calls, MCP servers, harnesses). `None` keeps today's behaviour (inherit bee's cwd).
A delegation's child sandbox inherits its parent's.

## Agent runtime (`src/skills.rs`)

```text
Agent {
  name, description, tools, turn_limit, requires, dir, skill_md, source,   # 018, unchanged
  runtime: AgentRuntime,                                                     # NEW
}
AgentRuntime =
  | Loop                                  # default: bee's own loop (018)
  | Acp { command: PathBuf, args: Vec<String>, env: BTreeMap<String,String> }
```

**Validation** (at discovery, warnings like 018's):
- `command` absolute, no shell expansion; `env` keys must not be a credential-bearing key bee strips
  (`DEFAULT_KEY_VARS`, `strip_env`) unless the operator's config allows passing that key to this
  agent (see contracts/harness-runtime.md, "Credentials").
- `tools` must be empty or omitted for an ACP agent (its tools are its own); `turn-limit` ignored.
- `requires` keeps its meaning; for an ACP agent, `requires.net` entries are the provider destinations
  (routed to its proxy scope, research R8).

## HarnessRecord (`src/transcript.rs`) — on `DelegationRecord.harness`

| Field | Meaning |
|---|---|
| `command`, `args` | What ran (env values not recorded; keys are). |
| `protocol_version` | Negotiated ACP version. |
| `agent_info` | The harness's `agentInfo` (name, version). |
| `turns: Vec<HarnessTurn>` | One per `session/prompt` bee sent (one in this feature). |
| `permissions: Vec<PermissionRecord>` | Each request: tool-call title/kind, options offered, option chosen, time. |
| `refused_methods: Vec<String>` | `fs/*` / `terminal/*` calls the harness made anyway. |
| `stop_reason` | The prompt's `stopReason`, or why there was none (exit, protocol error, deadline). |
| `stderr_tail` | Last 4 KiB of the harness's stderr, for failures. |

`HarnessTurn { text: String /* agent_message_chunk, concatenated */, thoughts_len: usize,
tool_calls: Vec<HarnessToolCall> }`; `HarnessToolCall { id, title, kind, status, raw_input, raw_output }`
— raw values capped with `transcript::truncate`.

`DelegationRecord` changes: `harness: Option<Box<HarnessRecord>>` (new; `transcript` is `None` for a
harness); `turns_used` and `tokens_used` become `Option<_>` — `None` means "not counted", never zero
(spec FR-016). Serialized with `skip_serializing_if = "Option::is_none"`; old records still read.

## Proxy scope (`src/supervisor.rs`, `src/sandbox.rs`, `src/intercept/session.rs`)

```text
ScopeRecord { id, label, parent, plan, ..., proxy: Option<ProxyScope> }   # was EnforcedSandbox.sidecar
ProxyScope  { scope_id, worker (Interceptor), credential namespace, admitted: Map<host, Set<IpAddr>> }
```

- Created for: a session whose policy has active `[policy.http]` (as today); a subagent whose derived
  policy has active `[policy.http]` (bee-loop, T092); every harness subagent (its `requires.net` as
  egress, plus the parent's targets when the parent intercepts).
- Torn down before its tool scope (unchanged order), children-first across the tree.
- `admitted` grows by resolve-and-admit (research R9): per host, at most 16 addresses; beyond that
  the oldest is evicted at the next reload. Each admit is a scope reload, recorded.

## Records produced

| Event | Where |
|---|---|
| Client permission decision | session consent log (`ConsentRecord`, 024), as for the REPL |
| Harness permission auto-answer | `HarnessRecord.permissions` |
| Kernel event in a harness / proxy scope | that scope's audit, attached to the delegation record (018 router) |
| Tunnel to a provider | 019 store `TunnelRecord`, attributed to the subagent's proxy scope |
| In-scope exchange by a subagent | 019 store `ExchangeRecord`, attributed to the subagent |
| Resolve-and-admit | proxy-scope reload event in the delegation record |
