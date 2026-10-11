# Data Model: One Session Core

**Feature**: [spec.md](./spec.md) · **Research**: [research.md](./research.md)

These are in-process library types, not persisted schemas. The two exceptions are `ConsentRecord`
and `CallOutcome`'s recorded form, which reach the transcript and so are serialized. Field types are
indicative; names are binding for the contracts.

---

## Operator

| Field | Type | Notes |
|---|---|---|
| `kind` | `OperatorKind` = `Interactive \| Autonomous` | Recorded on every `ConsentRecord`. |
| `consent` | `Arc<dyn Consent>` | Interactive: `ChannelConsent`. Autonomous: `AllowWithinCeiling`. |
| `output` | `Arc<dyn SessionOutput>` | Interactive: `TerminalOutput` / `SessionSink`. Autonomous: `ProgressOutput`. |
| `timeout` | `Duration` | Applied by `Operator::consent`, not by the adapter. Default 120 s Interactive, 60 s Autonomous. |
| `log` | `ConsentLog` (`Arc<Mutex<Vec<ConsentRecord>>>`) | Drained into the session record. |

**Invariants**: a session has exactly one Operator (FR-001). Nothing outside `Operator` calls a
`Consent` adapter or writes to stdout/stderr for session output.

## ConsentRequest (owned, crosses a channel)

| Field | Type |
|---|---|
| `origin` | `GrantOrigin` — `Startup{skill}` (new variant) \| `KernelDenial{op,target}` \| `SkillRequires{skill}` \| `ProxyRefusal{host,port,call}` \| `Explicit` |
| `tools` | `Vec<String>` |
| `filesystem` | `BTreeMap<String, Access>` |
| `exec` | `Vec<String>` |
| `net` | `Vec<String>` |
| `http_targets` | `Vec<String>` |
| `turn` | `u32` (model turn; 0 at start-up) |

**Validation**: a request with every capability list empty is never constructed (escalate refuses it
earlier). Startup requests carry all kinds. Today's start-up path hard-codes `net`/`exec`/`http_targets`
empty (`src/skills/grant.rs:213-220`); that is fixed here.

## ConsentRecord (serialized into the session record)

| Field | Type | Notes |
|---|---|---|
| `request` | `ConsentRequest` | |
| `decision` | `Granted \| Refused` | |
| `reason` | `Granted \| DeniedByOperator \| TimedOut \| BeyondCeiling` | A fully already-held request is not a decision and is never recorded. |
| `operator` | `OperatorKind` | |
| `lease` | `Option<GrantId>` | Set when granted. |
| `ts` | RFC 3339 string | |

**State**: a request is either recorded without being offered (`BeyondCeiling`), or
offered and then recorded as `Granted`, `DeniedByOperator` or `TimedOut`. A request is never left
unrecorded.

## SessionSpec

| Field | Type | Notes |
|---|---|---|
| `entry` | `EntryPoint` = `Headless \| Repl \| Tui \| Batch{concurrent: bool}` | Selects refusals and labels only, never behaviour. |
| `provider` | provider config | |
| `policy` | `Option<Policy>` | `None` means host (where allowed). |
| `ceiling` | `Option<Policy>` | Defaults to `policy`. |
| `enforcement` | `Enforcement` = `Kernel \| Host` | Resolved once (`resolve_enforcement`). |
| `tools` | `Vec<String>` | Requested tool names. |
| `ctf_flag` | `Option<String>` | |
| `skills` | `SkillRoots` | The same discovery for every entry point. |
| `mcp` | `McpConfig` | |
| `security` | `SecurityConfig` | Findings dir, scanner settings. |
| `workdir` | `PathBuf` | |
| `system_prompt` | `Option<String>` | The base prompt; the builder appends tool notes. |
| `timeouts` | `{ tool: Duration, episode: Option<Duration> }` | |
| `strip_env` | `Vec<String>` | |

## Session

| Field | Type | Notes |
|---|---|---|
| `sandbox` | `Sandbox` | |
| `registry` | `ToolRegistry` | Holds `Arc<ToolDeps>`. |
| `active` | `Option<ActivePolicy>` | `None` when escalation is off. |
| `escalation` | `Option<LoopEscalation>` | Hooks, timeout, default TTL. Consent now comes from the Operator. |
| `operator` | `Operator` | |
| `http` | `Option<HttpPart>` (cfg `intercept`) | Interceptor, prepared scope, advisory. |
| `mcp` | `Option<McpPart>` (cfg `mcp`) | Bridge, plus the `McpRefreshHook` registered in hooks. |
| `system_prompt` | `String` | `effective_system_prompt` output. |
| `turn` | `u32` | The model-turn counter. Monotonic for the session, across REPL exchanges. |

**Lifecycle**: `Session::build` produces `Built` → loops call `turn_start` and `run_call` → `Session::shutdown`
produces `Closed`. On error, the `Drop` guard runs the same teardown order:
MCP → Interceptor → proxy scope → tool scope.

## ToolDeps (held by ToolRegistry)

| Field | cfg | Notes |
|---|---|---|
| `ctf_flag: Option<String>` | — | `submit_flag` registers only when `Some`. |
| `ledger: Option<Ledger>`, `run_id: String` | `findings` | |
| `scanner_grants: ScannerGrants` | `scanners` | Recomputed from the active policy before a granted tool registers. |
| `interceptor: Option<Interceptor>` | `intercept` | Set before the first registration. |
| `skills: Arc<SkillRegistry>` | — | |

**Invariant**: `registry.register(name)` is the only constructor of a non-MCP tool (FR-013).

## CallInput / CallOutcome

`CallInput { call: &ToolCall, turn: u32, origin: CallOrigin, timeout: TimeoutPolicy }`

`TimeoutPolicy = Deadline(Instant) | PerCall(Duration)` — `PerCall(t)` becomes `Deadline(start + t)`;
the first attempt and any retry share it.

| `CallOutcome` field | Type | Notes |
|---|---|---|
| `result` | `ToolResult` | Always from the same attempt as `audit` (FR-025). |
| `audit` | `Vec<AuditEvent>` | Tool scope, including late events (FR-023). |
| `denied_attempt_audit` | `Vec<AuditEvent>` | The attempt that triggered a retry (FR-021). Empty if no retry. |
| `proxy_audit` | `Vec<AuditEvent>` | Proxy-scope kernel events, `scope_id = "proxy"`. |
| `proxy_events` | `Vec<ProxyEvent>` | |
| `retried` | `bool` | At most one retry per call (FR-019). |
| `timed_out` | `bool` | |
| `refused_by_hook` | `Option<String>` | A `BeforeToolCall → Deny`; the tool never ran. |
| `escalations` | `Vec<EscalationRecord { trigger: Trigger, outcome: EscalateOutcome }>` | `Trigger = Proactive \| KernelDenial{op,target} \| ProxyRefusal{host,port}` |

Derived:

- `tool_denials()` counts denials in `audit` and `denied_attempt_audit`, never in `proxy_audit` (FR-022).
- `to_recorded() -> RecordedCall` gives the transcript form. `RecordedCall` gains
  `denied_attempt_audit`, `proxy_audit`, `escalations`, `timed_out`, `retried`, all with
  `serde(default, skip_serializing_if = empty/false)`.

## Hook types

`StepEvent = TurnStart{turn} | BeforeToolCall{call} | KernelDenial{op,target,call} | ProxyRefusal{host,port,call}`

`Flow = Continue | Deny(String) | Escalate(GrantDelta) | Deescalate(GrantId) | RefreshTools`

**Combination**: every observing hook is consulted; then `Deny > Escalate (deltas merged) > Continue`.
`Deescalate` and `RefreshTools` accumulate alongside whichever wins.

## GrantLease (existing, `src/grants/mod.rs`)

The fields are unchanged. `granted_at_turn` and `Ttl::Turns(n)` now count model turns in both loops.
Expiry is evaluated at `TurnStart`.

## TeardownLog (cfg `test-support` only)

`Arc<Mutex<Vec<&'static str>>>`. `Session::shutdown` (and the `Drop` guard) append `"mcp"`,
`"interceptor"`, `"scopes"` in the order they run.

## ScriptedAudit (cfg `test-support` only)

`{ tool: Mutex<VecDeque<Vec<AuditEvent>>>, proxy: Mutex<VecDeque<Vec<AuditEvent>>> }`. Each drain pops
one batch, or returns empty when the queue is exhausted.

## Interceptor operation types (`src/intercept/ops/`)

- `StructuredRequest { method, url, headers: Vec<(String,String)>, body: Vec<u8> }`
- `SendSpec { target: RawTarget, bytes, follow_redirects: u32, timeout, tags, baseline: Option<String> }`
- `SendResult { last: Sent, hops: Vec<Hop{id,status,location,stopped}>, refused: Option<(ProxyEventKind, RawTarget)>, preview: Preview, diff: Option<Value> }`
- `ReplaySpec { id, edits: Vec<Edit>, noise_probe: bool, timeout }`
- `ReplayResult { id, parent, probe: Option<String>, diff: Value }`
- `FuzzSpec { target, template_text, marker, mode, sets: Vec<Vec<String>>, rps, concurrency, timeout }`
- `FuzzResult { run_id, summary: Value, planned, counts, effective_rps, effective_concurrency }`
- `SitemapQuery { host, path_prefix, depth }`
- `OpError = Unavailable(String) | Invalid(String) | Refused(reason) | Failed(String)`
