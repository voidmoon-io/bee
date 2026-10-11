# Contract: Session builder (`src/session/`)

FR-006–FR-012, FR-028–FR-030. Types in [data-model.md](../data-model.md#sessionspec).

```rust
pub async fn build(spec: SessionSpec, operator: Operator) -> Result<Session, BuildError>;

impl Session {
    pub fn snapshot(&self) -> SessionSnapshot;                     // serializable, Operator excluded
    pub async fn turn_start(&mut self, turn: u32) -> TurnStartReport; // leases, deescalation, MCP refresh
    pub async fn call(&mut self, call: &ToolCall, timeout: TimeoutPolicy) -> CallOutcome; // → run_call
    pub fn system_prompt(&self) -> &str;
    pub fn tool_schemas(&self) -> Vec<ToolSchema>;
    pub async fn shutdown(self) -> Result<(), TeardownError>;
}
```

## Build pipeline (one order, every entry point)

1. Refuse unsupported combinations for `spec.entry` (table below) — before any scope exists.
2. Resolve enforcement (`Kernel`/`Host`); refuse `Kernel` on an unsupported kernel.
3. Strip-env list (provider keys + MCP token env names).
4. Materialize workdir.
5. Discover skills (`spec.skills`, same rule for every entry).
6. Resolve start-up grants through the Operator (all capability kinds); fold skill dirs (Read) into
   policy **and** ceiling; widen scanner report dir when `scan` is granted.
7. `http_advisory(&spec)` — once; reported through `operator.output()`.
8. Build sandbox (scope id prefix from `entry`); attach proxy scope when `[policy.http]`.
9. Start Interceptor (cfg `intercept`).
10. Build `ToolDeps`; register requested + granted tools via `registry.register`.
11. Connect MCP; register `mcp__*`; add `McpRefreshHook`.
12. Escalation: ceiling, hooks (Denial, ProxyRefusal, Skill, McpRefresh, embedder hooks), TTL.
13. `effective_system_prompt`.

## Refusals (FR-008)

| Entry | `[policy.http]` | MCP servers | widening escalation | Message names |
|---|---|---|---|---|
| `Batch{concurrent:true}` | refused | refused | refused | the feature + "not supported in concurrent batches (see 018)" |
| `Kernel` enforcement on a build without `enforce` | — | — | — | refused: "kernel enforcement not compiled in" |
| `[policy.http]` on a build without `intercept` | refused | | | "interception not compiled in" |

## Teardown order (FR-012)

`shutdown`: MCP servers → Interceptor → `Sandbox::teardown` (proxy scope, then tool scope). Same order
from a `Drop` guard on error paths. A teardown failure is returned, never swallowed. Under
`test-support`, each stage name is appended to the session's `TeardownLog`.

## Known limitation (FR-027)

Kernel events from an MCP server's own process (`tgid`) are routed to that server's record. Events from
processes the server spawns remain in the tool scope's stream until MCP servers get their own scope
(018-subagent-scopes). This limitation is stated in the module documentation.
