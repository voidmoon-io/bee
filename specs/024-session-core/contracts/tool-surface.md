# Contract: Tool surface

FR-013–FR-016.

```rust
impl ToolRegistry {
    pub fn with_deps(deps: Arc<ToolDeps>) -> Self;
    /// The only constructor of a non-MCP tool. Always configured from deps.
    pub fn register(&mut self, name: &str) -> Result<(), UnknownTool>;
    pub fn set_deps(&mut self, deps: Arc<ToolDeps>);   // e.g. scanner grants after a policy change
    pub fn surface(&self) -> Vec<SurfaceEntry>;          // name, schema, deps summary
    // unchanged: contains, schemas, execute, remove, mcp registration
}
```

- `register` of a feature-disabled tool → `NotCompiledIn` (016 outcome).
- `register` of a tool whose dependency is absent → the tool registers and fails closed when called
  (e.g. `InterceptorUnavailable`), identical to start-up.
- `submit_flag`/`give_up` register only when `deps.ctf_flag` is set.
- Deleted: `configure_security_tools`, `configure_http_tools`, `register_named`'s defaulting behaviour.
- `escalate()` registers granted tools via `register` (after `set_deps` if the policy changed).
