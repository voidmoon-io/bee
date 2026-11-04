# User-configured MCP tools in durable codemode

Status: ready-for-agent

## Problem

`ALLOWED` in `src/session/driver/codemode.rs` excludes:
- **MCP registrations.** Their cancellation and reconciliation behavior under durable
  replay isn't qualified. Durable sessions also currently refuse persistent MCP
  transports outright (`execution.rs`).
- **`submit_flag`, `give_up`, `finish`.** These end the session; a script result cannot
  represent "stop the episode".
- **`render`.** Its UI side effects (panels, overlays) have no defined meaning inside a
  script.

## Agreed direction (2026-11-01)

Scope the next slice to MCP. Keep `finish`, `give_up`, and `submit_flag` outside
codemode: scripts return results and the outer agent decides whether to terminate.
Defer `render` until display restoration and replay behavior have a contract.

### Product contract and first slice

End users can configure arbitrary MCP servers through the existing supported
transports. Discover their tools and expose permitted registrations to durable
sessions and codemode, without server-specific code changes or a curated server
allowlist. Existing server authorization, consent and tool filters still apply.
Protocol/transport compatibility errors must remain explicit.

Start with sequential execution and a deterministic fixture for lifecycle tests.
Individual servers are test cases, not product eligibility requirements. Generic
support uses conservative recovery; optional stronger retry or reconciliation
contracts may be added later. Never infer replay safety from server annotations.

- Keep interrupted calls `NeverReplay`; after dispatch, timeout/disconnect/cancel
  does not prove that an effect failed. Record an unresolved outcome unless a
  committed result or qualified reconciliation establishes completion.
- Persist call identity and result/receipt ownership across reconnect and reopen.
  Completed calls replay their stored result without contacting the server again.
- For stdio, tie server-process cleanup to durable lifecycle ownership. For remote
  servers, cancellation notification is not evidence that server-side work stopped.
- Preserve existing consent, tool filtering, provenance and audit attribution.
- Bind discovered tool identity/schema and configuration to session compatibility;
  changed registrations must not silently resume pending work under a new contract.
- Defer overlap of MCP calls until per-call attribution and cancellation isolation
  are verified; `call_tools` must not implicitly qualify concurrent server access.

### Current implementation obstacles

`src/session/driver/execution.rs` rejects registrations with `mcp_server` metadata;
`src/app/repl.rs` also rejects persistent MCP transports for durable sessions.
`src/mcp/proxy.rs` currently converts transport errors and timeouts into ordinary
`ToolResult::error` results. Durable support must distinguish unresolved remote
execution from a tool-reported error before either guard is relaxed.

### Acceptance

Use a fixture that can block after receiving a request and before replying. Cover
committed-result reopen, lost reply, timeout/cancel, process death and schema/config
change. Prove completed effects never repeat, ambiguous effects block continuation,
server cleanup is bounded, and receipts/audits remain attached to the correct call.
Verify that changing configured server/tool names needs no application code changes
and that denied tools remain absent from the guest catalog. Exercise both stdio and
remote transport lifecycle behavior, then a representative real server through a
durable codemode script. An MCP tool reporting an ordinary error is a committed
result; a transport failure after dispatch may be an unresolved effect. These must
remain distinguishable. Cancel notifications are best-effort and never establish
remote completion or rollback.
