# Widen the guest catalog: MCP and terminal tools

Status: needs-triage

## Problem

`ALLOWED` in `src/session/driver/codemode.rs` excludes:
- **MCP registrations.** Their cancellation and reconciliation behavior under durable
  replay isn't qualified. Durable sessions also currently refuse persistent MCP
  transports outright (`execution.rs`).
- **`submit_flag`, `give_up`, `finish`.** These end the session; a script result cannot
  represent "stop the episode".
- **`render`.** Its UI side effects (panels, overlays) have no defined meaning inside a
  script.

## Decision needed

For each group, either define a contract (e.g. a terminal tool inside a script ends the
script and surfaces as a terminal outer result; render inside a script is rejected or
deferred to the outer result) or record it as permanently excluded. MCP depends on
durable-session MCP support landing first.
