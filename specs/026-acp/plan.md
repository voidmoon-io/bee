# Implementation Plan: ACP — bee as an Agent, and Foreign Harnesses as Scoped Subagents

**Branch**: `026-acp` | **Date**: 2026-11-09 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/026-acp/spec.md`

## Summary

Two front doors onto one session engine.

**Inward**, `bee acp` is a new front-end beside the REPL and TUI: it reads ACP v1 from stdin, and for
each `session/new` builds a bee session exactly as `bee repl` does in that working directory, on one
process-wide `Supervisor`. A prompt runs `run_exchange` with an `AcpOutput` that turns streamed text,
tool calls and results into `session/update` notifications. Consent goes through the session's
`ChannelConsent`, serviced as `session/request_permission`. Cancel drops the exchange future, which
already kills the turn's processes.

**Outward**, an agent definition may name an ACP harness as its `runtime`. `delegate::run_inner`
derives and creates the child scope as today, then — instead of `run_loop` — spawns the harness
through the child sandbox's hardened spawn (cgroup join before exec, cleared env), speaks ACP to it
over its pipes, auto-answers its permission requests, and builds the report from its final turn's
text. The harness's kernel network is the loopback proxy port only; its model-provider hostnames are
tunnelled, unopened and name-checked, by a **proxy scope of its own** — 019's long-blocked T092,
which this feature delivers for every subagent. A proxy scope admits a provider's freshly resolved
addresses into its kernel rules when it resolves the name, so CDN rotation never forces a wide rule.

```text
t3code ──ACP──▶ bee acp ─┬─ session A (scope A) ── task ─▶ bee-loop subagent (scope A1 [+proxy A1p])
                         │                         └────▶ harness subagent  (scope A2 + proxy A2p)
                         │                                  claude-agent-acp ─HTTPS_PROXY─▶ A2p ─tunnel─▶ api.anthropic.com
                         └─ session B (scope B)        ▲ ACP over pipes (bee is the client)
                 one Supervisor, one eBPF object, flat scopes
```

## Technical Context

**Language/Version**: Rust 2021, package floor 1.96 (`Cargo.toml:83`); core crates stay at 1.85.

**Primary Dependencies**: new — `agent-client-protocol` 5.1 (Apache-2.0, MSRV 1.88, no features;
runtime-neutral, driven by bee's tokio runtime) and `tokio-util` (`compat`, to adapt tokio pipes to
`futures` I/O). Existing: `tokio`, `comb` (proxy worker, control channel, tunnels), `bee-userspace`
(Supervisor, scopes, reload), `serde_yaml_ng` (agent frontmatter).

**Storage**: none new. The delegation record gains a `harness` section; tunnels already land in the
019 store as `TunnelRecord`s.

**Testing**: host — `cargo test` with a scripted ACP *client* driving `bee acp` over in-memory pipes
(`MockModel` behind it), and a scripted ACP *harness* (a small test binary speaking ACP) for
delegation. Kernel — new VM matrix cases for every enforcement claim (quickstart S3–S8). Real-model
SC-004 with Claude's adapter on `bee-build`.

**Target Platform**: Linux, `CONFIG_BPF_LSM=y`, cgroup v2. A harness requires a kernel scope.

**Project Type**: Rust library + thin CLI; `bee acp` is a CLI front-end over library entry points.

**Performance Goals**: harness spawn (derive → compile → scope + proxy scope → spawn → ACP
`initialize`) ≤ 500 ms p95 excluding the harness's own start-up; per-session overhead in `bee acp`
≤ that of `bee repl` session build. Resolve-and-admit adds at most one scope reload per newly seen
provider address.

**Constraints**: BPF map writes stay serialized on the supervisor task. ACP handlers must never
await a request they sent on the dispatch loop (research R1). The kernel network of a harness scope
is the proxy port only — no direct egress.

**Scale/Scope**: sessions per `bee acp` process bounded by a new `[acp] max_sessions` (default 8);
subagents per session by 018's `[delegation]`.

## Constitution Check

*GATE: evaluated before Phase 0 and re-evaluated after Phase 1.*

| Principle | Verdict | Evidence |
|---|---|---|
| **I. Deny-by-default & fail-closed** | **PASS** | Client fs/terminal methods are never used (bee) and never advertised (to a harness); a harness's fs/terminal calls are refused and recorded. Client MCP servers are refused unless an operator-only key admits them (R7). An unanswered, rejected or cancelled permission request is `Denied`. A harness without a kernel scope is refused, not run unenforced (FR-017). An invalid `cwd` refuses the session before a scope exists. A harness has no direct egress at all; its provider is reachable only through its proxy, by declared name. |
| **II. Capability attenuation** | **PASS** | A harness scope is `parent.active().derive(requested)` exactly as 018's (FR-011). Provider hostnames are the agent's ordinary `requires.net` entries, attenuated by `check_network`'s exact match against the parent's allowlist — so a parent holding `api.anthropic.com:443` *by name* is what authorizes it (under an intercepting parent, against its `[policy.http]` targets and egress instead). For a harness bee then *routes* those entries to its proxy scope's tunnel-only egress rather than to kernel address rules. Credential paths are filesystem rules under `check_protected`. Per-subagent proxy scopes are derived from the subagent's derived policy (T092: "attenuation-checked by T026"). |
| **III. Kernel enforcement is authoritative** | **PASS** | The harness's whole process tree is in its child cgroup (joined before exec). Its only kernel network rule is the proxy port. The proxy scope's upstream addresses are admitted into the kernel only when bee resolves a declared name (R9), so the kernel holds every address the worker can reach — no port-wide rule. The harness's own approval prompts are explicitly *not* part of the boundary, and exec narrowing is not claimed for a harness that holds a shell (FR-021, R16). |
| **IV. Policy-as-data** | **PASS** | A harness agent is a `SKILL.md` with two new frontmatter keys (`runtime`, `command`/`args`/`env`); its capabilities are the same `requires` block. `[acp]` is config text. |
| **V. Library-first, runtime-free core** | **PASS** | `bee-core` gains no runtime. The ACP agent is a front-end module (`src/acp/`) over `session::build` and `run_exchange`; it adds no enforcement. The harness runtime lives beside `delegate.rs` and uses the same `Sandbox` spawn path as MCP servers. |

**Additional gates**:
- *Scope isolation* — each harness and each proxy scope is a bee-managed cgroup on the session's
  supervisor, flat, torn down children-first; a scope that will not empty fails the delegation.
- *Process hardening* — harnesses spawn through `hardened_command` (setuid refusal, no core dumps,
  non-dumpable, env allowlist, `strip_env`), same as every tool child.
- *Protected paths* — harness credential stores are added to a harness scope's protected list
  (R10); global defaults unchanged.
- *Auditability* — every kernel event in a harness or proxy scope is attributed to that scope (018
  router); every permission request and answer is recorded; every tunnel is recorded with metadata.

**Test-first gate**: VM cases for harness containment, egress-by-name, proxy attribution and
credential protection are written and failing before the code that makes them pass.

**Result: PASS.** No violations. Complexity Tracking records one structural change (T092).

## Project Structure

### Documentation (this feature)

```text
specs/026-acp/
├── spec.md
├── plan.md              # this file
├── research.md          # R1–R16
├── data-model.md
├── quickstart.md        # S1–S9
├── contracts/
│   ├── acp-agent.md     # bee acp: messages handled, mapping to bee, errors
│   ├── harness-runtime.md   # agent definition keys + bee as ACP client
│   └── proxy-scopes.md  # per-subagent proxy scopes + resolve-and-admit
└── tasks.md             # /speckit-tasks
```

### Source Code (repository root)

```text
src/
├── acp/                         # NEW — ACP, both directions
│   ├── mod.rs                   #   shared types, protocol version, record helpers
│   ├── agent.rs                 #   bee acp: connection, session table, handlers
│   ├── output.rs                #   AcpOutput: ReplOutput → session/update
│   ├── consent.rs               #   ConsentAsk ↔ session/request_permission
│   └── harness.rs               #   bee as ACP client: spawn, drive, report, record
├── app/
│   ├── acp.rs                   # NEW — `bee acp` entry: runtime, config per cwd, supervisor
│   └── config/{mod,file}.rs     # [acp] section (operator-only: client_mcp, max_sessions)
├── main.rs                      # Cmd::Acp
├── delegate.rs                  # branch on agent runtime; child proxy scope; drop T092 refusal
├── skills.rs                    # Agent.runtime (Loop | Acp{command,args,env})
├── sandbox.rs                   # ChildEnv.cwd; proxy scopes as supervisor records (not `sidecar`)
├── supervisor.rs                # scope records carry an optional proxy scope
├── intercept/session.rs         # attach a proxy scope to any Sandbox; resolver → admit
├── session/{mod,spec,parts}.rs  # EntryPoint::Acp; scope/run ids from session id; prebuilt supervisor
├── transcript.rs                # DelegationRecord.harness; turns/tokens Option
└── mcp/                         # client stdio servers → McpServerConfig (when admitted)
crates/core/src/
├── compiler.rs                  # harness protected list; proxy-scope net reload helper
└── policy.rs                    # (no schema change: egress reused)
tests/
├── acp_agent.rs                 # scripted ACP client ↔ bee acp (host)
├── acp_harness.rs               # scripted harness via test binary (host + test-support)
└── bin/acp_fake_harness.rs      # minimal ACP agent for tests and VM cases
test/vm/remote-matrix.sh         # acp-* and harness-* cases
```

**Structure Decision**: a single new module `src/acp/` for both protocol directions, so ACP types
never leak into the session engine; the engine changes are small seams (`ChildEnv.cwd`,
`EntryPoint::Acp`, ids, `Agent.runtime`, proxy scopes per sandbox).

## Implementation Sequence

Each step is one PR, reviewable and VM-gated on its own. Steps 1 and 2 are independent.

| # | Slice | Stories | Delivers |
|---|---|---|---|
| 1 | **`bee acp` agent** | US1, US2 | `Cmd::Acp`; one supervisor; session per `session/new` (cwd validated, config resolved per cwd, `ChildEnv.cwd`); `AcpOutput`; consent ↔ `request_permission`; cancel; client MCP refusal / `[acp] client_mcp`. Host tests with a scripted client; VM cases `acp-denial-reported`, `acp-two-sessions-isolated`. |
| 2 | **Proxy scopes per subagent (T092)** | US5 (+ groundwork for US4) | Sidecar → supervisor scope record; any `Sandbox` may own a proxy scope; delegation from intercepted sessions allowed; child proxy credential namespace; attribution. Resolve-and-admit. VM `subagent-intercept-attributed`, `proxy-admit-on-resolve`. |
| 3 | **Harness runtime** | US3, US4 | `runtime: acp` agents; spawn in child scope + own proxy scope with provider `egress`; ACP client; auto-permission; report + `HarnessRecord`; deadline/cancel; harness protected list; host-mode refusal. Fake-harness VM cases `harness-contained`, `harness-egress-by-name`, `harness-credentials`. |
| 4 | **Real harness + polish** | SC-004, SC-006 | Claude adapter end to end on `bee-build`; docs (`docs/` + AGENTS skill for writing harness agents); quickstart S1–S9 recorded; benchmark. |

## Complexity Tracking

| Change | Why needed | Simpler alternative rejected because |
|---|---|---|
| Proxy scopes move from `EnforcedSandbox.sidecar` (one per session) to supervisor scope records (one per sandbox that needs one) — 019 T092 | A harness's only route to its provider is a proxy scope that tunnels by name; and intercepted sessions cannot delegate without per-subagent recording | Sharing the session's proxy: a subagent's exchanges would be attributed to the parent (why delegation is refused today, `delegate.rs:322-330`), and the harness's provider host would have to be in the *parent's* egress. Direct kernel egress for the harness: addresses only, breaks on CDN rotation or must be wide (R8). |

## Post-Design Constitution Re-Check

Re-evaluated after data-model and contracts: unchanged — **PASS**. The contracts add no capability
outside `derive`: `runtime`/`command` are not capabilities (they choose *what runs* in the scope, and
the operator authors them); provider hostnames are `requires.net` entries, already attenuated, merely routed to the proxy; the
harness protected list only adds denials. The one place a new kernel rule appears at run time —
resolve-and-admit — admits only addresses resolved for a name already in that scope's compiled
egress/targets, and is recorded as a scope reload.
