# Contract: harness agents — bee as an ACP client

## Agent definition

An 018 agent definition (`SKILL.md`, `kind: agent`) with a `runtime` block:

```yaml
---
name: claude
kind: agent
description: Claude Code, for open-ended coding tasks in this repository.
runtime:
  acp:
    command: /opt/claude-agent-acp/claude-agent-acp      # absolute; no shell, no npx
    args: []
    env:
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1"
requires:
  filesystem:
    "/home/me/src/proj": write
    "/home/me/.claude": write          # its sign-in and state (harness credential store)
    "/home/me/.claude.json": write
  net: ["api.anthropic.com:443", "platform.claude.com:443"]   # provider hosts, by name
---
(Body: unused for a harness. It may document the agent for the operator.)
```

| Key | Rule |
|---|---|
| `runtime` | Absent ⇒ bee's own loop (018). `runtime.acp` ⇒ a harness. Any other runtime is a malformed-definition warning. |
| `runtime.acp.command` | Absolute path to an executable. Resolved at delegation; a setuid/file-capability binary is refused by the hardened spawn. |
| `runtime.acp.args` | Literal arguments. |
| `runtime.acp.env` | Added to the scope's cleared environment. Keys bee strips as credential-bearing are refused, except those the operator lists in `[acp] harness_env_passthrough` (operator-only), e.g. `ANTHROPIC_API_KEY` — then the **value is taken from bee's environment**, never from the file. |
| `tools` | Must be empty or omitted (a warning otherwise). The model chooses the agent by `name` + `description` only. |
| `turn-limit` | Ignored for a harness (not observable). |
| `requires.*` | 018 semantics: derived against the parent before anything exists. For a harness, `requires.net` entries are provider destinations routed to its proxy scope, never kernel address rules. |

## What bee does on delegation

1. 018 checks (agent known, depth, parent policy present). A session with **no kernel scope** →
   refused: `the harness 'claude' needs a kernel scope, and this session has none`.
2. Derive the child policy. For a harness, protected stores (`~/.claude`, `~/.claude.json`,
   `~/.codex`, `~/.local/share/opencode`, `~/.config/opencode`) are denied unless the agent names them
   and the parent names them too.
3. Create the child scope **and its proxy scope**: child kernel network = proxy loopback only; proxy
   egress = `requires.net`; proxy targets = the parent's targets when the parent intercepts.
4. Spawn `command args` through the child sandbox (cgroup join before exec, env cleared + `env` +
   proxy env + CA bundle only if anything is inspected; `cwd` = session cwd); stdin/stdout piped,
   stderr captured (tail kept).
5. ACP client handshake:
   - `initialize { protocolVersion: 1, clientCapabilities: { fs: {readTextFile:false, writeTextFile:false}, terminal: false }, clientInfo: {name:"bee"} }` — a version other than 1 → `Failed`.
   - `session/new { cwd, mcpServers: [] }`.
   - `session/prompt { prompt: [text: <task prompt>] }`.
6. While the prompt runs:
   - `session/update` → recorded (`HarnessRecord.turns`); `agent_message_chunk` text accumulated;
     progress lines go to the delegating session's progress sink (`[claude] …`).
   - `session/request_permission` → answered by research R11 (allow_once ≫ allow_always ≫ cancelled)
     and recorded. Never shown to a person.
   - `fs/*`, `terminal/*`, any other client method → JSON-RPC `method_not_found`, recorded in
     `refused_methods`.
   - The child scope's audit is drained on each update and at the end.
7. End:
   - `stopReason` received → `Completed` (`end_turn`), or `CutShort` (`max_tokens`,
     `max_turn_requests`), or `Completed` with the refusal stated (`refusal`).
   - Deadline → `session/cancel`; 5 s grace; then teardown → `CutShort { Deadline }`.
   - Harness exits or breaks protocol → `Failed { detail }` with the stderr tail.
   - In every case: close stdin, tear down proxy scope then child scope (`cgroup.kill`); a scope that
     will not empty → `Failed`.

## Report to the parent model

```
subagent 'claude' — completed (harness, end_turn)
<text of the harness's final turn>
```

Capped like any tool result. Provenance `Remote { source: "subagent:claude" }`. Plus, always:
`NOTE: this subagent is an external harness. bee confined its files and network; it did not narrow
which programs it ran.` (FR-021). An `UNENFORCED` delegation cannot occur (step 1).
