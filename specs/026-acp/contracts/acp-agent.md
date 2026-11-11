# Contract: `bee acp` — bee as an ACP agent

`bee acp [--config FILE] [flags shared with bee repl]` reads ACP **v1** JSON-RPC on stdin and writes
it on stdout. Diagnostics go to stderr only; nothing else is ever written to stdout.

## initialize

| Field | bee sends |
|---|---|
| `protocolVersion` | `1` (whatever the client asked; bee speaks only 1) |
| `agentCapabilities.loadSession` | `false` |
| `agentCapabilities.promptCapabilities` | `image: false, audio: false, embeddedContext: true` (embedded text resources are passed to the model as user text, marked as client-supplied) |
| `agentCapabilities.mcpCapabilities` | `http: false, sse: false` |
| `agentInfo` | `{ name: "bee", version: <crate version> }` |
| `authMethods` | `[]` — bee's model provider comes from its own configuration |

The client's `clientCapabilities` are recorded and **ignored**: bee never sends `fs/*` or `terminal/*`.

## session/new { cwd, mcpServers }

1. Refuse when `max_sessions` sessions are open.
2. Validate `cwd` (absolute, exists, directory). Resolve configuration as `bee repl` would in `cwd`
   (user → project `cwd/.bee/config.toml` → `--config`; project is untrusted).
3. Build the session (`EntryPoint::Acp`) on the process supervisor; scope id `acp-<session id>`.
   Start-up consent asks are put to the client as permission requests during this call (the
   `sessionId` they carry is the one about to be returned).
4. Check the session's policy can read `cwd`; otherwise tear down and refuse.
5. `mcpServers`: stdio entries start only when `[acp] client_mcp = true`, under the operator's
   `McpPolicy`; HTTP/SSE entries never. Each dropped server is listed in one
   `agent_message_chunk` notice after the response.
6. Respond `{ sessionId }`.

Errors: JSON-RPC `invalid_params` (bad cwd, bad server entry) or `internal_error` with a message
naming the cause (config incomplete, policy refused by ceiling, kernel unavailable).

## session/prompt { sessionId, prompt }

- Refused with an error if a prompt is already running in that session.
- Text blocks and embedded text resources are joined into the user message. Image/audio blocks are
  refused (capability not advertised). Resource links are passed as their URI text.
- Runs `run_exchange` in a spawned task (research R1); the handler returns at once and the response
  is sent when the exchange ends.
- `stopReason`: `end_turn` (Responded), `max_turn_requests` (BudgetExhausted), `max_tokens`
  (ContextExhausted), `cancelled` (session/cancel). `ApiError`, `Terminated`, `Stuck` end the turn
  with `end_turn` after an `agent_message_chunk` stating the error, so the client shows it.

### session/update mapping (`AcpOutput`)

| bee front-end call | ACP update |
|---|---|
| `assistant_delta(chunk)` | `agent_message_chunk { content: text }` |
| `tool_call(name, args)` | `tool_call { toolCallId: <bee call id>, title: "<name> <short args>", kind, status: in_progress, rawInput: args }` |
| `tool_result(result, audit)` | `tool_call_update { status: completed / failed, content: [text], rawOutput }`; each denial in `audit` is appended as a content line `kernel denied <op> <target>` |
| `info(msg)` / `error(msg)` | `agent_message_chunk` prefixed `bee: ` |
| delegation of a `task` call | the call's `tool_call` is updated with progress lines while the subagent runs; final content is the report |
| `consent_decided(record)` | no update (the permission request itself is the trace) |

`kind` mapping: `read_file`→`read`, `write_file`/`edit_file`→`edit`, `bash`/`exec`→`execute`,
`http`/`fetch`→`fetch`, `grep`/`glob`/`search`→`search`, `task`→`other`, else `other`.

All text from tool results, subagent reports and audit is passed through `safe_text` (no control
sequences) and is attributed by `toolCallId`; bee never presents it as its own words.

## session/request_permission (bee → client)

Sent for every `ConsentAsk`:

```json
{ "sessionId": "...",
  "toolCall": { "toolCallId": "<triggering call id, or consent-<seq>>", "title": "<render_lines()[0]>",
                "kind": "other", "content": [ {"type":"content","content":{"type":"text","text":"<every render_lines() line>"}} ] },
  "options": [ {"optionId":"allow","name":"Allow","kind":"allow_once"},
               {"optionId":"reject","name":"Reject","kind":"reject_once"} ] }
```

`selected: allow` → Granted. `selected: reject`, `cancelled`, an error, no answer within the
operator's consent timeout, or a closed connection → Denied. The decision is recorded in the
session's consent log with `operator: interactive`.

## session/cancel { sessionId }

Abort the running exchange (dropping it kills the turn's tool processes and any subagent scopes),
refuse pending consent asks for the session, truncate the conversation to before the prompt, and
answer the prompt `stopReason: cancelled`. No-op when idle.

## Unsupported

`session/load`, `session/set_mode`, `session/set_model`, `authenticate`, and every unknown method →
JSON-RPC `method_not_found`. Unknown notifications are ignored.

## Shutdown

stdin EOF or a broken stdout: cancel every running prompt, then `shutdown()` every session (MCP →
interceptor → scopes), then exit 0. A session whose scope will not empty is reported on stderr and
makes the exit status non-zero.
