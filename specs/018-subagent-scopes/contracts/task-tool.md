# Contract: The `task` Tool

**Feature**: 018-subagent-scopes | Consumers: `src/tools/task.rs`, `src/tools.rs`, `src/delegate.rs`

`task` is the model-facing delegation surface. It does **not** run a subagent — it validates and
returns a `DelegationRequest`, which the loop fulfils. This is the `render` idiom (`render` validates
a script and returns a `render_spec` the front-end draws; the model sees only a text summary).

## Enablement

`TASK_TOOLS = &["task"]`. **Not** in `DEFAULT_TOOLS`. A scenario or REPL config opts in by listing
`"task"`, exactly as it does for `render` and the security tools. The tool is registered only when at
least one `kind: agent` definition was discovered, and is **omitted entirely** from a child at
`depth >= max_depth`.

## Schema

```json
{
  "name": "task",
  "description": "Delegate a self-contained piece of work to a subagent. The subagent runs with its own, narrower capabilities and returns a written report. Available agents:\n- test-runner: Runs the test suite in an isolated scratch directory and reports failures verbatim.\n- dep-auditor: Reviews dependency manifests for known-risky packages. Offline.",
  "parameters": {
    "type": "object",
    "properties": {
      "agent":  { "type": "string", "enum": ["test-runner", "dep-auditor"],
                  "description": "Which agent to delegate to." },
      "prompt": { "type": "string",
                  "description": "The task, self-contained. The subagent does not see this conversation." }
    },
    "required": ["agent", "prompt"]
  }
}
```

The `enum` is generated from the registry, so an unknown name is usually impossible — but see the
refusal taxonomy: it is still handled, because a model can emit anything.

**There is no policy, tool-list, or capability parameter, and there never will be** (FR-003). The
model chooses what to delegate and to whom. The operator chose what that agent may do, by writing its
definition.

## Success result

The tool returns:

```rust
ToolResult {
    content: String::new(),                  // the loop replaces this with the report
    delegate: Some(DelegationRequest { agent, prompt }),
    is_error: false,
    ..
}
```

The loop then, in order:

1. Derives `parent.active().derive(agent_policy)` — **before any cgroup exists**.
2. Asks the supervisor for a child scope, subscribing to the demux **before** the child's first call.
3. Runs the child's `run_loop` with its own registry, conversation, and `DelegationCtx`.
4. Tears the child's scope down.
5. Replaces `content` with the bounded report and sets `delegate = None`.

**Invariant**: a `ToolResult` entering `Message::ToolResult` always has `delegate == None`. The
conversation never receives the child's individual tool calls (FR-027).

## Report format

What the parent model receives as `content`:

```
subagent 'test-runner' — completed (7 turns)

<the child's final assistant text, verbatim>
```

Cut short:

```
subagent 'test-runner' — CUT SHORT: shared turn budget exhausted after 4 turns.
The task was NOT completed.

<whatever the child had produced>
```

Unenforced (host mode / non-enforce build):

```
subagent 'dep-auditor' — completed (5 turns)
WARNING: this subagent ran with NO kernel scope. Its declared capability
limits were validated but NOT enforced.

<the child's final assistant text, verbatim>
```

Rules:
- Truncated at `DEFAULT_OUTPUT_CAP` by the same `transcript::truncate` every tool result uses, with the
  truncation marker visible (FR-026).
- A child that produced no text yields `"subagent 'x' — completed (n turns), but produced no report."`
  — distinct from a child reporting that it found nothing.
- The status line is always first, so a cut-short or unenforced run cannot be mistaken for a clean one
  even if the body is truncated away.

## Refusal taxonomy

Every refusal is an **error result fed back to the model** — never a panic, never a silent no-op — and
every one of them leaves **no cgroup, no process, and no partial state**.

| Reason | Trigger | Message shape |
|---|---|---|
| `UnknownAgent` | `agent` names nothing discovered | `task: unknown agent 'x'. Available: test-runner, dep-auditor` |
| `InvalidArgs` | missing/mistyped `agent` or `prompt` | `task: invalid arguments: <detail>` (the existing FR-016 shape) |
| `ToolNotHeld` | the agent's `tools` contains a name the parent's registry lacks | `task: agent 'x' requires tool 'scan', which this session does not hold` |
| `Attenuation` | `derive` rejected the declaration | `task: agent 'x' exceeds this session's authority: <the AttenuationError, verbatim>` |
| `DepthExceeded` | `depth >= max_depth` | `task: delegation depth limit (1) reached; a subagent may not delegate further` |
| `BudgetExhausted` | no turns or time remain **before** spawning | `task: no budget remains to delegate (0 turns left)` |
| `FanOutExceeded` | simultaneous-subagent cap reached | `task: too many subagents already running (cap 4)` |
| `NotCompiledIn` | the build cannot enforce and the session did not opt into host mode | handled by the existing enforcement gate, not here |

`Attenuation` quotes the validator verbatim rather than paraphrasing: `AttenuationError` already names
the rule and the region it violated, and rewording it would lose the detail an operator needs to fix
the definition.

## Failure (not refusal)

A failure is something that went wrong *after* validation passed:

| Outcome | Trigger | Behaviour |
|---|---|---|
| `Failed { detail }` | scope creation, plan compile, or engine command failed | error result naming the cause; any partial cgroup is removed |
| `Failed { detail }` | the child's scope would not empty at teardown | error result **and** the existing operator warning on stderr; the parent is **not** told the delegation was clean (FR-022) |

## What a subagent cannot do to its parent

Enforced by construction, and asserted by test:

- It cannot widen the parent's policy — the parent's `ActivePolicy` is not reachable from a child loop.
- It cannot alter agent definitions — discovery is host-side and read-only.
- It cannot record a human verdict — no agent can (`bee findings adjudicate` is CLI-only).
- It cannot inject into the parent's conversation beyond its report, which is bounded, prefixed with a
  status line the child does not author, and truncated by the harness.

The last one matters because a subagent's report is **untrusted text**: it may quote file contents the
child read. It is delivered as a tool result, which the parent model already treats as data, and the
status line is harness-authored so a child cannot forge `completed` over a cut-short run.
