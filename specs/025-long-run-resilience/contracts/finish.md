# Contract: Finish tool (`src/tools/finish.rs`)

FR-031–FR-037.

## Schema offered to the model

```json
{
  "name": "finish",
  "description": "End this run. Call it once, when the task is complete, or when you cannot make further progress. outcome: \"completed\" if the task is done; \"blocked\" if something outside your control (access, missing information, a broken environment) prevents it; \"abandoned\" if you stopped for another reason. summary: what you did, what the result is, and anything the operator must know. Tool calls after finish in the same turn are not run.",
  "parameters": {
    "type": "object",
    "properties": {
      "outcome": { "type": "string", "enum": ["completed", "blocked", "abandoned"] },
      "summary": { "type": "string", "minLength": 1, "maxLength": 4000 }
    },
    "required": ["outcome", "summary"],
    "additionalProperties": false
  }
}
```

## Results

| Input | `ToolResult` | Run |
|---|---|---|
| valid | `terminal_ok("run finished: {outcome}")` | ends: `Finished{outcome, summary, turn}` |
| missing/unknown outcome, empty or over-long summary | `invalid_args("finish", …)` | continues |

## Offering

| Session | Offered |
|---|---|
| `run_loop` (bee run, batch, concurrent, harness), `mode = standard`, `finish = true` (default) | yes |
| `mode = standard`, `finish = false` | no |
| `mode = ctf` | no; listing it is a validation error |
| REPL / TUI | no |

## Text-only turns when finish is offered

1. The first text-only turn: the assistant message is pushed, and a `HarnessNote{FinishRequired}` is
   queued:
   `[bee] This run ends only when you call finish. If the task is done, call finish with outcome "completed" and a summary; otherwise continue working.`
   The run continues.
2. A second text-only turn, at any later point: the run ends with `EndedWithoutFinish`.

## Exit status (`bee run`)

| Status | finish offered | finish not offered |
|---|---|---|
| `Finished{completed}` | 0 | — |
| `Finished{blocked\|abandoned}`, `EndedWithoutFinish` | 3 | — |
| `Stuck`, `ContextExhausted` | 3 | 3 |
| `Timeout` | 3 | 0 (unchanged) |
| `Completed`, `NoToolCalls`, `Captured`, `NotCaptured` | — | 0 (unchanged) |
| `ApiError` | 69 | 69 |
| `InfraError` | 70 | 70 |

Exit 3 means "the run ended without completing its task". It is documented beside the existing codes in `src/app/run.rs` and in `bee run --help`.

## Progress lines

```text
  call finish {"outcome":"completed","summary":"…"}
  result ok: run finished: completed
done: finished (completed) · {n} turns · {ms}ms
  summary: {preview(summary, 200)}
```

The `summary:` line is new and printed after `done:`.
