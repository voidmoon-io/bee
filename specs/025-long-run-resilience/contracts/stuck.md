# Contract: Stuck detection (`src/stuck.rs`)

FR-023–FR-030. Types in [data-model.md](../data-model.md#streaktracker).

```rust
let signal = session.stuck.observe(&call, &outcome);   // after every call, in order
```

| Signal | Episode loop | REPL |
|---|---|---|
| `Remind(r)` | queue `r` as a `HarnessNote`; pushed at the next turn start | same, at the next step |
| `Stop{..}` | record the call, set `EpisodeStatus::Stuck{tool, arguments, repeats}`, end the run | record, `output.error(..)`, return `ExchangeOutcome::Stuck` |

Every call the model made is observed, except calls skipped after `finish` (`not_run`). A call
refused by a hook before running, and a call rejected as invalid arguments, are observed and count as
failing. A model that repeats a malformed or hook-refused call is stuck too.

## Reminder texts

General (`remind_after`):

```text
[bee] You have called {tool} with the same arguments {n} times in a row{failing}. Repeating it is
unlikely to give a different result. Try a different approach: check your assumptions, inspect the
error, or use another tool.
```

`{failing}` is `, and it failed each time` when every call in the streak failed, and empty otherwise.

Policy (`denied_remind_after`, when every call in the streak was denied and not granted):

```text
[bee] {tool} with these arguments was denied {n} times by the session's security policy
({denial}). This is a policy decision, not a transient error: the same call will be denied again.
Work within the access you have, or, if you cannot complete the task without it, say so.
```

When finish is offered, the policy reminder ends with `…say so and call finish with outcome "blocked".`

## Stop message

Headless progress line: `  stuck: {tool} repeated {n} times with the same failing result — ending run`.
REPL: `output.error("stopped: {tool} was repeated {n} times with the same failing result")`.

## Reset

`StreakTracker::reset()` runs on `/clear`. A new REPL exchange does **not** reset it: a streak can span
user messages. A person who sees the stop message can rephrase, and the next different call starts a
new streak.
