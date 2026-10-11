# Contract: Configuration (025)

Defaults and validation are in [data-model.md](../data-model.md). Every key is optional.

## User and project config (`~/.config/bee/config.toml`, `.bee/config.toml`)

```toml
[context]
window_tokens    = 200000   # overrides the model table and the provider file
compaction       = true     # default false until SC-010 has run
soft             = 0.60
hard             = 0.85
target_gap       = 0.10
recent_share     = 0.30
bulky_tokens     = 300
summary_share    = 0.10
result_cap_bytes = 24000
result_cap_share = 0.10

[stuck]
remind_after        = 5
denied_remind_after = 2
stop_after          = 8
stop                = true
```

Layering is the same as the existing tables: user, then project, then `--config`, each `Some`
overriding the one before. Unknown keys are rejected (`deny_unknown_fields`, as `[session]`). Neither
table is user-only.

## Provider file

```toml
[provider]
context_window = 131072    # for a model bee has no table entry for
```

Precedence for the window: the scenario's `[context] window_tokens`, then user and project
`[context] window_tokens`, then `[provider] context_window`, then the built-in table, then 32,000.

## Scenario file

```toml
[scenario]
finish = true              # default; false opts the run out of the finish tool

[context]                  # same keys as above; overrides user/project config for this scenario
[stuck]
```

`[context]` and `[stuck]` are top-level tables in the scenario file, like `[mcp]` and `[security]`, and
are folded into `Scenario` by `from_path`.
