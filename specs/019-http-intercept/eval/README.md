# SC-005 evaluation: does the HTTP tool set beat shell + curl?

**What SC-005 claims:** on the same web-testing task, an agent with bee's HTTP tools needs fewer
tool calls and reads fewer tokens of tool output than the same agent with only `bash` + `curl`, and
reaches the same or a better result. This is a paired, live-provider measurement. It is **not a CI
gate**: it costs model calls and its numbers depend on the model.

## Setup

1. Start the fixture target and note its ports:

   ```bash
   cargo run --features intercept --example vuln_target
   # vuln_target http  = 127.0.0.1:<T>
   ```

2. Put `<T>` into `policy.toml` (`targets = ["127.0.0.1:<T>"]`).
3. Use a provider TOML for a real model (any provider bee supports). Use the **same** provider and
   model for both arms, and run each arm several times (n ≥ 5). Single runs are noisy.

## The two arms

Both arms share the task, the policy (`policy.toml`: interception on, the fixture in scope, `bash`
and `curl` allowed) and the turn limit. They differ only in the tool list:

| Arm | Scenario | Tools |
|---|---|---|
| shell | `scenarios/eval-http-shell.toml` | `bash` (curl goes through the proxy, so it is recorded too) |
| http | `scenarios/eval-http-tools.toml` | `http_send`, `http_get`, `http_history`, `http_replay`, `http_fuzz`, `http_leads`, `record_finding` |

The task asks for the fixture's three planted issues: the reflected `q` on `/search`, the
`X-Forwarded-For` bypass on `/admin`, and the quote-triggered 500 on `/item`.

```bash
for arm in shell tools; do
  for i in 1 2 3 4 5; do
    bee run --scenario specs/019-http-intercept/eval/scenarios/eval-http-$arm.toml \
            --provider <provider.toml> --http-scope-advisory \
            --out eval-$arm-$i.json
  done
done
```

On a host without BPF-LSM the session needs `--http-scope-advisory`. On the VM, drop it and run as
root.

## What to record, per transcript

| Measure | How |
|---|---|
| tool calls | `jq '[.turns[].calls[]] \| length' eval-*.json` |
| tool-output tokens | sum of `len(result.content)` / 4 across calls (a byte proxy is enough for a paired comparison) |
| issues found | how many of the three are named correctly in the final answer, or recorded with `record_finding` |
| turns used | `jq '.turns \| length'` |

Report the median and range per arm, and the per-run pairs. SC-005 holds when the http arm's median
tool calls and output tokens are both lower, and its issues-found median is no worse.

## Notes

- Output tokens are where the shell arm usually loses: `curl -v` and full bodies land in the
  transcript whole, while the HTTP tools return bounded slices and ids.
- A run that ends in an infrastructure error is excluded and reported as such, never counted as a
  loss for either arm.
