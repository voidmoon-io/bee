# AX smoke test

The smoke task uses the deployed AX runner image. AX launches its own runner,
which supervises commands; Bee runs with `--host` inside that sandbox.
The mock provider checks remote tool execution and feedback persistence without
model charges. `live.toml` targets the cluster Anthropic proxy, with a placeholder
BEE_API_KEY; the real credential remains in the proxy.

This is a bootstrap experiment: the binary and inputs are uploaded to the debug
guest API, not baked into an image. Do not treat it as a reproducible release.
The local checkout had an older incompatible runner (unknown `createTime` field).
The AX SSH CLI also does not forward stdin; uploads require the guest WriteFile API.

Run artifacts belong under /workspace/bee-smoke; retrieve them before suspension.
AX Running means the runner is available, not that Bee passed: inspect Bee's exit
status and transcript. No feedback is sent to Linear by this smoke test.
