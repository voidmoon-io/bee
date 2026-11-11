# 023 codemode — remaining work

Created: 2026-10-31. Baseline: PR #49 (merged 2026-11-01 as `f59e240`), which landed
Python visual scripts, durable script compositions and the codemode driver on `main`.
Design and verification: [`specs/023-codemode/`](../../specs/023-codemode/), especially
[`parallel-nesting-plan.md`](../../specs/023-codemode/parallel-nesting-plan.md).

| # | Issue | Status | Size |
| --- | --- | --- | --- |
| 01 | [Land PR #49](issues/01-land-pr-49.md) | done (merged `f59e240`) | — |
| 02 | [Overlap batch calls under kernel enforcement](issues/02-enforced-batch-overlap.md) | done | L |
| 03 | [Exec rules and symlinked binaries (`sh` → `dash`)](issues/03-exec-symlink-policy.md) | done | S–M |
| 04 | [Indent nested calls by depth in the TUI](issues/04-tui-nesting-depth.md) | done | S |
| 05 | [Validate codemode with a real model](issues/05-real-model-validation.md) | done | M |
| 06 | [User-configured MCP tools in durable codemode](issues/06-catalog-mcp-terminal.md) | ready-for-agent | M |
| 07 | [Retire the pre-port branches and local backups](issues/07-retire-old-branches.md) | done | S |
| 08 | [Imported module checkpoint error](issues/08-imported-module-checkpoint.md) | needs-triage | S–M |

02, 03 and 04 are completed locally. 05 passed real-model validation after a description clarification. 06 has an agreed generic MCP contract and is ready for implementation. 07 is complete (archive tags and a verified durable backup).

## What is already done (not tracked here)

- `call_tool`, `call_tools` (1–4 calls, one commit, ordered results), nested `codemode`
  (≤4 levels, shared 32-call / 64-invocation limits), host and enforced overlap.
- Snapshot/store v7, journal v4, Forget after delivery, pruning drops finished scripts.
- Depth-aware grouped presentation (terminal, TUI, replay) and partial reports on failure.
- Verified with 932 host tests and the 20/20 BPF-LSM codemode gate for 02/04.
  Earlier baseline also passed all CI feature sets and 4/4 durable kernel cases.

Known deliberate limits (documented, not bugs): print output is discarded; no
arbitrary Python async; `submit_flag`, `give_up`, `render` and MCP tools are excluded
from the guest catalog (see 06).
