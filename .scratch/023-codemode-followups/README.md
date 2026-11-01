# 023 codemode — remaining work

Created: 2026-10-31. Baseline: PR #49 (merged 2026-11-01 as `f59e240`), which landed
Python visual scripts, durable script compositions and the codemode driver on `main`.
Design and verification: [`specs/023-codemode/`](../../specs/023-codemode/), especially
[`parallel-nesting-plan.md`](../../specs/023-codemode/parallel-nesting-plan.md).

| # | Issue | Status | Size |
| --- | --- | --- | --- |
| 01 | [Land PR #49](issues/01-land-pr-49.md) | done (merged `f59e240`) | — |
| 02 | [Overlap batch calls under kernel enforcement](issues/02-enforced-batch-overlap.md) | ready-for-agent | L |
| 03 | [Exec rules and symlinked binaries (`sh` → `dash`)](issues/03-exec-symlink-policy.md) | needs-triage | S–M |
| 04 | [Indent nested calls by depth in the TUI](issues/04-tui-nesting-depth.md) | ready-for-agent | S |
| 05 | [Validate codemode with a real model](issues/05-real-model-validation.md) | ready-for-human | M |
| 06 | [Widen the guest catalog: MCP and terminal tools](issues/06-catalog-mcp-terminal.md) | needs-triage | M |
| 07 | [Retire the pre-port branches and local backups](issues/07-retire-old-branches.md) | ready-for-human | S |

Order: 02 builds on `main` now that #49 is merged. 03 and 04 are independent. 05 needs
provider keys and spend. 06 needs a contract decision before any code. 07 can start now.

## What is already done (not tracked here)

- `call_tool`, `call_tools` (1–4 calls, one commit, ordered results), nested `codemode`
  (≤4 levels, shared 32-call / 64-invocation limits), host-mode overlap.
- Snapshot/store v7, journal v3, Forget after delivery, pruning drops finished scripts.
- Grouped presentation (terminal, TUI, replay) and partial reports on failure.
- Verified on host (all CI feature sets) and on the BPF-LSM VM (17/17 codemode,
  4/4 durable cases) on 2026-10-31.

Known deliberate limits (documented, not bugs): print output is discarded; no
arbitrary Python async; `submit_flag`, `give_up`, `render` and MCP tools are excluded
from the guest catalog (see 06).
