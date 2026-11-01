# Land PR #49

Status: ready-for-human

PR: https://github.com/voidmoon-io/bee/pull/49 (`feat/023-codemode` → `main`)

## What remains

- **CI.** On open, rustfmt passed; build & test, clippy, durable investigation recovery
  and enforce type-check were still running. Local runs of every CI command passed.
- **`main` was already red** before this PR: the `mcp,sec,astgrep-rust` clippy job
  (dead `EvidenceStore::forget_committed`, fixed in #49 by gating it on
  `durable-sessions`) and the "durable investigation recovery" job, whose cause was not
  identified. `test/durable-investigation.sh` passes locally on #49. If that job still fails
  on #49, compare with main's run 41223354592 before blaming the PR.
- **Review the user-visible breaks:**
  - Rhai render scripts are rejected; Python (Monty) is the only visual language.
    Migration guide: `docs/python-visuals.md`.
  - The `bee` application package needs Rust 1.96 (Monty's MSRV). Core crates keep 1.85.
  - Durable stores open as v7 and journals as v3; older Bee builds refuse them.
- **Review the integration points:** `src/session/driver/execution.rs` (codemode
  dispatch, `parent_call_id`, overlap call — both boxed to keep the drive future off the
  test-thread stack), `mod.rs` (cancel cascade, journal upgrade, partial report),
  `durable/composition.rs` (Forget, `forget_pruned`).

## Done when

PR merged with green CI, or a CI failure is shown to be pre-existing on `main`.
