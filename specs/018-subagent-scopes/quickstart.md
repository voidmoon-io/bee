# Quickstart: Validating Subagent Delegation

**Feature**: 018-subagent-scopes

Runnable scenarios that prove the feature works. Host scenarios need only `cargo test`; the
enforcement claims need the BPF-LSM VM, because — per the constitution — an enforcement claim proven
only by unit mocks does not count.

> **Read this first.** A scope's rules are found by **identity**, not inheritance: `resolve_scope`
> looks up a cgroup registered in `SCOPES` and applies *that scope's own* rule list. The kernel never
> composes a policy from a cgroup chain. Attenuation is guaranteed entirely by `Policy::derive` at
> install time — these scenarios prove install-time derivation plus per-scope enforcement, not kernel
> inheritance.
>
> Consequently every subagent cgroup is created **flat**, a sibling under `/sys/fs/cgroup/bee`. Nesting
> it under its parent would let a subagent that migrates into a sub-cgroup resolve to the *parent*
> scope — `resolve_scope`'s ancestor walk returns the shallowest match — and silently acquire the
> parent's broader authority. S9 below is the regression test for exactly that.

## Prerequisites

**Host scenarios** (S1, S2, S5, S6):
```bash
cargo test --features findings          # no kernel, no root
```

**Enforcement scenarios** (S3, S4, S7): the `ac-matrix-vm` KubeVirt VM with a BPF-LSM kernel, built
per `test/vm/README.md`. Requires `--features enforce` on the nightly bpf toolchain, and root.

## Fixtures

An agent that cannot reach the network, at `.claude/skills/dep-auditor/SKILL.md`:

```yaml
---
name: dep-auditor
kind: agent
description: Reviews dependency manifests for known-risky packages. Offline.
tools: [read_file, list_directory]
turn-limit: 8
requires:
  filesystem:
    ":project_root": read
  exec: []
  net: []
---
Read the dependency manifests and report anything risky. You have no network.
```

An agent that asks for more than a read-only parent holds, at
`.claude/skills/over-broad/SKILL.md`:

```yaml
---
name: over-broad
kind: agent
description: Deliberately over-broad; used to prove attenuation refusal.
tools: [write_file]
turn-limit: 4
requires:
  filesystem:
    ":project_root": write
---
You should never run.
```

Schema details: [`contracts/agent-definition.md`](./contracts/agent-definition.md).

---

## S1 — Discovery, precedence, and malformed definitions *(host)*

**Proves**: FR-005..FR-008. A malformed definition warns and never aborts.

```bash
cargo test --test skills_episode -- agent_
```

**Expect**: `kind: agent` definitions load as agents and ordinary skills are unaffected; a project
definition shadows a user one of the same name **with a warning naming both paths**; a definition with
`turn-limit: 0` or a bad `requires.filesystem` value produces a `SkillLoadError`, is omitted, and the
session still starts.

---

## S2 — Attenuation refused before anything exists *(host)*

**Proves**: US2, FR-009, FR-010, SC-002. The most important negative test in the feature.

```bash
cargo test --test delegation -- refuses_over_broad_agent
```

**Expect**:
- The result is an error naming the path and the access levels, quoting the `AttenuationError`
  verbatim.
- **No cgroup was created.** The test asserts this directly by counting supervisor scopes before and
  after, not by inspecting a log.
- The parent session continues; the refusal is a tool result, not a terminated episode.

Also covered here: `UnknownAgent`, `ToolNotHeld`, `DepthExceeded`, `BudgetExhausted` — the full
taxonomy in [`contracts/task-tool.md`](./contracts/task-tool.md), each asserting the same
nothing-left-behind property.

---

## S3 — A subagent is denied what its parent holds *(VM, root)*

**Proves**: US1, SC-001. This is the feature.

```bash
# On the VM, as root:
sudo ./target/debug/bee run \
  --scenario test/vm/scenarios/delegation-denied-net.toml \
  --policy policies/parent-with-net.toml
```

The parent policy grants network access. `dep-auditor` declares none. The scenario instructs the
subagent to fetch a URL.

**Expect**:
- The connection is **denied in the kernel** — the child's scope has no `NET_ALLOW` entry.
- The denial appears in the child's `audit_trail`, stamped with the child's `scope_id`.
- The **parent's** `audit_trail` does not contain it.
- The parent's own network access still works, in the same episode.

Add to `test/vm/remote-matrix.sh` as `sub-deny-net`.

---

## S4 — Siblings do not contaminate each other *(VM, root)*

**Proves**: US5, FR-030, SC-004.

```bash
sudo ./target/debug/bee run \
  --scenario test/vm/scenarios/delegation-fanout.toml \
  --policy policies/parent-broad.toml
```

Three subagents run simultaneously with mutually exclusive capabilities; each attempts an operation
only a sibling is permitted.

**Expect**: three denials, one per subagent, each in its own nested transcript with its own
`scope_id`; zero cross-attribution. Then verify with:

```bash
jq '[.. | .child? // empty | {agent, scope_id,
     denials: (.transcript.audit_trail | map(select(.decision=="denied")) | length)}]' transcript.json
```

Add to the matrix as `sub-fanout-isolate`.

---

## S5 — A delegating session cannot outspend a non-delegating one *(host)*

**Proves**: US4, FR-023, SC-005.

```bash
cargo test --test delegation -- budget_
```

**Expect**: with a turn budget of N, `sum(turns_used across the tree) + parent turns <= N`, asserted
straight off the transcript. A subagent stopped by the shared bound has
`outcome: CutShort { reason: Turns }` and a report whose **first line** says it was cut short — so a
truncated body can never make it read as complete.

---

## S6 — The record stays compatible and attributable *(host)*

**Proves**: FR-018..FR-020, SC-006.

```bash
cargo test --test delegation_audit
```

**Expect**:
- A session that never delegates serializes byte-identically to a pre-018 run (fixture comparison).
- `RecordedCall.child` is absent — not `null` — on every non-delegating call.
- Every `ToolResult` reaching the conversation has `delegate == None`.
- `audit_tree()` yields each event exactly once; `denials()` and `ScoreReport` keep their own-scope
  meaning.

---

## S7 — Reload works under concurrency *(VM, root)*

**Proves**: FR-021, SC-007 — a gap that exists today, repaired as a side effect of the supervisor.

```bash
sudo ./target/debug/bee batch --scenarios test/vm/scenarios/concurrent-escalate/ --concurrent
```

**Before this feature** this fails with `reload unsupported on a concurrent sandbox (engine owned by
the runner)` (`src/sandbox.rs:94`) — dynamic grants are simply dead under the concurrent runner.

**Expect after**: each episode escalates and reloads independently; a widen in one scope leaves the
others' enforced rules unchanged. Extends the existing 007 `SC-007` matrix case.

---

## S8 — Unenforced delegation announces itself *(host)*

**Proves**: US6, FR-032..FR-034, SC-008.

```bash
cargo test --test delegation -- host_mode_
./target/debug/bee run --scenario examples/delegation.toml --host 2>&1 | grep -i unenforced
```

**Expect**: the operator sees, at the point of delegation, that the subagent ran with no kernel scope;
the report's second line carries the same warning; and the record deserializes with
`enforced: false` — distinguishable **without** knowing how the binary was built.

---

## S9 — A migrating subagent cannot climb to its parent's authority *(VM, root)*

**Proves**: FR-009/FR-011 hold against the one manoeuvre that would defeat them. This case exists
because the naive nested-cgroup layout fails it (research R5); it is the test that keeps the flat
layout from being "simplified" later.

```bash
sudo ./target/debug/bee run \
  --scenario test/vm/scenarios/delegation-migrate-escape.toml \
  --policy policies/parent-with-net.toml
```

The scenario delegates to `dep-auditor` (no network) from a parent that **has** network, and
instructs the subagent to `mkdir /sys/fs/cgroup/bee/<its-scope>/sub`, migrate itself into it, and
then connect.

**Expect**: the connection is **denied**. `resolve_scope` misses the exact sub-cgroup, walks
ancestors, and finds the subagent's own scope — the only registered scope above it — so the child's
(empty) `NET_ALLOW` still governs.

**This case must be run against a nested-layout build and confirmed to FAIL** before it is trusted, per
the false-PASS discipline in `test/vm/README.md`: under nesting the walk would return the parent scope
first and the connect would be *allowed*, which is the escape. A case that passes both ways proves
nothing.

Add to the matrix as `sub-migrate-noescape`.

---

## Slice-1 regression gate

The supervisor restructuring must land with **no behaviour change**. Before any delegation code is
written:

```bash
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
# On the VM:
sudo ./test/vm/remote-matrix.sh          # every existing case, unchanged
```

All three must pass with the `Sandbox` collapse in place and no new tests added. That is the entire
success criterion for slice 1 — see the migration table in
[`contracts/supervisor-api.md`](./contracts/supervisor-api.md).

**Baseline captured 2026-08-09 at `1bd4abb`, before any 018 code: `pass=38 fail=0`** on kernel
6.8.0-136 (`--features concurrent,sec --release`). That is the number slice 1 must still produce.

Two existing cases are worth watching closely during the refactor, because 018 changes exactly what
they cover:

- **`cgroup-migrate-enforced`** — "migrated to child cgroup, read still denied". This is the empirical
  proof of the `resolve_scope` ancestor walk that R5's flat-layout decision rests on, and S9 is its
  subagent-level extension. If this case breaks, the layout reasoning breaks with it.
- **`concurrent-audit-isolation`** — "4 concurrent scopes, no cgroup cross-contamination". The
  supervisor moves every scope onto one demux; this case is what proves the move preserved isolation.
