# Contract: Agent Definition

**Feature**: 018-subagent-scopes | Consumers: `src/skills.rs`, `src/tools/task.rs`, `src/delegate.rs`

An agent definition is a `SKILL.md` with `kind: agent`. It is discovered by the existing skill pass,
in the existing roots, with the existing warning behaviour. Nothing here introduces a second loader.

## File location and precedence

Discovered by `SkillRegistry::discover` over `SkillRegistry::default_roots(cwd)`:

1. `<project>/.claude/skills/<dir>/SKILL.md` — **wins** a name clash
2. `~/.claude/skills/<dir>/SKILL.md`

A shadowed definition emits a warning naming both paths. It is never silently dropped.

## Frontmatter schema

```yaml
---
name: test-runner                    # required, unique; the `task` tool's `agent` argument
kind: agent                          # required to be delegable; absent or `skill` ⇒ ordinary skill
description: >                       # required; the ONLY text the delegating model sees
  Runs the test suite in an isolated scratch directory and reports failures verbatim.
tools: [bash, read_file]             # required (may be empty); ⊆ the parent's registry at spawn
turn-limit: 12                       # required; effective cap is min(this, budget remaining)
requires:                            # optional; absent ⇒ inherit the parent's policy wholesale
  filesystem:
    ":project_root": read
    ":project_root/target": write
  exec: ["/usr/bin/cargo"]            # a subset of the parent's; omit to inherit
---
You run the test suite and nothing else. Report failures verbatim, with the
command that produced them. Do not attempt to fix anything.
```

The body after the frontmatter is the child's **instructions** — its system prompt. It is read lazily,
host-side, exactly as a skill body is (`Skill::body`).

### Field rules

| Field | Required | Rule |
|---|---|---|
| `name` | yes | Non-empty. The delegation argument and the record's `agent`. |
| `kind` | yes (for agents) | `agent`. Any other value, or absent, is an ordinary skill — existing definitions are unaffected. |
| `description` | yes | Non-empty. Injected verbatim into the `task` tool's schema so the model can choose. Never truncated. |
| `tools` | yes | May be empty (an agent that only reasons). Every name must be a tool the **parent holds at delegation time**. |
| `turn-limit` | yes | `u32 >= 1`. Kebab-case, matching the frontmatter convention already used for `user-invocable`. |
| `requires.filesystem` | no | `path -> read \| write \| deny`. Same vocabulary as a bee policy. |
| `requires.exec` | no | Absolute program paths, as in `ExecPolicy.allow`. A non-empty subset of the parent's; **an explicit empty list is malformed** (see below). |
| `requires.net` | no | `host:port` entries, as in `NetworkPolicy.allow`. A non-empty subset of the parent's; **an explicit empty list is malformed**. |

**Why `net: []` is refused (2026-11-09).** A child policy that states no rule for a dimension
inherits the parent's (`Policy::derive`), and the kernel cannot yet install "no destinations" or "no
executables" — egress is enforced only when at least one allow rule exists. So `net: []` would
silently hand the child the parent's network under a declaration that reads as its opposite. Until
bee can enforce "none", the loader refuses it and says why; omit the key to inherit, or list a subset.
| `requires.tools` | no | **Ignored for agents.** An agent's tool set is the top-level `tools` key; carrying two sources would let them disagree. Present-and-non-empty is a malformed-definition warning. |

Unknown keys are tolerated, as they are for skills, so definitions authored for other ecosystems load.

## Discovery-time validation

A definition failing any of these produces a `SkillLoadError` warning, is omitted from the registry,
and **does not abort the session**:

1. Frontmatter does not parse.
2. `kind: agent` with a missing or empty `name`, `description`, or `turn-limit`.
3. `turn-limit` is `0`.
4. A `requires.filesystem` value outside `read` / `write` / `deny`.
5. `requires.tools` present and non-empty on an agent.

**Deliberately not validated here**: whether the declaration is within any parent's authority. The
same definition is legitimately usable from parents of differing authority, and no session's active
policy is known at discovery. Attenuation is per-delegation — see `task-tool.md`.

## What the model sees

The `task` tool's schema enumerates the discovered agents by `name` with their `description`. The
model sees **no** capability information: not the tool list, not the `requires` block, not the turn
limit. It chooses *what work to delegate to whom*, never *what authority to grant*.

## Semantics of an omitted rule

`requires` is **subtractive**, because `Policy::derive` closes what a request leaves unsaid:

- A definition with **no** `requires` block inherits the parent's policy wholesale.
- A definition that states filesystem rules keeps them **and re-acquires every parent `deny`**.
- A rule the definition never mentions is a parent restriction the child still carries.

So an author narrows by *stating less about what they need*, and can never widen by omission
(FR-011). This is existing `derive` behaviour (`crates/core/src/attenuation.rs`), not new logic.

## Example: an agent that cannot reach the network

```yaml
---
name: dep-auditor
kind: agent
description: Reviews dependency manifests for known-risky packages. Offline.
tools: [read_file, list_directory, search]
turn-limit: 20
requires:
  filesystem:
    ":project_root": read
---
Read the dependency manifests and report anything you would not want in a
production build. You have no shell; do not ask for one.
```

Delegated from a session that *does* hold network access, this child is denied every outbound
connection in the kernel — not because it was told not to, but because its scope has no `NET_ALLOW`
entry. That denial is the acceptance test for US1.

## External harnesses (026)

An agent with a `runtime.acp` block (`command`, `args`, `env`) is run as an external harness —
Claude Code, Codex, OpenCode — spoken to over ACP inside its own kernel scope, rather than by bee's
loop. It takes no `tools`, and `turn-limit` is ignored. Its `requires.net` entries are provider hosts
by name, routed to a proxy scope of its own. See `specs/026-acp/contracts/harness-runtime.md`.
