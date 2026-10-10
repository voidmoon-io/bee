# bee — eBPF-Enforced Sandbox Harness for Coding Agents

bee is a Rust library and CLI that provides kernel-enforced, capability-scoped sandboxing for AI
coding agents. It uses eBPF **LSM** hooks (via [Aya](https://aya-rs.dev)) to enforce per-tool-call and
per-subagent policy — file access control, process-exec allowlisting, and network egress filtering —
without containers, VMs, or namespace overhead.

See [`specs/001-ebpf-agent-sandbox/`](specs/001-ebpf-agent-sandbox/) for the full spec, plan, research,
data model, and contracts.

## Design principles (constitution)

1. **Deny-by-default & fail-closed** — zero capabilities to start; refuse rather than degrade silently.
2. **Capability attenuation** — a subagent policy is *provably* a subset of its parent.
3. **Kernel enforcement is authoritative** — user space compiles/loads/observes; the kernel decides.
4. **Policy-as-data** — declarative, diffable, reviewable TOML is the source of truth.
5. **Library-first, runtime-free core** — the CLI is a thin wrapper; the core needs no async runtime.

## Workspace

| Crate | Role | Status |
|-------|------|--------|
Five packages, one host executable ([ADR-0002](docs/adr/0002-present-bee-as-one-user-facing-application.md)):

```text
Cargo.toml           # workspace root *and* the `bee` application package
src/                 # the harness library (episodes, tools, REPL core, render pipeline)
src/app/             # the application layer: commands, config resolution, session construction
crates/
  core/  common/  userspace/  ebpf/
```

| Package | Role | Status |
|-------|------|--------|
| `bee` (root) | The application and sole host executable, plus the harness library it drives | ✅ host-tested; enforcement behind features |
| `crates/common` | `#[repr(C)]` map layouts + verifier-safe matcher primitives (`no_std`) | ✅ implemented + tested |
| `crates/core` | Policy types, TOML parsing, compiler/glob-lowering, attenuation validator, audit types | ✅ implemented + tested |
| `crates/userspace` | Support detection, cgroup lifecycle, hardened launcher (incl. process hardening, FR-011), engine gating | ✅ host logic tested; ⏳ eBPF attach behind `--features enforce` |
| `crates/ebpf` | LSM programs (`file_open`, `bprm_check_security`, `socket_connect`), built as `bee-lsm` | ⏳ requires nightly bpf toolchain + BPF-LSM kernel |
| `src/intercept` (feature `intercept`) | HTTP(S) interception: the confined `bee proxy-worker`, the exchange store, and the `http_*` tools (019) | ✅ host-tested; ⏳ kernel half on the VM matrix |

The four `crates/` packages stay separate because their runtime, kernel, `no_std`, and BPF-target
constraints earn it. The harness library does not: it has exactly one consumer.

## Build & test

User-space crates build on **stable** Rust:

```bash
cargo build
cargo test          # ~47 unit/integration/property tests (no kernel needed)
cargo clippy --workspace --all-targets
```

Try the CLI (works without a special kernel):

```bash
./target/debug/bee                                                    # help — bare `bee` runs nothing
./target/debug/bee check                                              # kernel support gates
./target/debug/bee validate --policy policies/cargo-test.toml         # prove policy is runnable
./target/debug/bee validate --policy policies/subagent.toml \
                            --parent policies/parent.toml             # attenuation check
```

### The two primary journeys

```bash
# Headless: one agent episode, a batch of them, or a concurrent batch.
./target/debug/bee run --scenario <scenario.toml> --provider <provider.toml>

# Interactive: chat with a sandboxed agent, inline or full-screen.
./target/debug/bee repl --policy <policy.toml> --provider <provider.toml>
```

Both resolve the same **effective configuration** — explicit flags, then `--config <file>`, then
`.bee/config.toml`, then `~/.config/bee/config.toml` — and both refuse to start rather than run
unenforced by accident. A session with no policy needs an explicit `--host`, which says out loud
that tools will run as hardened host processes with no kernel scope. See
[ADR-0001](docs/adr/0001-configuration-files-are-optional.md) and
[ADR-0002](docs/adr/0002-present-bee-as-one-user-facing-application.md).

`bee exec --policy P -- COMMAND` runs a single host command inside a scope. It is a **diagnostic** —
a way to prove a policy enforces with no agent in the picture — and needs a BPF-LSM kernel, so it
fails closed on an ordinary host. `bee metrics` reports recorded usage, cost, and latency.

### Full-screen TUI (optional)

`bee repl` runs the classic inline REPL by default. Build with the `tui` feature and pass `--tui` for
a full-screen chat surface with model-owned live panels (008-grid-tui):

```bash
cargo build --release --features tui
./target/release/bee repl --provider <provider.toml> --tui        # --no-tui forces inline
```

The agent can address a rendered widget to a named side panel with `render_to("metrics", widget)`
(and `render_to_ttl` / `remove_panel` / `clear_panels` to manage them); an untargeted `render(widget)`
still flows inline. `--tui` degrades honestly — piped output, `TERM=dumb`, or a terminal below 40×10
fall back to the inline REPL with a one-line note. The feature is **off by default**, so the standard
build pulls in no terminal backend.

Assistant replies render as **markdown** once the message finishes streaming — headings, emphasis,
lists, links and code, styled through the active theme's semantic roles rather than a second palette.
A skill's instructions render the same way when you `/skill <name>`, and the agent can emit a block
itself with `markdown(source)` in a render script.

Keys: `↑`/`↓` and the mouse wheel scroll the conversation (they move the cursor first when the input
holds a `Shift+Enter` newline), `PgUp`/`PgDn` page it, `gg`/`G` jump to the ends, `Ctrl-P`/`Ctrl-N`
walk input history, `Tab` focus, `p` panel overlay on narrow terminals, `y` yank, `?` help, `q` quit.
Mouse reporting is on so the wheel works, which means drag-to-select is the terminal's `Shift`-click
gesture there.

## Security analysis tooling (opt-in)

Tools for using an agent to *review* code, rather than only to write it. All default-off: a build
that selects none of them has the dependency graph it had before they existed.

```bash
cargo build --features sec,astgrep-rust,astgrep-python   # everything, with two grammars
cargo build --features findings                          # just the ledger
cargo build --features astgrep,astgrep-rust              # just structural search, one grammar
```

| Feature | Tool | What it is |
|---|---|---|
| `astgrep` + `astgrep-<lang>` | `ast_grep` | Structural search over the parse tree, so a match in a comment or a string literal is not a match. One feature per grammar — each is compiled C, so a build pays only for the languages it scans. |
| `findings` | `record_finding`, `list_findings` | The durable finding ledger. |
| `cvss` | `cvss` | Severity **computed** from a vector, never asserted by the model. |
| `scanners` | `scan` | External scanner adapters — Opengrep for pattern rules, CodeQL for whole-program analysis. Implies `findings`. |
| `gitlog` | `git_log` | Repository history via `gix` — `log` for the commits touching a path, `blame` for the commit that introduced one line. Read-only; runs in a scope-joined child like every other file tool, because `.git` is a directory of files. |
| `sec` | — | Umbrella for all of the above. Grammars stay explicit. |

**Two tiers, one rule.** When the value is the *engine*, bee links the crate and runs it as a
scope-joined child. When the value is a curated *rule corpus*, bee drives the third-party binary
instead of reimplementing it — under an inode-pinned `exec.allow` grant, with argv built from typed
inputs. The model chooses what to scan; never how the scanner is configured.

```toml
# policy — the capability
[exec]
allow = ["!/home/you/.local/bin/opengrep"]      # `!` pins the inode

# config — how the granted binary is configured (operator-only)
[security.scanners.opengrep]
rules = "/etc/bee/opengrep-rules"               # `auto` is refused: a scanning scope has no egress
```

**CodeQL is the same shape, plus a version pin.** The grant names the bundle's own CLI; the pin is
verified by running it before anything is analysed, so a bundle that is not the one the operator
provisioned is an explicit unavailability rather than a thin set of results.

```toml
[exec]
allow = ["!/opt/codeql-bundle/codeql/codeql"]

[security.scanners.codeql]
bundle_version = "codeql-bundle-v2.26.1"        # or "2.26.1" — either spelling of the same pin
```

Databases are built one way, `--build-mode=none`, so `actions`, `csharp`, `java`, `javascript`,
`python`, and `ruby` are analysable and everything else is **declined by name**. Extracting a
compiled language means intercepting the build's process spawns, which would mean admitting every
compiler and linker that build happens to invoke — an unbounded widening of the very scope bee
exists to hold. Half-support would be worse than none: a thin database yields few findings, which
reads exactly like clean code.

**Findings outlive the session.** They land in `.bee/findings/ledger.jsonl` — append-only, one JSON
object per line, meant to be committed and reviewed in a pull request. Re-running merges rather than
duplicating, and identity excludes the line number so code movement does not mint a duplicate.

```bash
./target/debug/bee findings list
./target/debug/bee findings adjudicate <id> --state false-positive --note "sanitised upstream"
```

Adjudication is CLI-only and has no tool equivalent: an agent can record what it saw, and only a
person can rule on it. A later automated rediscovery appends a sighting and cannot clear the verdict.

**Every tool answers in three states** — completed, could-not-run, or failed. A missing binary, an
ungranted scanner, a substituted binary, a timeout, or an unparseable report each say so explicitly.
None of them can render as "scanned, found nothing", because a security tool that reports no issues
when it did not run is worse than one that was never installed.

> **MSRV note.** The application package declares Rust **1.88** (`ast-grep-core`'s floor). The
> embeddable crates — `bee-core`, `bee-common`, `bee-userspace` — keep **1.85**.

## HTTP(S) interception (opt-in, `intercept`)

For testing web applications in scope: an interception proxy the agent drives through tools, whose
target scope the kernel holds rather than a filter over a history view.

```bash
cargo build --features intercept            # host tier
cargo build --features intercept,enforce    # kernel-enforced
```

```toml
[policy.http]
targets = ["app.test:443", "10.20.0.5:8080"]   # may be tested
egress  = ["index.crates.io:443"]              # reachable as a tunnel, never testable
inspect = ["app.test"]                         # decrypt TLS for these hosts only
```

With `[policy.http]` present, tool children reach **only** the session proxy, and the proxy, in its
own kernel scope, reaches only the resolved targets and egress hosts. The proxy adds the checks an
address cannot express: host name, CONNECT host = SNI, the `Host` header, the role, and pacing. It
labels which layer enforces every rule. A session whose kernel would not block (host mode, a build
without `enforce`, an observe-mode policy) refuses to start unless you pass `--http-scope-advisory`.

| Tool | What it does |
|---|---|
| `http_scope` | What may be tested, what is only reachable, and which layer enforces each rule. Read-only. |
| `http_send` | One request, structured or **byte-exact raw**; returns an exchange id and a bounded preview. |
| `http_get` | One bounded view of an exchange: headers, a decoded byte range, a grep, a JSON pointer, the raw head. |
| `http_history` | Typed filters over recorded traffic, as compact rows. |
| `http_replay` | Re-send with edits and get a **measured** diff (a noise probe suppresses volatile values). |
| `http_sitemap` | A tree of paths, methods, statuses and parameter names seen. |
| `http_fuzz` | Marker templates × payload sets within the policy's limits, answered with clusters and outliers. |
| `http_intercept` | Session-only modify/drop/hold rules over other tools' traffic. |
| `http_leads` | Passive leads noticed in traffic. Leads are not findings. |

Widening the target scope is the operator's call: a refused host becomes a consent prompt naming
exactly that `host:port`, bounded by the ceiling. `bee http export --har` writes HAR 1.2 with proxy
credentials stripped. The walkthrough is `specs/019-http-intercept/quickstart.md`.

## Kernel requirements (for enforcement)

The `enforce` feature and the `crates/ebpf` package require:

* Linux **≥ 5.7** with `CONFIG_BPF_LSM=y` and `CONFIG_DEBUG_INFO_BTF=y`,
* **`bpf` in the active LSM list** — check `cat /sys/kernel/security/lsm` for a `bpf` token; if absent,
  add `lsm=...,bpf` to the kernel cmdline and reboot (`CONFIG_BPF_LSM=y` alone is *not* sufficient),
* **cgroup v2** unified hierarchy, and
* the nightly bpf toolchain: `rustup toolchain install nightly --component rust-src` and
  `cargo install bpf-linker` (LLVM version matched to the pinned nightly — the top build-break risk).

`bee check` verifies these gates and **fails closed** (exit 65) when enforcement is unavailable, so bee
never runs with silently-absent enforcement.

## Caveats worth knowing

* **Policy preparation has two stages.** `bee-core` compiles author intent into a backend-neutral
  `CompiledPolicy`; `bee-userspace` must then produce an eBPF `EnforcementPlan` before any kernel state
  is touched. `bee validate` runs both stages, so success means the policy is runnable by this backend.
* **Current eBPF glob support** is exact/subtree plus postfix (`*.ext`). Segment (`**/name`) and
  bounded-star patterns are normalized by the core but rejected during enforcement planning, as are
  inode-pinned executables and enabled exfiltration detection. Nothing is silently weakened.
* **Path matching sees resolved paths.** LSM hooks fire after path resolution, so enforcement is
  TOCTOU-resistant, but a rule written against a *symlink's* name won't match its target, and name-based
  rules don't catch hard links / alternate bind mounts to the same inode. Inode-pinned rules are not
  yet implemented and are rejected during enforcement planning.
* **Capabilities** to load LSM programs: `CAP_BPF + CAP_PERFMON` (possibly `+ CAP_MAC_ADMIN`) or
  `CAP_SYS_ADMIN`. The exact minimal set is kernel-version-dependent — verify empirically per target.

## Not in the MVP

Exfiltration detection (US3), the Landlock+seccomp degraded fallback, macOS/Windows, and behavior when
bee runs inside an existing container are out of scope for the MVP (see the spec's assumptions).

## License

MIT OR Apache-2.0
