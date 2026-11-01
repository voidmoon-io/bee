# Exec rules and symlinked binaries (`sh` → `dash`)

Status: needs-triage

Found: 2026-10-31, `kernel_codemode_shell_policy` VM case.

## Problem

Unpinned exec allow rules match the executed file's **path** (`bprm->file` via
`bpf_d_path`, `crates/ebpf/src/main.rs`). `SystemResolver::resolve_exec`
(`crates/userspace/src/resolve.rs`) returns the PATH hit without canonicalizing it. On
Ubuntu, `allow = ["sh"]` resolves to `/usr/bin/sh`, but the kernel sees
`/usr/bin/dash`, so `sh` is denied (`EACCES`). The `bash` tool runs `sh -c`. The test
fixture works around this by allowing the canonical path.

## Decision needed

1. **Canonicalize at compile time.** `sh` becomes `/usr/bin/dash`. Convenient, but it
   quietly widens the rule: allowing `sh` also allows running `dash` directly, plus any
   other link that points to the same target.
2. **Keep strict matching and document it** in the policy docs and `bee check` output.
3. **Warn when an allowed name is a symlink.** Have `bee check` / policy compile warn and
   name the target to add.

Recommendation: 3, optionally with 1 behind an explicit opt-in. Whichever is chosen,
add a VM matrix case for a symlinked allowlist entry.
