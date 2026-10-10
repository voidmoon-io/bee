# Contract: `[policy.http]` — target scope as policy data

Types: [data-model.md § HttpPolicy](../data-model.md#httppolicy-in-policy-section-policyhttp).
Rationale: [research R4, R5](../research.md#r5--policy-schema-policyhttp-in-bee-core).

## Example

```toml
[policy]
name = "pentest-app"
mode = "enforce"

[policy.filesystem]
":project_root" = "read"

[policy.exec]
allow = ["curl", "sh"]

# NOTE: no [policy.network] — when [policy.http] is present, tool children reach only the proxy.

[policy.http]
targets = ["app.test:443", "app.test:80", "10.20.0.5:8080"]
egress  = ["index.crates.io:443"]          # reachable via proxy tunnel; never testable
inspect = ["app.test"]                     # decrypt TLS for these hosts only
insecure_upstream = []                     # verify upstream certificates

[policy.http.limits]
rps = 10
concurrency = 4
max_requests_per_run = 2000
max_body_bytes = 16777216
store_cap_bytes = 2147483648
```

## Compile-time guarantees

| Condition | Result |
|---|---|
| Unknown key anywhere in `[policy.http]` | `CompileError::UnknownField` |
| `targets` and `[policy.network].allow` both non-empty | `CompileError::HttpWithDirectNetwork` |
| `inspect` pattern matching no target | `CompileError::InspectOutsideTargets` |
| `insecure_upstream ⊄ inspect` | `CompileError::InsecureOutsideInspect` |
| Host in both `targets` and `egress` | `CompileError::HostRoleConflict` |
| Unresolvable host | `CompileError::UnresolvableHost` (existing) |
| Any limit = 0 | `CompileError::ZeroLimit` |

## Derived enforcement

| Scope | Network rules installed in the kernel |
|---|---|
| Tool scope | exactly `127.0.0.1:<proxy-port>` (synthesised; port from the harness-bound listener) |
| Proxy scope | `resolve(h):p` for every `h:p` in `targets ∪ egress` |

| Scope | Filesystem rules installed in the kernel (deny-list model, research R2) |
|---|---|
| Tool scope | the policy's own `[policy.filesystem]` + `PROTECTED_DEFAULTS` (includes `.bee/`) + read of the session CA bundle |
| Proxy scope | `FLAG_FS_WRITE_DEFAULT_DENY`; read-deny `:project_root`, `$HOME`, `/home`, `/root`, protected credential dirs; **exact read-allow of the worker binary** (outranks the prefix denies, so exec works from `target/` or `/home`) |

**MCP stdio servers** share the tool scope, so with `[policy.http]` present they too reach only the
proxy. Their traffic is attributed to `mcp:<server>`, and any host they need must be listed in
`targets` or `egress`.

| Check | Layer |
|---|---|
| Tool child reaches only the proxy | **Kernel** |
| Proxy reaches only resolved target/egress addresses | **Kernel** |
| Host name ∈ scope; CONNECT host = SNI; egress not testable; limits | **Proxy** (user space) |

## CLI

- `bee validate --policy child.toml --parent parent.toml` covers `[policy.http]` attenuation with no
  new flags.
- `--http-scope-advisory` (run/repl): required to start a session with `[policy.http]` without
  *blocking* kernel enforcement: host mode, a non-`enforce` build, or `mode = "observe"`. Not settable from any configuration file.
