# comb

bee's HTTP(S) interceptor as a library and a standalone binary. It provides a scoped forward proxy with optional TLS inspection, plus a SQLite exchange store with content-addressed bodies. On top of the store it offers send, replay with a measured diff, fuzzing, intercept rules, a sitemap, passive leads, history queries and HAR export.

bee uses the library directly; its `http_*` tools are thin adapters over `comb::api`. Other harnesses run the `comb` binary and get the same tools through JSON lines.

## Enforcement: read this first

Under bee, the proxy worker runs inside a kernel (BPF-LSM) scope, and tool children can reach only the proxy. The kernel enforces addresses; the proxy enforces host names, SNI and roles.

**Standalone `comb` has no kernel scope.** It enforces scope by host name in user space, and nothing stops a client from connecting to a target directly. Containment is the host's job: for example a gVisor sandbox or a network policy that allows clients to reach only the proxy port. Every result says `"enforcement": "advisory"` and never claims kernel enforcement.

## Scope

The scope is a bee policy file. Only its `[policy.http]` table is used:

```toml
[policy]
name = "engagement-42"

[policy.http]
targets = ["app.example.com:443", "127.0.0.1:8080"]   # testable
egress  = ["cdn.example.net:443"]                     # tunnelled only, never tested
inspect = ["app.example.com"]                         # TLS-decrypted (needs the CA bundle)
```

The pacing limits (`rps`, `concurrency`, `max_requests_per_run`, store cap) are the same keys bee reads.

## `comb serve`

```
comb serve --policy policy.toml [--project DIR] [--session ID] [--listen 127.0.0.1:0] [--ca-bundle PATH]
```

This runs one session. The store is `DIR/.bee/http/` and outlives the session. `--listen` must be a loopback address.

stdin takes one JSON request per line. stdout carries one JSON response or event per line. Requests run concurrently, so responses can arrive out of order; each one echoes its request's `id`. EOF on stdin, or `{"op":"shutdown"}`, ends the session.

### First line: `ready`

```json
{"event":"ready","session":"comb-1a2b3c4d5e6f","port":41231,"proxy":"http://127.0.0.1:41231",
 "store":"/work/.bee/http","ca_bundle":"/run/user/1000/comb/comb-…/ca-bundle.pem",
 "enforcement":"advisory","enforcement_reason":"…","tools":["http_scope","http_send",…]}
```

### Requests

| op | fields | result |
|---|---|---|
| `tools` | | tool definitions: `[{name, description, parameters}]`, where `parameters` is the JSON Schema to give your model |
| `call` | `tool`, `args`, optional `call_id`, `turn` | `{text, source, is_error}` |
| `credential` | `call_id` | `{call_id, proxy_url, env}`: the per-call proxy credential and the environment that routes a child process through it |
| `revoke` | `call_id` | `{call_id, proxy_events}`: ends the credential and returns what the proxy refused during the call |
| `shutdown` | | `{}` |

Responses look like `{"id":…, "ok":true, "result":…}` or `{"id":…, "ok":false, "error":{"code","message"}}`. These are the error codes:
- `invalid_args`: the model's to fix.
- `refused`: with `refusal: {kind: out_of_scope | egress_only | limit_exceeded, …}`.
- `interceptor_unavailable`
- `failed`
- `not_granted`
- `unknown_tool`
- `bad_request`

### Events

| event | meaning |
|---|---|
| `{"event":"proxy_event","data":{…}}` | a refusal, rule firing or hold, as it happens |
| `{"event":"notice","text":…}` | an operator notice (worker restart, store eviction) |

### Tool results are untrusted data

`result.text` is bounded JSON. When `result.source` is set (`http:<id>`), the text contains bytes a target controls. Give it to a model as untrusted data inside a delimited envelope, never as instructions.

### Routing your own tools through the proxy

Call `credential` with the tool call's id before running the tool, and pass the returned `env` to the child. It sets `HTTP(S)_PROXY`, `ALL_PROXY`, an empty `NO_PROXY`, and the CA variables when anything is inspected. Call `revoke` when the tool call ends. A revoked token is useless, so one leaked into a log cannot be replayed. Traffic without a live credential gets a `407` and is not forwarded.

The proxy records forwarded traffic like any other exchange, attributed to the `call_id` (`origin: "forwarded"`). `http_intercept` rules apply to it.

## Offline

```
comb history [--project DIR] '{"host":"app.example.com","status_range":[500,599]}'
comb har     [--project DIR] '{"call_id":"toolu_01…"}' > run.har
comb tools
```

`history` and `har` open the store read-only. They see every session unless the filter sets `"all_sessions": false`.
