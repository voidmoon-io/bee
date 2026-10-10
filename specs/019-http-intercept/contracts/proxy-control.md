# Contract: harness ↔ `bee proxy-worker` control channel

Rationale: [research R2, R3, R4](../research.md#r3--harness--worker-control-channel).

## Process contract

- Spawned once per session by the harness as `bee proxy-worker --session <id>` (hidden subcommand),
  joined to the **proxy scope**, with the environment stripped as for every child.
- **fd 3** is a listening TCP socket bound to `127.0.0.1:<port>` by the harness. The worker exits
  with status 2 if fd 3 is missing, not listening, or not IPv4 loopback.
- No other inherited descriptors. No filesystem writes (proxy scope is write-default-deny; reads of project/home/credential paths are
  kernel-denied — research R2). `kill_on_drop`; the harness kills it before
  removing the proxy scope.
- If the worker exits, every HTTP tool returns `Unavailable { interceptor_unavailable }` and tool
  children's traffic fails (kernel: they can reach nothing else). The harness does **not** restart it
  silently: it restarts at most once per session, announcing the restart, then gives up.

## Framing

Each frame: 4-byte big-endian length `L`, then `L` bytes of UTF-8 JSON, optionally followed by binary
segments declared in the JSON (`"segments": [len, …]`), each sent raw immediately after. Max JSON
frame 1 MiB; max segment = `limits.max_body_bytes`. Malformed frame → the receiver closes the
channel (fail closed).

## Harness → worker

| Frame | Fields | Reply |
|---|---|---|
| `init` | `http_scope`, `limits`, `session_id` | `hello` |
| `creds.issue` | `token`, `ctx {call_id, turn, origin}` | `ack` |
| `creds.revoke` | `token` | `ack` |
| `scope.update` | new `http_scope` (after kernel reload) | `ack` / `error` |
| `send` | `req_id`, `raw {scheme, host, port, bytes}`, `timeout_ms`, `ctx` | `exchange` |
| `fuzz.start` | `run_id`, `variants` (streamed in batches of ≤256), effective limits, `ctx` | `exchange`… then `fuzz.done` |
| `fuzz.cancel` | `run_id` | `fuzz.done {cancelled}` |
| `rule.add` / `rule.remove` | `rule` / `rule_id` | `ack` |
| `hold.release` | `hold_id`, `decision` | `ack` |
| `resolved` | `req_id`, `addrs` or `error` — the answer to a worker `resolve` (research R2 addendum) | — |
| `shutdown` | — | worker exits 0 |
| `debug.connect` / `debug.read` | `addr` / `path` — **only in `vm-test` builds**; never decodable otherwise | `error` with the errno |

Structured `http_send` requests are serialised to raw bytes **in the harness** before `send`, so
the worker has one send path (the raw writer) for all model-originated traffic.

## Worker → harness

| Frame | Fields |
|---|---|
| `hello` | `version`, `ca_cert_pem` (present iff `inspect` non-empty; **certificate only**) |
| `exchange` | the full `Exchange` record minus blob ids; bytes as segments `[req_head, req_body, resp_head, resp_body]`, plus `[req_original_head, req_original_body]` iff `has_original` (heads are segments too, because a byte-exact head is not JSON) |
| `tunnel` | `TunnelRecord` |
| `proxy_event` | `ProxyEvent` (refusals, rule fires, holds, auto-forwards) |
| `resolve` | `req_id`, `host`: the proxy scope cannot reach a DNS server, so the harness resolves; the worker drift-checks the answer against the compiled set |
| `held` | `hold_id`, request summary, deadline |
| `fuzz.done` | `run_id`, counts, `state` |
| `error` | `req_id?`, `code`, `message` |

## Invariants (tested)

1. The CA private key never appears in any frame (test: scan every frame of an inspected session for
   PKCS#8 / `PRIVATE KEY` markers and the key's DER).
2. A `send` whose host is not a `target` is refused by the worker even if the harness sent it
   (defence in depth; test sends one directly).
3. Every `exchange`/`tunnel`/`proxy_event` carries a `call_id` that was issued and not yet revoked at
   the time the request arrived, or `call_id: null` with kind `refused_bad_credential`.
4. Pacing (`rps`, `concurrency`) is enforced in the worker; the harness cannot exceed it by sending
   faster.
