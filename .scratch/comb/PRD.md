# comb: bee's HTTP interceptor as its own crate, plus `combq`

Status: ready-for-agent

## Why

The interceptor (019, `src/intercept/`, ~8.5k lines) is only reachable as bee's `http_*` tools.
offsec-code (TypeScript, `~/git/offsec-code`) wants the same capability: today its `http_capture` /
`captureHttp` is a single bounded GET with no history, replay, fuzz, rules or proxy. offsec-code
already shells out to a pinned `bee` binary (`isolation.backend: "bee"`), so it consumes comb the
same way: a standalone binary with a JSON-lines control API.

Separately, filtering is weak and split in two: `http_history` takes flat AND-only JSON filters with
no header/body search (`src/intercept/query.rs`), and intercept rules have their own, different
`Matcher` (`src/intercept/worker/rules.rs`). The REPL pane cannot filter at all.

## What

1. **`crates/comb`** — library. Control protocol, worker (forward, MITM, rules, pacing, scope
   checks), exchange store, history query, diff, fuzz, HAR, passive leads, slice, typed ops.
2. **`combq`** — a query language over exchanges, modelled on Caido's HTTPQL but our own:
   `namespace.field op value`, `and` / `or` / `not`, parentheses, comments, bare string = raw search.
3. **`comb` binary** (`crates/comb-cli`) — `comb serve` (proxy + JSON-lines control),
   `comb query '<combq>'`, `comb get <id>`, replay/fuzz/rules over the same API. Full set: offsec-code
   gets everything bee's tools get.
4. **bee** keeps the bee-specific wiring: `session.rs` (policy compile, proxy loopback),
   `creds.rs` (call attribution via sandbox hooks), `pane.rs` (render), the `http_*` tools, and
   `bee proxy-worker` becomes a thin wrapper that runs comb's worker inside the kernel scope.

## Decisions

- **comb depends on `bee-core`** (serde/toml/time only). Host-pattern matching and `HttpScope`
  are scope-defining; one copy, not two that can drift. Standalone comb builds scopes whose
  `enforced_by` holds only `Proxy` entries — no `Kernel` claim — so every result already labels
  enforcement truthfully (`ops/read.rs`).
- **Enforcement is reported, not assumed.** Under bee the proxy scope is kernel-enforced IP:port;
  standalone comb is user-space only unless the host (gVisor, cell netpol) adds a boundary, and
  says so.
- **Keep both filter forms.** `http_history` keeps its JSON fields and gains `q` (combq); they AND
  together. Rules keep `Matcher` and gain `when` (combq).
- **combq in all three places:** history, pane, rules. One parser, one AST, two backends.
- Lives in the bee workspace, not a new repo: the control protocol and scope types still move
  with bee, and offsec-code already pins bee binaries.
- Builds and tests run on the `bee-build` KubeVirt VM (namespace `bee-build`), not the laptop.

## combq sketch

```
req.host eq "api.example.com" and resp.code gte 500
req.method eq "POST" and (req.header["content-type"] cont "json" or req.body regex "\"role\"\\s*:")
origin eq "fuzz" and resp.len gt 10000 and not tag eq "baseline"
req.created_at gt -10m and resp.roundtrip gt 2000
"Authorization"            # bare string: req.raw or resp.raw, cont
```

- `req.{method,host,port,path,query,ext,tls,len,created_at,header,header["x"],body,raw}`
- `resp.{code,len,roundtrip,ttfb,header,header["x"],body,raw}`
- bee namespaces: `origin`, `call`, `turn`, `tag`, `outcome`, `fuzz`, `id`, `session`
- ops: `eq ne gt gte lt lte cont ncont like nlike regex nregex`; `cont` is case-insensitive
- precedence: `not` > `and` > `or` (Caido's docs contradict themselves here; we don't)
- parse errors carry a byte span and say what was expected
- limits: query length, nesting depth, regex size (as `rules.rs` does today)

Execution: indexed conjuncts compile to parameterised SQL (no value spliced into SQL text, as
today); headers/bodies/raw/regex run as a residual Rust predicate over SQL candidates, decoding
stored (still-encoded) bodies, under a hard scan cap reported as `scanned` / `scan_truncated`.
Live rules evaluate the same AST in memory; a `resp.*` field in a request-phase rule is a compile
error.

## Not in scope

- Changing offsec-code itself (separate, after the binary exists; ask first).
- Publishing comb to crates.io.
