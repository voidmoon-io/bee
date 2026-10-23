# Contract: model-facing HTTP tools

All tools: feature `intercept`; registered under `HTTP_TOOLS` in `src/tools.rs`; `NotCompiledIn`
stub when the feature is off (FR-029). Every result is a `ToolOutcome` (016 contract) rendered with
`provenance = Remote { source: "http:<id>" }` for target-derived content
([model-framing.md](./model-framing.md)), and is bounded by `DEFAULT_OUTPUT_CAP` (100 KiB) **and** the
per-tool bound below (FR-017). Bodies are never returned whole unless they fit the slice bound.

Common result fields: `enforcement: "kernel" | "advisory"` (FR-010).

Common refusal (`Unavailable`) reasons: `interceptor_unavailable` (worker not running — never falls
back to direct egress), `out_of_scope {host, port, layer}`, `egress_only {host}`,
`limit_exceeded {limit, value}`, `not_compiled_in`.

---

## `http_scope` (M1) — read-only

**Args**: `{}`
**Result**: per entry `{ host, port, role: target|egress, inspect: bool, insecure_upstream: bool,
enforced_by: [{layer: "kernel", addr, port}…, {layer: "proxy", host}] }`, plus `limits`,
`enforcement`, and `widening: "requires operator approval"`. Bound: 8 KiB.

## `http_send` (M1)

**Args** (exactly one of `request` / `raw`):
```json
{
  "request": { "method": "POST", "url": "https://app.test/api/x?y=1",
               "headers": [["Content-Type","application/json"]],
               "body": "{\"a\":1}", "body_base64": null },
  "raw":     { "scheme": "https", "host": "app.test", "port": 443, "bytes": "<string>", "bytes_base64": null },
  "baseline": "E7a2-41",
  "follow_redirects": 0,
  "timeout_ms": 15000,
  "tags": ["authz"]
}
```
- `headers` is an ordered list of pairs; duplicates and casing are preserved.
- `raw.bytes` is sent byte-for-byte (FR-018); bee adds nothing.
- `follow_redirects` (max 5) scope-checks every hop; an out-of-scope hop stops and is reported (FR-023).

**Result**:
```json
{ "id": "E7a2-42", "status": 200, "elapsed_ms": 83, "resp_bytes": 14211,
  "content_type": "text/html", "headers_preview": [["server","nginx"], "…"],
  "body_preview": "<untrusted …>first 1 KiB, decoded</untrusted …>",
  "redirects": [], "diff": { /* present iff baseline; see http_replay */ } }
```
Bound: 4 KiB without diff, 16 KiB with.

## `http_get` (M1)

**Args**: `{ "id": "E7a2-42", "part": "request|response", "view": <one of> }`
- `{"headers": true}`
- `{"range": {"start": 0, "len": 4096}}` — on the decoded body
- `{"grep": {"pattern": "csrf", "context_lines": 1, "max_matches": 20}}`
- `{"json_pointer": "/data/0/id"}`
- `{"raw_head": true}` — exact bytes as sent/received

**Result**: `{ id, part, total_decoded_bytes, encoding, truncated, evicted, origin, content }`.
Bound: 32 KiB.

## `http_history` (M1)

**Args**: filter object, all optional, AND-combined; list = OR (research R11):
```json
{ "host": ["app.test"], "method": ["POST"], "path_prefix": "/api/",
  "status": [500, 502], "status_range": [400, 499],
  "min_bytes": 0, "max_bytes": 100000, "since": "-10m", "until": null,
  "call_id": null, "turn": null, "origin": ["tool","forwarded"], "tags": ["authz"],
  "outcome": ["completed","refused"],
  "limit": 50, "order": "newest" }
```
**Result**: `{ total_matched, returned, rows: [ { id, t, method, host, path, status, resp_bytes,
ms, origin, call_id, tags } ] }` — one compact row each; `limit` max 200. Bound: 24 KiB.

## `http_replay` (M2)

**Args**: `{ "id": "E7a2-42", "edits": [Edit…], "noise_probe": true, "timeout_ms": 15000 }`
(`Edit` per [data-model.md § Edit](../data-model.md#edit-shared-by-replay-and-rules)).

**Result**:
```json
{ "id": "E7a2-44", "parent": "E7a2-42", "probe": "E7a2-43",
  "diff": { "status": [200, 403], "length": [14211, 512], "elapsed_ms": [83, 12],
            "headers": { "added": [], "removed": ["set-cookie"], "changed": [] },
            "body": { "kind": "json|text|binary", "hunks": ["…bounded unified hunks…"],
                      "json_paths_changed": ["/user/role"] },
            "volatile_suppressed": { "count": 3, "paths": ["header:date", "/meta/request_id"] } } }
```
Bound: 16 KiB.

## `http_sitemap` (M2)

**Args**: `{ "host": "app.test", "path_prefix": "/", "depth": 4 }`
**Result**: tree of `{ segment, methods, statuses, count, params: { query: [...], body: [...] } }`,
with `omitted_children` counts. Bound: 24 KiB.

## `http_fuzz` (M3)

**Args**:
```json
{ "template": { "from": "E7a2-42" } ,            // or { "raw": {…as http_send.raw…} }
  "markers": "§",                                // positions delimited by the marker in the template text
  "payloads": [ {"builtin": "sqli-basic"}, {"range": {"from":1,"to":500}},
                {"inline": ["a","b"]}, {"project_file": "wordlists/paths.txt"} ],
  "mode": "sniper", "rps": null, "concurrency": null }
```
- `rps`/`concurrency` may only lower policy limits.
- Planned count > `max_requests_per_run` → refused before sending (FR-021).

**Result**: `ClusterSummary` ([data-model](../data-model.md#clustersummary)) + `run_id` + counts.
Bound: 16 KiB regardless of variant count (SC-006).

## `http_intercept` (M3)

**Args** (one action):
- `{"action":"add_rule","rule":{matcher, action}}` → `{rule_id}`
- `{"action":"remove_rule","rule_id":"R3"}`
- `{"action":"list"}` → rules with hit counts + currently held requests (`hold_id`, summary, deadline)
- `{"action":"release","hold_id":"H9","decision":"forward"|"drop"|{"forward_edited":[Edit…]}}`

Held requests auto-forward unchanged at the deadline (FR-022). Bound: 8 KiB.

## `record_finding` (extended, M3)

New optional arg `evidence_refs: ["http:E7a2-44", …]` (≤ 16 refs). (Named `evidence_refs`, not
`evidence`, because `evidence` is already the finding's required text field.) The refs are stored
on the sighting. Unknown ids are rejected at record time, resolved against the exchange store
beside the ledger in the same `.bee/`. Ids whose body has since been evicted, or that are gone,
resolve as `missing` on review (FR-027).

## `http_leads` (M3)

**Args**: `{ "only_new": true, "limit": 20 }` → `[ {id, kind, summary, exchange_ids} ]`.
Leads are never findings (FR-028). Bound: 8 KiB.

> `http_leads` is the one tool not named in the spec's tool list; it is how the model "lists them on
> request" (US8 acceptance 2) without overloading `http_history`.
