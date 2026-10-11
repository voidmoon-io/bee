# Contract: Interceptor operations (`src/intercept/ops/`)

FR-035–FR-038. Types in [data-model.md](../data-model.md#interceptor-operation-types-srcinterceptops).

```rust
pub fn build_request(r: StructuredRequest) -> Result<(RawTarget, Vec<u8>), OpError>;
pub async fn send(icpt: &Interceptor, ctx: &CallCtx, spec: SendSpec) -> Result<SendResult, OpError>;
pub async fn replay(icpt: &Interceptor, ctx: &CallCtx, spec: ReplaySpec) -> Result<ReplayResult, OpError>;
pub async fn template_from(icpt: &Interceptor, id: &str, marks: &[String], marker: &str)
    -> Result<(RawTarget, String), OpError>;
pub async fn fuzz(icpt: &Interceptor, ctx: &CallCtx, spec: FuzzSpec) -> Result<FuzzResult, OpError>;
pub async fn sitemap(icpt: &Interceptor, q: SitemapQuery, bound: usize) -> Result<Value, OpError>;
pub async fn read_exchange(icpt: &Interceptor, id: &str, part: Part, view: &View) -> Result<Value, OpError>;
pub fn scope_view(icpt: &Interceptor) -> Value;
pub fn stored_request(..); pub fn side_of(..);          // shared, moved from http_replay
pub mod bound { bounded_json, text_or_binary, clip, b64 }
```

- `send` follows at most `follow_redirects` hops, every hop a GET, and stops at the first hop outside
  the Target scope, reporting it in `hops[].stopped` — identical to `http_send` today.
- Ops never take a `Sandbox`; the caller passes `CallCtx` (call id + turn) explicitly.
- Tools: `src/tools/http_*.rs` = schema + arg parsing + one op call + `http::respond(..)`.
- `CallOrigin::Fuzz` deleted.
