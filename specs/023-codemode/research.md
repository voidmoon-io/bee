# Phase 0 Research: Codemode — Every Tool as a Scriptable JS API

> **Decision update (2026-10-31):** Monty is selected. [spec.md](spec.md) is the current design; runtime recommendations and integration assumptions below are historical research.

**Feature**: spec.md (not yet written) · **Date**: 2026-10-10 · **Status**: research spike

Codemode lets the model write one JavaScript program that calls bee's tools as async functions,
instead of one tool call per turn. The program runs in an embedded interpreter in the harness; only
its result comes back into context. The goal of this spike was to survey what exists and take the
best idea from each, not to reuse any one implementation.

Tree references are to `main` at `6a0ab48` (019 merged). Third-party claims were read from source or
crates.io/docs.rs on 2026-10-10 unless marked *(unverified)*.

---

## Prior art surveyed

| | opencode | Cloudflare Code Mode | OpenAI Codex |
|---|---|---|---|
| Engine | Own tree-walking interpreter in TypeScript (Acorn + Effect fibers), `packages/codemode` | V8 isolate per snippet (Worker Loader) | V8 via the `v8` crate, `codex-rs/code-mode-runtime` |
| Process model | In-process on Bun | Isolate, RPC bindings back to the agent | Separate host process over gRPC/stdio *(inferred from crate names)* |
| Tool API | `tools.<ns>.<name>(input)`; one TS signature line per tool rendered from schema | MCP schemas → typed TS API with doc comments | *(not examined)* |
| Isolation | Feature allowlist (no timers, imports, fs, process) | Real isolate; `fetch`/`connect` blocked, `globalOutbound` routes egress | V8 sandbox |
| Limits | Cooperative, **no defaults** (`timeoutMs`, `maxToolCalls`, `maxOutputBytes`) | Isolate limits | *(not examined)* |
| Permissions | Package refuses to own them; leaf tools check themselves | Credentials stay supervisor-side | *(not examined)* |

opencode's open issues are the most useful negative evidence: approval prompts from inner MCP calls
never reach the TUI and `execute` hangs (#51223); `ask` is bypassed for nested plugin tools (#47177);
parallel asks orphan one another (#51224); no timeout on `execute`, MCP calls default to 12 h
(#54220).

Bun's Rust port (oven-sh/bun#30412, merged 2026-05) has a Cargo workspace (`bun_jsc`,
`bun_runtime`, `bun_js_parser`, …) but publishes nothing to crates.io, and its engine is still
JavaScriptCore — V8-class weight. Not a dependency candidate today.

---

## R1 — Engine: rquickjs 0.14 (QuickJS-ng), features `futures` + `parallel`

**Decision**: Embed `rquickjs` and run the model's JS directly. No interpreter-in-interpreter.

**Rationale**: the only candidate meeting every requirement:
- async host functions awaitable from tokio (`AsyncRuntime`/`AsyncContext`, `Func::from(Async(..))`,
  `Promise::into_future`);
- `AsyncRuntime` is `Send + Sync` with `parallel`, so it can live in a tokio task;
- `set_interrupt_handler` (wall-clock) and `set_memory_limit` (heap cap);
- build adds only a `cc`-compiled C library (bindings prebuilt).

**Alternatives rejected**:
- `boa_engine` 0.22 — pure Rust, but no wall-clock interrupt and no heap limit (verified).
- `deno_core` / `v8` — best hardening, but a prebuilt static lib of tens of MB; breaks the lean build.
- `javy` — QuickJS in Wasm; sync imports make async host calls awkward, and pulls in wasmtime.
- opencode's interpreter in QuickJS, or in a Bun sidecar — buys opencode's exact semantics, which is
  not a goal.

**Caveats**: QuickJS is C with a CVE history, so it is one layer, not the sandbox. Never enable
rquickjs `loader`/`dyn-load`; register no `std`/`os` modules. `set_memory_limit` is ignored under the
`rust-alloc`/`allocator` features — do not enable them. The interrupt handler only fires while
bytecode runs, so wrap the whole run in `tokio::time::timeout` as well.

**TypeScript**: ask the model for plain JS. Type stripping (`oxc_transformer` or
`swc_ts_fast_strip`) is a possible later cargo feature.

---

## R2 — API shape (from opencode and Cloudflare)

- `tools.<family>.<name>(input) -> Promise<Result>`, e.g. `tools.http.send`, `tools.fs.read_file`,
  `tools.mcp.<server>.<tool>`; bracket access for non-identifier names.
- The model is shown one TypeScript signature line per tool, generated from the JSON Schema each
  tool already declares (`ToolSchema.parameters`, `src/provider.rs:209`). MCP `input_schema` passes
  through unchanged (`src/mcp/proxy.rs:19`), so it uses the same generator.
- The catalog goes in the system prompt under a size budget; when it is cut, a synchronous
  `search(query)` built-in is advertised for discovery.
- The catalog changes between turns (MCP `list_changed`, escalation-granted tools), so updates are
  sent as diffs, as opencode does.
- Result to the model: the program's return value, then `Logs:` (captured `console.*`), then
  `Warnings:` (unhandled rejections, cancelled calls). Work still pending when the program returns is
  cancelled.
- Inner tool failures throw a JS error the script can catch, carrying the `ToolOutcome` state
  (Completed / Unavailable / Failed, 016) rather than a bare string.
- Codemode coexists with direct tools and is opt-in per tool.

---

## R3 — Safety: hard defaults, and every inner call is a real call

What opencode leaves out, bee must not:

- **Default limits, always on**: wall-clock budget (the episode deadline or `tool_timeout_secs`),
  heap cap, max inner calls per program, max output bytes. All configurable; none can be unset.
- **Every inner call goes through the same per-call path as a direct call**: scope, `begin_call`,
  audit drain, reactive/proactive/proxy escalation with consent, retry, recording. Inner calls get
  `CallOrigin::Script` and ids `{outer_call_id}.{n}`.
- **Consent prompts must surface mid-script** through the REPL/TUI input path, never a raw stdin read
  (opencode #51223; bee's own PR #19 review findings 2–3).
- **Provenance**: if any inner result was `Provenance::Child` or `Remote`, the whole program result is
  wrapped as untrusted. Otherwise a script launders child/remote bytes past the `<untrusted-data>`
  envelope.
- **Excluded at first**: `submit_flag` / `give_up` (`terminal` ends the episode) and `render` (its
  output is UI-only, never model-visible).

---

## R4 — Prerequisite: one per-call wrapper

Codemode cannot be an ordinary `Tool`. `Tool::call` receives `&Sandbox` (`src/tools.rs:283`), but the
wrapping around a call needs `&mut Sandbox` and `&mut ToolRegistry`: `begin_call`/`end_call`/`settle`/
`drain_audit` (`src/sandbox.rs:440,450,761,771`), escalation and `reload`, registering granted tools.

That wrapping is about 13 steps, duplicated between `run_loop` (`src/episode.rs:274-506`) and
`run_exchange` (`src/repl.rs:628-821`). The copies have already drifted (PR #19 review findings 4 and
9: the REPL drops the pre-retry denial from the audit trail).

**Decision**: extract one shared per-call executor, parameterised over progress output, timeout
policy, `turn`/`call_id` and `CallOrigin`, before any codemode code. Codemode then runs as a
loop-level call: the script's host functions send inner calls over a channel to the loop driver,
which runs each through that executor.

**Status (2026-10-12)**: done, by 024-session-core, which is on main (#28 call lifecycle, #27
tool surface). The line references above are to `430640c` and are now stale. Codemode's seams are:

- **`src/call.rs::run_call(CallInput, &mut Sandbox, &mut ToolRegistry, Option<Escalation>) ->
  CallOutcome`**. This is the shared per-call executor. Both loops already call it and nothing
  else. Each inner call is one `run_call` with `CallInput { call, turn, origin, timeout }`. The outer
  codemode call's remaining budget is passed as `TimeoutPolicy::Deadline`, so inner calls cannot
  outlive it. The loop driver keeps the `Escalation` it already holds. Each inner `CallOutcome`
  (`result`, `audit`, `denied_attempt_audit`, `proxy_audit`, escalations) becomes one nested
  `RecordedCall` (R5.2).
- **`ToolRegistry::surface() -> Vec<SurfaceEntry>`** (`src/tools.rs`). Every callable tool, with its
  schema and the dependencies it was built with, in the order `schemas()` offers them. The `tools.*`
  API generator (R5.4) reads this rather than the raw registry. A tool granted mid-session appears
  here the same way as one present from the start, so the generated API can be rebuilt at a turn
  start after a grant.

**Inner calls are serialised**: the sandbox holds one current-call slot (`ChildEnv.call`,
`src/sandbox.rs:153`) and audit is drained per scope, not per call. `Promise.all` over tools is
accepted and queued. Real parallelism needs per-call audit attribution — out of scope.

---

## R5 — Scope decisions (operator, 2026-10-10)

1. **Both loops.** The episode (batch) loop and the REPL both get codemode in the first cut — which
   the shared per-call executor (R4) makes one implementation, not two.
2. **Nested recording.** Inner calls are `RecordedCall`s nested under the outer codemode call in the
   transcript, each with its own audit and proxy events.
3. **`bash` is exposed.** Inner `bash` calls are still counted by 020's bash-reach instrumentation, so
   a script that shells out around a typed tool is measured the same as a direct call.
4. **All tools, eventually; the http family first.** The first slice exposes `tools.http.*` (the
   interceptor: `scope`, `send`, `get`, `history`, `replay`, `sitemap`, `fuzz`, `intercept`, `leads`).
   The API generator is written over the whole registry from the start, so later families are an
   allowlist change, not new code. R3's exclusions (`submit_flag`, `give_up`, `render`) still apply.

## Sources

- opencode `packages/codemode` and `packages/core/src/codemode/*` (anomalyco/opencode `dev` @
  823ac87); local copies in the session scratchpad
- https://blog.cloudflare.com/code-mode/
- openai/codex `codex-rs/Cargo.toml`, `codex-rs/code-mode-runtime`
- docs.rs rquickjs 0.14.0; docs.rs boa_engine 0.22.0; github.com/DelSkayn/rquickjs
- https://github.com/oven-sh/bun/pull/30412; oven-sh/bun `Cargo.toml`
