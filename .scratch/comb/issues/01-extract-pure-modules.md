# Extract comb's harness-side modules into `crates/comb`

Status: done

Create `crates/comb` (workspace member, depends on `bee-core`). Move, without behaviour change:
`control`, `store`, `query`, `diff`, `fuzz` (+ `payloads/`), `har`, `slice`, `passive`,
`proxy_event` (from `src/proxy_event.rs`) and `ops/bound`. bee re-exports them so existing paths
(`crate::intercept::store`, `crate::proxy_event`, …) keep compiling. The modules that depend on
`crate::sandbox`, `render_spec` or `safe_text` stay in bee for now.

Done when: `cargo test` passes on bee-build, including every `tests/intercept_*.rs`, and
`cargo tree -p comb` shows no bee (root crate), aya or ratatui.
