//! T037 — the `bee-core` dependency guard (Constitution V, FR-021; SC-005).
//!
//! The whole TUI (ratatui, crossterm, color-eyre, textwrap) and the async runtime live in
//! the application package **only**. `bee-core` is the policy/enforcement core: it must stay free of terminal
//! and runtime dependencies so it can be audited, embedded, and built without a UI toolchain.
//!
//! This is easy to break by accident — one `use` in the wrong crate and Cargo quietly pulls a
//! terminal backend into the core. So we assert it structurally, against the manifests themselves,
//! rather than trusting review.

use std::path::{Path, PathBuf};

/// Crates that must never appear in `bee-core`'s (or `bee-common`'s) dependency tables.
const FORBIDDEN: &[&str] = &[
    // Terminal / UI
    "ratatui",
    "crossterm",
    "termion",
    "color-eyre",
    "textwrap",
    "rustyline",
    "indicatif",
    // Async runtimes
    "tokio",
    "async-std",
    "smol",
    "futures-util",
    // Scripting / rendering brought in by the harness
    "rhai",
    // Terminal effects (009-tachyonfx-effects, SC-009)
    "tachyonfx",
    // Markdown → ratatui `Text` (010): a chat-pane concern, never a policy-core one. Both the
    // crate bee uses and the one it deliberately did not are listed, so reaching for either from
    // the core fails here rather than in review.
    "tui-markdown",
    "ratatui-markdown",
    // MCP client
    "rmcp",
    // Security analysis tooling (016-native-tools, SC-009). These are the application's business:
    // the core compiles and enforces policy, it does not analyse source. `tree-sitter` is listed
    // alongside the ast-grep crates because it is the transitive C parser they carry — reaching it
    // from the core would drag a compiled grammar into a crate that must stay auditable and
    // toolchain-light.
    "ast-grep-core",
    "ast-grep-language",
    "tree-sitter",
    "gix",
    "cvss",
    // HTTP(S) interception (019-http-intercept, SC-009). The proxy, its TLS stack, the certificate
    // minting and the exchange store are the application's business; the core compiles `[policy.http]`
    // into scopes and checks attenuation, as pure data, and never opens a socket or a database.
    "hyper",
    "rustls",
    "tokio-rustls",
    "rcgen",
    "rusqlite",
    "json-patch",
    "brotli-decompressor",
    "ruzstd",
];

fn workspace_root() -> PathBuf {
    // The application package *is* the workspace root (consolidation issue 08), so the manifest
    // directory is the root rather than one below it.
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// Every dependency name declared in `manifest`, across normal/dev/build and target-specific tables.
/// Deliberately a **textual** scan of dependency table keys: it needs no toml crate in dev-deps and
/// catches a forbidden crate however it is declared (plain, table, renamed via `package = `).
fn declared_deps(manifest: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_deps = false;
    for raw in manifest.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            // e.g. [dependencies], [dev-dependencies], [target.'cfg(unix)'.dependencies]
            in_deps = line.ends_with("dependencies]");
            continue;
        }
        if !in_deps || line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, rest)) = line.split_once('=') {
            let key = key.trim().trim_matches('"');
            if !key.is_empty() {
                names.push(key.to_string());
            }
            // A renamed dependency hides the real crate behind `package = "..."`.
            if let Some(idx) = rest.find("package") {
                let tail = &rest[idx..];
                if let Some(start) = tail.find('"') {
                    if let Some(end) = tail[start + 1..].find('"') {
                        names.push(tail[start + 1..start + 1 + end].to_string());
                    }
                }
            }
        }
    }
    names
}

fn assert_clean(crate_name: &str) {
    let path = workspace_root().join(crate_name).join("Cargo.toml");
    let manifest = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let deps = declared_deps(&manifest);

    let leaked: Vec<&String> = deps
        .iter()
        .filter(|d| FORBIDDEN.contains(&d.as_str()))
        .collect();

    assert!(
        leaked.is_empty(),
        "{crate_name} must stay free of terminal/async-runtime dependencies (Constitution V, \
         FR-021), but its manifest declares: {leaked:?}.\n\
         The TUI and runtime belong in the application package — move the code rather than the dependency."
    );
}

#[test]
fn bee_core_has_no_terminal_or_runtime_dependency() {
    assert_clean("crates/core");
}

#[test]
fn bee_common_has_no_terminal_or_runtime_dependency() {
    assert_clean("crates/common");
}

/// `tachyonfx` must also stay out of the **headless** application build (009 SC-009,
/// Constitution V): a batch run or a CI episode has no terminal, and pulling an effects engine into
/// it would make the animation layer a cost everyone pays rather than one the TUI opts into.
///
/// Asserted against the manifest rather than the resolved tree, so the rule holds without building:
/// the dependency must be `optional` and reachable only through the `tui` feature.
fn assert_reachable_only_through_the_tui_feature(dep: &str) {
    let path = workspace_root().join("Cargo.toml");
    let manifest = std::fs::read_to_string(&path).expect("read the application manifest");

    // The declaration spans several lines, so take it from its key to the end of its table.
    let start = manifest
        .find(&format!("\n{dep}"))
        .unwrap_or_else(|| panic!("the application manifest must declare {dep}"));
    let decl: String = manifest[start + 1..]
        .lines()
        .take_while(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        decl.contains("optional = true"),
        "{dep} must be optional so the headless build never pulls it in, but got: {decl}"
    );

    // And the only feature that turns it on is `tui`. Feature values are multi-line arrays, so
    // track which key's value each `dep:<name>` falls inside.
    let features = manifest
        .split("[features]")
        .nth(1)
        .expect("the application manifest must have a [features] table");
    let features = features.split("\n[").next().unwrap_or(features);
    let mut current = "";
    let mut enabling: Vec<&str> = Vec::new();
    for line in features.lines() {
        if let Some((key, _)) = line.split_once('=') {
            if !key.trim().is_empty() && !key.trim_start().starts_with('#') {
                current = key.trim();
            }
        }
        if line.contains(&format!("dep:{dep}")) {
            enabling.push(current);
        }
    }
    assert_eq!(
        enabling,
        vec!["tui"],
        "only the `tui` feature may enable {dep}"
    );
}

#[test]
fn tachyonfx_is_reachable_only_through_the_tui_feature() {
    assert_reachable_only_through_the_tui_feature("tachyonfx");
}

/// Markdown rendering is a chat-pane concern (010): a batch run or a CI episode has no chat pane,
/// so a headless build must not carry a markdown parser — the same rule tachyonfx lives under.
#[test]
fn tui_markdown_is_reachable_only_through_the_tui_feature() {
    assert_reachable_only_through_the_tui_feature("tui-markdown");
}

#[test]
fn the_guard_actually_detects_a_leak() {
    // A guard that cannot fail is worthless — prove the parser sees a forbidden dep in every shape
    // it could be declared in.
    let manifest = r#"
[package]
name = "fake"

[dependencies]
serde = "1"
ratatui = { version = "0.29", default-features = false }

[dev-dependencies]
tokio = { version = "1", features = ["macros"] }

[target.'cfg(unix)'.dependencies]
term = { package = "crossterm", version = "0.28" }
"#;
    let deps = declared_deps(manifest);
    for expected in ["ratatui", "tokio", "crossterm"] {
        assert!(
            deps.contains(&expected.to_string()),
            "parser missed {expected} in {deps:?}"
        );
    }
    // And a plain manifest is clean.
    assert!(!declared_deps("[dependencies]\nserde = \"1\"\n")
        .iter()
        .any(|d| FORBIDDEN.contains(&d.as_str())));
}
