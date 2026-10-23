//! `test-support` must never reach a shipping build (024 research R1).
//!
//! The feature gives `Sandbox::Host` a scripted audit source. A scripted batch can fabricate the
//! kernel denials that drive capability grants, so the feature is only safe while nothing a user
//! builds can turn it on. A feature reaches a build in two ways, and both are checked here against
//! the manifests:
//!
//! * bee's own feature sets — no shipping set enables `test-support`, directly or through another
//!   feature;
//! * feature unification — no workspace member depends on `bee` with `test-support`, which would
//!   switch it on for every `cargo build --workspace`.
//!
//! A runtime `cfg!` assertion is deliberately absent: a test can only observe the features *it* was
//! compiled with, which says nothing about the build that ships.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Feature sets a user builds by default or ships. `default` is the only one today; a `release` or
/// `dist` set added later is covered without editing this list.
const SHIPPING_SETS: &[&str] = &["default", "release", "dist"];

const FEATURE: &str = "test-support";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn manifest(path: &Path) -> toml::Table {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    text.parse()
        .unwrap_or_else(|e| panic!("parse {path:?}: {e}"))
}

/// Every feature `root` enables, following feature-to-feature edges. `dep:x` and `crate/feature`
/// entries name dependencies, not features of this package, so they are not followed.
fn closure(features: &toml::Table, root: &str) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut stack = vec![root.to_string()];
    while let Some(name) = stack.pop() {
        if !seen.insert(name.clone()) {
            continue;
        }
        let Some(list) = features.get(&name).and_then(|v| v.as_array()) else {
            continue;
        };
        for entry in list.iter().filter_map(|v| v.as_str()) {
            if !entry.starts_with("dep:") && !entry.contains('/') {
                stack.push(entry.to_string());
            }
        }
    }
    seen
}

/// Dependency tables that reach a shipping build: `[dependencies]` and `[build-dependencies]`, also
/// under `[target.*]`, plus `[workspace.dependencies]`. Dev-dependencies only reach test builds.
fn shipping_dep_tables(m: &toml::Table) -> Vec<(String, toml::Table)> {
    let mut out = Vec::new();
    let mut take = |label: String, t: Option<&toml::Value>| {
        if let Some(t) = t.and_then(|v| v.as_table()) {
            out.push((label, t.clone()));
        }
    };
    for key in ["dependencies", "build-dependencies"] {
        take(key.to_string(), m.get(key));
    }
    if let Some(targets) = m.get("target").and_then(|v| v.as_table()) {
        for (cfg, t) in targets {
            for key in ["dependencies", "build-dependencies"] {
                take(format!("target.{cfg}.{key}"), t.get(key));
            }
        }
    }
    if let Some(ws) = m.get("workspace").and_then(|v| v.as_table()) {
        take("workspace.dependencies".into(), ws.get("dependencies"));
    }
    out
}

/// `(table, dep)` for every dependency on `bee` (by name or `package = "bee"`) that lists
/// `test-support` among its features.
fn bee_deps_enabling_it(m: &toml::Table) -> Vec<String> {
    let mut hits = Vec::new();
    for (label, deps) in shipping_dep_tables(m) {
        for (name, spec) in deps {
            let Some(spec) = spec.as_table() else {
                continue; // `bee = "0.1"`: no features
            };
            let package = spec
                .get("package")
                .and_then(|v| v.as_str())
                .unwrap_or(&name);
            if package != "bee" {
                continue;
            }
            let enables = spec
                .get("features")
                .and_then(|v| v.as_array())
                .is_some_and(|f| f.iter().any(|x| x.as_str() == Some(FEATURE)));
            if enables {
                hits.push(format!("{label}.{name}"));
            }
        }
    }
    hits
}

/// The root manifest and every workspace member's.
fn workspace_manifests() -> Vec<(PathBuf, toml::Table)> {
    let root_path = root().join("Cargo.toml");
    let root_manifest = manifest(&root_path);
    let members: Vec<String> = root_manifest
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(|m| m.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let mut out = vec![(root_path, root_manifest)];
    for member in members {
        assert!(
            !member.contains('*'),
            "workspace member glob {member:?}: expand it here so every member is checked"
        );
        let path = root().join(&member).join("Cargo.toml");
        let m = manifest(&path);
        out.push((path, m));
    }
    out
}

#[test]
fn no_shipping_feature_set_enables_test_support() {
    let m = manifest(&root().join("Cargo.toml"));
    let features = m
        .get("features")
        .and_then(|f| f.as_table())
        .expect("[features] table");
    assert!(
        features.contains_key(FEATURE),
        "the guard is checking a feature that no longer exists — update or delete it"
    );
    for set in SHIPPING_SETS {
        if !features.contains_key(*set) {
            continue;
        }
        let reached = closure(features, set);
        assert!(
            !reached.contains(FEATURE),
            "feature set `{set}` enables `{FEATURE}` (via {reached:?}); it must never ship"
        );
    }
}

#[test]
fn no_workspace_member_depends_on_bee_with_test_support() {
    let manifests = workspace_manifests();
    assert!(manifests.len() > 1, "expected workspace members to check");
    for (path, m) in manifests {
        let hits = bee_deps_enabling_it(&m);
        assert!(
            hits.is_empty(),
            "{path:?} enables bee's `{FEATURE}` through {hits:?}; feature unification would \
             compile it into every workspace build"
        );
    }
}

#[test]
fn closure_follows_feature_edges() {
    let features: toml::Table = toml::from_str(
        r#"
        default = ["a"]
        a = ["b", "dep:x", "other/feat"]
        b = ["test-support"]
        test-support = []
        "#,
    )
    .unwrap();
    assert!(closure(&features, "default").contains(FEATURE));
}

#[test]
fn dependency_scan_finds_every_spelling() {
    let m: toml::Table = toml::from_str(
        r#"
        [dependencies]
        bee = { path = "..", features = ["test-support"] }
        [target.'cfg(unix)'.build-dependencies]
        renamed = { package = "bee", features = ["test-support"] }
        [dev-dependencies]
        bee = { path = "..", features = ["test-support"] }
        [workspace.dependencies]
        bee = { path = ".", features = ["intercept"] }
        "#,
    )
    .unwrap();
    assert_eq!(
        bee_deps_enabling_it(&m),
        vec![
            "dependencies.bee".to_string(),
            "target.cfg(unix).build-dependencies.renamed".to_string(),
        ],
        "shipping tables are caught, dev-dependencies and other features are not"
    );
}
