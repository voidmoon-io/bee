//! `test-support` must never reach a shipping build (024 research R1).
//!
//! The feature gives `Sandbox::Host` a scripted audit source. A scripted batch can fabricate the
//! kernel denials that drive capability grants, so the feature is only safe while nothing a user
//! builds can turn it on. Two checks:
//!
//! * the manifest: no shipping feature set reaches `test-support`, directly or through another
//!   feature;
//! * the build: a default-features test binary was not compiled with it.

use std::collections::BTreeSet;

/// Feature sets a user builds by default or ships. `default` is the only one today; a `release` or
/// `dist` set added later is covered without editing this list.
const SHIPPING_SETS: &[&str] = &["default", "release", "dist"];

fn features() -> toml::Table {
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("read Cargo.toml");
    let doc: toml::Table = manifest.parse().expect("parse Cargo.toml");
    doc.get("features")
        .and_then(|f| f.as_table())
        .cloned()
        .expect("[features] table")
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

#[test]
fn no_shipping_feature_set_enables_test_support() {
    let features = features();
    assert!(
        features.contains_key("test-support"),
        "the guard is checking a feature that no longer exists — update or delete it"
    );
    for set in SHIPPING_SETS {
        if !features.contains_key(*set) {
            continue;
        }
        let reached = closure(&features, set);
        assert!(
            !reached.contains("test-support"),
            "feature set `{set}` enables `test-support` (via {reached:?}); it must never ship"
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
    assert!(closure(&features, "default").contains("test-support"));
}

#[cfg(not(feature = "test-support"))]
#[test]
// The constant is the point: it is what this build was compiled with.
#[allow(clippy::assertions_on_constants)]
fn default_build_does_not_compile_test_support() {
    assert!(!cfg!(feature = "test-support"));
}
