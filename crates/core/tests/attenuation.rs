//! Attenuation validator unit tests (T040) — targeted soundness/usability cases.

use bee_core::{Access, Policy};

fn p(toml: &str) -> Policy {
    Policy::from_toml(toml).expect("valid policy")
}

#[test]
fn subset_child_is_accepted() {
    let parent = p(r#"
[policy]
name = "parent"
[policy.filesystem]
"/proj" = "write"
[policy.exec]
allow = ["cargo", "rustc"]
[policy.network]
allow = ["crates.io:443"]
"#);
    let child = p(r#"
[policy]
name = "child"
[policy.filesystem]
"/proj/src" = "read"
[policy.exec]
allow = ["cargo"]
"#);
    assert!(parent.derive(child).is_ok());
}

#[test]
fn over_grant_filesystem_rejected() {
    // AS-1: child adds write to a path the parent cannot write.
    let parent = p("[policy]\nname=\"p\"\n[policy.filesystem]\n\"/proj\" = \"write\"\n");
    let child = p("[policy]\nname=\"c\"\n[policy.filesystem]\n\"/etc/passwd\" = \"write\"\n");
    let err = parent.derive(child).unwrap_err();
    assert!(err.capability.contains("/etc/passwd"));
}

#[test]
fn read_only_child_cannot_upgrade_to_write() {
    let parent = p("[policy]\nname=\"p\"\n[policy.filesystem]\n\"/proj\" = \"read\"\n");
    let child = p("[policy]\nname=\"c\"\n[policy.filesystem]\n\"/proj/src\" = \"write\"\n");
    assert!(parent.derive(child).is_err());
}

#[test]
fn child_may_narrow_access() {
    let parent = p("[policy]\nname=\"p\"\n[policy.filesystem]\n\"/proj\" = \"write\"\n");
    let child = p("[policy]\nname=\"c\"\n[policy.filesystem]\n\"/proj/src\" = \"read\"\n");
    assert!(parent.derive(child).is_ok());
}

#[test]
fn parent_deny_inside_grant_must_be_replicated() {
    // Parent grants /proj=write but denies /proj/.git. A child re-granting /proj write without
    // replicating the deny would over-grant (could write .git) -> rejected.
    let parent = p(r#"
[policy]
name = "p"
[policy.filesystem]
"/proj" = "write"
"/proj/.git" = "deny"
"#);
    let child_bad = p("[policy]\nname=\"c\"\n[policy.filesystem]\n\"/proj\" = \"write\"\n");
    assert!(parent.derive(child_bad).is_err());

    let child_ok = p(r#"
[policy]
name = "c"
[policy.filesystem]
"/proj" = "write"
"/proj/.git" = "deny"
"#);
    assert!(parent.derive(child_ok).is_ok());
}

#[test]
fn exec_not_in_parent_rejected() {
    let parent = p("[policy]\nname=\"p\"\n[policy.exec]\nallow=[\"cargo\"]\n");
    let child = p("[policy]\nname=\"c\"\n[policy.exec]\nallow=[\"curl\"]\n");
    let err = parent.derive(child).unwrap_err();
    assert!(err.capability.contains("curl"));
}

#[test]
fn network_not_in_parent_rejected() {
    let parent = p("[policy]\nname=\"p\"\n[policy.network]\nallow=[\"crates.io:443\"]\n");
    let child = p("[policy]\nname=\"c\"\n[policy.network]\nallow=[\"evil.com:443\"]\n");
    assert!(parent.derive(child).is_err());
}

#[test]
fn no_network_child_is_subset() {
    // AS-3: a child with no network is trivially within a parent that has network.
    let parent = p("[policy]\nname=\"p\"\n[policy.network]\nallow=[\"crates.io:443\"]\n");
    let child = p("[policy]\nname=\"c\"\n");
    assert!(parent.derive(child).is_ok());
}

#[test]
fn child_may_not_be_looser_mode() {
    let parent = p("[policy]\nname=\"p\"\nmode=\"enforce\"\n");
    let child = p("[policy]\nname=\"c\"\nmode=\"observe\"\n");
    assert!(
        parent.derive(child).is_err(),
        "observe child under enforce parent is looser"
    );

    let parent2 = p("[policy]\nname=\"p\"\nmode=\"observe\"\n");
    let child2 = p("[policy]\nname=\"c\"\nmode=\"enforce\"\n");
    assert!(
        parent2.derive(child2).is_ok(),
        "enforce child under observe parent is stricter"
    );
}

#[test]
fn identical_glob_grant_is_allowed() {
    let parent = p("[policy]\nname=\"p\"\n[policy.filesystem]\n\"*.log\" = \"write\"\n");
    let child = p("[policy]\nname=\"c\"\n[policy.filesystem]\n\"*.log\" = \"read\"\n");
    assert!(parent.derive(child).is_ok());
}

#[test]
fn novel_glob_grant_rejected() {
    let parent = p("[policy]\nname=\"p\"\n[policy.filesystem]\n\"/proj\" = \"write\"\n");
    let child = p("[policy]\nname=\"c\"\n[policy.filesystem]\n\"*.log\" = \"write\"\n");
    assert!(
        parent.derive(child).is_err(),
        "glob not provably contained in a prefix grant"
    );
}

// ---------------------------------------------------------------------------
// Widening by omission (f001, f002, f012, f014, f025). `derive` returns the
// *effective* child: silence inherits the parent's restrictions, never resets them.
// ---------------------------------------------------------------------------

#[test]
fn parent_deny_outside_any_child_grant_is_inherited() {
    // f001: the child never mentions /secrets, so no replication check fires — but dropping the
    // denial would hand it back the default-allowed read the parent took away.
    let parent = p(r#"
[policy]
name = "p"
[policy.filesystem]
"/proj" = "write"
"/secrets" = "deny"
"#);
    let child = p("[policy]\nname=\"c\"\n[policy.filesystem]\n\"/proj/src\" = \"read\"\n");
    let derived = parent
        .derive(child)
        .expect("narrowing child is within the parent");
    assert_eq!(
        derived.filesystem.get("/secrets"),
        Some(&Access::Deny),
        "the parent's denial must survive into the derived policy"
    );
}

#[test]
fn silent_filesystem_child_inherits_the_parent_map() {
    // An empty rule set installs no rules at all, which reads downstream as "no filesystem
    // enforcement" — writes included. Inherit instead.
    let parent = p(r#"
[policy]
name = "p"
[policy.filesystem]
"/proj" = "write"
"/secrets" = "deny"
"#);
    let derived = parent
        .derive(p("[policy]\nname=\"c\"\n"))
        .expect("a child that asks for nothing is trivially a subset");
    assert_eq!(derived.filesystem, parent.filesystem);
}

#[test]
fn empty_child_network_inherits_rather_than_disabling_egress() {
    // f012: an empty list clears FLAG_NET_ENFORCED, which permits *every* destination.
    let parent = p("[policy]\nname=\"p\"\n[policy.network]\nallow=[\"crates.io:443\"]\n");
    let derived = parent.derive(p("[policy]\nname=\"c\"\n")).unwrap();
    assert_eq!(derived.network.allow, vec!["crates.io:443".to_string()]);
}

#[test]
fn empty_child_exec_inherits_rather_than_unrestricting() {
    // f014: no EXEC_ALLOW entry is read by the kernel as unrestricted execution.
    let parent = p("[policy]\nname=\"p\"\n[policy.exec]\nallow=[\"cargo\",\"rustc\"]\n");
    let derived = parent.derive(p("[policy]\nname=\"c\"\n")).unwrap();
    assert_eq!(
        derived.exec.allow,
        vec!["cargo".to_string(), "rustc".to_string()]
    );

    // A child that *does* name executables still narrows to its own selection.
    let narrowed = parent
        .derive(p(
            "[policy]\nname=\"c\"\n[policy.exec]\nallow=[\"cargo\"]\n",
        ))
        .unwrap();
    assert_eq!(narrowed.exec.allow, vec!["cargo".to_string()]);
}

#[test]
fn child_inherits_the_parent_inode_pin() {
    // f025: dropping the `!` widens — an unpinned rule matches whatever now sits at that path.
    let parent = p("[policy]\nname=\"p\"\n[policy.exec]\nallow=[\"!cargo\"]\n");
    let derived = parent
        .derive(p(
            "[policy]\nname=\"c\"\n[policy.exec]\nallow=[\"cargo\"]\n",
        ))
        .unwrap();
    assert_eq!(derived.exec.allow, vec!["!cargo".to_string()]);
}

#[test]
fn child_cannot_reach_into_a_protected_region_under_a_broad_grant() {
    // f002: protected defaults are injected at compile time, after attenuation, and a more
    // specific rule out-ranks them at load — so the refusal has to happen here.
    let parent = p("[policy]\nname=\"p\"\n[policy.filesystem]\n\"~\" = \"write\"\n");
    let err = parent
        .derive(p(
            "[policy]\nname=\"c\"\n[policy.filesystem]\n\"~/.ssh/id_rsa\" = \"read\"\n",
        ))
        .unwrap_err();
    assert!(err.reason.contains("protected region"), "{}", err.reason);

    // The operator may still override it explicitly; the child then inherits that override.
    let permissive = p(r#"
[policy]
name = "p"
[policy.filesystem]
"~" = "write"
"~/.ssh" = "read"
"#);
    assert!(permissive
        .derive(p(
            "[policy]\nname=\"c\"\n[policy.filesystem]\n\"~/.ssh/id_rsa\" = \"read\"\n"
        ))
        .is_ok());
}

#[test]
fn protected_git_is_readable_but_not_writable_by_a_child() {
    let parent = p("[policy]\nname=\"p\"\n[policy.filesystem]\n\":project_root\" = \"write\"\n");
    assert!(
        parent
            .derive(p(
                "[policy]\nname=\"c\"\n[policy.filesystem]\n\":project_root/.git\" = \"read\"\n"
            ))
            .is_ok(),
        "the protected default for .git is read-only, not deny"
    );
    assert!(parent
        .derive(p(
            "[policy]\nname=\"c\"\n[policy.filesystem]\n\":project_root/.git/hooks\" = \"write\"\n"
        ))
        .is_err());
}

#[test]
fn effective_defaults_survive_serialization() {
    let parent = p("[policy]\nname='parent'\n[policy.filesystem]\n'/project'='write'\n");
    let child = parent
        .derive(p(
            "[policy]\nname='child'\n[policy.filesystem]\n'/project'='read'\n",
        ))
        .unwrap();
    let restored: Policy = toml::from_str(&toml::to_string(&child).unwrap()).unwrap();
    assert!(restored.denies_unmatched_writes());
    assert!(!restored
        .filesystem
        .values()
        .any(|a| *a == bee_core::Access::Write));
}

#[test]
fn inherited_read_only_region_stays_readable() {
    let parent = p("[policy]\nname='parent'\n[policy.filesystem]\n'/project'='read'\n");
    let child = parent
        .derive(p(
            "[policy]\nname='child'\n[policy.filesystem]\n'/project/sub'='read'\n",
        ))
        .unwrap();
    assert_eq!(
        child.filesystem.get("/project"),
        Some(&bee_core::Access::Read)
    );
}
