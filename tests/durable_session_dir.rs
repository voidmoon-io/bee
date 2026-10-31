#![cfg(feature = "durable-sessions")]
//! A session directory sandboxed tools can write is refused: what is on disk there is the record.

use bee::session::driver::tool_writable_path;
use bee_core::{CompileError, ExecIdentity, Policy, Resolver};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

struct Fixed;
impl Resolver for Fixed {
    fn project_root(&self) -> &str {
        "/work"
    }
    fn home(&self) -> &str {
        "/home/u"
    }
    fn resolve_exec(&self, name: &str) -> Result<PathBuf, CompileError> {
        Ok(PathBuf::from(name))
    }
    fn resolve_exec_identity(&self, path: &Path) -> Result<ExecIdentity, CompileError> {
        Err(CompileError::UnresolvableExec(
            path.display().to_string(),
            "fixture".into(),
        ))
    }
    fn resolve_host(&self, _: &str) -> Result<Vec<IpAddr>, CompileError> {
        Ok(vec![])
    }
}

fn reach(rules: &str, dir: &str) -> Option<PathBuf> {
    let policy = Policy::from_toml(&format!(
        "[policy]\nname = \"p\"\n{rules}\n[policy.filesystem]\n\"/work\" = \"write\"\n"
    ))
    .unwrap();
    tool_writable_path(&policy, Path::new(dir), &Fixed).unwrap()
}

#[test]
fn a_session_dir_outside_every_write_grant_is_accepted() {
    // Any write grant makes unmatched writes default-deny, so /srv is out of reach.
    assert_eq!(reach("", "/srv/session"), None);
    // The protected `:project_root/.bee` deny outranks the project's write grant.
    assert_eq!(reach("", "/work/.bee/session"), None);
}

#[test]
fn a_session_dir_a_tool_could_write_is_refused() {
    assert_eq!(
        reach("", "/work/session"),
        Some(PathBuf::from("/work/session"))
    );
    // A grant only on what lies beneath the directory still reaches the store's files.
    let below = Policy::from_toml(
        "[policy]\nname = \"p\"\n[policy.filesystem]\n\"/srv/session/evidence\" = \"write\"\n",
    )
    .unwrap();
    assert!(
        tool_writable_path(&below, Path::new("/srv/session"), &Fixed)
            .unwrap()
            .is_some_and(|p| p.starts_with("/srv/session/evidence"))
    );
    // A suffix grant reaches every receipt file.
    let suffix = Policy::from_toml(
        "[policy]\nname = \"p\"\n[policy.filesystem]\n\"/work\" = \"write\"\n\"*.json\" = \"write\"\n",
    )
    .unwrap();
    assert!(
        tool_writable_path(&suffix, Path::new("/srv/session"), &Fixed)
            .unwrap()
            .is_some_and(|p| p.extension().is_some_and(|e| e == "json"))
    );
}

#[test]
fn a_policy_without_write_grants_or_in_observe_mode_reaches_the_dir() {
    // No write rule at all: the kernel leaves unmatched writes allowed.
    let open = Policy::from_toml("[policy]\nname = \"p\"\n").unwrap();
    assert!(tool_writable_path(&open, Path::new("/srv/session"), &Fixed)
        .unwrap()
        .is_some());
    // Observe mode records and blocks nothing.
    assert!(reach("mode = \"observe\"", "/srv/session").is_some());
}
