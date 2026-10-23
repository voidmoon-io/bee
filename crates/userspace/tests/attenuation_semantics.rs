//! Capture the real encoded reload plan through its public map backend and evaluate its matcher.
use bee_common::layout::{DenyList, NetKey, ScopeMeta};
use bee_common::{ScopeMode, FLAG_FS_WRITE_DEFAULT_DENY};
use bee_core::{Access, Policy};
use bee_userspace::reload::{self, ScopeMaps};
use bee_userspace::{EnforcementPlan, SystemResolver};

struct Maps {
    meta: ScopeMeta,
    fs: Option<DenyList>,
}
impl ScopeMaps for Maps {
    fn meta(&self, _: u64) -> Result<Option<ScopeMeta>, String> {
        Ok(Some(self.meta))
    }
    fn set_meta(&mut self, _: u64, m: ScopeMeta) -> Result<(), String> {
        self.meta = m;
        Ok(())
    }
    fn fs(&self, _: u64) -> Result<Option<DenyList>, String> {
        Ok(self.fs)
    }
    fn set_fs(&mut self, _: u64, d: DenyList) -> Result<(), String> {
        self.fs = Some(d);
        Ok(())
    }
    fn remove_fs(&mut self, _: u64) -> Result<(), String> {
        self.fs = None;
        Ok(())
    }
    fn exec(&self, _: u64) -> Result<Option<DenyList>, String> {
        Ok(None)
    }
    fn set_exec(&mut self, _: u64, _: DenyList) -> Result<(), String> {
        Ok(())
    }
    fn remove_exec(&mut self, _: u64) -> Result<(), String> {
        Ok(())
    }
    fn net_keys(&self, _: u64) -> Result<Vec<NetKey>, String> {
        Ok(vec![])
    }
    fn insert_net(&mut self, _: NetKey) -> Result<(), String> {
        Ok(())
    }
    fn remove_net(&mut self, _: &NetKey) -> Result<(), String> {
        Ok(())
    }
}

fn allows_write(policy: &Policy, path: &[u8]) -> bool {
    let compiled = policy.compile(&SystemResolver::current()).unwrap();
    let plan = EnforcementPlan::prepare(&compiled, ScopeMode::Enforce).unwrap();
    let mut maps = Maps {
        meta: ScopeMeta {
            mode: 0,
            flags: 0,
            _pad: [0; 6],
        },
        fs: None,
    };
    reload::apply(&mut maps, 1, &plan).unwrap();
    !bee_common::matcher::fs_open_blocked(
        path,
        &maps.fs.unwrap(),
        true,
        maps.meta.flags & FLAG_FS_WRITE_DEFAULT_DENY != 0,
    )
}

#[test]
fn narrowing_write_to_read_preserves_unmatched_write_denial() {
    let parent = Policy::from_toml(
        "[policy]\nname='audit'\n[policy.filesystem]\n'/project-audit'='write'\n",
    )
    .unwrap();
    let mut request = parent.clone();
    request
        .filesystem
        .insert("/project-audit".into(), Access::Read);
    let child = parent.derive(request).unwrap();
    assert!(!allows_write(&parent, b"/outside-audit/file"));
    assert!(!allows_write(&child, b"/outside-audit/file"));
    let grandchild = child
        .derive(Policy::from_toml("[policy]\nname='grandchild'\n").unwrap())
        .unwrap();
    assert!(!allows_write(&grandchild, b"/outside-audit/file"));
}

#[test]
fn accepted_children_never_gain_sampled_write_authority() {
    for parent_access in ["read", "write"] {
        let parent = Policy::from_toml(&format!("[policy]\nname='parent'\n[policy.filesystem]\n'/project'='{parent_access}'\n'/private'='deny'\n")).unwrap();
        for child_access in ["read", "write", "deny"] {
            for root in ["/project", "/project/sub", "/private", "/outside"] {
                let request = Policy::from_toml(&format!(
                    "[policy]\nname='child'\n[policy.filesystem]\n'{root}'='{child_access}'\n"
                ))
                .unwrap();
                let Ok(child) = parent.derive(request) else {
                    continue;
                };
                for path in [
                    "/project",
                    "/project/file",
                    "/project/sub/file",
                    "/project-other",
                    "/private/file",
                    "/outside/file",
                ] {
                    assert!(!allows_write(&child, path.as_bytes()) || allows_write(&parent, path.as_bytes()), "child gained write access: {parent_access}, {child_access}, {root}, {path}");
                }
            }
        }
    }
}
