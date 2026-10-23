//! Capture the real encoded reload plan through its public map backend and evaluate its matcher.
use bee_common::layout::{DenyList, NetKey, ScopeMeta};
use bee_common::{FLAG_FS_WRITE_DEFAULT_DENY, ScopeMode};
use bee_core::{Access, Policy};
use bee_userspace::{EnforcementPlan, SystemResolver};
use bee_userspace::reload::{self, ScopeMaps};

struct Maps { meta: ScopeMeta, fs: Option<DenyList> }
impl ScopeMaps for Maps {
    fn meta(&self, _: u64) -> Result<Option<ScopeMeta>, String> { Ok(Some(self.meta)) }
    fn set_meta(&mut self, _: u64, m: ScopeMeta) -> Result<(), String> { self.meta = m; Ok(()) }
    fn fs(&self, _: u64) -> Result<Option<DenyList>, String> { Ok(self.fs) }
    fn set_fs(&mut self, _: u64, d: DenyList) -> Result<(), String> { self.fs = Some(d); Ok(()) }
    fn remove_fs(&mut self, _: u64) -> Result<(), String> { self.fs = None; Ok(()) }
    fn exec(&self, _: u64) -> Result<Option<DenyList>, String> { Ok(None) }
    fn set_exec(&mut self, _: u64, _: DenyList) -> Result<(), String> { Ok(()) }
    fn remove_exec(&mut self, _: u64) -> Result<(), String> { Ok(()) }
    fn net_keys(&self, _: u64) -> Result<Vec<NetKey>, String> { Ok(vec![]) }
    fn insert_net(&mut self, _: NetKey) -> Result<(), String> { Ok(()) }
    fn remove_net(&mut self, _: &NetKey) -> Result<(), String> { Ok(()) }
}

fn allows_outside_write(policy: &Policy) -> bool {
    let compiled = policy.compile(&SystemResolver::current()).unwrap();
    let plan = EnforcementPlan::prepare(&compiled, ScopeMode::Enforce).unwrap();
    let mut maps = Maps { meta: ScopeMeta { mode: 0, flags: 0, _pad: [0; 6] }, fs: None };
    reload::apply(&mut maps, 1, &plan).unwrap();
    !bee_common::matcher::fs_open_blocked(b"/outside-audit/file", &maps.fs.unwrap(), true,
        maps.meta.flags & FLAG_FS_WRITE_DEFAULT_DENY != 0)
}

#[test]
fn probe_narrowing_write_to_read_widens_unmatched_writes() {
    let parent = Policy::from_toml("[policy]\nname='audit'\n[policy.filesystem]\n'/project-audit'='write'\n").unwrap();
    let mut request = parent.clone();
    request.filesystem.insert("/project-audit".into(), Access::Read);
    let child = parent.derive(request).unwrap();
    assert!(!allows_outside_write(&parent));
    assert!(allows_outside_write(&child), "probe: an accepted child permits what its parent denies");
}
