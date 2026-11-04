//! Host-environment [`bee_core::Resolver`] used to compile policies against the real machine.
//!
//! The `Resolver` trait lives in `bee-core` (pure, no ambient I/O — NFR-005); this concrete
//! implementation — reading cwd / `$HOME` / `PATH` / system DNS — lives here in `bee-userspace`, the
//! crate that owns host-facing operations and already provides [`crate::spawn::resolve_in_path`].
//! Shared by the application package (the standard abstract-trait-in-core, concrete-impl-in-a-
//! higher-crate pattern). Sync only — no async runtime; `resolve_host` blocks at policy-compile
//! time, before any agent loop runs.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use bee_core::{CompileError, ExecIdentity, Resolver};

/// Diagnose path rules that differ from the path the kernel sees. This is advisory:
/// validation never rewrites a grant, and pinned rules already identify the target inode.
pub fn exec_path_warnings(policy: &bee_core::CompiledPolicy) -> Vec<String> {
    use std::os::unix::ffi::OsStrExt;

    policy.exec.iter().filter(|rule| !rule.pin_inode).filter_map(|rule| {
        let path = Path::new(std::ffi::OsStr::from_bytes(&rule.path));
        match path.canonicalize() {
            Ok(target) if target != path => Some(format!(
                "exec allow path '{}' resolves to '{}'; the kernel matches the resolved file path, so this entry may deny execution. Explicitly allow '{}' if intended (also permits executing that target directly). The rule is unchanged.",
                path.display(), target.display(), target.display()
            )),
            Ok(_) => None,
            Err(error) => Some(format!(
                "cannot inspect exec allow path '{}': {error}; resolved-path matching could not be checked. The rule is unchanged.",
                path.display()
            )),
        }
    }).collect()
}

/// Convert a libc `st_dev` into the kernel's `s_dev` encoding — a **conversion, not a cast**.
///
/// glibc packs a 64-bit `dev_t` with the major split across two ranges; the kernel's `s_dev` is the
/// 32-bit `(major << 20) | minor` that `new_encode_dev` produces, and that is the value the LSM hook
/// reads out of `super_block`. Comparing the two directly would silently never match, which for a
/// pin means an exec the operator granted is denied — fail-closed, but for a reason no one could
/// diagnose.
fn kernel_dev(st_dev: u64) -> u32 {
    let major = libc::major(st_dev);
    let minor = libc::minor(st_dev);
    ((major & 0xfff) << 20) | (minor & 0xf_ffff)
}

/// Resolver backed by the real host environment (cwd, `$HOME`, `PATH`, system DNS).
pub struct SystemResolver {
    root: String,
    home: String,
}

impl SystemResolver {
    /// Capture the current host environment: cwd as project root (fallback `"."`) and `$HOME`
    /// (fallback `"/root"`).
    pub fn current() -> Self {
        let root = std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| ".".into());
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
        SystemResolver { root, home }
    }
}

impl Resolver for SystemResolver {
    fn project_root(&self) -> &str {
        &self.root
    }
    fn home(&self) -> &str {
        &self.home
    }
    fn resolve_exec(&self, name: &str) -> Result<PathBuf, CompileError> {
        crate::spawn::resolve_in_path(name)
            .ok_or_else(|| CompileError::UnresolvableExec(name.into(), "not found on PATH".into()))
    }
    fn resolve_exec_identity(&self, path: &Path) -> Result<ExecIdentity, CompileError> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path).map_err(|e| {
            CompileError::UnresolvableExec(path.display().to_string(), format!("cannot stat: {e}"))
        })?;
        Ok(ExecIdentity {
            ino: meta.ino(),
            dev: kernel_dev(meta.dev()),
        })
    }
    fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, CompileError> {
        use std::net::ToSocketAddrs;
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let addrs = (host, 0u16)
            .to_socket_addrs()
            .map_err(|e| CompileError::UnresolvableHost(host.into(), e.to_string()))?;
        let ips: Vec<IpAddr> = addrs.map(|sa| sa.ip()).collect();
        if ips.is_empty() {
            return Err(CompileError::UnresolvableHost(
                host.into(),
                "no addresses".into(),
            ));
        }
        Ok(ips)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_returns_nonempty_paths() {
        let r = SystemResolver::current();
        assert!(!r.project_root().is_empty());
        assert!(!r.home().is_empty());
    }

    #[test]
    fn resolve_exec_finds_sh() {
        let r = SystemResolver::current();
        let p = r.resolve_exec("sh").expect("sh resolves on PATH");
        assert!(p.is_absolute(), "expected an absolute path, got {p:?}");
    }

    #[test]
    fn resolve_exec_rejects_missing() {
        let r = SystemResolver::current();
        let err = r.resolve_exec("definitely-not-a-binary-xyz").unwrap_err();
        assert!(matches!(err, CompileError::UnresolvableExec(..)));
    }

    #[test]
    fn resolve_host_parses_ip_literal() {
        let r = SystemResolver::current();
        let ips = r.resolve_host("127.0.0.1").expect("ip literal resolves");
        assert_eq!(ips, vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
    }
}
