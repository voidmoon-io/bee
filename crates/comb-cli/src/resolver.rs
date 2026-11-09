//! The [`bee_core::Resolver`] `comb serve` compiles `[policy.http]` with: the project root, `$HOME`,
//! `PATH`, and the system resolver. Executable identity only matters to a kernel scope, which comb
//! does not create; it is answered from `stat` all the same so a policy compiles exactly as in bee.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use bee_core::{CompileError, ExecIdentity, Resolver};

pub struct HostResolver {
    root: String,
    home: String,
}

impl HostResolver {
    pub fn new(project_root: &Path) -> Self {
        HostResolver {
            root: project_root.display().to_string(),
            home: std::env::var("HOME").unwrap_or_else(|_| "/root".into()),
        }
    }
}

impl Resolver for HostResolver {
    fn project_root(&self) -> &str {
        &self.root
    }

    fn home(&self) -> &str {
        &self.home
    }

    fn resolve_exec(&self, name: &str) -> Result<PathBuf, CompileError> {
        let found = if name.contains('/') {
            Some(PathBuf::from(name)).filter(|p| p.is_file())
        } else {
            std::env::var_os("PATH").and_then(|path| {
                std::env::split_paths(&path)
                    .map(|d| d.join(name))
                    .find(|p| p.is_file())
            })
        };
        found.ok_or_else(|| CompileError::UnresolvableExec(name.into(), "not found on PATH".into()))
    }

    fn resolve_exec_identity(&self, path: &Path) -> Result<ExecIdentity, CompileError> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path).map_err(|e| {
            CompileError::UnresolvableExec(path.display().to_string(), format!("cannot stat: {e}"))
        })?;
        Ok(ExecIdentity {
            ino: meta.ino(),
            dev: meta.dev() as u32,
        })
    }

    fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, CompileError> {
        use std::net::ToSocketAddrs;
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let ips: Vec<IpAddr> = (host, 0u16)
            .to_socket_addrs()
            .map_err(|e| CompileError::UnresolvableHost(host.into(), e.to_string()))?
            .map(|sa| sa.ip())
            .collect();
        if ips.is_empty() {
            return Err(CompileError::UnresolvableHost(
                host.into(),
                "no addresses".into(),
            ));
        }
        Ok(ips)
    }
}
