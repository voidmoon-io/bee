//! Reconcile a previously owned kernel scope by boot identity and directory inode, never PID.
//! Host mode has no durable descendant boundary and therefore reports Unknown after a crash.
use crate::Sandbox;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Executor {
    boot: String,
    path: PathBuf,
    device: u64,
    inode: u64,
}
impl Executor {
    pub fn capture(sandbox: &Sandbox) -> std::io::Result<Option<Self>> {
        #[cfg(not(feature = "enforce"))]
        {
            let _ = sandbox;
            Ok(None)
        }
        #[cfg(feature = "enforce")]
        {
            let Some(path) = sandbox.scope_path() else {
                return Ok(None);
            };
            let path = path.canonicalize()?;
            let meta = std::fs::symlink_metadata(&path)?;
            Ok(Some(Self {
                boot: std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?,
                path,
                device: meta.dev(),
                inode: meta.ino(),
            }))
        }
    }
    pub async fn stop(&self) -> std::io::Result<bool> {
        if std::fs::read_to_string("/proc/sys/kernel/random/boot_id")? != self.boot {
            return Ok(true);
        }
        // Missing/replaced paths are not evidence of stopped descendants.
        if !self.path.starts_with("/sys/fs/cgroup") || self.path.canonicalize()? != self.path {
            return Ok(false);
        }
        let meta = std::fs::symlink_metadata(&self.path)?;
        if !meta.is_dir() || meta.dev() != self.device || meta.ino() != self.inode {
            return Ok(false);
        }
        std::fs::write(self.path.join("cgroup.kill"), "1")?;
        for _ in 0..100 {
            if std::fs::read_to_string(self.path.join("cgroup.events"))?
                .lines()
                .any(|s| s == "populated 0")
            {
                return Ok(true);
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        Ok(false)
    }
}
