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
    pub fn cgroup_id(&self) -> u64 {
        self.inode
    }

    pub fn remove_empty(&self) -> std::io::Result<()> {
        if std::fs::read_to_string("/proc/sys/kernel/random/boot_id")? != self.boot {
            return Ok(());
        }
        let meta = std::fs::symlink_metadata(&self.path)?;
        if meta.dev() != self.device || meta.ino() != self.inode {
            return Err(std::io::Error::other("executor identity changed"));
        }
        let mut paths = vec![self.path.clone()];
        let mut index = 0;
        while index < paths.len() {
            for entry in std::fs::read_dir(&paths[index])? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    if paths.len() >= 256 {
                        return Err(std::io::Error::other(
                            "executor cgroup tree exceeds cleanup bound",
                        ));
                    }
                    paths.push(entry.path());
                }
            }
            index += 1;
        }
        for path in paths.into_iter().rev() {
            std::fs::remove_dir(path)?;
        }
        Ok(())
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

impl super::Driver {
    /// Reconcile all slots before inspecting individual script outcomes. A failed stop
    /// leaves every identity in the journal for the next activation to retry.
    pub(super) async fn reconcile_batch_executors(&mut self) -> Result<(), super::DriverError> {
        use super::*;
        let executors = self.active().batch_executors.clone();
        let mut failed = None;
        for (id, executor) in &executors {
            if !executor.stop().await.unwrap_or(false) {
                failed.get_or_insert(*id);
            }
        }
        if let Some(id) = failed {
            return Err(DriverError::Unresolved(id.0));
        }
        for id in executors.keys() {
            match self
                .state
                .committed()
                .operation(*id)
                .map(|o| o.phase.clone())
            {
                Some(Phase::Recovering { attempt }) => {
                    let now_ms = self.time();
                    self.apply(Event::Recovered {
                        token: RecoveryToken {
                            activation: self.state.activation(),
                            attempt,
                        },
                        outcome: RecoveryOutcome::Quiescent,
                        now_ms,
                    })
                    .await?;
                }
                Some(Phase::Cancelling { attempt, .. }) => {
                    self.apply(Event::Cleaned {
                        token: RecoveryToken {
                            activation: self.state.activation(),
                            attempt,
                        },
                    })
                    .await?;
                }
                _ => {}
            }
        }
        if executors.keys().any(|id| {
            self.state
                .committed()
                .operation(*id)
                .is_some_and(|op| matches!(op.phase, Phase::Running { .. }))
        }) {
            return Ok(());
        }
        if !executors.is_empty() {
            self.active_mut().batch_executors.clear();
            self.save().await?;
            for executor in executors.values() {
                executor.remove_empty()?;
            }
        }
        Ok(())
    }
}
