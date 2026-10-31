//! Descriptor-relative extraction of verified Git objects. Runs only in the scoped source worker.

use super::{commit_id, err, object, SourcePin};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Materialization {
    pub pin: SourcePin,
    pub files: usize,
    pub bytes: usize,
    pub manifest_sha256: String,
}

fn open_at(parent: &File, name: &CStr, flags: i32, mode: u32) -> Result<File, String> {
    // SAFETY: parent descriptor and nul-terminated name remain live during openat.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: openat returned a newly owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn directory(parent: &File, name: &CStr) -> Result<File, String> {
    // SAFETY: valid parent descriptor and child name; existing entries are always refused.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    open_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)
}

struct Budget {
    entries: usize,
    bytes: usize,
    files: usize,
    manifest: Sha256,
}

fn extract(
    repo: &gix::Repository,
    id: gix::ObjectId,
    dir: &File,
    path: &str,
    budget: &mut Budget,
    depth: usize,
) -> Result<(), String> {
    if depth > 64 {
        return Err("snapshot depth exceeds 64".into());
    }
    let tree = object(repo, id)?.try_into_tree().map_err(err)?;
    budget.bytes += tree.data.len();
    if budget.bytes > 64 * 1024 * 1024 {
        return Err("snapshot exceeds 64 MiB object budget".into());
    }
    for entry in tree.iter() {
        let entry = entry.map_err(err)?;
        budget.entries += 1;
        if budget.entries > 4096 {
            return Err("snapshot exceeds 4096 entries".into());
        }
        let name = std::str::from_utf8(entry.filename().as_ref()).map_err(err)?;
        if name.is_empty()
            || name.len() > 255
            || name == "."
            || name == ".."
            || name.eq_ignore_ascii_case(".git")
            || name.contains(['/', '\\', '\0'])
        {
            return Err("snapshot contains an unsafe entry name".into());
        }
        let child_path = format!("{path}{name}");
        if child_path.len() > 4096 {
            return Err("snapshot path exceeds 4096 bytes".into());
        }
        let c_name = CString::new(name).map_err(err)?;
        let mode = entry.mode().as_str();
        if mode == "tree" {
            let child = directory(dir, &c_name)?;
            extract(
                repo,
                entry.object_id(),
                &child,
                &format!("{child_path}/"),
                budget,
                depth + 1,
            )?;
        } else if mode == "blob" || mode == "exe" {
            let blob = object(repo, entry.object_id())?
                .try_into_blob()
                .map_err(err)?;
            budget.bytes += blob.data.len();
            if budget.bytes > 64 * 1024 * 1024 {
                return Err("snapshot exceeds 64 MiB object budget".into());
            }
            let mut file = open_at(
                dir,
                &c_name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                if mode == "exe" { 0o700 } else { 0o600 },
            )?;
            file.write_all(&blob.data).map_err(err)?;
            budget.files += 1;
            // JSON lines preserve path/mode/content identity without ambiguity.
            let record = serde_json::to_vec(&(
                child_path,
                mode,
                entry.object_id().to_string(),
                format!("{:x}", Sha256::digest(&blob.data)),
            ))
            .map_err(err)?;
            budget.manifest.update(record);
            budget.manifest.update(b"\n");
        } else {
            return Err("snapshot contains a symlink or submodule; materialization refused".into());
        }
    }
    Ok(())
}

pub(super) fn materialize(pin: SourcePin, destination: &Path) -> Result<Materialization, String> {
    if !destination.is_absolute() {
        return Err("snapshot destination must be absolute".into());
    }
    let mut parent = File::open("/").map_err(err)?;
    for component in destination.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                parent = open_at(
                    &parent,
                    &CString::new(name.as_bytes()).map_err(err)?,
                    libc::O_RDONLY | libc::O_DIRECTORY,
                    0,
                )?;
            }
            _ => return Err("snapshot destination is not normalized".into()),
        }
    }
    let repo = gix::open(&pin.repository).map_err(err)?;
    let commit = object(&repo, commit_id(&pin.commit)?)?
        .try_into_commit()
        .map_err(err)?;
    let tree = commit.tree_id().map_err(err)?.detach();
    if tree.to_string() != pin.tree {
        return Err("pin tree does not match commit".into());
    }
    let dir = directory(&parent, c"source")?;
    let mut budget = Budget {
        entries: 0,
        files: 0,
        bytes: 0,
        manifest: Sha256::new(),
    };
    extract(&repo, tree, &dir, "", &mut budget, 0)?;
    Ok(Materialization {
        pin,
        files: budget.files,
        bytes: budget.bytes,
        manifest_sha256: format!("{:x}", budget.manifest.finalize()),
    })
}
