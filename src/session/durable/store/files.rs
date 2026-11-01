//! Private, descriptor-walked session directory. The directory inode is the writer lock.

use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use super::StoreError;

pub(super) struct Directory {
    dir: File,
    path: PathBuf,
}

fn open_at(dir: &File, name: &CStr, flags: i32) -> io::Result<File> {
    // SAFETY: live directory descriptor and nul-terminated relative name.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned an owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

impl Directory {
    pub(super) fn open(path: &Path) -> Result<Self, StoreError> {
        if !path.is_absolute() {
            return Err(StoreError::UnsafePath);
        }
        let mut dir = File::open("/")?;
        for component in path.components() {
            let Component::Normal(name) = component else {
                if component == Component::RootDir {
                    continue;
                }
                return Err(StoreError::UnsafePath);
            };
            let name =
                std::ffi::CString::new(name.as_bytes()).map_err(|_| StoreError::UnsafePath)?;
            match open_at(&dir, &name, libc::O_RDONLY | libc::O_DIRECTORY) {
                Ok(child) => dir = child,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    // SAFETY: live parent descriptor and valid component; no traversal accepted.
                    if unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                        let error = io::Error::last_os_error();
                        if error.kind() != io::ErrorKind::AlreadyExists {
                            return Err(error.into());
                        }
                    }
                    let child = open_at(&dir, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
                    dir.sync_all()?;
                    dir = child;
                }
                Err(error) => return Err(error.into()),
            }
        }
        let meta = dir.metadata()?;
        // SAFETY: geteuid has no preconditions.
        if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err(StoreError::UnsafePath);
        }
        // SAFETY: dir owns the descriptor until the Store is dropped. Nonblocking acquisition.
        if unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let error = io::Error::last_os_error();
            return Err(if error.kind() == io::ErrorKind::WouldBlock {
                StoreError::Locked
            } else {
                error.into()
            });
        }
        // Use SQLite's ordinary Unix VFS with NOFOLLOW. Hold the directory descriptor and
        // verify its identity before operations; a custom SQLite VFS is not needed here.
        let path = std::fs::read_link(format!("/proc/self/fd/{}", dir.as_raw_fd()))?;
        let result = Self { dir, path };
        result.check_entry(c"session.sqlite3", false)?;
        result.check_sidecars()?;
        // Precreate mode 0600 so SQLite's sidecars inherit private permissions even under umask 0.
        let file = open_at(
            &result.dir,
            c"session.sqlite3",
            libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK,
        )?;
        drop(file); // close before SQLite acquires any POSIX locks on this inode
        result.verify()?;
        result.sync()?;
        Ok(result)
    }

    pub(super) fn database(&self) -> PathBuf {
        self.path.join("session.sqlite3")
    }

    pub(super) fn sync(&self) -> Result<(), StoreError> {
        Ok(self.dir.sync_all()?)
    }

    fn check_sidecars(&self) -> Result<(), StoreError> {
        for name in [
            c"session.sqlite3-wal",
            c"session.sqlite3-shm",
            c"session.sqlite3-journal",
        ] {
            self.check_entry(name, false)?;
        }
        Ok(())
    }

    fn check_entry(&self, name: &CStr, required: bool) -> Result<(), StoreError> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: valid descriptor/name and writable stat memory. Never follow a link.
        if unsafe {
            libc::fstatat(
                self.dir.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            let error = io::Error::last_os_error();
            if !required && error.kind() == io::ErrorKind::NotFound {
                return Ok(());
            }
            return Err(error.into());
        }
        // SAFETY: successful fstatat initialized stat.
        let stat = unsafe { stat.assume_init() };
        // SAFETY: geteuid has no preconditions.
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || stat.st_nlink != 1
            || stat.st_uid != unsafe { libc::geteuid() }
            || stat.st_mode & 0o077 != 0
        {
            return Err(StoreError::UnsafePath);
        }
        Ok(())
    }

    pub(super) fn verify(&self) -> Result<(), StoreError> {
        let named = std::fs::symlink_metadata(&self.path)?;
        let held = self.dir.metadata()?;
        if !named.is_dir()
            || named.dev() != held.dev()
            || named.ino() != held.ino()
            || held.mode() & 0o077 != 0
        {
            return Err(StoreError::UnsafePath);
        }
        self.check_entry(c"session.sqlite3", true)?;
        self.check_sidecars()
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        // Store drops SQLite before this guard. Explicitly release the shared
        // open-description lock: a concurrent fork can retain this descriptor
        // until exec, even with O_CLOEXEC. Such children never use the store.
        // SAFETY: dir is still owned here; unlocking cannot release a lock on
        // another open description. Closing below remains the fallback.
        unsafe { libc::flock(self.dir.as_raw_fd(), libc::LOCK_UN) };
    }
}
