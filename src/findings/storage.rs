//! Descriptor-relative ledger storage. Repository-controlled paths never follow symlinks.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) struct Storage {
    dir: File,
    // Closing the descriptor releases the cross-process advisory lock.
    _lock: File,
}

fn open_at(dir: &File, name: &CStr, flags: i32, mode: u32) -> io::Result<File> {
    // SAFETY: live directory descriptor, valid C string, and a supplied mode for O_CREAT.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new descriptor owned here.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn regular(dir: &File, name: &CStr, flags: i32) -> io::Result<File> {
    let file = open_at(dir, name, flags | libc::O_NONBLOCK, 0o600)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ledger entry must be a regular file with one link",
        ));
    }
    Ok(file)
}

impl Storage {
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        let mut dir = File::open(if path.is_absolute() {
            Path::new("/")
        } else {
            Path::new(".")
        })?;
        for component in path.components() {
            let name = match component {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(name) => CString::new(name.as_bytes())?,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "ledger path cannot contain parent traversal",
                    ))
                }
            };
            match open_at(&dir, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
                Ok(next) => dir = next,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    // SAFETY: valid parent descriptor and child component.
                    if unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                        let e = io::Error::last_os_error();
                        if e.kind() != io::ErrorKind::AlreadyExists {
                            return Err(e);
                        }
                    }
                    dir = open_at(&dir, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
                }
                Err(e) => return Err(e),
            }
        }
        let lock = regular(&dir, c"ledger.lock", libc::O_CREAT | libc::O_RDWR)?;
        // A bounded wait avoids hanging forever behind an abandoned/uncooperative process.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            // SAFETY: lock owns its descriptor for the entire transaction.
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::WouldBlock {
                return Err(e);
            }
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "ledger writer lock timed out",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        Ok(Self { dir, _lock: lock })
    }

    /// Read a bounded immutable object relative to the held directory descriptor.
    pub(crate) fn read_blob(&self, name: &CStr, limit: u64) -> io::Result<Vec<u8>> {
        use std::io::Read;
        let file = regular(&self.dir, name, libc::O_RDONLY)?;
        let mut bytes = Vec::new();
        file.take(limit + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "receipt exceeds size limit",
            ));
        }
        Ok(bytes)
    }

    /// Publish an object atomically; the writer lock serializes existence checks.
    pub(crate) fn publish_blob(&self, name: &CStr, bytes: &[u8]) -> io::Result<()> {
        match self.read_blob(name, bytes.len() as u64) {
            Ok(existing) if existing == bytes => {
                // A prior publication may have lost its acknowledgement at either sync.
                regular(&self.dir, name, libc::O_RDONLY)?.sync_all()?;
                return self.dir.sync_all();
            }
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "receipt identity conflict",
                ))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        // A stale temporary from an interrupted write is never treated as evidence.
        let temp_name = CString::new(format!(
            "receipt-{}-{}.tmp",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        ))?;
        let mut temp = regular(
            &self.dir,
            &temp_name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        let result = (|| {
            temp.write_all(bytes)?;
            temp.sync_all()?;
            // SAFETY: both names are relative to the directory descriptor held under the lock.
            if unsafe {
                libc::renameat(
                    self.dir.as_raw_fd(),
                    temp_name.as_ptr(),
                    self.dir.as_raw_fd(),
                    name.as_ptr(),
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            self.dir.sync_all()
        })();
        if result.is_err() {
            // SAFETY: only remove the temporary created by this operation.
            unsafe {
                libc::unlinkat(self.dir.as_raw_fd(), temp_name.as_ptr(), 0);
            }
        }
        result
    }

    pub(super) fn reader(&self) -> io::Result<Option<File>> {
        match regular(&self.dir, c"ledger.jsonl", libc::O_RDONLY) {
            Ok(file) => Ok(Some(file)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub(super) fn append(&self, line: &str) -> io::Result<()> {
        let mut file = regular(
            &self.dir,
            c"ledger.jsonl",
            libc::O_CREAT | libc::O_RDWR | libc::O_APPEND,
        )?;
        let len = file.metadata()?.len();
        if len > 0 {
            let mut last = [0];
            file.read_exact_at(&mut last, len - 1)?;
            if last[0] != b'\n' {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ledger has an incomplete trailing record; repair before appending",
                ));
            }
        }
        file.write_all(line.as_bytes())
    }

    pub(super) fn publish(&self, bytes: &[u8]) -> io::Result<()> {
        static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
        let mut temp = None;
        for _ in 0..32 {
            let name = CString::new(format!(
                "view.{}.{}.tmp",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ))?;
            match regular(
                &self.dir,
                &name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            ) {
                Ok(file) => {
                    temp = Some((name, file));
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        let (name, mut file) = temp.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "ledger cache temporary names exhausted",
            )
        })?;
        let result = (|| {
            file.write_all(bytes)?;
            // Replaces the directory entry itself, never follows an existing cache symlink.
            // SAFETY: both paths are relative to the live directory descriptor.
            if unsafe {
                libc::renameat(
                    self.dir.as_raw_fd(),
                    name.as_ptr(),
                    self.dir.as_raw_fd(),
                    c"view.json".as_ptr(),
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })();
        if result.is_err() {
            // SAFETY: remove only the exclusive temporary owned by this operation.
            unsafe {
                libc::unlinkat(self.dir.as_raw_fd(), name.as_ptr(), 0);
            }
        }
        result
    }
}
