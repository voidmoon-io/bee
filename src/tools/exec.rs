//! Bounded subprocess I/O with one owner for the child and its cancellation cleanup.

use crate::sandbox::Sandbox;
use crate::tools::ToolResult;
use std::io;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);
// 200 normalized findings at 4 KiB each fit comfortably. Raw reports need more space;
// this is a protocol limit, independent of the small model-facing tool-result cap.
#[cfg(feature = "scanners")]
const SCANNER_OUTPUT_CAP: usize = 8 * 1024 * 1024;

struct ChildOwner<'a> {
    child: Child,
    pgid: i32,
    cgroup: Option<PathBuf>,
    sandbox: &'a Sandbox,
    signaled: bool,
    finished: bool,
}

impl ChildOwner<'_> {
    fn signal(&mut self) -> io::Result<()> {
        if self.signaled {
            return Ok(());
        }
        // SAFETY: process_group(0) established a dedicated group led by this child.
        if unsafe { libc::kill(-self.pgid, libc::SIGKILL) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        if let Some(path) = &self.cgroup {
            std::fs::write(path.join("cgroup.kill"), "1")?;
        }
        self.signaled = true;
        Ok(())
    }

    fn cleanup(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        self.signal()?;
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        // Drop cannot await. Bounded synchronous cleanup retains the borrowed sandbox (and its
        // enforcement engine) until the child has exited, including when an outer future cancels.
        loop {
            let reaped = self.child.try_wait()?.is_some();
            let empty = match &self.cgroup {
                Some(path) => std::fs::read_to_string(path.join("cgroup.events"))?
                    .lines()
                    .any(|line| line == "populated 0"),
                None => true,
            };
            if reaped && empty {
                break;
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "child cleanup could not confirm exit",
                ));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        if let Some(path) = &self.cgroup {
            remove_cgroup_tree(path)?;
        }
        self.finished = true;
        Ok(())
    }
}

fn remove_cgroup_tree(root: &std::path::Path) -> io::Result<()> {
    let mut paths = vec![root.to_path_buf()];
    let mut index = 0;
    while index < paths.len() {
        for entry in std::fs::read_dir(&paths[index])? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                if paths.len() >= 256 {
                    return Err(io::Error::other(
                        "invocation cgroup tree exceeds cleanup bound",
                    ));
                }
                paths.push(entry.path());
            }
        }
        index += 1;
    }
    for path in paths.iter().rev() {
        std::fs::remove_dir(path)?;
    }
    Ok(())
}

impl Drop for ChildOwner<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            self.sandbox.cleanup_failed(error.to_string());
        }
    }
}

struct Capture {
    bytes: Vec<u8>,
    total: usize,
}

async fn drain(
    mut pipe: impl AsyncRead + Unpin,
    cap: usize,
    reject_overflow: bool,
) -> io::Result<Capture> {
    let mut output = Capture {
        bytes: Vec::new(),
        total: 0,
    };
    let mut chunk = [0; 8192];
    loop {
        let n = pipe.read(&mut chunk).await?;
        if n == 0 {
            return Ok(output);
        }
        output.total = output.total.saturating_add(n);
        if reject_overflow && output.total > cap {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "subprocess protocol output exceeds byte limit",
            ));
        }
        let keep = n.min(cap.saturating_sub(output.bytes.len()));
        output.bytes.extend_from_slice(&chunk[..keep]);
    }
}

async fn capture(
    sandbox: &Sandbox,
    program: &str,
    args: &[String],
    input: Option<Vec<u8>>,
    cap: usize,
    protocol: bool,
) -> io::Result<(ExitStatus, Capture, Capture)> {
    let (command, cgroup) = sandbox
        .invocation_command(program, args)
        .map_err(io::Error::other)?;
    let mut command = Command::from(command);
    command
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            if let Some(path) = cgroup {
                std::fs::remove_dir(path)?;
            }
            return Err(error);
        }
    };
    let pgid = child.id().expect("newly spawned child has a pid") as i32;
    let mut owner = ChildOwner {
        child,
        pgid,
        cgroup,
        sandbox,
        signaled: false,
        finished: false,
    };
    let stdout = owner.child.stdout.take().expect("piped stdout");
    let stderr = owner.child.stderr.take().expect("piped stderr");
    let stdin = owner.child.stdin.take();
    let wait = async {
        let status = owner.child.wait().await?;
        // Kill background writers before waiting for pipe EOF; they can inherit open pipes.
        owner.signal()?;
        Ok::<_, io::Error>(status)
    };
    let write = async {
        if let (Some(data), Some(mut sink)) = (input, stdin) {
            match sink.write_all(&data).await {
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe => (),
                result => result?,
            }
        }
        Ok::<_, io::Error>(())
    };
    let (status, out, err, ()) = tokio::try_join!(
        wait,
        drain(stdout, cap, protocol),
        drain(stderr, cap.min(64 * 1024), protocol),
        write
    )?;
    owner.cleanup()?;
    Ok((status, out, err))
}

pub async fn run_child(
    sandbox: &Sandbox,
    program: &str,
    args: &[String],
    stdin_data: Option<Vec<u8>>,
    cap: usize,
) -> ToolResult {
    let (status, out, err) = match capture(sandbox, program, args, stdin_data, cap, false).await {
        Ok(result) => result,
        Err(e) => return ToolResult::error(format!("{program}: {e}")),
    };
    let mut text = String::from_utf8_lossy(&out.bytes).into_owned();
    if err.total > 0 {
        text.push_str("\n[stderr]\n");
        text.push_str(&String::from_utf8_lossy(&err.bytes));
    }
    let total = out
        .total
        .saturating_add(err.total)
        .saturating_add(if err.total > 0 { 10 } else { 0 });
    let mut result =
        crate::transcript::tool_result_from_output(text, status.code(), !status.success(), cap);
    if total > cap {
        if !result.truncated {
            let shown = result.content.len();
            result
                .content
                .push_str(&format!("\n[truncated: {total} bytes, showing {shown}]"));
        }
        result.truncated = true;
        result.original_len = Some(total);
    }
    result
}

#[cfg(feature = "scanners")]
pub struct ChildRun {
    pub stdout: String,
    pub stderr: String,
    pub code: Option<i32>,
    pub success: bool,
}

#[cfg(feature = "scanners")]
pub enum ChildError {
    TimedOut(Duration),
    Spawn(String),
    OutputTooLarge,
}

#[cfg(feature = "scanners")]
impl std::fmt::Display for ChildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimedOut(d) => write!(f, "timed out after {}s", d.as_secs()),
            Self::Spawn(e) => f.write_str(e),
            Self::OutputTooLarge => f.write_str("subprocess protocol output exceeds byte limit"),
        }
    }
}

#[cfg(feature = "scanners")]
pub async fn run_child_timed(
    sandbox: &Sandbox,
    program: &str,
    args: &[String],
    budget: Duration,
) -> Result<ChildRun, ChildError> {
    match tokio::time::timeout(
        budget,
        capture(sandbox, program, args, None, SCANNER_OUTPUT_CAP, true),
    )
    .await
    {
        Err(_) => Err(ChildError::TimedOut(budget)),
        Ok(Err(e)) if e.kind() == io::ErrorKind::FileTooLarge => Err(ChildError::OutputTooLarge),
        Ok(Err(e)) => Err(ChildError::Spawn(e.to_string())),
        Ok(Ok((status, out, err))) => Ok(ChildRun {
            stdout: String::from_utf8_lossy(&out.bytes).into_owned(),
            stderr: String::from_utf8_lossy(&err.bytes).into_owned(),
            code: status.code(),
            success: status.success(),
        }),
    }
}
