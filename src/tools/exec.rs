//! Shared child-execution helper. Every file/process tool routes through here so they all run as
//! hardened, credential-stripped, scope-confined children (contracts/tool-contracts.md).

use std::process::Stdio;

use tokio::io::AsyncWriteExt;
use tokio::process::Command as TokioCommand;

use crate::sandbox::Sandbox;
use crate::tools::ToolResult;
use crate::transcript::tool_result_from_output;

/// Run `program args` inside `sandbox`, optionally feeding `stdin_data`, capping output at `cap`.
///
/// stdout (and, if non-empty, a `\n[stderr]\n…` section) becomes the result content; `is_error` is
/// set on any non-zero exit — which is how a kernel denial (`cat: …: Permission denied`, exit 1)
/// surfaces. A spawn refusal (e.g. a privileged target) is itself an error result, never a panic.
pub async fn run_child(
    sandbox: &Sandbox,
    program: &str,
    args: &[String],
    stdin_data: Option<Vec<u8>>,
    cap: usize,
) -> ToolResult {
    let std_cmd = match sandbox.tool_command(program, args) {
        Ok(c) => c,
        Err(e) => return ToolResult::error(format!("{program}: cannot spawn: {e}")),
    };

    let mut cmd = TokioCommand::from(std_cmd);
    cmd.stdin(if stdin_data.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    // If the loop's per-call timeout drops this future, kill the child rather than leak it.
    .kill_on_drop(true)
    // Give the child its own process group so we can reap what it leaves behind. `kill_on_drop`
    // and the wait below only ever reach the direct child: a shell that backgrounds a redirected
    // descendant (`cmd >/dev/null 2>&1 &`) exits cleanly while the descendant keeps running. In a
    // host sandbox there is no cgroup to catch it, so the process group is the only handle.
    .process_group(0);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return ToolResult::error(format!("{program}: spawn failed: {e}")),
    };
    // `process_group(0)` makes the child its own group leader, so the group id is its pid. Capture
    // it now — `wait_with_output` consumes the handle.
    let pgid = child.id().map(|id| id as i32);

    // Write stdin concurrently with output draining to avoid a pipe deadlock on large payloads.
    if let (Some(data), Some(mut sink)) = (stdin_data, child.stdin.take()) {
        tokio::spawn(async move {
            let _ = sink.write_all(&data).await;
            let _ = sink.shutdown().await;
        });
    }

    let out = match child.wait_with_output().await {
        Ok(o) => o,
        Err(e) => {
            kill_process_group(pgid);
            return ToolResult::error(format!("{program}: wait failed: {e}"));
        }
    };
    // The direct child is gone; anything it backgrounded is not. A tool call ends when it ends.
    kill_process_group(pgid);

    let mut content = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.stderr.is_empty() {
        if !content.is_empty() {
            content.push('\n');
        }
        content.push_str("[stderr]\n");
        content.push_str(&String::from_utf8_lossy(&out.stderr));
    }
    tool_result_from_output(content, out.status.code(), !out.status.success(), cap)
        .with_provenance(crate::provider::Provenance::Child)
}

/// What a timed child left behind (016-native-tools, T039a).
///
/// Deliberately not a [`ToolResult`]. [`run_child`] folds stderr into the content, caps it, and
/// reports only "was it non-zero" — all correct for a tool whose output *is* its answer, and all
/// wrong for a pipeline stage whose output has to be parsed and whose success is decided by
/// something other than its exit status (research R6). So this returns the pieces separately and
/// lets the caller judge.
#[cfg(feature = "scanners")]
pub struct ChildRun {
    pub stdout: String,
    pub stderr: String,
    /// `None` when the child was killed by a signal — which is not the same as a non-zero exit and
    /// must not be read as one.
    pub code: Option<i32>,
    pub success: bool,
}

/// Why a timed child produced no result at all.
#[cfg(feature = "scanners")]
pub enum ChildError {
    /// The child did not finish within its budget and was killed. Never a partial `Completed`.
    TimedOut(std::time::Duration),
    /// It could not be spawned or waited on.
    Spawn(String),
}

#[cfg(feature = "scanners")]
impl std::fmt::Display for ChildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChildError::TimedOut(d) => write!(f, "timed out after {}s", d.as_secs()),
            ChildError::Spawn(e) => f.write_str(e),
        }
    }
}

/// Run `program args` inside `sandbox` under a wall-clock `budget`, keeping stdout and stderr apart.
///
/// Same hardened, scope-joined, credential-stripped spawn as [`run_child`] — it goes through the
/// same [`Sandbox::tool_command`] — and the same process-group cleanup, which matters more here:
/// a scanner that exceeds its budget is killed mid-walk, and anything it forked has to go with it.
#[cfg(feature = "scanners")]
pub async fn run_child_timed(
    sandbox: &Sandbox,
    program: &str,
    args: &[String],
    budget: std::time::Duration,
) -> Result<ChildRun, ChildError> {
    let std_cmd = match sandbox.tool_command(program, args) {
        Ok(c) => c,
        Err(e) => return Err(ChildError::Spawn(format!("{program}: cannot spawn: {e}"))),
    };

    let mut cmd = TokioCommand::from(std_cmd);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return Err(ChildError::Spawn(format!("{program}: spawn failed: {e}"))),
    };
    let pgid = child.id().map(|id| id as i32);

    let out = match tokio::time::timeout(budget, child.wait_with_output()).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            kill_process_group(pgid);
            return Err(ChildError::Spawn(format!("{program}: wait failed: {e}")));
        }
        Err(_elapsed) => {
            // The future is dropped here, so `kill_on_drop` reaps the direct child; the group kill
            // catches whatever it left running.
            kill_process_group(pgid);
            return Err(ChildError::TimedOut(budget));
        }
    };
    kill_process_group(pgid);

    Ok(ChildRun {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        code: out.status.code(),
        success: out.status.success(),
    })
}

/// SIGKILL every process left in the tool child's process group.
///
/// The group leader has already been reaped by the time this runs, so the only members left are
/// descendants the child backgrounded. `ESRCH` (nobody left) is the common, expected outcome.
fn kill_process_group(pgid: Option<i32>) {
    let Some(pgid) = pgid else { return };
    // SAFETY: a negative pid signals the process group with that id. `process_group(0)` made the
    // child a group leader, so the group contains only it and its descendants — never bee itself.
    unsafe { libc::kill(-pgid, libc::SIGKILL) };
}
