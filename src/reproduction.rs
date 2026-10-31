//! Controlled behavior experiments with optional materialized source provenance, not proof of impact.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::sandbox::Sandbox;
use crate::security::ReproductionProfile;
use crate::source::{Materialization, SourcePin};
use crate::tools::exec::{run_probe, ChildError};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub profile: String,
    pub input: String,
    pub control_input: String,
    pub stdout_contains: String,
    pub repetitions: u32,
    #[serde(default)]
    pub snapshot: Option<String>,
    #[serde(default)]
    pub comparison_snapshot: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    Reproduced,
    NotReproduced,
    UnableToRun,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Attempt {
    #[serde(default)]
    pub materialization: Option<Materialization>,
    pub role: String,
    pub index: u32,
    pub exit_code: Option<i32>,
    pub signal_fired: bool,
    pub stdout_sha256: Option<String>,
    pub stderr_sha256: Option<String>,
    pub stdout_bytes: Option<usize>,
    pub stderr_bytes: Option<usize>,
    pub stdout_excerpt: String,
    pub stderr_excerpt: String,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    #[serde(default)]
    pub snapshot: Option<SourcePin>,
    #[serde(default)]
    pub comparison_snapshot: Option<SourcePin>,
    #[serde(default)]
    pub comparison: Option<String>,
    pub schema_version: u32,
    pub profile: String,
    pub execution_profile: ReproductionProfile,
    pub decision: Decision,
    pub behavior_reproduced: bool,
    pub impact_supported: String,
    pub source_binding: String,
    pub execution_posture: String,
    pub repetitions: u32,
    pub input_sha256: String,
    pub control_input_sha256: String,
    pub stdout_contains: String,
    pub attempts: Vec<Attempt>,
    pub reason: String,
}

pub fn validate(plan: &Plan, profile: &ReproductionProfile) -> Result<(), String> {
    if plan.comparison_snapshot.is_some() && plan.snapshot.is_none() {
        return Err("comparison_snapshot requires snapshot".into());
    }
    if !profile.program.is_absolute() || profile.program.to_str().is_none() {
        return Err("reproduction program must be an absolute UTF-8 path".into());
    }
    if !(1..=60).contains(&profile.timeout_secs) || !(2..=5).contains(&profile.max_repetitions) {
        return Err("profile timeout must be 1–60 seconds and max_repetitions 2–5".into());
    }
    if !(2..=profile.max_repetitions).contains(&plan.repetitions) {
        return Err(
            "repetitions must be at least 2 and within the operator profile ceiling".into(),
        );
    }
    if plan.input.len() > 64 * 1024 || plan.control_input.len() > 64 * 1024 {
        return Err("each probe input is limited to 64 KiB".into());
    }
    if plan.stdout_contains.is_empty() || plan.stdout_contains.len() > 1024 {
        return Err("stdout_contains must be nonempty and at most 1024 bytes".into());
    }
    if plan.input == plan.control_input {
        return Err("control input must differ from the positive input".into());
    }
    if profile.args.len() > 64
        || profile
            .args
            .iter()
            .any(|arg| arg.len() > 8192 || arg.contains('\0'))
    {
        return Err("profile arguments exceed limits or contain NUL".into());
    }
    Ok(())
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

struct AttemptSpec<'a> {
    input: &'a str,
    signal: &'a str,
    role: &'a str,
    index: u32,
    pin: Option<&'a SourcePin>,
    worker: &'a Path,
}

async fn stage(
    sandbox: &Sandbox,
    pin: &SourcePin,
    directory: &Path,
    worker: &Path,
    timeout: u64,
) -> Result<Materialization, String> {
    let request = crate::source::Request::Materialize {
        pin: pin.clone(),
        destination: directory.into(),
    };
    let args = vec![
        "source-worker".into(),
        "--request".into(),
        serde_json::to_string(&request).map_err(|e| e.to_string())?,
    ];
    let result = crate::tools::exec::run_child_timed(
        sandbox,
        &worker.to_string_lossy(),
        &args,
        Duration::from_secs(timeout),
    )
    .await
    .map_err(|e| e.to_string())?;
    if !result.success {
        return Err(format!(
            "snapshot materialization failed: {}",
            result.stderr.trim()
        ));
    }
    let materialization: Materialization =
        serde_json::from_str(&result.stdout).map_err(|e| e.to_string())?;
    if &materialization.pin != pin {
        return Err("materializer returned a different pin".into());
    }
    Ok(materialization)
}

async fn attempt(
    sandbox: &Sandbox,
    profile: &ReproductionProfile,
    spec: AttemptSpec<'_>,
) -> Attempt {
    let AttemptSpec {
        input,
        signal,
        role,
        index,
        pin,
        worker,
    } = spec;
    let mut attempt = Attempt {
        materialization: None,
        role: role.into(),
        index,
        exit_code: None,
        signal_fired: false,
        stdout_sha256: None,
        stderr_sha256: None,
        stdout_bytes: None,
        stderr_bytes: None,
        stdout_excerpt: String::new(),
        stderr_excerpt: String::new(),
        error: None,
    };
    let directory = match tempfile::Builder::new().prefix("bee-repro-").tempdir() {
        Ok(directory) => directory,
        Err(error) => {
            attempt.error = Some(format!("scratch unavailable: {error}"));
            return attempt;
        }
    };
    let mut cwd = directory.path().to_path_buf();
    if let Some(pin) = pin {
        match stage(sandbox, pin, directory.path(), worker, profile.timeout_secs).await {
            Ok(materialization) => {
                attempt.materialization = Some(materialization);
                cwd = cwd.join("source");
            }
            Err(error) => attempt.error = Some(error),
        }
    }
    if attempt.error.is_none() {
        let result = run_probe(
            sandbox,
            profile.program.to_str().expect("validated profile"),
            &profile.args,
            input.as_bytes().to_vec(),
            cwd,
            Duration::from_secs(profile.timeout_secs),
        )
        .await;
        match result {
            Ok(output) => {
                attempt.exit_code = output.code;
                attempt.signal_fired = output
                    .stdout
                    .windows(signal.len())
                    .any(|window| window == signal.as_bytes());
                attempt.stdout_sha256 = Some(hash(&output.stdout));
                attempt.stderr_sha256 = Some(hash(&output.stderr));
                attempt.stdout_bytes = Some(output.stdout.len());
                attempt.stderr_bytes = Some(output.stderr.len());
                attempt.stdout_excerpt =
                    String::from_utf8_lossy(&output.stdout[..output.stdout.len().min(512)])
                        .into_owned();
                attempt.stderr_excerpt =
                    String::from_utf8_lossy(&output.stderr[..output.stderr.len().min(512)])
                        .into_owned();
            }
            Err(error) => {
                attempt.error = Some(match error {
                    ChildError::TimedOut(_) => "probe timed out".into(),
                    ChildError::OutputTooLarge => "probe output exceeds 64 KiB".into(),
                    ChildError::Spawn(reason) => format!("probe could not run: {reason}"),
                })
            }
        }
    }
    if let Err(error) = directory.close() {
        let reason = format!("scratch cleanup failed: {error}");
        sandbox.cleanup_failed(reason.clone());
        attempt.error = Some(reason);
    }
    if let Err(error) = sandbox.check_cleanup() {
        attempt.error = Some(error);
    }
    attempt
}

pub async fn run(
    plan: Plan,
    profile: ReproductionProfile,
    sandbox: &Sandbox,
) -> Result<Report, String> {
    run_pinned(
        plan,
        profile,
        sandbox,
        None,
        std::env::current_exe().map_err(|e| e.to_string())?,
    )
    .await
}

pub async fn run_pinned(
    plan: Plan,
    profile: ReproductionProfile,
    sandbox: &Sandbox,
    pins: Option<(SourcePin, Option<SourcePin>)>,
    worker: PathBuf,
) -> Result<Report, String> {
    run_inner(
        plan,
        profile,
        ExecutionSandbox::Shared(sandbox),
        pins,
        worker,
        #[cfg(feature = "durable-sessions")]
        None,
    )
    .await
    .map_err(|e| e.to_string())
}

#[derive(Debug, thiserror::Error)]
enum RunError {
    #[error("{0}")]
    Invalid(String),
    #[cfg(feature = "durable-sessions")]
    #[error(transparent)]
    Durable(#[from] crate::session::driver::DriverError),
}
#[cfg(feature = "durable-sessions")]
pub async fn run_pinned_journaled(
    plan: Plan,
    profile: ReproductionProfile,
    sandbox: &mut Sandbox,
    pins: Option<(SourcePin, Option<SourcePin>)>,
    worker: PathBuf,
    journal: &mut crate::session::driver::journal::Journal,
) -> Result<Report, crate::session::driver::DriverError> {
    run_inner(
        plan,
        profile,
        ExecutionSandbox::Journaled(sandbox),
        pins,
        worker,
        Some(journal),
    )
    .await
    .map_err(|e| match e {
        RunError::Invalid(s) => crate::session::driver::DriverError::Refused(s),
        RunError::Durable(e) => e,
    })
}
impl From<String> for RunError {
    fn from(value: String) -> Self {
        Self::Invalid(value)
    }
}
enum ExecutionSandbox<'a> {
    Shared(&'a Sandbox),
    #[cfg(feature = "durable-sessions")]
    Journaled(&'a mut Sandbox),
}
impl ExecutionSandbox<'_> {
    fn get(&self) -> &Sandbox {
        match self {
            Self::Shared(s) => s,
            #[cfg(feature = "durable-sessions")]
            Self::Journaled(s) => s,
        }
    }
}
#[allow(unused_mut)]
async fn run_inner(
    plan: Plan,
    profile: ReproductionProfile,
    mut sandbox: ExecutionSandbox<'_>,
    pins: Option<(SourcePin, Option<SourcePin>)>,
    worker: PathBuf,
    #[cfg(feature = "durable-sessions")] mut journal: Option<
        &mut crate::session::driver::journal::Journal,
    >,
) -> Result<Report, RunError> {
    validate(&plan, &profile)?;
    if plan.snapshot.is_some() != pins.is_some()
        || plan.comparison_snapshot.is_some() != pins.as_ref().and_then(|p| p.1.as_ref()).is_some()
    {
        return Err(
            String::from("requested snapshot receipts must be resolved before execution").into(),
        );
    }
    if let Some((pin, Some(comparison))) = &pins {
        if pin.repository != comparison.repository || pin.commit == comparison.commit {
            return Err(String::from(
                "comparison must be a different commit of the same repository",
            )
            .into());
        }
    }
    let snapshot = pins.as_ref().map(|p| p.0.clone());
    let comparison_snapshot = pins.as_ref().and_then(|p| p.1.clone());
    let mut report = Report {
        schema_version: 2,
        snapshot: snapshot.clone(),
        comparison_snapshot: comparison_snapshot.clone(),
        comparison: comparison_snapshot.as_ref().map(|_| "not-completed".into()),
        profile: plan.profile.clone(),
        execution_profile: profile.clone(),
        decision: Decision::UnableToRun,
        behavior_reproduced: false,
        impact_supported: "unknown".into(),
        source_binding: "unbound".into(),
        execution_posture: match sandbox.get() {
            Sandbox::Host(_) => "host",
            #[cfg(feature = "enforce")]
            _ => "bee-scope",
        }
        .into(),
        repetitions: plan.repetitions,
        input_sha256: hash(plan.input.as_bytes()),
        control_input_sha256: hash(plan.control_input.as_bytes()),
        stdout_contains: plan.stdout_contains.clone(),
        attempts: Vec::new(),
        reason: String::new(),
    };
    // Every positive and control starts a fresh process in a fresh workspace. External state is not reset.
    let mut phases = vec![
        ("positive", &plan.input, snapshot.as_ref()),
        ("control", &plan.control_input, snapshot.as_ref()),
    ];
    if let Some(pin) = comparison_snapshot.as_ref() {
        phases.extend([
            ("comparison", &plan.input, Some(pin)),
            ("comparison-control", &plan.control_input, Some(pin)),
        ]);
    }
    for (role, input, pin) in phases {
        for index in 1..=plan.repetitions {
            #[cfg(feature = "durable-sessions")]
            let key = format!("{role}:{index}");
            #[cfg(feature = "durable-sessions")]
            let previous = if let Some(journal) = &mut journal {
                journal
                    .begin(key.clone(), &(&plan, &profile, pin, role, index))
                    .await?
            } else {
                None
            };
            let execute = || {
                attempt(
                    sandbox.get(),
                    &profile,
                    AttemptSpec {
                        input,
                        signal: &plan.stdout_contains,
                        role,
                        index,
                        pin,
                        worker: &worker,
                    },
                )
            };
            #[cfg(not(feature = "durable-sessions"))]
            let attempt = execute().await;
            #[cfg(feature = "durable-sessions")]
            let attempt = if let Some(previous) = previous {
                serde_json::from_value(previous.output)
                    .map_err(crate::session::driver::DriverError::from)?
            } else {
                let start = std::time::Instant::now();
                let observation = execute().await;
                if let Some(journal) = &mut journal {
                    let ExecutionSandbox::Journaled(sandbox) = &mut sandbox else {
                        unreachable!()
                    };
                    sandbox.settle().await;
                    let mut audit = sandbox.drain_audit(None);
                    sandbox.retain_audit(&mut audit);
                    journal
                        .complete(
                            &key,
                            crate::session::durable::store::journal::ProbeResult {
                                output: serde_json::to_value(&observation)
                                    .map_err(crate::session::driver::DriverError::from)?,
                                duration_ms: start
                                    .elapsed()
                                    .as_millis()
                                    .try_into()
                                    .unwrap_or(u64::MAX),
                                audit,
                            },
                        )
                        .await?;
                }
                observation
            };
            let unavailable = attempt.error.is_some()
                || attempt.exit_code.is_none()
                || (role != "positive" && attempt.exit_code != Some(0));
            report.attempts.push(attempt);
            if snapshot.is_some() && report.attempts.iter().all(|a| a.materialization.is_some()) {
                report.source_binding = "materialized-pin".into();
            } else if snapshot.is_some() {
                report.source_binding = "incomplete".into();
            }
            report.behavior_reproduced = ["positive", "control"].iter().all(|role| {
                let attempts: Vec<_> = report.attempts.iter().filter(|a| a.role == *role).collect();
                attempts.len() == plan.repetitions as usize
                    && attempts.iter().all(|a| {
                        a.error.is_none()
                            && a.exit_code == Some(0)
                            && a.signal_fired == (*role == "positive")
                    })
            });
            if unavailable {
                report.reason = "Experiment incomplete: a probe could not run completely or the control was unhealthy".into();
                return Ok(report);
            }
        }
    }
    let comparison_passed = report
        .attempts
        .iter()
        .filter(|a| a.role.starts_with("comparison"))
        .all(|a| !a.signal_fired);
    if comparison_snapshot.is_some() {
        report.comparison = Some(
            if comparison_passed {
                "passed"
            } else {
                "signal-fired"
            }
            .into(),
        );
    }
    report.decision = if report.behavior_reproduced && comparison_passed {
        Decision::Reproduced
    } else {
        Decision::NotReproduced
    };
    report.reason = if report.decision == Decision::Reproduced { "All positive attempts fired the signal; all controls and requested comparison probes exited successfully without it. This establishes behavior only." } else { "A positive missed the signal, a healthy control fired it, or the requested comparison failed." }.into();
    Ok(report)
}
