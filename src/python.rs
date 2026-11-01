//! Bounded Python execution in a disposable `bee python-worker` process.
use monty::{MontyRun, RunProgress};
use monty_types::{
    CompileOptions, MontyObject, ObjectRef, OsPolicy, PrintWriter, ResourceLimits, ResourceTracker,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    io::{Read, Write},
    path::PathBuf,
    time::Duration,
};

pub const RUNTIME_ID: &str = "monty-1.4.0/bee-python-2/postcard-1";
pub const MAX_SOURCE: usize = 64 * 1024;
pub const MAX_CHECKPOINT: usize = 4 * 1024 * 1024;
const MAX_FRAME: usize = 24 * 1024 * 1024;
const MEMORY: usize = 64 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Request {
    Start {
        source: String,
        inputs: Value,
        visual: bool,
    },
    Resume {
        snapshot: Vec<u8>,
        result: Value,
    },
}
pub const MAX_BATCH_CALLS: usize = 4;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposedCall {
    pub name: String,
    pub arguments: Value,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Response {
    Complete {
        value: Value,
    },
    Call {
        name: String,
        arguments: Value,
        snapshot: Vec<u8>,
    },
    Batch {
        calls: Vec<ProposedCall>,
        snapshot: Vec<u8>,
    },
    Error {
        message: String,
    },
}

pub fn executable() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    // Cargo integration/unit harnesses live beside the application under target/*/deps.
    if exe.parent().is_some_and(|p| p.ends_with("deps")) {
        return Ok(exe.parent().unwrap().parent().unwrap().join("bee"));
    }
    Ok(exe)
}

pub async fn execute(request: Request, sandbox: &crate::Sandbox) -> Result<Response, String> {
    let input = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    if input.len() > MAX_FRAME {
        return Err("Python request exceeds byte limit".into());
    }
    let exe = executable()?;
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        crate::tools::exec::run_worker(
            sandbox,
            exe.to_str().ok_or("worker path is not UTF-8")?,
            &[
                "python-worker".into(),
                "--parent".into(),
                std::process::id().to_string(),
            ],
            input,
            MAX_FRAME,
        ),
    )
    .await
    .map_err(|_| "Python worker deadline exceeded".to_string())?;
    if result.is_error || result.truncated {
        return Err(result.content);
    }
    serde_json::from_str(&result.content)
        .map_err(|e| format!("invalid Python worker response: {e}"))
}

fn limits() -> ResourceLimits {
    ResourceLimits {
        max_memory: Some(MEMORY),
        max_feed_duration: Some(Duration::from_secs(1)),
        max_recursion_depth: 64,
        ..ResourceLimits::default()
    }
}

pub fn from_json(value: Value) -> MontyObject {
    match value {
        Value::Null => MontyObject::none(),
        Value::Bool(v) => MontyObject::bool(v),
        Value::Number(v) => v
            .as_i64()
            .map(MontyObject::int)
            .or_else(|| v.as_u64().map(|v| MontyObject::bigint(v.into())))
            .unwrap_or_else(|| MontyObject::float(v.as_f64().unwrap())),
        Value::String(v) => MontyObject::string(v),
        Value::Array(v) => MontyObject::list(v.into_iter().map(from_json)),
        Value::Object(v) => MontyObject::dict(
            v.into_iter()
                .map(|(k, v)| (MontyObject::string(k), from_json(v))),
        ),
    }
}
fn to_json(value: ObjectRef<'_>, depth: usize) -> Result<Value, String> {
    if depth > 32 {
        return Err("Python result nesting exceeds 32".into());
    }
    if value.type_name() == "NoneType" {
        return Ok(Value::Null);
    }
    if let Some(v) = value.as_bool() {
        return Ok(Value::Bool(v));
    }
    if let Some(v) = value.as_int() {
        return Ok(v.into());
    }
    if value.type_name() == "int" {
        return value
            .to_string()
            .parse::<u64>()
            .map(Value::from)
            .map_err(|_| "Python integer exceeds JSON range".into());
    }
    if let Some(v) = value.as_float() {
        return serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or("non-finite result".into());
    }
    if let Some(v) = value.as_str() {
        return Ok(v.into());
    }
    if let Some(v) = value.pairs() {
        return v
            .into_iter()
            .map(|(k, v)| {
                Ok((
                    k.as_str().ok_or("result keys must be strings")?.to_string(),
                    to_json(v, depth + 1)?,
                ))
            })
            .collect::<Result<serde_json::Map<_, _>, String>>()
            .map(Value::Object);
    }
    if matches!(value.type_name(), "list" | "tuple") {
        return value
            .items()
            .ok_or("invalid sequence")?
            .into_iter()
            .map(|v| to_json(v, depth + 1))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array);
    }
    Err(format!(
        "unsupported Python result type {}",
        value.type_name()
    ))
}

fn evaluate(request: Request) -> Result<Response, String> {
    let progress = match request {
        Request::Start {
            source,
            inputs,
            visual,
        } => {
            if source.len() > MAX_SOURCE {
                return Err("Python source exceeds 64 KiB".into());
            }
            let source = if visual {
                format!(
                    "{}\n{}\n_bee_output\n",
                    include_str!("python/visual.py"),
                    source
                )
            } else {
                source
            };
            let policy = OsPolicy {
                datetime: monty_types::DateTimeSource::CallHost,
                sleep: monty_types::SleepMode::CallHost,
                random_start: monty_types::RandomStart::CallHost,
                ..OsPolicy::default()
            };
            let runner = MontyRun::new(
                source,
                "bee.py",
                vec![
                    "inputs".into(),
                    "call_tool".into(),
                    "call_tools".into(),
                    "_bee_sprite".into(),
                    "_bee_animation".into(),
                ],
                CompileOptions::default(),
            )
            .map_err(|e| e.to_string())?
            .with_os_policy(policy);
            runner
                .start(
                    vec![
                        from_json(inputs),
                        MontyObject::function(if visual { "denied" } else { "call_tool" }, None),
                        MontyObject::function(if visual { "denied" } else { "call_tools" }, None),
                        from_json(
                            serde_json::to_value(crate::viz::bee::sprite())
                                .map_err(|e| e.to_string())?,
                        ),
                        from_json(
                            serde_json::to_value(crate::viz::bee::animation())
                                .map_err(|e| e.to_string())?,
                        ),
                    ],
                    ResourceTracker::new(limits()),
                    PrintWriter::Disabled,
                )
                .map_err(|e| e.to_string())?
        }
        Request::Resume { snapshot, result } => {
            if snapshot.len() > MAX_CHECKPOINT {
                return Err("Python checkpoint exceeds byte limit".into());
            }
            let RunProgress::FunctionCall(mut call) =
                postcard::from_bytes(&snapshot).map_err(|e| e.to_string())?
            else {
                return Err("expected suspended Python call".into());
            };
            call.tracker_mut().tighten_limits(&limits());
            call.resume(from_json(result), PrintWriter::Disabled)
                .map_err(|e| e.to_string())?
        }
    };
    match progress {
        RunProgress::Complete(value) => {
            let value = to_json(value.as_ref(), 0)?;
            if serde_json::to_vec(&value).map_err(|e| e.to_string())?.len() > 1024 * 1024 {
                return Err("Python result exceeds 1 MiB".into());
            }
            Ok(Response::Complete { value })
        }
        RunProgress::FunctionCall(ref call) if call.function_name == "call_tools" => {
            if call.args.args().len() != 1 || call.args.kwargs().len() != 0 {
                return Err("call_tools requires one list of calls".into());
            }
            let value = to_json(call.args.arg(0).ok_or("missing calls")?, 0)?;
            let calls: Vec<ProposedCall> = serde_json::from_value(value)
                .map_err(|_| "each call requires only name and arguments".to_string())?;
            if calls.is_empty() || calls.len() > MAX_BATCH_CALLS {
                return Err("call_tools requires between one and four calls".into());
            }
            if calls
                .iter()
                .any(|c| c.name.is_empty() || c.name.len() > 256 || !c.arguments.is_object())
            {
                return Err("each call requires a bounded name and dict arguments".into());
            }
            let snapshot = postcard::to_allocvec(&progress).map_err(|e| e.to_string())?;
            if snapshot.len() > MAX_CHECKPOINT {
                return Err("Python checkpoint exceeds byte limit".into());
            }
            Ok(Response::Batch { calls, snapshot })
        }
        RunProgress::FunctionCall(ref call) if call.function_name == "call_tool" => {
            if call.args.args().len() != 2 || call.args.kwargs().len() != 0 {
                return Err("call_tool requires name and arguments".into());
            }
            let name = call
                .args
                .arg(0)
                .and_then(|v| v.as_str())
                .ok_or("tool name must be a string")?
                .to_string();
            let arguments = to_json(call.args.arg(1).ok_or("missing arguments")?, 0)?;
            if !arguments.is_object() {
                return Err("tool arguments must be a dict".into());
            }
            let snapshot = postcard::to_allocvec(&progress).map_err(|e| e.to_string())?;
            if snapshot.len() > MAX_CHECKPOINT {
                return Err("Python checkpoint exceeds byte limit".into());
            }
            Ok(Response::Call {
                name,
                arguments,
                snapshot,
            })
        }
        _ => Err("Python host access denied: function or OS capability not found".into()),
    }
}

pub fn worker_main(parent: u32) -> std::process::ExitCode {
    // Arm before reading or compiling untrusted input, then close the fork/exec parent-death race.
    #[cfg(target_os = "linux")]
    unsafe {
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
            || libc::getppid() as u32 != parent
        {
            return std::process::ExitCode::FAILURE;
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = parent;

    let response = (|| {
        monty_alloc::set_hard_limit(monty_types::memory_limit_with_headroom(Some(MEMORY), false))
            .map_err(str::to_string)?;
        let mut bytes = Vec::new();
        std::io::stdin()
            .take((MAX_FRAME + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > MAX_FRAME {
            return Err("Python request exceeds byte limit".into());
        }
        evaluate(serde_json::from_slice(&bytes).map_err(|e| e.to_string())?)
    })()
    .unwrap_or_else(|message| Response::Error { message });
    match serde_json::to_vec(&response) {
        Ok(bytes) if bytes.len() <= MAX_FRAME => {
            if std::io::stdout().write_all(&bytes).is_ok() {
                std::process::ExitCode::SUCCESS
            } else {
                std::process::ExitCode::FAILURE
            }
        }
        _ => std::process::ExitCode::FAILURE,
    }
}
