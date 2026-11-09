//! The interceptor's tools, independent of who calls them (contracts/http-tools.md).
//!
//! One definition per tool — name, description, JSON Schema — and one [`call`] that parses JSON
//! arguments into an op spec, makes the op call and shapes a bounded result. bee's model-facing
//! `http_*` tools and `comb serve`'s JSON-lines API are both thin adapters over this, so an agent
//! driving comb from another harness sees exactly the tools bee's model sees.
//!
//! Results that carry target-derived bytes name their [`Reply::source`] (`http:<id>`): the caller
//! must deliver them to a model as untrusted data, never as instructions.

use std::future::Future;
use std::pin::Pin;

use serde_json::Value;

use crate::bound::bounded_json;
use crate::ops::{CallCtx, OpError};
use crate::sidecar::Interceptor;

#[cfg(feature = "vm-test")]
mod debug;
mod fuzz;
mod get;
mod history;
mod intercept;
mod leads;
mod replay;
mod scope;
mod send;
mod sitemap;

/// The tools, in the order a harness lists them.
pub const TOOL_NAMES: &[&str] = &[
    "http_scope",
    "http_send",
    "http_get",
    "http_history",
    "http_replay",
    "http_sitemap",
    "http_fuzz",
    "http_intercept",
    "http_leads",
];

/// A tool as a model sees it.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ToolDef {
    pub name: &'static str,
    pub description: &'static str,
    /// JSON Schema for the arguments.
    pub parameters: Value,
}

/// Every tool's definition (plus `http_debug` in `vm-test` builds).
pub fn tools() -> Vec<ToolDef> {
    let v: Vec<ToolDef> = TOOL_NAMES.iter().filter_map(|n| def(n)).collect();
    #[cfg(feature = "vm-test")]
    let v = {
        let mut v = v;
        v.push(debug::def());
        v
    };
    v
}

/// The definition of tool `name`, if there is one.
pub fn def(name: &str) -> Option<ToolDef> {
    Some(match name {
        "http_scope" => scope::def(),
        "http_send" => send::def(),
        "http_get" => get::def(),
        "http_history" => history::def(),
        "http_replay" => replay::def(),
        "http_sitemap" => sitemap::def(),
        "http_fuzz" => fuzz::def(),
        "http_intercept" => intercept::def(),
        "http_leads" => leads::def(),
        #[cfg(feature = "vm-test")]
        "http_debug" => debug::def(),
        _ => return None,
    })
}

/// A tool's answer: already bounded text, and where its content came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub text: String,
    /// `Some("http:<id>")` when the text carries target-derived content (untrusted data).
    pub source: Option<String>,
    /// The call ran but the exchange itself failed (a send that never got a response).
    pub is_error: bool,
}

impl Reply {
    fn json(v: &Value, bound: usize, source: Option<String>) -> Reply {
        Reply {
            text: bounded_json(v, bound),
            source,
            is_error: false,
        }
    }
}

/// Why a tool call produced no [`Reply`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    Op(OpError),
    /// The caller's scope may not run what reading a payload file needs.
    NotGranted {
        name: String,
    },
    UnknownTool(String),
}

impl From<OpError> for CallError {
    fn from(e: OpError) -> Self {
        CallError::Op(e)
    }
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Op(e) => write!(f, "{e}"),
            CallError::NotGranted { name } => write!(f, "not_granted: {name}"),
            CallError::UnknownTool(n) => write!(f, "unknown tool `{n}`"),
        }
    }
}

fn invalid(e: impl std::fmt::Display) -> CallError {
    CallError::Op(OpError::Invalid(e.to_string()))
}

pub type LinesFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<String>, CallError>> + Send + 'a>>;

/// How `http_fuzz` reads a `project_file` payload set. The embedder decides what may be read: bee
/// reads through a child in the tool scope, so the kernel decides, and never opens it itself.
pub trait PayloadFiles: Send + Sync {
    fn read_lines<'a>(&'a self, path: &'a str) -> LinesFuture<'a>;
}

/// No project files: every `project_file` payload set is refused.
pub struct NoPayloadFiles;

impl PayloadFiles for NoPayloadFiles {
    fn read_lines<'a>(&'a self, _path: &'a str) -> LinesFuture<'a> {
        Box::pin(async { Err(invalid("project_file payloads are not available here")) })
    }
}

/// Call tool `name` with `args`, attributed to `ctx`.
pub async fn call(
    icpt: &Interceptor,
    name: &str,
    args: Value,
    ctx: &CallCtx,
    files: &dyn PayloadFiles,
) -> Result<Reply, CallError> {
    let args = if args.is_null() {
        Value::Object(Default::default())
    } else {
        args
    };
    match name {
        "http_scope" => Ok(scope::call(icpt)),
        "http_send" => send::call(icpt, ctx, &args).await,
        "http_get" => get::call(icpt, &args),
        "http_history" => history::call(icpt, args),
        "http_replay" => replay::call(icpt, ctx, &args).await,
        "http_sitemap" => sitemap::call(icpt, &args),
        "http_fuzz" => fuzz::call(icpt, ctx, &args, files).await,
        "http_intercept" => intercept::call(icpt, &args).await,
        "http_leads" => leads::call(icpt, &args),
        #[cfg(feature = "vm-test")]
        "http_debug" => debug::call(icpt, &args).await,
        other => Err(CallError::UnknownTool(other.to_string())),
    }
}

/// Refuse any key of `args` not in `allowed`; a typo'd argument is never read as "unset".
fn only_keys(args: &Value, allowed: &[&str]) -> Result<(), CallError> {
    let obj = args
        .as_object()
        .ok_or_else(|| invalid("arguments must be an object"))?;
    match obj.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(k) => Err(invalid(format!("unknown argument `{k}`"))),
        None => Ok(()),
    }
}
