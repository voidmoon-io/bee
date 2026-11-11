//! `comb` — the interception proxy, its exchange store and its tools, outside bee.
//!
//! `comb serve` runs the proxy for one session and serves the same `http_*` tools bee's model gets
//! (`comb::api`) as JSON lines on stdin/stdout; `comb history` and `comb har` read a store offline.
//!
//! **Enforcement.** Standalone, the proxy enforces scope by host name in user space only: nothing
//! stops a client from connecting to a target directly. Under bee the same proxy runs inside a
//! kernel scope; here the containing boundary — a gVisor sandbox, a network policy — is the host's.
//! Every result says so (`"enforcement": "advisory"`).

use std::io::Read as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod resolver;
mod serve;

#[derive(Parser)]
#[command(
    name = "comb",
    version,
    about = "HTTP(S) interception proxy, exchange store and tools"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the proxy for one session and serve the tools as JSON lines on stdin/stdout.
    Serve {
        /// A bee policy file; its `[policy.http]` table is the scope.
        #[arg(long)]
        policy: PathBuf,
        /// Where `.bee/http/` (the store) lives.
        #[arg(long, default_value = ".")]
        project: PathBuf,
        /// Session id (default: a fresh one).
        #[arg(long)]
        session: Option<String>,
        /// Loopback address the proxy listens on.
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: SocketAddr,
        /// Where to write the CA bundle when anything is inspected (default: a private temp dir).
        #[arg(long)]
        ca_bundle: Option<PathBuf>,
    },
    /// Print the tool definitions as JSON.
    Tools,
    /// List recorded exchanges from a store, offline. FILTER is `http_history`'s argument as JSON.
    History {
        #[arg(long, default_value = ".")]
        project: PathBuf,
        #[arg(default_value = "{}")]
        filter: String,
    },
    /// Export recorded exchanges as HAR 1.2, offline. FILTER is `http_history`'s argument as JSON.
    Har {
        #[arg(long, default_value = ".")]
        project: PathBuf,
        #[arg(default_value = "{}")]
        filter: String,
    },
    /// The proxy worker. Spawned by `comb serve` with the listener on fd 3; not run by hand.
    #[command(hide = true)]
    Worker {
        #[arg(long)]
        session: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Worker { session } => comb::worker::run(&session),
        Cmd::Tools => {
            println!(
                "{}",
                serde_json::to_string_pretty(&comb::api::tools()).unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        Cmd::History { project, filter } => offline(&project, &filter, |store, f| {
            comb::query::history(store, f)
                .map_err(|e| e.to_string())
                .and_then(|r| serde_json::to_string_pretty(&r).map_err(|e| e.to_string()))
        }),
        Cmd::Har { project, filter } => offline(&project, &filter, |store, f| {
            comb::har::export(store, f)
                .and_then(|h| serde_json::to_string_pretty(&h).map_err(|e| e.to_string()))
        }),
        Cmd::Serve {
            policy,
            project,
            session,
            listen,
            ca_bundle,
        } => {
            let opts = match serve_options(policy, project, session, listen, ca_bundle) {
                Ok(o) => o,
                Err(e) => return fail(&e),
            };
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => return fail(&format!("runtime: {e}")),
            };
            let r = rt.block_on(serve::run(opts));
            // stdin is read on a blocking thread that only an EOF ends; a client may keep it open
            // after `shutdown`, so do not wait for it.
            rt.shutdown_timeout(std::time::Duration::from_secs(1));
            match r {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(&e),
            }
        }
    }
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("comb: {msg}");
    ExitCode::FAILURE
}

/// Open `project`'s store read-only and answer `run` over the parsed filter. Offline reads see
/// every session unless the filter says otherwise: there is no "this session" here.
fn offline(
    project: &Path,
    filter: &str,
    run: impl FnOnce(&comb::store::Store, &comb::query::HistoryFilter) -> Result<String, String>,
) -> ExitCode {
    let mut v: serde_json::Value = match serde_json::from_str(filter) {
        Ok(v) => v,
        Err(e) => return fail(&format!("filter: {e}")),
    };
    if let Some(o) = v.as_object_mut() {
        o.entry("all_sessions")
            .or_insert(serde_json::Value::Bool(true));
    }
    let f: comb::query::HistoryFilter = match serde_json::from_value(v) {
        Ok(f) => f,
        Err(e) => return fail(&format!("filter: {e}")),
    };
    let store = match comb::store::Store::open_read(project) {
        Ok(s) => s,
        Err(e) => return fail(&format!("store: {e}")),
    };
    match run(&store, &f) {
        Ok(out) => {
            println!("{out}");
            ExitCode::SUCCESS
        }
        Err(e) => fail(&e),
    }
}

/// Everything `serve::run` needs, checked before any runtime starts.
pub struct ServeOptions {
    pub session_id: String,
    pub project_root: PathBuf,
    pub http_scope: bee_core::compiler::HttpScope,
    pub listener: std::net::TcpListener,
    pub worker_exe: PathBuf,
    pub ca_bundle: PathBuf,
}

fn serve_options(
    policy: PathBuf,
    project: PathBuf,
    session: Option<String>,
    listen: SocketAddr,
    ca_bundle: Option<PathBuf>,
) -> Result<ServeOptions, String> {
    // The proxy authenticates its clients per call, but it is still a forward proxy: never on a
    // routable address.
    if !listen.ip().is_loopback() {
        return Err(format!(
            "--listen must be a loopback address, not {}",
            listen.ip()
        ));
    }
    let project_root = project
        .canonicalize()
        .map_err(|e| format!("--project {}: {e}", project.display()))?;
    let text = std::fs::read_to_string(&policy)
        .map_err(|e| format!("--policy {}: {e}", policy.display()))?;
    let parsed = bee_core::Policy::from_toml(&text).map_err(|e| format!("policy: {e}"))?;
    let worker_exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .map_err(|e| format!("cannot resolve the comb binary for the worker: {e}"))?;
    let resolver = resolver::HostResolver::new(&project_root);
    let compiled = parsed
        .compile_http(&resolver, &worker_exe)
        .map_err(|e| format!("[policy.http]: {e}"))?
        .ok_or("the policy has no active [policy.http] table, so there is nothing to intercept")?;
    let listener =
        std::net::TcpListener::bind(listen).map_err(|e| format!("listen on {listen}: {e}"))?;
    let session_id = session.unwrap_or_else(fresh_session_id);
    let ca_bundle = match ca_bundle {
        Some(p) => p,
        None => private_dir(&session_id)?.join("ca-bundle.pem"),
    };
    Ok(ServeOptions {
        session_id,
        project_root,
        http_scope: compiled.http_scope,
        listener,
        worker_exe,
        ca_bundle,
    })
}

fn fresh_session_id() -> String {
    let mut b = [0u8; 6];
    let _ = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b));
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("comb-{hex}")
}

/// `$XDG_RUNTIME_DIR/comb/<session>/`, or `<tmp>/comb-<uid>/<session>/`; mode 0700.
fn private_dir(session_id: &str) -> Result<PathBuf, String> {
    use std::os::unix::fs::DirBuilderExt;
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
        .map(|p| p.join("comb"))
        .unwrap_or_else(|| {
            // SAFETY: getuid has no preconditions and cannot fail.
            std::env::temp_dir().join(format!("comb-{}", unsafe { libc::getuid() }))
        });
    let dir = base.join(session_id);
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    Ok(dir)
}
