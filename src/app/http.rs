//! `bee http` — operator commands over the recorded HTTP traffic (019-http-intercept US9).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Subcommand};

use crate::app::session::{EX_IOERR, EX_USAGE};

const CMD: &str = "bee http";

#[derive(Args, Debug)]
pub struct HttpArgs {
    #[command(subcommand)]
    pub cmd: HttpCmd,
}

#[derive(Subcommand, Debug)]
pub enum HttpCmd {
    /// Export recorded exchanges as HAR 1.2. Proxy credentials are stripped; sensitive headers
    /// (Authorization, Cookie, Set-Cookie) are named per entry in `_bee.sensitive` for redaction.
    Export {
        /// The HAR file to write.
        #[arg(long)]
        har: PathBuf,
        /// An `http_history` filter, as JSON (e.g. '{"host": "app.test", "status_range": [500, 599]}').
        #[arg(long)]
        filter: Option<String>,
        /// Project directory whose `.bee/http/` store is read (default: the current directory).
        #[arg(long)]
        project: Option<PathBuf>,
    },
}

pub fn main(args: HttpArgs) -> ExitCode {
    match args.cmd {
        HttpCmd::Export {
            har,
            filter,
            project,
        } => {
            let project = project.unwrap_or_else(|| PathBuf::from("."));
            let filter: bee::intercept::query::HistoryFilter = match filter.as_deref() {
                None => Default::default(),
                Some(f) => match serde_json::from_str(f) {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("{CMD}: --filter: {e}");
                        return ExitCode::from(EX_USAGE);
                    }
                },
            };
            let store = match bee::intercept::store::Store::open_read(&project) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{CMD}: {e}");
                    return ExitCode::from(EX_IOERR);
                }
            };
            let doc = match bee::intercept::har::export(&store, &filter) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("{CMD}: {e}");
                    return ExitCode::from(EX_USAGE);
                }
            };
            let n = doc.log.entries.len();
            match serde_json::to_vec_pretty(&doc)
                .map_err(|e| e.to_string())
                .and_then(|b| std::fs::write(&har, b).map_err(|e| e.to_string()))
            {
                Ok(()) => {
                    eprintln!(
                        "{CMD}: wrote {n} entr{} to {}",
                        if n == 1 { "y" } else { "ies" },
                        har.display()
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{CMD}: cannot write {}: {e}", har.display());
                    ExitCode::from(EX_IOERR)
                }
            }
        }
    }
}
