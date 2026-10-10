//! The proxy worker: `bee proxy-worker`, running inside the proxy scope (019-http-intercept).

pub mod connect;
pub mod forward;
pub mod listen;
pub mod mitm;
pub mod pace;
pub mod raw;
pub mod rules;
pub mod scope;

use std::process::ExitCode;

/// Worker entry point. Not yet implemented: exits 2 so a harness that spawns it fails closed.
pub fn run(_session: &str) -> ExitCode {
    eprintln!("bee proxy-worker: not implemented");
    ExitCode::from(2)
}
