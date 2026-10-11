//! The application layer: the commands `bee` exposes, and what they resolve before running.
//!
//! Reached only from `src/main.rs`. Everything beside it in `src/` is the harness *library* — the
//! episode loop, the tool registry, the REPL core, the render pipeline — which this layer drives
//! and does not extend. Keeping the two in one package reflects that the library has exactly one
//! consumer (ADR-0002); keeping them in separate module trees keeps the direction of that
//! dependency visible.

pub mod config;
// `bee findings` — the operator's half of the finding ledger (016-native-tools US2). Gated with the
// ledger itself.
#[cfg(feature = "findings")]
pub mod findings;
// `bee http` — the operator's view of recorded HTTP traffic (019-http-intercept US9).
#[cfg(feature = "intercept")]
pub mod http;
pub mod metrics;
pub mod repl;
pub mod run;
pub mod session;
