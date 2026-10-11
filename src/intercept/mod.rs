//! HTTP(S) interception (019-http-intercept).
//!
//! Two halves share this module because they share the control-channel types (ADR-0002's
//! reasoning: one consumer, one package):
//!
//! - the **harness** side — [`sidecar`] spawns and talks to the worker, [`creds`] attributes
//!   traffic to tool calls, [`store`] is the exchange index, and [`query`], [`slice`], [`diff`],
//!   [`fuzz`], [`passive`] and [`har`] answer from it; [`ops`] are the typed operations the `http_*`
//!   tools adapt;
//! - the **worker** side — [`worker`] runs as `bee proxy-worker` inside its own kernel scope, the
//!   *proxy scope*, whose network rules are exactly the resolved target and egress hosts.
//!
//! The kernel enforces IP:port for both scopes. Host names, CONNECT host = SNI, the egress-vs-target
//! role and pacing are user-space checks in the worker, and are labelled as such wherever they are
//! shown (Constitution III, FR-011).

pub mod control;
pub mod creds;
pub mod diff;
pub mod fuzz;
pub mod har;
pub mod ops;
pub mod pane;
pub mod passive;
pub mod query;
pub mod session;
pub mod sidecar;
pub mod slice;
pub mod store;
pub mod worker;
