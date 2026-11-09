//! comb — bee's HTTP(S) interceptor as a library (`.scratch/comb/PRD.md`).
//!
//! - the **harness** side: [`sidecar::Interceptor`] spawns the worker (the embedder supplies the
//!   command, so bee runs it as `bee proxy-worker` inside a kernel scope), records every exchange in
//!   the [`store`], and the typed [`ops`] — send, replay, fuzz, sitemap, bounded reads — answer from
//!   it with [`query`], [`slice`], [`diff`], [`fuzz`], [`har`] and [`passive`];
//! - the **worker** side: [`worker::run`] serves the proxy on an inherited listener (fd 3) and talks
//!   [`control`] frames on stdio.
//!
//! Enforcement is the embedder's. Under bee the proxy runs in a kernel scope whose network rules
//! are the resolved target and egress addresses; host names, CONNECT host = SNI, roles and pacing
//! are user-space checks. Every result labels which layer enforced it (`HttpScope::enforced_by`),
//! so a standalone embedding without a kernel scope never claims one.

pub mod api;
pub mod bound;
pub mod client;
pub mod control;
pub mod diff;
pub mod fuzz;
pub mod har;
pub mod ops;
pub mod passive;
pub mod query;
pub mod sidecar;
pub mod slice;
pub mod store;
pub mod worker;
