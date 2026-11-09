//! comb — bee's HTTP(S) interceptor as a library (`.scratch/comb/PRD.md`).
//!
//! This first slice holds the harness-side pieces that need no sandbox: the control-channel
//! protocol shared with the proxy worker, the exchange store and its history query, and what
//! answers from the store — slices, diffs, fuzz templates, HAR export and passive leads.
//!
//! Enforcement is the embedder's. Under bee the proxy runs in a kernel scope whose network rules
//! are the resolved target and egress addresses; host names, CONNECT host = SNI, roles and pacing
//! are user-space checks. Every result labels which layer enforced it (`HttpScope::enforced_by`),
//! so a standalone embedding without a kernel scope never claims one.

pub mod bound;
pub mod control;
pub mod diff;
pub mod fuzz;
pub mod har;
pub mod passive;
pub mod query;
pub mod slice;
pub mod store;
