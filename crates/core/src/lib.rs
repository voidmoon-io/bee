//! `bee-core` — policy types, TOML parsing, the policy compiler, the attenuation validator, and
//! audit event types for the bee sandbox harness.
//!
//! This crate contains **no eBPF code and requires no async runtime** (constitution Principle V /
//! NFR-005). Agent frameworks embed it to author, compile, and attenuate policies; the kernel-facing
//! loading lives in `bee-userspace`.

#![forbid(unsafe_code)]

pub mod attenuation;
pub mod audit;
pub mod compiler;
pub mod error;
pub mod pattern;
pub mod policy;

pub use audit::AuditEvent;
pub use compiler::{
    CompiledExec, CompiledNet, CompiledPolicy, ExecIdentity, FsPrimitive, Resolver,
};
pub use error::{AttenuationError, CompileError, PolicyError};
pub use pattern::HostPattern;
pub use policy::{
    Access, EffectiveDefaults, ExecPolicy, ExfilPolicy, HostPort, HttpLimits, HttpPolicy, Mode,
    NetPolicy, Policy,
};
