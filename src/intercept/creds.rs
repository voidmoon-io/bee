//! Per-call proxy credentials (019 T042, research R6).
//!
//! At the start of every tool call the harness mints a 128-bit token, registers `{token → call}` with
//! the worker and **waits for the ack**; at the end it revokes it. The call's children get
//! `HTTP_PROXY=http://<call_id>:<token>@127.0.0.1:<port>` (and the lowercase, `HTTPS_`, and `ALL_`
//! variants, with `NO_PROXY` empty), applied after the environment is cleared, so a child never
//! inherits anything else. A child can unset them — which is why the kernel's loopback-only rule is
//! the control, and the variables only the route: a child that drops them reaches nothing.
//!
//! A token revoked at call end is useless later, so one leaked into a file or a transcript cannot be
//! replayed (spec edge case "credential reuse"). Tokens never reach the store or the transcript.

use std::sync::Arc;

use crate::sandbox::{CallContext, CallHooks, CallOrigin, EnvOverlay};

use super::control::WireCtx;
use super::sidecar::Interceptor;

pub use comb::client::{CA_VARS, PROXY_VARS};

/// The [`CallHooks`] and environment provider for an interception session.
pub struct ProxyCredentials {
    interceptor: Interceptor,
    /// The session CA bundle, when `inspect` is non-empty.
    ca_bundle: Option<std::path::PathBuf>,
}

impl ProxyCredentials {
    pub fn new(interceptor: Interceptor, ca_bundle: Option<std::path::PathBuf>) -> Arc<Self> {
        Arc::new(ProxyCredentials {
            interceptor,
            ca_bundle,
        })
    }

    /// The overlay for `call`: the proxy URL carrying its credential. A call with no live credential
    /// (the worker is down, or issuing failed) still gets the proxy URL, without userinfo — its
    /// traffic is then refused with a `407` naming the reason, rather than going anywhere else.
    pub fn overlay(&self, call: &CallContext) -> EnvOverlay {
        let token = self.interceptor.token_for(&call.call_id);
        let url = comb::client::proxy_url(
            self.interceptor.port(),
            token.as_deref().map(|t| (call.call_id.as_str(), t)),
        );
        let vars = comb::client::child_env(&url, self.ca_bundle.as_deref());
        EnvOverlay::new(vars).expect("proxy variables are never stripped names")
    }

    /// Install on `sandbox`: hooks for issue/revoke, and the overlay provider.
    pub fn install(self: &Arc<Self>, sandbox: &mut crate::sandbox::Sandbox) {
        sandbox.set_call_hooks(self.clone());
        let me = self.clone();
        sandbox.set_env_provider(Box::new(move |call| me.overlay(call)));
    }

    /// Issue a credential for a long-lived MCP stdio server, attributed `mcp:<server>`.
    pub async fn issue_mcp(&self, server: &str) -> Option<(CallContext, EnvOverlay)> {
        let call = CallContext {
            call_id: format!("mcp:{server}"),
            turn: 0,
            origin: CallOrigin::Mcp(server.to_string()),
        };
        self.interceptor.issue(wire_ctx(&call)).await.ok()?;
        let overlay = self.overlay(&call);
        Some((call, overlay))
    }

    pub async fn revoke_mcp(&self, server: &str) {
        self.interceptor.revoke(&format!("mcp:{server}")).await;
    }
}

impl CallHooks for ProxyCredentials {
    fn begin<'a>(&'a self, call: &'a CallContext) -> futures_util::future::BoxFuture<'a, ()> {
        Box::pin(async move {
            // A failure leaves the call without a credential; its traffic is refused (407), which is
            // the fail-closed outcome. The worker's state is reported through the tools.
            let _ = self.interceptor.issue(wire_ctx(call)).await;
        })
    }

    fn end<'a>(&'a self, call: &'a CallContext) -> futures_util::future::BoxFuture<'a, ()> {
        // The revoke's ack doubles as a barrier: the worker emits every event a request produced
        // before answering its client, and the control channel is ordered, so once the ack is in
        // every event of this call has been read.
        Box::pin(async move { self.interceptor.revoke(&call.call_id).await })
    }

    fn take_events(&self, call: &CallContext) -> Vec<crate::proxy_event::ProxyEvent> {
        self.interceptor.take_events(&call.call_id)
    }

    fn turn_notes(&self) -> Vec<String> {
        let n = self
            .interceptor
            .with_store(|s| s.announce_leads())
            .unwrap_or(0);
        if n == 0 {
            return Vec::new();
        }
        vec![format!(
            "[bee] {n} new passive lead{} from recorded HTTP traffic. `http_leads` lists them. \
             Leads are observations to check, not findings.",
            if n == 1 { "" } else { "s" }
        )]
    }
}

pub fn wire_ctx(call: &CallContext) -> WireCtx {
    WireCtx {
        call_id: call.call_id.clone(),
        turn: call.turn,
        origin: match &call.origin {
            CallOrigin::Tool => "tool".into(),
            CallOrigin::Mcp(s) => format!("mcp:{s}"),
        },
    }
}
