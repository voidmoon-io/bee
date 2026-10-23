//! The loop hooks lifecycle (007-dynamic-grants, 024 FR-028–FR-034) — bee's own, Rig-shaped.
//!
//! Rig's `AgentHook`/`StepEvent`/`Flow` fire inside Rig's agent loop, which bee does not use (Rig is
//! confined behind [`crate::provider::Model`]). Escalation needs the [`crate::sandbox::Sandbox`] and
//! the audit ring, which Rig cannot see — so the lifecycle lives here. A [`LoopHook`] observes a
//! [`StepEvent`] and returns a [`Flow`]; [`dispatch`] consults **every** hook that observes the event
//! and combines what they returned into one [`Dispatch`]:
//!
//! - a refusal wins: if any hook returns [`Flow::Deny`], no grant is proposed for that event (FR-034);
//! - grants proposed by several hooks are merged into one;
//! - lease releases and tool refreshes accumulate.
//!
//! Hooks are pure — `&StepEvent → Flow` — and hold no mutable access to the session. What a flow
//! means is carried out by its one consumer: `BeforeToolCall`, `KernelDenial` and `ProxyRefusal` by
//! [`crate::call::run_call`]; `TurnStart` by [`crate::turn::turn_start`], at the top of every model
//! turn in both loops. Every event offered here is dispatched, and every flow is acted on (FR-033).

use crate::grants::{GrantDelta, GrantId};
use crate::provider::ToolCall;

/// A lifecycle event a hook observes. Borrows loop state; never owns it.
pub enum StepEvent<'a> {
    /// The top of a model turn — where leases expire and hooks may release them (007 US4, FR-028).
    TurnStart { turn: u32 },
    BeforeModelCall {
        convo: &'a crate::provider::Conversation,
        schemas: &'a [crate::provider::ToolSchema],
    },
    AfterToolResult {
        call: &'a ToolCall,
        result: &'a crate::tools::ToolResult,
        audit: &'a [bee_core::AuditEvent],
    },
    /// Before a tool call executes.
    BeforeToolCall(&'a ToolCall),
    /// A drained audit event denied this call (bee-specific; the reactive-escalation trigger).
    KernelDenial {
        op: &'a str,
        target: &'a str,
        call: &'a ToolCall,
    },
    /// The interception proxy refused this call's request to an out-of-scope `host:port` (019 US3) —
    /// the trigger for a consented target-scope widening.
    ProxyRefusal {
        host: &'a str,
        port: u16,
        call: &'a ToolCall,
    },
}

/// The field-less discriminant of [`StepEvent`], used by [`LoopHook::observes`] to skip events a
/// hook does not care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepEventKind {
    TurnStart,
    BeforeModelCall,
    AfterToolResult,
    BeforeToolCall,
    KernelDenial,
    ProxyRefusal,
}

impl StepEvent<'_> {
    /// The kind of this event.
    pub fn kind(&self) -> StepEventKind {
        match self {
            StepEvent::TurnStart { .. } => StepEventKind::TurnStart,
            StepEvent::BeforeModelCall { .. } => StepEventKind::BeforeModelCall,
            StepEvent::AfterToolResult { .. } => StepEventKind::AfterToolResult,
            StepEvent::BeforeToolCall(_) => StepEventKind::BeforeToolCall,
            StepEvent::KernelDenial { .. } => StepEventKind::KernelDenial,
            StepEvent::ProxyRefusal { .. } => StepEventKind::ProxyRefusal,
        }
    }
}

/// A hook's returned action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Flow {
    /// Observe only.
    Continue,
    Terminate(String),
    /// On `BeforeToolCall`: do not run the tool; the model is told a hook declined it (FR-031). On
    /// any event: no grant is made for it, whatever another hook proposed (FR-034).
    Deny(String),
    /// Propose a grant: the widen cycle runs, and the triggering call is retried once if it widened
    /// the scope (007 US1/US2).
    Escalate(GrantDelta),
    /// Release the named lease; the scope narrows at that turn start (007 US4, FR-032).
    Deescalate(GrantId),
    /// Re-register the MCP tools at this turn start (004 FR-043, 024 FR-030).
    RefreshTools,
}

/// A hook observing the loop lifecycle. Object-safe via `async_trait` so hooks live in a
/// `Vec<Box<dyn LoopHook>>`.
#[async_trait::async_trait]
pub trait LoopHook: Send + Sync {
    /// Observe one event and return a [`Flow`]. Awaited inline — keep it light.
    async fn on_event(&self, ev: &StepEvent<'_>) -> Flow;

    /// Filter high-frequency events without dispatching (Rig's `observes`). Default: observe all.
    fn observes(&self, _kind: StepEventKind) -> bool {
        true
    }
}

/// What every hook observing one event returned, combined (contracts/hooks.md).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dispatch {
    pub terminate: Option<String>,
    /// The first refusal, by registration order. When set, `escalate` is `None`.
    pub deny: Option<String>,
    /// Every proposed grant, merged.
    pub escalate: Option<GrantDelta>,
    /// Every lease a hook released.
    pub deescalate: Vec<GrantId>,
    /// Whether any hook asked for the MCP tools to be refreshed.
    pub refresh_tools: bool,
}

impl Dispatch {
    /// Fold `other` into this, keeping the precedence rule.
    pub fn merge(&mut self, other: Dispatch) {
        if self.terminate.is_none() {
            self.terminate = other.terminate;
        }
        if self.deny.is_none() {
            self.deny = other.deny;
        }
        if let Some(d) = other.escalate {
            match &mut self.escalate {
                Some(mine) => mine.merge(d),
                None => self.escalate = Some(d),
            }
        }
        if self.deny.is_some() {
            self.escalate = None;
        }
        self.deescalate.extend(other.deescalate);
        self.refresh_tools |= other.refresh_tools;
    }

    fn add(&mut self, flow: Flow) {
        let one = match flow {
            Flow::Continue => return,
            Flow::Terminate(r) => Dispatch {
                terminate: Some(r),
                ..Dispatch::default()
            },
            Flow::Deny(r) => Dispatch {
                deny: Some(r),
                ..Dispatch::default()
            },
            Flow::Escalate(d) => Dispatch {
                escalate: Some(d),
                ..Dispatch::default()
            },
            Flow::Deescalate(id) => Dispatch {
                deescalate: vec![id],
                ..Dispatch::default()
            },
            Flow::RefreshTools => Dispatch {
                refresh_tools: true,
                ..Dispatch::default()
            },
        };
        self.merge(one);
    }
}

/// Dispatch an event to every hook that observes it, in registration order, and combine their flows.
pub async fn dispatch(hooks: &[Box<dyn LoopHook>], ev: &StepEvent<'_>) -> Dispatch {
    let kind = ev.kind();
    let mut out = Dispatch::default();
    for hook in hooks {
        if hook.observes(kind) {
            out.add(hook.on_event(ev).await);
        }
    }
    out
}

/// Hook execution is an operation with the session's configured timeout.
pub(crate) async fn dispatch_bounded(
    hooks: &[Box<dyn LoopHook>],
    event: &StepEvent<'_>,
    timeout: std::time::Duration,
) -> Dispatch {
    tokio::time::timeout(timeout, dispatch(hooks, event))
        .await
        .unwrap_or_else(|_| Dispatch {
            terminate: Some("lifecycle hook timed out".into()),
            ..Dispatch::default()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bee_core::Access;

    struct Fixed(Flow, StepEventKind);
    #[async_trait::async_trait]
    impl LoopHook for Fixed {
        async fn on_event(&self, _ev: &StepEvent<'_>) -> Flow {
            self.0.clone()
        }
        fn observes(&self, kind: StepEventKind) -> bool {
            kind == self.1
        }
    }

    fn turn_ev() -> StepEvent<'static> {
        StepEvent::TurnStart { turn: 0 }
    }

    fn fs(path: &str, a: Access) -> GrantDelta {
        let mut d = GrantDelta::default();
        d.filesystem.insert(path.into(), a);
        d
    }

    fn at_turn(flows: Vec<Flow>) -> Vec<Box<dyn LoopHook>> {
        flows
            .into_iter()
            .map(|f| Box::new(Fixed(f, StepEventKind::TurnStart)) as Box<dyn LoopHook>)
            .collect()
    }

    // FR-034: a refusal outranks a grant whichever registered first.
    #[tokio::test]
    async fn deny_beats_escalate_in_either_order() {
        for flows in [
            vec![
                Flow::Escalate(fs("/a", Access::Read)),
                Flow::Deny("no".into()),
            ],
            vec![
                Flow::Deny("no".into()),
                Flow::Escalate(fs("/a", Access::Read)),
            ],
        ] {
            let d = dispatch(&at_turn(flows), &turn_ev()).await;
            assert_eq!(d.deny.as_deref(), Some("no"));
            assert_eq!(d.escalate, None);
        }
    }

    #[tokio::test]
    async fn the_first_refusal_is_the_reason() {
        let d = dispatch(
            &at_turn(vec![
                Flow::Deny("first".into()),
                Flow::Deny("second".into()),
            ]),
            &turn_ev(),
        )
        .await;
        assert_eq!(d.deny.as_deref(), Some("first"));
    }

    #[tokio::test]
    async fn escalations_from_two_hooks_merge() {
        let d = dispatch(
            &at_turn(vec![
                Flow::Escalate(fs("/a", Access::Read)),
                Flow::Escalate(fs("/b", Access::Write)),
            ]),
            &turn_ev(),
        )
        .await;
        let merged = d.escalate.expect("merged");
        assert_eq!(merged.filesystem.get("/a"), Some(&Access::Read));
        assert_eq!(merged.filesystem.get("/b"), Some(&Access::Write));
    }

    #[tokio::test]
    async fn releases_and_refreshes_accumulate_beside_the_winner() {
        let d = dispatch(
            &at_turn(vec![
                Flow::Deescalate("g0".into()),
                Flow::RefreshTools,
                Flow::Escalate(fs("/a", Access::Read)),
                Flow::Deescalate("g1".into()),
            ]),
            &turn_ev(),
        )
        .await;
        assert_eq!(d.deescalate, vec!["g0".to_string(), "g1".to_string()]);
        assert!(d.refresh_tools);
        assert!(d.escalate.is_some());
    }

    #[tokio::test]
    async fn observes_filters_events() {
        // This hook only observes BeforeToolCall, so a TurnStart event skips it.
        let hooks: Vec<Box<dyn LoopHook>> = vec![Box::new(Fixed(
            Flow::Deny("x".into()),
            StepEventKind::BeforeToolCall,
        ))];
        assert_eq!(dispatch(&hooks, &turn_ev()).await, Dispatch::default());
    }

    #[tokio::test]
    async fn all_continue_yields_nothing() {
        let hooks = at_turn(vec![Flow::Continue, Flow::Continue]);
        assert_eq!(dispatch(&hooks, &turn_ev()).await, Dispatch::default());
    }
}
