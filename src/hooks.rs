//! The loop hooks lifecycle (007-dynamic-grants) — bee's own, Rig-shaped.
//!
//! Rig's `AgentHook`/`StepEvent`/`Flow` fire inside Rig's agent loop, which bee does not use (Rig is
//! confined behind [`crate::provider::Model`]). Escalation needs the [`crate::sandbox::Sandbox`] and
//! the audit ring, which Rig cannot see — so the lifecycle lives here, in bee's `run_loop`. A
//! [`LoopHook`] observes a [`StepEvent`] and returns a [`Flow`]; the first hook returning a non-
//! [`Flow::Continue`] action wins for that event (Rig's composition rule). The existing per-turn
//! `refresh_tools` closure (004-mcp) is re-expressed as a `LoopHook` on [`StepEvent::TurnStart`].

use bee_core::AuditEvent;

use crate::grants::{GrantDelta, GrantId};
use crate::provider::{Conversation, ToolCall, ToolSchema};
use crate::tools::ToolResult;

/// A lifecycle event a hook observes. Borrows loop state; never owns it.
#[non_exhaustive]
pub enum StepEvent<'a> {
    /// Top of a turn — where lease expiry is evaluated (007, US4).
    TurnStart { turn: u32 },
    /// Before a model completion.
    BeforeModelCall {
        convo: &'a Conversation,
        schemas: &'a [ToolSchema],
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
    /// After a tool call executed and its audit was drained.
    AfterToolResult {
        call: &'a ToolCall,
        result: &'a ToolResult,
        audit: &'a [AuditEvent],
    },
}

/// The field-less discriminant of [`StepEvent`], used by [`LoopHook::observes`] to skip events a
/// hook does not care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepEventKind {
    TurnStart,
    BeforeModelCall,
    BeforeToolCall,
    KernelDenial,
    ProxyRefusal,
    AfterToolResult,
}

impl StepEvent<'_> {
    /// The kind of this event.
    pub fn kind(&self) -> StepEventKind {
        match self {
            StepEvent::TurnStart { .. } => StepEventKind::TurnStart,
            StepEvent::BeforeModelCall { .. } => StepEventKind::BeforeModelCall,
            StepEvent::BeforeToolCall(_) => StepEventKind::BeforeToolCall,
            StepEvent::KernelDenial { .. } => StepEventKind::KernelDenial,
            StepEvent::ProxyRefusal { .. } => StepEventKind::ProxyRefusal,
            StepEvent::AfterToolResult { .. } => StepEventKind::AfterToolResult,
        }
    }
}

/// A hook's returned action. The first non-[`Flow::Continue`] in the stack wins for an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Flow {
    /// Observe only; try the next hook.
    Continue,
    /// Skip the tool call and return this reason to the model (Rig `skip`).
    Deny(String),
    /// Resolve the grant, reload the scope, and auto-retry the triggering call once (007, US1/US2).
    Escalate(GrantDelta),
    /// Drop the named lease; narrowing reload (007, US4).
    Deescalate(GrantId),
    /// End the episode with a reason (Rig `terminate`).
    Terminate(String),
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

/// Dispatch an event to a hook stack in registration order, returning the first non-`Continue`
/// [`Flow`] (later hooks are not consulted for that event). `Continue` if every hook continues.
pub async fn dispatch(hooks: &[Box<dyn LoopHook>], ev: &StepEvent<'_>) -> Flow {
    let kind = ev.kind();
    for hook in hooks {
        if !hook.observes(kind) {
            continue;
        }
        match hook.on_event(ev).await {
            Flow::Continue => continue,
            other => return other,
        }
    }
    Flow::Continue
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[tokio::test]
    async fn first_non_continue_wins() {
        let hooks: Vec<Box<dyn LoopHook>> = vec![
            Box::new(Fixed(Flow::Continue, StepEventKind::TurnStart)),
            Box::new(Fixed(Flow::Deny("first".into()), StepEventKind::TurnStart)),
            Box::new(Fixed(Flow::Deny("second".into()), StepEventKind::TurnStart)),
        ];
        assert_eq!(
            dispatch(&hooks, &turn_ev()).await,
            Flow::Deny("first".into())
        );
    }

    #[tokio::test]
    async fn observes_filters_events() {
        // This hook only observes BeforeToolCall, so a TurnStart event skips it → Continue.
        let hooks: Vec<Box<dyn LoopHook>> = vec![Box::new(Fixed(
            Flow::Terminate("x".into()),
            StepEventKind::BeforeToolCall,
        ))];
        assert_eq!(dispatch(&hooks, &turn_ev()).await, Flow::Continue);
    }

    #[tokio::test]
    async fn all_continue_yields_continue() {
        let hooks: Vec<Box<dyn LoopHook>> =
            vec![Box::new(Fixed(Flow::Continue, StepEventKind::TurnStart))];
        assert_eq!(dispatch(&hooks, &turn_ev()).await, Flow::Continue);
    }
}
