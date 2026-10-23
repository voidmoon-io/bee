//! The top of a model turn (024 FR-028–FR-030, FR-032, research R6).
//!
//! Both loops call [`turn_start`] once per model turn, before the model is asked anything. It is the
//! one consumer of [`StepEvent::TurnStart`]: hooks may release leases there, leases whose lifetime in
//! model turns has run out expire there (D3), the scope narrows when either happened, and the MCP tool
//! list is refreshed when a server said it changed. 024 PR5 moves it onto the session.

use std::sync::Arc;

use crate::grants::{ActivePolicy, GrantId};
use crate::hooks::{dispatch_bounded, Flow, LoopHook, StepEvent, StepEventKind};
use crate::sandbox::Sandbox;
use crate::tools::ToolRegistry;

/// A source of tools that can change mid-session — an MCP bridge whose server sent
/// `tools/list_changed` (004 FR-043).
pub trait ToolRefresh: Send + Sync {
    /// Whether the tool list changed since the last call. Consumes the signal.
    fn take_dirty(&self) -> bool;
    /// Replace this source's tools in `registry` with its current ones.
    fn reregister(&self, registry: &mut ToolRegistry);
}

/// Asks for a tool refresh at turn start when its source changed (024 FR-030): refresh goes through
/// the hook mechanism, while the re-registration itself stays with [`turn_start`], so the hook needs
/// no access to the registry.
pub struct RefreshHook {
    pub source: Arc<dyn ToolRefresh>,
}

#[async_trait::async_trait]
impl LoopHook for RefreshHook {
    fn observes(&self, kind: StepEventKind) -> bool {
        kind == StepEventKind::TurnStart
    }

    async fn on_event(&self, _ev: &StepEvent<'_>) -> Flow {
        if self.source.take_dirty() {
            Flow::RefreshTools
        } else {
            Flow::Continue
        }
    }
}

/// What one turn start did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TurnStartReport {
    /// Leases a hook released (FR-032).
    pub released: Vec<GrantId>,
    /// Leases whose lifetime ran out at this turn (FR-029).
    pub expired: Vec<GrantId>,
    /// Tools only a dropped lease had granted, now unregistered.
    pub removed_tools: Vec<String>,
    /// The MCP tools were re-registered.
    pub refreshed_tools: bool,
    /// A turn-start action failed. The loop must stop; failed narrowing leaves the last committed
    /// lease set intact and poisons further dispatch.
    pub narrow_error: Option<String>,
}

impl TurnStartReport {
    /// Whether the scope narrowed.
    pub fn narrowed(&self) -> bool {
        !self.released.is_empty() || !self.expired.is_empty()
    }
}

/// Run the top of model turn `turn` (research R6):
///
/// 1. dispatch `TurnStart` to `hooks`, and to a [`RefreshHook`] over `refresh` when there is one;
/// 2. release every lease a hook released;
/// 3. expire every lease whose lifetime has run out;
/// 4. when anything was dropped: reload the scope with the narrower policy, push the narrower target
///    scope to the proxy when a dropped lease had widened it, and unregister tools only a dropped
///    lease granted;
/// 5. on a refresh request: re-register the MCP tools.
pub async fn turn_start(
    turn: u32,
    hooks: &[Box<dyn LoopHook>],
    active: Option<&mut ActivePolicy>,
    sandbox: &mut Sandbox,
    registry: &mut ToolRegistry,
    refresh: Option<&Arc<dyn ToolRefresh>>,
) -> TurnStartReport {
    let ev = StepEvent::TurnStart { turn };
    let mut d = dispatch_bounded(hooks, &ev, std::time::Duration::from_secs(60)).await;
    if let Some(source) = refresh {
        let hook: [Box<dyn LoopHook>; 1] = [Box::new(RefreshHook {
            source: source.clone(),
        })];
        d.merge(dispatch_bounded(&hook, &ev, std::time::Duration::from_secs(60)).await);
    }

    let mut report = TurnStartReport::default();
    if let Err(e) = sandbox.check_cleanup() {
        report.narrow_error = Some(e);
        return report;
    }
    if let Some(e) = d.terminate {
        report.narrow_error = Some(e);
        return report;
    }
    if d.deny.is_some() || d.escalate.is_some() {
        report.narrow_error = Some("unsupported hook action at turn start".into());
        return report;
    }
    if let Some(active) = active {
        let mut candidate = active.clone();
        for id in &d.deescalate {
            match candidate.release(id) {
                Ok(true) => report.released.push(id.clone()),
                Ok(false) => {
                    report.narrow_error = Some(format!("unknown grant: {id}"));
                    return report;
                }
                Err(e) => {
                    report.narrow_error = Some(e);
                    return report;
                }
            }
        }
        report.expired = match candidate.expire(turn) {
            Ok(ids) => ids,
            Err(e) => {
                report.narrow_error = Some(e);
                return report;
            }
        };
        if report.narrowed() {
            let before = active.granted_tools();
            let after = candidate.granted_tools();
            report.removed_tools = before.difference(&after).cloned().collect();
            if let Err(e) =
                crate::grants::escalate::install_narrowing(active, candidate, sandbox, registry)
                    .await
            {
                report.narrow_error = Some(e);
                return report;
            }
        }
    }

    if d.refresh_tools {
        if let Some(source) = refresh {
            source.reregister(registry);
            report.refreshed_tools = true;
        }
    }
    report
}
