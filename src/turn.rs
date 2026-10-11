//! The top of a model turn (024 FR-028–FR-030, FR-032, research R6).
//!
//! Both loops call [`turn_start`] once per model turn, before the model is asked anything. It is the
//! one consumer of [`StepEvent::TurnStart`]: hooks may release leases there, leases whose lifetime in
//! model turns has run out expire there (D3), the scope narrows when either happened, and the MCP tool
//! list is refreshed when a server said it changed. 024 PR5 moves it onto the session.

use std::sync::Arc;

use crate::grants::{ActivePolicy, GrantId, GrantLease};
use crate::hooks::{dispatch, Flow, LoopHook, StepEvent, StepEventKind};
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
    /// Narrowing the live scope failed. The leases are gone from the active policy either way; this is
    /// reported, never swallowed.
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
    let mut d = dispatch(hooks, &ev).await;
    if let Some(source) = refresh {
        let hook: [Box<dyn LoopHook>; 1] = [Box::new(RefreshHook {
            source: source.clone(),
        })];
        d.merge(dispatch(&hook, &ev).await);
    }

    let mut report = TurnStartReport::default();
    if let Some(active) = active {
        let before: Vec<GrantLease> = active.leases().to_vec();
        for id in &d.deescalate {
            if active.release(id) {
                report.released.push(id.clone());
            }
        }
        report.expired = active.expire(turn);

        if report.narrowed() {
            let dropped: Vec<&GrantLease> = before
                .iter()
                .filter(|l| report.released.contains(&l.id) || report.expired.contains(&l.id))
                .collect();
            if let Err(e) = sandbox.reload(active.active()) {
                report.narrow_error = Some(format!("reload failed: {e}"));
            }
            if dropped.iter().any(|l| !l.delta.http_targets.is_empty()) {
                if let Err(e) = sandbox.apply_http_scope(active.active()).await {
                    report.narrow_error = Some(format!("target-scope narrowing failed: {e}"));
                }
            }
            // A lease's tools were absent when it was granted (escalation registers only those), so
            // a tool no live lease still grants was the lease's alone.
            let still = active.granted_tools();
            for tool in dropped.iter().flat_map(|l| &l.delta.tools) {
                if !still.contains(tool) && registry.remove(tool) {
                    report.removed_tools.push(tool.clone());
                }
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
