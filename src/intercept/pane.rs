//! The live HTTP history pane (019 US9, T090).
//!
//! A table of the most recent exchanges, rebuilt only when new ones have been stored. Every cell is
//! target-influenced — hosts, paths, methods — so every cell goes through
//! [`crate::safe_text::safe_line`]: an ANSI escape or a bidi override in a path draws as visible,
//! inert text, never as terminal control (the same rule as every other untrusted string bee shows).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::render_spec::{RenderSpec, Row};

use super::query::{history, HistoryFilter};
use super::sidecar::Interceptor;

/// Rows shown.
pub const PANE_ROWS: u32 = 15;

/// One pane row's data, already reduced to what the pane shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaneRow {
    pub id: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub status: String,
    pub bytes: String,
    pub ms: String,
    pub origin: String,
}

/// The pane as a table spec. Pure: what it draws is decided here, and escaped here.
pub fn history_spec(rows: &[PaneRow]) -> RenderSpec {
    let safe = |s: &str| crate::safe_text::safe_line(s).into_owned();
    RenderSpec::Table {
        title: "http history".into(),
        headers: [
            "id", "method", "host", "path", "status", "bytes", "ms", "origin",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
        rows: rows
            .iter()
            .map(|r| Row {
                cells: vec![
                    safe(&r.id),
                    safe(&r.method),
                    safe(&r.host),
                    safe(&r.path),
                    safe(&r.status),
                    safe(&r.bytes),
                    safe(&r.ms),
                    safe(&r.origin),
                ],
                color: match r.status.chars().next() {
                    Some('5') => Some("error".into()),
                    Some('4') => Some("warning".into()),
                    _ => None,
                },
            })
            .collect(),
    }
}

/// The pane for a session: a new table when exchanges arrive or the filter changes.
pub struct PaneSource {
    icpt: Interceptor,
    seen: AtomicU64,
    /// The combq filter, if any.
    filter: Mutex<Option<String>>,
}

pub fn pane_source(icpt: Interceptor) -> Arc<dyn crate::repl::HttpPane> {
    Arc::new(PaneSource {
        icpt,
        seen: AtomicU64::new(u64::MAX),
        filter: Mutex::new(None),
    })
}

impl crate::repl::HttpPane for PaneSource {
    fn refresh(&self) -> Option<RenderSpec> {
        let now = self.icpt.with_store(|s| s.count_exchanges()).unwrap_or(0);
        if self.seen.swap(now, Ordering::Relaxed) == now {
            return None;
        }
        let q = self.filter.lock().expect("pane filter lock").clone();
        let filter = HistoryFilter {
            limit: Some(PANE_ROWS),
            q: q.clone(),
            ..Default::default()
        };
        let res = self.icpt.with_store(|s| history(s, &filter)).ok()?;
        let rows: Vec<PaneRow> = res
            .rows
            .into_iter()
            .map(|r| PaneRow {
                id: r.id,
                method: r.method.unwrap_or_default(),
                host: r.host,
                path: r.path.unwrap_or_default(),
                status: r
                    .status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| r.outcome.clone()),
                bytes: r.resp_bytes.map(|b| b.to_string()).unwrap_or_default(),
                ms: r.ms.map(|m| m.to_string()).unwrap_or_default(),
                origin: r.origin,
            })
            .collect();
        let mut spec = history_spec(&rows);
        if let (Some(q), RenderSpec::Table { title, .. }) = (&q, &mut spec) {
            *title = format!("http history — {}", crate::safe_text::safe_line(q));
        }
        Some(spec)
    }

    fn set_filter(&self, q: Option<&str>) -> Result<String, String> {
        let msg = match q {
            Some(q) => {
                // Parse here for a caret under the mistake; the query runs on the next refresh.
                comb::combq::parse(q).map_err(|e| format!("http filter: {}", e.render(q)))?;
                format!("http pane filtered: {q}")
            }
            None => "http pane filter cleared".to_string(),
        };
        *self.filter.lock().expect("pane filter lock") = q.map(str::to_string);
        // Force the next refresh to redraw.
        self.seen.store(u64::MAX, Ordering::Relaxed);
        Ok(msg)
    }
}
