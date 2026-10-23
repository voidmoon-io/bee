//! Intercept rules over traffic from other tools (019 US7, research R16).
//!
//! A rule is a matcher and an action: **modify** (the [`Edit`]s `http_replay` uses), **drop** (the
//! client gets a 502 naming the rule), or **hold** (the request waits for the model's decision and is
//! forwarded unchanged at its deadline — at most 300 s, never indefinitely, FR-022). Rules live in
//! worker memory only: a new session starts with none. A rewritten request is checked against scope
//! again before it is sent — a rule cannot move traffic out of scope.
//!
//! Rules apply to forwarded traffic (plain HTTP, and HTTPS on inspected hosts). Model-originated
//! requests are already exactly what the model wrote.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::intercept::diff::Edit;

/// Longest a request may be held.
pub const MAX_HOLD_S: u32 = 300;
pub const DEFAULT_HOLD_S: u32 = 30;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matcher {
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub path_regex: Option<String>,
    #[serde(default)]
    pub header_present: Option<String>,
    #[serde(default)]
    pub body_contains: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Modify(Vec<Edit>),
    Drop,
    Hold {
        #[serde(default = "default_hold")]
        timeout_s: u32,
    },
}

fn default_hold() -> u32 {
    DEFAULT_HOLD_S
}

/// A rule as installed: what the harness sends in `rule.add`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    pub id: String,
    pub matcher: Matcher,
    pub action: Action,
}

impl RuleSpec {
    /// Validate: a hold's timeout is bounded; a regex compiles within its size limit.
    pub fn validate(&self) -> Result<(), String> {
        if let Action::Hold { timeout_s } = self.action {
            if timeout_s == 0 || timeout_s > MAX_HOLD_S {
                return Err(format!("hold timeout_s must be 1–{MAX_HOLD_S}"));
            }
        }
        if let Some(re) = &self.matcher.path_regex {
            regex::RegexBuilder::new(re)
                .size_limit(1 << 20)
                .build()
                .map_err(|e| format!("path_regex: {e}"))?;
        }
        Ok(())
    }
}

struct Rule {
    spec: RuleSpec,
    path_re: Option<regex::Regex>,
    hits: AtomicU32,
}

/// What the model decides about a held request.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldDecision {
    Forward,
    Drop,
    ForwardEdited(Vec<Edit>),
}

/// The worker's rule table and its held requests.
#[derive(Default)]
pub struct Rules {
    rules: Mutex<Vec<Arc<Rule>>>,
    holds: Mutex<HashMap<String, oneshot::Sender<HoldDecision>>>,
    next_hold: AtomicU32,
}

/// A request as the rules see it.
pub struct Seen<'a> {
    pub host: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub head: &'a [u8],
    pub body: &'a [u8],
}

/// The first decisive rule for a request, or the modify rules to apply.
pub enum Verdict {
    Pass,
    Modify {
        rule_ids: Vec<String>,
        edits: Vec<Edit>,
    },
    Drop {
        rule_id: String,
    },
    Hold {
        rule_id: String,
        timeout: Duration,
    },
}

impl Rules {
    pub fn add(&self, spec: RuleSpec) -> Result<(), String> {
        spec.validate()?;
        let path_re = match &spec.matcher.path_regex {
            Some(r) => Some(regex::Regex::new(r).map_err(|e| e.to_string())?),
            None => None,
        };
        let mut rules = self.rules.lock().expect("rules lock");
        if rules.iter().any(|r| r.spec.id == spec.id) {
            return Err(format!("rule {} already exists", spec.id));
        }
        rules.push(Arc::new(Rule {
            spec,
            path_re,
            hits: AtomicU32::new(0),
        }));
        Ok(())
    }

    pub fn remove(&self, id: &str) -> bool {
        let mut rules = self.rules.lock().expect("rules lock");
        let before = rules.len();
        rules.retain(|r| r.spec.id != id);
        rules.len() != before
    }

    /// Match `req`: every modify rule's edits, in order — unless a drop or hold rule matches first,
    /// which decides alone.
    pub fn evaluate(&self, req: &Seen<'_>) -> Verdict {
        let rules = self.rules.lock().expect("rules lock").clone();
        let mut ids = Vec::new();
        let mut edits = Vec::new();
        for r in rules {
            if !matches(&r, req) {
                continue;
            }
            r.hits.fetch_add(1, Ordering::Relaxed);
            match &r.spec.action {
                Action::Drop if ids.is_empty() => {
                    return Verdict::Drop {
                        rule_id: r.spec.id.clone(),
                    }
                }
                Action::Hold { timeout_s } if ids.is_empty() => {
                    return Verdict::Hold {
                        rule_id: r.spec.id.clone(),
                        timeout: Duration::from_secs(u64::from(*timeout_s)),
                    }
                }
                Action::Modify(e) => {
                    ids.push(r.spec.id.clone());
                    edits.extend(e.iter().cloned());
                }
                // A drop or hold after a modify already matched: the modifies stand, in order.
                _ => {}
            }
        }
        if ids.is_empty() {
            Verdict::Pass
        } else {
            Verdict::Modify {
                rule_ids: ids,
                edits,
            }
        }
    }

    /// Register a hold; the receiver yields the model's decision.
    pub fn hold(&self) -> (String, oneshot::Receiver<HoldDecision>) {
        let id = format!("H{}", self.next_hold.fetch_add(1, Ordering::Relaxed) + 1);
        let (tx, rx) = oneshot::channel();
        self.holds
            .lock()
            .expect("holds lock")
            .insert(id.clone(), tx);
        (id, rx)
    }

    /// Deliver the model's decision. `Err` if there is no such held request (already decided, or
    /// auto-forwarded at its deadline).
    pub fn release(&self, hold_id: &str, decision: HoldDecision) -> Result<(), String> {
        let tx = self
            .holds
            .lock()
            .expect("holds lock")
            .remove(hold_id)
            .ok_or_else(|| {
                format!("no held request {hold_id} (already released or auto-forwarded)")
            })?;
        tx.send(decision)
            .map_err(|_| format!("held request {hold_id} is gone"))
    }

    /// Forget a hold whose deadline passed.
    pub fn expire(&self, hold_id: &str) {
        self.holds.lock().expect("holds lock").remove(hold_id);
    }
}

fn matches(r: &Rule, req: &Seen<'_>) -> bool {
    let m = &r.spec.matcher;
    if let Some(h) = &m.host {
        if !bee_core::pattern::normalize_host(h).eq(&bee_core::pattern::normalize_host(req.host)) {
            return false;
        }
    }
    if let Some(meth) = &m.method {
        if !meth.eq_ignore_ascii_case(req.method) {
            return false;
        }
    }
    if let Some(p) = &m.path_prefix {
        if !req.path.starts_with(p.as_str()) {
            return false;
        }
    }
    if let Some(re) = &r.path_re {
        if !re.is_match(req.path) {
            return false;
        }
    }
    if let Some(name) = &m.header_present {
        let text = String::from_utf8_lossy(req.head);
        let present = text.split('\n').skip(1).any(|l| {
            l.split_once(':')
                .is_some_and(|(k, _)| k.trim().eq_ignore_ascii_case(name))
        });
        if !present {
            return false;
        }
    }
    if let Some(needle) = &m.body_contains {
        if !req
            .body
            .windows(needle.len().max(1))
            .any(|w| w == needle.as_bytes())
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seen<'a>(path: &'a str, head: &'a [u8]) -> Seen<'a> {
        Seen {
            host: "app.test",
            method: "GET",
            path,
            head,
            body: b"",
        }
    }

    #[test]
    fn modifies_accumulate_and_a_drop_first_wins() {
        let r = Rules::default();
        r.add(RuleSpec {
            id: "R1".into(),
            matcher: Matcher {
                path_prefix: Some("/api".into()),
                ..Default::default()
            },
            action: Action::Modify(vec![Edit::SetHeader {
                name: "X".into(),
                value: "1".into(),
            }]),
        })
        .unwrap();
        assert!(matches!(
            r.evaluate(&seen("/api/x", b"GET / HTTP/1.1\r\n\r\n")),
            Verdict::Modify { .. }
        ));
        assert!(matches!(r.evaluate(&seen("/other", b"")), Verdict::Pass));
        r.add(RuleSpec {
            id: "R0".into(),
            matcher: Matcher::default(),
            action: Action::Drop,
        })
        .unwrap();
        // R1 matched first, so its modify stands and R0's drop does not override it.
        assert!(matches!(
            r.evaluate(&seen("/api/x", b"")),
            Verdict::Modify { .. }
        ));
        assert!(matches!(
            r.evaluate(&seen("/other", b"")),
            Verdict::Drop { .. }
        ));
    }

    #[test]
    fn a_hold_longer_than_the_cap_is_refused() {
        let spec = RuleSpec {
            id: "R".into(),
            matcher: Matcher::default(),
            action: Action::Hold { timeout_s: 301 },
        };
        assert!(spec.validate().is_err());
    }

    #[tokio::test]
    async fn a_release_reaches_the_held_request_once() {
        let r = Rules::default();
        let (id, rx) = r.hold();
        r.release(&id, HoldDecision::Forward).unwrap();
        assert_eq!(rx.await.unwrap(), HoldDecision::Forward);
        assert!(r.release(&id, HoldDecision::Drop).is_err());
    }
}
