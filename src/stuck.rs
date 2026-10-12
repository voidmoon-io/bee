//! Stuck detection (025 US2, contracts/stuck.md, data-model.md "StreakTracker").
//!
//! Both loops observe every call they run, in order, across turns. A model that keeps making the
//! same call gets one reminder, sooner when the call keeps being denied by policy; one that keeps
//! making the same *failing* call is stopped. Identical means the same tool with structurally equal
//! arguments (research R9): bee's `serde_json` keeps objects as sorted maps, so key order and
//! whitespace never make two calls differ.

use serde::{Deserialize, Serialize};

use crate::call::CallOutcome;
use crate::context::ConfigError;
use crate::grants::escalate::EscalateOutcome;
use crate::provider::ToolCall;
use crate::proxy_event::ProxyEventKind;
use crate::transcript::{HarnessNote, NoteKind};

/// Default identical calls before the general reminder.
pub const DEFAULT_REMIND_AFTER: u32 = 5;
/// Default identical denied calls before the policy reminder.
pub const DEFAULT_DENIED_REMIND_AFTER: u32 = 2;
/// Default identical failing calls before the run ends.
pub const DEFAULT_STOP_AFTER: u32 = 8;

/// One layer of `[stuck]` settings. `None` means "not set here"; layers fold with [`merge`].
///
/// [`merge`]: StuckConfig::merge
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StuckConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remind_after: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denied_remind_after: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_after: Option<u32>,
    /// Whether a stuck run is ended at all (FR-030). Reminders are sent either way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop: Option<bool>,
}

impl StuckConfig {
    /// `self` with every key `over` sets replaced by `over`'s value.
    pub fn merge(self, over: StuckConfig) -> StuckConfig {
        StuckConfig {
            remind_after: over.remind_after.or(self.remind_after),
            denied_remind_after: over.denied_remind_after.or(self.denied_remind_after),
            stop_after: over.stop_after.or(self.stop_after),
            stop: over.stop.or(self.stop),
        }
    }

    /// Apply defaults and validate: `1 ≤ denied_remind_after ≤ remind_after < stop_after`. A bad
    /// combination is a start-up error, never a silent clamp (Constitution I).
    pub fn resolve(&self) -> Result<ResolvedStuck, ConfigError> {
        let r = ResolvedStuck {
            remind_after: self.remind_after.unwrap_or(DEFAULT_REMIND_AFTER),
            denied_remind_after: self
                .denied_remind_after
                .unwrap_or(DEFAULT_DENIED_REMIND_AFTER),
            stop_after: self.stop_after.unwrap_or(DEFAULT_STOP_AFTER),
            stop: self.stop.unwrap_or(true),
        };
        if !(1 <= r.denied_remind_after
            && r.denied_remind_after <= r.remind_after
            && r.remind_after < r.stop_after)
        {
            return Err(ConfigError(format!(
                "[stuck] needs 1 <= denied_remind_after <= remind_after < stop_after \
                 (denied_remind_after = {}, remind_after = {}, stop_after = {})",
                r.denied_remind_after, r.remind_after, r.stop_after
            )));
        }
        Ok(r)
    }
}

/// `[stuck]` with every default applied, validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedStuck {
    pub remind_after: u32,
    pub denied_remind_after: u32,
    pub stop_after: u32,
    pub stop: bool,
}

impl Default for ResolvedStuck {
    fn default() -> Self {
        StuckConfig::default()
            .resolve()
            .expect("the defaults are valid")
    }
}

/// What makes two calls the same call.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CallKey(String, String);

impl CallKey {
    fn of(call: &ToolCall) -> CallKey {
        CallKey(
            call.name.clone(),
            serde_json::to_string(&call.arguments).unwrap_or_default(),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reminded {
    None,
    General,
    Policy,
}

/// A note for the model, queued by the loop for the start of its next turn.
#[derive(Debug, Clone)]
pub struct Reminder {
    pub kind: NoteKind,
    pub text: String,
    /// The repeated call.
    pub call: ToolCall,
}

impl Reminder {
    /// The note as the turn records it (FR-028).
    pub fn into_note(self) -> HarnessNote {
        HarnessNote::new(self.kind, self.text)
    }
}

/// What one observed call means.
#[derive(Debug, Clone)]
pub enum StuckSignal {
    None,
    Remind(Reminder),
    /// The same failing call has been made `repeats` times in a row: end the run (or exchange).
    Stop {
        tool: String,
        arguments: serde_json::Value,
        repeats: u32,
    },
}

/// The current streak of identical calls (data-model.md).
#[derive(Debug, Clone)]
pub struct StreakTracker {
    cfg: ResolvedStuck,
    /// Whether the policy reminder may point at `finish` (025 US3).
    finish_offered: bool,
    key: Option<CallKey>,
    count: u32,
    failing: u32,
    all_denied: bool,
    reminded: Reminded,
}

impl StreakTracker {
    pub fn new(cfg: ResolvedStuck) -> StreakTracker {
        StreakTracker {
            cfg,
            finish_offered: false,
            key: None,
            count: 0,
            failing: 0,
            all_denied: false,
            reminded: Reminded::None,
        }
    }

    /// The same tracker, whose policy reminder tells the model to call `finish` (025 US3).
    pub fn with_finish_offered(mut self, offered: bool) -> StreakTracker {
        self.finish_offered = offered;
        self
    }

    /// Observe one call that ran (or was refused before running), in execution order.
    pub fn observe(&mut self, call: &ToolCall, outcome: &CallOutcome) -> StuckSignal {
        let denial = denial_of(outcome);
        let denied = denial.is_some();
        let failing = outcome.result.is_error || outcome.timed_out || denied;
        let key = CallKey::of(call);

        if self.key.as_ref() == Some(&key) {
            self.count += 1;
            self.failing = if failing { self.failing + 1 } else { 0 };
            self.all_denied &= denied;
        } else {
            self.key = Some(key);
            self.count = 1;
            self.failing = u32::from(failing);
            self.all_denied = denied;
            self.reminded = Reminded::None;
        }

        if self.cfg.stop && self.failing == self.cfg.stop_after {
            return StuckSignal::Stop {
                tool: call.name.clone(),
                arguments: call.arguments.clone(),
                repeats: self.failing,
            };
        }
        if self.reminded != Reminded::None {
            return StuckSignal::None;
        }
        if self.all_denied && self.count == self.cfg.denied_remind_after {
            self.reminded = Reminded::Policy;
            return StuckSignal::Remind(Reminder {
                kind: NoteKind::StuckPolicy,
                text: policy_text(
                    &call.name,
                    self.count,
                    denial.as_deref().unwrap_or("denied"),
                    self.finish_offered,
                ),
                call: call.clone(),
            });
        }
        if self.count == self.cfg.remind_after {
            self.reminded = Reminded::General;
            return StuckSignal::Remind(Reminder {
                kind: NoteKind::StuckGeneral,
                text: general_text(&call.name, self.count, self.failing == self.count),
                call: call.clone(),
            });
        }
        StuckSignal::None
    }

    /// Forget the streak (`/clear`).
    pub fn reset(&mut self) {
        *self = StreakTracker::new(self.cfg).with_finish_offered(self.finish_offered);
    }
}

/// What denied the call that stands, if policy did and no grant in the call changed that (research
/// R9): a tool-scope kernel denial, or the proxy refusing an out-of-scope target.
fn denial_of(outcome: &CallOutcome) -> Option<String> {
    if outcome
        .escalations
        .iter()
        .any(|e| matches!(e.outcome, EscalateOutcome::Granted(_)))
    {
        return None;
    }
    if let Some(e) = outcome
        .audit
        .iter()
        .find(|e| e.decision == "denied" && e.scope_id.as_deref() != Some("proxy"))
    {
        return Some(format!("{} on {}", e.op, e.target));
    }
    outcome
        .proxy_events
        .iter()
        .find(|e| e.kind == ProxyEventKind::RefusedOutOfScope)
        .map(|e| {
            format!(
                "a request to {}:{} outside the target scope",
                e.host, e.port
            )
        })
}

fn general_text(tool: &str, n: u32, all_failed: bool) -> String {
    let failing = if all_failed {
        ", and it failed each time"
    } else {
        ""
    };
    format!(
        "[bee] You have called {tool} with the same arguments {n} times in a row{failing}. \
         Repeating it is unlikely to give a different result. Try a different approach: check your \
         assumptions, inspect the error, or use another tool."
    )
}

fn policy_text(tool: &str, n: u32, denial: &str, finish_offered: bool) -> String {
    let ending = if finish_offered {
        "say so and call finish with outcome \"blocked\"."
    } else {
        "say so."
    };
    format!(
        "[bee] {tool} with these arguments was denied {n} times by the session's security policy \
         ({denial}). This is a policy decision, not a transient error: the same call will be denied \
         again. Work within the access you have, or, if you cannot complete the task without it, \
         {ending}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call::{EscalationRecord, Trigger};
    use crate::tools::ToolResult;
    use bee_core::AuditEvent;
    use serde_json::json;

    fn call(args: serde_json::Value) -> ToolCall {
        ToolCall {
            id: "c".into(),
            name: "bash".into(),
            arguments: args,
        }
    }

    fn outcome(result: ToolResult) -> CallOutcome {
        CallOutcome {
            result,
            audit: Vec::new(),
            denied_attempt_audit: Vec::new(),
            proxy_audit: Vec::new(),
            proxy_events: Vec::new(),
            denied_attempt_proxy_events: Vec::new(),
            retried: false,
            timed_out: false,
            escalations: Vec::new(),
            refused_by_hook: None,
        }
    }

    fn ok() -> CallOutcome {
        outcome(ToolResult::ok("fine"))
    }

    fn err() -> CallOutcome {
        outcome(ToolResult::error("boom"))
    }

    fn denied() -> CallOutcome {
        let mut o = err();
        o.audit.push(AuditEvent {
            ts: String::new(),
            scope_id: None,
            cgroup_id: 0,
            pid: None,
            tgid: None,
            op: "file_open".into(),
            decision: "denied".into(),
            errno: 13,
            target: "/etc/shadow".into(),
        });
        o
    }

    fn tracker() -> StreakTracker {
        StreakTracker::new(ResolvedStuck::default())
    }

    fn signals(
        t: &mut StreakTracker,
        runs: &[(serde_json::Value, CallOutcome)],
    ) -> Vec<StuckSignal> {
        runs.iter()
            .map(|(a, o)| t.observe(&call(a.clone()), o))
            .collect()
    }

    fn reminders(s: &[StuckSignal]) -> Vec<(usize, NoteKind)> {
        s.iter()
            .enumerate()
            .filter_map(|(i, s)| match s {
                StuckSignal::Remind(r) => Some((i, r.kind)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn the_key_is_order_independent() {
        let mut t = tracker();
        let a = json!({"command": "ls", "cwd": "/"});
        let b: serde_json::Value =
            serde_json::from_str(r#"{ "cwd":"/",  "command":"ls" }"#).unwrap();
        let runs: Vec<_> = (0..5)
            .map(|i| (if i % 2 == 0 { a.clone() } else { b.clone() }, ok()))
            .collect();
        let s = signals(&mut t, &runs);
        assert_eq!(reminders(&s), vec![(4, NoteKind::StuckGeneral)]);
    }

    #[test]
    fn failing_resets_on_success() {
        let mut t = tracker();
        let a = json!({"x": 1});
        let mut runs: Vec<_> = (0..7).map(|_| (a.clone(), err())).collect();
        runs.push((a.clone(), ok()));
        runs.extend((0..7).map(|_| (a.clone(), err())));
        let s = signals(&mut t, &runs);
        assert!(
            !s.iter().any(|s| matches!(s, StuckSignal::Stop { .. })),
            "never 8 failures in a row"
        );
        let stop = t.observe(&call(a), &err());
        assert!(
            matches!(&stop, StuckSignal::Stop { tool, arguments, repeats: 8 }
                if tool == "bash" && *arguments == json!({"x": 1})),
            "{stop:?}"
        );
    }

    #[test]
    fn all_denied_clears_on_a_non_denied_call() {
        let mut t = tracker();
        let a = json!({"x": 1});
        let s = signals(&mut t, &[(a.clone(), err()), (a.clone(), denied())]);
        assert_eq!(reminders(&s), vec![], "the first call was not denied");
    }

    #[test]
    fn each_reminder_fires_once_per_streak() {
        let mut t = tracker();
        let a = json!({"x": 1});
        let s = signals(
            &mut t,
            &(0..7).map(|_| (a.clone(), ok())).collect::<Vec<_>>(),
        );
        assert_eq!(reminders(&s), vec![(4, NoteKind::StuckGeneral)]);

        let mut t = tracker();
        let s = signals(
            &mut t,
            &(0..7).map(|_| (a.clone(), denied())).collect::<Vec<_>>(),
        );
        assert_eq!(
            reminders(&s),
            vec![(1, NoteKind::StuckPolicy)],
            "the policy reminder stands in for the general one"
        );

        // A different call starts a new streak, which may be reminded again.
        let b = json!({"x": 2});
        let s = signals(
            &mut t,
            &(0..5).map(|_| (b.clone(), ok())).collect::<Vec<_>>(),
        );
        assert_eq!(reminders(&s), vec![(4, NoteKind::StuckGeneral)]);
    }

    #[test]
    fn stop_false_never_stops() {
        let cfg = StuckConfig {
            stop: Some(false),
            ..StuckConfig::default()
        }
        .resolve()
        .unwrap();
        let mut t = StreakTracker::new(cfg);
        let a = json!({});
        let s = signals(
            &mut t,
            &(0..20).map(|_| (a.clone(), err())).collect::<Vec<_>>(),
        );
        assert!(!s.iter().any(|s| matches!(s, StuckSignal::Stop { .. })));
        assert_eq!(
            reminders(&s),
            vec![(4, NoteKind::StuckGeneral)],
            "reminders still sent"
        );
    }

    #[test]
    fn a_granted_retry_is_not_denied() {
        let mut o = denied();
        o.escalations.push(EscalationRecord {
            trigger: Trigger::KernelDenial {
                op: "file_open".into(),
                target: "/etc/shadow".into(),
            },
            outcome: EscalateOutcome::Granted("g0".into()),
        });
        assert_eq!(denial_of(&o), None);
    }

    #[test]
    fn the_texts_follow_the_contract() {
        let mut t = tracker();
        let a = json!({});
        let s = signals(
            &mut t,
            &(0..2).map(|_| (a.clone(), denied())).collect::<Vec<_>>(),
        );
        let StuckSignal::Remind(r) = &s[1] else {
            panic!("no policy reminder")
        };
        assert!(r.text.starts_with(
            "[bee] bash with these arguments was denied 2 times by the session's security policy \
             (file_open on /etc/shadow)."
        ));
        assert!(r.text.ends_with("say so."));

        let mut t = tracker().with_finish_offered(true);
        let s = signals(
            &mut t,
            &(0..2).map(|_| (a.clone(), denied())).collect::<Vec<_>>(),
        );
        let StuckSignal::Remind(r) = &s[1] else {
            panic!("no policy reminder")
        };
        assert!(r.text.ends_with("call finish with outcome \"blocked\"."));

        assert!(general_text("bash", 5, true)
            .starts_with("[bee] You have called bash with the same arguments 5 times in a row, and it failed each time."));
        assert!(general_text("bash", 5, false)
            .starts_with("[bee] You have called bash with the same arguments 5 times in a row. "));
    }

    #[test]
    fn validation_holds_the_order() {
        assert!(StuckConfig::default().resolve().is_ok());
        for (d, r, s) in [(0, 5, 8), (3, 2, 8), (2, 8, 8), (2, 9, 8)] {
            let c = StuckConfig {
                denied_remind_after: Some(d),
                remind_after: Some(r),
                stop_after: Some(s),
                stop: None,
            };
            assert!(c.resolve().is_err(), "{d} {r} {s} accepted");
        }
        let c = StuckConfig {
            denied_remind_after: Some(3),
            remind_after: Some(3),
            stop_after: Some(4),
            stop: None,
        };
        assert!(c.resolve().is_ok(), "equal reminder thresholds are allowed");
    }

    #[test]
    fn reset_forgets_the_streak() {
        let mut t = tracker();
        let a = json!({});
        signals(
            &mut t,
            &(0..4).map(|_| (a.clone(), ok())).collect::<Vec<_>>(),
        );
        t.reset();
        let s = signals(
            &mut t,
            &(0..4).map(|_| (a.clone(), ok())).collect::<Vec<_>>(),
        );
        assert_eq!(reminders(&s), vec![]);
    }
}
