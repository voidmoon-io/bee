//! Answering a consent question in the inline REPL (024 T058, contracts/operator.md).
//!
//! The REPL has one line reader. While the agent runs, every submitted line is steering, so a
//! question about a grant has to share that reader: a line that is an answer — `y`, `yes`, `n`, `no`,
//! trimmed, any case — answers it, and any other line is steering as before, after which the question
//! is shown again. An answer that arrives after the operator stopped waiting is dropped, never
//! applied and never steered.

use tokio::sync::oneshot;

use crate::operator::{ConsentAsk, Decision};
use crate::repl::ReplOutput;

/// The line the question ends with.
pub const QUESTION: &str = "grant these (within the ceiling)? answer y or n";

/// A line that does not answer the question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotAnAnswer;

/// `y`/`yes` grants, `n`/`no` refuses; nothing else answers.
pub fn parse(line: &str) -> Result<Decision, NotAnAnswer> {
    match line.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Ok(Decision::Granted),
        "n" | "no" => Ok(Decision::Denied),
        _ => Err(NotAnAnswer),
    }
}

/// A question waiting on the operator.
pub struct Pending {
    lines: Vec<String>,
    reply: oneshot::Sender<Decision>,
}

impl Pending {
    pub fn new(ask: ConsentAsk) -> Self {
        Pending {
            lines: ask.request.render_lines(),
            reply: ask.reply,
        }
    }

    /// Show the request and the question.
    pub fn show(&self, output: &dyn ReplOutput) {
        for line in &self.lines {
            output.info(line);
        }
        output.info(QUESTION);
    }

    /// Refuse it: the operator ended input instead of answering.
    pub fn refuse(self) {
        let _ = self.reply.send(Decision::Denied);
    }
}

/// Where a submitted line went.
#[derive(Debug, PartialEq, Eq)]
pub enum Routed {
    /// It answered the waiting question.
    Answered,
    /// It was an answer, but the operator had stopped waiting: dropped.
    TooLate,
    /// It is not an answer, or nothing is waiting: the caller steers with it. A question still
    /// waiting stays in `pending`, to be shown again.
    Steering,
}

/// Route `line` while `pending` may hold a question.
pub fn route(pending: &mut Option<Pending>, line: &str) -> Routed {
    let Some(p) = pending.take() else {
        return Routed::Steering;
    };
    match parse(line) {
        Ok(decision) => match p.reply.send(decision) {
            Ok(()) => Routed::Answered,
            Err(_) => Routed::TooLate,
        },
        Err(NotAnAnswer) => {
            if !p.reply.is_closed() {
                *pending = Some(p);
            }
            Routed::Steering
        }
    }
}

/// What the operator sees when an answer arrived too late.
pub const TOO_LATE: &str = "consent already timed out — answer dropped";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::GrantOrigin;
    use crate::operator::ConsentRequest;

    fn pending() -> (Option<Pending>, oneshot::Receiver<Decision>) {
        let (reply, rx) = oneshot::channel();
        let ask = ConsentAsk {
            request: ConsentRequest {
                origin: GrantOrigin::Explicit,
                tools: vec!["bash".into()],
                filesystem: Default::default(),
                exec: Vec::new(),
                net: Vec::new(),
                http_targets: Vec::new(),
                turn: 1,
            },
            reply,
        };
        (Some(Pending::new(ask)), rx)
    }

    #[test]
    fn only_yes_and_no_answer() {
        for yes in ["y", "Y", "yes", " YES ", "Yes\n"] {
            assert_eq!(parse(yes), Ok(Decision::Granted), "{yes:?}");
        }
        for no in ["n", "N", "no", " No "] {
            assert_eq!(parse(no), Ok(Decision::Denied), "{no:?}");
        }
        for other in ["", "yep", "nope", "y please", "ok", "sure", "1", "yes!"] {
            assert_eq!(parse(other), Err(NotAnAnswer), "{other:?}");
        }
    }

    #[test]
    fn an_answer_reaches_the_question() {
        let (mut p, mut rx) = pending();
        assert_eq!(route(&mut p, "y"), Routed::Answered);
        assert!(p.is_none());
        assert_eq!(rx.try_recv(), Ok(Decision::Granted));
    }

    #[test]
    fn anything_else_steers_and_keeps_the_question() {
        let (mut p, mut rx) = pending();
        assert_eq!(route(&mut p, "also check /var"), Routed::Steering);
        assert!(p.is_some(), "the question is still waiting");
        assert!(rx.try_recv().is_err(), "and unanswered");
        assert_eq!(route(&mut p, "no"), Routed::Answered);
        assert_eq!(rx.try_recv(), Ok(Decision::Denied));
    }

    #[test]
    fn a_late_answer_is_dropped_and_not_steered() {
        let (mut p, rx) = pending();
        drop(rx); // the operator stopped waiting
        assert_eq!(route(&mut p, "yes"), Routed::TooLate);
        assert!(p.is_none());
    }

    #[test]
    fn once_the_question_is_gone_a_line_is_just_steering() {
        let (mut p, rx) = pending();
        drop(rx);
        assert_eq!(route(&mut p, "keep going"), Routed::Steering);
        assert!(p.is_none(), "a dead question is not shown again");
        assert_eq!(route(&mut p, "y"), Routed::Steering);
    }
}
