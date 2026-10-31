use crate::session::durable::{ActivationId, Attempt};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Wake {
    pub generation: u64,
    #[serde(with = "super::budget::attempt_json")]
    pub attempt: Attempt,
    pub deadline_ms: u64,
    /// The full delay. A process that has itself waited this long on its monotonic clock may retry
    /// even if the wall clock was set back; journals from before this field wait on the wall clock.
    #[serde(default)]
    pub delay_ms: u64,
    pub ready: bool,
}

#[derive(Debug, Clone)]
pub(super) struct WakeToken {
    pub activation: ActivationId,
    pub wake: Wake,
}

impl Wake {
    /// `waited_ms` is how long this process has waited on its monotonic clock. The wall clock can
    /// jump forward (so it alone could release a retry early) or back (so it alone could withhold
    /// one past the submission deadline); waiting the full delay here settles either case.
    pub fn accepts(
        &self,
        token: &WakeToken,
        activation: ActivationId,
        now_ms: u64,
        wall_ms: u64,
        waited_ms: u64,
    ) -> bool {
        !self.ready
            && token.activation == activation
            && token.wake == *self
            && now_ms >= self.deadline_ms
            && (wall_ms >= self.deadline_ms || (self.delay_ms > 0 && waited_ms >= self.delay_ms))
    }
}

impl super::Driver {
    pub(super) fn schedule_retry(
        &mut self,
        attempt: Attempt,
        delay: std::time::Duration,
    ) -> Result<(), super::DriverError> {
        let now = self.time();
        let generation = self.journal().next_wake_generation;
        self.journal_mut().next_wake_generation = generation
            .checked_add(1)
            .ok_or(crate::session::durable::Error::Limit)?;
        let delay_ms = delay.as_millis().try_into().unwrap_or(u64::MAX);
        self.active_mut().wake = Some(Wake {
            generation,
            attempt,
            deadline_ms: now.saturating_add(delay_ms),
            delay_ms,
            ready: false,
        });
        Ok(())
    }
    pub(super) async fn retry_wait(
        &mut self,
        output: &dyn crate::repl::ReplOutput,
    ) -> Result<(), super::DriverError> {
        let waiting = std::time::Instant::now();
        loop {
            let Some(wake) = self.active().wake.clone() else {
                return Ok(());
            };
            if wake.ready {
                return Ok(());
            }
            output.info("provider retry delayed; waiting before the next attempt");
            let token = WakeToken {
                activation: self.state.activation(),
                wake,
            };
            // Expiry uses the conservative clock; a retry also waits for its wall deadline, or for
            // its full delay on this process's monotonic clock if the wall clock went back.
            let deadline = token.wake.deadline_ms;
            let conservative = deadline.saturating_sub(self.time());
            let mut released = deadline.saturating_sub(super::now_ms());
            if token.wake.delay_ms > 0 {
                let local = token.wake.delay_ms.saturating_sub(elapsed_ms(waiting));
                released = released.min(local);
            }
            let remaining = conservative.max(released);
            self.wait(
                tokio::time::sleep(std::time::Duration::from_millis(remaining)),
                self.active().deadline_ms,
                output,
            )
            .await?;
            let now = self.time();
            if self.active().wake.as_ref().is_some_and(|w| {
                w.accepts(
                    &token,
                    self.state.activation(),
                    now,
                    super::now_ms(),
                    elapsed_ms(waiting),
                )
            }) {
                self.active_mut().wake.as_mut().expect("matched wake").ready = true;
                self.save().await?;
                return Ok(());
            }
        }
    }
}

fn elapsed_ms(start: std::time::Instant) -> u64 {
    start.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::durable::{OperationId, SessionId};

    #[test]
    fn early_duplicate_and_stale_wakes_cannot_release_retry() {
        let wake = Wake {
            generation: 3,
            attempt: Attempt {
                session: SessionId("wake".into()),
                activation: ActivationId(1),
                operation: OperationId(2),
                number: 1,
            },
            deadline_ms: 100,
            delay_ms: 50,
            ready: false,
        };
        let token = WakeToken {
            activation: ActivationId(2),
            wake: wake.clone(),
        };
        assert!(!wake.accepts(&token, ActivationId(2), 99, 99, 0));
        assert!(!wake.accepts(&token, ActivationId(2), 140, 99, 0));
        assert!(!wake.accepts(&token, ActivationId(2), 99, 140, 0));
        assert!(wake.accepts(&token, ActivationId(2), 100, 100, 0));
        assert!(!wake.accepts(&token, ActivationId(3), 100, 100, 0));
        let mut ready = wake.clone();
        ready.ready = true;
        assert!(!ready.accepts(&token, ActivationId(2), 100, 100, 0));
        let mut next = wake.clone();
        next.generation += 1;
        assert!(!next.accepts(&token, ActivationId(2), 100, 100, 0));
        next = wake;
        next.attempt.number += 1;
        assert!(!next.accepts(&token, ActivationId(2), 100, 100, 0));
    }

    #[test]
    fn a_wall_clock_set_back_does_not_withhold_a_retry_waited_out_here() {
        let wake = Wake {
            generation: 1,
            attempt: Attempt {
                session: SessionId("wake".into()),
                activation: ActivationId(1),
                operation: OperationId(1),
                number: 1,
            },
            deadline_ms: 3_600_100,
            delay_ms: 100,
            ready: false,
        };
        let token = WakeToken {
            activation: ActivationId(1),
            wake: wake.clone(),
        };
        // The wall clock went back an hour after the conservative clock recorded the deadline.
        assert!(!wake.accepts(&token, ActivationId(1), 3_600_100, 100, 99));
        assert!(wake.accepts(&token, ActivationId(1), 3_600_100, 100, 100));
        // A full local wait alone is not enough before the conservative deadline.
        assert!(!wake.accepts(&token, ActivationId(1), 3_600_099, 100, 100));
        // A journal written before `delay_ms` keeps the wall-clock rule.
        let legacy = Wake {
            delay_ms: 0,
            ..wake
        };
        let token = WakeToken {
            activation: ActivationId(1),
            wake: legacy.clone(),
        };
        assert!(!legacy.accepts(&token, ActivationId(1), 3_600_100, 100, u64::MAX));
    }
}
