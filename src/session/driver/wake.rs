use crate::session::durable::{ActivationId, Attempt};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Wake {
    pub generation: u64,
    #[serde(with = "super::budget::attempt_json")]
    pub attempt: Attempt,
    pub deadline_ms: u64,
    pub ready: bool,
}

#[derive(Debug, Clone)]
pub(super) struct WakeToken {
    pub activation: ActivationId,
    pub wake: Wake,
}

impl Wake {
    pub fn accepts(
        &self,
        token: &WakeToken,
        activation: ActivationId,
        now_ms: u64,
        wall_ms: u64,
    ) -> bool {
        !self.ready
            && token.activation == activation
            && token.wake == *self
            && now_ms >= self.deadline_ms
            && wall_ms >= self.deadline_ms
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
        self.active_mut().wake = Some(Wake {
            generation,
            attempt,
            deadline_ms: now.saturating_add(delay.as_millis().try_into().unwrap_or(u64::MAX)),
            ready: false,
        });
        Ok(())
    }
    pub(super) async fn retry_wait(
        &mut self,
        output: &dyn crate::repl::ReplOutput,
    ) -> Result<(), super::DriverError> {
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
            // Expiry uses the conservative clock; a retry must also wait for its wall deadline.
            let remaining = token
                .wake
                .deadline_ms
                .saturating_sub(self.time().min(super::now_ms()));
            self.wait(
                tokio::time::sleep(std::time::Duration::from_millis(remaining)),
                self.active().deadline_ms,
                output,
            )
            .await?;
            let now = self.time();
            if self
                .active()
                .wake
                .as_ref()
                .is_some_and(|w| w.accepts(&token, self.state.activation(), now, super::now_ms()))
            {
                self.active_mut().wake.as_mut().expect("matched wake").ready = true;
                self.save().await?;
                return Ok(());
            }
        }
    }
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
            ready: false,
        };
        let token = WakeToken {
            activation: ActivationId(2),
            wake: wake.clone(),
        };
        assert!(!wake.accepts(&token, ActivationId(2), 99, 99));
        assert!(!wake.accepts(&token, ActivationId(2), 140, 99));
        assert!(!wake.accepts(&token, ActivationId(2), 99, 140));
        assert!(wake.accepts(&token, ActivationId(2), 100, 100));
        assert!(!wake.accepts(&token, ActivationId(3), 100, 100));
        let mut ready = wake.clone();
        ready.ready = true;
        assert!(!ready.accepts(&token, ActivationId(2), 100, 100));
        let mut next = wake.clone();
        next.generation += 1;
        assert!(!next.accepts(&token, ActivationId(2), 100, 100));
        next = wake;
        next.attempt.number += 1;
        assert!(!next.accepts(&token, ActivationId(2), 100, 100));
    }
}
