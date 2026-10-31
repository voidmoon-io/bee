//! Charges are never refunded merely because dispatch or its result is uncertain.
use crate::provider::Usage;
use crate::session::durable::{Attempt, Error, Phase, Snapshot, WorkKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Charge {
    Reserved,
    Settled {
        usage: Option<Usage>,
        duration_ms: u64,
    },
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reservation {
    #[serde(with = "attempt_json")]
    pub attempt: Attempt,
    pub kind: WorkKind,
    pub charge: Charge,
}

// Driver checkpoints pass through serde_json::Value, whose integers cannot hold a u128.
pub(super) mod attempt_json {
    use crate::session::durable::{ActivationId, Attempt, OperationId, SessionId};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct Record {
        session: SessionId,
        activation: String,
        operation: OperationId,
        number: u32,
    }

    pub fn serialize<S: Serializer>(attempt: &Attempt, serializer: S) -> Result<S::Ok, S::Error> {
        Record {
            session: attempt.session.clone(),
            activation: attempt.activation.0.to_string(),
            operation: attempt.operation,
            number: attempt.number,
        }
        .serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Attempt, D::Error> {
        let record = Record::deserialize(deserializer)?;
        Ok(Attempt {
            session: record.session,
            activation: ActivationId(
                record
                    .activation
                    .parse()
                    .map_err(serde::de::Error::custom)?,
            ),
            operation: record.operation,
            number: record.number,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    pub reservations: Vec<Reservation>,
}

impl Budget {
    pub fn charged(&self, kind: WorkKind) -> u32 {
        self.reservations.iter().filter(|r| r.kind == kind).count() as u32
    }
    pub fn unresolved(&self) -> usize {
        self.reservations
            .iter()
            .filter(|r| r.charge == Charge::Unresolved)
            .count()
    }
    pub fn unreported_model_usage(&self) -> usize {
        self.reservations
            .iter()
            .filter(|r| {
                r.kind == WorkKind::Model
                    && !matches!(r.charge, Charge::Settled { usage: Some(_), .. })
            })
            .count()
    }
    pub fn known_usage(&self) -> Result<Option<Usage>, Error> {
        let mut total = None;
        for r in &self.reservations {
            if let Charge::Settled {
                usage: Some(usage), ..
            } = r.charge
            {
                let previous: Usage = total.unwrap_or_default();
                total = Some(Usage {
                    input_tokens: previous
                        .input_tokens
                        .checked_add(usage.input_tokens)
                        .ok_or(Error::Limit)?,
                    output_tokens: previous
                        .output_tokens
                        .checked_add(usage.output_tokens)
                        .ok_or(Error::Limit)?,
                    cache_read_tokens: previous
                        .cache_read_tokens
                        .checked_add(usage.cache_read_tokens)
                        .ok_or(Error::Limit)?,
                    cache_write_tokens: previous
                        .cache_write_tokens
                        .checked_add(usage.cache_write_tokens)
                        .ok_or(Error::Limit)?,
                    reasoning_tokens: previous
                        .reasoning_tokens
                        .checked_add(usage.reasoning_tokens)
                        .ok_or(Error::Limit)?,
                });
            }
        }
        Ok(total)
    }
    pub(super) fn reserve(
        &mut self,
        attempt: Attempt,
        kind: WorkKind,
        limit: u32,
    ) -> Result<(), Error> {
        if self.reservations.iter().any(|r| r.attempt == attempt) {
            return Err(Error::Conflict);
        }
        if self.charged(kind) >= limit {
            return Err(Error::Limit);
        }
        self.reservations.push(Reservation {
            attempt,
            kind,
            charge: Charge::Reserved,
        });
        Ok(())
    }
    pub(super) fn settle(
        &mut self,
        attempt: &Attempt,
        usage: Option<Usage>,
        duration_ms: u64,
    ) -> Result<(), Error> {
        let reservation = self
            .reservations
            .iter_mut()
            .find(|r| &r.attempt == attempt)
            .ok_or(Error::InvalidSnapshot)?;
        let charge = Charge::Settled { usage, duration_ms };
        if reservation.charge == charge {
            return Ok(());
        }
        if reservation.charge != Charge::Reserved {
            return Err(Error::InvalidPhase);
        }
        reservation.charge = charge;
        Ok(())
    }
    pub(super) fn interrupt(&mut self) {
        for reservation in &mut self.reservations {
            if reservation.charge == Charge::Reserved {
                reservation.charge = Charge::Unresolved;
            }
        }
    }
    pub(super) fn reconcile(&mut self, attempt: &Attempt, duration_ms: u64) -> Result<(), Error> {
        let reservation = self
            .reservations
            .iter_mut()
            .find(|r| &r.attempt == attempt)
            .ok_or(Error::InvalidSnapshot)?;
        if reservation.kind != WorkKind::Tool || reservation.charge != Charge::Unresolved {
            return Err(Error::InvalidPhase);
        }
        reservation.charge = Charge::Settled {
            usage: None,
            duration_ms,
        };
        Ok(())
    }
    pub(super) fn validate(
        &self,
        snapshot: &Snapshot,
        model_limit: u32,
        tool_limit: u32,
    ) -> Result<(), Error> {
        if self.charged(WorkKind::Model) > model_limit || self.charged(WorkKind::Tool) > tool_limit
        {
            return Err(Error::InvalidSnapshot);
        }
        let mut identities = std::collections::BTreeSet::new();
        for r in &self.reservations {
            let op = snapshot
                .operation(r.attempt.operation)
                .ok_or(Error::InvalidSnapshot)?;
            if r.attempt.session != *snapshot.session()
                || r.kind != op.spec.kind
                || r.attempt.number == 0
                || r.attempt.number > op.attempts
                || !identities.insert((r.attempt.operation, r.attempt.number))
            {
                return Err(Error::InvalidSnapshot);
            }
            match &r.charge {
                Charge::Settled { usage, duration_ms } => {
                    let (attempt, result) = match &op.phase {
                        Phase::Completed { attempt, result }
                        | Phase::Publishing { attempt, result } => (attempt, result),
                        _ => return Err(Error::InvalidSnapshot),
                    };
                    let expected = if r.kind == WorkKind::Model {
                        serde_json::from_value::<crate::provider::Turn>(result.output.clone())
                            .map_err(|_| Error::InvalidSnapshot)?
                            .usage
                    } else {
                        None
                    };
                    if attempt != &r.attempt
                        || *usage != expected
                        || *duration_ms != result.duration_ms
                    {
                        return Err(Error::InvalidSnapshot);
                    }
                }
                Charge::Reserved => {
                    if !matches!(&op.phase, Phase::Running { attempt } if attempt == &r.attempt) {
                        return Err(Error::InvalidSnapshot);
                    }
                }
                Charge::Unresolved => {
                    if matches!(&op.phase, Phase::Completed { attempt, .. } | Phase::Publishing { attempt, .. } if attempt == &r.attempt)
                    {
                        return Err(Error::InvalidSnapshot);
                    }
                }
            }
        }
        self.known_usage()?;
        Ok(())
    }
}
