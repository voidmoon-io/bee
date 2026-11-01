//! Persisted script continuations. Guest requests become ordinary durable child operations.
use super::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_SCRIPTS: usize = 64;
pub const MAX_SCRIPT_CALLS: usize = 256;
pub const MAX_CHECKPOINT_BYTES: usize = 4 * 1024 * 1024;
/// Children admitted together by one suspension.
pub const MAX_BATCH: usize = 4;
/// Script levels including the root.
pub const MAX_DEPTH: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptSpec {
    pub source_input_sha256: String,
    pub runtime: String,
    pub compatibility: String,
    pub deadline_ms: u64,
    pub max_calls: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointRef {
    pub sha256: String,
    pub bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suspension {
    pub checkpoint: CheckpointRef,
    /// Admitted atomically. Results resume the continuation in this order.
    pub children: Vec<OperationId>,
    /// A batch resumes with a result list even when it contains one child.
    pub batch: bool,
}

/// A nested script executes as the parent's admitted child operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptParent {
    pub script: String,
    pub child: OperationId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScriptPhase {
    Active,
    Completed(serde_json::Value),
    Stopped(StopReason),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Script {
    pub spec: ScriptSpec,
    pub parent: Option<ScriptParent>,
    /// Append-only: length is the persisted generation.
    pub suspensions: Vec<Suspension>,
    pub phase: ScriptPhase,
}
impl Script {
    pub fn calls(&self) -> usize {
        self.suspensions.iter().map(|s| s.children.len()).sum()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptEvent {
    Start {
        id: String,
        spec: ScriptSpec,
        parent: Option<ScriptParent>,
    },
    Suspend {
        id: String,
        generation: u32,
        checkpoint: CheckpointRef,
        children: Vec<(OperationId, OperationSpec)>,
        batch: bool,
    },
    Finish {
        id: String,
        generation: u32,
        output: serde_json::Value,
    },
    Stop {
        id: String,
    },
    /// Drop a finished script and its descendants once its result was delivered.
    Forget {
        id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptResume<'a> {
    Start,
    Waiting(OperationId),
    Unresolved {
        child: OperationId,
        reason: UnresolvedReason,
    },
    Continue {
        checkpoint: &'a CheckpointRef,
        children: Vec<(OperationId, &'a Completion)>,
        batch: bool,
    },
    Completed(&'a serde_json::Value),
    Stopped(StopReason),
}

pub(crate) fn digest_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl CheckpointRef {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if !digest_valid(&self.sha256)
            || self.bytes == 0
            || self.bytes as usize > MAX_CHECKPOINT_BYTES
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}
impl ScriptSpec {
    fn validate(&self) -> Result<(), Error> {
        if !digest_valid(&self.source_input_sha256)
            || self.runtime.is_empty()
            || self.runtime.len() > 256
            || self.compatibility.is_empty()
            || self.compatibility.len() > 256
            || self.deadline_ms == 0
            || self.max_calls == 0
            || self.max_calls as usize > MAX_SCRIPT_CALLS
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}

impl Snapshot {
    pub fn scripts(&self) -> &BTreeMap<String, Script> {
        &self.scripts
    }

    /// Interpreter blobs required by authoritative recovery. Historical bindings
    /// remain validated metadata even after their bytes are reclaimed.
    pub fn required_checkpoints(&self) -> impl Iterator<Item = &CheckpointRef> {
        self.scripts
            .values()
            .filter(|script| script.phase == ScriptPhase::Active)
            .filter_map(|script| script.suspensions.last().map(|s| &s.checkpoint))
    }

    /// Call after activation with current trusted compatibility and time. This never dispatches.
    pub fn resume_script(
        &self,
        id: &str,
        spec: &ScriptSpec,
        now_ms: u64,
    ) -> Result<ScriptResume<'_>, Error> {
        let script = self.scripts.get(id).ok_or(Error::NotFound)?;
        if &script.spec != spec {
            return Err(Error::Conflict);
        }
        match &script.phase {
            ScriptPhase::Completed(value) => return Ok(ScriptResume::Completed(value)),
            ScriptPhase::Stopped(reason) => return Ok(ScriptResume::Stopped(*reason)),
            ScriptPhase::Active => {}
        }
        if now_ms.max(self.observed_ms) >= script.spec.deadline_ms {
            return Ok(ScriptResume::Stopped(StopReason::Deadline));
        }
        let Some(last) = script.suspensions.last() else {
            return Ok(ScriptResume::Start);
        };
        let mut results = Vec::with_capacity(last.children.len());
        let mut waiting = None;
        let mut stopped = None;
        for &child in &last.children {
            let op = self.operations.get(&child).ok_or(Error::InvalidSnapshot)?;
            match &op.phase {
                Phase::Completed { result, .. } => results.push((child, result)),
                Phase::Unresolved { reason, .. } => {
                    return Ok(ScriptResume::Unresolved {
                        child,
                        reason: *reason,
                    })
                }
                Phase::Stopped { reason, .. } => {
                    stopped.get_or_insert(*reason);
                }
                _ => {
                    waiting.get_or_insert(child);
                }
            }
        }
        if let Some(child) = waiting {
            return Ok(ScriptResume::Waiting(child));
        }
        if let Some(reason) = stopped {
            return Ok(ScriptResume::Stopped(reason));
        }
        Ok(ScriptResume::Continue {
            checkpoint: &last.checkpoint,
            children: results,
            batch: last.batch,
        })
    }

    /// Ancestor chain from the immediate parent to the root. Bounded and cycle-checked.
    pub fn script_ancestors(&self, id: &str) -> Result<Vec<&str>, Error> {
        let mut chain = Vec::new();
        let mut script = self.scripts.get(id).ok_or(Error::NotFound)?;
        while let Some(parent) = &script.parent {
            if chain.len() + 1 >= MAX_DEPTH {
                return Err(Error::InvalidSnapshot);
            }
            let (key, next) = self
                .scripts
                .get_key_value(&parent.script)
                .ok_or(Error::InvalidSnapshot)?;
            chain.push(key.as_str());
            script = next;
        }
        Ok(chain)
    }

    fn script_root<'a>(&'a self, id: &'a str) -> Result<&'a str, Error> {
        Ok(self.script_ancestors(id)?.last().copied().unwrap_or(id))
    }

    /// Calls admitted by every script sharing this script's root.
    pub fn tree_calls(&self, id: &str) -> Result<usize, Error> {
        let root = self.script_root(id)?;
        let mut total = 0;
        for key in self.scripts.keys() {
            if self.script_root(key)? == root {
                total += self.scripts[key].calls();
            }
        }
        Ok(total)
    }
}

fn can_advance(snapshot: &Snapshot, id: &str, generation: u32) -> Result<(), Error> {
    let script = snapshot.scripts.get(id).ok_or(Error::NotFound)?;
    if script.phase != ScriptPhase::Active
        || generation as usize != script.suspensions.len()
        || snapshot.observed_ms >= script.spec.deadline_ms
    {
        return Err(Error::Stale);
    }
    if let Some(last) = script.suspensions.last() {
        if !last.children.iter().all(|child| {
            matches!(
                snapshot.operations.get(child).map(|op| &op.phase),
                Some(Phase::Completed { .. })
            )
        }) {
            return Err(Error::InvalidPhase);
        }
    }
    Ok(())
}

pub(super) fn apply(
    state: &State,
    snapshot: &mut Snapshot,
    event: ScriptEvent,
) -> Result<Vec<Effect>, Error> {
    match event {
        ScriptEvent::Start { id, spec, parent } => {
            spec.validate()?;
            if id.is_empty() || id.len() > 64 || snapshot.observed_ms >= spec.deadline_ms {
                return Err(Error::InvalidInput);
            }
            if let Some(old) = snapshot.scripts.get(&id) {
                return if old.spec == spec && old.parent == parent {
                    Ok(vec![])
                } else {
                    Err(Error::Conflict)
                };
            }
            if snapshot.scripts.len() >= MAX_SCRIPTS {
                return Err(Error::Limit);
            }
            if let Some(parent) = &parent {
                check_parent(snapshot, &id, &spec, parent)?;
                let owner = &snapshot.scripts[&parent.script];
                let child = &snapshot.operations[&parent.child];
                if owner.phase != ScriptPhase::Active
                    || !owner
                        .suspensions
                        .last()
                        .is_some_and(|s| s.children.contains(&parent.child))
                    || matches!(child.phase, Phase::Completed { .. } | Phase::Stopped { .. })
                {
                    return Err(Error::InvalidPhase);
                }
                if snapshot.script_ancestors(&parent.script)?.len() + 2 > MAX_DEPTH {
                    return Err(Error::Limit);
                }
            }
            snapshot.scripts.insert(
                id,
                Script {
                    spec,
                    parent,
                    suspensions: vec![],
                    phase: ScriptPhase::Active,
                },
            );
        }
        ScriptEvent::Suspend {
            id,
            generation,
            checkpoint,
            children,
            batch,
        } => {
            can_advance(snapshot, &id, generation)?;
            checkpoint.validate()?;
            if children.is_empty() || children.len() > MAX_BATCH || (!batch && children.len() != 1)
            {
                return Err(Error::InvalidInput);
            }
            let root = snapshot.script_root(&id)?.to_owned();
            if snapshot.tree_calls(&id)? + children.len()
                > snapshot.scripts[&root].spec.max_calls as usize
                || snapshot.operations.len() + children.len() > MAX_OPERATIONS
            {
                return Err(Error::Limit);
            }
            let script = &snapshot.scripts[&id];
            for (index, (child, spec)) in children.iter().enumerate() {
                validate_spec(spec)?;
                if child.0 == 0
                    || snapshot.operations.contains_key(child)
                    || children[..index].iter().any(|(c, _)| c == child)
                {
                    return Err(Error::Conflict);
                }
                if spec.kind != WorkKind::Tool
                    || spec.deadline_ms > script.spec.deadline_ms
                    || spec.deadline_ms <= snapshot.observed_ms
                {
                    return Err(Error::InvalidInput);
                }
            }
            let mut effects = Vec::with_capacity(children.len() * 2);
            let ids = children.iter().map(|(child, _)| *child).collect();
            for (child, spec) in children {
                snapshot.operations.insert(
                    child,
                    Operation {
                        spec,
                        attempts: 0,
                        phase: Phase::Ready,
                    },
                );
                effects.extend([Effect::Accepted(child), Effect::Ready(child)]);
            }
            snapshot
                .scripts
                .get_mut(&id)
                .ok_or(Error::NotFound)?
                .suspensions
                .push(Suspension {
                    checkpoint,
                    children: ids,
                    batch,
                });
            return Ok(effects);
        }
        ScriptEvent::Finish {
            id,
            generation,
            output,
        } => {
            can_advance(snapshot, &id, generation)?;
            validate_payload(&output)?;
            snapshot.scripts.get_mut(&id).ok_or(Error::NotFound)?.phase =
                ScriptPhase::Completed(output);
        }
        ScriptEvent::Forget { id } => {
            for key in finished_tree(snapshot, &id)? {
                snapshot.scripts.remove(&key);
            }
        }
        ScriptEvent::Stop { id } => {
            if snapshot.scripts.get(&id).ok_or(Error::NotFound)?.phase != ScriptPhase::Active {
                return Err(Error::InvalidPhase);
            }
            // Stopping a script stops every active descendant and its admitted children.
            let mut targets = Vec::new();
            for key in snapshot.scripts.keys() {
                if key == &id || snapshot.script_ancestors(key)?.contains(&id.as_str()) {
                    targets.push(key.clone());
                }
            }
            let mut effects = Vec::new();
            for key in targets {
                let script = snapshot.scripts.get_mut(&key).ok_or(Error::NotFound)?;
                if script.phase != ScriptPhase::Active {
                    continue;
                }
                script.phase = ScriptPhase::Stopped(StopReason::Cancelled);
                let children = script
                    .suspensions
                    .last()
                    .map(|s| s.children.clone())
                    .unwrap_or_default();
                for child in children {
                    let op = snapshot
                        .operations
                        .get_mut(&child)
                        .ok_or(Error::InvalidSnapshot)?;
                    let before = op.phase.clone();
                    super::stop(op, StopReason::Cancelled);
                    if op.phase != before {
                        effects.extend(super::notification(state, child, &op.phase));
                    }
                }
            }
            return Ok(effects);
        }
    }
    Ok(vec![])
}

/// The script and every descendant, or an error if any of them is still active.
fn finished_tree(snapshot: &Snapshot, id: &str) -> Result<Vec<String>, Error> {
    let mut tree = Vec::new();
    for key in snapshot.scripts.keys() {
        if key == id || snapshot.script_ancestors(key)?.contains(&id) {
            if snapshot.scripts[key].phase == ScriptPhase::Active {
                return Err(Error::InvalidPhase);
            }
            tree.push(key.clone());
        }
    }
    Ok(tree)
}

/// After a prune: finished scripts whose bound operations are all gone go with them.
pub(super) fn forget_pruned(snapshot: &mut Snapshot) {
    let gone = |snapshot: &Snapshot, id: &OperationId| !snapshot.operations.contains_key(id);
    let removable: Vec<String> = snapshot
        .scripts
        .iter()
        .filter(|(_, script)| {
            script.phase != ScriptPhase::Active
                && script
                    .suspensions
                    .iter()
                    .flat_map(|s| s.children.iter())
                    .all(|child| gone(snapshot, child))
                && script
                    .parent
                    .as_ref()
                    .is_none_or(|parent| gone(snapshot, &parent.child))
        })
        .map(|(id, _)| id.clone())
        .collect();
    for id in removable {
        snapshot.scripts.remove(&id);
    }
}

fn check_parent(
    snapshot: &Snapshot,
    id: &str,
    spec: &ScriptSpec,
    parent: &ScriptParent,
) -> Result<(), Error> {
    let owner = snapshot
        .scripts
        .get(&parent.script)
        .ok_or(Error::InvalidInput)?;
    let child = snapshot
        .operations
        .get(&parent.child)
        .ok_or(Error::InvalidInput)?;
    if parent.script == id
        || !owner
            .suspensions
            .iter()
            .any(|s| s.children.contains(&parent.child))
        || spec.deadline_ms > child.spec.deadline_ms
        || spec.deadline_ms > owner.spec.deadline_ms
        || snapshot
            .scripts
            .iter()
            .any(|(other, s)| other != id && s.parent.as_ref() == Some(parent))
    {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

pub(super) fn validate(snapshot: &Snapshot) -> Result<(), Error> {
    if snapshot.scripts.len() > MAX_SCRIPTS
        || (snapshot.activation.is_none() && !snapshot.scripts.is_empty())
    {
        return Err(Error::InvalidSnapshot);
    }
    let mut children = std::collections::BTreeSet::new();
    for (id, script) in &snapshot.scripts {
        script.spec.validate()?;
        if id.is_empty() || id.len() > 64 || script.calls() > script.spec.max_calls as usize {
            return Err(Error::InvalidSnapshot);
        }
        for (index, suspension) in script.suspensions.iter().enumerate() {
            suspension.checkpoint.validate()?;
            let settled = index + 1 < script.suspensions.len()
                || matches!(script.phase, ScriptPhase::Completed(_));
            if suspension.children.is_empty()
                || suspension.children.len() > MAX_BATCH
                || (!suspension.batch && suspension.children.len() != 1)
            {
                return Err(Error::InvalidSnapshot);
            }
            for child in &suspension.children {
                let op = snapshot
                    .operations
                    .get(child)
                    .ok_or(Error::InvalidSnapshot)?;
                if !children.insert(*child)
                    || op.spec.kind != WorkKind::Tool
                    || op.spec.deadline_ms > script.spec.deadline_ms
                    || (settled && !matches!(op.phase, Phase::Completed { .. }))
                {
                    return Err(Error::InvalidSnapshot);
                }
            }
        }
        if let ScriptPhase::Completed(output) = &script.phase {
            validate_payload(output)?;
        }
        if let Some(parent) = &script.parent {
            check_parent(snapshot, id, &script.spec, parent).map_err(|_| Error::InvalidSnapshot)?;
            let owner_child = &snapshot.operations[&parent.child];
            if script.phase == ScriptPhase::Active
                && matches!(owner_child.phase, Phase::Completed { .. })
            {
                return Err(Error::InvalidSnapshot);
            }
        }
        // Bounded walk rejects cycles and excessive depth.
        snapshot
            .script_ancestors(id)
            .map_err(|_| Error::InvalidSnapshot)?;
        if script.parent.is_none() && snapshot.tree_calls(id)? > script.spec.max_calls as usize {
            return Err(Error::InvalidSnapshot);
        }
    }
    Ok(())
}
