//! Consent-gated, attenuation-bounded capability grants for skills (006-skills, step 3).
//!
//! A skill's [`SkillRequires`] block proposes *widening* the episode's **base** policy. The widening
//! is bounded two ways, in order:
//!
//! 1. **Attenuation ceiling (not human-overridable).** The widened candidate must be a provable
//!    subset of a **ceiling** policy (`ceiling.derive(candidate)`, [`bee_core`]). Beyond the ceiling
//!    the grant is *refused* — no prompt can authorize it (Constitution II, III). Absent a distinct
//!    ceiling, base *is* the ceiling, so nothing widens and skills stay instructions-only.
//! 2. **Human consent (within the ceiling).** A within-ceiling request is offered to a
//!    [`ConsentSink`]. The non-interactive default ([`DenyAll`]) refuses every grant, so batch,
//!    concurrent, and CTF runs stay deny-by-default (Constitution I); only an interactive session
//!    wires a sink that can approve.
//!
//! This module is pure and host-testable: it computes the policy to compile and the tools to
//! register, but neither compiles a scope nor mutates a registry — the caller does that.

use std::collections::BTreeMap;

use bee_core::{Access, Policy};

use crate::skills::{Skill, SkillRequires};

/// A skill's capability request, surfaced to a [`ConsentSink`] for human review.
pub struct GrantRequest<'a> {
    /// The requesting skill's name.
    pub skill: &'a str,
    /// Harness tools it wants registered (e.g. `bash`).
    pub tools: &'a [String],
    /// Filesystem grants it wants, as authored (`path -> "read"|"write"|"deny"`).
    pub filesystem: &'a BTreeMap<String, String>,
}

/// The outcome of a consent request. A timeout at the call site maps to [`Decision::Denied`]
/// (fail-closed, Constitution I).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Granted,
    Denied,
}

/// Decides whether a within-ceiling capability request is approved. Async so a sink may poll an
/// out-of-band approver (prompt, queue, webhook); implemented for any `Fn(&GrantRequest) -> bool`
/// so a synchronous closure (a REPL prompt, a test) still works (007-dynamic-grants, contract
/// `consent.md`).
#[async_trait::async_trait]
pub trait ConsentSink: Send + Sync {
    /// [`Decision::Granted`] to grant, [`Decision::Denied`] to refuse. When in doubt, refuse.
    async fn confirm(&self, request: &GrantRequest<'_>) -> Decision;
}

#[async_trait::async_trait]
impl<F: Fn(&GrantRequest<'_>) -> bool + Send + Sync> ConsentSink for F {
    async fn confirm(&self, request: &GrantRequest<'_>) -> Decision {
        if self(request) {
            Decision::Granted
        } else {
            Decision::Denied
        }
    }
}

/// The non-interactive default: refuse every grant. Keeps automated runs deny-by-default.
pub struct DenyAll;

#[async_trait::async_trait]
impl ConsentSink for DenyAll {
    async fn confirm(&self, _request: &GrantRequest<'_>) -> Decision {
        Decision::Denied
    }
}

/// Approve every request — used when the **ceiling policy file** *is* the authorization (batch/CTF
/// episodes, Constitution IV). Safe because [`resolve_grants`] only consults a sink for a request it
/// has already proven ⊆ ceiling; with no distinct ceiling, base = ceiling and nothing reaches here.
pub struct AllowWithinCeiling;

#[async_trait::async_trait]
impl ConsentSink for AllowWithinCeiling {
    async fn confirm(&self, _request: &GrantRequest<'_>) -> Decision {
        Decision::Granted
    }
}

/// The result of resolving a set of skills' capability requests.
pub struct GrantOutcome {
    /// `base` ∪ every approved delta — the policy to compile for the scope. Equal to `base` when
    /// nothing was granted.
    pub policy: Policy,
    /// Harness tool names to register, from approved skills (deduped, stable order).
    pub tools: Vec<String>,
    /// Names of skills whose capabilities were granted.
    pub granted: Vec<String>,
    /// Skills whose requests were refused, each with a human-readable reason.
    pub refused: Vec<(String, String)>,
}

impl GrantOutcome {
    /// True when no skill widened the policy or added a tool (the instructions-only case).
    pub fn is_noop(&self) -> bool {
        self.tools.is_empty() && self.granted.is_empty()
    }
}

/// Parse an authored access word into a [`bee_core::Access`].
pub(crate) fn parse_access(word: &str) -> Result<Access, String> {
    match word.trim().to_ascii_lowercase().as_str() {
        "read" => Ok(Access::Read),
        "write" => Ok(Access::Write),
        "deny" => Ok(Access::Deny),
        other => Err(format!(
            "invalid access '{other}' (expected read|write|deny)"
        )),
    }
}

/// The more-permissive of two access levels (Write > Read > Deny), for widening a base grant.
fn more_permissive(a: Access, b: Access) -> Access {
    fn rank(x: Access) -> u8 {
        match x {
            Access::Deny => 0,
            Access::Read => 1,
            Access::Write => 2,
        }
    }
    if rank(a) >= rank(b) {
        a
    } else {
        b
    }
}

/// Resolve every skill's capability request against `base` and `ceiling`, gating within-ceiling
/// requests through `consent`. Skills without a `requires` block are instructions-only and skipped.
/// The returned [`GrantOutcome::policy`] is `base` widened by exactly the approved deltas.
pub async fn resolve_grants(
    skills: &[&Skill],
    base: &Policy,
    ceiling: &Policy,
    consent: &dyn ConsentSink,
) -> GrantOutcome {
    let mut policy = base.clone();
    let mut tools: Vec<String> = Vec::new();
    let mut granted: Vec<String> = Vec::new();
    let mut refused: Vec<(String, String)> = Vec::new();

    for skill in skills {
        let Some(req) = &skill.requires else {
            continue; // instructions-only
        };

        let candidate = match widen(&policy, req) {
            Ok(c) => c,
            Err(reason) => {
                refused.push((skill.name.clone(), reason));
                continue;
            }
        };

        // 1. Attenuation ceiling — not overridable by consent. `derive` proves candidate ⊆ ceiling.
        let candidate = match ceiling.derive(candidate) {
            Ok(policy) => policy,
            Err(e) => {
                refused.push((
                    skill.name.clone(),
                    format!("exceeds capability ceiling: {e}"),
                ));
                continue;
            }
        };

        // 2. Human consent, only for a request that is already within the ceiling.
        let request = GrantRequest {
            skill: &skill.name,
            tools: &req.tools,
            filesystem: &req.filesystem,
        };
        if consent.confirm(&request).await == Decision::Denied {
            refused.push((skill.name.clone(), "denied by operator".to_string()));
            continue;
        }

        policy = candidate;
        tools.extend(req.tools.iter().cloned());
        granted.push(skill.name.clone());
    }

    tools.sort();
    tools.dedup();
    GrantOutcome {
        policy,
        tools,
        granted,
        refused,
    }
}

/// Build `policy` widened by `req`'s filesystem grants (tools are registry membership, not policy).
/// Errors on a malformed access word so a bad skill is refused, not silently narrowed.
fn widen(policy: &Policy, req: &SkillRequires) -> Result<Policy, String> {
    let mut candidate = policy.clone();
    for (path, word) in &req.filesystem {
        let access = parse_access(word)?;
        let raised = match candidate.filesystem.get(path) {
            Some(&existing) => more_permissive(existing, access),
            None => access,
        };
        candidate.filesystem.insert(path.clone(), raised);
    }
    Ok(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skills::{SkillRequires, SkillSource};
    use std::path::PathBuf;

    /// A `Skill` with a given `requires`, without touching the filesystem.
    fn skill(name: &str, requires: Option<SkillRequires>) -> Skill {
        Skill {
            name: name.to_string(),
            description: "d".to_string(),
            dir: PathBuf::from("/nonexistent"),
            skill_md: PathBuf::from("/nonexistent/SKILL.md"),
            requires,
            user_invocable: false,
            model_invocable: true,
            source: SkillSource::Project,
        }
    }

    fn requires(tools: &[&str], fs: &[(&str, &str)]) -> SkillRequires {
        SkillRequires {
            tools: tools.iter().map(|s| s.to_string()).collect(),
            filesystem: fs
                .iter()
                .map(|(p, a)| (p.to_string(), a.to_string()))
                .collect(),
        }
    }

    /// A policy granting the given `path -> access` pairs (enforce mode, so ceilings can enforce).
    fn policy(name: &str, fs: &[(&str, Access)]) -> Policy {
        let mut p = Policy {
            name: name.to_string(),
            description: None,
            mode: bee_core::Mode::Enforce,
            filesystem: BTreeMap::new(),
            exec: Default::default(),
            network: Default::default(),
            defaults: Default::default(),
            exfiltration: Default::default(),
        };
        for (path, access) in fs {
            p.filesystem.insert(path.to_string(), *access);
        }
        p
    }

    #[tokio::test]
    async fn instructions_only_skill_is_a_noop() {
        let s = skill("plain", None);
        let base = policy("base", &[]);
        let out = resolve_grants(&[&s], &base, &base, &DenyAll).await;
        assert!(out.is_noop());
        assert!(out.granted.is_empty());
        assert!(out.refused.is_empty());
        assert_eq!(out.policy.filesystem, base.filesystem);
    }

    #[tokio::test]
    async fn within_ceiling_grant_is_approved_with_consent() {
        let s = skill(
            "writer",
            Some(requires(&["bash"], &[("/tmp/work", "write")])),
        );
        let base = policy("base", &[]);
        // Ceiling permits write under /tmp.
        let ceiling = policy("ceiling", &[("/tmp", Access::Write)]);
        let out = resolve_grants(&[&s], &base, &ceiling, &|_: &GrantRequest<'_>| true).await;
        assert_eq!(out.granted, vec!["writer".to_string()]);
        assert_eq!(out.tools, vec!["bash".to_string()]);
        assert_eq!(out.policy.filesystem.get("/tmp/work"), Some(&Access::Write));
        assert!(out.refused.is_empty());
    }

    #[tokio::test]
    async fn within_ceiling_grant_is_refused_without_consent() {
        let s = skill(
            "writer",
            Some(requires(&["bash"], &[("/tmp/work", "write")])),
        );
        let base = policy("base", &[]);
        let ceiling = policy("ceiling", &[("/tmp", Access::Write)]);
        let out = resolve_grants(&[&s], &base, &ceiling, &DenyAll).await;
        assert!(out.granted.is_empty());
        assert!(out.tools.is_empty());
        // Policy is untouched — the base has no /tmp/work grant.
        assert!(!out.policy.filesystem.contains_key("/tmp/work"));
        assert_eq!(out.refused[0].0, "writer");
        assert!(out.refused[0].1.contains("denied by operator"));
    }

    #[tokio::test]
    async fn beyond_ceiling_grant_is_refused_without_prompting() {
        use std::sync::atomic::{AtomicBool, Ordering};
        static PROMPTED: AtomicBool = AtomicBool::new(false);
        let s = skill("greedy", Some(requires(&[], &[("/etc", "write")])));
        let base = policy("base", &[]);
        // Ceiling only permits /tmp — /etc is out of bounds.
        let ceiling = policy("ceiling", &[("/tmp", Access::Write)]);
        let consent = |_: &GrantRequest<'_>| {
            PROMPTED.store(true, Ordering::SeqCst);
            true
        };
        let out = resolve_grants(&[&s], &base, &ceiling, &consent).await;
        assert!(out.granted.is_empty());
        assert!(!out.policy.filesystem.contains_key("/etc"));
        assert!(out.refused[0].1.contains("exceeds capability ceiling"));
        // The human is never even asked for an unauthorizable request.
        assert!(!PROMPTED.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn malformed_access_word_is_refused() {
        let s = skill("typo", Some(requires(&[], &[("/tmp/x", "wrtie")])));
        let base = policy("base", &[("/tmp", Access::Write)]);
        let out = resolve_grants(&[&s], &base, &base, &|_: &GrantRequest<'_>| true).await;
        assert!(out.granted.is_empty());
        assert!(out.refused[0].1.contains("invalid access"));
    }

    #[tokio::test]
    async fn no_ceiling_means_no_widening_even_with_consent() {
        // base == ceiling and base grants nothing ⇒ any fs request exceeds the ceiling.
        let s = skill("writer", Some(requires(&[], &[("/tmp/work", "write")])));
        let base = policy("base", &[]);
        let out = resolve_grants(&[&s], &base, &base, &|_: &GrantRequest<'_>| true).await;
        assert!(out.granted.is_empty());
        assert!(out.refused[0].1.contains("exceeds capability ceiling"));
    }

    #[tokio::test]
    async fn tool_only_grant_needs_no_ceiling_room() {
        // A skill wanting only a tool (no fs delta) is within any ceiling; consent alone gates it.
        let s = skill("tooler", Some(requires(&["bash"], &[])));
        let base = policy("base", &[]);
        let out = resolve_grants(&[&s], &base, &base, &|_: &GrantRequest<'_>| true).await;
        assert_eq!(out.granted, vec!["tooler".to_string()]);
        assert_eq!(out.tools, vec!["bash".to_string()]);
    }

    #[tokio::test]
    async fn tools_from_multiple_skills_are_deduped() {
        let a = skill("a", Some(requires(&["bash", "read_file"], &[])));
        let b = skill("b", Some(requires(&["bash"], &[])));
        let base = policy("base", &[]);
        let out = resolve_grants(&[&a, &b], &base, &base, &|_: &GrantRequest<'_>| true).await;
        assert_eq!(out.tools, vec!["bash".to_string(), "read_file".to_string()]);
        assert_eq!(out.granted.len(), 2);
    }
}
