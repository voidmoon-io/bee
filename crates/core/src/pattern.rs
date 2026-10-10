//! Host-name patterns (019-http-intercept), shared by `[policy.http]` and the MCP domain gate.
//!
//! An exact name or `*.suffix`. A wildcard matches one or more subdomain labels but **never** the
//! bare apex or a suffix-substring: `*.company.com` matches `a.company.com` and `a.b.company.com`, not
//! `company.com` or `evilcompany.com`. Matching ignores ASCII case and a trailing dot.
//!
//! These are the `DomainPattern` semantics MCP already shipped (004), lifted into the core so policy
//! attenuation and `bee validate` can reason about them — which also gives them a containment
//! relation, [`HostPattern::covers`], that the MCP gate never needed.

use serde::{Deserialize, Serialize};

/// A single host rule. Parses from a bare string: `"example.com"` → [`HostPattern::Exact`],
/// `"*.example.com"` → [`HostPattern::Wildcard`]. Any other use of `*` is rejected at parse time.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum HostPattern {
    /// A single, normalised host name.
    Exact(String),
    /// The normalised suffix after `*.`.
    Wildcard(String),
}

/// Lowercase and strip a trailing dot, so matching is case- and FQDN-dot-insensitive.
pub fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

impl TryFrom<String> for HostPattern {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let t = s.trim();
        if t.is_empty() {
            return Err("empty domain pattern".into());
        }
        if let Some(suffix) = t.strip_prefix("*.") {
            if suffix.is_empty() || suffix.contains('*') || normalize_host(suffix).is_empty() {
                return Err(format!("invalid wildcard domain pattern: {s:?}"));
            }
            return Ok(HostPattern::Wildcard(normalize_host(suffix)));
        }
        if t.contains('*') {
            return Err(format!(
                "invalid domain pattern {s:?}: a wildcard must be written as `*.suffix`"
            ));
        }
        let n = normalize_host(t);
        if n.is_empty() {
            return Err(format!("invalid domain pattern {s:?}"));
        }
        Ok(HostPattern::Exact(n))
    }
}

impl From<HostPattern> for String {
    fn from(p: HostPattern) -> String {
        p.to_string()
    }
}

impl HostPattern {
    /// Whether `host` matches this pattern.
    pub fn matches(&self, host: &str) -> bool {
        let h = normalize_host(host);
        match self {
            HostPattern::Exact(e) => &h == e,
            HostPattern::Wildcard(suffix) => is_strict_subdomain(&h, suffix),
        }
    }

    /// Whether every host `other` matches is also matched by `self`.
    ///
    /// `Some(true)`/`Some(false)` when that is decidable from the two patterns alone, which for this
    /// pattern language is always — but the signature keeps `None` ("cannot tell") so a future
    /// pattern form that is not decidable has somewhere to go, and every caller is already written to
    /// treat it as a refusal (Constitution II: fail closed on an unprovable subset).
    ///
    /// - exact ⊆ exact iff equal;
    /// - exact `x` ⊆ `*.s` iff `x` is a strict subdomain of `s`;
    /// - `*.t` ⊆ `*.s` iff `t == s` or `t` is a strict subdomain of `s`;
    /// - a wildcard is never ⊆ an exact name.
    pub fn covers(&self, other: &HostPattern) -> Option<bool> {
        Some(match (self, other) {
            (HostPattern::Exact(a), HostPattern::Exact(b)) => a == b,
            (HostPattern::Exact(_), HostPattern::Wildcard(_)) => false,
            (HostPattern::Wildcard(s), HostPattern::Exact(x)) => is_strict_subdomain(x, s),
            (HostPattern::Wildcard(s), HostPattern::Wildcard(t)) => {
                t == s || is_strict_subdomain(t, s)
            }
        })
    }
}

/// `h` ends with `.{suffix}` with at least one non-empty label in front.
fn is_strict_subdomain(h: &str, suffix: &str) -> bool {
    h.strip_suffix(suffix)
        .is_some_and(|prefix| prefix.len() > 1 && prefix.ends_with('.'))
}

impl std::fmt::Display for HostPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostPattern::Exact(h) => write!(f, "{h}"),
            HostPattern::Wildcard(s) => write!(f, "*.{s}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> HostPattern {
        HostPattern::try_from(s.to_string()).unwrap()
    }

    #[test]
    fn matching_follows_the_mcp_semantics() {
        assert!(p("*.company.com").matches("a.company.com"));
        assert!(p("*.company.com").matches("A.B.Company.COM."));
        assert!(!p("*.company.com").matches("company.com"));
        assert!(!p("*.company.com").matches("evilcompany.com"));
        assert!(p("Example.com.").matches("example.COM"));
    }

    #[test]
    fn parse_rejects_stray_wildcards() {
        for bad in ["", "*", "*foo.com", "a.*.com", "*.", "*.*.com", "."] {
            assert!(HostPattern::try_from(bad.to_string()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn containment() {
        assert_eq!(p("a.b").covers(&p("A.B.")), Some(true));
        assert_eq!(p("a.b").covers(&p("*.a.b")), Some(false));
        assert_eq!(p("*.a.b").covers(&p("x.a.b")), Some(true));
        assert_eq!(p("*.a.b").covers(&p("a.b")), Some(false));
        assert_eq!(p("*.a.b").covers(&p("*.x.a.b")), Some(true));
        assert_eq!(p("*.a.b").covers(&p("*.a.b")), Some(true));
        assert_eq!(p("*.x.a.b").covers(&p("*.a.b")), Some(false));
        assert_eq!(p("*.a.b").covers(&p("*.xa.b")), Some(false));
    }
}
