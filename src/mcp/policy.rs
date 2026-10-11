//! MCP policy: the `[mcp]` table — the master switch, domain allowlist/denylist, and the server
//! list. Pure declarative data (Constitution IV, always compiled). Domain *matching* and resolution
//! land in the remote slice (US9/T025); this module carries the types and their parsing.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::config::McpServerConfig;

/// A single allow/deny domain rule: `"example.com"` or `"*.example.com"` (subdomains only, never the
/// bare apex). The type moved into `bee-core` as [`bee_core::HostPattern`] (019-http-intercept), so
/// `[policy.http]` attenuation shares exactly these semantics; the MCP name is kept as an alias.
pub use bee_core::HostPattern as DomainPattern;

/// Extract the hostname from a URL (scheme/userinfo/port/path stripped), for domain gating. Handles
/// bracketed IPv6 literals. Returns `None` if no host is present.
pub fn url_host(url: &str) -> Option<&str> {
    let after_scheme = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        rest.split_once(']').map(|(h, _)| h).unwrap_or(rest) // IPv6 literal
    } else {
        host_port.split(':').next().unwrap_or(host_port)
    };
    (!host.is_empty()).then_some(host)
}

/// The `[mcp]` table. Every field defaults (fail-closed): an absent/partial `[mcp]` is disabled with
/// no remote reachability (research R10/R11).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct McpPolicy {
    /// Master switch. `false`/absent ⇒ no MCP servers, no MCP tools (SC-027).
    pub enabled: bool,
    /// Remote allowlist. Empty ⇒ no remote server may connect (deny-by-default).
    pub allowed_domains: Vec<DomainPattern>,
    /// Always-denied domains; take precedence over `allowed_domains`.
    pub denied_domains: Vec<DomainPattern>,
    /// Cap on simultaneously-connected servers.
    pub max_servers: u32,
    /// Per-MCP-tool-call timeout, seconds (FR-038).
    pub tool_timeout_secs: u64,
    /// Whether the agent may connect to servers not listed in `servers`. Fail-closed default (FR-040).
    pub allow_dynamic_connect: bool,
    /// The `[[mcp.servers]]` array.
    pub servers: Vec<McpServerConfig>,
}

impl Default for McpPolicy {
    fn default() -> Self {
        McpPolicy {
            enabled: false,
            allowed_domains: Vec::new(),
            denied_domains: Vec::new(),
            max_servers: 5,
            tool_timeout_secs: 30,
            allow_dynamic_connect: false,
            servers: Vec::new(),
        }
    }
}

impl McpPolicy {
    /// Load an MCP policy from a standalone TOML file with a top-level `[mcp]` table (and
    /// `[[mcp.servers]]`) — used by the REPL's `--mcp-config` (US10).
    pub fn from_path(path: &std::path::Path) -> Result<McpPolicy, crate::config::ConfigError> {
        #[derive(Deserialize)]
        struct McpFile {
            #[serde(default)]
            mcp: McpPolicy,
        }
        let text =
            std::fs::read_to_string(path).map_err(|e| crate::config::ConfigError::read(path, e))?;
        let file: McpFile =
            toml::from_str(&text).map_err(|e| crate::config::ConfigError::parse(path, e))?;
        file.mcp
            .validate()
            .map_err(crate::config::ConfigError::Invalid)?;
        Ok(file.mcp)
    }

    /// The per-tool-call timeout as a `Duration`.
    pub fn tool_timeout(&self) -> Duration {
        Duration::from_secs(self.tool_timeout_secs)
    }

    /// The names of every configured `token_env` — added to the sandbox credential strip-list so MCP
    /// tokens never leak into a stdio server child's environment (FR-041, T012).
    pub fn token_env_names(&self) -> Vec<String> {
        self.servers
            .iter()
            .filter_map(|s| s.token_env.clone())
            .filter(|n| !n.is_empty())
            .collect()
    }

    /// Decide whether a remote MCP server at `url` may be connected (FR-035). Resolution order:
    /// **denied → allowed → deny-by-default**. Returns `Ok(())` to allow, or `Err(reason)` with a
    /// transcript-ready message to refuse — evaluated **before** any transport is opened (SC-021).
    pub fn allow_url(&self, url: &str) -> Result<(), String> {
        let host = url_host(url).ok_or_else(|| {
            format!("connection refused by MCP policy — cannot parse host from {url:?}")
        })?;
        if self.denied_domains.iter().any(|p| p.matches(host)) {
            return Err(format!(
                "connection refused by MCP policy — domain {host} is in the denylist"
            ));
        }
        if self.allowed_domains.iter().any(|p| p.matches(host)) {
            return Ok(());
        }
        Err(format!(
            "connection refused by MCP policy — domain {host} not in the allowlist"
        ))
    }

    /// Semantic validation (called from `Scenario::validate`). Only enforced when `enabled`.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.max_servers < 1 {
            return Err("mcp.max_servers must be >= 1".into());
        }
        if self.tool_timeout_secs < 1 {
            return Err("mcp.tool_timeout_secs must be >= 1".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        for s in &self.servers {
            s.validate()?;
            if !seen.insert(&s.name) {
                return Err(format!("duplicate mcp server name: {}", s.name));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<DomainPattern, String> {
        DomainPattern::try_from(s.to_string())
    }

    #[test]
    fn parses_exact_and_wildcard() {
        assert_eq!(
            parse("Example.com").unwrap(),
            DomainPattern::Exact("example.com".into())
        );
        assert_eq!(
            parse("*.Company.com").unwrap(),
            DomainPattern::Wildcard("company.com".into())
        );
        // trailing dot normalized away
        assert_eq!(
            parse("example.com.").unwrap(),
            DomainPattern::Exact("example.com".into())
        );
    }

    #[test]
    fn rejects_bare_and_malformed_wildcards() {
        assert!(parse("*").is_err());
        assert!(parse("*com").is_err());
        assert!(parse("*.a*b.com").is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn roundtrips_through_string() {
        for s in ["example.com", "*.company.com"] {
            let p = parse(s).unwrap();
            assert_eq!(String::from(p.clone()), s);
        }
    }

    #[test]
    fn default_is_disabled_and_fail_closed() {
        let p = McpPolicy::default();
        assert!(!p.enabled);
        assert_eq!(p.max_servers, 5);
        assert_eq!(p.tool_timeout_secs, 30);
        assert!(!p.allow_dynamic_connect);
        assert!(p.validate().is_ok()); // disabled → no checks
    }

    #[test]
    fn wildcard_matching_rules() {
        let w = DomainPattern::try_from("*.company.com".to_string()).unwrap();
        assert!(w.matches("a.company.com"));
        assert!(w.matches("a.b.company.com"));
        assert!(w.matches("A.Company.Com")); // case-insensitive
        assert!(w.matches("x.company.com.")); // trailing dot normalized
        assert!(!w.matches("company.com")); // bare apex excluded
        assert!(!w.matches("evilcompany.com")); // suffix-substring, not a subdomain
        assert!(!w.matches("company.com.evil.com"));

        let e = DomainPattern::try_from("mcp.internal.dev".to_string()).unwrap();
        assert!(e.matches("mcp.internal.dev"));
        assert!(!e.matches("x.mcp.internal.dev"));
        assert!(!e.matches("mcp.internal.dev.evil.com"));
    }

    /// The normative resolution matrix from contracts/mcp-policy.md §3.
    #[test]
    fn resolution_matrix() {
        let pol = |allow: &[&str], deny: &[&str]| McpPolicy {
            enabled: true,
            allowed_domains: allow
                .iter()
                .map(|s| DomainPattern::try_from(s.to_string()).unwrap())
                .collect(),
            denied_domains: deny
                .iter()
                .map(|s| DomainPattern::try_from(s.to_string()).unwrap())
                .collect(),
            ..Default::default()
        };
        let host_of = |p: &McpPolicy, url: &str| p.allow_url(url).is_ok();

        // 1: exact allow
        assert!(host_of(
            &pol(&["mcp.internal.dev"], &[]),
            "https://mcp.internal.dev/tools"
        ));
        // 2: not allowed → refuse
        assert!(!host_of(
            &pol(&["mcp.internal.dev"], &[]),
            "https://mcp.evil.dev/tools"
        ));
        // 3: denied wins over wildcard allow
        assert!(!host_of(
            &pol(&["*.company.com"], &["admin.company.com"]),
            "https://admin.company.com/mcp"
        ));
        // 4: wildcard allow
        assert!(host_of(
            &pol(&["*.company.com"], &["admin.company.com"]),
            "https://app.company.com/mcp"
        ));
        // 5: wildcard ≠ apex
        assert!(!host_of(
            &pol(&["*.company.com"], &[]),
            "https://company.com/mcp"
        ));
        // 6: empty allowlist → refuse everything
        assert!(!host_of(&pol(&[], &[]), "https://anything.example/mcp"));
    }

    #[test]
    fn url_host_extraction() {
        assert_eq!(
            url_host("https://mcp.internal.dev/github"),
            Some("mcp.internal.dev")
        );
        assert_eq!(
            url_host("https://user@db.company.com:8443/mcp?x=1"),
            Some("db.company.com")
        );
        assert_eq!(
            url_host("http://[2001:db8::1]:9000/mcp"),
            Some("2001:db8::1")
        );
        assert_eq!(url_host("mcp.internal.dev/x"), Some("mcp.internal.dev"));
    }

    proptest::proptest! {
        // A wildcard `*.suffix` never matches the bare apex and never matches a label that merely
        // ends with the suffix text without a dot boundary (the substring-attack class).
        #[test]
        fn wildcard_never_matches_apex_or_substring(
            label in "[a-z]{1,8}",
            suffix in "[a-z]{1,6}\\.[a-z]{2,4}",
        ) {
            let w = DomainPattern::Wildcard(suffix.clone());
            let subdomain = format!("{label}.{suffix}");
            let substring = format!("{label}{suffix}");
            proptest::prop_assert!(!w.matches(&suffix));      // apex excluded
            proptest::prop_assert!(w.matches(&subdomain));    // real subdomain matches
            proptest::prop_assert!(!w.matches(&substring));   // no dot boundary → no match
        }
    }

    #[test]
    fn rejects_duplicate_server_names() {
        let srv = McpServerConfig {
            name: "fs".into(),
            transport: super::super::config::McpTransport::Stdio,
            command: Some("srv".into()),
            args: vec![],
            env: Default::default(),
            url: None,
            token_env: None,
            allowed_tools: None,
            denied_tools: None,
        };
        let p = McpPolicy {
            enabled: true,
            servers: vec![srv.clone(), srv],
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }
}
