//! The proxy worker's user-space scope checks (019 T036, research R7/R14).
//!
//! The kernel already limits the proxy scope to the compiled target and egress addresses; these
//! checks add what an address cannot express — the host *name*, CONNECT host = SNI, the role (a
//! target may be tested, an egress host only tunnelled), and DNS drift — and every refusal names the
//! layer that made it. Matching is ASCII-case-insensitive and ignores a trailing dot. An IP-literal
//! target matches only itself.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};

use bee_core::compiler::{HttpScope, Role, ScopeEntry};
use bee_core::pattern::normalize_host;

use crate::intercept::control::ProxyEventKind;

/// Why the proxy refused, as recorded and as answered to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub kind: ProxyEventKind,
    pub host: String,
    pub port: u16,
    pub detail: serde_json::Value,
}

impl Refusal {
    fn new(kind: ProxyEventKind, host: &str, port: u16) -> Self {
        Refusal {
            kind,
            host: host.to_string(),
            port,
            detail: serde_json::Value::Null,
        }
    }

    /// The HTTP status a client receives for this refusal.
    pub fn status(&self) -> u16 {
        match self.kind {
            ProxyEventKind::RefusedBadCredential => 407,
            ProxyEventKind::RefusedLimit => 429,
            ProxyEventKind::RefusedAddressDrift => 502,
            _ => 403,
        }
    }

    /// A one-line body for the client: bee's own words, naming the layer (FR-011).
    pub fn message(&self) -> String {
        format!(
            "refused by proxy (user-space check): {}:{} ({})\n",
            self.host,
            self.port,
            self.kind.as_str()
        )
    }
}

/// Resolves a host name to addresses. In the worker this asks the harness over the control channel
/// (the proxy scope cannot reach a DNS server — research R2 addendum).
pub trait HostResolver: Send + Sync {
    fn resolve(
        &self,
        host: &str,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, String>> + Send + '_>>;
}

/// The worker's view of the scope. Replaced wholesale by `scope.update`.
#[derive(Debug, Clone)]
pub struct ScopeChecker {
    scope: HttpScope,
}

impl ScopeChecker {
    pub fn new(scope: HttpScope) -> Self {
        ScopeChecker { scope }
    }

    pub fn scope(&self) -> &HttpScope {
        &self.scope
    }

    /// Replace the scope (after the kernel has been reloaded to match, US3).
    pub fn update(&mut self, scope: HttpScope) {
        self.scope = scope;
    }

    /// The entry for `host:port`, in either role.
    pub fn entry(&self, host: &str, port: u16) -> Option<&ScopeEntry> {
        let h = normalize_host(strip_brackets(host));
        self.scope
            .targets
            .iter()
            .chain(&self.scope.egress)
            .find(|e| e.port == port && e.host == h)
    }

    /// Whether `host:port` is in scope at all, and in which role.
    pub fn check_target(&self, host: &str, port: u16) -> Result<Role, Refusal> {
        self.entry(host, port)
            .map(|e| e.role)
            .ok_or_else(|| Refusal::new(ProxyEventKind::RefusedOutOfScope, host, port))
    }

    /// For model-originated traffic, and for decrypted or plain-HTTP requests: only a **target** may
    /// be tested. An egress host is reachable as a tunnel and nothing else.
    pub fn check_testable(&self, host: &str, port: u16) -> Result<(), Refusal> {
        match self.check_target(host, port)? {
            Role::Target => Ok(()),
            Role::Egress => Err(Refusal::new(ProxyEventKind::RefusedEgressOnly, host, port)),
        }
    }

    /// CONNECT host = SNI. A ClientHello without SNI is accepted only when the CONNECT authority is
    /// an IP literal (there is no name to compare).
    pub fn check_sni(
        &self,
        connect_host: &str,
        port: u16,
        sni: Option<&str>,
    ) -> Result<(), Refusal> {
        let ch = normalize_host(strip_brackets(connect_host));
        let ok = match sni {
            Some(s) => normalize_host(s) == ch,
            None => ch.parse::<IpAddr>().is_ok(),
        };
        if ok {
            Ok(())
        } else {
            let mut r = Refusal::new(ProxyEventKind::RefusedSniMismatch, connect_host, port);
            r.detail = serde_json::json!({ "sni": sni });
            Err(r)
        }
    }

    /// The `Host` header of a request to `host:port` must name an in-scope **target** too (T036).
    /// Otherwise one in-scope address could be used to test any virtual host behind it — a name the
    /// operator never listed. A request with no `Host` header passes (HTTP/1.0); one with several is
    /// checked on each.
    pub fn check_host_header(
        &self,
        values: &[String],
        host: &str,
        port: u16,
    ) -> Result<(), Refusal> {
        for v in values {
            let named = match split_authority(v.trim()) {
                Some((h, p)) => (h, p),
                None => (strip_brackets(v.trim()).to_string(), port),
            };
            let same =
                normalize_host(&named.0) == normalize_host(strip_brackets(host)) && named.1 == port;
            if !same && self.check_testable(&named.0, named.1).is_err() {
                let mut r = Refusal::new(ProxyEventKind::RefusedOutOfScope, &named.0, named.1);
                r.detail = serde_json::json!({ "reason": "the request (Host header or request-target) names an out-of-scope host", "authority": format!("{host}:{port}") });
                return Err(r);
            }
        }
        Ok(())
    }

    /// Whether a tunnel to `host:port` is decrypted: it matches `inspect` **and** is a testable
    /// target. An `inspect` wildcard can also match an egress host (`*.corp.com` over
    /// `pkg.corp.com`); egress stays an opaque tunnel, since every request decrypted on it would be
    /// refused as not testable.
    pub fn is_inspected(&self, host: &str, port: u16) -> bool {
        self.scope.inspect.iter().any(|p| p.matches(host))
            && self.check_testable(host, port).is_ok()
    }

    /// Whether `host`'s upstream certificate goes unverified (∈ `insecure_upstream`).
    pub fn is_insecure_upstream(&self, host: &str) -> bool {
        self.scope.insecure_upstream.iter().any(|p| p.matches(host))
    }

    /// Resolve `host` **now** and keep only addresses in the entry's compiled set. Every upstream
    /// connect goes through this. When none remain the request is refused with
    /// `refused_address_drift`, naming both sets, *before* any connect: the operator sees why,
    /// instead of an anonymous kernel denial (spec edge case "DNS changes mid-session").
    pub async fn resolve_checked(
        &self,
        host: &str,
        port: u16,
        resolver: &dyn HostResolver,
    ) -> Result<SocketAddr, Refusal> {
        let entry = self
            .entry(host, port)
            .ok_or_else(|| Refusal::new(ProxyEventKind::RefusedOutOfScope, host, port))?;
        let bare = strip_brackets(host);
        let now: Vec<IpAddr> = match bare.parse::<IpAddr>() {
            // An IP literal entry *is* its compiled address.
            Ok(ip) => vec![ip],
            Err(_) => resolver.resolve(&entry.host).await.unwrap_or_default(),
        };
        match now.iter().find(|a| entry.resolved.contains(a)) {
            Some(a) => Ok(SocketAddr::new(*a, port)),
            None => {
                let mut r = Refusal::new(ProxyEventKind::RefusedAddressDrift, host, port);
                r.detail = serde_json::json!({
                    "now_resolves_to": now,
                    "compiled": entry.resolved,
                });
                Err(r)
            }
        }
    }
}

fn strip_brackets(h: &str) -> &str {
    h.strip_prefix('[')
        .and_then(|x| x.strip_suffix(']'))
        .unwrap_or(h)
}

/// Split an authority `host:port` (`[v6]:port` allowed).
pub fn split_authority(a: &str) -> Option<(String, u16)> {
    let (h, p) = a.rsplit_once(':')?;
    // `::1` is a bare IPv6 host, not host `:` port 1; only a bracketed literal carries a port.
    if h.contains(':') && !(h.starts_with('[') && h.ends_with(']')) {
        return None;
    }
    let port: u16 = p.parse().ok()?;
    let host = strip_brackets(h);
    (!host.is_empty()).then(|| (host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bee_core::compiler::EnforcedBy;
    use bee_core::policy::HttpLimits;

    fn entry(host: &str, port: u16, ips: &[&str], role: Role) -> ScopeEntry {
        let resolved: Vec<IpAddr> = ips.iter().map(|s| s.parse().unwrap()).collect();
        ScopeEntry {
            host: host.into(),
            port,
            enforced_by: vec![EnforcedBy::Proxy { host: host.into() }],
            resolved,
            role,
        }
    }

    fn checker() -> ScopeChecker {
        ScopeChecker::new(HttpScope {
            targets: vec![
                entry("app.test", 443, &["127.0.0.2"], Role::Target),
                entry("10.0.0.5", 8080, &["10.0.0.5"], Role::Target),
            ],
            egress: vec![entry("crates.io", 443, &["127.0.0.9"], Role::Egress)],
            inspect: vec![],
            insecure_upstream: vec![],
            limits: HttpLimits::default(),
        })
    }

    struct Fixed(Vec<IpAddr>);
    impl HostResolver for Fixed {
        fn resolve(
            &self,
            _h: &str,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, String>> + Send + '_>>
        {
            let v = self.0.clone();
            Box::pin(async move { Ok(v) })
        }
    }

    #[test]
    fn host_matching_ignores_case_and_trailing_dot() {
        let c = checker();
        assert_eq!(c.check_target("APP.test.", 443), Ok(Role::Target));
        assert!(c.check_target("app.test", 80).is_err(), "port matters");
        assert!(c.check_target("x.app.test", 443).is_err());
        assert_eq!(c.check_target("crates.io", 443), Ok(Role::Egress));
    }

    #[test]
    fn egress_is_not_testable() {
        let c = checker();
        assert_eq!(
            c.check_testable("crates.io", 443).unwrap_err().kind,
            ProxyEventKind::RefusedEgressOnly
        );
        assert!(c.check_testable("app.test", 443).is_ok());
    }

    #[test]
    fn sni_must_equal_the_connect_host() {
        let c = checker();
        assert!(c.check_sni("app.test", 443, Some("APP.TEST")).is_ok());
        assert_eq!(
            c.check_sni("app.test", 443, Some("other.test"))
                .unwrap_err()
                .kind,
            ProxyEventKind::RefusedSniMismatch
        );
        assert!(
            c.check_sni("app.test", 443, None).is_err(),
            "no SNI on a name"
        );
        assert!(
            c.check_sni("10.0.0.5", 8080, None).is_ok(),
            "no SNI on an IP literal"
        );
    }

    #[tokio::test]
    async fn drift_is_refused_before_connecting() {
        let c = checker();
        let ok = c
            .resolve_checked("app.test", 443, &Fixed(vec!["127.0.0.2".parse().unwrap()]))
            .await
            .unwrap();
        assert_eq!(ok, "127.0.0.2:443".parse().unwrap());

        let r = c
            .resolve_checked("app.test", 443, &Fixed(vec!["127.0.0.3".parse().unwrap()]))
            .await
            .unwrap_err();
        assert_eq!(r.kind, ProxyEventKind::RefusedAddressDrift);
        assert_eq!(r.detail["now_resolves_to"][0], "127.0.0.3");
        assert_eq!(r.detail["compiled"][0], "127.0.0.2");

        // An IP literal never consults the resolver.
        let lit = c
            .resolve_checked("10.0.0.5", 8080, &Fixed(vec![]))
            .await
            .unwrap();
        assert_eq!(lit, "10.0.0.5:8080".parse().unwrap());
    }

    #[test]
    fn an_unbracketed_ipv6_authority_has_no_port() {
        assert_eq!(split_authority("::1"), None);
        assert_eq!(split_authority("[::1]:8443"), Some(("::1".into(), 8443)));
        assert_eq!(
            split_authority("app.test:443"),
            Some(("app.test".into(), 443))
        );
    }

    #[test]
    fn an_inspect_wildcard_never_decrypts_egress() {
        let mut scope = checker().scope.clone();
        scope.inspect =
            vec![bee_core::policy::HostPattern::try_from("*.test".to_string()).unwrap()];
        scope
            .egress
            .push(entry("pkg.test", 443, &["127.0.0.8"], Role::Egress));
        let c = ScopeChecker::new(scope);
        assert!(c.is_inspected("app.test", 443));
        assert!(!c.is_inspected("pkg.test", 443));
        assert!(!c.is_inspected("app.test", 8443));
    }

    #[test]
    fn a_host_header_must_name_an_in_scope_target() {
        let c = checker();
        assert!(c
            .check_host_header(&["app.test".into()], "app.test", 443)
            .is_ok());
        assert!(c
            .check_host_header(&["APP.test:443".into()], "app.test", 443)
            .is_ok());
        assert!(
            c.check_host_header(&[], "app.test", 443).is_ok(),
            "HTTP/1.0: no Host"
        );
        // Another in-scope target on the same address is fine; an unlisted vhost is not.
        assert!(c
            .check_host_header(&["10.0.0.5:8080".into()], "app.test", 443)
            .is_ok());
        let r = c
            .check_host_header(&["admin.internal".into()], "app.test", 443)
            .unwrap_err();
        assert_eq!(r.kind, ProxyEventKind::RefusedOutOfScope);
        assert!(c
            .check_host_header(&["app.test".into(), "evil.test".into()], "app.test", 443)
            .is_err());
        // An egress host is never testable, even by Host header.
        assert!(c
            .check_host_header(&["crates.io:443".into()], "app.test", 443)
            .is_err());
    }

    #[test]
    fn authorities_split() {
        assert_eq!(split_authority("a.test:443"), Some(("a.test".into(), 443)));
        assert_eq!(split_authority("[::1]:80"), Some(("::1".into(), 80)));
        assert_eq!(split_authority("a.test"), None);
    }
}
