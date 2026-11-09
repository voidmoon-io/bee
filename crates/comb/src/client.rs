//! What a client of the proxy needs: the proxy URL carrying a per-call credential, the environment
//! that routes a child through it, and the CA bundle that lets it trust inspected hosts (019 R6, R7).
//!
//! A credential is minted by [`crate::sidecar::Interceptor::issue`] at the start of a call and revoked
//! at its end, so one leaked into a file or a transcript cannot be replayed. The variables are only
//! the route: a child can unset them, which is why containment needs a boundary outside the proxy
//! (bee's kernel scope, or the host's).

use std::path::Path;

/// The variables a credentialed child receives.
pub const PROXY_VARS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
];

/// TLS trust variables, set when the session decrypts anything (US4).
pub const CA_VARS: &[&str] = &[
    "SSL_CERT_FILE",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "GIT_SSL_CAINFO",
];

/// The proxy URL for a call: `http://<call_id>:<token>@127.0.0.1:<port>`, or without userinfo when
/// there is no live credential — its traffic is then refused with a `407`, never sent elsewhere.
pub fn proxy_url(port: u16, credential: Option<(&str, &str)>) -> String {
    match credential {
        Some((call_id, token)) => format!(
            "http://{}:{token}@127.0.0.1:{port}",
            userinfo_escape(call_id)
        ),
        None => format!("http://127.0.0.1:{port}"),
    }
}

/// The environment a child gets: every proxy variable set to `url`, `NO_PROXY` empty, and the CA
/// variables pointing at `ca_bundle` when there is one.
pub fn child_env(url: &str, ca_bundle: Option<&Path>) -> Vec<(String, String)> {
    let mut vars: Vec<(String, String)> = PROXY_VARS
        .iter()
        .map(|k| (k.to_string(), url.to_string()))
        .collect();
    vars.push(("NO_PROXY".into(), String::new()));
    vars.push(("no_proxy".into(), String::new()));
    if let Some(b) = ca_bundle {
        let p = b.display().to_string();
        vars.extend(CA_VARS.iter().map(|k| (k.to_string(), p.clone())));
    }
    vars
}

/// System roots plus the session CA. The roots matter: tunnelled hosts present their real
/// certificates, and a bundle of the session CA alone would break every one of them (research R7).
pub fn write_ca_bundle(path: &Path, ca_pem: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let system = [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/cert.pem",
    ]
    .iter()
    .find_map(|p| std::fs::read_to_string(p).ok())
    .unwrap_or_default();
    let tmp = path.with_extension("pem.tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&tmp)
        .map_err(|e| format!("CA bundle {}: {e}", tmp.display()))?;
    f.write_all(system.as_bytes())
        .and_then(|_| {
            if !system.is_empty() && !system.ends_with('\n') {
                f.write_all(b"\n")?;
            }
            f.write_all(ca_pem.as_bytes())
        })
        .map_err(|e| format!("CA bundle: {e}"))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("CA bundle: {e}"))
}

/// Percent-escape what URL userinfo cannot carry raw. Provider call ids are `[A-Za-z0-9_-]`, but
/// nothing guarantees it, and a `@` or `:` would split the URL in the wrong place.
pub fn userinfo_escape(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn userinfo_is_escaped() {
        assert_eq!(userinfo_escape("toolu_01AbC-x"), "toolu_01AbC-x");
        assert_eq!(userinfo_escape("a:b@c"), "a%3Ab%40c");
        assert_eq!(userinfo_escape("mcp:fs"), "mcp%3Afs");
    }
}
