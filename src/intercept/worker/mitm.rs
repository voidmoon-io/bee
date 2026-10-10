//! TLS inspection for hosts in `inspect` (019 US4, research R7).
//!
//! A **per-session CA** is generated in worker memory at start — only when `inspect` is non-empty —
//! with a one-day validity. Its private key is never serialised: only the CA *certificate* leaves the
//! worker, in `hello` (SC-008; rcgen's `zeroize` wipes the key on drop). Leaf certificates are minted
//! per host on first use and cached for the session. The client side offers ALPN `http/1.1` only;
//! the upstream side verifies against webpki roots unless the host is in `insecure_upstream`, which is
//! recorded on every exchange.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;

/// The session CA and its leaf cache.
pub struct SessionCa {
    issuer: Issuer<'static, KeyPair>,
    cert_pem: String,
    cert_der: Vec<u8>,
    leaves: Mutex<HashMap<String, Arc<CertifiedKey>>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl SessionCa {
    pub fn generate() -> Result<SessionCa, String> {
        let key = KeyPair::generate().map_err(|e| format!("CA key: {e}"))?;
        let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
        params
            .distinguished_name
            .push(DnType::CommonName, "bee interception session CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(1);
        let cert = params
            .self_signed(&key)
            .map_err(|e| format!("CA cert: {e}"))?;
        Ok(SessionCa {
            cert_pem: cert.pem(),
            cert_der: cert.der().to_vec(),
            issuer: Issuer::new(params, key),
            leaves: Mutex::new(HashMap::new()),
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        })
    }

    /// The CA certificate, PEM. Certificate only — never the key.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// A leaf for `host` (DNS name or IP literal), minted once and cached.
    pub fn leaf(&self, host: &str) -> Result<Arc<CertifiedKey>, String> {
        let key = bee_core::pattern::normalize_host(host);
        if let Some(l) = self.leaves.lock().expect("leaf cache").get(&key) {
            return Ok(l.clone());
        }
        let leaf_key = KeyPair::generate().map_err(|e| format!("leaf key: {e}"))?;
        let mut params =
            CertificateParams::new(vec![key.clone()]).map_err(|e| format!("leaf params: {e}"))?;
        params
            .distinguished_name
            .push(DnType::CommonName, key.clone());
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(1);
        let cert = params
            .signed_by(&leaf_key, &self.issuer)
            .map_err(|e| format!("leaf cert: {e}"))?;
        let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let signing = self
            .provider
            .key_provider
            .load_private_key(der)
            .map_err(|e| format!("leaf key load: {e}"))?;
        let certified = Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(cert.der().to_vec())],
            signing,
        ));
        self.leaves
            .lock()
            .expect("leaf cache")
            .insert(key, certified.clone());
        Ok(certified)
    }

    /// A server config presenting the leaf for `host`, ALPN `http/1.1` only (HTTP/2 is out of scope).
    pub fn server_config(&self, host: &str) -> Result<Arc<rustls::ServerConfig>, String> {
        let leaf = self.leaf(host)?;
        let mut cfg = rustls::ServerConfig::builder_with_provider(self.provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Fixed(leaf)));
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(cfg))
    }
}

#[derive(Debug)]
struct Fixed(Arc<CertifiedKey>);

impl rustls::server::ResolvesServerCert for Fixed {
    fn resolve(&self, _hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ca_certificate_carries_no_key() {
        let ca = SessionCa::generate().unwrap();
        assert!(ca.cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(!ca.cert_pem().contains("PRIVATE KEY"));
    }

    #[test]
    fn leaves_are_cached_per_host() {
        let ca = SessionCa::generate().unwrap();
        let a = ca.leaf("App.Test.").unwrap();
        let b = ca.leaf("app.test").unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        let ip = ca.leaf("127.0.0.1").unwrap();
        assert!(!Arc::ptr_eq(&a, &ip));
    }
}
