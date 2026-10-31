//! Operator configuration for the security tooling (016-native-tools).
//!
//! Deliberately **ungated**: it is plain data with no dependencies, and a configuration file must
//! keep parsing across builds. If this section only existed when `--features sec` was compiled in, a
//! config naming a scanner would be a hard error on a slim build — punishing the operator for the
//! build's shape rather than telling them the tool is absent, which is the tool's job to say
//! (`NotCompiledIn`, spec Edge Case "the build was slimmed down").
//!
//! ## Why the ruleset lives here and the grant does not
//!
//! Running an external scanner takes two decisions, and they belong to different documents:
//!
//! * **May this episode execute this binary?** That is a capability. It lives in policy, as an
//!   inode-pinned `ExecPolicy.allow` entry, and it goes through the ordinary derive/ceiling
//!   attenuation path like every other capability (FR-008, Constitution II).
//! * **What should the granted binary do?** That is configuration. Which rules, how long to run. It
//!   grants nothing on its own — without the policy entry above, none of it can execute — so
//!   admitting it to policy would widen the security surface for something that confers no
//!   authority (Constitution IV).
//!
//! What is absent from both is any way for the *model* to influence either one. It chooses what to
//! scan; never how the scanner is configured (FR-007).

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The `[security]` table.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// Override the finding ledger's location.
    ///
    /// Exists for the case where the analysed project is read-only in policy (research open
    /// question 2). The ledger is bee's own record — the same category as the episode transcript —
    /// so when the project cannot hold it, it moves rather than forcing the project writable. When
    /// neither location can be written, recording **fails**: a finding that could not be persisted
    /// is never reported as recorded (Constitution I).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub findings_dir: Option<PathBuf>,
    /// Per-scanner configuration, keyed by adapter name (`opengrep`, `codeql`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub scanners: BTreeMap<String, ScannerConfig>,
    /// Operator-fixed commands for controlled reproduction. No profile is enabled by default.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub reproductions: BTreeMap<String, ReproductionProfile>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReproductionProfile {
    pub program: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
    pub timeout_secs: u64,
    pub max_repetitions: u32,
}

impl SecurityConfig {
    /// This scanner's configuration, or the empty default. An unconfigured scanner is not an error
    /// here — the adapter decides whether it can run without one (Opengrep cannot; it needs a local
    /// ruleset, and says so).
    pub fn scanner(&self, name: &str) -> ScannerConfig {
        self.scanners.get(name).cloned().unwrap_or_default()
    }
}

/// One external scanner's operator-set configuration.
///
/// Note what is absent: no argv, no extra flags, no binary path. The path and its inode pin come
/// from the policy grant; the target comes from the model. There is nothing here that composes into
/// a command line (contract `scanner-adapter.md`).
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ScannerConfig {
    /// A local ruleset path. Required for Opengrep, which refuses `--config auto`: `auto` fetches
    /// the rule registry over the network, and a scanning scope has no egress (research R6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<PathBuf>,
    /// Wall-clock budget for one scan. Exceeding it is a `Failed` — never a partial `Completed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
    /// A provisioned analysis bundle (CodeQL, US6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<PathBuf>,
    /// The bundle version the operator pinned, verified before use (FR-011).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_version: Option<String>,
}

/// The default wall-clock budget for one scan, when the operator sets none.
pub const DEFAULT_SCAN_TIMEOUT_SECS: u64 = 300;

impl ScannerConfig {
    pub fn timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.timeout_secs.unwrap_or(DEFAULT_SCAN_TIMEOUT_SECS))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scanner_table_parses_by_name() {
        let cfg: SecurityConfig = toml::from_str(
            r#"
findings_dir = "/var/lib/bee/findings"
[scanners.opengrep]
rules = "/etc/bee/rules"
timeout_secs = 60
"#,
        )
        .unwrap();
        assert_eq!(
            cfg.findings_dir.as_deref(),
            Some(std::path::Path::new("/var/lib/bee/findings"))
        );
        let og = cfg.scanner("opengrep");
        assert_eq!(
            og.rules.as_deref(),
            Some(std::path::Path::new("/etc/bee/rules"))
        );
        assert_eq!(og.timeout().as_secs(), 60);
    }

    #[test]
    fn an_unconfigured_scanner_yields_the_default_not_an_error() {
        let cfg = SecurityConfig::default();
        assert_eq!(cfg.scanner("opengrep"), ScannerConfig::default());
        assert_eq!(
            cfg.scanner("opengrep").timeout().as_secs(),
            DEFAULT_SCAN_TIMEOUT_SECS
        );
    }

    #[test]
    fn a_mistyped_key_is_refused_rather_than_ignored() {
        // `deny_unknown_fields` throughout: a security setting that silently does nothing is the
        // worst outcome for a file that governs what a granted binary does.
        let err = toml::from_str::<SecurityConfig>("[scanners.opengrep]\nrulez = \"/etc\"\n");
        assert!(err.is_err());
    }
}
