//! The external scanner tier (016-native-tools US3).
//!
//! An adapter wraps a third-party scanner whose value is its **rule corpus**, not its engine
//! (research R2). bee does not reimplement corpora, and — the load-bearing half — it does not hand
//! the model a command line either.
//!
//! ## Two authorities, deliberately separated
//!
//! | Question | Answered by | Why there |
//! |---|---|---|
//! | May this episode execute this binary? | the policy's `ExecPolicy.allow` | it is a capability, so it goes through the ordinary derive/ceiling attenuation path (FR-008) |
//! | How is the binary configured? | `[security.scanners.<name>]` | it confers no authority on its own; putting it in policy would widen the policy surface for nothing (Constitution IV) |
//! | What gets scanned? | the model, via [`ScanRequest`] | the one decision the model is well placed to make |
//!
//! [`ScanRequest`] has three fields and none of them is free-form: no `extra_args`, no
//! `config_inline`, no passthrough of any kind. This is the discipline [`crate::search`] already
//! states for ripgrep, generalised — *there is nothing here that runs another program* except the
//! one the operator pinned.
//!
//! ## The pin is checked twice, and the second time is the one that counts
//!
//! A grant records the binary's identity when it is resolved. [`ScannerAdapter::probe`] re-reads it
//! **immediately before spawning**, so a binary swapped between grant issuance and run yields
//! [`UnavailableReason::PinMismatch`] and is never executed (FR-009, SC-010). In an `enforce` build
//! the kernel holds the same pin; in a host build this check is the only one, which is exactly why
//! it lives at the tool layer rather than being left to the LSM.

pub mod codeql;
pub mod opengrep;

use std::path::{Path, PathBuf};
use std::time::Duration;

use bee_core::Policy;

use crate::security::SecurityConfig;
use crate::tools::outcome::UnavailableReason;

/// What kind of report a scanner writes. Both current adapters write SARIF; the enum exists so a
/// future adapter with another format cannot be silently mis-parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportKind {
    Sarif,
}

/// A binary's identity at a moment in time: the device and inode it resolved to.
///
/// Cheap, and sufficient for what it has to catch — a binary replaced at the same path between the
/// grant and the spawn. It is not a content hash and does not try to be: the kernel's pin is the
/// authoritative check under enforcement, and a hash would mean reading the whole binary on every
/// call to close a window this already closes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InodePin {
    pub dev: u64,
    pub ino: u64,
}

impl InodePin {
    /// Read the identity of the file at `path`, or `None` if it is not there.
    pub fn read(path: &Path) -> Option<InodePin> {
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::metadata(path).ok()?;
        Some(InodePin {
            dev: md.dev(),
            ino: md.ino(),
        })
    }
}

/// An operator's authorisation for one episode to run one external analysis binary.
#[derive(Debug, Clone)]
pub struct ScannerGrant {
    /// Adapter name — `opengrep`, `codeql`.
    pub name: String,
    /// Absolute path to the granted binary, as the policy named it.
    pub path: PathBuf,
    /// The binary's identity when the grant was resolved. `None` means it was already absent then,
    /// which `probe` reports as [`UnavailableReason::BinaryMissing`].
    pub pin: Option<InodePin>,
    /// Operator-provided local ruleset. Never `auto` (research R6).
    pub rules: Option<PathBuf>,
    /// A provisioned bundle and its pinned version (CodeQL, US6).
    pub bundle: Option<PathBuf>,
    pub bundle_version: Option<String>,
    /// The operator's wall-clock budget for one scan.
    pub timeout: Duration,
}

impl ScannerGrant {
    /// A grant for tests, with the pin read from whatever is at `path` right now.
    pub fn for_test(name: &str, path: PathBuf, rules: Option<PathBuf>) -> ScannerGrant {
        ScannerGrant {
            pin: InodePin::read(&path),
            name: name.to_string(),
            path,
            rules,
            bundle: None,
            bundle_version: None,
            timeout: Duration::from_secs(crate::security::DEFAULT_SCAN_TIMEOUT_SECS),
        }
    }
}

/// A scan the model asked for. Note what is absent — see the module note.
#[derive(Debug, Clone)]
pub struct ScanRequest {
    /// Directory or file to scan.
    pub target: PathBuf,
    /// Language hint, where the scanner needs one.
    pub lang: Option<String>,
    /// Wall-clock budget. Exceeded ⇒ `Failed`, never a partial `Completed`.
    pub timeout: Duration,
}

impl ScanRequest {
    pub fn new(target: PathBuf) -> ScanRequest {
        ScanRequest {
            target,
            lang: None,
            timeout: Duration::from_secs(crate::security::DEFAULT_SCAN_TIMEOUT_SECS),
        }
    }
}

/// One external scanner bee knows how to drive.
///
/// A scan is up to three phases, and an adapter opts into as much of that as it needs. Opengrep
/// uses one; CodeQL uses all three, which is why the shape is not simply "one argv" (US6).
///
/// ```text
///   probe()      no process at all — pin, provisioning, and whether this request is even answerable
///   preflight()  one child whose stdout verify_preflight() reads — a version pin, checked in scope
///   steps()      the scan itself, in order; every step must exit 0 before the next one runs
/// ```
pub trait ScannerAdapter: Send + Sync {
    /// Stable name, used in policy grants and in `FindingSource::Scanner(name)`.
    fn name(&self) -> &'static str;

    /// Can this scanner answer *this request* right now? Existence, pin, provisioned artefacts, and
    /// whether the thing being asked for is something this adapter will do at all. Runs **before**
    /// argv construction, so unavailability is reported without spawning anything.
    ///
    /// It takes the request because availability is not purely a property of the installation: a
    /// CodeQL bundle that is present, pinned, and correct still cannot analyse a language whose
    /// extraction requires observing a build (FR-011).
    fn probe(&self, grant: &ScannerGrant, req: &ScanRequest) -> Result<(), UnavailableReason>;

    /// A child to run before the scan, whose stdout [`ScannerAdapter::verify_preflight`] reads.
    /// `None` — the default — means there is nothing to ask the binary before using it.
    ///
    /// This exists because some facts can only be had by asking the tool, and asking it is running
    /// it: the tool is spawned in scope like any other child rather than probed from the harness
    /// (Constitution III).
    fn preflight(&self, _grant: &ScannerGrant) -> Option<Vec<String>> {
        None
    }

    /// Judge what [`ScannerAdapter::preflight`] printed. An `Err` here stops the scan before its
    /// first step, so a failed check is an unavailability and never a scan that found nothing.
    fn verify_preflight(
        &self,
        _grant: &ScannerGrant,
        _stdout: &str,
    ) -> Result<(), UnavailableReason> {
        Ok(())
    }

    /// Build the scan's children from typed, validated inputs. The **only** place argv is authored.
    /// Returns an error — never a partially-built command — if any input fails validation.
    ///
    /// `scratch` is a per-call directory inside the scope, created before this is called and removed
    /// afterwards; an adapter that needs somewhere to put intermediate state puts it there. `out` is
    /// where the last step must leave its report.
    fn steps(
        &self,
        grant: &ScannerGrant,
        req: &ScanRequest,
        scratch: &Path,
        out: &Path,
    ) -> Result<Vec<Vec<String>>, String>;

    /// Where this scanner writes its report.
    fn report_kind(&self) -> ReportKind {
        ReportKind::Sarif
    }
}

/// The adapter for `name`, or `None` if bee has none.
pub fn adapter_for(name: &str) -> Option<&'static dyn ScannerAdapter> {
    match name {
        "opengrep" => Some(&opengrep::Opengrep),
        "codeql" => Some(&codeql::CodeQl),
        _ => None,
    }
}

/// Every adapter bee ships. Used to decide which `exec.allow` entries are scanner grants.
pub const KNOWN_SCANNERS: &[&str] = &["opengrep", "codeql"];

/// The shared existence-and-pin check every adapter's `probe` delegates to.
pub fn probe_binary(grant: &ScannerGrant) -> Result<(), UnavailableReason> {
    let current = InodePin::read(&grant.path);
    match (grant.pin, current) {
        // Gone since the grant was resolved, or never there.
        (_, None) => Err(UnavailableReason::BinaryMissing {
            path: grant.path.clone(),
        }),
        (None, Some(_)) => {
            // Absent when the grant was resolved and present now: something changed under us, and
            // there is no recorded identity to compare against. That is the swap case with the
            // evidence missing, so it refuses (Constitution I).
            Err(UnavailableReason::PinMismatch {
                path: grant.path.clone(),
            })
        }
        (Some(pinned), Some(now)) if pinned != now => Err(UnavailableReason::PinMismatch {
            path: grant.path.clone(),
        }),
        (Some(_), Some(_)) => Ok(()),
    }
}

/// Resolve the episode's scanner grants from its policy and the operator's configuration.
///
/// A policy entry becomes a grant only when **all** of these hold:
///
/// * it names a binary whose file name matches an adapter bee ships;
/// * it is **inode-pinned** (`!`-prefixed).
///
/// The pin requirement is stricter than the policy language demands, and deliberately so. An
/// unpinned entry authorises the *path*, so a binary swapped at that path still runs — which is the
/// scenario SC-010 exists to forbid. For an ordinary tool that is the operator's call to make; for a
/// third-party analysis binary running over the code bee is meant to be securing, it is not a trade
/// worth offering. An unpinned entry yields no grant, and the tool says `NotGranted` rather than
/// running something whose identity it cannot vouch for.
///
/// Discovery of a binary on `PATH` confers nothing: this function reads policy, never the filesystem
/// search path (FR-008).
pub fn grants_from_policy(policy: Option<&Policy>, security: &SecurityConfig) -> Vec<ScannerGrant> {
    let Some(policy) = policy else {
        return Vec::new();
    };

    let mut grants = Vec::new();
    for entry in &policy.exec.allow {
        let Some(path) = entry.strip_prefix('!') else {
            continue; // unpinned — see the note above
        };
        let path = PathBuf::from(path);
        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(name) = KNOWN_SCANNERS.iter().find(|s| **s == file_name) else {
            continue;
        };

        let cfg = security.scanner(name);
        grants.push(ScannerGrant {
            pin: InodePin::read(&path),
            name: (*name).to_string(),
            path,
            rules: cfg.rules.clone(),
            bundle: cfg.bundle.clone(),
            bundle_version: cfg.bundle_version.clone(),
            timeout: cfg.timeout(),
        });
    }
    grants
}

/// Validate that `target` is a sane thing to hand a scanner.
///
/// Two refusals, both about the model's one free input. A path that begins with `-` would be read by
/// the scanner as a flag, which is how a "what to scan" field turns into a "how to run" field; and a
/// path with no filesystem presence is refused before a process is spawned to discover the same
/// thing more slowly. Whether the target is *readable* is the kernel's decision, not this function's
/// — the LSM answers that when the child opens it (Constitution III).
pub fn validate_target(target: &Path) -> Result<(), String> {
    let s = target.to_string_lossy();
    if s.is_empty() {
        return Err("target is empty".to_string());
    }
    if s.starts_with('-') {
        return Err(format!(
            "target `{s}` begins with `-` and would be read as a flag; refusing to build the command"
        ));
    }
    if !target.exists() {
        return Err(format!("target `{s}` does not exist"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, "#!/bin/sh\n").unwrap();
        p
    }

    fn policy_with(allow: Vec<String>) -> Policy {
        Policy {
            name: "t".into(),
            description: None,
            mode: Default::default(),
            filesystem: Default::default(),
            exec: bee_core::ExecPolicy { allow },
            network: Default::default(),
            defaults: Default::default(),
            exfiltration: Default::default(),
            http: None,
        }
    }

    #[test]
    fn only_pinned_entries_naming_a_known_scanner_become_grants() {
        let tmp = tempfile::tempdir().unwrap();
        let og = touch(tmp.path(), "opengrep");
        let cat = touch(tmp.path(), "cat");

        let grants = grants_from_policy(
            Some(&policy_with(vec![
                format!("!{}", og.display()),
                format!("!{}", cat.display()), // pinned, but not a scanner
                og.display().to_string(),      // a scanner, but unpinned
            ])),
            &SecurityConfig::default(),
        );
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].name, "opengrep");
    }

    #[test]
    fn a_binary_swapped_after_the_grant_fails_the_probe() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = touch(tmp.path(), "opengrep");
        let grant = ScannerGrant::for_test("opengrep", bin.clone(), None);
        assert!(probe_binary(&grant).is_ok());

        // Replace the file — same path, new inode. This is the TOCTOU the pin exists to catch.
        //
        // Via rename, not remove-then-write: the filesystem readily hands the *same* inode back to
        // an immediate recreate, which would leave the pin matching and quietly turn this into a
        // test of nothing.
        let replacement = tmp.path().join("replacement");
        std::fs::write(&replacement, "#!/bin/sh\necho pwned\n").unwrap();
        std::fs::rename(&replacement, &bin).unwrap();
        assert_ne!(
            InodePin::read(&bin),
            grant.pin,
            "the swap must change the inode"
        );
        assert!(matches!(
            probe_binary(&grant),
            Err(UnavailableReason::PinMismatch { .. })
        ));
    }

    #[test]
    fn a_removed_binary_reports_absence_not_a_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = touch(tmp.path(), "opengrep");
        let grant = ScannerGrant::for_test("opengrep", bin.clone(), None);
        std::fs::remove_file(&bin).unwrap();
        assert!(matches!(
            probe_binary(&grant),
            Err(UnavailableReason::BinaryMissing { .. })
        ));
    }

    #[test]
    fn a_binary_that_appeared_after_an_empty_grant_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("opengrep");
        let grant = ScannerGrant::for_test("opengrep", path.clone(), None);
        assert!(grant.pin.is_none());
        std::fs::write(&path, "#!/bin/sh\n").unwrap();
        assert!(matches!(
            probe_binary(&grant),
            Err(UnavailableReason::PinMismatch { .. })
        ));
    }

    #[test]
    fn a_target_that_is_really_a_flag_is_refused() {
        assert!(validate_target(Path::new("--config=auto")).is_err());
        assert!(validate_target(Path::new("-e")).is_err());
        assert!(validate_target(Path::new("")).is_err());
    }

    #[test]
    fn configuration_reaches_the_grant() {
        let tmp = tempfile::tempdir().unwrap();
        let og = touch(tmp.path(), "opengrep");
        let mut security = SecurityConfig::default();
        security.scanners.insert(
            "opengrep".into(),
            crate::security::ScannerConfig {
                rules: Some("/etc/rules".into()),
                timeout_secs: Some(7),
                ..Default::default()
            },
        );
        let grants = grants_from_policy(
            Some(&policy_with(vec![format!("!{}", og.display())])),
            &security,
        );
        assert_eq!(grants[0].rules.as_deref(), Some(Path::new("/etc/rules")));
        assert_eq!(grants[0].timeout.as_secs(), 7);
    }
}
