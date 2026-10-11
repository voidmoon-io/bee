//! 019-http-intercept T021 — `[policy.http]`: schema, compile errors, derived enforcement
//! (contracts/policy-http.md).
//!
//! The kernel half of every guarantee here is the VM tier (`http-*` cases in
//! `test/vm/remote-matrix.sh`); this file pins what the compiler hands the kernel.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

use bee_common::AccessMode;
use bee_core::compiler::{with_proxy_loopback, CompiledHttp, EnforcedBy, Role};
use bee_core::policy::HostPort;
use bee_core::{CompileError, CompiledNet, ExecIdentity, FsPrimitive, Policy, Resolver};

/// A resolver with fixed answers, so no test touches DNS.
struct Stub {
    root: String,
    home: String,
}

impl Stub {
    fn new() -> Self {
        Stub {
            root: "/home/u/proj".into(),
            home: "/home/u".into(),
        }
    }
}

impl Resolver for Stub {
    fn project_root(&self) -> &str {
        &self.root
    }
    fn home(&self) -> &str {
        &self.home
    }
    fn resolve_exec(&self, name: &str) -> Result<PathBuf, CompileError> {
        Ok(PathBuf::from(format!("/usr/bin/{name}")))
    }
    fn resolve_exec_identity(&self, _: &Path) -> Result<ExecIdentity, CompileError> {
        Ok(ExecIdentity { ino: 1, dev: 1 })
    }
    fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, CompileError> {
        match host {
            "app.test" => Ok(vec!["10.0.0.7".parse().unwrap()]),
            "api.app.test" => Ok(vec!["10.0.0.8".parse().unwrap()]),
            "index.crates.io" => Ok(vec![
                "192.0.2.1".parse().unwrap(),
                "192.0.2.2".parse().unwrap(),
            ]),
            h => h
                .parse::<IpAddr>()
                .map(|a| vec![a])
                .map_err(|_| CompileError::UnresolvableHost(h.into(), "no such host".into())),
        }
    }
}

const WORKER: &str = "/opt/bee/bin/bee";

/// The contracts/policy-http.md example, verbatim.
const EXAMPLE: &str = r#"
[policy]
name = "pentest-app"
mode = "enforce"

[policy.filesystem]
":project_root" = "read"

[policy.exec]
allow = ["curl", "sh"]

[policy.http]
targets = ["app.test:443", "app.test:80", "10.20.0.5:8080"]
egress  = ["index.crates.io:443"]
inspect = ["app.test"]
insecure_upstream = []

[policy.http.limits]
rps = 10
concurrency = 4
max_requests_per_run = 2000
max_body_bytes = 16777216
store_cap_bytes = 2147483648
"#;

fn compile(toml: &str) -> Result<CompiledHttp, CompileError> {
    let p = Policy::from_toml(toml).expect("parses");
    Ok(p.compile_http(&Stub::new(), Path::new(WORKER))?
        .expect("[policy.http] present"))
}

fn with_http(body: &str) -> String {
    format!("[policy]\nname = \"t\"\n[policy.http]\n{body}\n")
}

#[test]
fn the_contract_example_parses_with_its_values() {
    let p = Policy::from_toml(EXAMPLE).expect("example parses");
    let http = p.http.as_ref().expect("http section");
    assert_eq!(http.targets.len(), 3);
    assert_eq!(
        http.targets[2],
        HostPort {
            host: "10.20.0.5".into(),
            port: 8080
        }
    );
    assert_eq!(http.egress[0].host, "index.crates.io");
    assert_eq!(http.inspect[0].to_string(), "app.test");
    assert_eq!(http.limits.rps, 10);
    assert_eq!(http.limits.store_cap_bytes, 2_147_483_648);
}

#[test]
fn limits_default_when_omitted() {
    let p = Policy::from_toml(&with_http("targets = [\"app.test:443\"]")).unwrap();
    let l = &p.http.unwrap().limits;
    assert_eq!(
        (l.rps, l.concurrency, l.max_requests_per_run),
        (10, 4, 2000)
    );
    assert_eq!(l.max_body_bytes, 16 * 1024 * 1024);
    assert_eq!(l.store_cap_bytes, 2 * 1024 * 1024 * 1024);
}

// ── compile errors (contract table) ─────────────────────────────────────────────────────────────

#[test]
fn an_unknown_key_is_refused_naming_it() {
    for body in [
        "targets = [\"app.test:443\"]\ntargets_typo = []",
        "targets = [\"app.test:443\"]\n[policy.http.limits]\nrsp = 5",
    ] {
        let err = Policy::from_toml(&with_http(body)).expect_err("unknown key refused");
        let msg = err.to_string();
        assert!(
            msg.contains("unknown field") && (msg.contains("targets_typo") || msg.contains("rsp")),
            "{msg}"
        );
    }
}

#[test]
fn targets_with_a_direct_network_allowlist_is_refused() {
    let toml = "[policy]\nname = \"t\"\n[policy.network]\nallow = [\"1.1.1.1:443\"]\n\
                [policy.http]\ntargets = [\"app.test:443\"]\n";
    assert!(matches!(
        compile(toml),
        Err(CompileError::HttpWithDirectNetwork(..))
    ));
}

#[test]
fn an_inspect_pattern_matching_no_target_is_refused() {
    let toml = with_http("targets = [\"app.test:443\"]\ninspect = [\"other.test\"]");
    assert!(matches!(
        compile(&toml),
        Err(CompileError::InspectOutsideTargets(p)) if p == "other.test"
    ));
}

#[test]
fn insecure_upstream_outside_inspect_is_refused() {
    let toml = with_http(
        "targets = [\"app.test:443\"]\ninspect = [\"app.test\"]\ninsecure_upstream = [\"*.app.test\"]",
    );
    assert!(matches!(
        compile(&toml),
        Err(CompileError::InsecureOutsideInspect(..))
    ));
}

#[test]
fn a_host_in_both_roles_is_refused() {
    let toml = with_http("targets = [\"app.test:443\"]\negress = [\"APP.test.:80\"]");
    assert!(matches!(
        compile(&toml),
        Err(CompileError::HostRoleConflict(h)) if h == "app.test"
    ));
}

#[test]
fn an_unresolvable_host_is_refused() {
    let toml = with_http("targets = [\"nowhere.invalid:443\"]");
    assert!(matches!(
        compile(&toml),
        Err(CompileError::UnresolvableHost(..))
    ));
}

#[test]
fn a_zero_limit_is_refused() {
    for field in [
        "rps",
        "concurrency",
        "max_requests_per_run",
        "max_body_bytes",
        "store_cap_bytes",
    ] {
        let toml = with_http(&format!(
            "targets = [\"app.test:443\"]\n[policy.http.limits]\n{field} = 0"
        ));
        assert!(
            matches!(compile(&toml), Err(CompileError::ZeroLimit(f)) if f == field),
            "{field}"
        );
    }
}

#[test]
fn a_malformed_host_port_is_refused_at_parse() {
    // `fe80::1` is an unbracketed IPv6 literal that once parsed as host `fe80:` port 1.
    for bad in [
        "app.test",
        "app.test:http",
        ":443",
        "app.test:70000",
        "fe80::1",
        "::1:443",
    ] {
        let toml = with_http(&format!("targets = [\"{bad}\"]"));
        assert!(Policy::from_toml(&toml).is_err(), "{bad} accepted");
    }
    let ok = HostPort::try_from("[fe80::1]:443".to_string()).unwrap();
    assert_eq!((ok.host.as_str(), ok.port), ("fe80::1", 443));
}

// ── derived enforcement ──────────────────────────────────────────────────────────────────────────

#[test]
fn the_proxy_scope_reaches_exactly_the_resolved_targets_and_egress() {
    let c = compile(EXAMPLE).unwrap();
    let mut got: Vec<(IpAddr, u16)> = c.proxy_scope.net.iter().map(|n| (n.addr, n.port)).collect();
    got.sort();
    let mut want: Vec<(IpAddr, u16)> = vec![
        ("10.0.0.7".parse().unwrap(), 443),
        ("10.0.0.7".parse().unwrap(), 80),
        ("10.20.0.5".parse().unwrap(), 8080),
        ("192.0.2.1".parse().unwrap(), 443),
        ("192.0.2.2".parse().unwrap(), 443),
    ];
    want.sort();
    assert_eq!(got, want);
}

#[test]
fn the_tool_scope_reaches_only_the_proxy() {
    let p = Policy::from_toml(EXAMPLE).unwrap();
    let tool = p.compile(&Stub::new()).unwrap();
    assert!(
        tool.proxy_loopback_required,
        "a tool policy with [policy.http] is not installable until the loopback rule is applied"
    );
    let tool = with_proxy_loopback(tool, 41234);
    assert_eq!(
        tool.net,
        vec![CompiledNet {
            addr: "127.0.0.1".parse().unwrap(),
            port: 41234
        }]
    );
    assert!(!tool.proxy_loopback_required);
}

#[test]
fn every_scope_entry_names_both_enforcement_layers() {
    let c = compile(EXAMPLE).unwrap();
    for e in c.http_scope.targets.iter().chain(&c.http_scope.egress) {
        assert!(
            e.enforced_by
                .iter()
                .any(|l| matches!(l, EnforcedBy::Kernel { .. })),
            "{e:?}"
        );
        assert!(
            e.enforced_by
                .iter()
                .any(|l| matches!(l, EnforcedBy::Proxy { host } if *host == e.host)),
            "{e:?}"
        );
        // One kernel rule per resolved address.
        let kernel = e
            .enforced_by
            .iter()
            .filter(|l| matches!(l, EnforcedBy::Kernel { .. }))
            .count();
        assert_eq!(kernel, e.resolved.len());
    }
    assert!(c.http_scope.targets.iter().all(|e| e.role == Role::Target));
    assert!(c.http_scope.egress.iter().all(|e| e.role == Role::Egress));
}

/// research R2: the proxy scope's filesystem. The kernel file model is a deny list, so this is a
/// *reduced* read surface — project, home and credential paths denied — plus write-default-deny and
/// an exact read rule for the worker binary, which the prefix denies would otherwise block from exec.
#[test]
fn the_proxy_scope_filesystem_denies_project_home_and_credentials() {
    let c = compile(EXAMPLE).unwrap();
    let fs = &c.proxy_scope.fs;
    // Covered by a deny prefix — the compiler drops a deny already beneath another, so `/home/u/proj`
    // and `/home/u` fold into `/home` here (and spend no rule of the kernel's budget).
    let deny = |p: &str| {
        fs.iter().any(|r| {
            matches!(r, FsPrimitive::Prefix { path, mode, .. }
                if mode.is_deny()
                    && (p.as_bytes() == path.as_slice()
                        || (p.as_bytes().starts_with(path) && p.as_bytes()[path.len()] == b'/')))
        })
    };
    for p in ["/home/u/proj", "/home/u", "/home/u/.ssh", "/home", "/root"] {
        assert!(deny(p), "{p} not denied: {fs:?}");
    }
    assert!(fs.iter().any(|r| matches!(r,
        FsPrimitive::Prefix { path, mode, .. }
            if path == WORKER.as_bytes() && *mode == AccessMode::READ)));
    assert!(c.proxy_scope.fs_write_default_deny);
    assert_eq!(c.proxy_scope.exec.len(), 1);
    assert_eq!(c.proxy_scope.exec[0].path, WORKER.as_bytes());
    // It fits the kernel's rule budget with room to spare.
    assert!(
        fs.len() <= bee_common::layout::DENY_MAX_RULES,
        "{}",
        fs.len()
    );
}

/// A worker binary under a denied prefix — a dev build in `target/` under the project, or the VM
/// matrix binary in `/home/ubuntu` — still gets its exact read rule.
#[test]
fn a_worker_binary_under_a_denied_prefix_keeps_its_read_rule() {
    for exe in ["/home/u/proj/target/debug/bee", "/home/ubuntu/bee"] {
        let p = Policy::from_toml(EXAMPLE).unwrap();
        let c = p
            .compile_http(&Stub::new(), Path::new(exe))
            .unwrap()
            .unwrap();
        assert!(
            c.proxy_scope.fs.iter().any(|r| matches!(r,
                FsPrimitive::Prefix { path, mode, .. }
                    if path == exe.as_bytes() && *mode == AccessMode::READ)),
            "{exe}"
        );
    }
}

/// A project and home outside `/home` keep their own deny rules.
#[test]
fn a_project_outside_home_is_denied_by_its_own_rule() {
    struct Elsewhere(Stub);
    impl Resolver for Elsewhere {
        fn project_root(&self) -> &str {
            "/srv/work/app"
        }
        fn home(&self) -> &str {
            "/var/lib/agent"
        }
        fn resolve_exec(&self, n: &str) -> Result<PathBuf, CompileError> {
            self.0.resolve_exec(n)
        }
        fn resolve_exec_identity(&self, p: &Path) -> Result<ExecIdentity, CompileError> {
            self.0.resolve_exec_identity(p)
        }
        fn resolve_host(&self, h: &str) -> Result<Vec<IpAddr>, CompileError> {
            self.0.resolve_host(h)
        }
    }
    let p = Policy::from_toml(EXAMPLE).unwrap();
    let c = p
        .compile_http(&Elsewhere(Stub::new()), Path::new(WORKER))
        .unwrap()
        .unwrap();
    for want in ["/srv/work/app", "/var/lib/agent", "/home", "/root"] {
        assert!(
            c.proxy_scope.fs.iter().any(|r| matches!(r,
                FsPrimitive::Prefix { path, mode, .. } if path == want.as_bytes() && mode.is_deny())),
            "{want}"
        );
    }
    assert!(c.proxy_scope.fs.len() <= bee_common::layout::DENY_MAX_RULES);
}

#[test]
fn a_policy_without_http_compiles_no_proxy_scope() {
    let p = Policy::from_toml("[policy]\nname = \"t\"\n").unwrap();
    assert!(p
        .compile_http(&Stub::new(), Path::new(WORKER))
        .unwrap()
        .is_none());
    assert!(!p.compile(&Stub::new()).unwrap().proxy_loopback_required);
}

// ── `bee validate` ───────────────────────────────────────────────────────────────────────────────

fn validate(body: &str) -> std::process::Output {
    let dir = std::env::temp_dir().join(format!(
        "bee-http-validate-{}-{}",
        std::process::id(),
        body.len()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("p.toml");
    std::fs::write(&path, body).unwrap();
    Command::new(env!("CARGO_BIN_EXE_bee"))
        .args(["validate", "--policy"])
        .arg(&path)
        .output()
        .unwrap()
}

#[test]
fn validate_refuses_a_typo_naming_the_field() {
    let out = validate(&with_http(
        "targets = [\"127.0.0.1:8080\"]\ninpsect = [\"x\"]",
    ));
    assert_eq!(out.status.code(), Some(64));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("inpsect"), "{stderr}");
}

#[test]
fn validate_accepts_a_runnable_http_policy() {
    let out = validate(&with_http("targets = [\"127.0.0.1:8080\"]"));
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn validate_reports_an_http_compile_error() {
    let out = validate(&with_http(
        "targets = [\"127.0.0.1:8080\"]\negress = [\"127.0.0.1:9090\"]",
    ));
    assert_eq!(out.status.code(), Some(64));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("127.0.0.1"), "{stderr}");
}
