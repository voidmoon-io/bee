//! Audit event types (FR-007). `AuditEvent` is the JSON-serializable user-space view of a kernel
//! [`bee_common::AuditRecord`], matching `contracts/audit-event.schema.json`.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use bee_common::{AuditRecord, Decision, Op};

/// A structured record of a denied (or would-be-denied) operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// ISO-8601 / RFC-3339 wall-clock time.
    pub ts: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_id: Option<String>,
    pub cgroup_id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executor_cgroup_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tgid: Option<u32>,
    pub op: String,
    pub decision: String,
    pub errno: i32,
    pub target: String,
}

fn op_str(op: u8) -> &'static str {
    match op {
        x if x == Op::FileOpen as u8 => "file_open",
        x if x == Op::Exec as u8 => "exec",
        x if x == Op::Connect as u8 => "connect",
        x if x == Op::Exfil as u8 => "exfil",
        _ => "unknown",
    }
}

fn decision_str(d: u8) -> &'static str {
    match d {
        x if x == Decision::Denied as u8 => "denied",
        x if x == Decision::Observed as u8 => "observed",
        _ => "unknown",
    }
}

/// Size of the binary destination a connect record carries (019 P5): `family: u16 LE`,
/// `port: u16 BE`, then the 16-byte address laid out exactly like `NetKey.addr` — IPv4 in the first
/// four bytes with the remaining twelve zero, IPv6 in all sixteen.
pub const CONNECT_TARGET_LEN: usize = 20;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// Format a connect record's binary destination as `ip:port` (`[v6]:port` for IPv6).
///
/// An empty target — a record from an eBPF object older than P5 — formats as `""`, which
/// [`crate`] consumers already treat as "destination unknown". Anything else that is not exactly the
/// documented encoding formats as `<malformed>` rather than as a plausible-looking address: a wrong
/// destination in an audit record is worse than an admittedly missing one, because a grant built from
/// it would widen the scope to the wrong place.
fn format_connect_target(t: &[u8]) -> String {
    if t.is_empty() {
        return String::new();
    }
    if t.len() != CONNECT_TARGET_LEN {
        return "<malformed>".into();
    }
    let family = u16::from_le_bytes([t[0], t[1]]);
    let port = u16::from_be_bytes([t[2], t[3]]);
    let addr = &t[4..20];
    match family {
        AF_INET if addr[4..].iter().all(|b| *b == 0) => {
            let ip = std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
            format!("{ip}:{port}")
        }
        AF_INET6 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(addr);
            format!("[{}]:{port}", std::net::Ipv6Addr::from(a))
        }
        _ => "<malformed>".into(),
    }
}

impl AuditEvent {
    /// Build an event from a kernel record. `ts` is the wall-clock time the user-space consumer maps
    /// the record's monotonic `ts_ns` to (the monotonic→wall conversion is a loader concern).
    pub fn from_record(rec: &AuditRecord, scope_id: Option<String>, ts: OffsetDateTime) -> Self {
        let len = (rec.target_len as usize).min(rec.target.len());
        let target = if rec.op == Op::Connect as u8 {
            format_connect_target(&rec.target[..len])
        } else {
            String::from_utf8_lossy(&rec.target[..len]).into_owned()
        };
        AuditEvent {
            ts: ts
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string()),
            scope_id,
            cgroup_id: rec.cgroup_id,
            executor_cgroup_id: Some(rec.executor_cgroup_id),
            pid: Some(rec.pid),
            tgid: Some(rec.tgid),
            op: op_str(rec.op).to_string(),
            decision: decision_str(rec.decision).to_string(),
            errno: rec.errno,
            target,
        }
    }

    /// Serialize to a single JSON line.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("AuditEvent is always serializable")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec() -> AuditRecord {
        let mut target = [0u8; bee_common::TARGET_MAX];
        let s = b"/home/jg/.ssh/id_rsa";
        target[..s.len()].copy_from_slice(s);
        AuditRecord {
            executor_cgroup_id: 0,
            ts_ns: 0,
            cgroup_id: 74213,
            pid: 40122,
            tgid: 40122,
            op: Op::FileOpen as u8,
            decision: Decision::Denied as u8,
            _pad: [0; 2],
            errno: -13,
            target_len: s.len() as u16,
            _pad2: [0; 6],
            target,
        }
    }

    #[test]
    fn maps_record_to_json() {
        let ev = AuditEvent::from_record(
            &rec(),
            Some("cargo-test-1a2b".into()),
            OffsetDateTime::UNIX_EPOCH,
        );
        assert_eq!(ev.op, "file_open");
        assert_eq!(ev.decision, "denied");
        assert_eq!(ev.errno, -13);
        assert_eq!(ev.target, "/home/jg/.ssh/id_rsa");
        assert_eq!(ev.cgroup_id, 74213);
        let json = ev.to_json();
        assert!(json.contains("\"op\":\"file_open\""));
        assert!(json.contains("\"target\":\"/home/jg/.ssh/id_rsa\""));
    }

    // ── 019 P5: a kernel connect denial names its destination (FR-009, research R13) ─────────────

    /// A connect record carrying the 20-byte binary destination the eBPF hook writes:
    /// `family: u16 LE`, `port: u16 BE`, `addr: [u8; 16]` laid out like `NetKey.addr`.
    fn connect_rec(family: u16, port: u16, addr: [u8; 16], target_len: u16) -> AuditRecord {
        let mut r = rec();
        r.op = Op::Connect as u8;
        r.target = [0u8; bee_common::TARGET_MAX];
        r.target[0..2].copy_from_slice(&family.to_le_bytes());
        r.target[2..4].copy_from_slice(&port.to_be_bytes());
        r.target[4..20].copy_from_slice(&addr);
        r.target_len = target_len;
        r
    }

    fn v4(a: [u8; 4]) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..4].copy_from_slice(&a);
        out
    }

    fn target_of(r: &AuditRecord) -> String {
        AuditEvent::from_record(r, None, OffsetDateTime::UNIX_EPOCH).target
    }

    #[test]
    fn a_v4_connect_formats_as_ip_port() {
        assert_eq!(
            target_of(&connect_rec(2, 443, v4([10, 0, 0, 5]), 20)),
            "10.0.0.5:443"
        );
    }

    #[test]
    fn a_v4_connect_with_trailing_bytes_is_malformed() {
        let mut addr = v4([10, 0, 0, 5]);
        addr[15] = 1;
        assert_eq!(target_of(&connect_rec(2, 443, addr, 20)), "<malformed>");
    }

    #[test]
    fn a_v6_connect_formats_bracketed() {
        let ip: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            target_of(&connect_rec(10, 443, ip.octets(), 20)),
            "[2001:db8::1]:443"
        );
    }

    #[test]
    fn a_connect_without_a_target_formats_empty() {
        // Records from an eBPF object older than P5 carry no destination.
        let mut r = rec();
        r.op = Op::Connect as u8;
        r.target_len = 0;
        assert_eq!(target_of(&r), "");
    }

    #[test]
    fn a_connect_target_of_the_wrong_size_or_family_is_malformed() {
        assert_eq!(
            target_of(&connect_rec(2, 443, v4([1, 2, 3, 4]), 19)),
            "<malformed>"
        );
        assert_eq!(
            target_of(&connect_rec(1, 443, v4([1, 2, 3, 4]), 20)),
            "<malformed>"
        );
    }

    #[test]
    fn a_file_record_is_unchanged() {
        assert_eq!(target_of(&rec()), "/home/jg/.ssh/id_rsa");
    }
}
