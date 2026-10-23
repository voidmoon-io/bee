//! 019-http-intercept T029 — the `.bee/http/` store (contracts/store.md).

#![cfg(feature = "intercept")]

use bee::intercept::control::{
    now_rfc3339, ExchangeRecord, Origin, OriginKind, Outcome, ProxyEvent, ProxyEventKind, SendPath,
    Timing, TlsInfo, TunnelRecord,
};
use bee::intercept::store::{ExchangeBytes, Store, StoreError, SCHEMA_VERSION};
use bee_core::policy::HttpLimits;

fn limits() -> HttpLimits {
    HttpLimits::default()
}

fn rec(target: &str, status: u16) -> ExchangeRecord {
    ExchangeRecord {
        req_id: None,
        call_id: Some("toolu_1".into()),
        turn: Some(1),
        origin: Origin {
            kind: OriginKind::Tool,
            path: SendPath::Raw,
            parent: None,
            fuzz_run: None,
            rule_ids: vec![],
        },
        scheme: "http".into(),
        host: "app.test".into(),
        port: 80,
        method: Some("GET".into()),
        target: Some(target.into()),
        status: Some(status),
        tls: TlsInfo::None,
        timing: Timing {
            started: now_rfc3339(),
            connect_ms: Some(1),
            ttfb_ms: Some(2),
            total_ms: Some(3),
        },
        req_bytes: 0,
        resp_bytes: 0,
        req_truncated: false,
        resp_truncated: false,
        has_original: false,
        outcome: Outcome::Completed,
        tags: vec![],
    }
}

fn bytes(body: &[u8]) -> ExchangeBytes {
    ExchangeBytes {
        req_head: b"GET / HTTP/1.1\r\nHost: app.test\r\n\r\n".to_vec(),
        req_body: Vec::new(),
        resp_head: b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n".to_vec(),
        resp_body: body.to_vec(),
        original: None,
    }
}

fn project() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

#[test]
fn schema_v1_is_created_with_a_private_directory() {
    let dir = project();
    let store = Store::open(dir.path(), "sess-a", &limits()).unwrap();
    assert_eq!(store.schema_version().unwrap(), SCHEMA_VERSION);
    assert_eq!(SCHEMA_VERSION, 1);
    let http = dir.path().join(".bee/http");
    assert!(http.join("index.sqlite").exists());
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&http).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "{mode:o}");
}

#[test]
fn an_exchange_round_trips_with_its_bodies() {
    let dir = project();
    let mut store = Store::open(dir.path(), "sess-a", &limits()).unwrap();
    let id = store
        .insert_exchange(&rec("/a?x=1", 200), &bytes(b"abc"))
        .unwrap();
    assert!(id.starts_with('E') && id.contains('-'), "{id}");

    let got = store.get_exchange(&id).unwrap().expect("stored");
    assert_eq!(got.status, Some(200));
    assert_eq!(got.target.as_deref(), Some("/a?x=1"));
    assert_eq!(got.path.as_deref(), Some("/a"));
    assert_eq!(got.call_id.as_deref(), Some("toolu_1"));
    assert_eq!(got.req_head, bytes(b"").req_head);
    let body = store.read_blob(got.resp_body.as_ref().unwrap()).unwrap();
    assert_eq!(body.as_deref(), Some(&b"abc"[..]));
}

#[test]
fn ids_increase_within_a_session() {
    let dir = project();
    let mut store = Store::open(dir.path(), "sess-a", &limits()).unwrap();
    let a = store
        .insert_exchange(&rec("/1", 200), &bytes(b"1"))
        .unwrap();
    let b = store
        .insert_exchange(&rec("/2", 200), &bytes(b"2"))
        .unwrap();
    let seq = |id: &str| id.rsplit('-').next().unwrap().parse::<u64>().unwrap();
    assert!(seq(&b) > seq(&a));
    // A second session in the same project never collides.
    let mut other = Store::open(dir.path(), "sess-b", &limits()).unwrap();
    let c = other
        .insert_exchange(&rec("/1", 200), &bytes(b"1"))
        .unwrap();
    assert_ne!(a, c);
}

#[test]
fn identical_bodies_share_one_blob_file() {
    let dir = project();
    let mut store = Store::open(dir.path(), "sess-a", &limits()).unwrap();
    let a = store
        .insert_exchange(&rec("/1", 200), &bytes(b"same body"))
        .unwrap();
    let b = store
        .insert_exchange(&rec("/2", 200), &bytes(b"same body"))
        .unwrap();
    let ea = store.get_exchange(&a).unwrap().unwrap();
    let eb = store.get_exchange(&b).unwrap().unwrap();
    assert_eq!(ea.resp_body, eb.resp_body);
    let mut files = 0;
    for shard in std::fs::read_dir(dir.path().join(".bee/http/blobs")).unwrap() {
        files += std::fs::read_dir(shard.unwrap().path()).unwrap().count();
    }
    // One for the shared response body (empty request bodies store no blob).
    assert_eq!(files, 1);
}

#[test]
fn two_writers_lose_nothing() {
    let dir = project();
    let root = dir.path().to_path_buf();
    let mut handles = Vec::new();
    for s in ["sess-1", "sess-2"] {
        let root = root.clone();
        handles.push(std::thread::spawn(move || {
            let mut store = Store::open(&root, s, &HttpLimits::default()).unwrap();
            for i in 0..50 {
                store
                    .insert_exchange(
                        &rec(&format!("/{i}"), 200),
                        &bytes(format!("{s}-{i}").as_bytes()),
                    )
                    .unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let store = Store::open(&root, "reader", &limits()).unwrap();
    assert_eq!(store.count_exchanges().unwrap(), 100);
}

#[test]
fn a_newer_schema_opens_read_only() {
    let dir = project();
    {
        let store = Store::open(dir.path(), "sess-a", &limits()).unwrap();
        store.force_schema_version_for_test(99).unwrap();
    }
    let mut store = Store::open(dir.path(), "sess-b", &limits()).unwrap();
    assert!(store.is_read_only());
    assert!(matches!(
        store.insert_exchange(&rec("/x", 200), &bytes(b"x")),
        Err(StoreError::ReadOnly { found: 99 })
    ));
}

#[test]
fn eviction_removes_the_oldest_blobs_and_keeps_the_rows() {
    let dir = project();
    let cap = 1000u64;
    let lim = HttpLimits {
        store_cap_bytes: cap,
        ..HttpLimits::default()
    };
    let mut store = Store::open(dir.path(), "sess-a", &lim).unwrap();
    let mut ids = Vec::new();
    let mut summaries = Vec::new();
    for i in 0..10 {
        let body = vec![b'a' + i as u8; 300];
        ids.push(
            store
                .insert_exchange(&rec(&format!("/{i}"), 200), &bytes(&body))
                .unwrap(),
        );
        if let Some(s) = store.take_eviction_summary() {
            summaries.push(s);
        }
    }
    assert!(!summaries.is_empty(), "eviction is never silent");
    assert!(store.blob_bytes().unwrap() <= cap * 9 / 10 + 300);
    // The oldest body is gone, the newest survives, every row remains.
    let oldest = store.get_exchange(&ids[0]).unwrap().unwrap();
    assert!(oldest.resp_body_evicted);
    assert_eq!(
        store.read_blob(oldest.resp_body.as_ref().unwrap()).unwrap(),
        None
    );
    let newest = store.get_exchange(ids.last().unwrap()).unwrap().unwrap();
    assert!(!newest.resp_body_evicted);
    assert_eq!(store.count_exchanges().unwrap(), 10);
}

#[test]
fn an_oversize_body_is_stored_truncated_and_flagged() {
    let dir = project();
    let lim = HttpLimits {
        max_body_bytes: 16,
        ..HttpLimits::default()
    };
    let mut store = Store::open(dir.path(), "sess-a", &lim).unwrap();
    let id = store
        .insert_exchange(&rec("/big", 200), &bytes(&[b'z'; 100]))
        .unwrap();
    let e = store.get_exchange(&id).unwrap().unwrap();
    assert!(e.resp_body_truncated);
    let body = store
        .read_blob(e.resp_body.as_ref().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(body.len(), 16);
}

#[test]
fn tunnels_and_refusals_are_recorded() {
    let dir = project();
    let mut store = Store::open(dir.path(), "sess-a", &limits()).unwrap();
    let t = store
        .insert_tunnel(&TunnelRecord {
            call_id: Some("c".into()),
            host: "crates.io".into(),
            port: 443,
            sni: Some("crates.io".into()),
            started: now_rfc3339(),
            ended: now_rfc3339(),
            bytes_up: 10,
            bytes_down: 20,
            outcome: "closed".into(),
        })
        .unwrap();
    assert!(t.starts_with('T'));
    store
        .insert_refusal(&ProxyEvent {
            ts: now_rfc3339(),
            session_id: "sess-a".into(),
            call_id: None,
            layer: "proxy".into(),
            kind: ProxyEventKind::RefusedOutOfScope,
            host: "evil.test".into(),
            port: 80,
            detail: serde_json::Value::Null,
        })
        .unwrap();
    assert_eq!(store.count_refusals().unwrap(), 1);
}
