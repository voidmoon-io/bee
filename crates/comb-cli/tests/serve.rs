//! `comb serve` end to end, driven the way another harness drives it: JSON lines in, JSON lines
//! out, against a local target. Covers a tool call, a client routed through the proxy with a
//! per-call credential, an out-of-scope refusal, history over both, and the offline reader.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{json, Value};

/// A target that answers every request `200 hello` and closes.
fn target() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = s.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                );
            });
        }
    });
    port
}

struct Serve {
    child: Child,
    stdin: ChildStdin,
    out: mpsc::Receiver<Value>,
    next: u64,
}

impl Serve {
    fn start(project: &std::path::Path, policy: &std::path::Path) -> (Serve, Value) {
        let mut child = Command::new(env!("CARGO_BIN_EXE_comb"))
            .args(["serve", "--policy"])
            .arg(policy)
            .arg("--project")
            .arg(project)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, out) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { return };
                let v: Value = serde_json::from_str(&line).expect("every stdout line is JSON");
                if tx.send(v).is_err() {
                    return;
                }
            }
        });
        let mut s = Serve {
            child,
            stdin,
            out,
            next: 1,
        };
        let ready = s.until(|v| v["event"] == "ready");
        (s, ready)
    }

    fn until(&mut self, pred: impl Fn(&Value) -> bool) -> Value {
        loop {
            let v = self
                .out
                .recv_timeout(Duration::from_secs(20))
                .expect("comb serve answered in time");
            if pred(&v) {
                return v;
            }
        }
    }

    fn request(&mut self, mut req: Value) -> Value {
        let id = self.next;
        self.next += 1;
        req["id"] = json!(id);
        writeln!(self.stdin, "{req}").unwrap();
        self.stdin.flush().unwrap();
        self.until(|v| v["id"] == json!(id))
    }

    fn call(&mut self, tool: &str, args: Value) -> Value {
        self.request(json!({ "op": "call", "tool": tool, "args": args }))
    }
}

fn b64(s: &str) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let b = s.as_bytes();
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// `call_id` and `token` out of `http://<call_id>:<token>@127.0.0.1:<port>`.
fn userinfo(url: &str) -> (String, String) {
    let rest = url.strip_prefix("http://").unwrap();
    let (ui, _) = rest.split_once('@').unwrap();
    let (u, p) = ui.split_once(':').unwrap();
    (u.to_string(), p.to_string())
}

#[test]
fn serve_end_to_end() {
    let port = target();
    let dir = tempfile::tempdir().unwrap();
    let policy = dir.path().join("policy.toml");
    std::fs::write(
        &policy,
        format!(
            "[policy]\nname = \"comb-test\"\n[policy.http]\ntargets = [\"127.0.0.1:{port}\"]\n"
        ),
    )
    .unwrap();
    let (mut s, ready) = Serve::start(dir.path(), &policy);
    assert_eq!(ready["enforcement"], "advisory", "{ready}");
    let proxy_port = ready["port"].as_u64().unwrap();

    // The tool list is bee's.
    let tools = s.request(json!({ "op": "tools" }));
    let names: Vec<&str> = tools["result"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"http_send") && names.contains(&"http_history"),
        "{names:?}"
    );

    // A tool call reaches the target and is recorded.
    let sent = s.call(
        "http_send",
        json!({ "request": { "url": format!("http://127.0.0.1:{port}/a") } }),
    );
    assert_eq!(sent["ok"], true, "{sent}");
    let body: Value = serde_json::from_str(sent["result"]["text"].as_str().unwrap()).unwrap();
    assert_eq!(body["status"], 200, "{body}");
    assert_eq!(body["enforcement"], "advisory");
    assert!(sent["result"]["source"]
        .as_str()
        .unwrap()
        .starts_with("http:"));

    // An out-of-scope target is refused, not sent.
    let refused = s.call(
        "http_send",
        json!({ "request": { "url": "http://127.0.0.1:1/" } }),
    );
    assert_eq!(refused["ok"], false, "{refused}");
    assert_eq!(refused["error"]["code"], "refused", "{refused}");

    // A client's own traffic, routed through the proxy with a per-call credential.
    let cred = s.request(json!({ "op": "credential", "call_id": "client-1" }));
    assert_eq!(cred["ok"], true, "{cred}");
    let url = cred["result"]["proxy_url"].as_str().unwrap().to_string();
    assert_eq!(cred["result"]["env"]["HTTP_PROXY"], url);
    let (user, token) = userinfo(&url);
    let mut c = TcpStream::connect(("127.0.0.1", proxy_port as u16)).unwrap();
    write!(
        c,
        "GET http://127.0.0.1:{port}/b HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nProxy-Authorization: Basic {}\r\nConnection: close\r\n\r\n",
        b64(&format!("{user}:{token}"))
    )
    .unwrap();
    let mut resp = String::new();
    c.read_to_string(&mut resp).unwrap();
    assert!(
        resp.starts_with("HTTP/1.1 200") && resp.ends_with("hello"),
        "{resp}"
    );

    // Without a credential the proxy answers 407 and sends nothing.
    let mut c = TcpStream::connect(("127.0.0.1", proxy_port as u16)).unwrap();
    write!(
        c,
        "GET http://127.0.0.1:{port}/c HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut resp = String::new();
    c.read_to_string(&mut resp).unwrap();
    assert!(resp.starts_with("HTTP/1.1 407"), "{resp}");

    let revoked = s.request(json!({ "op": "revoke", "call_id": "client-1" }));
    assert_eq!(revoked["ok"], true, "{revoked}");

    // History holds both: the tool's send and the forwarded request, attributed to its call.
    let hist = s.call("http_history", json!({ "order": "oldest" }));
    let h: Value = serde_json::from_str(hist["result"]["text"].as_str().unwrap()).unwrap();
    let rows = h["rows"].as_array().unwrap();
    assert!(
        rows.iter()
            .any(|r| r["path"] == "/a" && r["origin"] == "tool"),
        "{h}"
    );
    assert!(
        rows.iter()
            .any(|r| r["path"] == "/b" && r["origin"] == "forwarded" && r["call_id"] == "client-1"),
        "{h}"
    );

    let bye = s.request(json!({ "op": "shutdown" }));
    assert_eq!(bye["ok"], true);
    drop(s.stdin);
    let status = s.child.wait().unwrap();
    assert!(status.success(), "{status}");

    // The store outlives the session: the offline reader sees the same exchanges.
    let out = Command::new(env!("CARGO_BIN_EXE_comb"))
        .args(["history", "--project"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let h: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(h["total_matched"].as_u64().unwrap() >= 2, "{h}");
}
