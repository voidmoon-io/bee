use super::*;
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
};

fn environment(name: &str) -> Option<String> {
    match name {
        "BEE_DECISION_JEV_ENABLED" | "BEE_DECISION_CLEF_ENABLED" => Some("1".into()),
        "TYPESAFE_API_KEY" | "CLOUDFLARE_API_TOKEN" => Some("test-credential".into()),
        "CLOUDFLARE_ACCOUNT_ID" => Some("0123456789abcdef0123456789abcdef".into()),
        _ => None,
    }
}

fn request(backend: Backend) -> Value {
    json!({"backend":backend,"state":{"evidence":"a fixture"},"questions":{
        "relevant":{"type":"noul","instructions":"Is it relevant?"},
        "route":{"type":"choice","instructions":"Which route?","criteria":{"read":"Read more","test":"Test it"}},
        "quality":{"type":"score","instructions":"Quality?","criteria":["weak","strong"]}
    }})
}

fn answer() -> Value {
    json!({"model":"fixture-model","answers":{
        "relevant":{"type":"noul","noul":0.7},
        "route":{"type":"choice","choice":"read","confidence":0.8,"probabilities":{"read":0.8,"test":0.2}},
        "quality":{"type":"score","score":0.9,"confidence":0.8,"probabilities":{"0":0.1,"1":0.9},"legend":{"0":"weak","1":"strong"}}
    },"usage":{"input_tokens":100,"output_tokens":0}})
}

#[test]
fn official_endpoints_and_operator_models() {
    let jev = configured(Backend::Jev, &environment).unwrap();
    assert_eq!(jev.url, "https://api.typesafe.ai/v1/systemone");
    assert_eq!(jev.model, "jev-latest");
    for model in ["clef", "clef-flash"] {
        let cf = configured(Backend::Clef, &|name| {
            if name == "BEE_DECISION_CLEF_MODEL" {
                Some(model.into())
            } else {
                environment(name)
            }
        })
        .unwrap();
        assert_eq!(cf.model, model);
        assert_eq!(cf.url, format!("https://api.cloudflare.com/client/v4/accounts/0123456789abcdef0123456789abcdef/ai/run/@cf/cloudflare/{model}"));
    }
}

#[test]
fn credentials_alone_do_not_enable_a_backend() {
    for backend in [Backend::Jev, Backend::Clef] {
        assert!(configured(backend, &|name| if name.ends_with("ENABLED") {
            None
        } else {
            environment(name)
        })
        .is_err());
    }
    for (key, value) in [
        ("CLOUDFLARE_ACCOUNT_ID", "../elsewhere"),
        ("BEE_DECISION_CLEF_MODEL", "https://other"),
        ("CLOUDFLARE_API_TOKEN", "secret\r\nheader: injected"),
    ] {
        let error = configured(Backend::Clef, &|name| {
            if name == key {
                Some(value.into())
            } else {
                environment(name)
            }
        })
        .err()
        .unwrap();
        assert!(!error.contains(value));
    }
}

#[test]
fn malformed_requests_fail_before_network() {
    let mut cases = Vec::new();
    let mut v = request(Backend::Jev);
    v["url"] = json!("https://other");
    cases.push(v);
    let mut v = request(Backend::Jev);
    v["model"] = json!("other");
    cases.push(v);
    let mut v = request(Backend::Jev);
    v["state"] = Value::Null;
    cases.push(v);
    let mut v = request(Backend::Jev);
    v["questions"] = json!({});
    cases.push(v);
    let mut v = request(Backend::Jev);
    v["questions"]["quality"]["criteria"] = json!(["only"]);
    cases.push(v);
    let mut v = request(Backend::Jev);
    v["state"] = json!("x".repeat(MAX_REQUEST));
    cases.push(v);
    for v in cases {
        assert!(Args::parse(v).is_err());
    }
}

#[test]
fn both_wire_formats_preserve_decisions_and_usage() {
    for backend in [Backend::Jev, Backend::Clef] {
        let args = Args::parse(request(backend)).unwrap();
        let raw = answer();
        let wire = if backend == Backend::Clef {
            json!({"success":true,"result":raw})
        } else {
            raw.clone()
        };
        let result = normalize(&args, wire).unwrap();
        assert_eq!(result["answers"], raw["answers"]);
        assert_eq!(result["model"], raw["model"]);
        assert_eq!(result["usage"], raw["usage"]);
    }
}

#[test]
fn mismatched_or_invalid_answers_are_refused() {
    let args = Args::parse(request(Backend::Jev)).unwrap();
    let mut cases = Vec::new();
    let mut v = answer();
    v["answers"]["relevant"]["noul"] = json!(1.1);
    cases.push(v);
    let mut v = answer();
    v["answers"]["route"]["choice"] = json!("unknown");
    cases.push(v);
    let mut v = answer();
    v["answers"]["route"]["probabilities"] = json!({"read":0.1,"test":0.1});
    cases.push(v);
    let mut v = answer();
    v["answers"].as_object_mut().unwrap().remove("quality");
    cases.push(v);
    let mut v = answer();
    v["answers"]["quality"]["score"] = json!(2.0);
    cases.push(v);
    let mut v = answer();
    v["usage"]["input_tokens"] = json!(-1);
    cases.push(v);
    for v in cases {
        assert!(normalize(&args, v).is_err());
    }
    let cf = Args::parse(request(Backend::Clef)).unwrap();
    assert!(normalize(&cf, json!({"success":false,"result":answer()})).is_err());
}

// Only tests can replace an endpoint. The server reads exactly one bounded request.
fn server(status: &str, body: String, extra_headers: &str) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/decision", listener.local_addr().unwrap());
    let response = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/json\r\n{extra_headers}Connection: close\r\n\r\n{body}",body.len());
    let task = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut bytes = Vec::new();
        loop {
            let mut chunk = [0; 4096];
            let n = socket.read(&mut chunk).unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&chunk[..n]);
            assert!(bytes.len() < MAX_REQUEST + 8192);
            if let Some(pos) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&bytes[..pos]).to_lowercase();
                let length: usize = headers
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                if bytes.len() >= pos + 4 + length {
                    break;
                }
            }
        }
        let _ = socket.write_all(response.as_bytes());
        String::from_utf8(bytes).unwrap()
    });
    (url, task)
}

#[tokio::test]
async fn sends_authenticated_json_and_returns_remote_tool_result() {
    for backend in [Backend::Jev, Backend::Clef] {
        let wire = if backend == Backend::Clef {
            json!({"success":true,"result":answer()})
        } else {
            answer()
        };
        let (url, task) = server("200 OK", wire.to_string(), "");
        let mut tool = DecisionTool::configure(environment);
        let endpoint = if backend == Backend::Jev {
            &mut tool.jev
        } else {
            &mut tool.clef
        };
        endpoint.as_mut().unwrap().url = url;
        let mut registry = crate::tools::ToolRegistry::new();
        registry.insert(Box::new(tool));
        let call = crate::provider::ToolCall {
            id: "decision-fixture".into(),
            name: "decision_evaluate".into(),
            arguments: request(backend),
        };
        let outcome = crate::call::run_call(
            crate::call::CallInput {
                call: &call,
                turn: 0,
                origin: crate::sandbox::CallOrigin::Tool,
                timeout: crate::call::TimeoutPolicy::PerCall(Duration::from_secs(5)),
            },
            &mut Sandbox::host(Vec::new()),
            &mut registry,
            None,
        )
        .await;
        assert!(!outcome.retried);
        let result = outcome.result;
        assert!(!result.is_error, "{}", result.content);
        assert!(matches!(result.provenance, Provenance::Remote { .. }));
        assert!(!result.content.contains("test-credential"));
        let sent = task.join().unwrap();
        assert!(sent
            .to_lowercase()
            .contains("authorization: bearer test-credential"));
        let body: Value = serde_json::from_str(sent.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(body["questions"], request(backend)["questions"]);
        assert!(body.get("backend").is_none());
        assert_eq!(
            body["model"],
            if backend == Backend::Jev {
                "jev-latest"
            } else {
                "clef-flash"
            }
        );
    }
}

#[tokio::test]
async fn refuses_redirects_http_errors_and_oversized_responses_without_echoing_body() {
    for (status, body, headers) in [
        (
            "302 Found",
            "secret-body".into(),
            "Location: http://127.0.0.1:1/steal\r\n",
        ),
        ("429 Too Many Requests", "secret-body".into(), ""),
        ("200 OK", "x".repeat(MAX_RESPONSE + 1), ""),
        ("200 OK", "secret-body".into(), ""),
    ] {
        let (url, task) = server(status, body, headers);
        let mut tool = DecisionTool::configure(environment);
        tool.jev.as_mut().unwrap().url = url;
        let result = tool
            .call(request(Backend::Jev), &Sandbox::host(Vec::new()))
            .await;
        assert!(result.is_error);
        assert!(!result.content.contains("secret-body"));
        if status.starts_with("302") {
            assert!(result.content.contains("302"));
        }
        if status.starts_with("429") {
            assert!(result.content.contains("429"));
        }
        task.join().unwrap();
    }
}

#[tokio::test]
async fn disabled_backend_is_a_clear_tool_error() {
    let result = DecisionTool::configure(|_| None)
        .call(request(Backend::Jev), &Sandbox::host(Vec::new()))
        .await;
    assert!(result.is_error);
    assert!(result.content.contains("BEE_DECISION_JEV_ENABLED"));
    assert_eq!(
        DecisionTool::configure(|_| None)
            .durable_contract()
            .recovery,
        crate::session::durable::RecoveryPolicy::NeverReplay
    );
}

#[tokio::test]
async fn main_model_receives_the_decision_and_continues() {
    use crate::provider::{mock_model::MockModel, Message, ToolCall, Turn};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let (url, task) = server("200 OK", answer().to_string(), "");
    let mut tool = DecisionTool::configure(environment);
    tool.jev.as_mut().unwrap().url = url;
    let mut registry = crate::tools::ToolRegistry::new();
    registry.insert(Box::new(tool));
    let received = Arc::new(AtomicBool::new(false));
    let observed = received.clone();
    let model = MockModel::from_fn(move |conversation| {
        if let Some(Message::ToolResult {
            content,
            is_error,
            provenance,
            ..
        }) = conversation.messages.last()
        {
            assert!(!is_error, "{content}");
            let result: Value = serde_json::from_str(content).unwrap();
            assert_eq!(result["answers"]["route"]["choice"], "read");
            assert!(matches!(provenance, Provenance::Remote { .. }));
            observed.store(true, Ordering::SeqCst);
            Turn::text("I will read more evidence.")
        } else {
            Turn::calls(vec![ToolCall {
                id: "decision".into(),
                name: "decision_evaluate".into(),
                arguments: request(Backend::Jev),
            }])
        }
    });
    let scenario = serde_json::from_value(json!({
        "id":"decision-round-trip", "policy_path":"/dev/null", "system_prompt":"test", "task":"assess evidence",
        "turn_limit":3, "timeout_secs":5, "finish":false, "tools":["decision_evaluate"]
    })).unwrap();
    let transcript = crate::episode::run_loop(
        &model,
        &scenario,
        &mut registry,
        &mut Sandbox::host(Vec::new()),
        &crate::episode::LoopOptions::default(),
    )
    .await;
    assert!(received.load(Ordering::SeqCst));
    assert!(serde_json::to_string(&transcript)
        .unwrap()
        .contains("fixture-model"));
    task.join().unwrap();
}
