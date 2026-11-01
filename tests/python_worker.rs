//! Exercise the shipping worker protocol, including a fresh process for every continuation.
use bee::python::{execute, Request, Response};
use serde_json::json;

async fn request(request: Request) -> Response {
    execute(request, &bee::Sandbox::host(vec![])).await.unwrap()
}

#[tokio::test]
async fn continuation_preserves_locals_and_exact_integer_inputs() {
    let source = "first = call_tool('one', {'n': inputs['n']})\nsecond = call_tool('two', {'n': first['n'] + 1})\n[inputs['n'], second['n']]";
    let Response::Call {
        name,
        arguments,
        snapshot,
    } = request(Request::Start {
        source: source.into(),
        inputs: json!({"n": u64::MAX}),
        visual: false,
    })
    .await
    else {
        panic!("expected first call")
    };
    assert_eq!(name, "one");
    assert_eq!(arguments, json!({"n": u64::MAX}));
    let Response::Call {
        name,
        arguments,
        snapshot,
    } = request(Request::Resume {
        snapshot,
        result: json!({"n": 20}),
    })
    .await
    else {
        panic!("expected second call")
    };
    assert_eq!(name, "two");
    assert_eq!(arguments, json!({"n": 21}));
    let Response::Complete { value } = request(Request::Resume {
        snapshot,
        result: json!({"n": 42}),
    })
    .await
    else {
        panic!("expected completion")
    };
    assert_eq!(value, json!([u64::MAX, 42]));
}

#[tokio::test]
async fn visual_scripts_cannot_access_host_or_dispatch_tools() {
    for source in [
        "open('/etc/passwd').read()",
        "from pathlib import Path\nPath('/etc/passwd').read_text()",
        "import os\nos.getenv('HOME')",
        "import time\ntime.sleep(10)",
        "call_tool('bash', {'command': 'id'})",
    ] {
        let response = request(Request::Start {
            source: source.into(),
            inputs: json!({}),
            visual: true,
        })
        .await;
        assert!(
            matches!(response, Response::Error { .. }),
            "{source}: {response:?}"
        );
    }
}

#[tokio::test]
async fn malformed_snapshots_and_out_of_range_integers_fail_closed() {
    for request_value in [
        Request::Resume {
            snapshot: vec![255; 32],
            result: json!(null),
        },
        Request::Start {
            source: "2 ** 100".into(),
            inputs: json!({}),
            visual: false,
        },
    ] {
        assert!(matches!(
            request(request_value).await,
            Response::Error { .. }
        ));
    }
}

#[tokio::test]
async fn forged_visual_output_is_validated_by_rust() {
    for source in [
        "w = grid(1, 1)\nw.data['rows'] = 100\nrender(w)",
        "w = sprite(1, 1, palette())\nw.data['spec']['pixels'] = []\nrender(w)",
        "_bee_output['panel_ops'] = [{'op': 'remove', 'id': 'takeover'}]",
        "w = gauge('bad', 0.5)\nw.data['value'] = 2\nrender(w)",
    ] {
        assert!(
            bee::render_api::evaluate(source, &bee::Sandbox::host(vec![]))
                .await
                .is_err(),
            "{source}"
        );
    }
}

#[tokio::test]
async fn all_visual_examples_produce_valid_output() {
    let directory =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("specs/003-visual-render/examples");
    let mut checked = 0;
    for file in std::fs::read_dir(directory).unwrap() {
        let path = file.unwrap().path();
        if path.extension().is_some_and(|e| e == "py") {
            let script = std::fs::read_to_string(&path).unwrap();
            let output = bee::render_api::evaluate(&script, &bee::Sandbox::host(vec![]))
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            assert!(!output.is_empty(), "{}", path.display());
            checked += 1;
        }
    }
    assert_eq!(checked, 7);
}

#[tokio::test]
async fn exhausted_worker_does_not_affect_the_next_render() {
    let sandbox = bee::Sandbox::host(vec![]);
    let result = bee::render_api::evaluate("render(text('x' * 100_000_000))", &sandbox).await;
    assert!(result.is_err(), "allocation must exceed the worker budget");
    let result = bee::render_api::evaluate("render(text('still alive'))", &sandbox)
        .await
        .unwrap();
    assert!(
        matches!(result.inline, Some(bee::render_spec::RenderSpec::Text { content, .. }) if content == "still alive")
    );
}

#[tokio::test]
async fn batch_continuation_restores_ordered_results_in_a_fresh_worker() {
    let Response::Batch { calls, snapshot } = request(Request::Start {
        source: "n = 7\nr = call_tools([{'name': 'one', 'arguments': {}}, {'name': 'two', 'arguments': {'n': n}}])\n[n, r[0]['value'], r[1]['value']]".into(),
        inputs: json!({}),
        visual: false,
    }).await else { panic!("expected batch") };
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].name, "one");
    assert_eq!(calls[1].arguments, json!({"n": 7}));
    let Response::Complete { value } = request(Request::Resume {
        snapshot,
        result: json!([{"value": 11}, {"value": 22}]),
    })
    .await
    else {
        panic!("expected completion")
    };
    assert_eq!(value, json!([7, 11, 22]));
}

#[tokio::test]
async fn batches_reject_invalid_requests_and_visual_dispatch() {
    for source in [
        "call_tools([])",
        "call_tools([{'name': 'one', 'arguments': {}}] * 5)",
        "call_tools([{'name': 'one', 'arguments': [], 'extra': 1}])",
        "call_tools([{'name': '', 'arguments': {}}])",
        "call_tools([{'name': 'one', 'arguments': []}])",
        "call_tools({'name': 'one', 'arguments': {}})",
    ] {
        assert!(
            matches!(
                request(Request::Start {
                    source: source.into(),
                    inputs: json!({}),
                    visual: false
                })
                .await,
                Response::Error { .. }
            ),
            "{source}"
        );
    }
    assert!(matches!(
        request(Request::Start {
            source: "call_tools([{'name': 'bash', 'arguments': {'command': 'id'}}])".into(),
            inputs: json!({}),
            visual: true,
        })
        .await,
        Response::Error { .. }
    ));
}
