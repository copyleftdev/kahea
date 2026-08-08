use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use tungstenite::Message;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_kahea"))
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn scratch(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("kahea-cli-{name}-{nonce}"))
}

fn output_json(arguments: &[&str]) -> Value {
    let output = Command::new(binary()).args(arguments).output().unwrap();
    assert!(
        output.status.success(),
        "stderr={} stdout={}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn websocket_source(port: u16, actions: Value, action_timeout_ms: u64) -> Value {
    json!({
        "kind": "websocket-session",
        "version": 1,
        "operationId": "cliSession",
        "url": format!("ws://127.0.0.1:{port}/socket"),
        "actions": actions,
        "limits": {
            "connect_timeout_ms": 500,
            "action_timeout_ms": action_timeout_ms,
            "idle_timeout_ms": 500,
            "close_timeout_ms": 500,
            "total_timeout_ms": 2_000,
            "max_frame_bytes": 65_536,
            "max_message_bytes": 65_536,
            "max_inbound_frames": 16,
            "max_outbound_frames": 16,
            "max_inbound_messages": 8,
            "max_outbound_messages": 8,
            "max_inbound_bytes": 262_144,
            "max_outbound_bytes": 262_144
        }
    })
}

fn write_websocket_source(root: &Path, source: &Value) -> PathBuf {
    std::fs::create_dir_all(root).unwrap();
    let path = root.join("session.json");
    std::fs::write(&path, serde_json::to_vec(source).unwrap()).unwrap();
    path
}

fn plan_websocket(source: &Path, store: &Path) -> Value {
    output_json(&[
        "plan",
        source.to_str().unwrap(),
        "cliSession",
        "--store",
        store.to_str().unwrap(),
    ])
}

fn invoke_websocket(plan: &str, grants: &[String], store: &Path) -> std::process::Output {
    let mut arguments = vec!["invoke".to_owned(), plan.to_owned()];
    for grant in grants {
        arguments.push("--grant".into());
        arguments.push(grant.clone());
    }
    arguments.push("--store".into());
    arguments.push(store.display().to_string());
    Command::new(binary()).args(arguments).output().unwrap()
}

#[test]
fn text_sources_can_be_inspected_from_standard_input_as_ndjson() {
    let spec = std::fs::read(fixture("billing.openapi.yaml")).unwrap();
    let mut child = Command::new(binary())
        .args(["--format", "ndjson", "inspect", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&spec).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        output.stdout.iter().filter(|byte| **byte == b'\n').count(),
        1
    );
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["kind"], "operation-index");
}

#[test]
fn http_files_can_be_detected_from_standard_input() {
    let source = std::fs::read(fixture("imports/requests.http")).unwrap();
    let mut child = Command::new(binary())
        .args(["inspect", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&source).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["operations"].as_array().unwrap().len(), 2);
}

#[test]
fn cli_and_mcp_plans_are_semantically_identical() {
    let store = scratch("parity");
    let source = fixture("billing.openapi.yaml");
    let input = fixture("billing.create-invoice.input.json");
    let cli = output_json(&[
        "plan",
        source.to_str().unwrap(),
        "createInvoice",
        "--input",
        &format!("@{}", input.display()),
        "--store",
        store.to_str().unwrap(),
    ]);

    let request = json!({
        "jsonrpc":"2.0",
        "id":1,
        "method":"tools/call",
        "params":{
            "name":"kahea_plan",
            "arguments":{
                "source":source,
                "operation":"createInvoice",
                "input":serde_json::from_slice::<Value>(&std::fs::read(input).unwrap()).unwrap(),
                "store":store
            }
        }
    });
    let mut child = Command::new(binary())
        .args(["mcp", "serve"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{request}").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["result"]["structuredContent"], cli);
    std::fs::remove_dir_all(store).unwrap();
}

#[test]
fn current_postman_directory_fixture_is_cli_inspectable() {
    let source = fixture("imports/postman-v3");
    let result = output_json(&["inspect", source.to_str().unwrap()]);
    assert_eq!(result["operations"].as_array().unwrap().len(), 3);
    assert!(result["absent"].as_array().unwrap().iter().any(|absence| {
        absence["capability"] == "postman-script" && absence["blocking"] == true
    }));
}

#[test]
fn every_advertised_request_import_reaches_a_sealed_plan() {
    for (name, operation, method, body) in [
        (
            "imports/postman-2.1.json",
            "Create_widget_1",
            "POST",
            Some(r#"{"name":"precision"}"#),
        ),
        ("imports/postman-v3", "List_widgets_0", "GET", None),
        (
            "imports/postman-v3",
            "Update_widget_2",
            "PUT",
            Some(r#"{"name":"nested-precision"}"#),
        ),
        (
            "imports/request.har",
            "harRequest0_0",
            "POST",
            Some(r#"{"name":"fixture"}"#),
        ),
        (
            "imports/request.curl",
            "curlRequest_0",
            "POST",
            Some(r#"{"name":"fixture"}"#),
        ),
        (
            "imports/requests.http",
            "httpRequest1_1",
            "POST",
            Some(r#"{"name":"fixture"}"#),
        ),
        ("imports/request.rest", "httpRequest0_0", "GET", None),
        (
            "imports/direct-request.yaml",
            "deleteFixture_0",
            "DELETE",
            None,
        ),
        ("imports/direct-request.json", "readFixture_0", "GET", None),
    ] {
        let source = fixture(name);
        let store = scratch(&operation.to_ascii_lowercase());
        let plan = output_json(&[
            "plan",
            source.to_str().unwrap(),
            operation,
            "--store",
            store.to_str().unwrap(),
        ]);
        assert_eq!(plan["kind"], "plan", "format did not plan: {name}");
        assert_eq!(plan["method"], method, "wrong method for {name}");
        assert_eq!(plan["valid"], true, "unsealed plan for {name}");
        assert!(plan["fingerprint"].as_str().unwrap().starts_with("b3:"));
        match body {
            Some(body) => assert_eq!(plan["body"]["inline"], body, "wrong body for {name}"),
            None => assert!(plan["body"].is_null(), "unexpected body for {name}"),
        }
        std::fs::remove_dir_all(store).unwrap();
    }
}

#[test]
fn postman_script_absence_blocks_only_its_own_request() {
    let source = fixture("imports/postman-v3");
    let store = scratch("postman-script-scope");
    let output = Command::new(binary())
        .args([
            "plan",
            source.to_str().unwrap(),
            "Create_widget_1",
            "--store",
            store.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let error: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(error["code"], "invalid-plan");
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .contains("Postman script")
    );
}

#[test]
fn every_openapi_version_and_text_encoding_inspects_and_plans() {
    let root = scratch("openapi-matrix");
    std::fs::create_dir_all(&root).unwrap();
    for version in ["3.0.4", "3.1.2", "3.2.0"] {
        for encoding in ["json", "yaml"] {
            let source = root.join(format!("openapi-{version}.{encoding}"));
            let contents = if encoding == "json" {
                serde_json::to_vec(&json!({
                    "openapi":version,
                    "info":{"title":"matrix","version":"1"},
                    "servers":[{"url":"https://api.example.test"}],
                    "paths":{"/health":{"get":{
                        "operationId":"getHealth",
                        "responses":{"200":{"description":"ok"}}
                    }}}
                }))
                .unwrap()
            } else {
                format!(
                    "openapi: {version}\ninfo: {{ title: matrix, version: '1' }}\nservers: [{{ url: https://api.example.test }}]\npaths:\n  /health:\n    get:\n      operationId: getHealth\n      responses:\n        '200': {{ description: ok }}\n"
                )
                .into_bytes()
            };
            std::fs::write(&source, contents).unwrap();
            let index = output_json(&["inspect", source.to_str().unwrap()]);
            assert_eq!(index["operations"].as_array().unwrap().len(), 1);
            let store = root.join(format!("store-{version}-{encoding}"));
            let plan = output_json(&[
                "plan",
                source.to_str().unwrap(),
                "getHealth",
                "--store",
                store.to_str().unwrap(),
            ]);
            assert_eq!(plan["kind"], "plan");
            assert_eq!(plan["method"], "GET");
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn arazzo_json_and_yaml_both_inspect_and_plan() {
    for name in [
        "workflows/billing.arazzo.yaml",
        "workflows/billing.arazzo.json",
    ] {
        let source = fixture(name);
        let input = fixture("workflows/billing.input.json");
        let store = scratch("arazzo-matrix");
        let index = output_json(&["inspect", source.to_str().unwrap()]);
        assert_eq!(index["operations"][0][3], "createAndReadInvoice");
        let plan = output_json(&[
            "plan",
            source.to_str().unwrap(),
            "createAndReadInvoice",
            "--input",
            &format!("@{}", input.display()),
            "--store",
            store.to_str().unwrap(),
        ]);
        assert_eq!(plan["kind"], "workflow-plan");
        assert_eq!(plan["steps"].as_array().unwrap().len(), 2);
        std::fs::remove_dir_all(store).unwrap();
    }
}

#[test]
fn canonical_plan_matches_the_cross_platform_golden_bytes() {
    let store = scratch("golden");
    let source = fixture("billing.openapi.yaml");
    let input = fixture("billing.create-invoice.input.json");
    let output = Command::new(binary())
        .args([
            "plan",
            source.to_str().unwrap(),
            "createInvoice",
            "--input",
            &format!("@{}", input.display()),
            "--store",
            store.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        output.stdout,
        std::fs::read(fixture("golden/create-invoice.plan.json")).unwrap()
    );
    std::fs::remove_dir_all(store).unwrap();
}

#[test]
fn cli_and_mcp_conformance_campaigns_are_semantically_identical() {
    let store = scratch("conformance-parity");
    let source = fixture("billing.openapi.yaml");
    let cli = output_json(&[
        "conform",
        source.to_str().unwrap(),
        "createInvoice",
        "--cases",
        "6",
        "--seed",
        "42",
        "--store",
        store.to_str().unwrap(),
    ]);
    assert_eq!(cli["kind"], "conformance-plan");
    assert_eq!(cli["cases"].as_array().unwrap().len(), 6);

    let request = json!({
        "jsonrpc":"2.0",
        "id":1,
        "method":"tools/call",
        "params":{
            "name":"kahea_plan",
            "arguments":{
                "source":source,
                "operation":"createInvoice",
                "conformance":{"cases":6,"seed":42,"mode":"mixed"},
                "store":store
            }
        }
    });
    let mut child = Command::new(binary())
        .args(["mcp", "serve"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{request}").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["result"]["structuredContent"], cli);
    std::fs::remove_dir_all(store).unwrap();
}

#[test]
fn websocket_cli_runs_the_sealed_session_and_explains_bounded_evidence() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let root = scratch("websocket-success");
    let store = root.join("state");
    let source = write_websocket_source(
        &root,
        &websocket_source(
            port,
            json!([
                {"type":"send-text","text":"hello"},
                {"type":"expect-text","equals":"world","timeout_ms":null},
                {"type":"send-binary","payload_base64":"AAE="},
                {"type":"expect-binary","payload_base64":"AgM=","timeout_ms":null},
                {"type":"close","code":1000,"reason":"done"}
            ]),
            500,
        ),
    );
    let index = output_json(&["inspect", source.to_str().unwrap()]);
    assert_eq!(index["operations"][0][1], "WEBSOCKET");
    assert_eq!(index["operations"][0][3], "cliSession");

    let plan = plan_websocket(&source, &store);
    assert_eq!(plan["kind"], "websocket-plan");
    assert_eq!(plan["risk"], "write");
    assert_eq!(plan["actions"].as_array().unwrap().len(), 5);
    let grants: Vec<String> = plan["required_grants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|grant| grant.as_str().unwrap().to_owned())
        .collect();
    assert!(grants.iter().any(|grant| grant == "websocket:connect"));
    assert!(grants.iter().any(|grant| grant == "net-insecure-websocket"));

    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut socket = tungstenite::accept(stream).unwrap();
        assert_eq!(socket.read().unwrap(), Message::Text("hello".into()));
        socket.send(Message::Text("world".into())).unwrap();
        assert_eq!(
            socket.read().unwrap(),
            Message::Binary(vec![0_u8, 1].into())
        );
        socket.send(Message::Binary(vec![2_u8, 3].into())).unwrap();
        assert!(matches!(socket.read().unwrap(), Message::Close(Some(_))));
        let _ = socket.flush();
    });
    let output = invoke_websocket(plan["id"].as_str().unwrap(), &grants, &store);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr={} stdout={}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        output.stdout.iter().filter(|byte| **byte == b'\n').count(),
        1
    );
    let observation: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(observation["kind"], "websocket-observation");
    assert_eq!(observation["terminal_cause"], "completed");
    assert_eq!(observation["exit"], 0);
    server.join().unwrap();

    let transcript = observation["transcript"].as_str().unwrap();
    let matched = output_json(&[
        "explain",
        transcript,
        "--select",
        "/entries/1/check",
        "--store",
        store.to_str().unwrap(),
    ]);
    assert_eq!(matched["value"], "matched");
    let binary_handle = output_json(&[
        "explain",
        transcript,
        "--select",
        "/entries/3/payload",
        "--store",
        store.to_str().unwrap(),
    ])["value"]
        .as_str()
        .unwrap()
        .to_owned();
    let binary = output_json(&[
        "explain",
        &binary_handle,
        "--select",
        "bytes:0-1",
        "--store",
        store.to_str().unwrap(),
    ]);
    assert_eq!(binary["value"]["data"], "AgM=");

    let stored_path = store.join("store/plans").join(format!(
        "{}.json",
        plan["id"].as_str().unwrap().replace(':', "-")
    ));
    let denied_grants: Vec<_> = grants
        .into_iter()
        .filter(|grant| grant != "websocket:connect")
        .collect();
    let denied = invoke_websocket(stored_path.to_str().unwrap(), &denied_grants, &store);
    assert_eq!(denied.status.code(), Some(4));
    let denial: Value = serde_json::from_slice(&denied.stdout).unwrap();
    assert_eq!(denial["kind"], "denial");
    assert_eq!(denial["required"], "websocket:connect");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn websocket_cli_maps_expectation_timeout_and_handshake_failures() {
    let expectation_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let expectation_root = scratch("websocket-expectation");
    let expectation_store = expectation_root.join("state");
    let expectation_source = write_websocket_source(
        &expectation_root,
        &websocket_source(
            expectation_listener.local_addr().unwrap().port(),
            json!([
                {"type":"expect-text","equals":"expected","timeout_ms":null},
                {"type":"expect-close","codes":[1000],"reason":null,"timeout_ms":null}
            ]),
            500,
        ),
    );
    let expectation_plan = plan_websocket(&expectation_source, &expectation_store);
    let expectation_grants: Vec<_> = expectation_plan["required_grants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect();
    let expectation_server = thread::spawn(move || {
        let (stream, _) = expectation_listener.accept().unwrap();
        let mut socket = tungstenite::accept(stream).unwrap();
        socket.send(Message::Text("unexpected".into())).unwrap();
    });
    let output = invoke_websocket(
        expectation_plan["id"].as_str().unwrap(),
        &expectation_grants,
        &expectation_store,
    );
    assert_eq!(output.status.code(), Some(1));
    let observation: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(observation["terminal_cause"], "expectation-failed");
    expectation_server.join().unwrap();
    std::fs::remove_dir_all(expectation_root).unwrap();

    let timeout_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let timeout_root = scratch("websocket-timeout");
    let timeout_store = timeout_root.join("state");
    let timeout_source = write_websocket_source(
        &timeout_root,
        &websocket_source(
            timeout_listener.local_addr().unwrap().port(),
            json!([
                {"type":"expect-text","equals":"never","timeout_ms":40},
                {"type":"expect-close","codes":[1000],"reason":null,"timeout_ms":null}
            ]),
            40,
        ),
    );
    let timeout_plan = plan_websocket(&timeout_source, &timeout_store);
    let timeout_grants: Vec<_> = timeout_plan["required_grants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect();
    let timeout_server = thread::spawn(move || {
        let (stream, _) = timeout_listener.accept().unwrap();
        let _socket = tungstenite::accept(stream).unwrap();
        thread::sleep(Duration::from_millis(150));
    });
    let output = invoke_websocket(
        timeout_plan["id"].as_str().unwrap(),
        &timeout_grants,
        &timeout_store,
    );
    assert_eq!(output.status.code(), Some(3));
    let observation: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(observation["terminal_cause"], "action-timeout");
    timeout_server.join().unwrap();
    std::fs::remove_dir_all(timeout_root).unwrap();

    let handshake_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let handshake_root = scratch("websocket-handshake");
    let handshake_store = handshake_root.join("state");
    let handshake_source = write_websocket_source(
        &handshake_root,
        &websocket_source(
            handshake_listener.local_addr().unwrap().port(),
            json!([{"type":"expect-close","codes":[1000],"reason":null,"timeout_ms":null}]),
            500,
        ),
    );
    let handshake_plan = plan_websocket(&handshake_source, &handshake_store);
    let handshake_grants: Vec<_> = handshake_plan["required_grants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect();
    let handshake_server = thread::spawn(move || {
        let (mut stream, _) = handshake_listener.accept().unwrap();
        let mut request = [0_u8; 2048];
        let _ = stream.read(&mut request).unwrap();
        stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
    });
    let output = invoke_websocket(
        handshake_plan["id"].as_str().unwrap(),
        &handshake_grants,
        &handshake_store,
    );
    assert_eq!(output.status.code(), Some(1));
    let observation: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(observation["terminal_cause"], "handshake-check-failed");
    handshake_server.join().unwrap();
    std::fs::remove_dir_all(handshake_root).unwrap();
}

#[test]
fn websocket_cli_rejects_invalid_sources_and_unsealed_overrides() {
    let root = scratch("websocket-invalid");
    let source = write_websocket_source(
        &root,
        &websocket_source(
            9,
            json!([{"type":"expect-text","equals":"missing terminal","timeout_ms":null}]),
            500,
        ),
    );
    let store = root.join("state");
    let invalid = Command::new(binary())
        .args([
            "plan",
            source.to_str().unwrap(),
            "cliSession",
            "--store",
            store.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(2));
    let error: Value = serde_json::from_slice(&invalid.stdout).unwrap();
    assert_eq!(error["code"], "invalid-websocket-plan");

    let source = write_websocket_source(
        &root,
        &websocket_source(
            9,
            json!([{"type":"expect-close","codes":[1000],"reason":null,"timeout_ms":null}]),
            500,
        ),
    );
    let override_attempt = Command::new(binary())
        .args([
            "plan",
            source.to_str().unwrap(),
            "cliSession",
            "--server",
            "ws://attacker.example.test/socket",
            "--store",
            store.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(override_attempt.status.code(), Some(2));
    let error: Value = serde_json::from_slice(&override_attempt.stdout).unwrap();
    assert_eq!(error["code"], "invalid-websocket-plan-options");
    std::fs::remove_dir_all(root).unwrap();
}
