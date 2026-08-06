use serde_json::{Value, json};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

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
