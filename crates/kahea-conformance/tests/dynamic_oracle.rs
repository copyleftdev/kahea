//! In-process dynamic lifecycle: plan and execute campaigns against a freshly
//! generated API, and prove that each injected fault is rejected. This is the
//! `cargo test` counterpart of `scripts/dynamic-conformance.sh`.

use kahea_conformance::{
    ConformanceMode, ConformanceOptions, build_conformance_plan, invoke_conformance,
    store_conformance_plan,
};
use kahea_core::ConformanceObservation;
use kahea_evidence::EvidenceStore;
use kahea_exec::InvokeOptions;
use kahea_ingest::{load_openapi, resolve_operation};
use kahea_plan::ProjectConfiguration;
use kahea_test_server::{
    Diagnostics, FaultMode, RunningServer, generate_scenario, openapi_document, start_server,
};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SEED: u64 = 424242;
const CASES: usize = 6;

fn scratch(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("kahea-dynamic-{name}-{nonce}"))
}

fn diagnostics(server: &RunningServer) -> Diagnostics {
    let authority = server
        .manifest
        .base_url
        .trim_start_matches("http://")
        .to_string();
    let mut stream = TcpStream::connect(&authority).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "GET /__kahea/diagnostics HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let response = String::from_utf8(response).unwrap();
    let (_, body) = response
        .split_once("\r\n\r\n")
        .expect("diagnostics response has no body");
    serde_json::from_str(body).expect("diagnostics body is not a Diagnostics document")
}

/// Run one full startup lifecycle: generate an API, plan and invoke a mixed
/// campaign for every operation it publishes, then shut the server down.
fn lifecycle(
    label: &str,
    fault: FaultMode,
) -> (Vec<(String, ConformanceObservation)>, Diagnostics) {
    let scenario = generate_scenario(SEED);
    let server = start_server(scenario.clone(), fault).unwrap();
    let document = openapi_document(&scenario, &server.manifest.base_url);
    let bytes = serde_json::to_vec(&document).unwrap();
    let source = load_openapi(Path::new("dynamic.json"), &bytes).unwrap();
    assert!(
        server.manifest.operations.len() >= 3,
        "generated API is too small to exercise the oracle"
    );

    let root = scratch(label);
    let evidence = EvidenceStore::open(root.join("store")).unwrap();
    let mut observations = Vec::new();
    for operation_id in &server.manifest.operations {
        let operation = resolve_operation(&source, operation_id)
            .unwrap_or_else(|error| panic!("{operation_id} does not resolve: {error}"));
        let (campaign, requests) = build_conformance_plan(
            &source,
            &operation,
            ConformanceOptions {
                cases: CASES,
                seed: SEED,
                mode: ConformanceMode::Mixed,
                max_failures: CASES,
                ..ConformanceOptions::default()
            },
            &ProjectConfiguration::default(),
        )
        .unwrap_or_else(|error| panic!("{operation_id} campaign failed to plan: {error}"));
        store_conformance_plan(&root, &campaign, &requests).unwrap();
        let observation = invoke_conformance(
            &campaign,
            &InvokeOptions {
                grants: campaign.required_grants.iter().cloned().collect(),
                expected_config_fingerprint: Some(campaign.config_fingerprint.clone()),
                expected_policy_fingerprint: Some(campaign.policy_fingerprint.clone()),
                ..InvokeOptions::default()
            },
            &root,
            &evidence,
        )
        .unwrap_or_else(|error| panic!("{operation_id} campaign failed to run: {error}"));
        observations.push((operation_id.clone(), observation));
    }

    let snapshot = diagnostics(&server);
    server.stop().unwrap();
    drop(evidence);
    fs::remove_dir_all(root).unwrap();
    (observations, snapshot)
}

#[test]
fn a_correct_server_passes_every_generated_operation() {
    let (observations, diagnostics) = lifecycle("clean", FaultMode::None);
    let mut executed = 0_u64;
    for (operation, observation) in &observations {
        assert_eq!(observation.exit, 0, "{operation} did not conform");
        assert_eq!(observation.failed, 0, "{operation} reported failures");
        assert_eq!(observation.passed, observation.executed);
        assert_eq!(observation.executed, observation.generated);
        assert!(observation.executed > 0);
        executed += observation.executed as u64;
    }

    assert_eq!(
        diagnostics.requests, executed,
        "the server saw a different request count than the campaigns executed"
    );
    assert!(diagnostics.valid > 0 && diagnostics.invalid > 0);
    for (operation, seen) in &diagnostics.by_operation {
        assert!(seen.valid > 0, "{operation} never received valid traffic");
        assert!(
            seen.invalid > 0,
            "{operation} never received invalid traffic"
        );
    }
}

#[test]
fn a_server_that_accepts_invalid_requests_is_rejected() {
    let (observations, _) = lifecycle("accept-invalid", FaultMode::AcceptInvalid);
    let rejected: Vec<_> = observations
        .iter()
        .filter(|(_, observation)| observation.exit != 0 && observation.failed > 0)
        .collect();
    assert!(
        !rejected.is_empty(),
        "a server accepting schema-invalid requests was not detected"
    );
    assert!(
        rejected.iter().any(|(_, observation)| {
            observation
                .cases
                .iter()
                .any(|case| case.reason.contains("accepted"))
        }),
        "the failure was not attributed to accepted invalid input"
    );
}

#[test]
fn universally_faulty_servers_fail_every_operation() {
    for (label, fault) in [
        ("server-error", FaultMode::ServerError),
        ("undocumented-status", FaultMode::UndocumentedStatus),
        ("malformed-response", FaultMode::MalformedResponse),
    ] {
        let (observations, _) = lifecycle(label, fault);
        for (operation, observation) in &observations {
            assert_ne!(
                observation.exit, 0,
                "{label} was not detected on {operation}"
            );
            assert!(
                observation.failed > 0,
                "{label} produced no failing case on {operation}"
            );
            assert!(
                observation.passed < observation.executed,
                "{label} passed every executed case on {operation}"
            );
        }
    }
}
