//! Public-surface conformance campaign contracts: determinism, seal coverage,
//! fail-closed generation, and oracle behaviour against controlled servers.

use kahea_conformance::{
    ConformanceError, ConformanceMode, ConformanceOptions, build_conformance_plan,
    invoke_conformance, store_conformance_plan,
};
use kahea_core::{ConformanceGeneration, RequestPlan};
use kahea_evidence::EvidenceStore;
use kahea_exec::InvokeOptions;
use kahea_ingest::{OpenApiSource, OperationDefinition, load_openapi, resolve_operation};
use kahea_plan::{PlanOptions, ProjectConfiguration};
use kahea_test_server::{remove_temporary_store, temporary_store_path};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

fn fixture_spec() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/conformance/widgets.openapi.yaml");
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn source_for(spec: &str) -> (OpenApiSource, OperationDefinition) {
    let source = load_openapi(Path::new("widgets.openapi.yaml"), spec.as_bytes()).unwrap();
    let operation = resolve_operation(&source, "updateWidget").unwrap();
    (source, operation)
}

fn fixture() -> (OpenApiSource, OperationDefinition) {
    source_for(&fixture_spec())
}

fn loopback_fixture(port: u16) -> (OpenApiSource, OperationDefinition) {
    source_for(&fixture_spec().replace(
        "https://api.example.test",
        &format!("http://127.0.0.1:{port}"),
    ))
}

fn options(cases: usize, seed: u64, mode: ConformanceMode) -> ConformanceOptions {
    ConformanceOptions {
        cases,
        seed,
        mode,
        ..ConformanceOptions::default()
    }
}

fn scratch(name: &str) -> PathBuf {
    temporary_store_path(&format!("campaign-{name}"))
}

/// A single-request-per-connection loopback server that never blocks the test
/// on a case count the implementation is free to cut short.
struct ControlledServer {
    port: u16,
    stop: Arc<AtomicBool>,
    served: Arc<AtomicUsize>,
    worker: Option<JoinHandle<()>>,
}

impl ControlledServer {
    fn start(responder: impl Fn(&str) -> String + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let served = Arc::new(AtomicUsize::new(0));
        let worker = thread::spawn({
            let stop = Arc::clone(&stop);
            let served = Arc::clone(&served);
            move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            stream.set_nonblocking(false).unwrap();
                            let mut buffer = vec![0_u8; 32 * 1024];
                            let read = stream.read(&mut buffer).unwrap_or(0);
                            let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
                            let _ = stream.write_all(responder(&request).as_bytes());
                            let _ = stream.flush();
                            served.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(_) => break,
                    }
                }
            }
        });
        Self {
            port,
            stop,
            served,
            worker: Some(worker),
        }
    }

    fn served(&self) -> usize {
        self.served.load(Ordering::SeqCst)
    }
}

impl Drop for ControlledServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn response(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn spec_with_body(schema: Value) -> String {
    serde_json::to_string(&json!({
        "openapi": "3.1.0",
        "info": {"title": "generation", "version": "1"},
        "servers": [{"url": "https://api.example.test"}],
        "paths": {"/widgets/{id}": {"post": {
            "operationId": "updateWidget",
            "parameters": [
                {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}
            ],
            "requestBody": {
                "required": true,
                "content": {"application/json": {"schema": schema}}
            },
            "responses": {"200": {"description": "ok"}}
        }}}
    }))
    .unwrap()
}

#[test]
fn a_seed_sweep_is_reproducible_and_separates_every_campaign() {
    let (source, operation) = fixture();
    let mut fingerprints = BTreeSet::new();
    for seed in 0..16_u64 {
        let first = build_conformance_plan(
            &source,
            &operation,
            options(6, seed, ConformanceMode::Mixed),
            &ProjectConfiguration::default(),
        )
        .unwrap();
        let second = build_conformance_plan(
            &source,
            &operation,
            options(6, seed, ConformanceMode::Mixed),
            &ProjectConfiguration::default(),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_vec(&first.0).unwrap(),
            serde_json::to_vec(&second.0).unwrap(),
            "campaign is not byte-reproducible at seed {seed}"
        );
        assert_eq!(
            serde_json::to_vec(&first.1).unwrap(),
            serde_json::to_vec(&second.1).unwrap(),
            "request plans are not byte-reproducible at seed {seed}"
        );
        assert!(
            fingerprints.insert(first.0.fingerprint.clone()),
            "seed {seed} collided with an earlier campaign"
        );
    }
}

#[test]
fn the_execute_grant_always_names_the_generated_case_count() {
    let (source, operation) = fixture();
    for cases in 1..=12 {
        let (campaign, requests) = build_conformance_plan(
            &source,
            &operation,
            options(cases, 5, ConformanceMode::Mixed),
            &ProjectConfiguration::default(),
        )
        .unwrap();
        assert!(
            campaign.cases.len() <= cases,
            "campaign generated more than the requested {cases} cases"
        );
        assert_eq!(campaign.requested_cases, cases);
        assert_eq!(campaign.cases.len(), requests.len());
        let execute: Vec<_> = campaign
            .required_grants
            .iter()
            .filter(|grant| grant.starts_with("conformance:execute:"))
            .collect();
        assert_eq!(execute.len(), 1, "expected exactly one execution grant");
        assert_eq!(
            execute[0],
            &format!("conformance:execute:{}", campaign.cases.len())
        );
    }
}

#[test]
fn each_mode_selects_only_its_own_generation_and_grants() {
    let (source, operation) = fixture();
    for (mode, generation) in [
        (ConformanceMode::Positive, ConformanceGeneration::Positive),
        (ConformanceMode::Negative, ConformanceGeneration::Negative),
    ] {
        let (campaign, requests) = build_conformance_plan(
            &source,
            &operation,
            options(6, 3, mode),
            &ProjectConfiguration::default(),
        )
        .unwrap();
        assert!(
            campaign
                .cases
                .iter()
                .all(|case| case.generation == generation),
            "{mode:?} campaign mixed generations"
        );
        let negative = generation == ConformanceGeneration::Negative;
        assert_eq!(
            campaign
                .required_grants
                .contains(&"conformance:negative".to_string()),
            negative,
            "{mode:?} campaign carries the wrong negative grant"
        );
        for request in &requests {
            assert_eq!(request.valid, !negative, "{mode:?} plan validity is wrong");
            assert_eq!(
                request
                    .required_grants
                    .contains(&"conformance:negative".to_string()),
                negative
            );
        }
    }

    let (mixed, _) = build_conformance_plan(
        &source,
        &operation,
        options(6, 3, ConformanceMode::Mixed),
        &ProjectConfiguration::default(),
    )
    .unwrap();
    assert_eq!(mixed.cases[0].generation, ConformanceGeneration::Positive);
    assert!(
        mixed
            .cases
            .iter()
            .any(|case| case.generation == ConformanceGeneration::Negative)
    );
}

#[test]
fn every_case_binds_one_distinct_sealed_request_plan() {
    let (source, operation) = fixture();
    let (campaign, requests) = build_conformance_plan(
        &source,
        &operation,
        options(12, 17, ConformanceMode::Mixed),
        &ProjectConfiguration::default(),
    )
    .unwrap();

    let mut case_ids = BTreeSet::new();
    let mut plan_ids = BTreeSet::new();
    let mut fingerprints = BTreeSet::new();
    for (case, request) in campaign.cases.iter().zip(&requests) {
        assert!(case_ids.insert(&case.case_id), "duplicate case id");
        assert!(plan_ids.insert(&case.plan), "duplicate request plan id");
        assert!(
            fingerprints.insert(&case.plan_fingerprint),
            "two cases share a request fingerprint"
        );
        assert_eq!(case.plan, request.id);
        assert_eq!(case.plan_fingerprint, request.fingerprint);
        assert!(request.verify_seal().unwrap(), "case plan seal is invalid");
        assert!(case.request_digest.starts_with("b3:"));
        assert!(!case.strategy.is_empty());
        for grant in &request.required_grants {
            assert!(
                campaign.required_grants.contains(grant),
                "campaign omits case grant {grant}"
            );
        }
    }
}

#[test]
fn the_campaign_seal_covers_seed_case_count_pacing_and_failure_bound() {
    let (source, operation) = fixture();
    let base = ConformanceOptions {
        cases: 6,
        seed: 21,
        mode: ConformanceMode::Mixed,
        delay_ms: 0,
        max_failures: 10,
        ..ConformanceOptions::default()
    };
    let build = |options: ConformanceOptions| {
        build_conformance_plan(
            &source,
            &operation,
            options,
            &ProjectConfiguration::default(),
        )
        .unwrap()
        .0
        .fingerprint
    };
    let reference = build(base.clone());
    for (label, altered) in [
        (
            "seed",
            ConformanceOptions {
                seed: 22,
                ..base.clone()
            },
        ),
        (
            "cases",
            ConformanceOptions {
                cases: 7,
                ..base.clone()
            },
        ),
        (
            "delay",
            ConformanceOptions {
                delay_ms: 25,
                ..base.clone()
            },
        ),
        (
            "max_failures",
            ConformanceOptions {
                max_failures: 3,
                ..base.clone()
            },
        ),
        (
            "mode",
            ConformanceOptions {
                mode: ConformanceMode::Positive,
                ..base.clone()
            },
        ),
    ] {
        assert_ne!(
            reference,
            build(altered),
            "campaign seal does not cover {label}"
        );
    }
}

#[test]
fn a_substituted_or_corrupt_case_plan_is_rejected_before_any_request() {
    let (source, operation) = fixture();
    let (campaign, requests) = build_conformance_plan(
        &source,
        &operation,
        options(4, 31, ConformanceMode::Positive),
        &ProjectConfiguration::default(),
    )
    .unwrap();
    let root = scratch("tamper");
    store_conformance_plan(&root, &campaign, &requests).unwrap();
    let evidence = EvidenceStore::open(root.join("store")).unwrap();
    let stored = root
        .join("store/plans")
        .join(format!("{}.json", campaign.cases[0].plan.replace(':', "-")));
    let original = fs::read(&stored).unwrap();
    let grants = InvokeOptions {
        grants: campaign.required_grants.iter().cloned().collect(),
        ..InvokeOptions::default()
    };

    let mut substitute: RequestPlan = serde_json::from_slice(&original).unwrap();
    substitute.target.push_str("/substituted");
    let substitute = substitute.seal().unwrap();
    assert!(substitute.verify_seal().unwrap());
    fs::write(&stored, serde_json::to_vec(&substitute).unwrap()).unwrap();
    assert!(
        matches!(
            invoke_conformance(&campaign, &grants, &root, &evidence),
            Err(ConformanceError::InvalidCase(_))
        ),
        "a validly sealed but different plan was accepted for a case"
    );

    fs::write(&stored, b"{").unwrap();
    assert!(matches!(
        invoke_conformance(&campaign, &grants, &root, &evidence),
        Err(ConformanceError::InvalidCase(_))
    ));

    drop(evidence);
    remove_temporary_store(&root);
}

#[test]
fn a_campaign_planned_under_different_configuration_never_executes() {
    let (source, operation) = fixture();
    let (campaign, requests) = build_conformance_plan(
        &source,
        &operation,
        options(4, 13, ConformanceMode::Positive),
        &ProjectConfiguration::default(),
    )
    .unwrap();
    let root = scratch("fingerprint");
    store_conformance_plan(&root, &campaign, &requests).unwrap();
    let evidence = EvidenceStore::open(root.join("store")).unwrap();

    for options in [
        InvokeOptions {
            grants: campaign.required_grants.iter().cloned().collect(),
            expected_config_fingerprint: Some("b3:0000".into()),
            ..InvokeOptions::default()
        },
        InvokeOptions {
            grants: campaign.required_grants.iter().cloned().collect(),
            expected_policy_fingerprint: Some("b3:0000".into()),
            ..InvokeOptions::default()
        },
    ] {
        assert!(matches!(
            invoke_conformance(&campaign, &options, &root, &evidence),
            Err(ConformanceError::Plan(_))
        ));
    }

    drop(evidence);
    remove_temporary_store(&root);
}

#[test]
fn generation_fails_closed_on_schemas_it_cannot_bound() {
    for (label, schema) in [
        ("not", json!({"type": "object", "not": {"type": "string"}})),
        (
            "if",
            json!({"type": "object", "if": {"type": "object"}, "then": {"type": "object"}}),
        ),
        (
            "patternProperties",
            json!({"type": "object", "patternProperties": {"^x-": {"type": "string"}}}),
        ),
        (
            "propertyNames",
            json!({"type": "object", "propertyNames": {"pattern": "^x$"}}),
        ),
        (
            "dependentRequired",
            json!({"type": "object", "dependentRequired": {"a": ["b"]}}),
        ),
        (
            "contains",
            json!({"type": "array", "contains": {"type": "string"}}),
        ),
        (
            "prefixItems",
            json!({"type": "array", "prefixItems": [{"type": "string"}]}),
        ),
        (
            "unevaluatedProperties",
            json!({"type": "object", "unevaluatedProperties": false}),
        ),
        (
            "binary-format",
            json!({"type": "string", "format": "binary"}),
        ),
        ("empty-enum", json!({"enum": []})),
        (
            "impossible-integer",
            json!({"type": "integer", "minimum": 10, "maximum": 5}),
        ),
        (
            "impossible-string",
            json!({"type": "string", "minLength": 5, "maxLength": 2}),
        ),
        (
            "unbounded-pattern",
            json!({"type": "string", "pattern": "^[!@#]{2}$"}),
        ),
        ("unsupported-type", json!({"type": "function"})),
    ] {
        let spec = spec_with_body(schema);
        let (source, operation) = source_for(&spec);
        let result = build_conformance_plan(
            &source,
            &operation,
            options(4, 1, ConformanceMode::Positive),
            &ProjectConfiguration::default(),
        );
        assert!(
            matches!(result, Err(ConformanceError::Generation { .. })),
            "{label} did not fail closed: {:?}",
            result.map(|(campaign, _)| campaign.id)
        );
    }
}

#[test]
fn baseline_input_unblocks_values_the_bounded_generator_cannot_infer() {
    let spec = spec_with_body(json!({
        "type": "object",
        "required": ["code"],
        "properties": {"code": {"type": "string", "pattern": "^[!@#]{2}$"}}
    }));
    let (source, operation) = source_for(&spec);
    assert!(matches!(
        build_conformance_plan(
            &source,
            &operation,
            options(2, 1, ConformanceMode::Positive),
            &ProjectConfiguration::default(),
        ),
        Err(ConformanceError::Generation { .. })
    ));

    let (_, requests) = build_conformance_plan(
        &source,
        &operation,
        ConformanceOptions {
            input: Some(json!({"body": {"code": "!@"}})),
            ..options(2, 1, ConformanceMode::Positive)
        },
        &ProjectConfiguration::default(),
    )
    .unwrap();
    for request in requests {
        let body: Value = serde_json::from_str(&request.body.as_ref().unwrap().inline).unwrap();
        assert_eq!(body["code"], "!@");
    }
}

#[test]
fn explicit_overrides_pin_generated_parameters_across_every_case() {
    let (source, operation) = fixture();
    let (_, requests) = build_conformance_plan(
        &source,
        &operation,
        ConformanceOptions {
            plan: PlanOptions {
                explicit: vec![("path.id".into(), json!("pinned"))],
                ..PlanOptions::default()
            },
            ..options(8, 77, ConformanceMode::Positive)
        },
        &ProjectConfiguration::default(),
    )
    .unwrap();
    assert!(!requests.is_empty());
    for request in requests {
        assert!(
            request.target.contains("/widgets/pinned"),
            "explicit path override was regenerated: {}",
            request.target
        );
    }
}

#[test]
fn the_failure_bound_stops_execution_against_a_broken_server() {
    let server = ControlledServer::start(|_| response("500 Internal Server Error", "{}"));
    let (source, operation) = loopback_fixture(server.port);
    let (campaign, requests) = build_conformance_plan(
        &source,
        &operation,
        ConformanceOptions {
            max_failures: 3,
            ..options(10, 5, ConformanceMode::Positive)
        },
        &ProjectConfiguration::default(),
    )
    .unwrap();
    assert!(campaign.cases.len() > 3);

    let root = scratch("failure-bound");
    store_conformance_plan(&root, &campaign, &requests).unwrap();
    let evidence = EvidenceStore::open(root.join("store")).unwrap();
    let observation = invoke_conformance(
        &campaign,
        &InvokeOptions {
            grants: campaign.required_grants.iter().cloned().collect(),
            ..InvokeOptions::default()
        },
        &root,
        &evidence,
    )
    .unwrap();

    assert_eq!(observation.executed, 3, "failure bound was not enforced");
    assert_eq!(observation.failed, 3);
    assert_eq!(observation.passed, 0);
    assert_eq!(observation.generated, campaign.cases.len());
    assert_eq!(observation.exit, 1);
    assert!(
        observation
            .cases
            .iter()
            .all(|case| case.reason.contains("5xx")),
        "5xx responses were not reported as server errors"
    );
    assert_eq!(server.served(), 3, "more requests were sent than executed");

    drop(evidence);
    remove_temporary_store(&root);
}

#[test]
fn a_permissive_server_fails_every_negative_case() {
    let server = ControlledServer::start(|_| response("200 OK", "{}"));
    let (source, operation) = loopback_fixture(server.port);
    let (campaign, requests) = build_conformance_plan(
        &source,
        &operation,
        ConformanceOptions {
            max_failures: 16,
            ..options(4, 8, ConformanceMode::Negative)
        },
        &ProjectConfiguration::default(),
    )
    .unwrap();

    let root = scratch("permissive");
    store_conformance_plan(&root, &campaign, &requests).unwrap();
    let evidence = EvidenceStore::open(root.join("store")).unwrap();
    let observation = invoke_conformance(
        &campaign,
        &InvokeOptions {
            grants: campaign.required_grants.iter().cloned().collect(),
            ..InvokeOptions::default()
        },
        &root,
        &evidence,
    )
    .unwrap();

    assert_eq!(observation.executed, campaign.cases.len());
    assert_eq!(observation.passed, 0);
    assert_eq!(observation.failed, campaign.cases.len());
    assert_eq!(observation.exit, 1);
    let mut handles = BTreeSet::new();
    for case in &observation.cases {
        assert_eq!(case.generation, ConformanceGeneration::Negative);
        assert_eq!(case.status, Some(200));
        assert!(
            case.reason.contains("accepted"),
            "unexpected oracle reason: {}",
            case.reason
        );
        assert!(handles.insert(case.evidence.clone()), "evidence was reused");
        assert!(
            evidence.get(&case.evidence).is_ok(),
            "case evidence is not retrievable"
        );
    }

    drop(evidence);
    remove_temporary_store(&root);
}

#[test]
fn declared_pacing_is_applied_between_executed_cases() {
    let server = ControlledServer::start(|_| response("200 OK", "{}"));
    let (source, operation) = loopback_fixture(server.port);
    let (campaign, requests) = build_conformance_plan(
        &source,
        &operation,
        ConformanceOptions {
            delay_ms: 40,
            ..options(4, 9, ConformanceMode::Positive)
        },
        &ProjectConfiguration::default(),
    )
    .unwrap();
    let expected = Duration::from_millis(40 * (campaign.cases.len() as u64 - 1));

    let root = scratch("pacing");
    store_conformance_plan(&root, &campaign, &requests).unwrap();
    let evidence = EvidenceStore::open(root.join("store")).unwrap();
    let started = Instant::now();
    let observation = invoke_conformance(
        &campaign,
        &InvokeOptions {
            grants: campaign.required_grants.iter().cloned().collect(),
            ..InvokeOptions::default()
        },
        &root,
        &evidence,
    )
    .unwrap();
    let elapsed = started.elapsed();

    assert_eq!(observation.executed, campaign.cases.len());
    assert!(
        elapsed >= expected,
        "campaign ran in {elapsed:?}, faster than the declared {expected:?} pacing"
    );

    drop(evidence);
    remove_temporary_store(&root);
}
