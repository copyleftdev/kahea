//! Byte-exact golden for the generator's full schema surface, plus the
//! fail-closed edges that a golden cannot express.
//!
//! A golden earns its keep here because most of the generator's decisions pick
//! among values that are all schema-valid. Which corner, which union branch,
//! which optional property: a semantic assertion cannot see those choices
//! change, so only frozen bytes hold them still.

use kahea_conformance::{
    ConformanceError, ConformanceMode, ConformanceOptions, build_conformance_plan,
};
use kahea_core::RequestPlan;
use kahea_ingest::{OpenApiSource, OperationDefinition, load_openapi, resolve_operation};
use kahea_plan::{PlanOptions, ProjectConfiguration};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

const GOLDEN_SEED: u64 = 42;
const GOLDEN_CASES: usize = 12;

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn surface() -> (OpenApiSource, OperationDefinition) {
    let path = fixture_path("conformance/generator-surface.openapi.yaml");
    let bytes = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let source = load_openapi(&path, &bytes).expect("surface fixture is not loadable");
    let operation = resolve_operation(&source, "writeSurface").unwrap();
    (source, operation)
}

fn build(
    source: &OpenApiSource,
    operation: &OperationDefinition,
    options: ConformanceOptions,
) -> Result<(kahea_core::ConformancePlan, Vec<RequestPlan>), ConformanceError> {
    build_conformance_plan(source, operation, options, &ProjectConfiguration::default())
}

/// A human-readable projection of a campaign: everything a generated request
/// puts on the wire, so a golden mismatch names the field that moved instead of
/// only reporting a changed digest.
fn projection(campaign: &kahea_core::ConformancePlan, requests: &[RequestPlan]) -> Value {
    let cases: Vec<Value> = campaign
        .cases
        .iter()
        .zip(requests)
        .map(|(case, request)| {
            json!({
                "generation": case.generation,
                "strategy": case.strategy,
                "method": request.method,
                "target": request.target,
                "headers": request.headers,
                "body": request.body.as_ref().map(|body| {
                    serde_json::from_str::<Value>(&body.inline)
                        .unwrap_or_else(|_| Value::String(body.inline.clone()))
                }),
            })
        })
        .collect();
    json!({
        "seed": campaign.seed,
        "requested_cases": campaign.requested_cases,
        "fingerprint": campaign.fingerprint,
        "required_grants": campaign.required_grants,
        "cases": cases,
    })
}

#[test]
fn the_full_generator_surface_matches_its_golden_bytes() {
    let (source, operation) = surface();
    let (campaign, requests) = build(
        &source,
        &operation,
        ConformanceOptions {
            cases: GOLDEN_CASES,
            seed: GOLDEN_SEED,
            mode: ConformanceMode::Mixed,
            ..ConformanceOptions::default()
        },
    )
    .expect("the surface fixture must generate");

    let mut rendered = serde_json::to_vec_pretty(&projection(&campaign, &requests)).unwrap();
    rendered.push(b'\n');
    let golden = fixture_path("golden/generator-surface.conformance.json");

    if std::env::var_os("KAHEA_UPDATE_GOLDEN").is_some() {
        fs::create_dir_all(golden.parent().unwrap()).unwrap();
        fs::write(&golden, &rendered).unwrap();
        return;
    }

    let expected = fs::read(&golden).unwrap_or_else(|error| {
        panic!(
            "read {}: {error}\nregenerate with KAHEA_UPDATE_GOLDEN=1",
            golden.display()
        )
    });
    if rendered != expected {
        let left: Value = serde_json::from_slice(&rendered).unwrap();
        let right: Value = serde_json::from_slice(&expected).unwrap();
        for (index, (actual, wanted)) in left["cases"]
            .as_array()
            .unwrap()
            .iter()
            .zip(right["cases"].as_array().unwrap())
            .enumerate()
        {
            assert_eq!(actual, wanted, "generated case {index} drifted from golden");
        }
        assert_eq!(left, right, "campaign metadata drifted from golden");
        panic!("golden bytes differ but every field compared equal");
    }
}

#[test]
fn the_golden_campaign_is_reproducible_within_a_run() {
    let (source, operation) = surface();
    let options = || ConformanceOptions {
        cases: GOLDEN_CASES,
        seed: GOLDEN_SEED,
        mode: ConformanceMode::Mixed,
        ..ConformanceOptions::default()
    };
    let first = build(&source, &operation, options()).unwrap();
    let second = build(&source, &operation, options()).unwrap();
    assert_eq!(
        serde_json::to_vec(&projection(&first.0, &first.1)).unwrap(),
        serde_json::to_vec(&projection(&second.0, &second.1)).unwrap()
    );
}

fn body_of(plan: &RequestPlan) -> Value {
    serde_json::from_str(&plan.body.as_ref().expect("generated body").inline).unwrap()
}

fn positive_bodies(seeds: u64) -> Vec<Value> {
    let (source, operation) = surface();
    let mut bodies = Vec::new();
    for seed in 0..seeds {
        let (_, requests) = build(
            &source,
            &operation,
            ConformanceOptions {
                cases: 4,
                seed,
                mode: ConformanceMode::Positive,
                ..ConformanceOptions::default()
            },
        )
        .unwrap_or_else(|error| panic!("seed {seed}: {error}"));
        bodies.extend(requests.iter().map(body_of));
    }
    bodies
}

#[test]
fn declared_constructs_produce_their_declared_shapes() {
    let bodies = positive_bodies(8);
    assert!(!bodies.is_empty());
    for body in &bodies {
        assert_eq!(body["fixed"], "immutable", "const was not honoured");
        assert!(["alpha", "beta", "gamma"].contains(&body["choice"].as_str().unwrap()));
        assert!(body["nothing"].is_null(), "null type was not honoured");
        assert!(body["flag"].is_boolean());
        assert!(
            body["multi"].is_string() || body["multi"].is_number(),
            "a union of declared types produced {}",
            body["multi"]
        );
        assert!(
            body["merged"]["a"].is_string() && body["merged"]["b"].is_number(),
            "allOf did not merge both branches: {}",
            body["merged"]
        );
        assert!(body["either"].is_boolean() || body["either"].is_null());
        assert!(
            body["union"].is_number() || ["x", "y"].contains(&body["union"].as_str().unwrap_or("")),
            "oneOf produced {}",
            body["union"]
        );
        assert_eq!(body["dated"], "2026-08-05");
        assert_eq!(body["stamped"], "2026-08-05T00:00:00Z");
        assert_eq!(body["mail"], "kahea@example.test");
        assert_eq!(body["ident"], "00000000-0000-4000-8000-000000000001");
        assert_eq!(body["link"], "https://example.test/resource");
        assert_eq!(body["host"], "example.test");
        assert_eq!(body["v4"], "192.0.2.1");
        assert_eq!(body["v6"], "2001:db8::1");
        assert_eq!(body["raw"], "a2FoZWE=");
        assert!(
            body["digits"]
                .as_str()
                .unwrap()
                .chars()
                .all(|c| c.is_ascii_digit()),
            "digit pattern produced {}",
            body["digits"]
        );
        assert!(
            body["upper"]
                .as_str()
                .unwrap()
                .chars()
                .all(|c| c.is_ascii_uppercase())
        );
        assert!(
            body["lower"]
                .as_str()
                .unwrap()
                .chars()
                .all(|c| c.is_ascii_lowercase())
        );
        assert!(body["reffed"]["label"].is_string(), "$ref was not resolved");

        let nested = body["nested"].as_object().unwrap();
        assert!(nested.contains_key("p"), "required nested key is missing");
        assert!(
            nested.len() >= 2,
            "minProperties was not satisfied: {nested:?}"
        );
        let guarded = body["guarded"].as_object().unwrap();
        assert!(!guarded.is_empty(), "minProperties left an object empty");
        assert!(
            !guarded.contains_key("hidden"),
            "a readOnly property was generated: {guarded:?}"
        );
    }

    let sampled: Vec<&str> = bodies
        .iter()
        .filter_map(|body| body["sampled"].as_str())
        .collect();
    assert!(
        sampled
            .iter()
            .any(|value| ["one", "two", "three"].contains(value)),
        "declared examples were never drawn: {sampled:?}"
    );
    let exampled: Vec<&str> = bodies
        .iter()
        .filter_map(|body| body["exampled"].as_str())
        .collect();
    assert!(
        exampled.contains(&"from-example"),
        "a declared example was never used: {exampled:?}"
    );
    assert!(
        bodies
            .iter()
            .any(|body| body["defaulted"].as_i64() == Some(41)),
        "a declared default was never used"
    );
}

/// A cycle whose back-edge runs through exactly one construct. Routing every
/// cycle through object properties would hide a broken depth count elsewhere:
/// the surviving increment still reaches the limit, just later.
fn recursive_spec(node: &str) -> String {
    format!(
        r##"{{
          "openapi": "3.1.0",
          "info": {{"title": "cycle", "version": "1"}},
          "servers": [{{"url": "https://api.example.test"}}],
          "paths": {{"/cycle": {{"post": {{
            "operationId": "postCycle",
            "requestBody": {{"required": true, "content": {{"application/json": {{
              "schema": {{"$ref": "#/components/schemas/Node"}}
            }}}}}},
            "responses": {{"200": {{"description": "ok"}}}}
          }}}}}},
          "components": {{"schemas": {{"Node": {node}}}}}
        }}"##
    )
}

#[test]
fn self_referential_schemas_stop_at_the_depth_limit() {
    for (label, node) in [
        (
            "object",
            r##"{"type": "object", "required": ["child"],
                 "properties": {"child": {"$ref": "#/components/schemas/Node"}}}"##,
        ),
        (
            "array",
            r##"{"type": "array", "minItems": 1, "maxItems": 1,
                 "items": {"$ref": "#/components/schemas/Node"}}"##,
        ),
        (
            "oneOf",
            r##"{"oneOf": [{"$ref": "#/components/schemas/Node"}]}"##,
        ),
        (
            "anyOf",
            r##"{"anyOf": [{"$ref": "#/components/schemas/Node"}]}"##,
        ),
        (
            "allOf",
            r##"{"allOf": [{"$ref": "#/components/schemas/Node"}]}"##,
        ),
    ] {
        let spec = recursive_spec(node);
        let source = load_openapi(Path::new("cycle.json"), spec.as_bytes()).unwrap();
        let operation = resolve_operation(&source, "postCycle").unwrap();
        let result = build(
            &source,
            &operation,
            ConformanceOptions {
                cases: 2,
                seed: 1,
                mode: ConformanceMode::Positive,
                ..ConformanceOptions::default()
            },
        );
        match result {
            Err(ConformanceError::Generation { reason, .. }) => assert!(
                reason.contains("32 levels"),
                "{label} cycle stopped for the wrong reason: {reason}"
            ),
            other => panic!(
                "{label} cycle did not stop at the depth limit: {:?}",
                other.map(|(campaign, _)| campaign.id)
            ),
        }
    }
}

fn body_spec(schema: &str) -> String {
    format!(
        r#"{{
          "openapi": "3.1.0",
          "info": {{"title": "edge", "version": "1"}},
          "servers": [{{"url": "https://api.example.test"}}],
          "paths": {{"/edge": {{"post": {{
            "operationId": "postEdge",
            "requestBody": {{"required": true, "content": {{"application/json": {{"schema": {schema}}}}}}},
            "responses": {{"200": {{"description": "ok"}}}}
          }}}}}}
        }}"#
    )
}

fn edge(schema: &str) -> (OpenApiSource, OperationDefinition) {
    let spec = body_spec(schema);
    let source = load_openapi(Path::new("edge.json"), spec.as_bytes())
        .unwrap_or_else(|error| panic!("schema {schema} is not loadable: {error}"));
    let operation = resolve_operation(&source, "postEdge").unwrap();
    (source, operation)
}

fn edge_options() -> ConformanceOptions {
    ConformanceOptions {
        cases: 3,
        seed: 5,
        mode: ConformanceMode::Positive,
        ..ConformanceOptions::default()
    }
}

fn body_failure(schema: &str) -> String {
    let (source, operation) = edge(schema);
    match build(&source, &operation, edge_options()) {
        Err(ConformanceError::Generation { reason, .. }) => reason,
        Err(other) => panic!("schema {schema} failed for the wrong reason: {other}"),
        Ok((campaign, _)) => panic!(
            "schema {schema} generated instead of failing closed: {}",
            campaign.id
        ),
    }
}

fn body_values(schema: &str) -> Vec<Value> {
    let (source, operation) = edge(schema);
    build(&source, &operation, edge_options())
        .unwrap_or_else(|error| panic!("schema {schema} did not generate: {error}"))
        .1
        .iter()
        .map(body_of)
        .collect()
}

#[test]
fn array_bounds_are_honoured_at_their_edges_and_fail_closed_beyond_them() {
    let item = r#"{"type": "integer", "minimum": 0, "maximum": 9}"#;

    for value in body_values(&format!(
        r#"{{"type": "array", "minItems": 3, "maxItems": 3, "items": {item}}}"#
    )) {
        assert_eq!(
            value.as_array().unwrap().len(),
            3,
            "fixed length was ignored"
        );
    }
    for value in body_values(&format!(
        r#"{{"type": "array", "minItems": 16, "maxItems": 16, "items": {item}}}"#
    )) {
        assert_eq!(
            value.as_array().unwrap().len(),
            16,
            "the largest generatable array was refused"
        );
    }

    assert!(
        body_failure(&format!(
            r#"{{"type": "array", "minItems": 5, "maxItems": 2, "items": {item}}}"#
        ))
        .contains("array bounds")
    );
    assert!(
        body_failure(&format!(
            r#"{{"type": "array", "minItems": 17, "items": {item}}}"#
        ))
        .contains("array bounds")
    );
}

#[test]
fn an_unsatisfiable_unique_array_fails_closed() {
    let reason = body_failure(
        r#"{"type": "array", "minItems": 5, "maxItems": 5, "uniqueItems": true,
            "items": {"type": "string", "enum": ["a", "b"]}}"#,
    );
    assert!(
        reason.contains("unique"),
        "an impossible uniqueItems array failed for the wrong reason: {reason}"
    );
}

#[test]
fn property_count_bounds_are_honoured_at_their_edges() {
    let filled = body_values(
        r#"{"type": "object", "minProperties": 2, "required": ["a"],
            "properties": {"a": {"type": "string", "minLength": 1, "maxLength": 2},
                           "b": {"type": "integer", "minimum": 0, "maximum": 9},
                           "c": {"type": "boolean"}}}"#,
    );
    for value in &filled {
        let object = value.as_object().unwrap();
        assert!(object.contains_key("a"), "required key was dropped");
        assert!(
            object.len() >= 2,
            "minProperties was not filled: {object:?}"
        );
    }

    let exact = body_values(
        r#"{"type": "object", "maxProperties": 2, "required": ["a", "b"],
            "properties": {"a": {"type": "string", "minLength": 1, "maxLength": 2},
                           "b": {"type": "integer", "minimum": 0, "maximum": 9}}}"#,
    );
    for value in &exact {
        assert_eq!(
            value.as_object().unwrap().len(),
            2,
            "a schema whose required set exactly fills maxProperties was altered"
        );
    }

    assert!(
        body_failure(
            r#"{"type": "object", "minProperties": 3,
                "properties": {"a": {"type": "string", "minLength": 1, "maxLength": 2}}}"#
        )
        .contains("minProperties")
    );
    assert!(
        body_failure(
            r#"{"type": "object", "maxProperties": 2, "required": ["a", "b", "c"],
                "properties": {"a": {"type": "string", "minLength": 1, "maxLength": 2},
                               "b": {"type": "integer", "minimum": 0, "maximum": 9},
                               "c": {"type": "boolean"}}}"#
        )
        .contains("maxProperties")
    );
}

#[test]
fn a_read_only_property_is_never_generated_even_to_reach_min_properties() {
    for value in body_values(
        r#"{"type": "object", "minProperties": 1,
            "properties": {"hidden": {"type": "string", "readOnly": true, "minLength": 1, "maxLength": 2},
                           "shown": {"type": "string", "minLength": 1, "maxLength": 2}}}"#,
    ) {
        let object = value.as_object().unwrap();
        assert!(!object.is_empty(), "minProperties left the object empty");
        assert!(
            !object.contains_key("hidden"),
            "a readOnly property was generated: {object:?}"
        );
    }
}

#[test]
fn declared_pacing_is_accepted_at_its_limit_and_refused_beyond_it() {
    let (source, operation) = surface();
    let at_limit = build(
        &source,
        &operation,
        ConformanceOptions {
            cases: 2,
            delay_ms: 60_000,
            mode: ConformanceMode::Positive,
            ..ConformanceOptions::default()
        },
    );
    assert!(at_limit.is_ok(), "the maximum declared pacing was refused");

    let beyond = build(
        &source,
        &operation,
        ConformanceOptions {
            cases: 2,
            delay_ms: 60_001,
            mode: ConformanceMode::Positive,
            ..ConformanceOptions::default()
        },
    );
    assert!(matches!(beyond, Err(ConformanceError::InvalidOption(_))));
}

const TWO_MEDIA_TYPES: &str = r#"{
  "openapi": "3.1.0",
  "info": {"title": "media", "version": "1"},
  "servers": [{"url": "https://api.example.test"}],
  "paths": {"/media": {"post": {
    "operationId": "postMedia",
    "requestBody": {"required": true, "content": {
      "application/json": {"schema": {"type": "object", "required": ["a"],
        "properties": {"a": {"type": "string", "minLength": 1, "maxLength": 3}}}},
      "text/plain": {"schema": {"type": "string", "minLength": 1, "maxLength": 5}}
    }},
    "responses": {"200": {"description": "ok"}}
  }}}
}"#;

#[test]
fn an_explicit_content_type_is_selected_and_an_undeclared_one_fails_closed() {
    let source = load_openapi(Path::new("media.json"), TWO_MEDIA_TYPES.as_bytes()).unwrap();
    let operation = resolve_operation(&source, "postMedia").unwrap();
    let with = |content_type: &str| ConformanceOptions {
        cases: 2,
        seed: 3,
        mode: ConformanceMode::Positive,
        plan: PlanOptions {
            content_type: Some(content_type.into()),
            ..PlanOptions::default()
        },
        ..ConformanceOptions::default()
    };

    let (_, requests) = build(&source, &operation, with("text/plain")).unwrap();
    for request in &requests {
        assert_eq!(
            request.body.as_ref().unwrap().media_type,
            "text/plain",
            "the requested content type was not selected"
        );
    }

    let (_, defaulted) = build(
        &source,
        &operation,
        ConformanceOptions {
            cases: 2,
            seed: 3,
            mode: ConformanceMode::Positive,
            ..ConformanceOptions::default()
        },
    )
    .unwrap();
    assert!(
        defaulted
            .iter()
            .all(|request| request.body.as_ref().unwrap().media_type.contains("json")),
        "JSON was not preferred by default"
    );

    match build(&source, &operation, with("application/xml")) {
        Err(ConformanceError::Generation { reason, .. }) => {
            assert!(
                reason.contains("not declared"),
                "unexpected reason: {reason}"
            )
        }
        other => panic!(
            "an undeclared content type was accepted: {:?}",
            other.map(|(campaign, _)| campaign.id)
        ),
    }
}

#[test]
fn an_explicit_nested_body_override_survives_generation() {
    let (source, operation) = surface();
    let (_, requests) = build(
        &source,
        &operation,
        ConformanceOptions {
            cases: 4,
            seed: 6,
            mode: ConformanceMode::Positive,
            plan: PlanOptions {
                explicit: vec![
                    ("body.nested.p".into(), json!("pinned")),
                    ("body.choice".into(), json!("beta")),
                ],
                ..PlanOptions::default()
            },
            ..ConformanceOptions::default()
        },
    )
    .unwrap();
    assert!(!requests.is_empty());
    for request in &requests {
        let body = body_of(request);
        assert_eq!(body["nested"]["p"], "pinned", "a nested override was lost");
        assert_eq!(body["choice"], "beta", "a top-level override was lost");
    }
}

const OPTIONAL_BODY: &str = r#"{
  "openapi": "3.1.0",
  "info": {"title": "optional", "version": "1"},
  "servers": [{"url": "https://api.example.test"}],
  "paths": {"/optional": {"post": {
    "operationId": "postOptional",
    "parameters": [
      {"name": "trace", "in": "query", "schema": {"type": "string", "minLength": 1, "maxLength": 4}},
      {"name": "X-Hint", "in": "header", "schema": {"type": "integer", "minimum": 0, "maximum": 9}}
    ],
    "requestBody": {"content": {"application/json": {"schema": {
      "type": "object",
      "properties": {
        "a": {"type": "string", "minLength": 1, "maxLength": 3},
        "b": {"type": "integer", "minimum": 0, "maximum": 9},
        "c": {"type": "boolean"},
        "d": {"type": "string", "enum": ["p", "q", "r"]}
      }
    }}}},
    "responses": {"200": {"description": "ok"}}
  }}}
}"#;

/// Two scenarios a single golden cannot cover: an optional body and optional
/// parameters, whose inclusion is a coin flip the generator owns; and a supplied
/// baseline, which routes generation through a different code path that decides
/// which further properties to fill in around the values it was given.
#[test]
fn optional_inclusion_and_baseline_filling_match_their_golden_bytes() {
    let optional_source =
        load_openapi(Path::new("optional.json"), OPTIONAL_BODY.as_bytes()).unwrap();
    let optional_operation = resolve_operation(&optional_source, "postOptional").unwrap();
    let (optional_campaign, optional_requests) = build(
        &optional_source,
        &optional_operation,
        ConformanceOptions {
            cases: 10,
            seed: GOLDEN_SEED,
            mode: ConformanceMode::Positive,
            ..ConformanceOptions::default()
        },
    )
    .expect("the optional fixture must generate");

    let (source, operation) = surface();
    let (baseline_campaign, baseline_requests) = build(
        &source,
        &operation,
        ConformanceOptions {
            cases: 6,
            seed: GOLDEN_SEED,
            mode: ConformanceMode::Positive,
            input: Some(json!({
                "body": {
                    "choice": "beta",
                    "nested": {"p": "pin"},
                    "reffed": {"label": "fixed"}
                }
            })),
            ..ConformanceOptions::default()
        },
    )
    .expect("the baseline scenario must generate");

    let rendered = json!({
        "optional": projection(&optional_campaign, &optional_requests),
        "baseline": projection(&baseline_campaign, &baseline_requests),
    });
    let mut rendered = serde_json::to_vec_pretty(&rendered).unwrap();
    rendered.push(b'\n');
    let golden = fixture_path("golden/generator-baseline.conformance.json");

    if std::env::var_os("KAHEA_UPDATE_GOLDEN").is_some() {
        fs::create_dir_all(golden.parent().unwrap()).unwrap();
        fs::write(&golden, &rendered).unwrap();
        return;
    }

    let expected = fs::read(&golden).unwrap_or_else(|error| {
        panic!(
            "read {}: {error}\nregenerate with KAHEA_UPDATE_GOLDEN=1",
            golden.display()
        )
    });
    if rendered != expected {
        let left: Value = serde_json::from_slice(&rendered).unwrap();
        let right: Value = serde_json::from_slice(&expected).unwrap();
        for scenario in ["optional", "baseline"] {
            assert_eq!(
                left[scenario], right[scenario],
                "the {scenario} scenario drifted from golden"
            );
        }
        panic!("golden bytes differ but every scenario compared equal");
    }
}

#[test]
fn a_supplied_baseline_is_never_regenerated() {
    let (source, operation) = surface();
    let (_, requests) = build(
        &source,
        &operation,
        ConformanceOptions {
            cases: 8,
            seed: 11,
            mode: ConformanceMode::Positive,
            input: Some(json!({
                "body": {
                    "choice": "beta",
                    "nested": {"p": "pin"},
                    "reffed": {"label": "fixed"}
                }
            })),
            ..ConformanceOptions::default()
        },
    )
    .unwrap();
    assert!(!requests.is_empty());
    for request in &requests {
        let body = body_of(request);
        assert_eq!(body["choice"], "beta");
        assert_eq!(body["nested"]["p"], "pin");
        assert_eq!(body["reffed"]["label"], "fixed");
        assert!(
            body["dated"].is_string(),
            "a property absent from the baseline was not filled in"
        );
    }
}

#[test]
fn an_optional_body_and_optional_parameters_are_both_sometimes_present() {
    let source = load_openapi(Path::new("optional.json"), OPTIONAL_BODY.as_bytes()).unwrap();
    let operation = resolve_operation(&source, "postOptional").unwrap();
    let (_, requests) = build(
        &source,
        &operation,
        ConformanceOptions {
            cases: 16,
            seed: 4,
            mode: ConformanceMode::Positive,
            ..ConformanceOptions::default()
        },
    )
    .unwrap();

    assert!(
        requests.iter().any(|request| request.body.is_some()),
        "an optional body was never generated"
    );
    assert!(
        requests.iter().any(|request| request.body.is_none()),
        "an optional body was always generated"
    );
    assert!(
        requests
            .iter()
            .any(|request| request.target.contains("trace=")),
        "an optional query parameter was never generated"
    );
    assert!(
        requests
            .iter()
            .any(|request| !request.target.contains("trace=")),
        "an optional query parameter was always generated"
    );
}

#[test]
fn array_lengths_span_the_whole_declared_range() {
    let lengths: std::collections::BTreeSet<usize> = (0..12_u64)
        .flat_map(|seed| {
            let (source, operation) = edge(
                r#"{"type": "array", "minItems": 2, "maxItems": 5,
                    "items": {"type": "integer", "minimum": 0, "maximum": 9}}"#,
            );
            build(
                &source,
                &operation,
                ConformanceOptions {
                    cases: 4,
                    seed,
                    mode: ConformanceMode::Positive,
                    ..ConformanceOptions::default()
                },
            )
            .unwrap()
            .1
            .iter()
            .map(|plan| body_of(plan).as_array().unwrap().len())
            .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(
        lengths,
        [2, 3, 4, 5].into_iter().collect(),
        "array generation did not span its declared range"
    );
}

#[test]
fn string_length_limits_are_honoured_at_their_edge_and_fail_closed_beyond_it() {
    let at_limit = body_values(r#"{"type": "string", "minLength": 1024, "maxLength": 1024}"#);
    for value in &at_limit {
        assert_eq!(
            value.as_str().unwrap().len(),
            1024,
            "the longest generatable string was altered"
        );
    }
    assert!(
        body_failure(r#"{"type": "string", "minLength": 1025}"#).contains("string bounds"),
        "a string beyond the generation limit did not fail closed"
    );
    assert!(
        body_failure(r#"{"type": "string", "minLength": 8, "maxLength": 4}"#)
            .contains("string bounds")
    );
}

const ONE_PARAMETER: &str = r#"{
  "openapi": "3.1.0",
  "info": {"title": "sparse", "version": "1"},
  "servers": [{"url": "https://api.example.test"}],
  "paths": {"/sparse": {"get": {
    "operationId": "getSparse",
    "parameters": [
      {"name": "q", "in": "query", "required": true,
       "schema": {"type": "string", "minLength": 1, "maxLength": 4}}
    ],
    "responses": {"200": {"description": "ok"}}
  }}}
}"#;

#[test]
fn negative_cases_accumulate_across_positive_plans() {
    let source = load_openapi(Path::new("sparse.json"), ONE_PARAMETER.as_bytes()).unwrap();
    let operation = resolve_operation(&source, "getSparse").unwrap();
    let (campaign, _) = build(
        &source,
        &operation,
        ConformanceOptions {
            cases: 6,
            seed: 2,
            mode: ConformanceMode::Negative,
            ..ConformanceOptions::default()
        },
    )
    .expect("a sparse operation must still fill its negative quota");
    assert_eq!(
        campaign.cases.len(),
        6,
        "the negative pool stopped at the first positive plan instead of accumulating"
    );
}

#[test]
fn an_explicit_override_supplies_a_value_the_generator_cannot_infer() {
    let schema = r#"{"type": "object", "required": ["code"],
        "properties": {"code": {"type": "string", "pattern": "^[!@]{2}$"}}}"#;
    let (source, operation) = edge(schema);
    assert!(
        build(&source, &operation, edge_options()).is_err(),
        "the bounded generator claimed to handle an arbitrary pattern"
    );

    let (_, requests) = build(
        &source,
        &operation,
        ConformanceOptions {
            plan: PlanOptions {
                explicit: vec![("body.code".into(), json!("!@"))],
                ..PlanOptions::default()
            },
            ..edge_options()
        },
    )
    .expect("an explicit override must reach the baseline and unblock generation");
    for request in &requests {
        assert_eq!(body_of(request)["code"], "!@");
    }
}

#[test]
fn a_baseline_is_filled_out_even_when_the_schema_omits_its_type() {
    let (source, operation) = edge(
        r#"{"required": ["a", "b"],
            "properties": {"a": {"type": "string", "minLength": 1, "maxLength": 3},
                           "b": {"type": "integer", "minimum": 0, "maximum": 9}}}"#,
    );
    let (_, requests) = build(
        &source,
        &operation,
        ConformanceOptions {
            input: Some(json!({"body": {"a": "ab"}})),
            ..edge_options()
        },
    )
    .expect("a typeless object schema must still accept a baseline");
    assert!(!requests.is_empty());
    for request in &requests {
        let body = body_of(request);
        assert_eq!(body["a"], "ab", "the supplied baseline was overwritten");
        assert!(
            body["b"].is_number(),
            "a required property was not filled in around the baseline: {body}"
        );
    }
}

#[test]
fn a_baseline_deeper_than_the_generation_limit_fails_closed() {
    let spec = recursive_spec(
        r##"{"type": "object",
             "properties": {"child": {"$ref": "#/components/schemas/Node"}}}"##,
    );
    let source = load_openapi(Path::new("cycle.json"), spec.as_bytes()).unwrap();
    let operation = resolve_operation(&source, "postCycle").unwrap();

    let mut deep = json!({});
    for _ in 0..40 {
        deep = json!({ "child": deep });
    }
    match build(
        &source,
        &operation,
        ConformanceOptions {
            input: Some(json!({ "body": deep })),
            ..edge_options()
        },
    ) {
        Err(ConformanceError::Generation { reason, .. }) => assert!(
            reason.contains("32 levels"),
            "a deep baseline stopped for the wrong reason: {reason}"
        ),
        other => panic!(
            "a baseline deeper than the limit was accepted: {:?}",
            other.map(|(campaign, _)| campaign.id)
        ),
    }
}
