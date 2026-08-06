//! The generator's contract: every positive case is schema-valid, every
//! negative case violates the schema in the way its strategy names, and the
//! declared bounds are actually explored across seeds.

use kahea_conformance::{
    ConformanceError, ConformanceMode, ConformanceOptions, build_conformance_plan,
};
use kahea_core::RequestPlan;
use kahea_ingest::{OpenApiSource, OperationDefinition, load_openapi, resolve_operation};
use kahea_plan::ProjectConfiguration;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::Path;

const SPEC: &str = r#"
openapi: 3.1.0
info: { title: Generation, version: 1 }
servers: [{ url: "https://api.example.test" }]
paths:
  /widgets/{id}:
    post:
      operationId: updateWidget
      parameters:
        - { name: id, in: path, required: true, schema: { type: string, minLength: 3, maxLength: 6 } }
        - { name: limit, in: query, required: true, schema: { type: integer, minimum: 10, maximum: 40, multipleOf: 5 } }
        - { name: mode, in: query, required: true, schema: { type: string, enum: [fast, slow] } }
        - { name: X-Trace, in: header, required: true, schema: { type: string, minLength: 4, maxLength: 4 } }
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              additionalProperties: false
              required: [name, count, ratio, tags, nested, choice, when]
              properties:
                name: { type: string, minLength: 2, maxLength: 12 }
                count: { type: integer, minimum: -5, maximum: 25, multipleOf: 5 }
                ratio: { type: number, minimum: 0.5, maximum: 2.5 }
                flag: { type: boolean }
                when: { type: string, format: date-time }
                tags:
                  type: array
                  minItems: 2
                  maxItems: 3
                  uniqueItems: true
                  items: { type: string, minLength: 1, maxLength: 3 }
                nested:
                  type: object
                  required: [inner]
                  properties:
                    inner: { type: string, enum: [alpha, beta, gamma] }
                choice:
                  oneOf:
                    - { type: integer, minimum: 1, maximum: 3 }
                    - { type: string, enum: ["x", "y"] }
      responses:
        "200": { description: ok }
        "400": { description: rejected }
"#;

fn fixture() -> (OpenApiSource, OperationDefinition) {
    let source = load_openapi(Path::new("generation.yaml"), SPEC.as_bytes()).unwrap();
    let operation = resolve_operation(&source, "updateWidget").unwrap();
    (source, operation)
}

fn campaign(seed: u64, cases: usize, mode: ConformanceMode) -> Vec<RequestPlan> {
    let (source, operation) = fixture();
    build_conformance_plan(
        &source,
        &operation,
        ConformanceOptions {
            cases,
            seed,
            mode,
            ..ConformanceOptions::default()
        },
        &ProjectConfiguration::default(),
    )
    .unwrap_or_else(|error| panic!("seed {seed} failed to generate: {error}"))
    .1
}

fn body_schema() -> Value {
    let (source, _) = fixture();
    source.document["paths"]["/widgets/{id}"]["post"]["requestBody"]["content"]["application/json"]
        ["schema"]
        .clone()
}

fn parameter_schemas() -> Vec<(String, Value)> {
    let (source, _) = fixture();
    source.document["paths"]["/widgets/{id}"]["post"]["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|parameter| {
            (
                format!(
                    "{}.{}",
                    parameter["in"].as_str().unwrap(),
                    parameter["name"].as_str().unwrap()
                ),
                parameter["schema"].clone(),
            )
        })
        .collect()
}

fn body_of(plan: &RequestPlan) -> Value {
    serde_json::from_str(&plan.body.as_ref().expect("generated body").inline)
        .expect("generated body is not JSON")
}

/// A validator for exactly the keyword subset this fixture declares. It exists
/// so a generated value is checked against the contract, never against another
/// run of the same generator.
fn validate(schema: &Value, value: &Value, path: &str) -> Result<(), String> {
    let fail = |reason: &str| Err(format!("{path}: {reason} (value {value})"));

    if let Some(branches) = schema.get("oneOf").or_else(|| schema.get("anyOf")) {
        let branches = branches.as_array().unwrap();
        return if branches
            .iter()
            .any(|branch| validate(branch, value, path).is_ok())
        {
            Ok(())
        } else {
            fail("matches no declared union branch")
        };
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array)
        && !values.contains(value)
    {
        return fail("is outside the declared enum");
    }

    match schema.get("type").and_then(Value::as_str) {
        Some("string") => {
            let Some(text) = value.as_str() else {
                return fail("is not a string");
            };
            let length = text.chars().count() as u64;
            if let Some(minimum) = schema.get("minLength").and_then(Value::as_u64)
                && length < minimum
            {
                return fail(&format!("is shorter than minLength {minimum}"));
            }
            if let Some(maximum) = schema.get("maxLength").and_then(Value::as_u64)
                && length > maximum
            {
                return fail(&format!("is longer than maxLength {maximum}"));
            }
            if schema.get("format").and_then(Value::as_str) == Some("date-time")
                && !(text.len() >= 20 && text.contains('T') && text.ends_with('Z'))
            {
                return fail("is not an RFC 3339 date-time");
            }
        }
        Some("integer") => {
            let Some(number) = value.as_i64() else {
                return fail("is not an integer");
            };
            if let Some(minimum) = schema.get("minimum").and_then(Value::as_i64)
                && number < minimum
            {
                return fail(&format!("is below minimum {minimum}"));
            }
            if let Some(maximum) = schema.get("maximum").and_then(Value::as_i64)
                && number > maximum
            {
                return fail(&format!("is above maximum {maximum}"));
            }
            if let Some(multiple) = schema.get("multipleOf").and_then(Value::as_i64)
                && number % multiple != 0
            {
                return fail(&format!("is not a multiple of {multiple}"));
            }
        }
        Some("number") => {
            let Some(number) = value.as_f64() else {
                return fail("is not a number");
            };
            if let Some(minimum) = schema.get("minimum").and_then(Value::as_f64)
                && number < minimum
            {
                return fail(&format!("is below minimum {minimum}"));
            }
            if let Some(maximum) = schema.get("maximum").and_then(Value::as_f64)
                && number > maximum
            {
                return fail(&format!("is above maximum {maximum}"));
            }
        }
        Some("boolean") => {
            if !value.is_boolean() {
                return fail("is not a boolean");
            }
        }
        Some("array") => {
            let Some(items) = value.as_array() else {
                return fail("is not an array");
            };
            let length = items.len() as u64;
            if let Some(minimum) = schema.get("minItems").and_then(Value::as_u64)
                && length < minimum
            {
                return fail(&format!("has fewer than minItems {minimum}"));
            }
            if let Some(maximum) = schema.get("maxItems").and_then(Value::as_u64)
                && length > maximum
            {
                return fail(&format!("has more than maxItems {maximum}"));
            }
            if schema.get("uniqueItems") == Some(&Value::Bool(true)) {
                let unique: BTreeSet<_> = items.iter().map(Value::to_string).collect();
                if unique.len() != items.len() {
                    return fail("repeats an item despite uniqueItems");
                }
            }
            if let Some(item_schema) = schema.get("items") {
                for (index, item) in items.iter().enumerate() {
                    validate(item_schema, item, &format!("{path}[{index}]"))?;
                }
            }
        }
        Some("object") | None if schema.get("properties").is_some() || value.is_object() => {
            let Some(object) = value.as_object() else {
                return fail("is not an object");
            };
            for name in schema
                .get("required")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                if !object.contains_key(name) {
                    return Err(format!("{path}: required property {name:?} is missing"));
                }
            }
            let properties = schema.get("properties").and_then(Value::as_object);
            if schema.get("additionalProperties") == Some(&Value::Bool(false))
                && let Some(properties) = properties
                && let Some(unknown) = object.keys().find(|key| !properties.contains_key(*key))
            {
                return Err(format!("{path}: unknown property {unknown:?}"));
            }
            if let Some(properties) = properties {
                for (name, child) in object {
                    if let Some(child_schema) = properties.get(name) {
                        validate(child_schema, child, &format!("{path}.{name}"))?;
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
}

#[test]
fn the_validator_rejects_the_violations_it_is_meant_to_catch() {
    let schema = body_schema();
    let valid = serde_json::json!({
        "name": "widget",
        "count": 5,
        "ratio": 1.5,
        "when": "2026-08-05T00:00:00Z",
        "tags": ["a", "bb"],
        "nested": {"inner": "beta"},
        "choice": 2
    });
    validate(&schema, &valid, "body").expect("a conforming body was rejected");

    for (label, mutation) in [
        ("missing required", serde_json::json!({"count": 5})),
        (
            "short string",
            serde_json::json!({"name": "x", "count": 5, "ratio": 1.5, "when": "2026-08-05T00:00:00Z", "tags": ["a", "bb"], "nested": {"inner": "beta"}, "choice": 2}),
        ),
        (
            "out of range integer",
            serde_json::json!({"name": "widget", "count": 30, "ratio": 1.5, "when": "2026-08-05T00:00:00Z", "tags": ["a", "bb"], "nested": {"inner": "beta"}, "choice": 2}),
        ),
        (
            "wrong multiple",
            serde_json::json!({"name": "widget", "count": 7, "ratio": 1.5, "when": "2026-08-05T00:00:00Z", "tags": ["a", "bb"], "nested": {"inner": "beta"}, "choice": 2}),
        ),
        (
            "repeated unique item",
            serde_json::json!({"name": "widget", "count": 5, "ratio": 1.5, "when": "2026-08-05T00:00:00Z", "tags": ["a", "a"], "nested": {"inner": "beta"}, "choice": 2}),
        ),
        (
            "value outside enum",
            serde_json::json!({"name": "widget", "count": 5, "ratio": 1.5, "when": "2026-08-05T00:00:00Z", "tags": ["a", "bb"], "nested": {"inner": "delta"}, "choice": 2}),
        ),
        (
            "unknown property",
            serde_json::json!({"name": "widget", "count": 5, "ratio": 1.5, "when": "2026-08-05T00:00:00Z", "tags": ["a", "bb"], "nested": {"inner": "beta"}, "choice": 2, "extra": true}),
        ),
        (
            "no union branch",
            serde_json::json!({"name": "widget", "count": 5, "ratio": 1.5, "when": "2026-08-05T00:00:00Z", "tags": ["a", "bb"], "nested": {"inner": "beta"}, "choice": 9}),
        ),
    ] {
        assert!(
            validate(&schema, &mutation, "body").is_err(),
            "the validator accepted a body with a {label}"
        );
    }
}

#[test]
fn every_generated_positive_body_satisfies_the_declared_schema() {
    let schema = body_schema();
    for seed in 0..24_u64 {
        for plan in campaign(seed, 6, ConformanceMode::Positive) {
            assert!(plan.valid, "a positive case was marked invalid");
            let body = body_of(&plan);
            validate(&schema, &body, "body")
                .unwrap_or_else(|reason| panic!("seed {seed} generated an invalid body: {reason}"));
        }
    }
}

#[test]
fn every_generated_positive_parameter_satisfies_its_declared_schema() {
    let parameters = parameter_schemas();
    for seed in 0..24_u64 {
        for plan in campaign(seed, 6, ConformanceMode::Positive) {
            for (field, schema) in &parameters {
                let Some(derivation) = plan
                    .derivations
                    .iter()
                    .find(|derivation| &derivation.field == field)
                else {
                    panic!("seed {seed} omitted required parameter {field}");
                };
                validate(schema, &derivation.logical_value, field).unwrap_or_else(|reason| {
                    panic!("seed {seed} generated an invalid parameter: {reason}")
                });
            }
        }
    }
}

#[test]
fn generation_explores_the_declared_bounds_rather_than_one_corner() {
    let mut counts = BTreeSet::new();
    let mut name_lengths = BTreeSet::new();
    let mut tag_lengths = BTreeSet::new();
    let mut modes = BTreeSet::new();
    for seed in 0..24_u64 {
        for plan in campaign(seed, 6, ConformanceMode::Positive) {
            let body = body_of(&plan);
            counts.insert(body["count"].as_i64().unwrap());
            name_lengths.insert(body["name"].as_str().unwrap().len());
            tag_lengths.insert(body["tags"].as_array().unwrap().len());
            if let Some(derivation) = plan
                .derivations
                .iter()
                .find(|derivation| derivation.field == "query.mode")
            {
                modes.insert(derivation.logical_value.to_string());
            }
        }
    }

    assert!(
        counts.contains(&-5) && counts.contains(&25),
        "integer generation never reached both declared bounds: {counts:?}"
    );
    assert!(
        name_lengths.contains(&2) && name_lengths.contains(&12),
        "string generation never reached both declared lengths: {name_lengths:?}"
    );
    assert!(
        tag_lengths.contains(&2) && tag_lengths.contains(&3),
        "array generation never reached both declared sizes: {tag_lengths:?}"
    );
    assert_eq!(modes.len(), 2, "enum generation never covered both members");
}

fn parameter_is_on_the_wire(plan: &RequestPlan, location: &str, name: &str) -> bool {
    match location {
        "query" => url::Url::parse(&plan.target)
            .unwrap()
            .query_pairs()
            .any(|(key, _)| key == name),
        "header" => plan
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case(name)),
        _ => true,
    }
}

#[test]
fn every_generated_negative_case_actually_violates_its_named_strategy() {
    let schema = body_schema();
    let parameters = parameter_schemas();
    let mut strategies = BTreeSet::new();
    let mut body_mutations = 0;
    let mut invalid_parameters = 0;
    let mut omitted_parameters = 0;

    for seed in 0..6_u64 {
        let (source, operation) = fixture();
        let (campaign, plans) = build_conformance_plan(
            &source,
            &operation,
            ConformanceOptions {
                cases: 48,
                seed,
                mode: ConformanceMode::Negative,
                ..ConformanceOptions::default()
            },
            &ProjectConfiguration::default(),
        )
        .unwrap();

        for (case, plan) in campaign.cases.iter().zip(&plans) {
            assert!(!plan.valid, "a negative case claims to be valid");
            let (kind, name) = case
                .strategy
                .split_once(':')
                .unwrap_or_else(|| panic!("strategy {:?} has no target", case.strategy));
            strategies.insert(kind.to_string());

            if kind.contains("-body") {
                body_mutations += 1;
                assert!(
                    validate(&schema, &body_of(plan), "body").is_err(),
                    "seed {seed} strategy {} left the body schema-valid",
                    case.strategy
                );
                continue;
            }

            let location = kind.rsplit('-').next().expect("strategy names a location");
            let field = format!("{location}.{name}");
            let (_, parameter) = parameters
                .iter()
                .find(|(declared, _)| declared == &field)
                .unwrap_or_else(|| {
                    panic!("strategy {} names no declared parameter", case.strategy)
                });
            let mutation = plan
                .derivations
                .iter()
                .find(|derivation| {
                    derivation.field == "conformance.mutation"
                        && derivation.source_location == case.strategy
                })
                .unwrap_or_else(|| {
                    panic!("strategy {} recorded no mutation derivation", case.strategy)
                });

            if kind.starts_with("invalid") {
                invalid_parameters += 1;
                assert!(
                    validate(parameter, &mutation.logical_value, &field).is_err(),
                    "seed {seed} strategy {} injected a schema-valid value",
                    case.strategy
                );
                assert!(
                    parameter_is_on_the_wire(plan, location, name),
                    "seed {seed} strategy {} dropped the parameter instead of corrupting it",
                    case.strategy
                );
            } else {
                omitted_parameters += 1;
                assert!(mutation.logical_value.is_null());
                assert!(
                    !parameter_is_on_the_wire(plan, location, name),
                    "seed {seed} strategy {} left the parameter on the wire",
                    case.strategy
                );
            }
        }
    }

    assert!(body_mutations > 0, "no body mutation was generated");
    assert!(invalid_parameters > 0, "no parameter was corrupted");
    assert!(omitted_parameters > 0, "no required parameter was omitted");
    for expected in [
        "omit-required-body",
        "invalid-body-value",
        "unknown-body-property",
        "invalid-query",
        "invalid-header",
        "invalid-path",
        "omit-required-query",
        "omit-required-header",
    ] {
        assert!(
            strategies.contains(expected),
            "the negative generator never produced {expected}: {strategies:?}"
        );
    }
}

fn scalar_spec(schema: &str) -> String {
    format!(
        r#"{{
          "openapi": "3.1.0",
          "info": {{"title": "numeric", "version": "1"}},
          "servers": [{{"url": "https://api.example.test"}}],
          "paths": {{"/values": {{"post": {{
            "operationId": "putValue",
            "requestBody": {{"required": true, "content": {{"application/json": {{"schema": {{
              "type": "object",
              "required": ["v"],
              "properties": {{"v": {schema}}}
            }}}}}}}},
            "responses": {{"200": {{"description": "ok"}}}}
          }}}}}}
        }}"#
    )
}

fn scalar_source(schema: &str) -> (OpenApiSource, OperationDefinition) {
    let spec = scalar_spec(schema);
    let source = load_openapi(Path::new("numeric.json"), spec.as_bytes())
        .unwrap_or_else(|error| panic!("schema {schema} produced an unusable document: {error}"));
    let operation = resolve_operation(&source, "putValue").unwrap();
    (source, operation)
}

/// Every value the generator produces for one scalar schema, across seeds.
fn scalars(schema: Value, seeds: u64) -> Vec<Value> {
    let (source, operation) = scalar_source(&schema.to_string());
    let mut values = Vec::new();
    for seed in 0..seeds {
        let (_, plans) = build_conformance_plan(
            &source,
            &operation,
            ConformanceOptions {
                cases: 4,
                seed,
                mode: ConformanceMode::Positive,
                ..ConformanceOptions::default()
            },
            &ProjectConfiguration::default(),
        )
        .unwrap_or_else(|error| panic!("schema {schema} failed at seed {seed}: {error}"));
        values.extend(plans.iter().map(|plan| body_of(plan)["v"].clone()));
    }
    assert!(!values.is_empty());
    values
}

fn floats(schema: Value, seeds: u64) -> Vec<f64> {
    scalars(schema, seeds)
        .iter()
        .map(|value| {
            value
                .as_f64()
                .unwrap_or_else(|| panic!("generated {value} is not a number"))
        })
        .collect()
}

fn integers(schema: Value, seeds: u64) -> Vec<i64> {
    scalars(schema, seeds)
        .iter()
        .map(|value| {
            value
                .as_i64()
                .unwrap_or_else(|| panic!("generated {value} is not an integer"))
        })
        .collect()
}

fn scalar_failure(schema: Value) -> String {
    scalar_failure_raw(&schema.to_string())
}

/// The reason a schema is refused. Fail-closed behaviour is only useful if the
/// diagnostic names the constraint, so the reason is part of the contract.
/// Takes raw JSON so bounds that no `serde_json::Value` can hold, such as an
/// overflowing exponent, can still be expressed.
fn scalar_failure_raw(schema: &str) -> String {
    let (source, operation) = scalar_source(schema);
    match build_conformance_plan(
        &source,
        &operation,
        ConformanceOptions {
            cases: 4,
            seed: 1,
            mode: ConformanceMode::Positive,
            ..ConformanceOptions::default()
        },
        &ProjectConfiguration::default(),
    ) {
        Err(ConformanceError::Generation { reason, .. }) => reason,
        Err(other) => panic!("schema {schema} failed for the wrong reason: {other}"),
        Ok((campaign, _)) => panic!(
            "schema {schema} was generated instead of failing closed: {}",
            campaign.id
        ),
    }
}

#[test]
fn numeric_generation_reaches_both_declared_bounds_and_their_defaults() {
    let bounded = floats(
        json!({"type": "number", "minimum": -2.5, "maximum": 7.5}),
        12,
    );
    assert!(
        bounded.iter().all(|value| (-2.5..=7.5).contains(value)),
        "a generated number left its declared range: {bounded:?}"
    );
    for corner in [-2.5, 7.5, 0.0] {
        assert!(
            bounded.contains(&corner),
            "number generation never produced {corner}: {bounded:?}"
        );
    }

    let unbounded = floats(json!({"type": "number"}), 12);
    for corner in [-100.0, 100.0, 0.0] {
        assert!(
            unbounded.contains(&corner),
            "an unbounded number never reached the default {corner}: {unbounded:?}"
        );
    }

    let unbounded_integers = integers(json!({"type": "integer"}), 12);
    for corner in [-100, 100, 0] {
        assert!(
            unbounded_integers.contains(&corner),
            "an unbounded integer never reached the default {corner}"
        );
    }
}

#[test]
fn exclusive_numeric_bounds_are_approached_but_never_touched() {
    let above = floats(
        json!({"type": "number", "exclusiveMinimum": 4.0, "maximum": 8.0}),
        12,
    );
    assert!(
        above.iter().all(|value| *value > 4.0),
        "a generated number met or crossed its exclusive minimum: {above:?}"
    );
    assert!(
        above.iter().any(|value| *value < 4.000_001),
        "generation never approached the exclusive minimum: {above:?}"
    );

    let below = floats(
        json!({"type": "number", "minimum": -8.0, "exclusiveMaximum": -4.0}),
        12,
    );
    assert!(
        below.iter().all(|value| *value < -4.0),
        "a generated number met or crossed its exclusive maximum: {below:?}"
    );
    assert!(
        below.iter().any(|value| *value > -4.000_001),
        "generation never approached the exclusive maximum: {below:?}"
    );

    let integers_above = integers(
        json!({"type": "integer", "exclusiveMinimum": 4, "exclusiveMaximum": 9}),
        8,
    );
    assert!(
        integers_above.iter().all(|value| (5..=8).contains(value)),
        "an integer crossed an exclusive bound: {integers_above:?}"
    );
}

#[test]
fn a_single_admissible_number_is_generated_rather_than_refused() {
    assert!(
        integers(json!({"type": "integer", "minimum": 7, "maximum": 7}), 4)
            .iter()
            .all(|value| *value == 7)
    );
    assert!(
        floats(json!({"type": "number", "minimum": 1.5, "maximum": 1.5}), 4)
            .iter()
            .all(|value| *value == 1.5)
    );
}

#[test]
fn inverted_numeric_bounds_fail_closed() {
    assert!(
        scalar_failure(json!({"type": "number", "minimum": 5.0, "maximum": 1.0}))
            .contains("bounds")
    );
    assert!(
        scalar_failure(json!({"type": "integer", "minimum": 5, "maximum": 1})).contains("maximum")
    );
}

#[test]
fn multiple_of_is_validated_before_it_is_applied() {
    for schema in [
        json!({"type": "number", "multipleOf": 0.0}),
        json!({"type": "number", "multipleOf": -2.0}),
        json!({"type": "integer", "multipleOf": 0}),
        json!({"type": "integer", "multipleOf": -5}),
    ] {
        let reason = scalar_failure(schema.clone());
        assert!(
            reason.contains("multipleOf"),
            "schema {schema} failed without naming multipleOf: {reason}"
        );
    }
}

#[test]
fn generated_numbers_are_actual_multiples_within_range() {
    let values = floats(
        json!({"type": "number", "minimum": 0.0, "maximum": 10.0, "multipleOf": 2.5}),
        12,
    );
    for value in &values {
        assert!(
            (0.0..=10.0).contains(value),
            "multiple {value} left the declared range"
        );
        assert_eq!(
            (value / 2.5).fract(),
            0.0,
            "{value} is not a multiple of 2.5"
        );
    }
    assert!(
        values.contains(&10.0),
        "the maximum-corner multiple was never generated: {values:?}"
    );

    let whole = integers(
        json!({"type": "integer", "minimum": -9, "maximum": 9, "multipleOf": 3}),
        12,
    );
    for value in &whole {
        assert!((-9..=9).contains(value), "multiple {value} left its range");
        assert_eq!(value % 3, 0, "{value} is not a multiple of 3");
    }
}

#[test]
fn a_multiple_that_lands_on_a_bound_is_kept_not_refused() {
    let values = floats(
        json!({"type": "number", "minimum": 5.0, "maximum": 10.0, "multipleOf": 5.0}),
        8,
    );
    assert!(
        values.iter().all(|value| *value == 5.0 || *value == 10.0),
        "a bound-landing multiple was altered: {values:?}"
    );

    let whole = integers(
        json!({"type": "integer", "minimum": 4, "maximum": 8, "multipleOf": 4}),
        8,
    );
    assert!(whole.iter().all(|value| *value == 4 || *value == 8));
}

#[test]
fn a_multiple_outside_the_declared_range_fails_closed() {
    for schema in [
        json!({"type": "number", "minimum": 4.1, "maximum": 4.9, "multipleOf": 4.0}),
        json!({"type": "number", "minimum": 2.5, "maximum": 3.5, "multipleOf": 4.0}),
        json!({"type": "integer", "minimum": 1, "maximum": 4, "multipleOf": 7}),
    ] {
        let reason = scalar_failure(schema.clone());
        assert!(
            reason.contains("multipleOf"),
            "schema {schema} failed without naming multipleOf: {reason}"
        );
    }
}

#[test]
fn non_finite_numeric_bounds_are_refused_before_generation() {
    // `generate_number` also guards against non-finite bounds, but no document
    // Kahea can load reaches it: both parsers refuse the value first. The guard
    // is defence in depth, so this pins the layer that actually rejects.
    for schema in [
        r#"{"type": "number", "minimum": 1e400}"#,
        r#"{"type": "number", "maximum": -1e400}"#,
    ] {
        let spec = scalar_spec(schema);
        let error = load_openapi(Path::new("numeric.json"), spec.as_bytes())
            .expect_err("an overflowing JSON bound was accepted");
        assert!(
            error.to_string().contains("out of range"),
            "unexpected rejection for {schema}: {error}"
        );
    }

    let yaml = concat!(
        "openapi: 3.1.0\n",
        "info: { title: numeric, version: '1' }\n",
        "servers: [{ url: \"https://api.example.test\" }]\n",
        "paths:\n",
        "  /values:\n",
        "    get:\n",
        "      operationId: getValue\n",
        "      parameters:\n",
        "        - { name: q, in: query, schema: { type: number, minimum: .inf } }\n",
        "      responses:\n",
        "        '200': { description: ok }\n",
    );
    let error = load_openapi(Path::new("numeric.yaml"), yaml.as_bytes())
        .expect_err("an infinite YAML bound was accepted");
    assert!(
        error.to_string().contains("non-finite"),
        "unexpected YAML rejection: {error}"
    );
}
