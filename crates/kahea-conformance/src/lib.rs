//! Deterministic OpenAPI-derived conformance campaigns.

use kahea_core::{
    ConformanceCaseObservation, ConformanceCasePlan, ConformanceGeneration, ConformanceObservation,
    ConformancePlan, FieldDerivation, Outcome, PROTOCOL, RequestPlan, VERSION, digest,
    short_handle,
};
use kahea_evidence::EvidenceStore;
use kahea_exec::{ExecError, InvocationResult, InvokeOptions, invoke};
use kahea_ingest::{OpenApiSource, OperationDefinition};
use kahea_plan::{
    PlanOptions, ProjectConfiguration, build_plan_with_configuration, load_plan, store_plan,
};
use serde_json::{Map, Number, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use url::Url;

const MAX_CASES: usize = 256;
const MAX_FAILURES: usize = 256;
const MAX_DELAY_MS: u64 = 60_000;
const MAX_GENERATION_DEPTH: usize = 32;
const MAX_GENERATED_STRING: usize = 1_024;
const MAX_GENERATED_ARRAY: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConformanceMode {
    Positive,
    Negative,
    Mixed,
}

#[derive(Debug, Clone)]
pub struct ConformanceOptions {
    pub cases: usize,
    pub seed: u64,
    pub mode: ConformanceMode,
    pub delay_ms: u64,
    pub max_failures: usize,
    pub input: Option<Value>,
    pub plan: PlanOptions,
}

impl Default for ConformanceOptions {
    fn default() -> Self {
        Self {
            cases: 32,
            seed: 0,
            mode: ConformanceMode::Mixed,
            delay_ms: 0,
            max_failures: 10,
            input: None,
            plan: PlanOptions::default(),
        }
    }
}

#[derive(Debug, Error)]
pub enum ConformanceError {
    #[error("conformance option error: {0}")]
    InvalidOption(String),
    #[error("schema generation error at {path}: {reason}")]
    Generation { path: String, reason: String },
    #[error("no distinct {0} conformance cases could be generated")]
    NoCases(&'static str),
    #[error("request planning failed: {0}")]
    Plan(String),
    #[error("conformance plan seal is invalid")]
    InvalidSeal,
    #[error("stored case plan {0:?} does not match the campaign")]
    InvalidCase(String),
    #[error("conformance store error: {0}")]
    Store(#[from] std::io::Error),
    #[error("conformance serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("conformance evidence error: {0}")]
    Evidence(#[from] kahea_evidence::EvidenceError),
}

pub fn build_conformance_plan(
    source: &OpenApiSource,
    operation: &OperationDefinition,
    options: ConformanceOptions,
    configuration: &ProjectConfiguration,
) -> Result<(ConformancePlan, Vec<RequestPlan>), ConformanceError> {
    validate_options(&options)?;
    let content_type =
        selected_content_type(source, operation, options.plan.content_type.as_deref())?;
    let baseline = baseline_with_explicit(options.input.as_ref(), &options.plan.explicit)?;
    let mut positive = Vec::new();
    let mut seen = BTreeSet::new();
    let attempts = options.cases.saturating_mul(8).clamp(16, 2_048);
    for index in 0..attempts {
        let variant = variant(options.seed, index as u64, "positive");
        let input = generated_input(
            source,
            operation,
            baseline.as_ref(),
            content_type.as_deref(),
            variant,
        )?;
        let mut plan_options = options.plan.clone();
        plan_options.content_type.clone_from(&content_type);
        plan_options.input = Some(input);
        let plan = build_plan_with_configuration(source, operation, plan_options, configuration)
            .map_err(|error| ConformanceError::Plan(error.to_string()))?;
        if seen.insert(plan.fingerprint.clone()) {
            positive.push((format!("schema-valid:{variant}"), plan));
        }
        if positive.len() >= options.cases {
            break;
        }
    }
    if positive.is_empty() {
        return Err(ConformanceError::NoCases("positive"));
    }

    let mut negative = Vec::new();
    let mut negative_seen = BTreeSet::new();
    for (_, plan) in &positive {
        for (strategy, negative_plan) in negative_plans(source, operation, plan)? {
            if negative_seen.insert(negative_plan.fingerprint.clone()) {
                negative.push((strategy, negative_plan));
            }
            if negative.len() >= options.cases {
                break;
            }
        }
        if negative.len() >= options.cases {
            break;
        }
    }

    let selected = select_cases(options.mode, options.cases, positive, negative)?;
    let mut request_plans = Vec::with_capacity(selected.len());
    let mut cases = Vec::with_capacity(selected.len());
    let mut required_grants = BTreeSet::new();
    for (index, (generation, strategy, plan)) in selected.into_iter().enumerate() {
        required_grants.extend(plan.required_grants.iter().cloned());
        let case_id = short_handle(
            "case",
            &[
                source.source_fingerprint.as_bytes(),
                operation.handle.as_bytes(),
                &options.seed.to_be_bytes(),
                &(index as u64).to_be_bytes(),
                plan.fingerprint.as_bytes(),
            ],
        );
        cases.push(ConformanceCasePlan {
            case_id,
            generation,
            strategy,
            plan: plan.id.clone(),
            plan_fingerprint: plan.fingerprint.clone(),
            request_digest: request_digest(&plan)?,
        });
        request_plans.push(plan);
    }
    required_grants.insert(format!("conformance:execute:{}", cases.len()));
    if cases
        .iter()
        .any(|case| case.generation == ConformanceGeneration::Negative)
    {
        required_grants.insert("conformance:negative".into());
    }
    let campaign = ConformancePlan {
        protocol: PROTOCOL.into(),
        kind: "conformance-plan".into(),
        version: VERSION.into(),
        config_fingerprint: configuration
            .config_fingerprint()
            .map_err(|error| ConformanceError::Plan(error.to_string()))?,
        policy_fingerprint: configuration
            .policy_fingerprint()
            .map_err(|error| ConformanceError::Plan(error.to_string()))?,
        source_fingerprints: vec![source.source_fingerprint.clone()],
        id: String::new(),
        operation: operation.handle.clone(),
        seed: options.seed,
        requested_cases: options.cases,
        delay_ms: options.delay_ms,
        max_failures: options.max_failures,
        cases,
        risk: operation.risk,
        required_grants: required_grants.into_iter().collect(),
        fingerprint: String::new(),
        exit: 0,
    }
    .seal()?;
    Ok((campaign, request_plans))
}

fn baseline_with_explicit(
    baseline: Option<&Value>,
    explicit: &[(String, Value)],
) -> Result<Option<Value>, ConformanceError> {
    if baseline.is_none() && explicit.is_empty() {
        return Ok(None);
    }
    let mut result = baseline.cloned().unwrap_or_else(|| json!({}));
    let structured = result.as_object().is_some_and(|object| {
        object.keys().any(|key| {
            matches!(
                key.as_str(),
                "path" | "query" | "header" | "headers" | "cookie" | "cookies" | "body"
            )
        })
    });
    if !structured && baseline.is_some() {
        result = json!({"body": result});
    }
    let root = result
        .as_object_mut()
        .ok_or_else(|| generation("input", "baseline input must be an object"))?;
    for (key, value) in explicit {
        let (location, name) = key
            .split_once('.')
            .ok_or_else(|| generation(key, "explicit field requires a location"))?;
        let location = match location {
            "headers" => "header",
            "cookies" => "cookie",
            other => other,
        };
        if location == "body" {
            let body = root
                .entry("body")
                .or_insert_with(|| Value::Object(Map::new()));
            insert_nested(body, name, value.clone())?;
        } else if matches!(location, "path" | "query" | "header" | "cookie") {
            let section = root
                .entry(location)
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .ok_or_else(|| generation(location, "input section must be an object"))?;
            section.insert(name.into(), value.clone());
        } else {
            return Err(generation(key, "unsupported explicit field location"));
        }
    }
    Ok(Some(result))
}

fn insert_nested(root: &mut Value, path: &str, value: Value) -> Result<(), ConformanceError> {
    let mut current = root;
    let segments: Vec<_> = path.split('.').collect();
    for (index, segment) in segments.iter().enumerate() {
        let object = current
            .as_object_mut()
            .ok_or_else(|| generation(path, "explicit body parent must be an object"))?;
        if index + 1 == segments.len() {
            object.insert((*segment).into(), value);
            return Ok(());
        }
        current = object
            .entry((*segment).to_string())
            .or_insert_with(|| Value::Object(Map::new()));
    }
    Err(generation(path, "explicit body path is empty"))
}

fn selected_content_type(
    source: &OpenApiSource,
    operation: &OperationDefinition,
    requested: Option<&str>,
) -> Result<Option<String>, ConformanceError> {
    let Some(body) = operation.operation.get("requestBody") else {
        return Ok(None);
    };
    let body = resolve(source, body, "requestBody")?;
    let content = body
        .get("content")
        .and_then(Value::as_object)
        .ok_or_else(|| generation("body", "requestBody content is missing"))?;
    if let Some(requested) = requested {
        if !content.contains_key(requested) {
            return Err(generation(
                "body",
                &format!("content type {requested:?} is not declared"),
            ));
        }
        return Ok(Some(requested.into()));
    }
    Ok(content
        .keys()
        .find(|name| name.contains("json"))
        .or_else(|| content.keys().next())
        .cloned())
}

fn validate_options(options: &ConformanceOptions) -> Result<(), ConformanceError> {
    if !(1..=MAX_CASES).contains(&options.cases) {
        return Err(ConformanceError::InvalidOption(format!(
            "cases must be between 1 and {MAX_CASES}"
        )));
    }
    if !(1..=MAX_FAILURES).contains(&options.max_failures) {
        return Err(ConformanceError::InvalidOption(format!(
            "max failures must be between 1 and {MAX_FAILURES}"
        )));
    }
    if options.delay_ms > MAX_DELAY_MS {
        return Err(ConformanceError::InvalidOption(format!(
            "delay must not exceed {MAX_DELAY_MS} ms"
        )));
    }
    if options.plan.input.is_some() {
        return Err(ConformanceError::InvalidOption(
            "supply baseline input through ConformanceOptions.input".into(),
        ));
    }
    Ok(())
}

fn select_cases(
    mode: ConformanceMode,
    limit: usize,
    positive: Vec<(String, RequestPlan)>,
    negative: Vec<(String, RequestPlan)>,
) -> Result<Vec<(ConformanceGeneration, String, RequestPlan)>, ConformanceError> {
    let selected = match mode {
        ConformanceMode::Positive => positive
            .into_iter()
            .take(limit)
            .map(|(strategy, plan)| (ConformanceGeneration::Positive, strategy, plan))
            .collect(),
        ConformanceMode::Negative => {
            if negative.is_empty() {
                return Err(ConformanceError::NoCases("negative"));
            }
            negative
                .into_iter()
                .take(limit)
                .map(|(strategy, plan)| (ConformanceGeneration::Negative, strategy, plan))
                .collect()
        }
        ConformanceMode::Mixed => {
            let mut selected = Vec::new();
            let mut positive = positive.into_iter();
            let mut negative = negative.into_iter();
            while selected.len() < limit {
                let before = selected.len();
                if let Some((strategy, plan)) = positive.next() {
                    selected.push((ConformanceGeneration::Positive, strategy, plan));
                }
                if selected.len() < limit
                    && let Some((strategy, plan)) = negative.next()
                {
                    selected.push((ConformanceGeneration::Negative, strategy, plan));
                }
                if selected.len() == before {
                    break;
                }
            }
            selected
        }
    };
    if selected.is_empty() {
        return Err(ConformanceError::NoCases("requested"));
    }
    Ok(selected)
}

fn generated_input(
    source: &OpenApiSource,
    operation: &OperationDefinition,
    baseline: Option<&Value>,
    content_type: Option<&str>,
    variant: u64,
) -> Result<Value, ConformanceError> {
    let mut input = baseline.cloned().unwrap_or_else(|| json!({}));
    if !input.is_object() {
        input = json!({"body": input});
    }
    let structured = input.as_object().is_some_and(|object| {
        object.keys().any(|key| {
            matches!(
                key.as_str(),
                "path" | "query" | "header" | "headers" | "cookie" | "cookies" | "body"
            )
        })
    });
    if !structured && baseline.is_some() {
        input = json!({"body": input});
    }
    let input_object = input
        .as_object_mut()
        .expect("input was normalized to an object");

    for parameter in parameters(source, operation)? {
        let parameter = resolve(source, &parameter, "parameter")?;
        let name = parameter
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| generation("parameters", "parameter name is missing"))?;
        let location = parameter
            .get("in")
            .and_then(Value::as_str)
            .ok_or_else(|| generation(name, "parameter location is missing"))?;
        let required = parameter
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || location == "path";
        let section_name = match location {
            "path" | "query" | "header" | "cookie" => location,
            other => return Err(generation(name, &format!("unsupported location {other:?}"))),
        };
        let section = input_object
            .entry(section_name)
            .or_insert_with(|| Value::Object(Map::new()));
        let section = section
            .as_object_mut()
            .ok_or_else(|| generation(section_name, "input section must be an object"))?;
        if section.contains_key(name) {
            continue;
        }
        if required || !variant.is_multiple_of(3) {
            let schema = parameter.get("schema").unwrap_or(&Value::Null);
            section.insert(
                name.into(),
                generate_value(source, schema, variant_for(variant, name), name, 0)?,
            );
        }
    }

    if let Some((schema, required)) = request_body_schema(source, operation, content_type)? {
        let existing = input_object.get("body").cloned();
        if required || existing.is_some() || variant.is_multiple_of(2) {
            input_object.insert(
                "body".into(),
                generate_value_with_baseline(
                    source,
                    schema,
                    variant_for(variant, "body"),
                    "body",
                    0,
                    existing.as_ref(),
                )?,
            );
        }
    }
    Ok(input)
}

fn generate_value_with_baseline(
    source: &OpenApiSource,
    schema: &Value,
    variant: u64,
    path: &str,
    depth: usize,
    baseline: Option<&Value>,
) -> Result<Value, ConformanceError> {
    let Some(baseline) = baseline else {
        return generate_value(source, schema, variant, path, depth);
    };
    if depth >= MAX_GENERATION_DEPTH {
        return Err(generation(path, "schema generation exceeded 32 levels"));
    }
    let schema = resolve(source, schema, path)?;
    let Some(existing) = baseline.as_object() else {
        return Ok(baseline.clone());
    };
    if schema.get("properties").is_none() {
        return Ok(baseline.clone());
    }
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let required: BTreeSet<_> = schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let mut object = existing.clone();
    for (index, (name, child)) in properties.iter().enumerate() {
        let read_only = child
            .get("readOnly")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if read_only {
            continue;
        }
        if let Some(value) = existing.get(name) {
            object.insert(
                name.clone(),
                generate_value_with_baseline(
                    source,
                    child,
                    variant_for(variant, name),
                    &format!("{path}.{name}"),
                    depth + 1,
                    Some(value),
                )?,
            );
        } else if required.contains(name.as_str()) || (variant + index as u64).is_multiple_of(3) {
            object.insert(
                name.clone(),
                generate_value(
                    source,
                    child,
                    variant_for(variant, name),
                    &format!("{path}.{name}"),
                    depth + 1,
                )?,
            );
        }
    }
    Ok(Value::Object(object))
}

fn parameters(
    source: &OpenApiSource,
    operation: &OperationDefinition,
) -> Result<Vec<Value>, ConformanceError> {
    let mut result = Vec::new();
    for owner in [&operation.path_item, &operation.operation] {
        if let Some(values) = owner.get("parameters").and_then(Value::as_array) {
            result.extend(values.iter().cloned());
        }
    }
    for value in &result {
        let _ = resolve(source, value, "parameter")?;
    }
    Ok(result)
}

fn request_body_schema<'a>(
    source: &'a OpenApiSource,
    operation: &'a OperationDefinition,
    media_type: Option<&str>,
) -> Result<Option<(&'a Value, bool)>, ConformanceError> {
    let Some(body) = operation.operation.get("requestBody") else {
        return Ok(None);
    };
    let body = resolve(source, body, "requestBody")?;
    let required = body
        .get("required")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let content = body
        .get("content")
        .and_then(Value::as_object)
        .ok_or_else(|| generation("body", "requestBody content is missing"))?;
    let media = if let Some(media_type) = media_type {
        content.get(media_type)
    } else {
        content
            .iter()
            .find(|(name, _)| name.contains("json"))
            .or_else(|| content.iter().next())
            .map(|(_, value)| value)
    }
    .ok_or_else(|| generation("body", "requested media type is not declared"))?;
    let schema = media
        .get("schema")
        .ok_or_else(|| generation("body", "request body schema is missing"))?;
    Ok(Some((schema, required)))
}

fn generate_value(
    source: &OpenApiSource,
    schema: &Value,
    variant: u64,
    path: &str,
    depth: usize,
) -> Result<Value, ConformanceError> {
    if depth >= MAX_GENERATION_DEPTH {
        return Err(generation(path, "schema generation exceeded 32 levels"));
    }
    let schema = resolve(source, schema, path)?;
    for keyword in [
        "not",
        "if",
        "then",
        "else",
        "dependentRequired",
        "dependentSchemas",
        "patternProperties",
        "propertyNames",
        "contains",
        "prefixItems",
        "unevaluatedProperties",
        "unevaluatedItems",
    ] {
        if schema.get(keyword).is_some() {
            return Err(generation(
                path,
                &format!("schema keyword {keyword:?} requires baseline input"),
            ));
        }
    }
    if let Some(value) = schema.get("const") {
        return Ok(value.clone());
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        if values.is_empty() {
            return Err(generation(path, "enum is empty"));
        }
        return Ok(values[(variant as usize) % values.len()].clone());
    }
    if variant.is_multiple_of(5) {
        if let Some(value) = schema.get("example").or_else(|| schema.get("default")) {
            return Ok(value.clone());
        }
        if let Some(value) = schema
            .get("examples")
            .and_then(Value::as_array)
            .and_then(|values| values.get((variant as usize) % values.len().max(1)))
        {
            return Ok(value.clone());
        }
    }
    if let Some(branches) = schema
        .get("oneOf")
        .or_else(|| schema.get("anyOf"))
        .and_then(Value::as_array)
        && !branches.is_empty()
    {
        return generate_value(
            source,
            &branches[(variant as usize) % branches.len()],
            variant.rotate_left(7),
            path,
            depth + 1,
        );
    }
    if let Some(branches) = schema.get("allOf").and_then(Value::as_array) {
        let mut combined = Map::new();
        for (index, branch) in branches.iter().enumerate() {
            let value = generate_value(
                source,
                branch,
                variant_for(variant, &index.to_string()),
                path,
                depth + 1,
            )?;
            let Some(object) = value.as_object() else {
                return Ok(value);
            };
            combined.extend(object.clone());
        }
        return Ok(Value::Object(combined));
    }
    let declared_types: Vec<&str> = match schema.get("type") {
        Some(Value::String(kind)) => vec![kind],
        Some(Value::Array(kinds)) => kinds.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    let kind = (!declared_types.is_empty())
        .then(|| declared_types[(variant as usize) % declared_types.len()])
        .or_else(|| schema.get("properties").is_some().then_some("object"))
        .or_else(|| schema.get("items").is_some().then_some("array"))
        .unwrap_or("string");
    match kind {
        "null" => Ok(Value::Null),
        "boolean" => Ok(Value::Bool(variant.is_multiple_of(2))),
        "integer" => generate_integer(schema, variant, path),
        "number" => generate_number(schema, variant, path),
        "string" => generate_string(schema, variant, path).map(Value::String),
        "array" => {
            let minimum = schema.get("minItems").and_then(Value::as_u64).unwrap_or(0) as usize;
            let maximum = schema
                .get("maxItems")
                .and_then(Value::as_u64)
                .map(|value| value as usize)
                .unwrap_or(minimum.saturating_add(3));
            if minimum > maximum || minimum > MAX_GENERATED_ARRAY {
                return Err(generation(path, "array bounds are not safely generatable"));
            }
            let upper = maximum.min(MAX_GENERATED_ARRAY);
            let length = if upper == minimum {
                minimum
            } else {
                minimum + (variant as usize % (upper - minimum + 1))
            };
            let item_schema = schema.get("items").unwrap_or(&Value::Null);
            let unique = schema
                .get("uniqueItems")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let mut values = Vec::with_capacity(length);
            for index in 0..length {
                let mut generated = None;
                for attempt in 0..16 {
                    let candidate = generate_value(
                        source,
                        item_schema,
                        variant_for(variant.wrapping_add(attempt), &index.to_string()),
                        &format!("{path}[{index}]"),
                        depth + 1,
                    )?;
                    if !unique || !values.contains(&candidate) {
                        generated = Some(candidate);
                        break;
                    }
                }
                values.push(generated.ok_or_else(|| {
                    generation(path, "unique array items could not be generated")
                })?);
            }
            Ok(Value::Array(values))
        }
        "object" => {
            let properties = schema
                .get("properties")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let required: BTreeSet<_> = schema
                .get("required")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            let mut object = Map::new();
            for (index, (name, child)) in properties.iter().enumerate() {
                let read_only = child
                    .get("readOnly")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !read_only
                    && (required.contains(name.as_str())
                        || (variant + index as u64).is_multiple_of(3))
                {
                    object.insert(
                        name.clone(),
                        generate_value(
                            source,
                            child,
                            variant_for(variant, name),
                            &format!("{path}.{name}"),
                            depth + 1,
                        )?,
                    );
                }
            }
            let minimum = schema
                .get("minProperties")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
            for (name, child) in &properties {
                if object.len() >= minimum {
                    break;
                }
                if !object.contains_key(name)
                    && !child
                        .get("readOnly")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                {
                    object.insert(
                        name.clone(),
                        generate_value(
                            source,
                            child,
                            variant_for(variant, name),
                            &format!("{path}.{name}"),
                            depth + 1,
                        )?,
                    );
                }
            }
            if object.len() < minimum {
                return Err(generation(path, "minProperties cannot be generated safely"));
            }
            if schema
                .get("maxProperties")
                .and_then(Value::as_u64)
                .is_some_and(|maximum| object.len() as u64 > maximum)
            {
                return Err(generation(path, "required properties exceed maxProperties"));
            }
            Ok(Value::Object(object))
        }
        other => Err(generation(
            path,
            &format!("unsupported schema type {other:?}"),
        )),
    }
}

fn generate_integer(schema: &Value, variant: u64, path: &str) -> Result<Value, ConformanceError> {
    let mut minimum = schema
        .get("minimum")
        .and_then(Value::as_i64)
        .unwrap_or(-100);
    let mut maximum = schema.get("maximum").and_then(Value::as_i64).unwrap_or(100);
    if let Some(exclusive) = schema.get("exclusiveMinimum").and_then(Value::as_i64) {
        minimum = minimum.max(exclusive.saturating_add(1));
    } else if schema.get("exclusiveMinimum") == Some(&Value::Bool(true)) {
        minimum = minimum.saturating_add(1);
    }
    if let Some(exclusive) = schema.get("exclusiveMaximum").and_then(Value::as_i64) {
        maximum = maximum.min(exclusive.saturating_sub(1));
    } else if schema.get("exclusiveMaximum") == Some(&Value::Bool(true)) {
        maximum = maximum.saturating_sub(1);
    }
    if minimum > maximum {
        return Err(generation(path, "minimum exceeds maximum"));
    }
    let choices = [minimum, maximum, 0_i64.clamp(minimum, maximum)];
    let mut selected = choices[(variant as usize) % choices.len()];
    if let Some(multiple) = schema.get("multipleOf").and_then(Value::as_i64) {
        if multiple <= 0 {
            return Err(generation(path, "multipleOf must be positive"));
        }
        selected = selected.div_euclid(multiple) * multiple;
        if selected < minimum {
            selected = selected.saturating_add(multiple);
        }
        if selected > maximum {
            return Err(generation(path, "no multipleOf value exists within bounds"));
        }
    }
    Ok(Value::Number(selected.into()))
}

fn generate_number(schema: &Value, variant: u64, path: &str) -> Result<Value, ConformanceError> {
    let mut minimum = schema
        .get("minimum")
        .and_then(Value::as_f64)
        .unwrap_or(-100.0);
    let mut maximum = schema
        .get("maximum")
        .and_then(Value::as_f64)
        .unwrap_or(100.0);
    if let Some(exclusive) = schema.get("exclusiveMinimum").and_then(Value::as_f64) {
        minimum = minimum.max(exclusive + f64::EPSILON * exclusive.abs().max(1.0));
    }
    if let Some(exclusive) = schema.get("exclusiveMaximum").and_then(Value::as_f64) {
        maximum = maximum.min(exclusive - f64::EPSILON * exclusive.abs().max(1.0));
    }
    if numeric_bounds_are_invalid(minimum, maximum) {
        return Err(generation(path, "numeric bounds are invalid"));
    }
    let choices = [minimum, maximum, 0.0_f64.clamp(minimum, maximum)];
    let mut selected = choices[(variant as usize) % choices.len()];
    if let Some(multiple) = schema.get("multipleOf").and_then(Value::as_f64) {
        if !multiple.is_finite() || multiple <= 0.0 {
            return Err(generation(
                path,
                "multipleOf must be a positive finite number",
            ));
        }
        selected = (selected / multiple).round() * multiple;
        if selected < minimum || selected > maximum {
            return Err(generation(path, "no multipleOf value exists within bounds"));
        }
    }
    Number::from_f64(selected)
        .map(Value::Number)
        .ok_or_else(|| generation(path, "number cannot be represented as JSON"))
}

fn numeric_bounds_are_invalid(minimum: f64, maximum: f64) -> bool {
    !minimum.is_finite() || !maximum.is_finite() || minimum > maximum
}

fn generate_string(schema: &Value, variant: u64, path: &str) -> Result<String, ConformanceError> {
    if let Some(format) = schema.get("format").and_then(Value::as_str) {
        if format == "binary" {
            return Err(generation(
                path,
                "binary values require a baseline $file descriptor",
            ));
        }
        let formatted = match format {
            "date" => Some("2026-08-05"),
            "date-time" => Some("2026-08-05T00:00:00Z"),
            "email" => Some("kahea@example.test"),
            "uuid" => Some("00000000-0000-4000-8000-000000000001"),
            "uri" | "url" => Some("https://example.test/resource"),
            "hostname" => Some("example.test"),
            "ipv4" => Some("192.0.2.1"),
            "ipv6" => Some("2001:db8::1"),
            "byte" => Some("a2FoZWE="),
            _ => None,
        };
        if let Some(formatted) = formatted {
            return Ok(formatted.into());
        }
    }
    let minimum = schema.get("minLength").and_then(Value::as_u64).unwrap_or(0) as usize;
    let maximum = schema
        .get("maxLength")
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .unwrap_or(minimum.saturating_add(16));
    if minimum > maximum || minimum > MAX_GENERATED_STRING {
        return Err(generation(path, "string bounds are not safely generatable"));
    }
    if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
        if let Some(value) = simple_pattern_value(pattern, minimum)
            && value.len() <= maximum
        {
            return Ok(value);
        }
        if let Some(example) = schema
            .get("example")
            .or_else(|| schema.get("default"))
            .and_then(Value::as_str)
        {
            return Ok(example.into());
        }
        return Err(generation(
            path,
            "pattern is not in the bounded built-in subset; supply baseline input",
        ));
    }
    let upper = maximum.min(MAX_GENERATED_STRING);
    let lengths = [minimum, upper, minimum.saturating_add(1).min(upper)];
    let length = lengths[(variant as usize) % lengths.len()];
    Ok(if length == 0 {
        String::new()
    } else {
        let alphabet = ["a", "Z", "7"][(variant as usize) % 3];
        alphabet.repeat(length)
    })
}

fn simple_pattern_value(pattern: &str, minimum: usize) -> Option<String> {
    let length = minimum.max(1);
    if pattern.contains("\\d") || pattern.contains("0-9") {
        Some("7".repeat(length))
    } else if pattern.contains("A-Z") {
        Some("A".repeat(length))
    } else if pattern.contains("a-z") || pattern.contains("A-Za-z") {
        Some("a".repeat(length))
    } else {
        None
    }
}

fn resolve<'a>(
    source: &'a OpenApiSource,
    value: &'a Value,
    path: &str,
) -> Result<&'a Value, ConformanceError> {
    let Some(reference) = value.get("$ref").and_then(Value::as_str) else {
        return Ok(value);
    };
    reference
        .strip_prefix('#')
        .and_then(|pointer| source.document.pointer(pointer))
        .ok_or_else(|| generation(path, &format!("unresolved local reference {reference:?}")))
}

fn negative_plans(
    source: &OpenApiSource,
    operation: &OperationDefinition,
    plan: &RequestPlan,
) -> Result<Vec<(String, RequestPlan)>, ConformanceError> {
    let mut variants = Vec::new();
    if let Some(body) = &plan.body
        && body.media_type.contains("json")
        && let Ok(value) = serde_json::from_str::<Value>(&body.inline)
        && let Some((schema, _)) = request_body_schema(source, operation, Some(&body.media_type))?
    {
        for (strategy, mutated) in invalid_json_values(source, schema, &value, "body", 0)? {
            let mut candidate = plan.clone();
            let bytes = serde_json::to_vec(&mutated)?;
            if let Some(body) = candidate.body.as_mut() {
                body.bytes = bytes.len() as u64;
                body.blake3 = digest(&bytes);
                body.encoding = "utf-8".into();
                body.inline = String::from_utf8(bytes).expect("JSON is UTF-8");
            }
            candidate.valid = false;
            candidate.derivations.push(conformance_derivation(
                &strategy,
                mutated,
                candidate.body.as_ref().map(|body| body.inline.clone()),
            ));
            variants.push((strategy, seal_negative(candidate)?));
        }
    }

    for parameter in parameters(source, operation)? {
        let parameter = resolve(source, &parameter, "parameter")?;
        let Some(name) = parameter.get("name").and_then(Value::as_str) else {
            continue;
        };
        let Some(location) = parameter.get("in").and_then(Value::as_str) else {
            continue;
        };
        let required = parameter
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if required && location != "path" {
            let mut candidate = plan.clone();
            if remove_parameter(&mut candidate, location, name)? {
                let strategy = format!("omit-required-{location}:{name}");
                candidate.valid = false;
                candidate
                    .derivations
                    .push(conformance_derivation(&strategy, Value::Null, None));
                variants.push((strategy, seal_negative(candidate)?));
            }
        }
        if let Some(invalid) = invalid_scalar(parameter.get("schema").unwrap_or(&Value::Null)) {
            let mut candidate = plan.clone();
            if replace_parameter(&mut candidate, location, name, &invalid)? {
                let strategy = format!("invalid-{location}:{name}");
                candidate.valid = false;
                candidate.derivations.push(conformance_derivation(
                    &strategy,
                    Value::String(invalid),
                    None,
                ));
                variants.push((strategy, seal_negative(candidate)?));
            }
        }
    }
    Ok(variants)
}

fn seal_negative(mut plan: RequestPlan) -> Result<RequestPlan, ConformanceError> {
    plan.required_grants.push("conformance:negative".into());
    plan.required_grants.sort();
    plan.required_grants.dedup();
    Ok(plan.seal()?)
}

fn invalid_json_values(
    source: &OpenApiSource,
    schema: &Value,
    value: &Value,
    path: &str,
    depth: usize,
) -> Result<Vec<(String, Value)>, ConformanceError> {
    if depth >= MAX_GENERATION_DEPTH {
        return Ok(Vec::new());
    }
    let schema = resolve(source, schema, path)?;
    let mut candidates = Vec::new();
    if let (Some(required), Some(object)) = (
        schema.get("required").and_then(Value::as_array),
        value.as_object(),
    ) {
        for name in required.iter().filter_map(Value::as_str) {
            if object.contains_key(name) {
                let mut mutated = object.clone();
                mutated.remove(name);
                candidates.push((
                    format!("omit-required-body:{path}.{name}"),
                    Value::Object(mutated),
                ));
            }
        }
    }
    if schema.get("additionalProperties") == Some(&Value::Bool(false))
        && let Some(object) = value.as_object()
    {
        let mut mutated = object.clone();
        mutated.insert("__kahea_unknown".into(), Value::Bool(true));
        candidates.push((
            format!("unknown-body-property:{path}"),
            Value::Object(mutated),
        ));
    }
    if let (Some(properties), Some(object)) = (
        schema.get("properties").and_then(Value::as_object),
        value.as_object(),
    ) {
        for (name, child_schema) in properties {
            let Some(child) = object.get(name) else {
                continue;
            };
            for (strategy, invalid_child) in invalid_json_values(
                source,
                child_schema,
                child,
                &format!("{path}.{name}"),
                depth + 1,
            )? {
                let mut mutated = object.clone();
                mutated.insert(name.clone(), invalid_child);
                candidates.push((strategy, Value::Object(mutated)));
            }
        }
    }
    if let (Some(items), Some(values)) = (schema.get("items"), value.as_array()) {
        for (index, child) in values.iter().enumerate() {
            for (strategy, invalid_child) in
                invalid_json_values(source, items, child, &format!("{path}[{index}]"), depth + 1)?
            {
                let mut mutated = values.clone();
                mutated[index] = invalid_child;
                candidates.push((strategy, Value::Array(mutated)));
            }
        }
    }
    if let Some(invalid) = invalid_value(schema, value) {
        candidates.push((format!("invalid-body-value:{path}"), invalid));
    }
    Ok(candidates)
}

fn invalid_value(schema: &Value, value: &Value) -> Option<Value> {
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        let candidate = Value::String("__kahea_outside_enum__".into());
        if !values.contains(&candidate) {
            return Some(candidate);
        }
    }
    match schema.get("type").and_then(Value::as_str) {
        Some("string") => {
            if schema
                .get("minLength")
                .and_then(Value::as_u64)
                .is_some_and(|minimum| minimum > 0)
            {
                return Some(Value::String(String::new()));
            }
            if let Some(maximum) = schema.get("maxLength").and_then(Value::as_u64)
                && maximum < MAX_GENERATED_STRING as u64
            {
                return Some(Value::String("x".repeat(maximum as usize + 1)));
            }
            Some(json!(false))
        }
        Some("integer" | "number") => Some(Value::String("not-a-number".into())),
        Some("boolean") => Some(Value::String("not-a-boolean".into())),
        Some("array") => Some(json!({"not":"an-array"})),
        Some("object") => Some(json!(["not-an-object"])),
        Some("null") => Some(json!(true)),
        _ if value.is_string() => Some(json!(false)),
        _ => None,
    }
}

fn invalid_scalar(schema: &Value) -> Option<String> {
    if schema.get("enum").and_then(Value::as_array).is_some() {
        return Some("__kahea_outside_enum__".into());
    }
    match schema.get("type").and_then(Value::as_str) {
        Some("integer" | "number") => Some("not-a-number".into()),
        Some("boolean") => Some("not-a-boolean".into()),
        Some("string") if schema.get("minLength").and_then(Value::as_u64).unwrap_or(0) > 0 => {
            Some(String::new())
        }
        _ => None,
    }
}

fn remove_parameter(
    plan: &mut RequestPlan,
    location: &str,
    name: &str,
) -> Result<bool, ConformanceError> {
    match location {
        "query" => {
            let mut url = Url::parse(&plan.target)
                .map_err(|error| ConformanceError::Plan(error.to_string()))?;
            let before = url.query_pairs().count();
            let retained: Vec<_> = url
                .query_pairs()
                .filter(|(key, _)| key != name)
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect();
            if retained.len() == before {
                return Ok(false);
            }
            url.set_query(None);
            if !retained.is_empty() {
                let mut pairs = url.query_pairs_mut();
                for (key, value) in retained {
                    pairs.append_pair(&key, &value);
                }
            }
            plan.target = url.to_string();
            Ok(true)
        }
        "header" => {
            let before = plan.headers.len();
            plan.headers
                .retain(|header| !header.name.eq_ignore_ascii_case(name));
            Ok(before != plan.headers.len())
        }
        "cookie" => mutate_cookie(plan, name, None),
        _ => Ok(false),
    }
}

fn replace_parameter(
    plan: &mut RequestPlan,
    location: &str,
    name: &str,
    value: &str,
) -> Result<bool, ConformanceError> {
    match location {
        "query" => {
            let mut url = Url::parse(&plan.target)
                .map_err(|error| ConformanceError::Plan(error.to_string()))?;
            let mut changed = false;
            let pairs: Vec<_> = url
                .query_pairs()
                .map(|(key, old)| {
                    if key == name {
                        changed = true;
                        (key.into_owned(), value.to_string())
                    } else {
                        (key.into_owned(), old.into_owned())
                    }
                })
                .collect();
            if !changed {
                return Ok(false);
            }
            url.set_query(None);
            let mut query = url.query_pairs_mut();
            for (key, value) in pairs {
                query.append_pair(&key, &value);
            }
            drop(query);
            plan.target = url.to_string();
            Ok(true)
        }
        "header" => {
            if let Some(header) = plan
                .headers
                .iter_mut()
                .find(|header| header.name.eq_ignore_ascii_case(name))
            {
                header.value = value.into();
                Ok(true)
            } else {
                Ok(false)
            }
        }
        "cookie" => mutate_cookie(plan, name, Some(value)),
        "path" => {
            let field = format!("path.{name}");
            let Some(old) = plan
                .derivations
                .iter()
                .find(|derivation| derivation.field == field)
                .and_then(|derivation| derivation.wire_value.as_deref())
            else {
                return Ok(false);
            };
            let mut url = Url::parse(&plan.target)
                .map_err(|error| ConformanceError::Plan(error.to_string()))?;
            let Some(mut segments) = url
                .path_segments()
                .map(|segments| segments.map(str::to_owned).collect::<Vec<_>>())
            else {
                return Ok(false);
            };
            let Some(segment) = segments.iter_mut().find(|segment| *segment == old) else {
                return Ok(false);
            };
            *segment = value.into();
            url.path_segments_mut()
                .map_err(|()| {
                    ConformanceError::Plan("target URL cannot carry path segments".into())
                })?
                .clear()
                .extend(&segments);
            plan.target = url.to_string();
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn mutate_cookie(
    plan: &mut RequestPlan,
    name: &str,
    replacement: Option<&str>,
) -> Result<bool, ConformanceError> {
    let Some(header) = plan
        .headers
        .iter_mut()
        .find(|header| header.name.eq_ignore_ascii_case("cookie"))
    else {
        return Ok(false);
    };
    let mut changed = false;
    let cookies: Vec<_> = header
        .value
        .split(';')
        .filter_map(|part| {
            let (key, old) = part.trim().split_once('=')?;
            if key == name {
                changed = true;
                replacement.map(|value| format!("{key}={value}"))
            } else {
                Some(format!("{key}={old}"))
            }
        })
        .collect();
    if changed {
        header.value = cookies.join("; ");
    }
    Ok(changed)
}

fn conformance_derivation(
    strategy: &str,
    logical_value: Value,
    wire_value: Option<String>,
) -> FieldDerivation {
    FieldDerivation {
        field: "conformance.mutation".into(),
        source: "conformance-generator".into(),
        source_location: strategy.into(),
        logical_value,
        wire_value,
        transformations: vec!["schema-negative-mutation".into()],
    }
}

fn request_digest(plan: &RequestPlan) -> Result<String, ConformanceError> {
    Ok(digest(&serde_json::to_vec(&json!({
        "method": plan.method,
        "target": plan.target,
        "headers": plan.headers,
        "body": plan.body.as_ref().map(|body| &body.blake3),
    }))?))
}

fn variant(seed: u64, index: u64, domain: &str) -> u64 {
    let hash = blake3::hash(
        &[
            b"kahea/conformance/v1\0".as_slice(),
            &seed.to_be_bytes(),
            &index.to_be_bytes(),
            domain.as_bytes(),
        ]
        .concat(),
    );
    u64::from_be_bytes(hash.as_bytes()[..8].try_into().expect("eight bytes"))
}

fn variant_for(parent: u64, field: &str) -> u64 {
    variant(parent, field.len() as u64, field)
}

fn generation(path: &str, reason: &str) -> ConformanceError {
    ConformanceError::Generation {
        path: path.into(),
        reason: reason.into(),
    }
}

pub fn store_conformance_plan(
    root: &Path,
    plan: &ConformancePlan,
    requests: &[RequestPlan],
) -> Result<PathBuf, ConformanceError> {
    if !plan.verify_seal()? {
        return Err(ConformanceError::InvalidSeal);
    }
    let by_id: BTreeMap<_, _> = requests.iter().map(|plan| (&plan.id, plan)).collect();
    for case in &plan.cases {
        let request = by_id
            .get(&case.plan)
            .ok_or_else(|| ConformanceError::InvalidCase(case.plan.clone()))?;
        if request.fingerprint != case.plan_fingerprint || !request.verify_seal()? {
            return Err(ConformanceError::InvalidCase(case.plan.clone()));
        }
        store_plan(root, request).map_err(|error| ConformanceError::Plan(error.to_string()))?;
    }
    let directory = root.join("store/plans");
    fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{}.json", plan.id.replace(':', "-")));
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, serde_json::to_vec(plan)?)?;
    fs::rename(temporary, &path)?;
    Ok(path)
}

pub fn load_conformance_plan(
    root: &Path,
    reference: &str,
) -> Result<ConformancePlan, ConformanceError> {
    let path = if reference.starts_with("conformance-plan:") {
        root.join("store/plans")
            .join(format!("{}.json", reference.replace(':', "-")))
    } else {
        PathBuf::from(reference)
    };
    let plan: ConformancePlan = serde_json::from_slice(&fs::read(path)?)?;
    if !plan.verify_seal()? {
        return Err(ConformanceError::InvalidSeal);
    }
    Ok(plan)
}

pub fn invoke_conformance(
    plan: &ConformancePlan,
    options: &InvokeOptions,
    root: &Path,
    evidence: &EvidenceStore,
) -> Result<ConformanceObservation, ConformanceError> {
    if !plan.verify_seal()? {
        return Err(ConformanceError::InvalidSeal);
    }
    if options
        .expected_config_fingerprint
        .as_ref()
        .is_some_and(|expected| expected != &plan.config_fingerprint)
        || options
            .expected_policy_fingerprint
            .as_ref()
            .is_some_and(|expected| expected != &plan.policy_fingerprint)
    {
        return Err(ConformanceError::Plan(
            "campaign configuration or policy fingerprint mismatch".into(),
        ));
    }
    if let Some(missing) = plan
        .required_grants
        .iter()
        .find(|grant| !options.grants.contains(*grant))
    {
        return Ok(ConformanceObservation {
            protocol: PROTOCOL.into(),
            kind: "conformance-observation".into(),
            version: VERSION.into(),
            config_fingerprint: plan.config_fingerprint.clone(),
            policy_fingerprint: plan.policy_fingerprint.clone(),
            source_fingerprints: plan.source_fingerprints.clone(),
            conformance_plan: plan.id.clone(),
            outcome: Outcome::Denied,
            generated: plan.cases.len(),
            executed: 0,
            passed: 0,
            failed: 0,
            transport_errors: 0,
            cases: Vec::new(),
            required: Some(missing.clone()),
            exit: 4,
        });
    }

    let mut cases = Vec::new();
    let mut passed = 0;
    let mut failed = 0;
    let mut transport_errors = 0;
    let mut denied = false;
    for (index, case) in plan.cases.iter().enumerate() {
        if failed >= plan.max_failures {
            break;
        }
        if let Some(delay) = campaign_delay(index, plan.delay_ms) {
            std::thread::sleep(delay);
        }
        let request = load_plan(root, &case.plan)
            .map_err(|_| ConformanceError::InvalidCase(case.plan.clone()))?;
        if request.fingerprint != case.plan_fingerprint
            || request_digest(&request)? != case.request_digest
        {
            return Err(ConformanceError::InvalidCase(case.plan.clone()));
        }
        match invoke(&request, options, evidence) {
            Ok(result) => {
                let (case_passed, status, reason) = assess(case.generation, &result);
                denied |= matches!(result, InvocationResult::Denied(_));
                if case_passed {
                    passed += 1;
                } else {
                    failed += 1;
                }
                let result_value = match &result {
                    InvocationResult::Observation(value) => serde_json::to_value(value)?,
                    InvocationResult::Denied(value) => serde_json::to_value(value)?,
                };
                let record = evidence.put_json("conformance-case", &result_value, true)?;
                cases.push(ConformanceCaseObservation {
                    case_id: case.case_id.clone(),
                    generation: case.generation,
                    strategy: case.strategy.clone(),
                    plan: case.plan.clone(),
                    passed: case_passed,
                    status,
                    reason,
                    evidence: record.handle,
                });
            }
            Err(error) => {
                failed += 1;
                transport_errors += usize::from(matches!(
                    error,
                    ExecError::Transport(_) | ExecError::ResponseTooLarge(_)
                ));
                let reason = safe_exec_reason(&error);
                let record = evidence.put_json(
                    "conformance-case-error",
                    &json!({
                        "protocol": PROTOCOL,
                        "kind": "conformance-case-error",
                        "case": case.case_id,
                        "plan": case.plan,
                        "reason": reason,
                        "exit": if matches!(error, ExecError::Transport(_) | ExecError::ResponseTooLarge(_)) { 3 } else { 2 }
                    }),
                    true,
                )?;
                cases.push(ConformanceCaseObservation {
                    case_id: case.case_id.clone(),
                    generation: case.generation,
                    strategy: case.strategy.clone(),
                    plan: case.plan.clone(),
                    passed: false,
                    status: None,
                    reason,
                    evidence: record.handle,
                });
            }
        }
    }
    let exit = if denied {
        4
    } else if failed == 0 {
        0
    } else if transport_errors == failed {
        3
    } else {
        1
    };
    Ok(ConformanceObservation {
        protocol: PROTOCOL.into(),
        kind: "conformance-observation".into(),
        version: VERSION.into(),
        config_fingerprint: plan.config_fingerprint.clone(),
        policy_fingerprint: plan.policy_fingerprint.clone(),
        source_fingerprints: plan.source_fingerprints.clone(),
        conformance_plan: plan.id.clone(),
        outcome: if exit == 0 {
            Outcome::Passed
        } else if exit == 4 {
            Outcome::Denied
        } else {
            Outcome::Failed
        },
        generated: plan.cases.len(),
        executed: cases.len(),
        passed,
        failed,
        transport_errors,
        cases,
        required: None,
        exit,
    })
}

fn campaign_delay(index: usize, delay_ms: u64) -> Option<Duration> {
    (index > 0 && delay_ms > 0).then(|| Duration::from_millis(delay_ms))
}

fn assess(
    generation: ConformanceGeneration,
    result: &InvocationResult,
) -> (bool, Option<u16>, String) {
    match result {
        InvocationResult::Denied(denial) => (
            false,
            None,
            format!("case was denied at runtime; missing {}", denial.required),
        ),
        InvocationResult::Observation(observation) => {
            let status = observation.status;
            if status.is_some_and(|status| status >= 500) {
                return (false, status, "server returned a 5xx response".into());
            }
            match generation {
                ConformanceGeneration::Positive if observation.exit == 0 => {
                    (true, status, "valid generated request conformed".into())
                }
                ConformanceGeneration::Positive => (
                    false,
                    status,
                    "valid generated request failed response conformance".into(),
                ),
                ConformanceGeneration::Negative
                    if status.is_some_and(|status| (400..500).contains(&status))
                        && observation.exit == 0 =>
                {
                    (
                        true,
                        status,
                        "invalid generated request was rejected".into(),
                    )
                }
                ConformanceGeneration::Negative
                    if status.is_some_and(|status| (200..300).contains(&status)) =>
                {
                    (false, status, "schema-invalid request was accepted".into())
                }
                ConformanceGeneration::Negative => (
                    false,
                    status,
                    "invalid request rejection did not conform to the response contract".into(),
                ),
            }
        }
    }
}

fn safe_exec_reason(error: &ExecError) -> String {
    match error {
        ExecError::Transport(_) => "transport failed".into(),
        ExecError::ResponseTooLarge(limit) => {
            format!("response exceeded the {limit} byte campaign limit")
        }
        _ => error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kahea_ingest::{load_openapi, resolve_operation};
    use kahea_test_server::remove_temporary_store;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    const SPEC: &str = r#"
openapi: 3.1.0
info: { title: Conformance, version: 1 }
servers: [{ url: "https://api.example.test" }]
paths:
  /widgets/{id}:
    post:
      operationId: updateWidget
      parameters:
        - { name: id, in: path, required: true, schema: { type: string, minLength: 1, maxLength: 8 } }
        - { name: verbose, in: query, required: true, schema: { type: boolean } }
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              additionalProperties: false
              required: [name, count]
              properties:
                name: { type: string, minLength: 1, maxLength: 8 }
                count: { type: integer, minimum: 0, maximum: 10 }
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema: { type: object }
        "400":
          description: rejected
          content:
            application/json:
              schema: { type: object }
"#;

    fn fixture() -> (OpenApiSource, OperationDefinition) {
        let source = load_openapi(Path::new("conformance.yaml"), SPEC.as_bytes()).unwrap();
        let operation = resolve_operation(&source, "updateWidget").unwrap();
        (source, operation)
    }

    #[test]
    fn generation_is_seeded_sealed_mixed_and_reproducible() {
        let (source, operation) = fixture();
        let options = ConformanceOptions {
            cases: 8,
            seed: 42,
            ..ConformanceOptions::default()
        };
        let first = build_conformance_plan(
            &source,
            &operation,
            options.clone(),
            &ProjectConfiguration::default(),
        )
        .unwrap();
        let second = build_conformance_plan(
            &source,
            &operation,
            options,
            &ProjectConfiguration::default(),
        )
        .unwrap();
        assert_eq!(
            serde_json::to_vec(&first.0).unwrap(),
            serde_json::to_vec(&second.0).unwrap()
        );
        let different = build_conformance_plan(
            &source,
            &operation,
            ConformanceOptions {
                cases: 8,
                seed: 43,
                ..ConformanceOptions::default()
            },
            &ProjectConfiguration::default(),
        )
        .unwrap();
        assert_ne!(first.0.fingerprint, different.0.fingerprint);
        assert!(first.0.verify_seal().unwrap());
        assert_eq!(first.0.cases.len(), 8);
        assert!(
            first
                .0
                .required_grants
                .contains(&"conformance:execute:8".into())
        );
        assert!(
            first
                .0
                .required_grants
                .contains(&"conformance:negative".into())
        );
        assert!(
            first
                .0
                .cases
                .iter()
                .any(|case| case.generation == ConformanceGeneration::Positive)
        );
        assert!(
            first
                .0
                .cases
                .iter()
                .any(|case| case.generation == ConformanceGeneration::Negative)
        );
        for request in &first.1 {
            if !request.valid {
                assert!(
                    request
                        .required_grants
                        .contains(&"conformance:negative".into())
                );
            }
        }
    }

    #[test]
    fn path_mutation_replaces_only_the_matching_path_segment() {
        let (source, operation) = fixture();
        let (_, mut requests) = build_conformance_plan(
            &source,
            &operation,
            ConformanceOptions {
                cases: 2,
                seed: 42,
                mode: ConformanceMode::Positive,
                ..ConformanceOptions::default()
            },
            &ProjectConfiguration::default(),
        )
        .unwrap();
        let plan = requests.first_mut().unwrap();
        let derivation = plan
            .derivations
            .iter_mut()
            .find(|derivation| derivation.field == "path.id")
            .unwrap();
        derivation.wire_value = Some("1".into());
        plan.target = "http://127.0.0.1:8080/widgets/1".into();

        assert!(replace_parameter(plan, "path", "id", "not-a-number").unwrap());
        assert_eq!(plan.target, "http://127.0.0.1:8080/widgets/not-a-number");
    }

    #[test]
    fn storage_rechecks_campaign_and_every_case() {
        let (source, operation) = fixture();
        let (campaign, requests) = build_conformance_plan(
            &source,
            &operation,
            ConformanceOptions {
                cases: 4,
                seed: 7,
                ..ConformanceOptions::default()
            },
            &ProjectConfiguration::default(),
        )
        .unwrap();
        let root =
            std::env::temp_dir().join(format!("kahea-conformance-store-{}", std::process::id()));
        store_conformance_plan(&root, &campaign, &requests).unwrap();
        assert_eq!(
            load_conformance_plan(&root, &campaign.id)
                .unwrap()
                .fingerprint,
            campaign.fingerprint
        );
        remove_temporary_store(&root);
    }

    #[test]
    fn storage_rejects_a_case_fingerprint_mismatch_with_a_valid_request() {
        let (source, operation) = fixture();
        let (mut campaign, requests) = build_conformance_plan(
            &source,
            &operation,
            ConformanceOptions {
                cases: 1,
                mode: ConformanceMode::Positive,
                ..ConformanceOptions::default()
            },
            &ProjectConfiguration::default(),
        )
        .unwrap();
        campaign.cases[0].plan_fingerprint = "request:fingerprint:mismatch".into();
        campaign = campaign.seal().unwrap();
        let root = std::env::temp_dir().join(format!(
            "kahea-conformance-store-mismatch-{}",
            std::process::id()
        ));

        assert!(matches!(
            store_conformance_plan(&root, &campaign, &requests),
            Err(ConformanceError::InvalidCase(_))
        ));
        remove_temporary_store(&root);
    }

    #[test]
    fn campaign_denial_reports_the_first_exact_missing_grant_without_transport() {
        let (source, operation) = fixture();
        let (campaign, requests) = build_conformance_plan(
            &source,
            &operation,
            ConformanceOptions {
                cases: 4,
                seed: 11,
                ..ConformanceOptions::default()
            },
            &ProjectConfiguration::default(),
        )
        .unwrap();
        let root =
            std::env::temp_dir().join(format!("kahea-conformance-denial-{}", std::process::id()));
        store_conformance_plan(&root, &campaign, &requests).unwrap();
        let evidence = EvidenceStore::open(root.join("store")).unwrap();
        let observation =
            invoke_conformance(&campaign, &InvokeOptions::default(), &root, &evidence).unwrap();
        assert_eq!(observation.exit, 4);
        assert_eq!(
            observation.required.as_deref(),
            Some("conformance:execute:4")
        );
        assert_eq!(observation.executed, 0);
        drop(evidence);
        remove_temporary_store(&root);
    }

    #[test]
    fn runtime_rechecks_the_case_request_digest() {
        let (source, operation) = fixture();
        let (mut campaign, requests) = build_conformance_plan(
            &source,
            &operation,
            ConformanceOptions {
                cases: 1,
                mode: ConformanceMode::Positive,
                ..ConformanceOptions::default()
            },
            &ProjectConfiguration::default(),
        )
        .unwrap();
        campaign.cases[0].request_digest = "request:digest:mismatch".into();
        campaign = campaign.seal().unwrap();
        let root = std::env::temp_dir().join(format!(
            "kahea-conformance-digest-mismatch-{}",
            std::process::id()
        ));
        store_conformance_plan(&root, &campaign, &requests).unwrap();
        let evidence = EvidenceStore::open(root.join("store")).unwrap();
        let options = InvokeOptions {
            grants: campaign.required_grants.iter().cloned().collect(),
            ..InvokeOptions::default()
        };

        assert!(matches!(
            invoke_conformance(&campaign, &options, &root, &evidence),
            Err(ConformanceError::InvalidCase(_))
        ));
        drop(evidence);
        remove_temporary_store(&root);
    }

    #[test]
    fn a_case_level_denial_controls_the_campaign_outcome() {
        let (source, operation) = fixture();
        let (mut campaign, requests) = build_conformance_plan(
            &source,
            &operation,
            ConformanceOptions {
                cases: 1,
                mode: ConformanceMode::Positive,
                ..ConformanceOptions::default()
            },
            &ProjectConfiguration::default(),
        )
        .unwrap();
        let request_grant = requests[0]
            .required_grants
            .iter()
            .find(|grant| !grant.starts_with("conformance:"))
            .expect("request has a runtime grant")
            .clone();
        campaign
            .required_grants
            .retain(|grant| grant != &request_grant);
        campaign = campaign.seal().unwrap();
        let root = std::env::temp_dir().join(format!(
            "kahea-conformance-case-denial-{}",
            std::process::id()
        ));
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

        assert_eq!(observation.executed, 1);
        assert_eq!(observation.failed, 1);
        assert_eq!(observation.exit, 4);
        assert!(matches!(observation.outcome, Outcome::Denied));
        drop(evidence);
        remove_temporary_store(&root);
    }

    #[test]
    fn transport_failures_are_counted_and_classified() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let spec = SPEC.replace(
            "https://api.example.test",
            &format!("http://127.0.0.1:{port}"),
        );
        let source = load_openapi(Path::new("conformance.yaml"), spec.as_bytes()).unwrap();
        let operation = resolve_operation(&source, "updateWidget").unwrap();
        let (campaign, requests) = build_conformance_plan(
            &source,
            &operation,
            ConformanceOptions {
                cases: 2,
                max_failures: 2,
                mode: ConformanceMode::Positive,
                ..ConformanceOptions::default()
            },
            &ProjectConfiguration::default(),
        )
        .unwrap();
        let root = std::env::temp_dir().join(format!(
            "kahea-conformance-transport-{}",
            std::process::id()
        ));
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

        assert_eq!(observation.executed, 2);
        assert_eq!(observation.failed, 2);
        assert_eq!(observation.transport_errors, 2);
        assert_eq!(observation.exit, 3);
        assert!(matches!(observation.outcome, Outcome::Failed));
        assert!(
            observation
                .cases
                .iter()
                .all(|case| case.reason == "transport failed")
        );
        drop(evidence);
        remove_temporary_store(&root);
    }

    #[test]
    fn campaign_limits_fail_closed_before_case_generation() {
        let (source, operation) = fixture();
        for options in [
            ConformanceOptions {
                cases: 0,
                ..ConformanceOptions::default()
            },
            ConformanceOptions {
                cases: MAX_CASES + 1,
                ..ConformanceOptions::default()
            },
            ConformanceOptions {
                delay_ms: MAX_DELAY_MS + 1,
                ..ConformanceOptions::default()
            },
            ConformanceOptions {
                max_failures: 0,
                ..ConformanceOptions::default()
            },
        ] {
            assert!(matches!(
                build_conformance_plan(
                    &source,
                    &operation,
                    options,
                    &ProjectConfiguration::default(),
                ),
                Err(ConformanceError::InvalidOption(_))
            ));
        }
    }

    #[test]
    fn explicit_baselines_are_preserved_while_missing_fields_are_generated() {
        let (source, operation) = fixture();
        let (_, requests) = build_conformance_plan(
            &source,
            &operation,
            ConformanceOptions {
                cases: 2,
                mode: ConformanceMode::Positive,
                plan: PlanOptions {
                    explicit: vec![
                        ("path.id".into(), json!("fixed-id")),
                        ("body.name".into(), json!("fixed-name")),
                    ],
                    ..PlanOptions::default()
                },
                ..ConformanceOptions::default()
            },
            &ProjectConfiguration::default(),
        )
        .unwrap();
        for request in requests {
            assert!(request.target.contains("/widgets/fixed-id"));
            let body: Value = serde_json::from_str(&request.body.as_ref().unwrap().inline).unwrap();
            assert_eq!(body["name"], "fixed-name");
            assert!(body["count"].is_number());
        }
    }

    #[test]
    fn filling_a_missing_baseline_property_charges_one_depth_level() {
        let (source, _) = fixture();
        let schema = json!({
            "type": "object",
            "required": ["child"],
            "properties": {"child": {"type": "string"}}
        });

        let error = generate_value_with_baseline(
            &source,
            &schema,
            0,
            "body",
            MAX_GENERATION_DEPTH - 1,
            Some(&json!({})),
        )
        .expect_err("the generated child must cross the depth limit");

        assert!(matches!(
            error,
            ConformanceError::Generation { path, reason }
                if path == "body.child" && reason == "schema generation exceeded 32 levels"
        ));
    }

    #[test]
    fn filling_min_properties_charges_one_depth_level() {
        let (source, _) = fixture();
        let schema = json!({
            "type": "object",
            "minProperties": 1,
            "properties": {"child": {"type": "string"}}
        });

        let error = generate_value(&source, &schema, 1, "body", MAX_GENERATION_DEPTH - 1)
            .expect_err("the minProperties child must cross the depth limit");

        assert!(matches!(
            error,
            ConformanceError::Generation { path, reason }
                if path == "body.child" && reason == "schema generation exceeded 32 levels"
        ));
    }

    #[test]
    fn each_non_finite_numeric_bound_is_invalid_on_its_own() {
        assert!(numeric_bounds_are_invalid(f64::INFINITY, 1.0));
        assert!(numeric_bounds_are_invalid(0.0, f64::INFINITY));
        assert!(numeric_bounds_are_invalid(1.0, -1.0));
        assert!(!numeric_bounds_are_invalid(-1.0, 1.0));
    }

    #[test]
    fn recursive_invalid_values_charge_one_depth_level() {
        let (source, _) = fixture();
        for (schema, value) in [
            (
                json!({"properties": {"child": {"type": "string"}}}),
                json!({"child": "valid"}),
            ),
            (json!({"items": {"type": "string"}}), json!(["valid"])),
        ] {
            assert!(
                invalid_json_values(&source, &schema, &value, "body", MAX_GENERATION_DEPTH - 1,)
                    .unwrap()
                    .is_empty(),
                "a nested invalid value crossed the generation depth limit"
            );
        }
    }

    #[test]
    fn invalid_json_representatives_are_type_specific_and_bounded() {
        let sentinel = json!("__kahea_outside_enum__");
        assert_eq!(
            invalid_value(&json!({"enum": ["inside"]}), &json!("inside")),
            Some(sentinel.clone())
        );
        assert_eq!(
            invalid_value(
                &json!({"type": "string", "enum": ["__kahea_outside_enum__"]}),
                &sentinel,
            ),
            Some(json!(false))
        );
        assert_eq!(
            invalid_value(&json!({"type": "string", "minLength": 1}), &json!("x")),
            Some(json!(""))
        );
        assert_eq!(
            invalid_value(&json!({"type": "string", "minLength": 0}), &json!("x")),
            Some(json!(false))
        );
        assert_eq!(
            invalid_value(&json!({"type": "string", "maxLength": 2}), &json!("x")),
            Some(json!("xxx"))
        );
        assert_eq!(
            invalid_value(
                &json!({"type": "string", "maxLength": MAX_GENERATED_STRING}),
                &json!("x"),
            ),
            Some(json!(false))
        );
        for (kind, invalid) in [
            ("integer", json!("not-a-number")),
            ("number", json!("not-a-number")),
            ("boolean", json!("not-a-boolean")),
            ("array", json!({"not": "an-array"})),
            ("object", json!(["not-an-object"])),
            ("null", json!(true)),
        ] {
            assert_eq!(
                invalid_value(&json!({"type": kind}), &Value::Null),
                Some(invalid),
                "wrong invalid representative for {kind}"
            );
        }
        assert_eq!(
            invalid_value(&json!({}), &json!("value")),
            Some(json!(false))
        );
        assert_eq!(invalid_value(&json!({}), &json!(1)), None);
    }

    #[test]
    fn invalid_parameter_scalars_are_type_specific_and_bounded() {
        assert_eq!(
            invalid_scalar(&json!({"enum": ["inside"]})).as_deref(),
            Some("__kahea_outside_enum__")
        );
        for kind in ["integer", "number"] {
            assert_eq!(
                invalid_scalar(&json!({"type": kind})).as_deref(),
                Some("not-a-number")
            );
        }
        assert_eq!(
            invalid_scalar(&json!({"type": "boolean"})).as_deref(),
            Some("not-a-boolean")
        );
        assert_eq!(
            invalid_scalar(&json!({"type": "string", "minLength": 1})),
            Some(String::new())
        );
        assert_eq!(
            invalid_scalar(&json!({"type": "string", "minLength": 0})),
            None
        );
    }

    #[test]
    fn optional_parameters_are_never_required_omissions() {
        let spec = SPEC.replace(
            "        - { name: verbose, in: query, required: true, schema: { type: boolean } }",
            concat!(
                "        - { name: verbose, in: query, required: true, schema: { type: boolean } }\n",
                "        - { name: optional, in: query, schema: { type: boolean } }",
            ),
        );
        let source = load_openapi(Path::new("conformance.yaml"), spec.as_bytes()).unwrap();
        let operation = resolve_operation(&source, "updateWidget").unwrap();
        let (_, plans) = build_conformance_plan(
            &source,
            &operation,
            ConformanceOptions {
                cases: 1,
                mode: ConformanceMode::Positive,
                plan: PlanOptions {
                    explicit: vec![("query.optional".into(), json!(true))],
                    ..PlanOptions::default()
                },
                ..ConformanceOptions::default()
            },
            &ProjectConfiguration::default(),
        )
        .unwrap();

        for plan in plans {
            let strategies: Vec<_> = negative_plans(&source, &operation, &plan)
                .unwrap()
                .into_iter()
                .map(|(strategy, _)| strategy)
                .collect();
            assert!(
                !strategies
                    .iter()
                    .any(|strategy| strategy == "omit-required-query:optional"),
                "optional parameter was treated as required: {strategies:?}"
            );
        }
    }

    #[test]
    fn oracle_distinguishes_acceptance_rejection_and_server_errors() {
        fn observation(status: u16, exit: u8) -> InvocationResult {
            InvocationResult::Observation(kahea_core::Observation {
                protocol: PROTOCOL.into(),
                kind: "observation".into(),
                version: VERSION.into(),
                config_fingerprint: String::new(),
                policy_fingerprint: String::new(),
                source_fingerprints: Vec::new(),
                tool_version: VERSION.into(),
                plan: "plan:test".into(),
                outcome: if exit == 0 {
                    Outcome::Passed
                } else {
                    Outcome::Failed
                },
                status: Some(status),
                response_schema: None,
                latency_ms: None,
                response_bytes: None,
                body: None,
                trace: None,
                resolved_origin: None,
                http_version: None,
                secret_refs: Vec::new(),
                runtime: "test".into(),
                exit,
            })
        }
        assert!(assess(ConformanceGeneration::Positive, &observation(200, 0)).0);
        assert!(assess(ConformanceGeneration::Negative, &observation(400, 0)).0);
        assert_eq!(
            assess(ConformanceGeneration::Negative, &observation(200, 0)),
            (
                false,
                Some(200),
                "schema-invalid request was accepted".into()
            )
        );
        assert_eq!(
            assess(ConformanceGeneration::Negative, &observation(302, 0)),
            (
                false,
                Some(302),
                "invalid request rejection did not conform to the response contract".into()
            )
        );
        assert!(!assess(ConformanceGeneration::Positive, &observation(500, 0)).0);
    }

    #[test]
    fn pacing_waits_only_between_cases() {
        assert_eq!(campaign_delay(0, 0), None);
        assert_eq!(campaign_delay(0, 1), None);
        assert_eq!(campaign_delay(1, 0), None);
        assert_eq!(campaign_delay(1, 1), Some(Duration::from_millis(1)));
    }

    #[test]
    fn execution_errors_have_safe_specific_reasons() {
        assert_eq!(
            safe_exec_reason(&ExecError::Transport("secret detail".into())),
            "transport failed"
        );
        assert_eq!(
            safe_exec_reason(&ExecError::ResponseTooLarge(512)),
            "response exceeded the 512 byte campaign limit"
        );
        assert_eq!(
            safe_exec_reason(&ExecError::InvalidTarget("bad target".into())),
            "invalid target URL: bad target"
        );
    }

    #[test]
    fn mixed_campaign_executes_through_policy_and_response_conformance() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let spec = SPEC.replace(
            "https://api.example.test",
            &format!("http://127.0.0.1:{port}"),
        );
        let source = load_openapi(Path::new("conformance.yaml"), spec.as_bytes()).unwrap();
        let operation = resolve_operation(&source, "updateWidget").unwrap();
        let (campaign, requests) = build_conformance_plan(
            &source,
            &operation,
            ConformanceOptions {
                cases: 8,
                seed: 99,
                ..ConformanceOptions::default()
            },
            &ProjectConfiguration::default(),
        )
        .unwrap();
        let count = campaign.cases.len();
        let server = thread::spawn(move || {
            for _ in 0..count {
                let (mut stream, _) = listener.accept().unwrap();
                let mut bytes = vec![0_u8; 32 * 1024];
                let read = stream.read(&mut bytes).unwrap();
                let request = String::from_utf8_lossy(&bytes[..read]);
                let (head, body) = request.split_once("\r\n\r\n").unwrap_or((&request, ""));
                let document = serde_json::from_str::<Value>(body).unwrap_or(Value::Null);
                let valid = head
                    .lines()
                    .next()
                    .is_some_and(|line| line.contains("verbose="))
                    && document.get("name").is_some_and(Value::is_string)
                    && document.get("count").is_some_and(Value::is_number)
                    && document.as_object().is_some_and(|object| {
                        object
                            .keys()
                            .all(|key| matches!(key.as_str(), "name" | "count"))
                    });
                let status = if valid { "200 OK" } else { "400 Bad Request" };
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
                )
                .unwrap();
            }
        });
        let root =
            std::env::temp_dir().join(format!("kahea-conformance-invoke-{}", std::process::id()));
        store_conformance_plan(&root, &campaign, &requests).unwrap();
        let evidence = EvidenceStore::open(root.join("store")).unwrap();
        let options = InvokeOptions {
            grants: campaign.required_grants.iter().cloned().collect(),
            expected_config_fingerprint: Some(campaign.config_fingerprint.clone()),
            expected_policy_fingerprint: Some(campaign.policy_fingerprint.clone()),
            ..InvokeOptions::default()
        };
        let observation = invoke_conformance(&campaign, &options, &root, &evidence).unwrap();
        assert_eq!(observation.exit, 0);
        assert_eq!(observation.executed, campaign.cases.len());
        assert_eq!(observation.passed, campaign.cases.len());
        assert_eq!(observation.failed, 0);
        server.join().unwrap();
        drop(evidence);
        remove_temporary_store(&root);
    }
}
