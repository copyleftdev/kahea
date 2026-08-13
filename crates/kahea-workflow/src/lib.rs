//! Arazzo 1.1 workflow planning and controlled ordered execution.

use base64::Engine;
use kahea_core::{
    OperationIndexEnvelope, OperationSummary, Outcome, PROTOCOL, RiskClass, VERSION,
    WebSocketObservation, WorkflowObservation, WorkflowParameterBinding, WorkflowPlan,
    WorkflowStepObservation, WorkflowStepTemplate, WorkflowStepTransport, WorkflowWebSocketBinding,
    default_config_fingerprint, digest, short_handle,
};
use kahea_evidence::EvidenceStore;
use kahea_exec::{
    InvocationResult, InvokeOptions, WebSocketConnectResult, execute_websocket, invoke,
};
use kahea_ingest::{OpenApiSource, load_source, parse_data_document, resolve_operation};
use kahea_plan::{
    PlanOptions, ProjectConfiguration, build_plan_with_configuration,
    build_websocket_plan_with_configuration, is_websocket_session, store_plan,
    store_websocket_plan,
};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Instant;
use thiserror::Error;
use url::Url;

const WEBSOCKET_SOURCE_EXTENSION: &str = "x-kahea-source-kind";
const WEBSOCKET_SOURCE_KIND: &str = "websocket-session";

#[derive(Debug)]
enum WorkflowSource {
    Http(OpenApiSource),
    WebSocket {
        path: PathBuf,
        bytes: Vec<u8>,
        document: Value,
        source_fingerprint: String,
    },
}

impl WorkflowSource {
    fn document(&self) -> &Value {
        match self {
            Self::Http(source) => &source.document,
            Self::WebSocket { document, .. } => document,
        }
    }

    fn source_fingerprint(&self) -> &str {
        match self {
            Self::Http(source) => &source.source_fingerprint,
            Self::WebSocket {
                source_fingerprint, ..
            } => source_fingerprint,
        }
    }
}

#[derive(Debug, Error)]
pub enum WorkflowError {
    #[error("Arazzo document error: {0}")]
    Invalid(String),
    #[error("workflow {0:?} was not found")]
    UnknownWorkflow(String),
    #[error("workflow source error: {0}")]
    Source(String),
    #[error("workflow step {step:?} failed to plan: {reason}")]
    StepPlan { step: String, reason: String },
    #[error("workflow plan seal is invalid")]
    InvalidSeal,
    #[error("workflow store error: {0}")]
    Store(#[from] std::io::Error),
    #[error("workflow serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("workflow evidence error: {0}")]
    Evidence(#[from] kahea_evidence::EvidenceError),
}

pub fn is_arazzo(document: &Value) -> bool {
    document
        .get("arazzo")
        .and_then(Value::as_str)
        .is_some_and(|version| version.starts_with("1.1."))
}

pub fn inspect_workflows(
    document: &Value,
    bytes: &[u8],
    query: Option<&str>,
    limit: usize,
    cursor: usize,
) -> Result<OperationIndexEnvelope, WorkflowError> {
    if !is_arazzo(document) {
        return Err(WorkflowError::Invalid(
            "expected an Arazzo 1.1.x document".into(),
        ));
    }
    let source_fingerprint = digest(bytes);
    let source = short_handle("src", &[bytes]);
    let query = query.unwrap_or_default().trim().to_ascii_lowercase();
    let mut operations: Vec<_> = document
        .get("workflows")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|workflow| {
            let id = workflow.get("workflowId")?.as_str()?;
            let summary = workflow
                .get("summary")
                .or_else(|| workflow.get("description"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !query.is_empty()
                && !id.to_ascii_lowercase().contains(&query)
                && !summary.to_ascii_lowercase().contains(&query)
            {
                return None;
            }
            Some(OperationSummary(
                short_handle("workflow", &[source_fingerprint.as_bytes(), id.as_bytes()]),
                "WORKFLOW".into(),
                format!("workflow/{id}"),
                id.into(),
                RiskClass::Unknown,
            ))
        })
        .collect();
    operations.sort_by(|left, right| left.3.cmp(&right.3));
    if cursor > operations.len() {
        return Err(WorkflowError::Invalid(format!(
            "cursor {cursor} is outside the workflow set of {}",
            operations.len()
        )));
    }
    let end = cursor.saturating_add(limit).min(operations.len());
    let next = (end < operations.len()).then(|| end.to_string());
    Ok(OperationIndexEnvelope {
        protocol: PROTOCOL.into(),
        kind: "operation-index".into(),
        version: VERSION.into(),
        config_fingerprint: default_config_fingerprint(),
        source_fingerprints: vec![source_fingerprint],
        source,
        operations: operations.into_iter().skip(cursor).take(limit).collect(),
        next,
        absent: Vec::new(),
        exit: 0,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_workflow_plan(
    arazzo_path: &Path,
    document: &Value,
    workflow_id: &str,
    input: Value,
    auth: Option<String>,
    server: Option<String>,
    checks: Vec<String>,
    configuration: &ProjectConfiguration,
) -> Result<WorkflowPlan, WorkflowError> {
    if !is_arazzo(document) {
        return Err(WorkflowError::Invalid(
            "expected an Arazzo 1.1.x document".into(),
        ));
    }
    let workflows = document
        .get("workflows")
        .and_then(Value::as_array)
        .ok_or_else(|| WorkflowError::Invalid("workflows must be a non-empty array".into()))?;
    let workflow = workflows
        .iter()
        .find(|workflow| workflow.get("workflowId").and_then(Value::as_str) == Some(workflow_id))
        .ok_or_else(|| WorkflowError::UnknownWorkflow(workflow_id.into()))?;
    validate_workflow_inputs(workflow.get("inputs"), &input)?;
    let sources = load_sources(arazzo_path, document)?;
    let mut steps = Vec::new();
    let mut required_grants = BTreeSet::new();
    let mut risk = RiskClass::Read;
    let step_values = workflow
        .get("steps")
        .and_then(Value::as_array)
        .ok_or_else(|| WorkflowError::Invalid("workflow steps must be a non-empty array".into()))?;
    if step_values.is_empty() || step_values.len() > 100 {
        return Err(WorkflowError::Invalid(
            "workflow must contain between 1 and 100 steps".into(),
        ));
    }
    let mut step_ids = BTreeSet::new();
    for step in step_values {
        let step_id = step
            .get("stepId")
            .and_then(Value::as_str)
            .ok_or_else(|| WorkflowError::Invalid("every step requires stepId".into()))?;
        if step_ids.contains(step_id) {
            return Err(WorkflowError::Invalid(format!(
                "duplicate stepId {step_id:?}"
            )));
        }
        let depends_on = step
            .get("dependsOn")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|dependency| {
                dependency.as_str().map(str::to_string).ok_or_else(|| {
                    WorkflowError::Invalid(format!(
                        "step {step_id:?} dependsOn values must be strings"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        for dependency in &depends_on {
            if !step_ids.contains(dependency) {
                return Err(WorkflowError::Invalid(format!(
                    "step {step_id:?} dependency {dependency:?} must reference an earlier step"
                )));
            }
        }
        step_ids.insert(step_id.to_string());
        let (source_name, selector) = step_operation(step, &sources)?;
        let source = sources.get(&source_name).expect("step source was resolved");
        let (transport, websocket_plan) = match source {
            WorkflowSource::Http(source) => {
                let operation = resolve_operation(source, &selector)
                    .map_err(|error| WorkflowError::Source(error.to_string()))?;
                let effective_risk = configuration
                    .risk
                    .get(&format!("{} {}", operation.method, operation.path))
                    .copied()
                    .unwrap_or(operation.risk);
                risk = maximum_risk(risk, effective_risk);
                preview_grants(
                    source,
                    &operation,
                    server.as_deref(),
                    auth.as_deref(),
                    configuration,
                    &mut required_grants,
                )?;
                (WorkflowStepTransport::Http, None)
            }
            WorkflowSource::WebSocket { path, bytes, .. } => {
                let plan = build_websocket_plan_with_configuration(path, bytes, configuration)
                    .map_err(|error| WorkflowError::StepPlan {
                        step: step_id.into(),
                        reason: error.to_string(),
                    })?;
                let operation_id = source
                    .document()
                    .get("operationId")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        WorkflowError::Invalid(format!(
                            "WebSocket source {source_name:?} has no operationId"
                        ))
                    })?;
                if selector != operation_id && selector != plan.operation {
                    return Err(WorkflowError::Invalid(format!(
                        "WebSocket step {step_id:?} selects unknown operation {selector:?}"
                    )));
                }
                risk = maximum_risk(risk, plan.risk);
                required_grants.extend(plan.required_grants.iter().cloned());
                (WorkflowStepTransport::WebSocket, Some(plan))
            }
        };
        let parameters = step
            .get("parameters")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|parameter| {
                Ok(WorkflowParameterBinding {
                    name: parameter
                        .get("name")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            WorkflowError::Invalid(format!(
                                "step {step_id:?} parameter has no name"
                            ))
                        })?
                        .into(),
                    location: parameter
                        .get("in")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    value: parameter.get("value").cloned().ok_or_else(|| {
                        WorkflowError::Invalid(format!("step {step_id:?} parameter has no value"))
                    })?,
                })
            })
            .collect::<Result<Vec<_>, WorkflowError>>()?;
        let request_body = step
            .get("requestBody")
            .and_then(|body| body.get("payload").or_else(|| body.get("content")))
            .cloned();
        let websocket_bindings = if transport == WorkflowStepTransport::WebSocket {
            if !parameters.is_empty() || request_body.is_some() {
                return Err(WorkflowError::Invalid(format!(
                    "WebSocket step {step_id:?} uses x-kahea-websocket-bindings, not HTTP parameters or requestBody"
                )));
            }
            parse_websocket_bindings(step, source.document())?
        } else {
            if step.get("x-kahea-websocket-bindings").is_some() {
                return Err(WorkflowError::Invalid(format!(
                    "HTTP step {step_id:?} cannot declare x-kahea-websocket-bindings"
                )));
            }
            Vec::new()
        };
        let outputs: BTreeMap<String, Value> = step
            .get("outputs")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        if transport == WorkflowStepTransport::WebSocket {
            for expression in outputs.values() {
                validate_websocket_output_expression(expression)?;
            }
        }
        let success_criteria = value_array(step, "successCriteria");
        if transport == WorkflowStepTransport::WebSocket && !success_criteria.is_empty() {
            return Err(WorkflowError::Invalid(format!(
                "WebSocket step {step_id:?} expresses success through its sealed expect actions"
            )));
        } else {
            for criterion in &success_criteria {
                criterion_to_check(criterion)?;
            }
        }
        let on_success = value_array(step, "onSuccess");
        let on_failure = value_array(step, "onFailure");
        validate_actions(step_id, &on_success, true)?;
        validate_actions(step_id, &on_failure, false)?;
        if transport == WorkflowStepTransport::WebSocket
            && on_success
                .iter()
                .chain(&on_failure)
                .any(|action| !value_array(action, "criteria").is_empty())
        {
            return Err(WorkflowError::Invalid(format!(
                "WebSocket step {step_id:?} supports deterministic retry/end actions without HTTP response criteria"
            )));
        }
        let mut deferred = Vec::new();
        collect_runtime_expressions(step, &mut deferred);
        deferred.sort();
        deferred.dedup();
        steps.push(WorkflowStepTemplate {
            step_id: step_id.into(),
            source_name,
            source_document: source.document().clone(),
            source_fingerprint: source.source_fingerprint().into(),
            operation: selector,
            parameters,
            request_body,
            outputs,
            deferred_bindings: deferred,
            depends_on,
            success_criteria,
            on_success,
            on_failure,
            timeout_ms: step.get("timeout").and_then(Value::as_u64),
            transport,
            websocket_plan,
            websocket_bindings,
        });
    }
    let mut source_fingerprints: Vec<_> = sources
        .values()
        .map(|source| source.source_fingerprint().to_string())
        .collect();
    source_fingerprints.push(digest(&serde_json::to_vec(document)?));
    source_fingerprints.sort();
    let websocket_policy_fingerprint = steps
        .iter()
        .any(|step| step.transport == WorkflowStepTransport::WebSocket)
        .then(|| configuration.websocket_policy_fingerprint())
        .transpose()
        .map_err(|error| WorkflowError::Invalid(error.to_string()))?;
    WorkflowPlan {
        protocol: PROTOCOL.into(),
        kind: "workflow-plan".into(),
        version: VERSION.into(),
        config_fingerprint: configuration
            .config_fingerprint()
            .map_err(|error| WorkflowError::Invalid(error.to_string()))?,
        policy_fingerprint: configuration
            .policy_fingerprint()
            .map_err(|error| WorkflowError::Invalid(error.to_string()))?,
        source_fingerprints,
        id: String::new(),
        workflow: workflow_id.into(),
        input,
        steps,
        risk,
        required_grants: required_grants.into_iter().collect(),
        auth,
        server,
        checks,
        websocket_policy_fingerprint,
        fingerprint: String::new(),
        exit: 0,
    }
    .seal()
    .map_err(WorkflowError::Serialization)
}

pub fn store_workflow_plan(root: &Path, plan: &WorkflowPlan) -> Result<PathBuf, WorkflowError> {
    if !plan.verify_seal()? {
        return Err(WorkflowError::InvalidSeal);
    }
    let directory = root.join("store/plans");
    fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{}.json", plan.id.replace(':', "-")));
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, serde_json::to_vec(plan)?)?;
    fs::rename(temporary, &path)?;
    Ok(path)
}

pub fn load_workflow_plan(root: &Path, reference: &str) -> Result<WorkflowPlan, WorkflowError> {
    let path = if reference.starts_with("workflow-plan:") {
        root.join("store/plans")
            .join(format!("{}.json", reference.replace(':', "-")))
    } else {
        PathBuf::from(reference)
    };
    let plan: WorkflowPlan = serde_json::from_slice(&fs::read(path)?)?;
    if !plan.verify_seal()? {
        return Err(WorkflowError::InvalidSeal);
    }
    Ok(plan)
}

pub fn invoke_workflow(
    plan: &WorkflowPlan,
    options: &InvokeOptions,
    configuration: &ProjectConfiguration,
    store_root: &Path,
    evidence: &EvidenceStore,
) -> Result<WorkflowObservation, WorkflowError> {
    if !plan.verify_seal()? {
        return Err(WorkflowError::InvalidSeal);
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
        return Err(WorkflowError::Invalid(
            "workflow configuration or policy fingerprint mismatch".into(),
        ));
    }
    if let Some(expected) = &plan.websocket_policy_fingerprint
        && configuration
            .websocket_policy_fingerprint()
            .map_err(|error| WorkflowError::Invalid(error.to_string()))?
            != *expected
    {
        return Err(WorkflowError::Invalid(
            "workflow WebSocket policy fingerprint mismatch".into(),
        ));
    }
    if let Some(missing) = plan
        .required_grants
        .iter()
        .find(|grant| !options.grants.contains(*grant))
    {
        return Ok(workflow_denial(plan, missing));
    }
    let mut observations = Vec::new();
    let mut step_outputs: BTreeMap<String, BTreeMap<String, Value>> = BTreeMap::new();
    let workflow_started = Instant::now();
    for step in &plan.steps {
        if step.transport == WorkflowStepTransport::WebSocket {
            let run = invoke_websocket_workflow_step(
                step,
                &plan.input,
                &step_outputs,
                options,
                configuration,
                store_root,
                evidence,
                workflow_started,
            )?;
            observations.push(WorkflowStepObservation {
                step_id: step.step_id.clone(),
                plan: Some(run.plan),
                attempts: run.attempts,
                result: run.result,
            });
            if run.exit != 0 {
                return Ok(failed_workflow_observation(plan, observations, run.exit));
            }
            step_outputs.insert(step.step_id.clone(), run.outputs);
            if step
                .on_success
                .iter()
                .any(|action| action.get("type").and_then(Value::as_str) == Some("end"))
            {
                break;
            }
            continue;
        }
        let source_bytes = serde_json::to_vec(&step.source_document)?;
        let source = OpenApiSource {
            document: step.source_document.clone(),
            source_fingerprint: step.source_fingerprint.clone(),
            source_handle: kahea_core::short_handle("src", &[&source_bytes]),
        };
        let operation = resolve_operation(&source, &step.operation)
            .map_err(|error| WorkflowError::Source(error.to_string()))?;
        let mut explicit = Vec::new();
        for parameter in &step.parameters {
            let location = parameter
                .location
                .clone()
                .or_else(|| parameter_location(&operation, &source, &parameter.name))
                .ok_or_else(|| {
                    WorkflowError::Invalid(format!(
                        "step {:?} parameter {:?} has ambiguous location",
                        step.step_id, parameter.name
                    ))
                })?;
            let value = materialize(&parameter.value, &plan.input, &step_outputs)?;
            explicit.push((format!("{location}.{}", parameter.name), value));
        }
        let input = step
            .request_body
            .as_ref()
            .map(|body| materialize(body, &plan.input, &step_outputs))
            .transpose()?
            .map(|body| Value::Object(Map::from_iter([("body".into(), body)])));
        let mut checks = plan.checks.clone();
        for criterion in &step.success_criteria {
            checks.push(criterion_to_check(criterion)?);
        }
        let request_plan = build_plan_with_configuration(
            &source,
            &operation,
            PlanOptions {
                server: plan.server.clone(),
                auth: plan.auth.clone(),
                content_type: None,
                input,
                explicit,
                checks,
            },
            configuration,
        )
        .map_err(|error| WorkflowError::StepPlan {
            step: step.step_id.clone(),
            reason: error.to_string(),
        })?;
        store_plan(store_root, &request_plan).map_err(|error| WorkflowError::StepPlan {
            step: step.step_id.clone(),
            reason: error.to_string(),
        })?;
        let step_options = InvokeOptions {
            grants: options.grants.clone(),
            secrets: options.secrets.clone(),
            timeout: remaining_step_timeout(workflow_started, options.timeout, step.timeout_ms)?,
            max_response_bytes: options.max_response_bytes,
            expected_config_fingerprint: options.expected_config_fingerprint.clone(),
            expected_policy_fingerprint: options.expected_policy_fingerprint.clone(),
            additional_root_certificates_pem: options.additional_root_certificates_pem.clone(),
        };
        let mut attempts = Vec::new();
        let mut retries = 0_u64;
        let result = loop {
            match invoke(&request_plan, &step_options, evidence) {
                Ok(result) => {
                    attempts.push(match &result {
                        InvocationResult::Observation(observation) => {
                            serde_json::to_value(observation)?
                        }
                        InvocationResult::Denied(denial) => serde_json::to_value(denial)?,
                    });
                    if result.exit() != 0
                        && let Some(action) = select_action(&step.on_failure, &result, evidence)?
                        && action.get("type").and_then(Value::as_str) == Some("retry")
                        && retries < retry_limit(action)
                    {
                        retries += 1;
                        let delay = retry_delay(action);
                        if !delay.is_zero() {
                            sleep_retry_delay(workflow_started, options.timeout, delay)?;
                        }
                        continue;
                    }
                    break result;
                }
                Err(error) => {
                    attempts.push(serde_json::json!({
                        "protocol": PROTOCOL,
                        "kind": "workflow-attempt-error",
                        "message": error.to_string(),
                        "exit": 3
                    }));
                    if let Some(action) = unconditional_retry(&step.on_failure)
                        && retries < retry_limit(action)
                    {
                        retries += 1;
                        let delay = retry_delay(action);
                        if !delay.is_zero() {
                            sleep_retry_delay(workflow_started, options.timeout, delay)?;
                        }
                        continue;
                    }
                    return Err(WorkflowError::StepPlan {
                        step: step.step_id.clone(),
                        reason: error.to_string(),
                    });
                }
            }
        };
        let result_value = match &result {
            InvocationResult::Observation(observation) => serde_json::to_value(observation)?,
            InvocationResult::Denied(denial) => serde_json::to_value(denial)?,
        };
        observations.push(WorkflowStepObservation {
            step_id: step.step_id.clone(),
            plan: Some(request_plan.id.clone()),
            attempts,
            result: result_value,
        });
        if result.exit() != 0 {
            return Ok(failed_workflow_observation(
                plan,
                observations,
                result.exit(),
            ));
        }
        let InvocationResult::Observation(observation) = result else {
            unreachable!("nonzero denial returned above")
        };
        let body = observation
            .body
            .as_deref()
            .map(|handle| evidence.get(handle))
            .transpose()?
            .and_then(|record| serde_json::from_slice::<Value>(&record.data).ok());
        let mut outputs = BTreeMap::new();
        for (name, expression) in &step.outputs {
            outputs.insert(
                name.clone(),
                evaluate_output(expression, &observation, body.as_ref())?,
            );
        }
        step_outputs.insert(step.step_id.clone(), outputs);
        if select_action(
            &step.on_success,
            &InvocationResult::Observation(observation),
            evidence,
        )?
        .is_some_and(|action| action.get("type").and_then(Value::as_str) == Some("end"))
        {
            break;
        }
    }
    let outputs = step_outputs
        .into_iter()
        .flat_map(|(step, outputs)| {
            outputs
                .into_iter()
                .map(move |(name, value)| (format!("{step}.{name}"), value))
        })
        .collect();
    Ok(WorkflowObservation {
        protocol: PROTOCOL.into(),
        kind: "workflow-observation".into(),
        version: VERSION.into(),
        config_fingerprint: plan.config_fingerprint.clone(),
        policy_fingerprint: plan.policy_fingerprint.clone(),
        source_fingerprints: plan.source_fingerprints.clone(),
        workflow_plan: plan.id.clone(),
        outcome: Outcome::Passed,
        steps: observations,
        outputs,
        exit: 0,
    })
}

struct WebSocketStepRun {
    plan: String,
    attempts: Vec<Value>,
    result: Value,
    outputs: BTreeMap<String, Value>,
    exit: u8,
}

#[allow(clippy::too_many_arguments)]
fn invoke_websocket_workflow_step(
    step: &WorkflowStepTemplate,
    inputs: &Value,
    step_outputs: &BTreeMap<String, BTreeMap<String, Value>>,
    options: &InvokeOptions,
    configuration: &ProjectConfiguration,
    store_root: &Path,
    evidence: &EvidenceStore,
    workflow_started: Instant,
) -> Result<WebSocketStepRun, WorkflowError> {
    let sealed_websocket_plan = step.websocket_plan.as_ref().ok_or_else(|| {
        WorkflowError::Invalid(format!(
            "WebSocket step {:?} has no sealed child plan",
            step.step_id
        ))
    })?;
    let mut websocket_plan = sealed_websocket_plan.clone();
    if !step.websocket_bindings.is_empty() {
        let mut source = step.source_document.clone();
        for binding in &step.websocket_bindings {
            let value = materialize(&binding.value, inputs, step_outputs)?;
            let target = source.pointer_mut(&binding.pointer).ok_or_else(|| {
                WorkflowError::Invalid(format!(
                    "WebSocket binding pointer {:?} no longer resolves",
                    binding.pointer
                ))
            })?;
            *target = value;
        }
        let bytes = serde_json::to_vec(&source)?;
        websocket_plan = build_websocket_plan_with_configuration(
            Path::new("workflow-websocket-session.json"),
            &bytes,
            configuration,
        )
        .map_err(|error| WorkflowError::StepPlan {
            step: step.step_id.clone(),
            reason: error.to_string(),
        })?;
        validate_rebuilt_websocket_plan(
            &step.step_id,
            &step.operation,
            &source,
            sealed_websocket_plan,
            &websocket_plan,
        )?;
    }
    store_websocket_plan(store_root, &websocket_plan).map_err(|error| WorkflowError::StepPlan {
        step: step.step_id.clone(),
        reason: error.to_string(),
    })?;

    let mut attempts = Vec::new();
    let mut retries = 0_u64;
    let result = loop {
        let step_options = InvokeOptions {
            grants: options.grants.clone(),
            secrets: options.secrets.clone(),
            timeout: remaining_step_timeout(workflow_started, options.timeout, step.timeout_ms)?,
            max_response_bytes: options.max_response_bytes,
            expected_config_fingerprint: Some(websocket_plan.config_fingerprint.clone()),
            expected_policy_fingerprint: Some(websocket_plan.policy_fingerprint.clone()),
            additional_root_certificates_pem: options.additional_root_certificates_pem.clone(),
        };
        match execute_websocket(&websocket_plan, &step_options, evidence) {
            Ok(WebSocketConnectResult::Observation(observation)) => {
                attempts.push(serde_json::to_value(&observation)?);
                if observation.exit != 0
                    && let Some(action) = unconditional_retry(&step.on_failure)
                    && retries < retry_limit(action)
                {
                    retries += 1;
                    let delay = retry_delay(action);
                    if !delay.is_zero() {
                        sleep_retry_delay(workflow_started, options.timeout, delay)?;
                    }
                    continue;
                }
                break WebSocketConnectResult::Observation(observation);
            }
            Ok(WebSocketConnectResult::Denied(denial)) => {
                attempts.push(serde_json::to_value(&denial)?);
                break WebSocketConnectResult::Denied(denial);
            }
            Ok(WebSocketConnectResult::Connected(_)) => {
                return Err(WorkflowError::StepPlan {
                    step: step.step_id.clone(),
                    reason: "WebSocket executor returned a non-terminal connection".into(),
                });
            }
            Err(error) => {
                attempts.push(serde_json::json!({
                    "protocol": PROTOCOL,
                    "kind": "workflow-attempt-error",
                    "message": error.to_string(),
                    "exit": 3
                }));
                if let Some(action) = unconditional_retry(&step.on_failure)
                    && retries < retry_limit(action)
                {
                    retries += 1;
                    let delay = retry_delay(action);
                    if !delay.is_zero() {
                        sleep_retry_delay(workflow_started, options.timeout, delay)?;
                    }
                    continue;
                }
                return Err(WorkflowError::StepPlan {
                    step: step.step_id.clone(),
                    reason: error.to_string(),
                });
            }
        }
    };
    let (result, outputs, exit) = match result {
        WebSocketConnectResult::Observation(observation) => {
            let outputs = if observation.exit == 0 {
                step.outputs
                    .iter()
                    .map(|(name, expression)| {
                        Ok((
                            name.clone(),
                            evaluate_websocket_output(expression, &observation, evidence)?,
                        ))
                    })
                    .collect::<Result<_, WorkflowError>>()?
            } else {
                BTreeMap::new()
            };
            let exit = observation.exit;
            (serde_json::to_value(observation)?, outputs, exit)
        }
        WebSocketConnectResult::Denied(denial) => {
            let exit = denial.exit;
            (serde_json::to_value(denial)?, BTreeMap::new(), exit)
        }
        WebSocketConnectResult::Connected(_) => unreachable!("handled above"),
    };
    Ok(WebSocketStepRun {
        plan: websocket_plan.id,
        attempts,
        result,
        outputs,
        exit,
    })
}

fn validate_rebuilt_websocket_plan(
    step_id: &str,
    operation: &str,
    source: &Value,
    sealed: &kahea_core::WebSocketPlan,
    rebuilt: &kahea_core::WebSocketPlan,
) -> Result<(), WorkflowError> {
    if rebuilt.operation != operation
        && source.get("operationId").and_then(Value::as_str) != Some(operation)
    {
        return Err(WorkflowError::StepPlan {
            step: step_id.into(),
            reason: "runtime binding changed the WebSocket operation identity".into(),
        });
    }
    if rebuilt.risk != sealed.risk {
        return Err(WorkflowError::StepPlan {
            step: step_id.into(),
            reason: "runtime binding changed the sealed WebSocket risk".into(),
        });
    }
    if rebuilt.required_grants != sealed.required_grants {
        return Err(WorkflowError::StepPlan {
            step: step_id.into(),
            reason: "runtime binding changed the sealed WebSocket required capabilities".into(),
        });
    }
    Ok(())
}

fn remaining_step_timeout(
    workflow_started: Instant,
    workflow_timeout: std::time::Duration,
    step_timeout_ms: Option<u64>,
) -> Result<std::time::Duration, WorkflowError> {
    let remaining = workflow_timeout
        .checked_sub(workflow_started.elapsed())
        .ok_or_else(|| WorkflowError::Invalid("workflow timeout budget exhausted".into()))?;
    if remaining.is_zero() {
        return Err(WorkflowError::Invalid(
            "workflow timeout budget exhausted".into(),
        ));
    }
    Ok(step_timeout_ms
        .map(std::time::Duration::from_millis)
        .map(|timeout| timeout.min(remaining))
        .unwrap_or(remaining))
}

fn sleep_retry_delay(
    workflow_started: Instant,
    workflow_timeout: std::time::Duration,
    delay: std::time::Duration,
) -> Result<(), WorkflowError> {
    let remaining = workflow_timeout
        .checked_sub(workflow_started.elapsed())
        .ok_or_else(|| WorkflowError::Invalid("workflow timeout budget exhausted".into()))?;
    if delay >= remaining {
        return Err(WorkflowError::Invalid(
            "workflow retry delay exceeds the remaining timeout budget".into(),
        ));
    }
    std::thread::sleep(delay);
    Ok(())
}

fn failed_workflow_observation(
    plan: &WorkflowPlan,
    steps: Vec<WorkflowStepObservation>,
    exit: u8,
) -> WorkflowObservation {
    WorkflowObservation {
        protocol: PROTOCOL.into(),
        kind: "workflow-observation".into(),
        version: VERSION.into(),
        config_fingerprint: plan.config_fingerprint.clone(),
        policy_fingerprint: plan.policy_fingerprint.clone(),
        source_fingerprints: plan.source_fingerprints.clone(),
        workflow_plan: plan.id.clone(),
        outcome: if exit == 4 {
            Outcome::Denied
        } else {
            Outcome::Failed
        },
        steps,
        outputs: BTreeMap::new(),
        exit,
    }
}

fn evaluate_websocket_output(
    expression: &Value,
    observation: &WebSocketObservation,
    evidence: &EvidenceStore,
) -> Result<Value, WorkflowError> {
    let Some(expression) = expression.as_str() else {
        return Ok(expression.clone());
    };
    match expression {
        "$websocket.handshake.status" => {
            return Ok(observation
                .handshake_status
                .map_or(Value::Null, Value::from));
        }
        "$websocket.handshake.subprotocol" => {
            return Ok(observation
                .negotiated_subprotocol
                .clone()
                .map_or(Value::Null, Value::String));
        }
        "$websocket.close.code" => {
            return Ok(observation
                .close
                .as_ref()
                .map_or(Value::Null, |close| Value::from(close.code)));
        }
        "$websocket.close.reason" => {
            return Ok(observation
                .close
                .as_ref()
                .map_or(Value::Null, |close| Value::String(close.reason.clone())));
        }
        "$websocket.close.initiator" => {
            return Ok(observation
                .close
                .as_ref()
                .map(serde_json::to_value)
                .transpose()?
                .map_or(Value::Null, |close| close["initiator"].clone()));
        }
        "$websocket.evidence.transcript" => {
            return Ok(observation
                .transcript
                .clone()
                .map_or(Value::Null, Value::String));
        }
        "$websocket.evidence.handshake" => {
            return Ok(observation
                .handshake
                .clone()
                .map_or(Value::Null, Value::String));
        }
        "$websocket.evidence.trace" => {
            return Ok(observation.trace.clone().map_or(Value::Null, Value::String));
        }
        _ => {}
    }
    let rest = expression
        .strip_prefix("$websocket.message.")
        .ok_or_else(|| {
            WorkflowError::Invalid(format!(
                "unsupported WebSocket workflow output expression {expression:?}"
            ))
        })?;
    let (index, selector) = rest.split_once('.').ok_or_else(|| {
        WorkflowError::Invalid(format!("invalid WebSocket message selector {expression:?}"))
    })?;
    let index = index.parse::<u64>().map_err(|_| {
        WorkflowError::Invalid(format!("invalid WebSocket action index in {expression:?}"))
    })?;
    let transcript_handle = observation
        .transcript
        .as_deref()
        .ok_or_else(|| WorkflowError::Invalid("WebSocket transcript evidence is absent".into()))?;
    let transcript: Value = serde_json::from_slice(&evidence.get(transcript_handle)?.data)?;
    let payload_handle = transcript["entries"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|entry| {
            entry.get("direction").and_then(Value::as_str) == Some("inbound")
                && entry.get("action_index").and_then(Value::as_u64) == Some(index)
        })
        .and_then(|entry| entry.get("payload"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            WorkflowError::Invalid(format!(
                "WebSocket action {index} has no bounded inbound payload evidence"
            ))
        })?;
    if selector == "evidence" {
        return Ok(Value::String(payload_handle.into()));
    }
    let payload = evidence.get(payload_handle)?.data;
    if selector == "base64" {
        return Ok(Value::String(
            base64::engine::general_purpose::STANDARD.encode(payload),
        ));
    }
    let text = std::str::from_utf8(&payload).map_err(|_| {
        WorkflowError::Invalid(format!(
            "WebSocket action {index} payload is not UTF-8; select evidence or base64"
        ))
    })?;
    if selector == "text" {
        return Ok(Value::String(text.into()));
    }
    let json: Value = serde_json::from_str(text).map_err(|_| {
        WorkflowError::Invalid(format!("WebSocket action {index} payload is not JSON"))
    })?;
    if selector == "json" {
        return Ok(json);
    }
    let pointer = selector.strip_prefix("json#").ok_or_else(|| {
        WorkflowError::Invalid(format!("unsupported WebSocket selector {selector:?}"))
    })?;
    json.pointer(pointer).cloned().ok_or_else(|| {
        WorkflowError::Invalid(format!(
            "WebSocket message selector {expression:?} did not match"
        ))
    })
}

fn load_sources(
    arazzo_path: &Path,
    document: &Value,
) -> Result<BTreeMap<String, WorkflowSource>, WorkflowError> {
    let descriptions = document
        .get("sourceDescriptions")
        .and_then(Value::as_array)
        .ok_or_else(|| WorkflowError::Invalid("sourceDescriptions must be an array".into()))?;
    let mut sources = BTreeMap::new();
    for description in descriptions {
        let name = description
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| WorkflowError::Invalid("source description requires name".into()))?;
        let source_type = description.get("type").and_then(Value::as_str);
        let extension_kind = description
            .get(WEBSOCKET_SOURCE_EXTENSION)
            .and_then(Value::as_str);
        if extension_kind.is_some_and(|kind| kind != WEBSOCKET_SOURCE_KIND) {
            return Err(WorkflowError::Invalid(format!(
                "source {name:?} has unsupported {WEBSOCKET_SOURCE_EXTENSION} value {extension_kind:?}"
            )));
        }
        let websocket_source = extension_kind == Some(WEBSOCKET_SOURCE_KIND);
        if websocket_source && source_type.is_some() {
            return Err(WorkflowError::Invalid(format!(
                "WebSocket source {name:?} uses {WEBSOCKET_SOURCE_EXTENSION} and must not mislabel the direct session as an Arazzo source type"
            )));
        }
        if !websocket_source && source_type.is_some_and(|kind| kind != "openapi") {
            return Err(WorkflowError::Invalid(format!(
                "source {name:?} has unsupported type {source_type:?}"
            )));
        }
        let url = description
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| WorkflowError::Invalid(format!("source {name:?} requires url")))?;
        if Url::parse(url).is_ok() {
            return Err(WorkflowError::Invalid(format!(
                "remote workflow source {url:?} is denied during no-network planning; use a local relative path"
            )));
        }
        let path = arazzo_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(url);
        let bytes = fs::read(&path).map_err(|error| {
            WorkflowError::Source(format!("could not read {}: {error}", path.display()))
        })?;
        let source = if websocket_source {
            let document = parse_data_document(&path, &bytes)
                .map_err(|error| WorkflowError::Source(error.to_string()))?;
            if !is_websocket_session(&document) {
                return Err(WorkflowError::Invalid(format!(
                    "source {name:?} must be a websocket-session document"
                )));
            }
            WorkflowSource::WebSocket {
                path,
                source_fingerprint: digest(&bytes),
                bytes,
                document,
            }
        } else {
            WorkflowSource::Http(
                load_source(&path, &bytes)
                    .map_err(|error| WorkflowError::Source(error.to_string()))?,
            )
        };
        sources.insert(name.into(), source);
    }
    Ok(sources)
}

fn parse_websocket_bindings(
    step: &Value,
    source: &Value,
) -> Result<Vec<WorkflowWebSocketBinding>, WorkflowError> {
    let Some(bindings) = step.get("x-kahea-websocket-bindings") else {
        return Ok(Vec::new());
    };
    let bindings = bindings.as_array().ok_or_else(|| {
        WorkflowError::Invalid("x-kahea-websocket-bindings must be an array".into())
    })?;
    if bindings.len() > 64 {
        return Err(WorkflowError::Invalid(
            "a WebSocket workflow step supports at most 64 explicit bindings".into(),
        ));
    }
    let mut pointers = BTreeSet::new();
    bindings
        .iter()
        .map(|binding| {
            let pointer = binding
                .get("pointer")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    WorkflowError::Invalid("WebSocket binding requires pointer".into())
                })?;
            validate_websocket_binding_pointer(pointer)?;
            if source.pointer(pointer).is_none() {
                return Err(WorkflowError::Invalid(format!(
                    "WebSocket binding pointer {pointer:?} does not select an existing value"
                )));
            }
            if !pointers.insert(pointer.to_string()) {
                return Err(WorkflowError::Invalid(format!(
                    "duplicate WebSocket binding pointer {pointer:?}"
                )));
            }
            let value = binding.get("value").cloned().ok_or_else(|| {
                WorkflowError::Invalid(format!("WebSocket binding {pointer:?} requires a value"))
            })?;
            Ok(WorkflowWebSocketBinding {
                pointer: pointer.into(),
                value,
            })
        })
        .collect()
}

fn validate_websocket_binding_pointer(pointer: &str) -> Result<(), WorkflowError> {
    let segments: Vec<_> = pointer.split('/').collect();
    let valid_field = segments
        .get(3)
        .is_some_and(|field| matches!(*field, "text" | "payload_base64" | "equals" | "reason"));
    if segments.len() != 4
        || !segments[0].is_empty()
        || segments[1] != "actions"
        || segments[2].parse::<usize>().is_err()
        || !valid_field
    {
        return Err(WorkflowError::Invalid(format!(
            "WebSocket binding pointer {pointer:?} must select a bounded action payload or expectation field"
        )));
    }
    Ok(())
}

fn step_operation(
    step: &Value,
    sources: &BTreeMap<String, WorkflowSource>,
) -> Result<(String, String), WorkflowError> {
    if let Some(expression) = step.get("operationId").and_then(Value::as_str) {
        if let Some(rest) = expression.strip_prefix("$sourceDescriptions.") {
            let (source, operation) = rest.split_once('.').ok_or_else(|| {
                WorkflowError::Invalid(format!("invalid operationId expression {expression:?}"))
            })?;
            if !sources.contains_key(source) {
                return Err(WorkflowError::Invalid(format!("unknown source {source:?}")));
            }
            return Ok((source.into(), operation.into()));
        }
        if sources.len() == 1 {
            return Ok((
                sources.keys().next().expect("length checked").clone(),
                expression.into(),
            ));
        }
    }
    if let Some(expression) = step.get("operationPath").and_then(Value::as_str) {
        let normalized = expression
            .strip_prefix("{$sourceDescriptions.")
            .and_then(|value| value.split_once(".url}#"))
            .or_else(|| {
                expression
                    .strip_prefix("$sourceDescriptions.")
                    .and_then(|value| value.split_once(".url#"))
            });
        let (source_name, pointer) = normalized.ok_or_else(|| {
            WorkflowError::Invalid(format!("invalid operationPath expression {expression:?}"))
        })?;
        let source = sources
            .get(source_name)
            .ok_or_else(|| WorkflowError::Invalid(format!("unknown source {source_name:?}")))?;
        let WorkflowSource::Http(source) = source else {
            return Err(WorkflowError::Invalid(format!(
                "WebSocket step source {source_name:?} must use operationId"
            )));
        };
        let operation = source.document.pointer(pointer).ok_or_else(|| {
            WorkflowError::Invalid(format!("operationPath pointer {pointer:?} did not resolve"))
        })?;
        if !operation.is_object() {
            return Err(WorkflowError::Invalid(format!(
                "operationPath pointer {pointer:?} does not select an operation"
            )));
        }
        let mut segments = pointer.rsplitn(3, '/');
        let method = segments.next().unwrap_or_default();
        let encoded_path = segments.next().unwrap_or_default();
        if !matches!(
            method,
            "get" | "head" | "options" | "post" | "put" | "patch" | "delete" | "trace" | "query"
        ) {
            return Err(WorkflowError::Invalid(format!(
                "operationPath {expression:?} has unsupported method"
            )));
        }
        let path = encoded_path.replace("~1", "/").replace("~0", "~");
        return Ok((
            source_name.into(),
            format!("{} {path}", method.to_ascii_uppercase()),
        ));
    }
    Err(WorkflowError::Invalid(
        "each v1 step must identify an HTTP or WebSocket operationId, or an HTTP operationPath"
            .into(),
    ))
}

fn preview_grants(
    source: &OpenApiSource,
    operation: &kahea_ingest::OperationDefinition,
    requested_server: Option<&str>,
    auth: Option<&str>,
    configuration: &ProjectConfiguration,
    grants: &mut BTreeSet<String>,
) -> Result<(), WorkflowError> {
    let server = if let Some(requested) = requested_server {
        if let Some(configured) = configuration.servers.get(requested) {
            configured.url.clone()
        } else {
            requested.into()
        }
    } else {
        let servers = operation
            .operation
            .get("servers")
            .or_else(|| operation.path_item.get("servers"))
            .or_else(|| source.document.get("servers"))
            .and_then(Value::as_array)
            .ok_or_else(|| {
                WorkflowError::Invalid(format!(
                    "operation {:?} has no server",
                    operation.operation_id
                ))
            })?;
        if servers.len() != 1 {
            return Err(WorkflowError::Invalid(format!(
                "operation {:?} requires explicit server selection",
                operation.operation_id
            )));
        }
        servers[0]
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| WorkflowError::Invalid("server URL is missing".into()))?
            .into()
    };
    let server = resolve_preview_server_variables(&server, source, operation)?;
    let url = Url::parse(&server).map_err(|error| WorkflowError::Invalid(error.to_string()))?;
    let host = url
        .host_str()
        .ok_or_else(|| WorkflowError::Invalid("server host is missing".into()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| WorkflowError::Invalid("server port is missing".into()))?;
    if configuration
        .policy
        .denied_hosts
        .iter()
        .any(|denied| denied.eq_ignore_ascii_case(host))
    {
        return Err(WorkflowError::Invalid(format!(
            "host {host:?} is denied by project policy"
        )));
    }
    if !configuration.policy.allowed_hosts.is_empty()
        && !configuration
            .policy
            .allowed_hosts
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(host))
    {
        return Err(WorkflowError::Invalid(format!(
            "host {host:?} is outside the configured allowlist"
        )));
    }
    grants.insert(format!("net:{host}:{port}"));
    grants.insert(format!("http:{}", operation.method));
    if url.scheme() == "http" {
        grants.insert("net-insecure-http".into());
    }
    if let Ok(address) = host.parse::<IpAddr>() {
        let unsafe_address = address.is_loopback()
            || match address {
                IpAddr::V4(address) => address.is_private() || address.is_link_local(),
                IpAddr::V6(address) => address.is_unique_local() || address.is_unicast_link_local(),
            };
        if unsafe_address {
            grants.insert(match address {
                IpAddr::V4(address) => format!("net-cidr:{address}/32"),
                IpAddr::V6(address) => format!("net-cidr:{address}/128"),
            });
        }
    }
    let risk = configuration
        .risk
        .get(&format!("{} {}", operation.method, operation.path))
        .copied()
        .unwrap_or(operation.risk);
    if risk == RiskClass::Destructive {
        grants.insert("approve:destructive".into());
    }
    let origin = format!(
        "{}://{}{}",
        url.scheme(),
        host,
        url.port()
            .map(|port| format!(":{port}"))
            .unwrap_or_default()
    );
    let production = configuration.servers.values().any(|server| {
        server.url.trim_end_matches('/') == origin
            && server.classification.as_deref() == Some("production")
    });
    if production
        && configuration.policy.require_production_write_approval
        && matches!(risk, RiskClass::Write | RiskClass::Destructive)
    {
        grants.insert("approve:production-write".into());
    }
    if let Some(auth) = auth {
        let (scheme_name, profile) = auth.split_once('=').unwrap_or((auth, auth));
        grants.insert(format!("secret:{profile}"));
        if let Some(scheme) = resolve_security_scheme(&source.document, scheme_name) {
            if scheme.get("type").and_then(Value::as_str) == Some("mutualTLS") {
                grants.insert(format!("tls-client-cert:{profile}"));
            }
            let token_url = scheme
                .pointer("/flows/clientCredentials/tokenUrl")
                .or_else(|| scheme.pointer("/flows/authorizationCode/tokenUrl"))
                .and_then(Value::as_str);
            if let Some(token_url) = token_url {
                preview_url_grants(token_url, grants)?;
                grants.insert("http:POST".into());
            }
        }
    }
    Ok(())
}

fn resolve_preview_server_variables(
    server: &str,
    source: &OpenApiSource,
    operation: &kahea_ingest::OperationDefinition,
) -> Result<String, WorkflowError> {
    if !server.contains('{') {
        return Ok(server.into());
    }
    let server_object = operation
        .operation
        .get("servers")
        .or_else(|| operation.path_item.get("servers"))
        .or_else(|| source.document.get("servers"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|candidate| candidate.get("url").and_then(Value::as_str) == Some(server))
        .ok_or_else(|| WorkflowError::Invalid("server variables cannot be resolved".into()))?;
    let mut resolved = server.to_string();
    for (name, variable) in server_object
        .get("variables")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        let default = variable
            .get("default")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                WorkflowError::Invalid(format!("server variable {name:?} has no default"))
            })?;
        resolved = resolved.replace(&format!("{{{name}}}"), default);
    }
    if resolved.contains('{') {
        return Err(WorkflowError::Invalid(
            "not all workflow server variables have defaults".into(),
        ));
    }
    Ok(resolved)
}

fn resolve_security_scheme<'a>(document: &'a Value, name: &str) -> Option<&'a Value> {
    let scheme = document.pointer(&format!(
        "/components/securitySchemes/{}",
        name.replace('~', "~0").replace('/', "~1")
    ))?;
    if let Some(reference) = scheme.get("$ref").and_then(Value::as_str) {
        return reference
            .strip_prefix('#')
            .and_then(|pointer| document.pointer(pointer));
    }
    Some(scheme)
}

fn preview_url_grants(url: &str, grants: &mut BTreeSet<String>) -> Result<(), WorkflowError> {
    let url = Url::parse(url).map_err(|error| WorkflowError::Invalid(error.to_string()))?;
    let host = url
        .host_str()
        .ok_or_else(|| WorkflowError::Invalid("OAuth token URL has no host".into()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| WorkflowError::Invalid("OAuth token URL has no port".into()))?;
    grants.insert(format!("net:{host}:{port}"));
    if url.scheme() == "http" {
        grants.insert("net-insecure-http".into());
    }
    if let Ok(address) = host.parse::<IpAddr>() {
        let unsafe_address = address.is_loopback()
            || match address {
                IpAddr::V4(address) => address.is_private() || address.is_link_local(),
                IpAddr::V6(address) => address.is_unique_local() || address.is_unicast_link_local(),
            };
        if unsafe_address {
            grants.insert(match address {
                IpAddr::V4(address) => format!("net-cidr:{address}/32"),
                IpAddr::V6(address) => format!("net-cidr:{address}/128"),
            });
        }
    }
    Ok(())
}

fn validate_workflow_inputs(schema: Option<&Value>, input: &Value) -> Result<(), WorkflowError> {
    let Some(schema) = schema else { return Ok(()) };
    let object = input
        .as_object()
        .ok_or_else(|| WorkflowError::Invalid("workflow input must be an object".into()))?;
    for name in schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if !object.contains_key(name) {
            return Err(WorkflowError::Invalid(format!(
                "workflow input {name:?} is required"
            )));
        }
    }
    Ok(())
}

fn materialize(
    value: &Value,
    inputs: &Value,
    steps: &BTreeMap<String, BTreeMap<String, Value>>,
) -> Result<Value, WorkflowError> {
    match value {
        Value::String(expression) if expression.starts_with("$inputs.") => {
            let pointer = format!(
                "/{}",
                expression.trim_start_matches("$inputs.").replace('.', "/")
            );
            inputs.pointer(&pointer).cloned().ok_or_else(|| {
                WorkflowError::Invalid(format!("runtime expression {expression:?} did not resolve"))
            })
        }
        Value::String(expression) if expression.starts_with("$steps.") => {
            resolve_step_expression(expression, steps)
        }
        Value::Array(values) => values
            .iter()
            .map(|value| materialize(value, inputs, steps))
            .collect(),
        Value::Object(values) => values
            .iter()
            .map(|(key, value)| Ok((key.clone(), materialize(value, inputs, steps)?)))
            .collect::<Result<Map<_, _>, WorkflowError>>()
            .map(Value::Object),
        value => Ok(value.clone()),
    }
}

fn resolve_step_expression(
    expression: &str,
    steps: &BTreeMap<String, BTreeMap<String, Value>>,
) -> Result<Value, WorkflowError> {
    let rest = expression.trim_start_matches("$steps.");
    let (step, rest) = rest.split_once(".outputs.").ok_or_else(|| {
        WorkflowError::Invalid(format!("unsupported runtime expression {expression:?}"))
    })?;
    let (output, pointer) = rest.split_once('#').unwrap_or((rest, ""));
    let value = steps
        .get(step)
        .and_then(|outputs| outputs.get(output))
        .ok_or_else(|| {
            WorkflowError::Invalid(format!(
                "runtime expression {expression:?} references unavailable output"
            ))
        })?;
    if pointer.is_empty() {
        Ok(value.clone())
    } else {
        value.pointer(pointer).cloned().ok_or_else(|| {
            WorkflowError::Invalid(format!(
                "runtime expression {expression:?} pointer did not match"
            ))
        })
    }
}

fn evaluate_output(
    expression: &Value,
    observation: &kahea_core::Observation,
    body: Option<&Value>,
) -> Result<Value, WorkflowError> {
    let Some(expression) = expression.as_str() else {
        return Ok(expression.clone());
    };
    if expression == "$statusCode" {
        return Ok(Value::from(observation.status.unwrap_or_default()));
    }
    if let Some(pointer) = expression.strip_prefix("$response.body#") {
        let body = body.ok_or_else(|| {
            WorkflowError::Invalid("workflow output requires a JSON response body".into())
        })?;
        return body.pointer(pointer).cloned().ok_or_else(|| {
            WorkflowError::Invalid(format!("workflow output pointer {pointer:?} did not match"))
        });
    }
    if expression == "$response.body" {
        return Ok(body.cloned().unwrap_or(Value::Null));
    }
    Err(WorkflowError::Invalid(format!(
        "unsupported workflow output expression {expression:?}"
    )))
}

fn validate_websocket_output_expression(expression: &Value) -> Result<(), WorkflowError> {
    let Some(expression) = expression.as_str() else {
        return Ok(());
    };
    if matches!(
        expression,
        "$websocket.handshake.status"
            | "$websocket.handshake.subprotocol"
            | "$websocket.close.code"
            | "$websocket.close.reason"
            | "$websocket.close.initiator"
            | "$websocket.evidence.transcript"
            | "$websocket.evidence.handshake"
            | "$websocket.evidence.trace"
    ) {
        return Ok(());
    }
    let Some(rest) = expression.strip_prefix("$websocket.message.") else {
        return Err(WorkflowError::Invalid(format!(
            "unsupported WebSocket workflow output expression {expression:?}"
        )));
    };
    let (index, selector) = rest.split_once('.').ok_or_else(|| {
        WorkflowError::Invalid(format!(
            "WebSocket message output {expression:?} requires an action index and selector"
        ))
    })?;
    index.parse::<usize>().map_err(|_| {
        WorkflowError::Invalid(format!(
            "WebSocket message output {expression:?} has an invalid action index"
        ))
    })?;
    if matches!(selector, "text" | "json" | "evidence" | "base64") || selector.starts_with("json#/")
    {
        Ok(())
    } else {
        Err(WorkflowError::Invalid(format!(
            "WebSocket message output {expression:?} has an unsupported selector"
        )))
    }
}

fn parameter_location(
    operation: &kahea_ingest::OperationDefinition,
    source: &OpenApiSource,
    name: &str,
) -> Option<String> {
    [
        operation.path_item.get("parameters"),
        operation.operation.get("parameters"),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_array)
    .flatten()
    .filter_map(|parameter| {
        if let Some(reference) = parameter.get("$ref").and_then(Value::as_str) {
            reference
                .strip_prefix('#')
                .and_then(|pointer| source.document.pointer(pointer))
        } else {
            Some(parameter)
        }
    })
    .find(|parameter| parameter.get("name").and_then(Value::as_str) == Some(name))
    .and_then(|parameter| parameter.get("in").and_then(Value::as_str))
    .map(str::to_string)
}

fn collect_runtime_expressions(value: &Value, found: &mut Vec<String>) {
    match value {
        Value::String(value) if value.starts_with('$') => found.push(value.clone()),
        Value::Array(values) => values
            .iter()
            .for_each(|value| collect_runtime_expressions(value, found)),
        Value::Object(values) => values
            .values()
            .for_each(|value| collect_runtime_expressions(value, found)),
        _ => {}
    }
}

fn maximum_risk(left: RiskClass, right: RiskClass) -> RiskClass {
    fn rank(risk: RiskClass) -> u8 {
        match risk {
            RiskClass::Read => 0,
            RiskClass::Write => 1,
            RiskClass::Destructive => 2,
            RiskClass::Unknown => 3,
        }
    }
    if rank(left) >= rank(right) {
        left
    } else {
        right
    }
}

fn validate_actions(step_id: &str, actions: &[Value], success: bool) -> Result<(), WorkflowError> {
    for action in actions {
        if action.get("reference").is_some() {
            return Err(WorkflowError::Invalid(format!(
                "step {step_id:?} uses a reusable action; inline retry/end actions are required"
            )));
        }
        let kind = action.get("type").and_then(Value::as_str).ok_or_else(|| {
            WorkflowError::Invalid(format!("step {step_id:?} action requires type"))
        })?;
        let supported = if success {
            kind == "end"
        } else {
            matches!(kind, "retry" | "end")
        };
        if !supported {
            return Err(WorkflowError::Invalid(format!(
                "step {step_id:?} action type {kind:?} is not supported in v1"
            )));
        }
        if kind == "retry" {
            let limit = retry_limit(action);
            if limit > 10 {
                return Err(WorkflowError::Invalid(format!(
                    "step {step_id:?} retryLimit exceeds the v1 maximum of 10"
                )));
            }
            let after = action
                .get("retryAfter")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            if !after.is_finite() || !(0.0..=60.0).contains(&after) {
                return Err(WorkflowError::Invalid(format!(
                    "step {step_id:?} retryAfter must be between 0 and 60 seconds"
                )));
            }
        }
        for criterion in value_array(action, "criteria") {
            if criterion
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind != "simple")
            {
                return Err(WorkflowError::Invalid(
                    "v1 action criteria support only simple conditions".into(),
                ));
            }
            parse_simple_condition(
                criterion
                    .get("condition")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        WorkflowError::Invalid("action criterion requires condition".into())
                    })?,
            )?;
        }
    }
    Ok(())
}

fn criterion_to_check(criterion: &Value) -> Result<String, WorkflowError> {
    let condition = criterion
        .get("condition")
        .and_then(Value::as_str)
        .ok_or_else(|| WorkflowError::Invalid("success criterion requires condition".into()))?;
    match criterion
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("simple")
    {
        "simple" => {
            let (left, operator, right) = parse_simple_condition(condition)?;
            if operator != "==" {
                return Err(WorkflowError::Invalid(format!(
                    "success criterion {condition:?} cannot be represented by a v1 declarative check"
                )));
            }
            let expected = parse_literal(right)?;
            if left == "$statusCode" {
                let status = expected
                    .as_u64()
                    .filter(|status| *status <= u16::MAX as u64)
                    .ok_or_else(|| {
                        WorkflowError::Invalid("status criterion requires an integer status".into())
                    })?;
                return Ok(format!("status:{status}"));
            }
            if let Some(pointer) = response_body_pointer(left) {
                return Ok(format!(
                    "json-pointer:{pointer}={}",
                    serde_json::to_string(&expected)?
                ));
            }
            Err(WorkflowError::Invalid(format!(
                "unsupported success criterion operand {left:?}"
            )))
        }
        "jsonpath"
            if criterion.get("context").and_then(Value::as_str) == Some("$response.body") =>
        {
            Ok(format!("jsonpath:{condition}:exists"))
        }
        "xpath" if criterion.get("context").and_then(Value::as_str) == Some("$response.body") => {
            Ok(format!("xpath:{condition}:exists"))
        }
        kind => Err(WorkflowError::Invalid(format!(
            "unsupported success criterion type/context {kind:?}"
        ))),
    }
}

fn parse_simple_condition(condition: &str) -> Result<(&str, &str, &str), WorkflowError> {
    for operator in ["<=", ">=", "==", "!=", "<", ">"] {
        if let Some((left, right)) = condition.split_once(operator) {
            let left = left.trim();
            let right = right.trim();
            if left.is_empty() || right.is_empty() {
                break;
            }
            return Ok((left, operator, right));
        }
    }
    Err(WorkflowError::Invalid(format!(
        "unsupported simple condition {condition:?}"
    )))
}

fn parse_literal(literal: &str) -> Result<Value, WorkflowError> {
    if literal.starts_with('\'') && literal.ends_with('\'') && literal.len() >= 2 {
        return Ok(Value::String(
            literal[1..literal.len() - 1].replace("''", "'"),
        ));
    }
    serde_json::from_str(literal)
        .map_err(|_| WorkflowError::Invalid(format!("condition literal {literal:?} is invalid")))
}

fn response_body_pointer(expression: &str) -> Option<String> {
    if let Some(pointer) = expression.strip_prefix("$response.body#") {
        return Some(pointer.to_string());
    }
    expression.strip_prefix("$response.body.").map(|path| {
        format!(
            "/{}",
            path.split('.')
                .map(|segment| segment.replace('~', "~0").replace('/', "~1"))
                .collect::<Vec<_>>()
                .join("/")
        )
    })
}

fn select_action<'a>(
    actions: &'a [Value],
    result: &InvocationResult,
    evidence: &EvidenceStore,
) -> Result<Option<&'a Value>, WorkflowError> {
    for action in actions {
        let criteria = value_array(action, "criteria");
        if criteria.is_empty() || criteria_match(&criteria, result, evidence)? {
            return Ok(Some(action));
        }
    }
    Ok(None)
}

fn criteria_match(
    criteria: &[Value],
    result: &InvocationResult,
    evidence: &EvidenceStore,
) -> Result<bool, WorkflowError> {
    let InvocationResult::Observation(observation) = result else {
        return Ok(false);
    };
    let body = observation
        .body
        .as_deref()
        .map(|handle| evidence.get(handle))
        .transpose()?
        .and_then(|record| serde_json::from_slice::<Value>(&record.data).ok());
    for criterion in criteria {
        let condition = criterion
            .get("condition")
            .and_then(Value::as_str)
            .ok_or_else(|| WorkflowError::Invalid("action criterion requires condition".into()))?;
        let (left, operator, right) = parse_simple_condition(condition)?;
        let expected = parse_literal(right)?;
        let actual = if left == "$statusCode" {
            Value::from(observation.status.unwrap_or_default())
        } else if let Some(pointer) = response_body_pointer(left) {
            body.as_ref()
                .and_then(|body| body.pointer(&pointer))
                .cloned()
                .unwrap_or(Value::Null)
        } else {
            return Err(WorkflowError::Invalid(format!(
                "unsupported action criterion operand {left:?}"
            )));
        };
        if !compare_values(&actual, operator, &expected) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn compare_values(actual: &Value, operator: &str, expected: &Value) -> bool {
    match operator {
        "==" => match (actual.as_str(), expected.as_str()) {
            (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
            _ => actual == expected,
        },
        "!=" => !compare_values(actual, "==", expected),
        "<" | "<=" | ">" | ">=" => {
            let (Some(left), Some(right)) = (actual.as_f64(), expected.as_f64()) else {
                return false;
            };
            match operator {
                "<" => left < right,
                "<=" => left <= right,
                ">" => left > right,
                ">=" => left >= right,
                _ => unreachable!(),
            }
        }
        _ => false,
    }
}

fn unconditional_retry(actions: &[Value]) -> Option<&Value> {
    actions.iter().find(|action| {
        action.get("type").and_then(Value::as_str) == Some("retry")
            && value_array(action, "criteria").is_empty()
    })
}

fn retry_limit(action: &Value) -> u64 {
    action
        .get("retryLimit")
        .and_then(Value::as_u64)
        .unwrap_or(1)
}

fn retry_delay(action: &Value) -> std::time::Duration {
    std::time::Duration::from_secs_f64(
        action
            .get("retryAfter")
            .and_then(Value::as_f64)
            .unwrap_or(0.0),
    )
}

fn workflow_denial(plan: &WorkflowPlan, missing: &str) -> WorkflowObservation {
    WorkflowObservation {
        protocol: PROTOCOL.into(),
        kind: "workflow-observation".into(),
        version: VERSION.into(),
        config_fingerprint: plan.config_fingerprint.clone(),
        policy_fingerprint: plan.policy_fingerprint.clone(),
        source_fingerprints: plan.source_fingerprints.clone(),
        workflow_plan: plan.id.clone(),
        outcome: Outcome::Denied,
        steps: vec![WorkflowStepObservation {
            step_id: "policy".into(),
            plan: None,
            attempts: Vec::new(),
            result: serde_json::json!({"reason":"workflow invocation is missing a required capability","required":missing,"exit":4}),
        }],
        outputs: BTreeMap::new(),
        exit: 4,
    }
}

fn value_array(value: &Value, key: &str) -> Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kahea_test_server::{remove_temporary_store, temporary_store_path};
    use std::io::{self, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;
    use tungstenite::Message;

    fn temporary_root(label: &str) -> PathBuf {
        let root = temporary_store_path(&format!("workflow-{label}"));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn websocket_limits() -> Value {
        serde_json::json!({
            "connect_timeout_ms": 2_000,
            "action_timeout_ms": 2_000,
            "idle_timeout_ms": 2_000,
            "close_timeout_ms": 2_000,
            "total_timeout_ms": 5_000,
            "max_frame_bytes": 65_536,
            "max_message_bytes": 65_536,
            "max_inbound_frames": 16,
            "max_outbound_frames": 16,
            "max_inbound_messages": 8,
            "max_outbound_messages": 8,
            "max_inbound_bytes": 262_144,
            "max_outbound_bytes": 262_144
        })
    }

    fn spawn_websocket_peer(expected: String, response: Message) -> (u16, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let worker = thread::spawn(move || {
            let stream = accept_test_connection(&listener);
            let mut socket = tungstenite::accept(stream).unwrap();
            let message = socket.read().unwrap();
            assert_eq!(message.to_text().unwrap(), expected);
            socket.send(response).unwrap();
            let close = socket.read().unwrap();
            assert!(close.is_close());
            let _ = socket.flush();
        });
        (port, worker)
    }

    fn accept_test_connection(listener: &TcpListener) -> TcpStream {
        const TEST_IO_TIMEOUT: Duration = Duration::from_secs(5);
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + TEST_IO_TIMEOUT;
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    stream.set_read_timeout(Some(TEST_IO_TIMEOUT)).unwrap();
                    stream.set_write_timeout(Some(TEST_IO_TIMEOUT)).unwrap();
                    return stream;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "test WebSocket peer did not connect within five seconds"
                    );
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("test WebSocket accept failed: {error}"),
            }
        }
    }

    #[test]
    fn two_step_workflow_resolves_output_into_a_sealed_subplan() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let root = temporary_store_path("workflow");
        fs::create_dir_all(&root).unwrap();
        let openapi_path = root.join("api.yaml");
        fs::write(
            &openapi_path,
            format!(
                r#"
openapi: 3.1.0
info: {{ title: Workflow API, version: 1 }}
servers: [{{ url: "http://127.0.0.1:{port}" }}]
paths:
  /items:
    post:
      operationId: createItem
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [name]
              properties: {{ name: {{ type: string }} }}
      responses:
        "200":
          description: created
          content:
            application/json:
              schema:
                type: object
                required: [id]
                properties: {{ id: {{ type: string }} }}
  /items/{{id}}:
    get:
      operationId: getItem
      parameters:
        - {{ name: id, in: path, required: true, schema: {{ type: string }} }}
      responses:
        "200":
          description: found
          content:
            application/json:
              schema:
                type: object
                required: [id, name]
                properties:
                  id: {{ type: string }}
                  name: {{ type: string }}
"#
            ),
        )
        .unwrap();
        let arazzo = serde_json::json!({
            "arazzo": "1.1.0",
            "info": {"title":"workflow","version":"1"},
            "sourceDescriptions": [{"name":"api","url":"api.yaml","type":"openapi"}],
            "workflows": [{
                "workflowId": "createAndGet",
                "inputs": {"type":"object","required":["name"],"properties":{"name":{"type":"string"}}},
                "steps": [
                    {
                        "stepId":"create",
                        "operationId":"$sourceDescriptions.api.createItem",
                        "requestBody":{"payload":{"name":"$inputs.name"}},
                        "successCriteria":[{"condition":"$statusCode == 200"}],
                        "onFailure":[{
                            "name":"retryBusy",
                            "type":"retry",
                            "retryLimit":1,
                            "criteria":[{"condition":"$statusCode == 503"}]
                        }],
                        "outputs":{"itemId":"$response.body#/id"}
                    },
                    {
                        "stepId":"get",
                        "operationPath":"{$sourceDescriptions.api.url}#/paths/~1items~1{id}/get",
                        "dependsOn":["create"],
                        "parameters":[{"name":"id","in":"path","value":"$steps.create.outputs.itemId"}],
                        "timeout":5000,
                        "onSuccess":[{"name":"done","type":"end"}]
                    }
                ]
            }]
        });
        let plan = build_workflow_plan(
            &root.join("workflow.yaml"),
            &arazzo,
            "createAndGet",
            serde_json::json!({"name":"first"}),
            None,
            None,
            Vec::new(),
            &ProjectConfiguration::default(),
        )
        .unwrap();
        assert!(plan.verify_seal().unwrap());
        assert_eq!(plan.steps[1].operation, "GET /items/{id}");
        assert_eq!(plan.steps[1].depends_on, ["create"]);
        assert_eq!(plan.steps[1].timeout_ms, Some(5000));
        assert!(
            plan.steps[1]
                .deferred_bindings
                .contains(&"$steps.create.outputs.itemId".into())
        );
        let server = thread::spawn(move || {
            for (status, body) in [
                (503, r#"{}"#),
                (200, r#"{"id":"item-1"}"#),
                (200, r#"{"id":"item-1","name":"first"}"#),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0_u8; 4096];
                let bytes = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..bytes]);
                if body.contains("name") {
                    assert!(request.starts_with("GET /items/item-1 "));
                }
                write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        let evidence = EvidenceStore::open(root.join("store")).unwrap();
        let options = InvokeOptions {
            grants: plan.required_grants.iter().cloned().collect(),
            expected_config_fingerprint: Some(plan.config_fingerprint.clone()),
            expected_policy_fingerprint: Some(plan.policy_fingerprint.clone()),
            ..InvokeOptions::default()
        };
        let observation = invoke_workflow(
            &plan,
            &options,
            &ProjectConfiguration::default(),
            &root,
            &evidence,
        )
        .unwrap();
        assert_eq!(observation.exit, 0);
        assert_eq!(observation.steps.len(), 2);
        assert_eq!(observation.steps[0].attempts.len(), 2);
        server.join().unwrap();
        drop(evidence);
        remove_temporary_store(&root);
    }

    #[test]
    fn mixed_fixture_seals_exact_grants_risk_bindings_and_policy() {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let path = repository.join("fixtures/workflows/mixed.arazzo.yaml");
        let bytes = fs::read(&path).unwrap();
        let document = parse_data_document(&path, &bytes).unwrap();
        let configuration = ProjectConfiguration::default();
        let first = build_workflow_plan(
            &path,
            &document,
            "createAndPublishInvoice",
            serde_json::json!({"customer_id":"customer-1","amount":42}),
            None,
            None,
            Vec::new(),
            &configuration,
        )
        .unwrap();
        let second = build_workflow_plan(
            &path,
            &document,
            "createAndPublishInvoice",
            serde_json::json!({"customer_id":"customer-1","amount":42}),
            None,
            None,
            Vec::new(),
            &configuration,
        )
        .unwrap();
        assert_eq!(first.id, second.id);
        assert!(first.verify_seal().unwrap());
        assert_eq!(first.risk, RiskClass::Write);
        assert_eq!(first.steps[0].transport, WorkflowStepTransport::Http);
        assert_eq!(first.steps[1].transport, WorkflowStepTransport::WebSocket);
        assert!(first.steps[1].websocket_plan.is_some());
        assert_eq!(
            first.steps[1].websocket_bindings[0].pointer,
            "/actions/0/text"
        );
        assert!(
            first.steps[1]
                .deferred_bindings
                .contains(&"$steps.create.outputs.invoice_id".into())
        );
        for grant in [
            "http:POST",
            "net:sandbox.example.test:443",
            "net:socket.example.test:443",
            "websocket:connect",
        ] {
            assert!(first.required_grants.contains(&grant.into()), "{grant}");
        }
        assert_eq!(
            first.websocket_policy_fingerprint.as_deref(),
            Some(
                configuration
                    .websocket_policy_fingerprint()
                    .unwrap()
                    .as_str()
            )
        );

        let sealed_websocket_plan = first.steps[1].websocket_plan.as_ref().unwrap();
        let mut changed_risk = sealed_websocket_plan.clone();
        changed_risk.risk = RiskClass::Destructive;
        assert!(
            validate_rebuilt_websocket_plan(
                &first.steps[1].step_id,
                &first.steps[1].operation,
                &first.steps[1].source_document,
                sealed_websocket_plan,
                &changed_risk,
            )
            .unwrap_err()
            .to_string()
            .contains("sealed WebSocket risk")
        );
        let mut changed_grants = sealed_websocket_plan.clone();
        changed_grants
            .required_grants
            .push("unexpected:grant".into());
        assert!(
            validate_rebuilt_websocket_plan(
                &first.steps[1].step_id,
                &first.steps[1].operation,
                &first.steps[1].source_document,
                sealed_websocket_plan,
                &changed_grants,
            )
            .unwrap_err()
            .to_string()
            .contains("required capabilities")
        );

        let root = temporary_root("denial");
        let evidence = EvidenceStore::open(root.join("store")).unwrap();
        let denied_step_options = InvokeOptions {
            grants: first
                .required_grants
                .iter()
                .filter(|grant| grant.as_str() != "websocket:connect")
                .cloned()
                .collect(),
            timeout: Duration::from_millis(100),
            ..InvokeOptions::default()
        };
        let step_outputs = BTreeMap::from([(
            "create".into(),
            BTreeMap::from([("invoice_id".into(), Value::String("invoice-1".into()))]),
        )]);
        let denied_step = invoke_websocket_workflow_step(
            &first.steps[1],
            &first.input,
            &step_outputs,
            &denied_step_options,
            &configuration,
            &root,
            &evidence,
            Instant::now(),
        )
        .unwrap();
        assert_eq!(denied_step.exit, 4);
        assert_eq!(denied_step.attempts.len(), 1);

        let options = InvokeOptions {
            grants: first
                .required_grants
                .iter()
                .filter(|grant| grant.as_str() != "websocket:connect")
                .cloned()
                .collect(),
            expected_config_fingerprint: Some(first.config_fingerprint.clone()),
            expected_policy_fingerprint: Some(first.policy_fingerprint.clone()),
            ..InvokeOptions::default()
        };
        let denial = invoke_workflow(&first, &options, &configuration, &root, &evidence).unwrap();
        assert_eq!(denial.outcome, Outcome::Denied);
        assert_eq!(denial.exit, 4);
        assert_eq!(denial.steps[0].result["required"], "websocket:connect");

        let mut changed_configuration = configuration.clone();
        changed_configuration
            .policy
            .websocket
            .max_limits
            .total_timeout_ms -= 1;
        let exact_options = InvokeOptions {
            grants: first.required_grants.iter().cloned().collect(),
            expected_config_fingerprint: Some(first.config_fingerprint.clone()),
            expected_policy_fingerprint: Some(first.policy_fingerprint.clone()),
            ..InvokeOptions::default()
        };
        assert!(
            invoke_workflow(
                &first,
                &exact_options,
                &changed_configuration,
                &root,
                &evidence
            )
            .unwrap_err()
            .to_string()
            .contains("WebSocket policy fingerprint mismatch")
        );

        let mut unsafe_binding = document.clone();
        unsafe_binding["workflows"][0]["steps"][1]["x-kahea-websocket-bindings"] =
            serde_json::json!([{"pointer":"/url","value":"$steps.create.outputs.invoice_id"}]);
        assert!(
            build_workflow_plan(
                &path,
                &unsafe_binding,
                "createAndPublishInvoice",
                serde_json::json!({"customer_id":"customer-1","amount":42}),
                None,
                None,
                Vec::new(),
                &configuration,
            )
            .unwrap_err()
            .to_string()
            .contains("bounded action payload")
        );

        let mut unbounded_output = document.clone();
        unbounded_output["workflows"][0]["steps"][1]["outputs"]["unsafe"] =
            Value::String("$websocket.transcript".into());
        assert!(
            build_workflow_plan(
                &path,
                &unbounded_output,
                "createAndPublishInvoice",
                serde_json::json!({"customer_id":"customer-1","amount":42}),
                None,
                None,
                Vec::new(),
                &configuration,
            )
            .unwrap_err()
            .to_string()
            .contains("unsupported WebSocket workflow output")
        );
        drop(evidence);
        remove_temporary_store(&root);
    }

    #[test]
    fn absent_websocket_close_fields_are_null() {
        let root = temporary_root("absent-close");
        let evidence = EvidenceStore::open(root.join("store")).unwrap();
        let observation = WebSocketObservation {
            protocol: PROTOCOL.into(),
            kind: "websocket-observation".into(),
            version: VERSION.into(),
            config_fingerprint: String::new(),
            policy_fingerprint: String::new(),
            source_fingerprints: Vec::new(),
            tool_version: env!("CARGO_PKG_VERSION").into(),
            plan: String::new(),
            outcome: Outcome::Passed,
            handshake_status: Some(101),
            negotiated_subprotocol: None,
            handshake_latency_ms: None,
            session_duration_ms: None,
            transcript: None,
            handshake: None,
            trace: None,
            close: None,
            terminal_cause: kahea_core::WebSocketTerminalCause::Completed,
            counters: kahea_core::WebSocketCounters::default(),
            resolved_origin: None,
            http_version: None,
            secret_refs: Vec::new(),
            runtime: String::new(),
            exit: 0,
        };
        for expression in [
            "$websocket.close.code",
            "$websocket.close.reason",
            "$websocket.close.initiator",
        ] {
            assert_eq!(
                evaluate_websocket_output(
                    &Value::String(expression.into()),
                    &observation,
                    &evidence
                )
                .unwrap(),
                Value::Null
            );
        }
        drop(evidence);
        remove_temporary_store(&root);
    }

    #[test]
    fn http_output_binds_into_websocket_and_extracts_bounded_message_evidence() {
        let root = temporary_root("http-ws");
        let http_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let http_port = http_listener.local_addr().unwrap().port();
        let http_worker = thread::spawn(move || {
            let (mut stream, _) = http_listener.accept().unwrap();
            let mut request = [0_u8; 4096];
            let bytes = stream.read(&mut request).unwrap();
            assert!(String::from_utf8_lossy(&request[..bytes]).starts_with("POST /items "));
            let body = r#"{"id":"item-17"}"#;
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        });
        let (websocket_port, websocket_worker) = spawn_websocket_peer(
            "item-17".into(),
            Message::Text(r#"{"accepted":true,"id":"event-9"}"#.into()),
        );
        fs::write(
            root.join("api.json"),
            serde_json::to_vec(&serde_json::json!({
                "openapi":"3.1.0",
                "info":{"title":"workflow","version":"1"},
                "servers":[{"url":format!("http://127.0.0.1:{http_port}")}],
                "paths":{"/items":{"post":{"operationId":"createItem","responses":{"200":{"description":"ok"}}}}}
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            root.join("events.json"),
            serde_json::to_vec(&serde_json::json!({
                "kind":"websocket-session",
                "version":1,
                "operationId":"publishEvent",
                "url":format!("ws://127.0.0.1:{websocket_port}/events"),
                "risk":"write",
                "limits":websocket_limits(),
                "actions":[
                    {"type":"send-text","text":"pending"},
                    {"type":"expect-json","pointer":"/accepted","equals":true,"timeout_ms":2_000},
                    {"type":"close","code":1000,"reason":"done"}
                ]
            }))
            .unwrap(),
        )
        .unwrap();
        let workflow = serde_json::json!({
            "arazzo":"1.1.0",
            "info":{"title":"mixed","version":"1"},
            "sourceDescriptions":[
                {"name":"api","url":"api.json","type":"openapi"},
                {"name":"events","url":"events.json","x-kahea-source-kind":WEBSOCKET_SOURCE_KIND}
            ],
            "workflows":[{
                "workflowId":"httpToSocket",
                "steps":[
                    {"stepId":"create","operationId":"$sourceDescriptions.api.createItem","outputs":{"id":"$response.body#/id"}},
                    {
                        "stepId":"publish",
                        "operationId":"$sourceDescriptions.events.publishEvent",
                        "dependsOn":["create"],
                        "x-kahea-websocket-bindings":[{"pointer":"/actions/0/text","value":"$steps.create.outputs.id"}],
                        "outputs":{
                            "event_id":"$websocket.message.1.json#/id",
                            "payload":"$websocket.message.1.evidence",
                            "transcript":"$websocket.evidence.transcript",
                            "close_code":"$websocket.close.code"
                        }
                    }
                ]
            }]
        });
        let configuration = ProjectConfiguration::default();
        let plan = build_workflow_plan(
            &root.join("workflow.json"),
            &workflow,
            "httpToSocket",
            serde_json::json!({}),
            None,
            None,
            Vec::new(),
            &configuration,
        )
        .unwrap();
        let evidence = EvidenceStore::open(root.join("store")).unwrap();
        let options = InvokeOptions {
            grants: plan.required_grants.iter().cloned().collect(),
            expected_config_fingerprint: Some(plan.config_fingerprint.clone()),
            expected_policy_fingerprint: Some(plan.policy_fingerprint.clone()),
            timeout: std::time::Duration::from_secs(10),
            ..InvokeOptions::default()
        };
        let observation =
            invoke_workflow(&plan, &options, &configuration, &root, &evidence).unwrap();
        assert_eq!(observation.outcome, Outcome::Passed);
        assert_eq!(observation.steps.len(), 2);
        assert_eq!(observation.outputs["publish.event_id"], "event-9");
        assert_eq!(observation.outputs["publish.close_code"], 1000);
        for output in ["publish.payload", "publish.transcript"] {
            let handle = observation.outputs[output].as_str().unwrap();
            assert!(handle.contains(':'));
            assert!(!evidence.get(handle).unwrap().data.is_empty());
        }
        http_worker.join().unwrap();
        websocket_worker.join().unwrap();
        drop(evidence);
        remove_temporary_store(&root);
    }

    #[test]
    fn websocket_output_binds_into_a_second_finite_session() {
        let root = temporary_root("ws-ws");
        let (first_port, first_worker) =
            spawn_websocket_peer("begin".into(), Message::Text("token-42".into()));
        let (second_port, second_worker) = spawn_websocket_peer(
            "token-42".into(),
            Message::Text(r#"{"stored":true}"#.into()),
        );
        for (name, operation, port, send, expect) in [
            ("first", "receiveToken", first_port, "begin", "token-42"),
            ("second", "storeToken", second_port, "pending", "stored"),
        ] {
            let expectation = if name == "first" {
                serde_json::json!({"type":"expect-text","equals":expect,"timeout_ms":2_000})
            } else {
                serde_json::json!({"type":"expect-json","pointer":"/stored","equals":true,"timeout_ms":2_000})
            };
            fs::write(
                root.join(format!("{name}.json")),
                serde_json::to_vec(&serde_json::json!({
                    "kind":"websocket-session",
                    "version":1,
                    "operationId":operation,
                    "url":format!("ws://127.0.0.1:{port}/events"),
                    "risk":"write",
                    "limits":websocket_limits(),
                    "actions":[
                        {"type":"send-text","text":send},
                        expectation,
                        {"type":"close","code":1000,"reason":"done"}
                    ]
                }))
                .unwrap(),
            )
            .unwrap();
        }
        let workflow = serde_json::json!({
            "arazzo":"1.1.0",
            "info":{"title":"socket-chain","version":"1"},
            "sourceDescriptions":[
                {"name":"first","url":"first.json","x-kahea-source-kind":WEBSOCKET_SOURCE_KIND},
                {"name":"second","url":"second.json","x-kahea-source-kind":WEBSOCKET_SOURCE_KIND}
            ],
            "workflows":[{
                "workflowId":"socketChain",
                "steps":[
                    {"stepId":"receive","operationId":"$sourceDescriptions.first.receiveToken","outputs":{"token":"$websocket.message.1.text"}},
                    {
                        "stepId":"store",
                        "operationId":"$sourceDescriptions.second.storeToken",
                        "dependsOn":["receive"],
                        "x-kahea-websocket-bindings":[{"pointer":"/actions/0/text","value":"$steps.receive.outputs.token"}],
                        "outputs":{"stored":"$websocket.message.1.json#/stored"}
                    }
                ]
            }]
        });
        let configuration = ProjectConfiguration::default();
        let plan = build_workflow_plan(
            &root.join("workflow.json"),
            &workflow,
            "socketChain",
            serde_json::json!({}),
            None,
            None,
            Vec::new(),
            &configuration,
        )
        .unwrap();
        let evidence = EvidenceStore::open(root.join("store")).unwrap();
        let options = InvokeOptions {
            grants: plan.required_grants.iter().cloned().collect(),
            expected_config_fingerprint: Some(plan.config_fingerprint.clone()),
            expected_policy_fingerprint: Some(plan.policy_fingerprint.clone()),
            timeout: std::time::Duration::from_secs(10),
            ..InvokeOptions::default()
        };
        let observation =
            invoke_workflow(&plan, &options, &configuration, &root, &evidence).unwrap();
        assert_eq!(observation.outcome, Outcome::Passed);
        assert_eq!(observation.outputs["receive.token"], "token-42");
        assert_eq!(observation.outputs["store.stored"], true);
        first_worker.join().unwrap();
        second_worker.join().unwrap();
        drop(evidence);
        remove_temporary_store(&root);
    }
}
