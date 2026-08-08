//! Policy-gated execution of sealed request plans.

mod websocket;

pub use websocket::{
    WebSocketCancellation, WebSocketConnectResult, WebSocketConnection, WebSocketHandshakeMetadata,
    connect_websocket, execute_websocket, execute_websocket_with_cancellation,
};

use base64::Engine;
use kahea_core::{
    DenialEnvelope, Observation, Outcome, PROTOCOL, RequestPlan, VERSION,
    default_config_fingerprint, digest,
};
use kahea_evidence::{EvidenceError, EvidenceStore};
use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, StatusCode};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::time::{Duration, Instant};
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum ExecError {
    #[error("plan serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("plan fingerprint does not match its canonical bytes")]
    InvalidSeal,
    #[error("invalid target URL: {0}")]
    InvalidTarget(String),
    #[error("invalid HTTP method: {0}")]
    InvalidMethod(String),
    #[error("invalid planned header: {0}")]
    InvalidHeader(String),
    #[error("secret profile {0:?} was not resolved")]
    MissingSecret(String),
    #[error("unsupported authentication placement {0:?}")]
    UnsupportedAuth(String),
    #[error("OAuth credential profile is invalid")]
    InvalidOAuthProfile,
    #[error("OAuth token exchange failed")]
    OAuthExchange,
    #[error("mutual TLS identity could not be loaded")]
    InvalidClientIdentity,
    #[error("transport failure: {0}")]
    Transport(String),
    #[error("response exceeded the {0} byte limit")]
    ResponseTooLarge(u64),
    #[error("plan configuration fingerprint is incompatible with the invocation configuration")]
    ConfigurationMismatch,
    #[error("plan policy fingerprint is incompatible with the invocation policy")]
    PolicyMismatch,
    #[error("evidence failure: {0}")]
    Evidence(#[from] EvidenceError),
}

#[derive(Debug, Clone)]
pub struct InvokeOptions {
    pub grants: BTreeSet<String>,
    pub secrets: BTreeMap<String, String>,
    pub timeout: Duration,
    pub max_response_bytes: u64,
    pub expected_config_fingerprint: Option<String>,
    pub expected_policy_fingerprint: Option<String>,
    /// PEM-encoded root certificate bundles appended for `wss` connections only.
    /// Each entry may contain multiple PEM blocks; HTTPS requests made by [`invoke`] ignore them.
    pub additional_root_certificates_pem: Vec<Vec<u8>>,
}

impl Default for InvokeOptions {
    fn default() -> Self {
        Self {
            grants: BTreeSet::new(),
            secrets: BTreeMap::new(),
            timeout: Duration::from_secs(30),
            max_response_bytes: 16 * 1024 * 1024,
            expected_config_fingerprint: None,
            expected_policy_fingerprint: None,
            additional_root_certificates_pem: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub enum InvocationResult {
    Observation(Observation),
    Denied(DenialEnvelope),
}

impl InvocationResult {
    pub fn exit(&self) -> u8 {
        match self {
            Self::Observation(observation) => observation.exit,
            Self::Denied(denial) => denial.exit,
        }
    }
}

pub fn invoke(
    plan: &RequestPlan,
    options: &InvokeOptions,
    store: &EvidenceStore,
) -> Result<InvocationResult, ExecError> {
    if !plan.verify_seal()? {
        return Err(ExecError::InvalidSeal);
    }
    if options
        .expected_config_fingerprint
        .as_ref()
        .is_some_and(|expected| expected != &plan.config_fingerprint)
    {
        return Err(ExecError::ConfigurationMismatch);
    }
    if options
        .expected_policy_fingerprint
        .as_ref()
        .is_some_and(|expected| expected != &plan.policy_fingerprint)
    {
        return Err(ExecError::PolicyMismatch);
    }
    if let Some(missing) = plan
        .required_grants
        .iter()
        .find(|grant| !options.grants.contains(*grant))
    {
        return Ok(InvocationResult::Denied(denial(
            plan,
            "invocation is missing a required capability",
            missing,
        )));
    }
    let mut target =
        Url::parse(&plan.target).map_err(|error| ExecError::InvalidTarget(error.to_string()))?;
    let (runtime_denial, addresses) =
        evaluate_runtime_target(plan, &target, &plan.method, options)?;
    if let Some(denial) = runtime_denial {
        return Ok(InvocationResult::Denied(denial));
    }
    let method = Method::from_bytes(plan.method.as_bytes())
        .map_err(|error| ExecError::InvalidMethod(error.to_string()))?;
    let mut headers = planned_headers(plan)?;
    let mut response_redactions = secret_redactions(options);
    let identity = resolve_client_identity(plan, options)?;
    if plan
        .auth
        .as_ref()
        .is_some_and(|auth| auth.placement.starts_with("oauth2-"))
    {
        match obtain_oauth_token(plan, options, store)? {
            OAuthResult::Token(token) => {
                response_redactions.push(token.as_bytes().to_vec());
                insert_sensitive_header(&mut headers, "authorization", &format!("Bearer {token}"))?;
            }
            OAuthResult::Denied(denial) => return Ok(InvocationResult::Denied(denial)),
        }
    } else {
        apply_auth(plan, options, &mut target, &mut headers)?;
    }
    response_redactions.extend(
        headers
            .iter()
            .filter(|(_, value)| value.is_sensitive())
            .map(|(_, value)| value.as_bytes().to_vec()),
    );
    response_redactions.sort_by_key(|value| std::cmp::Reverse(value.len()));
    response_redactions.dedup();
    let body = planned_body_bytes(plan)?;
    if let Some(planned) = &plan.body
        && (planned.bytes != body.len() as u64 || planned.blake3 != digest(&body))
    {
        return Err(ExecError::InvalidSeal);
    }

    let host = target
        .host_str()
        .expect("runtime target validation requires host");
    let mut client_builder = Client::builder()
        .timeout(options.timeout)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .resolve_to_addrs(host, &addresses);
    if let Some(identity) = identity {
        client_builder = client_builder.identity(identity);
    }
    let client = client_builder.build().map_err(safe_transport_error)?;
    let request_trace = redacted_request_trace(plan, &target, &headers);
    let derivation = store.put_json("request-derivation", &plan.derivations, false)?;
    let started = Instant::now();
    let response = client
        .request(method, target.clone())
        .headers(headers)
        .body(body)
        .send()
        .map_err(safe_transport_error)?;
    let elapsed = started.elapsed();
    observe_response(
        plan,
        options,
        store,
        target,
        response,
        elapsed,
        request_trace,
        derivation.handle,
        &response_redactions,
    )
}

fn planned_body_bytes(plan: &RequestPlan) -> Result<Vec<u8>, ExecError> {
    let Some(body) = &plan.body else {
        return Ok(Vec::new());
    };
    match body.encoding.as_str() {
        "utf-8" => Ok(body.inline.as_bytes().to_vec()),
        "base64" => base64::engine::general_purpose::STANDARD
            .decode(&body.inline)
            .map_err(|_| ExecError::InvalidSeal),
        _ => Err(ExecError::InvalidSeal),
    }
}

fn evaluate_runtime_target(
    plan: &RequestPlan,
    target: &Url,
    method: &str,
    options: &InvokeOptions,
) -> Result<(Option<DenialEnvelope>, Vec<SocketAddr>), ExecError> {
    if !matches!(target.scheme(), "http" | "https") {
        return Err(ExecError::InvalidTarget(format!(
            "scheme {:?} is not supported",
            target.scheme()
        )));
    }
    if !target.username().is_empty() || target.password().is_some() {
        return Err(ExecError::InvalidTarget(
            "userinfo in target URLs is denied".into(),
        ));
    }
    if target.scheme() == "http" && !options.grants.contains("net-insecure-http") {
        return Ok((
            Some(denial(
                plan,
                "plaintext HTTP requires an explicit grant",
                "net-insecure-http",
            )),
            Vec::new(),
        ));
    }
    let host = target
        .host_str()
        .ok_or_else(|| ExecError::InvalidTarget("host is missing".into()))?;
    let port = target
        .port_or_known_default()
        .ok_or_else(|| ExecError::InvalidTarget("port is missing".into()))?;
    for required in [format!("net:{host}:{port}"), format!("http:{method}")] {
        if !options.grants.contains(&required) {
            return Ok((
                Some(denial(
                    plan,
                    "runtime target requires an explicit capability",
                    &required,
                )),
                Vec::new(),
            ));
        }
    }
    let addresses: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|error| ExecError::Transport(format!("DNS resolution failed: {error}")))?
        .collect();
    if addresses.is_empty() {
        return Err(ExecError::Transport("DNS returned no addresses".into()));
    }
    for address in &addresses {
        if unsafe_address(address.ip()) {
            let required = match address.ip() {
                IpAddr::V4(address) => format!("net-cidr:{address}/32"),
                IpAddr::V6(address) => format!("net-cidr:{address}/128"),
            };
            if !options.grants.contains(&required) {
                return Ok((
                    Some(denial(
                        plan,
                        "resolved address is denied by the network boundary",
                        &required,
                    )),
                    Vec::new(),
                ));
            }
        }
    }
    Ok((None, addresses))
}

fn planned_headers(plan: &RequestPlan) -> Result<HeaderMap, ExecError> {
    let mut headers = HeaderMap::new();
    for planned in &plan.headers {
        if planned.name.contains(['\r', '\n']) || planned.value.contains(['\r', '\n']) {
            return Err(ExecError::InvalidHeader("CR/LF is denied".into()));
        }
        let name = HeaderName::from_str(&planned.name)
            .map_err(|error| ExecError::InvalidHeader(error.to_string()))?;
        let value = HeaderValue::from_str(&planned.value)
            .map_err(|error| ExecError::InvalidHeader(error.to_string()))?;
        headers.append(name, value);
    }
    Ok(headers)
}

fn apply_auth(
    plan: &RequestPlan,
    options: &InvokeOptions,
    target: &mut Url,
    headers: &mut HeaderMap,
) -> Result<(), ExecError> {
    let Some(auth) = &plan.auth else {
        return Ok(());
    };
    let secret = options
        .secrets
        .get(&auth.profile)
        .ok_or_else(|| ExecError::MissingSecret(auth.profile.clone()))?;
    let parts: Vec<_> = auth.placement.split(':').collect();
    match parts.as_slice() {
        ["header", "Authorization", "basic"] => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(secret);
            insert_sensitive_header(headers, "authorization", &format!("Basic {encoded}"))
        }
        ["header", "Authorization", "bearer"] | ["header", "Authorization", "Bearer"] => {
            insert_sensitive_header(headers, "authorization", &format!("Bearer {secret}"))
        }
        ["header", name] => insert_sensitive_header(headers, name, secret),
        ["query", name] => {
            target.query_pairs_mut().append_pair(name, secret);
            Ok(())
        }
        ["cookie", name] => {
            let existing = headers
                .get("cookie")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            let value = if existing.is_empty() {
                format!("{name}={secret}")
            } else {
                format!("{existing}; {name}={secret}")
            };
            insert_sensitive_header(headers, "cookie", &value)
        }
        ["tls-client-certificate"] => Ok(()),
        _ => Err(ExecError::UnsupportedAuth(auth.placement.clone())),
    }
}

fn resolve_client_identity(
    plan: &RequestPlan,
    options: &InvokeOptions,
) -> Result<Option<reqwest::Identity>, ExecError> {
    let Some(auth) = plan
        .auth
        .as_ref()
        .filter(|auth| auth.placement == "tls-client-certificate")
    else {
        return Ok(None);
    };
    let pem = options
        .secrets
        .get(&auth.profile)
        .ok_or_else(|| ExecError::MissingSecret(auth.profile.clone()))?;
    reqwest::Identity::from_pem(pem.as_bytes())
        .map(Some)
        .map_err(|_| ExecError::InvalidClientIdentity)
}

enum OAuthResult {
    Token(String),
    Denied(DenialEnvelope),
}

fn obtain_oauth_token(
    plan: &RequestPlan,
    options: &InvokeOptions,
    store: &EvidenceStore,
) -> Result<OAuthResult, ExecError> {
    let auth = plan
        .auth
        .as_ref()
        .filter(|auth| auth.placement.starts_with("oauth2-"))
        .ok_or_else(|| ExecError::UnsupportedAuth("OAuth metadata is missing".into()))?;
    let token_url = auth
        .token_url
        .as_deref()
        .ok_or(ExecError::InvalidOAuthProfile)?;
    let target = Url::parse(token_url)
        .map_err(|error| ExecError::InvalidTarget(format!("OAuth token URL: {error}")))?;
    let (runtime_denial, addresses) = evaluate_runtime_target(plan, &target, "POST", options)?;
    if let Some(denial) = runtime_denial {
        return Ok(OAuthResult::Denied(denial));
    }
    let credentials: Value = serde_json::from_str(
        options
            .secrets
            .get(&auth.profile)
            .ok_or_else(|| ExecError::MissingSecret(auth.profile.clone()))?,
    )
    .map_err(|_| ExecError::InvalidOAuthProfile)?;
    let credentials = credentials
        .as_object()
        .ok_or(ExecError::InvalidOAuthProfile)?;
    let client_id = credentials
        .get("client_id")
        .and_then(Value::as_str)
        .ok_or(ExecError::InvalidOAuthProfile)?;
    let client_secret = credentials.get("client_secret").and_then(Value::as_str);
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    match auth.placement.as_str() {
        "oauth2-client-credentials" => {
            form.append_pair("grant_type", "client_credentials");
        }
        "oauth2-refresh-token" => {
            form.append_pair("grant_type", "refresh_token");
            form.append_pair(
                "refresh_token",
                credentials
                    .get("refresh_token")
                    .and_then(Value::as_str)
                    .ok_or(ExecError::InvalidOAuthProfile)?,
            );
        }
        _ => return Err(ExecError::UnsupportedAuth(auth.placement.clone())),
    }
    if !auth.scopes.is_empty() {
        form.append_pair("scope", &auth.scopes.join(" "));
    }
    let form = form.finish();
    let host = target
        .host_str()
        .ok_or_else(|| ExecError::InvalidTarget("OAuth token host is missing".into()))?;
    let client = Client::builder()
        .timeout(options.timeout)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .resolve_to_addrs(host, &addresses)
        .build()
        .map_err(safe_transport_error)?;
    let mut request = client
        .post(target.clone())
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form);
    request = if let Some(client_secret) = client_secret {
        request.basic_auth(client_id, Some(client_secret))
    } else {
        request
    };
    let mut response = request.send().map_err(safe_transport_error)?;
    let status = response.status();
    let mut data = Vec::new();
    response
        .by_ref()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut data)
        .map_err(|_| ExecError::OAuthExchange)?;
    if !status.is_success() || data.len() > 1024 * 1024 {
        return Err(ExecError::OAuthExchange);
    }
    let token = serde_json::from_slice::<Value>(&data)
        .ok()
        .and_then(|value| {
            value
                .get("access_token")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .ok_or(ExecError::OAuthExchange)?;
    store.put_json(
        "oauth-refresh",
        &json!({
            "token_url": target.as_str(),
            "status": status.as_u16(),
            "profile": format!("secret://{}", auth.profile),
            "response_blake3": digest(&data),
        }),
        true,
    )?;
    Ok(OAuthResult::Token(token))
}

fn insert_sensitive_header(
    headers: &mut HeaderMap,
    name: &str,
    value: &str,
) -> Result<(), ExecError> {
    let name =
        HeaderName::from_str(name).map_err(|error| ExecError::InvalidHeader(error.to_string()))?;
    let mut value = HeaderValue::from_str(value)
        .map_err(|error| ExecError::InvalidHeader(error.to_string()))?;
    value.set_sensitive(true);
    headers.insert(name, value);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn observe_response(
    plan: &RequestPlan,
    options: &InvokeOptions,
    store: &EvidenceStore,
    target: Url,
    mut response: Response,
    elapsed: Duration,
    request_trace: Value,
    derivation_handle: String,
    response_redactions: &[Vec<u8>],
) -> Result<InvocationResult, ExecError> {
    let status = response.status();
    let version = format!("{:?}", response.version());
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let response_headers = redacted_headers(response.headers(), &plan.sensitive_headers);
    let mut data = Vec::new();
    response
        .by_ref()
        .take(options.max_response_bytes + 1)
        .read_to_end(&mut data)
        .map_err(|error| ExecError::Transport(format!("response read failed: {error}")))?;
    if data.len() as u64 > options.max_response_bytes {
        return Err(ExecError::ResponseTooLarge(options.max_response_bytes));
    }
    let failures = validate_checks(
        plan,
        status,
        response.headers(),
        &content_type,
        &data,
        elapsed,
    );
    let configured_redaction = redact_json_pointers(&data, &plan.redact_response_json_pointers);
    let redacted_data = redact_bytes(&configured_redaction, response_redactions);
    let was_redacted = redacted_data != data;
    let body = store.put_blob("body", &content_type, &redacted_data, was_redacted)?;
    let schema_error = if failures.is_empty() {
        None
    } else {
        Some(store.put_json("schema-error", &failures, false)?.handle)
    };
    let trace = json!({
        "request": request_trace,
        "response": {
            "status": status.as_u16(),
            "headers": response_headers,
            "body": body.handle,
            "bytes": data.len(),
            "http_version": version,
        },
        "request_derivation": derivation_handle,
        "schema_error": schema_error,
    });
    let trace = store.put_json("trace", &trace, true)?;
    let passed = failures.is_empty();
    let origin = format!(
        "{}://{}:{}",
        target.scheme(),
        target.host_str().unwrap_or_default(),
        target.port_or_known_default().unwrap_or_default()
    );
    let observation = Observation {
        protocol: PROTOCOL.into(),
        kind: "observation".into(),
        version: VERSION.into(),
        config_fingerprint: plan.config_fingerprint.clone(),
        policy_fingerprint: plan.policy_fingerprint.clone(),
        source_fingerprints: plan.source_fingerprints.clone(),
        tool_version: VERSION.into(),
        plan: plan.id.clone(),
        outcome: if passed {
            Outcome::Passed
        } else {
            Outcome::Failed
        },
        status: Some(status.as_u16()),
        response_schema: Some(if passed {
            "passed".into()
        } else {
            "failed".into()
        }),
        latency_ms: Some(elapsed.as_secs_f64() * 1_000.0),
        response_bytes: Some(data.len() as u64),
        body: Some(body.handle),
        trace: Some(trace.handle),
        resolved_origin: Some(origin),
        http_version: Some(version),
        secret_refs: plan.secret_refs.clone(),
        runtime: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        exit: if passed { 0 } else { 1 },
    };
    store.persist_observation(&observation)?;
    Ok(InvocationResult::Observation(observation))
}

fn secret_redactions(options: &InvokeOptions) -> Vec<Vec<u8>> {
    let mut redactions = Vec::new();
    for secret in options.secrets.values() {
        if !secret.is_empty() {
            redactions.push(secret.as_bytes().to_vec());
        }
        if let Ok(value) = serde_json::from_str::<Value>(secret) {
            collect_string_values(&value, &mut redactions);
        }
    }
    redactions
}

fn collect_string_values(value: &Value, found: &mut Vec<Vec<u8>>) {
    match value {
        Value::String(value) if !value.is_empty() => found.push(value.as_bytes().to_vec()),
        Value::Array(values) => values
            .iter()
            .for_each(|value| collect_string_values(value, found)),
        Value::Object(values) => values
            .values()
            .for_each(|value| collect_string_values(value, found)),
        _ => {}
    }
}

fn redact_bytes(data: &[u8], secrets: &[Vec<u8>]) -> Vec<u8> {
    let mut redacted = data.to_vec();
    for secret in secrets.iter().filter(|secret| !secret.is_empty()) {
        let mut cursor = 0;
        while cursor + secret.len() <= redacted.len() {
            let Some(offset) = redacted[cursor..]
                .windows(secret.len())
                .position(|window| window == secret)
            else {
                break;
            };
            let start = cursor + offset;
            redacted.splice(start..start + secret.len(), b"[REDACTED]".iter().copied());
            cursor = start + b"[REDACTED]".len();
        }
    }
    redacted
}

fn redact_json_pointers(data: &[u8], pointers: &[String]) -> Vec<u8> {
    if pointers.is_empty() {
        return data.to_vec();
    }
    let Ok(mut value) = serde_json::from_slice::<Value>(data) else {
        return data.to_vec();
    };
    let mut changed = false;
    for pointer in pointers {
        if let Some(selected) = value.pointer_mut(pointer) {
            *selected = Value::String("[REDACTED]".into());
            changed = true;
        }
    }
    if changed {
        serde_json::to_vec(&value).unwrap_or_else(|_| data.to_vec())
    } else {
        data.to_vec()
    }
}

fn validate_checks(
    plan: &RequestPlan,
    status: StatusCode,
    headers: &HeaderMap,
    content_type: &str,
    data: &[u8],
    elapsed: Duration,
) -> Vec<String> {
    let mut failures = Vec::new();
    for check in &plan.checks {
        if let Some(values) = check
            .strip_prefix("status:any(")
            .and_then(|value| value.strip_suffix(')'))
        {
            let allowed = values
                .split(',')
                .filter_map(|value| value.parse::<u16>().ok());
            if !allowed
                .into_iter()
                .any(|allowed| allowed == status.as_u16())
            {
                failures.push(format!(
                    "status {} is not allowed by {check}",
                    status.as_u16()
                ));
            }
        } else if let Some(expected) = check.strip_prefix("status:") {
            if expected.parse::<u16>().ok() != Some(status.as_u16()) {
                failures.push(format!(
                    "status {} does not equal {expected}",
                    status.as_u16()
                ));
            }
        } else if let Some(expected) = check.strip_prefix("content-type:") {
            if !content_type
                .to_ascii_lowercase()
                .starts_with(&expected.to_ascii_lowercase())
            {
                failures.push(format!(
                    "content type {content_type:?} does not match {expected:?}"
                ));
            }
        } else if check == "response-schema:openapi" {
            validate_response_schema(plan, status, content_type, data, &mut failures);
        } else if let Some(specification) = check.strip_prefix("header:") {
            validate_header_check(headers, specification, &mut failures);
        } else if let Some(specification) = check.strip_prefix("json-pointer:") {
            validate_json_pointer_check(data, specification, &mut failures);
        } else if let Some(specification) = check.strip_prefix("jsonpath:") {
            validate_jsonpath_check(data, specification, &mut failures);
        } else if let Some(specification) = check.strip_prefix("xpath:") {
            validate_xpath_check(data, specification, &mut failures);
        } else if let Some(expected) = check.strip_prefix("body-digest:") {
            if digest(data) != expected {
                failures.push(format!("body digest does not equal {expected}"));
            }
        } else if let Some(maximum) = check.strip_prefix("response-bytes:max:") {
            match maximum.parse::<usize>() {
                Ok(maximum) if data.len() > maximum => failures.push(format!(
                    "response body is {} bytes, exceeding {maximum}",
                    data.len()
                )),
                Ok(_) => {}
                Err(_) => failures.push(format!("invalid response byte check {check:?}")),
            }
        } else if let Some(maximum) = check.strip_prefix("latency-ms:max:") {
            match maximum.parse::<f64>() {
                Ok(maximum) if elapsed.as_secs_f64() * 1_000.0 > maximum => failures.push(format!(
                    "latency {:.3} ms exceeds {maximum}",
                    elapsed.as_secs_f64() * 1_000.0
                )),
                Ok(_) => {}
                Err(_) => failures.push(format!("invalid latency check {check:?}")),
            }
        } else {
            failures.push(format!("unknown check syntax {check:?}"));
        }
        if failures.len() >= 20 {
            failures.truncate(20);
            break;
        }
    }
    failures
}

fn validate_header_check(headers: &HeaderMap, specification: &str, failures: &mut Vec<String>) {
    if let Some(name) = specification.strip_suffix(":exists") {
        if !headers.contains_key(name) {
            failures.push(format!("response header {name:?} is missing"));
        }
        return;
    }
    let Some((name, expected)) = specification.split_once('=') else {
        failures.push(format!("invalid header check {specification:?}"));
        return;
    };
    let actual = headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>();
    if !actual.contains(&expected) {
        failures.push(format!(
            "response header {name:?} does not equal {expected:?}"
        ));
    }
}

fn validate_json_pointer_check(data: &[u8], specification: &str, failures: &mut Vec<String>) {
    let Ok(document) = serde_json::from_slice::<Value>(data) else {
        failures.push("JSON Pointer check requires a valid JSON response".into());
        return;
    };
    if let Some(pointer) = specification.strip_suffix(":exists") {
        if document.pointer(pointer).is_none() {
            failures.push(format!("JSON Pointer {pointer:?} did not match"));
        }
        return;
    }
    if let Some((pointer, expected_type)) = specification.split_once(":type=") {
        match document.pointer(pointer) {
            Some(value) if value_kind(value) == expected_type => {}
            Some(value) => failures.push(format!(
                "JSON Pointer {pointer:?} has type {}, not {expected_type}",
                value_kind(value)
            )),
            None => failures.push(format!("JSON Pointer {pointer:?} did not match")),
        }
        return;
    }
    let Some((pointer, expected)) = specification.split_once('=') else {
        failures.push(format!("invalid JSON Pointer check {specification:?}"));
        return;
    };
    let expected =
        serde_json::from_str(expected).unwrap_or_else(|_| Value::String(expected.into()));
    if document.pointer(pointer) != Some(&expected) {
        failures.push(format!(
            "JSON Pointer {pointer:?} did not equal the expected value"
        ));
    }
}

fn validate_jsonpath_check(data: &[u8], specification: &str, failures: &mut Vec<String>) {
    use serde_json_path::JsonPath;
    let Ok(document) = serde_json::from_slice::<Value>(data) else {
        failures.push("JSONPath check requires a valid JSON response".into());
        return;
    };
    let query = specification
        .strip_suffix(":exists")
        .unwrap_or(specification);
    match JsonPath::parse(query) {
        Ok(path) if path.query(&document).all().is_empty() => {
            failures.push(format!("JSONPath {query:?} did not match"))
        }
        Ok(_) if specification.ends_with(":exists") => {}
        Ok(_) => failures.push(format!("JSONPath check {specification:?} must use :exists")),
        Err(error) => failures.push(format!("invalid JSONPath {query:?}: {error}")),
    }
}

fn validate_xpath_check(data: &[u8], specification: &str, failures: &mut Vec<String>) {
    let query = specification
        .strip_suffix(":exists")
        .unwrap_or(specification);
    let Ok(text) = std::str::from_utf8(data) else {
        failures.push("XPath check requires UTF-8 XML".into());
        return;
    };
    let Ok(package) = sxd_document::parser::parse(text) else {
        failures.push("XPath check requires valid XML".into());
        return;
    };
    match sxd_xpath::evaluate_xpath(&package.as_document(), query) {
        Ok(sxd_xpath::Value::Nodeset(nodes)) if nodes.size() == 0 => {
            failures.push(format!("XPath {query:?} did not match"))
        }
        Ok(value) if !value.boolean() => failures.push(format!("XPath {query:?} evaluated false")),
        Ok(_) if specification.ends_with(":exists") => {}
        Ok(_) => failures.push(format!("XPath check {specification:?} must use :exists")),
        Err(error) => failures.push(format!("invalid XPath {query:?}: {error}")),
    }
}

fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(number) if number.is_i64() || number.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn validate_response_schema(
    plan: &RequestPlan,
    status: StatusCode,
    content_type: &str,
    data: &[u8],
    failures: &mut Vec<String>,
) {
    let Some(contract) = plan.response_contract.as_object() else {
        return;
    };
    let responses = contract
        .get("responses")
        .and_then(Value::as_object)
        .unwrap_or(contract);
    let response = responses
        .get(&status.as_u16().to_string())
        .or_else(|| responses.get(&format!("{}XX", status.as_u16() / 100)))
        .or_else(|| responses.get(&format!("{}xx", status.as_u16() / 100)))
        .or_else(|| responses.get("default"));
    let Some(response) = response else {
        failures.push(format!(
            "response status {} is not declared",
            status.as_u16()
        ));
        return;
    };
    let response = resolve_contract_ref(&plan.response_contract, response).unwrap_or(response);
    let Some(response) = response.as_object() else {
        return;
    };
    let Some(content) = response.get("content").and_then(Value::as_object) else {
        return;
    };
    let media = content
        .iter()
        .find(|(declared, _)| content_type.starts_with(declared.as_str()))
        .or_else(|| content.iter().next());
    let Some((_, media)) = media else { return };
    let Some(schema) = media.get("schema") else {
        return;
    };
    if content_type.contains("json") {
        match serde_json::from_slice::<Value>(data) {
            Ok(value) => {
                validate_schema_value(&plan.response_contract, schema, &value, "$", failures, 0)
            }
            Err(error) => failures.push(format!("response is not valid JSON: {error}")),
        }
    }
}

fn validate_schema_value(
    root: &Value,
    schema: &Value,
    value: &Value,
    path: &str,
    failures: &mut Vec<String>,
    depth: usize,
) {
    if failures.len() >= 64 {
        return;
    }
    if depth >= 64 {
        failures.push(format!("{path}: schema validation exceeded 64 levels"));
        return;
    }
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        if let Some(resolved) = resolve_contract_ref(root, schema) {
            validate_schema_value(root, resolved, value, path, failures, depth + 1);
        } else {
            failures.push(format!("{path}: unresolved schema reference {reference:?}"));
        }
        return;
    }
    if schema
        .get("const")
        .is_some_and(|constant| constant != value)
    {
        failures.push(format!("{path}: value does not equal const"));
    }
    if schema
        .get("enum")
        .and_then(Value::as_array)
        .is_some_and(|values| !values.contains(value))
    {
        failures.push(format!("{path}: value is outside enum"));
    }
    if let Some(branches) = schema.get("allOf").and_then(Value::as_array) {
        for branch in branches {
            validate_schema_value(root, branch, value, path, failures, depth + 1);
        }
    }
    for keyword in ["anyOf", "oneOf"] {
        if let Some(branches) = schema.get(keyword).and_then(Value::as_array) {
            let passing = branches
                .iter()
                .filter(|branch| {
                    let mut branch_failures = Vec::new();
                    validate_schema_value(
                        root,
                        branch,
                        value,
                        path,
                        &mut branch_failures,
                        depth + 1,
                    );
                    branch_failures.is_empty()
                })
                .count();
            if (keyword == "oneOf" && passing != 1) || (keyword == "anyOf" && passing == 0) {
                failures.push(format!("{path}: value does not satisfy {keyword}"));
            }
        }
    }
    let declared_types: Vec<&str> = match schema.get("type") {
        Some(Value::String(kind)) => vec![kind],
        Some(Value::Array(kinds)) => kinds.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    if !declared_types.is_empty() {
        let matches = declared_types.iter().any(|kind| match *kind {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "number" => value.is_number(),
            "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            _ => true,
        });
        if !matches {
            failures.push(format!("{path}: expected {}", declared_types.join(" or ")));
            return;
        }
    }
    if let Some(text) = value.as_str() {
        let length = text.chars().count() as u64;
        if schema
            .get("minLength")
            .and_then(Value::as_u64)
            .is_some_and(|minimum| length < minimum)
        {
            failures.push(format!("{path}: string is shorter than minLength"));
        }
        if schema
            .get("maxLength")
            .and_then(Value::as_u64)
            .is_some_and(|maximum| length > maximum)
        {
            failures.push(format!("{path}: string is longer than maxLength"));
        }
    }
    if let Some(number) = value.as_f64() {
        if schema
            .get("minimum")
            .and_then(Value::as_f64)
            .is_some_and(|minimum| number < minimum)
        {
            failures.push(format!("{path}: number is below minimum"));
        }
        if schema
            .get("maximum")
            .and_then(Value::as_f64)
            .is_some_and(|maximum| number > maximum)
        {
            failures.push(format!("{path}: number is above maximum"));
        }
    }
    if let (Some(required), Some(object)) = (
        schema.get("required").and_then(Value::as_array),
        value.as_object(),
    ) {
        for name in required.iter().filter_map(Value::as_str) {
            if !object.contains_key(name) {
                failures.push(format!("{path}.{name}: required property is missing"));
            }
        }
    }
    let properties = schema.get("properties").and_then(Value::as_object);
    if let (Some(properties), Some(object)) = (properties, value.as_object()) {
        for (name, child_schema) in properties {
            if let Some(child) = object.get(name) {
                validate_schema_value(
                    root,
                    child_schema,
                    child,
                    &format!("{path}.{name}"),
                    failures,
                    depth + 1,
                );
            }
        }
    }
    if schema.get("additionalProperties") == Some(&Value::Bool(false))
        && let Some(object) = value.as_object()
    {
        for name in object.keys() {
            if !properties.is_some_and(|properties| properties.contains_key(name)) {
                failures.push(format!("{path}.{name}: additional property is denied"));
            }
        }
    }
    if let (Some(items), Some(values)) = (schema.get("items"), value.as_array()) {
        for (index, child) in values.iter().enumerate() {
            validate_schema_value(
                root,
                items,
                child,
                &format!("{path}[{index}]"),
                failures,
                depth + 1,
            );
        }
    }
}

fn resolve_contract_ref<'a>(root: &'a Value, value: &'a Value) -> Option<&'a Value> {
    let reference = value.get("$ref")?.as_str()?;
    reference
        .strip_prefix('#')
        .and_then(|pointer| root.pointer(pointer))
}

fn redacted_request_trace(plan: &RequestPlan, target: &Url, headers: &HeaderMap) -> Value {
    let mut safe_target = target.clone();
    if plan
        .auth
        .as_ref()
        .is_some_and(|auth| auth.placement.starts_with("query:"))
    {
        safe_target.set_query(Some("[REDACTED]"));
    }
    json!({
        "method": plan.method,
        "target": safe_target.as_str(),
        "headers": redacted_headers(headers, &plan.sensitive_headers),
        "body_blake3": plan.body.as_ref().map(|body| &body.blake3),
    })
}

fn redacted_headers(headers: &HeaderMap, configured: &[String]) -> Map<String, Value> {
    let mut result = Map::new();
    for (name, value) in headers {
        let sensitive = value.is_sensitive()
            || configured
                .iter()
                .any(|configured| configured.eq_ignore_ascii_case(name.as_str()))
            || matches!(
                name.as_str(),
                "authorization" | "proxy-authorization" | "cookie" | "set-cookie" | "x-api-key"
            );
        result.insert(
            name.to_string(),
            Value::String(if sensitive {
                "[REDACTED]".into()
            } else {
                value.to_str().unwrap_or("[NON-UTF8]").into()
            }),
        );
    }
    result
}

fn denial(plan: &RequestPlan, reason: &str, required: &str) -> DenialEnvelope {
    DenialEnvelope {
        protocol: PROTOCOL.into(),
        kind: "denial".into(),
        version: VERSION.into(),
        config_fingerprint: default_config_fingerprint(),
        plan: plan.id.clone(),
        reason: reason.into(),
        required: required.into(),
        policy: plan.policy_fingerprint.clone(),
        exit: 4,
    }
}

fn safe_transport_error(error: reqwest::Error) -> ExecError {
    ExecError::Transport(if error.is_timeout() {
        "request timed out".into()
    } else if error.is_connect() {
        "connection failed".into()
    } else {
        "HTTP transport failed".into()
    })
}

fn unsafe_address(address: IpAddr) -> bool {
    address.is_loopback()
        || address.is_unspecified()
        || address.is_multicast()
        || match address {
            IpAddr::V4(address) => unsafe_ipv4(address),
            IpAddr::V6(address) => unsafe_ipv6(address),
        }
}

fn unsafe_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    address.is_private()
        || address.is_link_local()
        || octets[0] == 0
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0)
        || (octets[0] == 198 && matches!(octets[1], 18 | 19 | 51))
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        || octets[0] >= 240
}

fn unsafe_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    address.is_unique_local()
        || address.is_unicast_link_local()
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x0100 && segments[1..].iter().all(|segment| *segment == 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kahea_core::{PlannedAuth, RiskClass};
    use std::fs;
    use std::io::{ErrorKind, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn store() -> (std::path::PathBuf, EvidenceStore) {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("kahea-exec-{}-{nonce}", std::process::id()));
        let store = EvidenceStore::open(&root).unwrap();
        (root, store)
    }

    fn plan(port: u16, auth: bool) -> RequestPlan {
        RequestPlan {
            protocol: PROTOCOL.into(),
            kind: "plan".into(),
            version: VERSION.into(),
            config_fingerprint: default_config_fingerprint(),
            policy_fingerprint: digest(b"test-policy"),
            source_fingerprints: vec![digest(b"test-source")],
            id: String::new(),
            operation: "op:test".into(),
            target: format!("http://127.0.0.1:{port}/resource"),
            method: "GET".into(),
            risk: RiskClass::Read,
            required_grants: vec![
                "http:GET".into(),
                "net-insecure-http".into(),
                format!("net:127.0.0.1:{port}"),
                "net-cidr:127.0.0.1/32".into(),
            ],
            secret_refs: if auth {
                vec!["secret://test-profile".into()]
            } else {
                Vec::new()
            },
            headers: Vec::new(),
            auth: auth.then(|| PlannedAuth {
                scheme: "bearerAuth".into(),
                kind: "http".into(),
                profile: "test-profile".into(),
                placement: "header:Authorization:bearer".into(),
                token_url: None,
                scopes: Vec::new(),
            }),
            body: None,
            checks: vec!["status:200".into(), "response-schema:openapi".into()],
            response_contract: json!({
                "200": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["ok"],
                                "properties": {"ok": {"type": "boolean"}}
                            }
                        }
                    }
                }
            }),
            sensitive_headers: Vec::new(),
            redact_response_json_pointers: Vec::new(),
            derivations: Vec::new(),
            valid: true,
            fingerprint: String::new(),
            exit: 0,
        }
        .seal()
        .unwrap()
    }

    fn all_grants(plan: &RequestPlan) -> InvokeOptions {
        InvokeOptions {
            grants: plan.required_grants.iter().cloned().collect(),
            ..InvokeOptions::default()
        }
    }

    fn serve_once(
        listener: TcpListener,
        status: u16,
        body: &'static str,
    ) -> thread::JoinHandle<String> {
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 4096];
            let bytes = stream.read(&mut request).unwrap();
            let reason = if status == 200 { "OK" } else { "Test Failure" };
            write!(
                stream,
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            String::from_utf8_lossy(&request[..bytes]).into_owned()
        })
    }

    #[test]
    fn missing_grant_is_denied_before_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let plan = plan(listener.local_addr().unwrap().port(), false);
        let (root, store) = store();
        let result = invoke(&plan, &InvokeOptions::default(), &store).unwrap();
        assert!(matches!(result, InvocationResult::Denied(_)));
        assert_eq!(result.exit(), 4);
        assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn successful_response_is_validated_and_evidenced_with_secrets_redacted() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let plan = plan(listener.local_addr().unwrap().port(), true);
        let server = serve_once(
            listener,
            200,
            r#"{"ok":true,"echo":"Bearer top-secret-value"}"#,
        );
        let (root, store) = store();
        let mut options = all_grants(&plan);
        options
            .secrets
            .insert("test-profile".into(), "top-secret-value".into());
        let result = invoke(&plan, &options, &store).unwrap();
        let InvocationResult::Observation(observation) = result else {
            panic!("expected observation")
        };
        assert_eq!(observation.exit, 0);
        let body = store.get(observation.body.as_ref().unwrap()).unwrap();
        assert!(body.envelope.redacted);
        let body = String::from_utf8(body.data).unwrap();
        assert!(body.contains("[REDACTED]"));
        assert!(!body.contains("top-secret-value"));
        let trace = store.get(observation.trace.as_ref().unwrap()).unwrap();
        let trace = String::from_utf8(trace.data).unwrap();
        assert!(trace.contains("[REDACTED]"));
        assert!(!trace.contains("top-secret-value"));
        let request = server.join().unwrap();
        assert!(request.contains("authorization: Bearer top-secret-value"));
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn contract_failures_return_exit_one_with_evidence() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let plan = plan(listener.local_addr().unwrap().port(), false);
        let server = serve_once(listener, 200, r#"{"wrong":true}"#);
        let (root, store) = store();
        let result = invoke(&plan, &all_grants(&plan), &store).unwrap();
        let InvocationResult::Observation(observation) = result else {
            panic!("expected observation")
        };
        assert_eq!(observation.exit, 1);
        assert_eq!(observation.response_schema.as_deref(), Some("failed"));
        server.join().unwrap();
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn tampered_plan_is_rejected_before_transport() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut plan = plan(listener.local_addr().unwrap().port(), false);
        plan.method = "DELETE".into();
        let (root, store) = store();
        assert!(matches!(
            invoke(&plan, &all_grants(&plan), &store),
            Err(ExecError::InvalidSeal)
        ));
        assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn oauth_client_credentials_exchange_is_policy_checked_and_redacted() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut plan = plan(port, false);
        plan.auth = Some(PlannedAuth {
            scheme: "oauth".into(),
            kind: "oauth2".into(),
            profile: "oauth-profile".into(),
            placement: "oauth2-client-credentials".into(),
            token_url: Some(format!("http://127.0.0.1:{port}/token")),
            scopes: vec!["items:read".into()],
        });
        plan.secret_refs = vec!["secret://oauth-profile".into()];
        plan.required_grants.push("http:POST".into());
        plan.required_grants.push("secret:oauth-profile".into());
        plan.required_grants.sort();
        plan = plan.seal().unwrap();
        let server = thread::spawn(move || {
            for (index, body) in [r#"{"access_token":"ephemeral-token"}"#, r#"{"ok":true}"#]
                .into_iter()
                .enumerate()
            {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0_u8; 4096];
                let bytes = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..bytes]);
                if index == 0 {
                    assert!(request.starts_with("POST /token "));
                    assert!(request.contains("grant_type=client_credentials"));
                    assert!(request.contains("scope=items%3Aread"));
                } else {
                    assert!(request.contains("authorization: Bearer ephemeral-token"));
                }
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        let (root, store) = store();
        let mut options = all_grants(&plan);
        options.secrets.insert(
            "oauth-profile".into(),
            r#"{"client_id":"client","client_secret":"never-persist"}"#.into(),
        );
        let result = invoke(&plan, &options, &store).unwrap();
        assert_eq!(result.exit(), 0);
        server.join().unwrap();
        drop(store);
        let persisted = fs::read(root.join("index.sqlite")).unwrap();
        assert!(
            !persisted
                .windows("never-persist".len())
                .any(|window| window == b"never-persist")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn private_network_cannot_be_omitted_from_a_self_sealed_plan() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut plan = plan(listener.local_addr().unwrap().port(), false);
        plan.required_grants
            .retain(|grant| grant != "net-cidr:127.0.0.1/32");
        plan = plan.seal().unwrap();
        let (root, store) = store();
        let result = invoke(&plan, &all_grants(&plan), &store).unwrap();
        let InvocationResult::Denied(denial) = result else {
            panic!("expected runtime network denial")
        };
        assert_eq!(denial.required, "net-cidr:127.0.0.1/32");
        assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn header_injection_is_rejected_before_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut plan = plan(listener.local_addr().unwrap().port(), false);
        plan.headers.push(kahea_core::PlannedHeader {
            name: "X-Test".into(),
            value: "safe\r\nInjected: true".into(),
        });
        plan = plan.seal().unwrap();
        let (root, store) = store();
        assert!(matches!(
            invoke(&plan, &all_grants(&plan), &store),
            Err(ExecError::InvalidHeader(_))
        ));
        assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn redirects_are_not_followed_or_given_credentials() {
        let source = TcpListener::bind("127.0.0.1:0").unwrap();
        let destination = TcpListener::bind("127.0.0.1:0").unwrap();
        destination.set_nonblocking(true).unwrap();
        let mut plan = plan(source.local_addr().unwrap().port(), true);
        plan = plan.seal().unwrap();
        let destination_url = format!(
            "http://127.0.0.1:{}/stolen",
            destination.local_addr().unwrap().port()
        );
        let server = thread::spawn(move || {
            let (mut stream, _) = source.accept().unwrap();
            let mut request = [0_u8; 4096];
            let bytes = stream.read(&mut request).unwrap();
            assert!(
                String::from_utf8_lossy(&request[..bytes])
                    .contains("authorization: Bearer redirect-secret")
            );
            write!(stream, "HTTP/1.1 302 Found\r\nLocation: {destination_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        });
        let (root, store) = store();
        let mut options = all_grants(&plan);
        options
            .secrets
            .insert("test-profile".into(), "redirect-secret".into());
        let result = invoke(&plan, &options, &store).unwrap();
        assert_eq!(result.exit(), 1);
        server.join().unwrap();
        assert_eq!(
            destination.accept().unwrap_err().kind(),
            ErrorKind::WouldBlock
        );
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
}
