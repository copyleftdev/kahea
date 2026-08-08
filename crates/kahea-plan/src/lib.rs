//! Deterministic, no-network request planning.

use base64::Engine;
use kahea_core::{
    FieldDerivation, PROTOCOL, PlannedAuth, PlannedBody, PlannedHeader, RequestPlan, VERSION,
    WebSocketAction, WebSocketLimits, WebSocketPlan, default_config_fingerprint, digest,
    short_handle,
};
use kahea_ingest::{OpenApiSource, OperationDefinition, parse_data_document};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use thiserror::Error;
use url::Url;

const PATH_SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

#[derive(Debug, Error)]
pub enum PlanError {
    #[error("no server is declared; provide --server with an absolute URL")]
    MissingServer,
    #[error("multiple servers are available; select one with --server")]
    AmbiguousServer,
    #[error("server selector {0:?} did not match a declared server")]
    UnknownServer(String),
    #[error("server URL is invalid: {0}")]
    InvalidServer(String),
    #[error("target URL is not permitted: {0}")]
    UnsafeTarget(String),
    #[error("missing required {location} parameter {name:?}")]
    MissingParameter { location: String, name: String },
    #[error("unknown input {0:?}")]
    UnknownInput(String),
    #[error("invalid input for {field}: {reason}")]
    InvalidInput { field: String, reason: String },
    #[error("request body is required")]
    MissingBody,
    #[error("request body is not declared for this operation")]
    UnexpectedBody,
    #[error("content type {0:?} is not declared for this operation")]
    UnknownContentType(String),
    #[error("authentication is required; provide --auth PROFILE or --auth SCHEME=PROFILE")]
    MissingAuth,
    #[error("security scheme {0:?} was not found")]
    UnknownSecurityScheme(String),
    #[error("unsupported security scheme {0:?}")]
    UnsupportedSecurityScheme(String),
    #[error("invalid explicit field {0:?}; expected LOCATION.NAME=VALUE")]
    InvalidExplicitField(String),
    #[error("could not serialize plan: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("plan store error: {0}")]
    Store(#[from] std::io::Error),
    #[error("plan fingerprint does not match its canonical bytes")]
    InvalidSeal,
    #[error("source has material unsupported behavior at {location}: {reason}")]
    BlockingAbsence { location: String, reason: String },
    #[error("configuration error: {0}")]
    Configuration(String),
    #[error("policy denied planning: {0}")]
    PolicyDenied(String),
    #[error("invalid WebSocket session source: {0}")]
    InvalidWebSocketSource(String),
}

#[derive(Debug, Clone, Default)]
pub struct PlanOptions {
    pub server: Option<String>,
    pub auth: Option<String>,
    pub content_type: Option<String>,
    pub input: Option<Value>,
    pub explicit: Vec<(String, Value)>,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ProjectConfiguration {
    pub version: u32,
    pub defaults: ConfigurationDefaults,
    pub servers: BTreeMap<String, ConfiguredServer>,
    pub auth: BTreeMap<String, ConfiguredAuth>,
    pub risk: BTreeMap<String, kahea_core::RiskClass>,
    pub policy: ConfigurationPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ConfigurationDefaults {
    pub source: Option<String>,
    pub server: Option<String>,
    pub auth: Option<String>,
    pub policy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ConfiguredServer {
    pub url: String,
    pub classification: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ConfiguredAuth {
    pub r#type: String,
    pub token: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub refresh_token: Option<String>,
    pub certificate: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConfigurationPolicy {
    pub denied_hosts: Vec<String>,
    pub allowed_hosts: Vec<String>,
    pub max_request_bytes: u64,
    pub require_production_write_approval: bool,
    pub sensitive_headers: Vec<String>,
    pub redact_response_json_pointers: Vec<String>,
    #[serde(skip_serializing_if = "WebSocketPolicy::is_default")]
    pub websocket: WebSocketPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct WebSocketPolicy {
    pub allowed_origins: Vec<String>,
    pub allowed_subprotocols: Vec<String>,
    pub max_limits: WebSocketPolicyLimits,
}

impl WebSocketPolicy {
    fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebSocketPolicyLimits {
    pub connect_timeout_ms: u64,
    pub action_timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub close_timeout_ms: u64,
    pub total_timeout_ms: u64,
    pub max_frame_bytes: u64,
    pub max_message_bytes: u64,
    pub max_inbound_frames: u64,
    pub max_outbound_frames: u64,
    pub max_inbound_messages: u64,
    pub max_outbound_messages: u64,
    pub max_inbound_bytes: u64,
    pub max_outbound_bytes: u64,
}

impl Default for WebSocketPolicyLimits {
    fn default() -> Self {
        Self {
            connect_timeout_ms: 30_000,
            action_timeout_ms: 30_000,
            idle_timeout_ms: 30_000,
            close_timeout_ms: 10_000,
            total_timeout_ms: 120_000,
            max_frame_bytes: 4 * 1024 * 1024,
            max_message_bytes: 16 * 1024 * 1024,
            max_inbound_frames: 4_096,
            max_outbound_frames: 4_096,
            max_inbound_messages: 2_048,
            max_outbound_messages: 2_048,
            max_inbound_bytes: 64 * 1024 * 1024,
            max_outbound_bytes: 64 * 1024 * 1024,
        }
    }
}

impl Default for ConfigurationPolicy {
    fn default() -> Self {
        Self {
            denied_hosts: Vec::new(),
            allowed_hosts: Vec::new(),
            max_request_bytes: 16 * 1024 * 1024,
            require_production_write_approval: true,
            sensitive_headers: Vec::new(),
            redact_response_json_pointers: Vec::new(),
            websocket: WebSocketPolicy::default(),
        }
    }
}

impl ProjectConfiguration {
    pub fn load(path: &Path) -> Result<Self, PlanError> {
        let bytes = fs::read(path)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|error| PlanError::Configuration(error.to_string()))?;
        let mut configuration: Self =
            toml::from_str(text).map_err(|error| PlanError::Configuration(error.to_string()))?;
        if configuration.version != 1 {
            return Err(PlanError::Configuration(format!(
                "unsupported configuration version {}; expected 1",
                configuration.version
            )));
        }
        for (name, auth) in &configuration.auth {
            for reference in [
                auth.token.as_deref(),
                auth.username.as_deref(),
                auth.password.as_deref(),
                auth.client_id.as_deref(),
                auth.client_secret.as_deref(),
                auth.refresh_token.as_deref(),
                auth.certificate.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                if !reference.starts_with("secret://") {
                    return Err(PlanError::Configuration(format!(
                        "auth profile {name:?} contains an inline credential; use secret:// references"
                    )));
                }
            }
        }
        if let Some(policy_path) = &configuration.defaults.policy {
            let policy_path = path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(policy_path);
            let policy_text = fs::read_to_string(&policy_path)?;
            configuration.policy = toml::from_str(&policy_text)
                .or_else(|_| {
                    #[derive(Deserialize)]
                    struct PolicyWrapper {
                        policy: ConfigurationPolicy,
                    }
                    toml::from_str::<PolicyWrapper>(&policy_text).map(|wrapper| wrapper.policy)
                })
                .map_err(|error| {
                    PlanError::Configuration(format!(
                        "invalid policy file {}: {error}",
                        policy_path.display()
                    ))
                })?;
        }
        Ok(configuration)
    }

    pub fn config_fingerprint(&self) -> Result<String, PlanError> {
        if self.version == 0 {
            Ok(default_config_fingerprint())
        } else {
            Ok(digest(&serde_json::to_vec(&self_as_value(self)?)?))
        }
    }

    pub fn policy_fingerprint(&self) -> Result<String, PlanError> {
        let value = serde_json::json!({
            "builtin": "kahea/builtin-policy/v1",
            "policy": {
                "denied_hosts": self.policy.denied_hosts,
                "allowed_hosts": self.policy.allowed_hosts,
                "max_request_bytes": self.policy.max_request_bytes,
                "require_production_write_approval": self.policy.require_production_write_approval,
                "sensitive_headers": self.policy.sensitive_headers,
                "redact_response_json_pointers": self.policy.redact_response_json_pointers,
            }
        });
        Ok(digest(&serde_json::to_vec(&value)?))
    }

    pub fn websocket_policy_fingerprint(&self) -> Result<String, PlanError> {
        let value = serde_json::json!({
            "builtin": "kahea/builtin-websocket-policy/v1",
            "policy": {
                "denied_hosts": self.policy.denied_hosts,
                "allowed_hosts": self.policy.allowed_hosts,
                "require_production_write_approval": self.policy.require_production_write_approval,
                "sensitive_headers": self.policy.sensitive_headers,
                "redact_response_json_pointers": self.policy.redact_response_json_pointers,
                "websocket": self.policy.websocket,
            }
        });
        Ok(digest(&serde_json::to_vec(&value)?))
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WebSocketSessionDocument {
    kind: String,
    version: u32,
    operation_id: String,
    url: String,
    #[serde(default)]
    risk: Option<kahea_core::RiskClass>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    auth: Option<String>,
    #[serde(default)]
    origin: Option<String>,
    #[serde(default)]
    subprotocols: Vec<String>,
    limits: WebSocketLimits,
    actions: Vec<WebSocketAction>,
}

fn self_as_value(configuration: &ProjectConfiguration) -> Result<Value, PlanError> {
    let text = toml::to_string(configuration)
        .map_err(|error| PlanError::Configuration(error.to_string()))?;
    toml::from_str::<toml::Value>(&text)
        .map_err(|error| PlanError::Configuration(error.to_string()))
        .and_then(|value| serde_json::to_value(value).map_err(PlanError::Serialization))
}

#[derive(Debug, Default)]
struct Inputs {
    path: BTreeMap<String, Value>,
    query: BTreeMap<String, Value>,
    header: BTreeMap<String, Value>,
    cookie: BTreeMap<String, Value>,
    body: Option<Value>,
    declared: BTreeSet<String>,
    used: BTreeSet<String>,
}

pub fn parse_explicit_field(value: &str) -> Result<(String, Value), PlanError> {
    let (key, raw) = value
        .split_once('=')
        .ok_or_else(|| PlanError::InvalidExplicitField(value.into()))?;
    if !key.contains('.') || key.ends_with('.') {
        return Err(PlanError::InvalidExplicitField(value.into()));
    }
    let parsed = serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.into()));
    Ok((key.into(), parsed))
}

pub fn build_plan(
    source: &OpenApiSource,
    operation: &OperationDefinition,
    options: PlanOptions,
) -> Result<RequestPlan, PlanError> {
    build_plan_with_configuration(source, operation, options, &ProjectConfiguration::default())
}

pub fn build_websocket_plan(path: &Path, bytes: &[u8]) -> Result<WebSocketPlan, PlanError> {
    build_websocket_plan_with_configuration(path, bytes, &ProjectConfiguration::default())
}

pub fn build_websocket_plan_with_configuration(
    path: &Path,
    bytes: &[u8],
    configuration: &ProjectConfiguration,
) -> Result<WebSocketPlan, PlanError> {
    let document = parse_data_document(path, bytes)
        .map_err(|error| PlanError::InvalidWebSocketSource(error.to_string()))?;
    let mut source: WebSocketSessionDocument = serde_json::from_value(document)
        .map_err(|error| PlanError::InvalidWebSocketSource(error.to_string()))?;
    if source.kind != "websocket-session" || source.version != 1 {
        return Err(PlanError::InvalidWebSocketSource(
            "kind must be websocket-session and version must be 1".into(),
        ));
    }
    if source.operation_id.is_empty()
        || source.operation_id.len() > 256
        || source.operation_id.contains(char::is_control)
    {
        return Err(PlanError::InvalidWebSocketSource(
            "operationId must be a non-empty bounded string without control characters".into(),
        ));
    }

    let target = websocket_target(&source.url)?;
    let host = target
        .host_str()
        .ok_or_else(|| PlanError::InvalidWebSocketSource("target URL has no host".into()))?;
    let port = target.port_or_known_default().ok_or_else(|| {
        PlanError::InvalidWebSocketSource("target URL has no effective port".into())
    })?;
    enforce_host_policy(host, configuration)?;

    let origin = source.origin.as_deref().map(normalize_origin).transpose()?;
    enforce_websocket_origin_policy(origin.as_deref(), configuration)?;
    enforce_websocket_subprotocol_policy(&source.subprotocols, configuration)?;
    let headers = websocket_headers(source.headers, configuration)?;
    let auth_profile = source.auth.or_else(|| configuration.defaults.auth.clone());
    let (auth, secret_refs) =
        bind_websocket_configured_auth(auth_profile.as_deref(), configuration)?;
    let limits = effective_websocket_limits(source.limits, configuration)?;
    tighten_websocket_action_timeouts(&mut source.actions, limits.action_timeout_ms);

    let risk_key = format!("WEBSOCKET {}", source.operation_id);
    let sends_data = source.actions.iter().any(|action| {
        matches!(
            action,
            WebSocketAction::SendText { .. } | WebSocketAction::SendBinary { .. }
        )
    });
    let policy_risk = configuration
        .risk
        .get(&risk_key)
        .or_else(|| configuration.risk.get(&source.operation_id))
        .copied();
    let risk = policy_risk.unwrap_or(match source.risk {
        Some(kahea_core::RiskClass::Read | kahea_core::RiskClass::Unknown) if sends_data => {
            kahea_core::RiskClass::Write
        }
        Some(risk) => risk,
        None if sends_data => kahea_core::RiskClass::Write,
        None => kahea_core::RiskClass::Unknown,
    });

    let mut grants = vec![format!("net:{host}:{port}"), "websocket:connect".into()];
    if target.scheme() == "ws" {
        grants.push("net-insecure-websocket".into());
    }
    let literal_host = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(address) = literal_host.parse::<IpAddr>()
        && is_unsafe_address(address)
    {
        grants.push(match address {
            IpAddr::V4(address) => format!("net-cidr:{address}/32"),
            IpAddr::V6(address) => format!("net-cidr:{address}/128"),
        });
    }
    if risk == kahea_core::RiskClass::Destructive {
        grants.push("approve:destructive".into());
    }
    if configuration.policy.require_production_write_approval
        && matches!(
            risk,
            kahea_core::RiskClass::Write | kahea_core::RiskClass::Destructive
        )
        && configuration
            .servers
            .values()
            .any(|server| configured_server_matches_target(server, &target))
    {
        grants.push("approve:production-write".into());
    }
    if let Some(auth) = &auth {
        grants.push(format!("secret:{}", auth.profile));
        if auth.placement == "tls-client-certificate" {
            grants.push(format!("tls-client-cert:{}", auth.profile));
        }
    }
    grants.sort();
    grants.dedup();

    validate_redaction_policy(configuration)?;
    let mut sensitive_headers = vec![
        "authorization".into(),
        "cookie".into(),
        "proxy-authorization".into(),
        "set-cookie".into(),
    ];
    sensitive_headers.extend(configuration.policy.sensitive_headers.iter().cloned());

    let mut handshake_checks = vec!["extensions:none".into(), "status:101".into()];
    match source.subprotocols.as_slice() {
        [] => {}
        [protocol] => handshake_checks.push(format!("subprotocol:{protocol}")),
        protocols => handshake_checks.push(format!("subprotocol:any({})", protocols.join(","))),
    }

    let source_fingerprint = digest(bytes);
    WebSocketPlan {
        protocol: PROTOCOL.into(),
        kind: "websocket-plan".into(),
        version: VERSION.into(),
        config_fingerprint: configuration.config_fingerprint()?,
        policy_fingerprint: configuration.websocket_policy_fingerprint()?,
        source_fingerprints: vec![source_fingerprint.clone()],
        id: String::new(),
        operation: short_handle(
            "op",
            &[
                source_fingerprint.as_bytes(),
                source.operation_id.as_bytes(),
            ],
        ),
        target: target.to_string(),
        risk,
        required_grants: grants,
        secret_refs,
        headers,
        auth,
        origin,
        subprotocols: source.subprotocols,
        handshake_checks,
        limits,
        actions: source.actions,
        sensitive_headers,
        redact_response_json_pointers: configuration.policy.redact_response_json_pointers.clone(),
        valid: true,
        fingerprint: String::new(),
        exit: 0,
    }
    .seal()
    .map_err(|error| PlanError::InvalidWebSocketSource(error.to_string()))
}

pub fn build_plan_with_configuration(
    source: &OpenApiSource,
    operation: &OperationDefinition,
    mut options: PlanOptions,
    configuration: &ProjectConfiguration,
) -> Result<RequestPlan, PlanError> {
    if let Some(absence) = [
        source.document.get("x-kahea-absent"),
        operation.operation.get("x-kahea-absent"),
    ]
    .into_iter()
    .filter_map(|value| value.and_then(Value::as_array))
    .flatten()
    .find(|absence| {
        absence
            .get("blocking")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }) {
        return Err(PlanError::BlockingAbsence {
            location: absence
                .get("location")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .into(),
            reason: absence
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("unsupported imported behavior")
                .into(),
        });
    }
    let mut inputs = Inputs::from_options(options.input.clone(), &options.explicit)?;
    if options.server.is_none() {
        options.server = configuration.defaults.server.clone();
    }
    if options.auth.is_none() {
        options.auth = configuration.defaults.auth.clone();
    }
    let server = select_server(source, operation, options.server.as_deref(), configuration)?;
    let mut target_path = operation.path.clone();
    let mut query_pairs = Vec::new();
    let mut headers = Vec::new();
    let mut cookies = Vec::new();
    let mut derivations = Vec::new();

    for parameter in parameters(source, operation)? {
        let name = string_field(&parameter, "name").unwrap_or_default();
        let location = string_field(&parameter, "in").unwrap_or_default();
        if name.is_empty() || location.is_empty() {
            continue;
        }
        let key = format!("{location}.{name}");
        let value = inputs.take(&location, &name).or_else(|| {
            parameter
                .get("schema")
                .and_then(|schema| schema.get("default"))
                .cloned()
                .map(|value| (value, "schema-default".to_string()))
        });
        let required = parameter
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || location == "path";
        let Some((value, provenance)) = value else {
            if required {
                return Err(PlanError::MissingParameter { location, name });
            }
            continue;
        };
        if let Some(schema) = parameter.get("schema") {
            validate_value(source, schema, &value, &key)?;
        }
        let wire_values = wire_values(&value, &parameter)?;
        match location.as_str() {
            "path" => {
                let wire = wire_values.first().cloned().unwrap_or_default();
                let encoded = utf8_percent_encode(&wire, PATH_SEGMENT).to_string();
                target_path = target_path.replace(&format!("{{{name}}}"), &encoded);
                derivations.push(derivation(
                    key,
                    value,
                    provenance,
                    Some(encoded),
                    "path-segment",
                ));
            }
            "query" => {
                for wire in &wire_values {
                    query_pairs.push((name.clone(), wire.clone()));
                }
                derivations.push(derivation(
                    key,
                    value,
                    provenance,
                    Some(wire_values.join(",")),
                    "query-form",
                ));
            }
            "header" => {
                let wire = wire_values.join(",");
                headers.push(PlannedHeader {
                    name: name.clone(),
                    value: wire.clone(),
                });
                derivations.push(derivation(key, value, provenance, Some(wire), "header"));
            }
            "cookie" => {
                let wire = wire_values.join(",");
                cookies.push((name.clone(), wire.clone()));
                derivations.push(derivation(key, value, provenance, Some(wire), "cookie"));
            }
            _ => {
                return Err(PlanError::InvalidInput {
                    field: key,
                    reason: format!("unsupported parameter location {location:?}"),
                });
            }
        }
    }

    if target_path.contains('{') {
        return Err(PlanError::InvalidInput {
            field: "target.path".into(),
            reason: "one or more path variables remain unresolved".into(),
        });
    }

    let mut target = build_target(&server, &target_path)?;
    if !query_pairs.is_empty() {
        let mut pairs = target.query_pairs_mut();
        for (name, value) in &query_pairs {
            pairs.append_pair(name, value);
        }
    }

    if !cookies.is_empty() {
        cookies.sort();
        headers.push(PlannedHeader {
            name: "Cookie".into(),
            value: cookies
                .into_iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; "),
        });
    }

    let body = bind_body(
        source,
        operation,
        &mut inputs,
        &options,
        &mut headers,
        &mut derivations,
    )?;
    let (auth, secret_refs) = bind_auth(source, operation, options.auth.as_deref())?;
    inputs.reject_unused()?;

    headers.sort_by(|a, b| {
        a.name
            .to_ascii_lowercase()
            .cmp(&b.name.to_ascii_lowercase())
    });
    let host = target
        .host_str()
        .ok_or_else(|| PlanError::InvalidServer("target has no host".into()))?;
    let port = target
        .port_or_known_default()
        .ok_or_else(|| PlanError::InvalidServer("target has no port".into()))?;
    if configuration
        .policy
        .denied_hosts
        .iter()
        .any(|denied| denied.eq_ignore_ascii_case(host))
    {
        return Err(PlanError::PolicyDenied(format!(
            "host {host:?} is explicitly denied"
        )));
    }
    if !configuration.policy.allowed_hosts.is_empty()
        && !configuration
            .policy
            .allowed_hosts
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(host))
    {
        return Err(PlanError::PolicyDenied(format!(
            "host {host:?} is outside the configured allowlist"
        )));
    }
    let risk_key = format!("{} {}", operation.method, operation.path);
    let risk = configuration
        .risk
        .get(&risk_key)
        .copied()
        .unwrap_or(operation.risk);
    let mut grants = vec![
        format!("net:{host}:{port}"),
        format!("http:{}", operation.method),
    ];
    if target.scheme() == "http" {
        grants.push("net-insecure-http".into());
    }
    if let Ok(address) = host.parse::<IpAddr>()
        && is_unsafe_address(address)
    {
        grants.push(match address {
            IpAddr::V4(address) => format!("net-cidr:{address}/32"),
            IpAddr::V6(address) => format!("net-cidr:{address}/128"),
        });
    }
    if risk == kahea_core::RiskClass::Destructive {
        grants.push("approve:destructive".into());
    }
    let production = configuration.servers.values().any(|server| {
        server.url.trim_end_matches('/') == server_origin(&target)
            && server.classification.as_deref() == Some("production")
    });
    if production
        && configuration.policy.require_production_write_approval
        && matches!(
            risk,
            kahea_core::RiskClass::Write | kahea_core::RiskClass::Destructive
        )
    {
        grants.push("approve:production-write".into());
    }
    if let Some(auth) = &auth {
        grants.push(format!("secret:{}", auth.profile));
        if auth.placement == "tls-client-certificate" {
            grants.push(format!("tls-client-cert:{}", auth.profile));
        }
        if let Some(token_url) = &auth.token_url {
            let token_url = Url::parse(token_url)
                .map_err(|error| PlanError::InvalidServer(format!("OAuth token URL: {error}")))?;
            let host = token_url
                .host_str()
                .ok_or_else(|| PlanError::InvalidServer("OAuth token URL has no host".into()))?;
            let port = token_url.port_or_known_default().ok_or_else(|| {
                PlanError::InvalidServer("OAuth token URL has no known port".into())
            })?;
            grants.push(format!("net:{host}:{port}"));
            grants.push("http:POST".into());
            if token_url.scheme() == "http" {
                grants.push("net-insecure-http".into());
            }
        }
    }
    grants.sort();

    let checks = if options.checks.is_empty() {
        default_checks(operation)
    } else {
        options.checks
    };
    if body
        .as_ref()
        .is_some_and(|body| body.bytes > configuration.policy.max_request_bytes)
    {
        return Err(PlanError::PolicyDenied(format!(
            "request body exceeds the {} byte policy limit",
            configuration.policy.max_request_bytes
        )));
    }
    let policy_fingerprint = configuration.policy_fingerprint()?;
    for pointer in &configuration.policy.redact_response_json_pointers {
        if !pointer.starts_with('/') || pointer.len() > 2_048 {
            return Err(PlanError::Configuration(format!(
                "response redaction pointer {pointer:?} must be a bounded JSON Pointer"
            )));
        }
    }
    for header in &configuration.policy.sensitive_headers {
        if header.is_empty() || header.contains(['\r', '\n']) {
            return Err(PlanError::Configuration(
                "sensitive header names must be non-empty and contain no line breaks".into(),
            ));
        }
    }
    RequestPlan {
        protocol: PROTOCOL.into(),
        kind: "plan".into(),
        version: VERSION.into(),
        config_fingerprint: configuration.config_fingerprint()?,
        policy_fingerprint,
        source_fingerprints: vec![source.source_fingerprint.clone()],
        id: String::new(),
        operation: operation.handle.clone(),
        target: target.to_string(),
        method: operation.method.clone(),
        risk,
        required_grants: grants,
        secret_refs,
        headers,
        auth,
        body,
        checks,
        response_contract: serde_json::json!({
            "responses": operation
                .operation
                .get("responses")
                .cloned()
                .unwrap_or_else(|| Value::Object(Map::new())),
            "components": source
                .document
                .get("components")
                .cloned()
                .unwrap_or_else(|| Value::Object(Map::new())),
        }),
        sensitive_headers: configuration.policy.sensitive_headers.clone(),
        redact_response_json_pointers: configuration.policy.redact_response_json_pointers.clone(),
        derivations,
        valid: true,
        fingerprint: String::new(),
        exit: 0,
    }
    .seal()
    .map_err(PlanError::Serialization)
}

impl Inputs {
    fn from_options(input: Option<Value>, explicit: &[(String, Value)]) -> Result<Self, PlanError> {
        let mut result = Self::default();
        if let Some(input) = input {
            result.apply_document(input)?;
        }
        for (key, value) in explicit {
            result.insert(key, value.clone(), true)?;
        }
        Ok(result)
    }

    fn apply_document(&mut self, input: Value) -> Result<(), PlanError> {
        let Some(object) = input.as_object() else {
            self.body = Some(input);
            self.declared.insert("body".into());
            return Ok(());
        };
        let structured = object.keys().any(|key| {
            matches!(
                key.as_str(),
                "path" | "query" | "header" | "headers" | "cookie" | "cookies" | "body"
            )
        });
        if !structured {
            self.body = Some(input);
            self.declared.insert("body".into());
            return Ok(());
        }
        for (section, value) in object {
            match section.as_str() {
                "path" | "query" | "header" | "headers" | "cookie" | "cookies" => {
                    let canonical = match section.as_str() {
                        "headers" => "header",
                        "cookies" => "cookie",
                        other => other,
                    };
                    let values = value.as_object().ok_or_else(|| PlanError::InvalidInput {
                        field: section.clone(),
                        reason: "section must be an object".into(),
                    })?;
                    for (name, value) in values {
                        self.insert(&format!("{canonical}.{name}"), value.clone(), false)?;
                    }
                }
                "body" => {
                    self.body = Some(value.clone());
                    self.declared.insert("body".into());
                }
                _ => return Err(PlanError::UnknownInput(section.clone())),
            }
        }
        Ok(())
    }

    fn insert(
        &mut self,
        key: &str,
        value: Value,
        override_existing: bool,
    ) -> Result<(), PlanError> {
        let (location, name) = key
            .split_once('.')
            .ok_or_else(|| PlanError::InvalidExplicitField(key.into()))?;
        let map = match location {
            "path" => &mut self.path,
            "query" => &mut self.query,
            "header" | "headers" => &mut self.header,
            "cookie" | "cookies" => &mut self.cookie,
            "body" => {
                insert_body_value(&mut self.body, name, value)?;
                self.declared.insert(format!("body.{name}"));
                return Ok(());
            }
            _ => return Err(PlanError::InvalidExplicitField(key.into())),
        };
        if override_existing || !map.contains_key(name) {
            map.insert(name.into(), value);
        }
        self.declared.insert(format!("{location}.{name}"));
        Ok(())
    }

    fn take(&mut self, location: &str, name: &str) -> Option<(Value, String)> {
        let map = match location {
            "path" => &self.path,
            "query" => &self.query,
            "header" => &self.header,
            "cookie" => &self.cookie,
            _ => return None,
        };
        map.get(name).cloned().map(|value| {
            self.used.insert(format!("{location}.{name}"));
            (value, "explicit-input".into())
        })
    }

    fn reject_unused(&self) -> Result<(), PlanError> {
        if let Some(key) = self.declared.iter().find(|key| {
            !self.used.contains(*key) && key.as_str() != "body" && !key.starts_with("body.")
        }) {
            return Err(PlanError::UnknownInput(key.clone()));
        }
        Ok(())
    }
}

fn insert_body_value(body: &mut Option<Value>, path: &str, value: Value) -> Result<(), PlanError> {
    let root = body.get_or_insert_with(|| Value::Object(Map::new()));
    let mut current = root;
    let segments: Vec<_> = path.split('.').collect();
    for (index, segment) in segments.iter().enumerate() {
        if index + 1 == segments.len() {
            let object = current
                .as_object_mut()
                .ok_or_else(|| PlanError::InvalidInput {
                    field: format!("body.{path}"),
                    reason: "parent is not an object".into(),
                })?;
            object.insert((*segment).into(), value);
            return Ok(());
        }
        let object = current
            .as_object_mut()
            .ok_or_else(|| PlanError::InvalidInput {
                field: format!("body.{path}"),
                reason: "parent is not an object".into(),
            })?;
        current = object
            .entry((*segment).to_string())
            .or_insert_with(|| Value::Object(Map::new()));
    }
    Ok(())
}

fn parameters(
    source: &OpenApiSource,
    operation: &OperationDefinition,
) -> Result<Vec<Map<String, Value>>, PlanError> {
    let mut parameters: BTreeMap<(String, String), Map<String, Value>> = BTreeMap::new();
    for array in [
        operation
            .path_item
            .get("parameters")
            .and_then(Value::as_array),
        operation
            .operation
            .get("parameters")
            .and_then(Value::as_array),
    ]
    .into_iter()
    .flatten()
    {
        for parameter in array {
            let parameter = resolve_object(source, parameter, "parameter")?;
            let name = string_field(&parameter, "name").unwrap_or_default();
            let location = string_field(&parameter, "in").unwrap_or_default();
            parameters.insert((location, name), parameter);
        }
    }
    Ok(parameters.into_values().collect())
}

fn bind_body(
    source: &OpenApiSource,
    operation: &OperationDefinition,
    inputs: &mut Inputs,
    options: &PlanOptions,
    headers: &mut Vec<PlannedHeader>,
    derivations: &mut Vec<FieldDerivation>,
) -> Result<Option<PlannedBody>, PlanError> {
    let Some(request_body_value) = operation.operation.get("requestBody") else {
        if inputs.body.is_some() {
            return Err(PlanError::UnexpectedBody);
        }
        return Ok(None);
    };
    let request_body = resolve_object(source, request_body_value, "requestBody")?;
    let required = request_body
        .get("required")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let (body, provenance) = if let Some(body) = inputs.body.take() {
        inputs.used.insert("body".into());
        for key in inputs
            .declared
            .iter()
            .filter(|key| key.starts_with("body."))
        {
            inputs.used.insert(key.clone());
        }
        (body, "explicit-input")
    } else if let Some(body) = operation.operation.get("x-kahea-captured-body") {
        (body.clone(), "captured-source")
    } else {
        if required {
            return Err(PlanError::MissingBody);
        }
        return Ok(None);
    };
    let content = request_body
        .get("content")
        .and_then(Value::as_object)
        .ok_or_else(|| PlanError::InvalidInput {
            field: "requestBody.content".into(),
            reason: "content map is missing".into(),
        })?;
    let media_type = select_content_type(content, options.content_type.as_deref())?;
    let media = content
        .get(&media_type)
        .and_then(Value::as_object)
        .ok_or_else(|| PlanError::UnknownContentType(media_type.clone()))?;
    if let Some(schema) = media.get("schema") {
        validate_value(source, schema, &body, "body")?;
    }
    let (wire_media_type, bytes, encoding, inline, transformation) =
        serialize_body(&media_type, &body)?;
    headers.push(PlannedHeader {
        name: "Content-Type".into(),
        value: wire_media_type.clone(),
    });
    derivations.push(derivation(
        "body".into(),
        body,
        provenance.into(),
        Some(inline.clone()),
        transformation,
    ));
    Ok(Some(PlannedBody {
        media_type: wire_media_type,
        bytes: bytes.len() as u64,
        blake3: digest(&bytes),
        encoding,
        inline,
    }))
}

fn serialize_body(
    media_type: &str,
    body: &Value,
) -> Result<(String, Vec<u8>, String, String, &'static str), PlanError> {
    if media_type == "application/json" || media_type.ends_with("+json") {
        let bytes = serde_json::to_vec(body)?;
        let inline = String::from_utf8(bytes.clone()).expect("JSON is UTF-8");
        return Ok((
            media_type.into(),
            bytes,
            "utf-8".into(),
            inline,
            "canonical-json",
        ));
    }
    if media_type.starts_with("text/") || media_type.contains("xml") {
        let text = body.as_str().ok_or_else(|| PlanError::InvalidInput {
            field: "body".into(),
            reason: format!("{media_type} body must be a string"),
        })?;
        return Ok((
            media_type.into(),
            text.as_bytes().to_vec(),
            "utf-8".into(),
            text.into(),
            "text-utf8",
        ));
    }
    if media_type == "application/x-www-form-urlencoded" {
        if let Some(captured) = body.as_str() {
            return Ok((
                media_type.into(),
                captured.as_bytes().to_vec(),
                "utf-8".into(),
                captured.into(),
                "captured-form",
            ));
        }
        let object = body.as_object().ok_or_else(|| PlanError::InvalidInput {
            field: "body".into(),
            reason: "form-urlencoded body must be an object".into(),
        })?;
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (name, value) in object {
            match value {
                Value::Array(values) => {
                    for value in values {
                        serializer.append_pair(name, &scalar_wire(value)?);
                    }
                }
                value => {
                    serializer.append_pair(name, &scalar_wire(value)?);
                }
            }
        }
        let encoded = serializer.finish();
        return Ok((
            media_type.into(),
            encoded.as_bytes().to_vec(),
            "utf-8".into(),
            encoded,
            "form-urlencoded",
        ));
    }
    if media_type == "multipart/form-data" {
        let object = body.as_object().ok_or_else(|| PlanError::InvalidInput {
            field: "body".into(),
            reason: "multipart body must be an object of scalar fields".into(),
        })?;
        let logical = serde_json::to_vec(body)?;
        let boundary = format!("kahea-{}", &digest(&logical)[3..19]);
        let mut bytes = Vec::new();
        for (name, value) in object {
            reject_multipart_token(name, "field name")?;
            bytes.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            if let Some(file) = value
                .as_object()
                .filter(|value| value.contains_key("$file"))
            {
                let path = file.get("$file").and_then(Value::as_str).ok_or_else(|| {
                    PlanError::InvalidInput {
                        field: format!("body.{name}.$file"),
                        reason: "file path must be a string".into(),
                    }
                })?;
                let filename = file
                    .get("filename")
                    .and_then(Value::as_str)
                    .or_else(|| Path::new(path).file_name().and_then(|name| name.to_str()))
                    .unwrap_or("upload.bin");
                let content_type = file
                    .get("content_type")
                    .and_then(Value::as_str)
                    .unwrap_or("application/octet-stream");
                reject_multipart_token(filename, "filename")?;
                reject_multipart_token(content_type, "file content type")?;
                let file_bytes = fs::read(path).map_err(|error| PlanError::InvalidInput {
                    field: format!("body.{name}.$file"),
                    reason: format!("could not read upload file {path:?}: {error}"),
                })?;
                bytes.extend_from_slice(
                    format!(
                        "Content-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\nContent-Type: {content_type}\r\n\r\n"
                    )
                    .as_bytes(),
                );
                bytes.extend_from_slice(&file_bytes);
            } else {
                let value = scalar_wire(value)?;
                bytes.extend_from_slice(
                    format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
                );
                bytes.extend_from_slice(value.as_bytes());
            }
            bytes.extend_from_slice(b"\r\n");
        }
        bytes.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        let inline = base64::engine::general_purpose::STANDARD.encode(&bytes);
        return Ok((
            format!("multipart/form-data; boundary={boundary}"),
            bytes,
            "base64".into(),
            inline,
            "multipart-deterministic",
        ));
    }
    let encoded = body.as_str().ok_or_else(|| PlanError::InvalidInput {
        field: "body".into(),
        reason: format!("binary {media_type} body must be a base64 string"),
    })?;
    let encoded = encoded.strip_prefix("base64:").unwrap_or(encoded);
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| PlanError::InvalidInput {
            field: "body".into(),
            reason: format!("invalid base64 body: {error}"),
        })?;
    Ok((
        media_type.into(),
        bytes,
        "base64".into(),
        encoded.into(),
        "base64-decode",
    ))
}

fn reject_multipart_token(value: &str, field: &str) -> Result<(), PlanError> {
    if value.contains(['\r', '\n', '"']) {
        return Err(PlanError::InvalidInput {
            field: field.into(),
            reason: "multipart metadata contains a forbidden character".into(),
        });
    }
    Ok(())
}

fn select_content_type(
    content: &Map<String, Value>,
    requested: Option<&str>,
) -> Result<String, PlanError> {
    if let Some(requested) = requested {
        return content
            .contains_key(requested)
            .then(|| requested.to_string())
            .ok_or_else(|| PlanError::UnknownContentType(requested.into()));
    }
    if content.contains_key("application/json") {
        return Ok("application/json".into());
    }
    if content.len() == 1 {
        return Ok(content.keys().next().expect("length checked").clone());
    }
    Err(PlanError::InvalidInput {
        field: "requestBody.content".into(),
        reason: "multiple content types are declared; provide --content-type".into(),
    })
}

fn bind_auth(
    source: &OpenApiSource,
    operation: &OperationDefinition,
    requested: Option<&str>,
) -> Result<(Option<PlannedAuth>, Vec<String>), PlanError> {
    let security = operation
        .operation
        .get("security")
        .or_else(|| source.document.get("security"))
        .and_then(Value::as_array);
    let required_schemes: Vec<String> = security
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .flat_map(|requirement| requirement.keys().cloned())
        .collect();
    if required_schemes.is_empty() && requested.is_none() {
        return Ok((None, Vec::new()));
    }
    let requested = requested.ok_or(PlanError::MissingAuth)?;
    let (scheme, profile) = requested
        .split_once('=')
        .map(|(scheme, profile)| (scheme.to_string(), profile.to_string()))
        .unwrap_or_else(|| {
            (
                required_schemes
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "bearer".into()),
                requested.to_string(),
            )
        });
    if !required_schemes.is_empty() && !required_schemes.contains(&scheme) {
        return Err(PlanError::UnknownSecurityScheme(scheme));
    }
    let scheme_value = source
        .document
        .pointer(&format!(
            "/components/securitySchemes/{}",
            escape_pointer(&scheme)
        ))
        .ok_or_else(|| PlanError::UnknownSecurityScheme(scheme.clone()))?;
    let scheme_object = resolve_object(source, scheme_value, "securityScheme")?;
    let kind = string_field(&scheme_object, "type").unwrap_or_default();
    let (placement, token_url) = match kind.as_str() {
        "apiKey" => (
            format!(
                "{}:{}",
                string_field(&scheme_object, "in").unwrap_or_default(),
                string_field(&scheme_object, "name").unwrap_or_default()
            ),
            None,
        ),
        "http" => (
            format!(
                "header:Authorization:{}",
                string_field(&scheme_object, "scheme").unwrap_or_default()
            ),
            None,
        ),
        "oauth2" => {
            let flows = scheme_object
                .get("flows")
                .and_then(Value::as_object)
                .ok_or_else(|| PlanError::UnsupportedSecurityScheme(scheme.clone()))?;
            if let Some(flow) = flows.get("clientCredentials").and_then(Value::as_object) {
                let token_url = string_field(flow, "tokenUrl")
                    .ok_or_else(|| PlanError::UnsupportedSecurityScheme(scheme.clone()))?;
                ("oauth2-client-credentials".into(), Some(token_url))
            } else if let Some(flow) = flows.get("authorizationCode").and_then(Value::as_object) {
                let token_url = string_field(flow, "tokenUrl")
                    .ok_or_else(|| PlanError::UnsupportedSecurityScheme(scheme.clone()))?;
                ("oauth2-refresh-token".into(), Some(token_url))
            } else {
                return Err(PlanError::UnsupportedSecurityScheme(scheme));
            }
        }
        "openIdConnect" => ("header:Authorization:bearer".into(), None),
        "mutualTLS" => ("tls-client-certificate".into(), None),
        _ => return Err(PlanError::UnsupportedSecurityScheme(scheme)),
    };
    let scopes = security
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .find_map(|requirement| requirement.get(&scheme))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();
    Ok((
        Some(PlannedAuth {
            scheme,
            kind,
            profile: profile.clone(),
            placement,
            token_url,
            scopes,
        }),
        vec![format!("secret://{profile}")],
    ))
}

fn resolve_object(
    source: &OpenApiSource,
    value: &Value,
    field: &str,
) -> Result<Map<String, Value>, PlanError> {
    let value = if let Some(reference) = value.get("$ref").and_then(Value::as_str) {
        resolve_ref(source, reference).ok_or_else(|| PlanError::InvalidInput {
            field: field.into(),
            reason: format!("unresolved reference {reference:?}"),
        })?
    } else {
        value
    };
    value
        .as_object()
        .cloned()
        .ok_or_else(|| PlanError::InvalidInput {
            field: field.into(),
            reason: "expected an object".into(),
        })
}

fn validate_value(
    source: &OpenApiSource,
    schema: &Value,
    value: &Value,
    field: &str,
) -> Result<(), PlanError> {
    let schema = if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        resolve_ref(source, reference).ok_or_else(|| PlanError::InvalidInput {
            field: field.into(),
            reason: format!("unresolved schema reference {reference:?}"),
        })?
    } else {
        schema
    };
    if schema.get("type").and_then(Value::as_str) == Some("string")
        && schema.get("format").and_then(Value::as_str) == Some("binary")
        && let Some(file) = value.as_object()
        && file.contains_key("$file")
    {
        for key in file.keys() {
            if !matches!(key.as_str(), "$file" | "filename" | "content_type") {
                return Err(PlanError::UnknownInput(format!("{field}.{key}")));
            }
        }
        if !file.get("$file").is_some_and(Value::is_string)
            || file.get("filename").is_some_and(|value| !value.is_string())
            || file
                .get("content_type")
                .is_some_and(|value| !value.is_string())
        {
            return Err(PlanError::InvalidInput {
                field: field.into(),
                reason: "binary upload descriptor fields must be strings".into(),
            });
        }
        return Ok(());
    }
    if value.is_null()
        && schema
            .get("nullable")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        return Ok(());
    }
    if let Some(all_of) = schema.get("allOf").and_then(Value::as_array) {
        for child in all_of {
            validate_value(source, child, value, field)?;
        }
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array)
        && !values.contains(value)
    {
        return Err(PlanError::InvalidInput {
            field: field.into(),
            reason: "value is not in the declared enum".into(),
        });
    }
    let declared_types: Vec<&str> = match schema.get("type") {
        Some(Value::String(value)) => vec![value],
        Some(Value::Array(values)) => values.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    if !declared_types.is_empty() && !declared_types.iter().any(|kind| type_matches(kind, value)) {
        return Err(PlanError::InvalidInput {
            field: field.into(),
            reason: format!(
                "expected {}, received {}",
                declared_types.join(" or "),
                value_kind(value)
            ),
        });
    }
    if let Some(object) = value.as_object() {
        let properties = schema.get("properties").and_then(Value::as_object);
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for name in required.iter().filter_map(Value::as_str) {
                let read_only = properties
                    .and_then(|properties| properties.get(name))
                    .and_then(|property| property.get("readOnly"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !read_only && !object.contains_key(name) {
                    return Err(PlanError::InvalidInput {
                        field: format!("{field}.{name}"),
                        reason: "required field is missing".into(),
                    });
                }
            }
        }
        for (name, child) in object {
            if let Some(child_schema) = properties.and_then(|properties| properties.get(name)) {
                validate_value(source, child_schema, child, &format!("{field}.{name}"))?;
            } else if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
                return Err(PlanError::UnknownInput(format!("{field}.{name}")));
            }
        }
    }
    if let Some(values) = value.as_array()
        && let Some(items) = schema.get("items")
    {
        for (index, item) in values.iter().enumerate() {
            validate_value(source, items, item, &format!("{field}[{index}]"))?;
        }
    }
    Ok(())
}

fn type_matches(kind: &str, value: &Value) -> bool {
    match kind {
        "null" => value.is_null(),
        "boolean" => value.is_boolean(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "number" => value.is_number(),
        "string" => value.is_string(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        _ => true,
    }
}

fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn resolve_ref<'a>(source: &'a OpenApiSource, reference: &str) -> Option<&'a Value> {
    reference
        .strip_prefix('#')
        .and_then(|pointer| source.document.pointer(pointer))
}

fn wire_values(value: &Value, parameter: &Map<String, Value>) -> Result<Vec<String>, PlanError> {
    let explode = parameter
        .get("explode")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    match value {
        Value::Array(values) if explode => values.iter().map(scalar_wire).collect(),
        Value::Array(values) => Ok(vec![
            values
                .iter()
                .map(scalar_wire)
                .collect::<Result<Vec<_>, _>>()?
                .join(","),
        ]),
        _ => Ok(vec![scalar_wire(value)?]),
    }
}

fn scalar_wire(value: &Value) -> Result<String, PlanError> {
    match value {
        Value::Null => Ok(String::new()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Number(value) => Ok(value.to_string()),
        Value::String(value) => Ok(value.clone()),
        _ => Err(PlanError::InvalidInput {
            field: "parameter".into(),
            reason: "object parameters are not yet supported; use a scalar or array".into(),
        }),
    }
}

fn select_server(
    source: &OpenApiSource,
    operation: &OperationDefinition,
    selector: Option<&str>,
    configuration: &ProjectConfiguration,
) -> Result<String, PlanError> {
    if let Some(selector) = selector
        && Url::parse(selector).is_ok()
    {
        return resolve_server_variables(selector, None);
    }
    if let Some(configured) = selector.and_then(|selector| configuration.servers.get(selector)) {
        return resolve_server_variables(&configured.url, None);
    }
    let servers = operation
        .operation
        .get("servers")
        .or_else(|| operation.path_item.get("servers"))
        .or_else(|| source.document.get("servers"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if servers.is_empty() {
        return Err(PlanError::MissingServer);
    }
    let selected = if let Some(selector) = selector {
        servers
            .iter()
            .find(|server| {
                server.get("url").and_then(Value::as_str) == Some(selector)
                    || server.get("description").and_then(Value::as_str) == Some(selector)
            })
            .ok_or_else(|| PlanError::UnknownServer(selector.into()))?
    } else if servers.len() == 1 {
        &servers[0]
    } else {
        return Err(PlanError::AmbiguousServer);
    };
    let url = selected
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| PlanError::InvalidServer("server URL is missing".into()))?;
    resolve_server_variables(url, selected.get("variables").and_then(Value::as_object))
}

fn server_origin(url: &Url) -> String {
    format!(
        "{}://{}{}",
        url.scheme(),
        url.host_str().unwrap_or_default(),
        url.port()
            .map(|port| format!(":{port}"))
            .unwrap_or_default()
    )
}

fn resolve_server_variables(
    template: &str,
    variables: Option<&Map<String, Value>>,
) -> Result<String, PlanError> {
    let mut result = template.to_string();
    for (name, variable) in variables.into_iter().flatten() {
        let default = variable.get("default").ok_or_else(|| {
            PlanError::InvalidServer(format!("server variable {name:?} has no default"))
        })?;
        result = result.replace(&format!("{{{name}}}"), &scalar_wire(default)?);
    }
    if result.contains('{') {
        return Err(PlanError::InvalidServer(
            "unresolved server variable".into(),
        ));
    }
    Ok(result)
}

fn build_target(server: &str, path: &str) -> Result<Url, PlanError> {
    let combined = format!("{}{}", server.trim_end_matches('/'), path);
    let url = Url::parse(&combined).map_err(|error| PlanError::InvalidServer(error.to_string()))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(PlanError::UnsafeTarget(format!(
            "scheme {} is denied",
            url.scheme()
        )));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(PlanError::UnsafeTarget("userinfo in URLs is denied".into()));
    }
    Ok(url)
}

fn websocket_target(value: &str) -> Result<Url, PlanError> {
    if value.len() > 8_192 {
        return Err(PlanError::InvalidWebSocketSource(
            "target URL exceeds 8192 bytes".into(),
        ));
    }
    let url = Url::parse(value).map_err(|error| {
        PlanError::InvalidWebSocketSource(format!("invalid target URL: {error}"))
    })?;
    if !matches!(url.scheme(), "ws" | "wss") {
        return Err(PlanError::UnsafeTarget(format!(
            "scheme {} is denied for WebSocket planning",
            url.scheme()
        )));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(PlanError::UnsafeTarget("userinfo in URLs is denied".into()));
    }
    if url.fragment().is_some() {
        return Err(PlanError::UnsafeTarget(
            "fragments in WebSocket URLs are denied".into(),
        ));
    }
    if url.host_str().is_none() {
        return Err(PlanError::InvalidWebSocketSource(
            "target URL has no host".into(),
        ));
    }
    Ok(url)
}

fn enforce_host_policy(host: &str, configuration: &ProjectConfiguration) -> Result<(), PlanError> {
    if configuration
        .policy
        .denied_hosts
        .iter()
        .any(|denied| denied.eq_ignore_ascii_case(host))
    {
        return Err(PlanError::PolicyDenied(format!(
            "host {host:?} is explicitly denied"
        )));
    }
    if !configuration.policy.allowed_hosts.is_empty()
        && !configuration
            .policy
            .allowed_hosts
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(host))
    {
        return Err(PlanError::PolicyDenied(format!(
            "host {host:?} is outside the configured allowlist"
        )));
    }
    Ok(())
}

fn normalize_origin(value: &str) -> Result<String, PlanError> {
    let origin = Url::parse(value).map_err(|error| {
        PlanError::InvalidWebSocketSource(format!("invalid Origin URL: {error}"))
    })?;
    if !matches!(origin.scheme(), "http" | "https")
        || origin.host_str().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err(PlanError::InvalidWebSocketSource(
            "Origin must be an http(s) origin without credentials, path, query, or fragment".into(),
        ));
    }
    Ok(origin.origin().ascii_serialization())
}

fn enforce_websocket_origin_policy(
    origin: Option<&str>,
    configuration: &ProjectConfiguration,
) -> Result<(), PlanError> {
    let allowed = configuration
        .policy
        .websocket
        .allowed_origins
        .iter()
        .map(|configured| {
            normalize_origin(configured).map_err(|error| {
                PlanError::Configuration(format!(
                    "invalid WebSocket origin allowlist entry {configured:?}: {error}"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(origin) = origin
        && !allowed.is_empty()
        && !allowed.iter().any(|configured| configured == origin)
    {
        return Err(PlanError::PolicyDenied(format!(
            "Origin {origin:?} is outside the configured WebSocket allowlist"
        )));
    }
    Ok(())
}

fn enforce_websocket_subprotocol_policy(
    subprotocols: &[String],
    configuration: &ProjectConfiguration,
) -> Result<(), PlanError> {
    let configured = &configuration.policy.websocket.allowed_subprotocols;
    let mut unique = BTreeSet::new();
    if configured
        .iter()
        .any(|protocol| !valid_websocket_token(protocol) || !unique.insert(protocol))
    {
        return Err(PlanError::Configuration(
            "WebSocket subprotocol allowlist entries must be unique RFC tokens".into(),
        ));
    }
    let mut requested = BTreeSet::new();
    if subprotocols
        .iter()
        .any(|protocol| !valid_websocket_token(protocol) || !requested.insert(protocol))
    {
        return Err(PlanError::InvalidWebSocketSource(
            "requested WebSocket subprotocols must be unique RFC tokens".into(),
        ));
    }
    if !configured.is_empty()
        && subprotocols
            .iter()
            .any(|protocol| !configured.contains(protocol))
    {
        return Err(PlanError::PolicyDenied(
            "one or more requested WebSocket subprotocols are outside the configured allowlist"
                .into(),
        ));
    }
    Ok(())
}

fn valid_websocket_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn websocket_headers(
    source: BTreeMap<String, String>,
    configuration: &ProjectConfiguration,
) -> Result<Vec<PlannedHeader>, PlanError> {
    let forbidden = [
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "host",
        "upgrade",
        "connection",
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-protocol",
        "sec-websocket-extensions",
        "content-length",
        "transfer-encoding",
    ];
    let mut names = BTreeSet::new();
    let mut headers = Vec::with_capacity(source.len());
    for (name, value) in source {
        let normalized = name.to_ascii_lowercase();
        if !valid_websocket_token(&name) {
            return Err(PlanError::InvalidWebSocketSource(format!(
                "header name {name:?} is not a valid HTTP token"
            )));
        }
        if value.contains(['\r', '\n']) {
            return Err(PlanError::InvalidWebSocketSource(format!(
                "header {name:?} value contains a line break"
            )));
        }
        if forbidden.contains(&normalized.as_str())
            || configuration
                .policy
                .sensitive_headers
                .iter()
                .any(|sensitive| sensitive.eq_ignore_ascii_case(&name))
        {
            return Err(PlanError::InvalidWebSocketSource(format!(
                "header {name:?} must be supplied by the transport or a secret profile"
            )));
        }
        if !names.insert(normalized) {
            return Err(PlanError::InvalidWebSocketSource(
                "handshake header names must be unique case-insensitively".into(),
            ));
        }
        headers.push(PlannedHeader { name, value });
    }
    Ok(headers)
}

fn bind_websocket_configured_auth(
    requested: Option<&str>,
    configuration: &ProjectConfiguration,
) -> Result<(Option<PlannedAuth>, Vec<String>), PlanError> {
    let Some(profile) = requested else {
        return Ok((None, Vec::new()));
    };
    let configured = configuration
        .auth
        .get(profile)
        .ok_or_else(|| PlanError::UnknownSecurityScheme(profile.into()))?;
    for reference in [
        configured.token.as_deref(),
        configured.username.as_deref(),
        configured.password.as_deref(),
        configured.client_id.as_deref(),
        configured.client_secret.as_deref(),
        configured.refresh_token.as_deref(),
        configured.certificate.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if !reference.starts_with("secret://") {
            return Err(PlanError::Configuration(format!(
                "auth profile {profile:?} contains an inline credential; use secret:// references"
            )));
        }
    }
    let (scheme, kind, placement) = match configured.r#type.as_str() {
        "bearer" => ("bearer", "http", "header:Authorization:bearer"),
        "basic" => ("basic", "http", "header:Authorization:basic"),
        "mtls" => ("mtls", "mutualTLS", "tls-client-certificate"),
        other => return Err(PlanError::UnsupportedSecurityScheme(other.into())),
    };
    Ok((
        Some(PlannedAuth {
            scheme: scheme.into(),
            kind: kind.into(),
            profile: profile.into(),
            placement: placement.into(),
            token_url: None,
            scopes: Vec::new(),
        }),
        vec![format!("secret://{profile}")],
    ))
}

fn effective_websocket_limits(
    requested: WebSocketLimits,
    configuration: &ProjectConfiguration,
) -> Result<WebSocketLimits, PlanError> {
    let maximum = &configuration.policy.websocket.max_limits;
    let maximum_values = [
        maximum.connect_timeout_ms,
        maximum.action_timeout_ms,
        maximum.idle_timeout_ms,
        maximum.close_timeout_ms,
        maximum.total_timeout_ms,
        maximum.max_frame_bytes,
        maximum.max_message_bytes,
        maximum.max_inbound_frames,
        maximum.max_outbound_frames,
        maximum.max_inbound_messages,
        maximum.max_outbound_messages,
        maximum.max_inbound_bytes,
        maximum.max_outbound_bytes,
    ];
    if maximum_values.contains(&0) {
        return Err(PlanError::Configuration(
            "WebSocket policy maxima must all be positive".into(),
        ));
    }
    if maximum.max_message_bytes < maximum.max_frame_bytes
        || maximum.connect_timeout_ms > maximum.total_timeout_ms
        || maximum.action_timeout_ms > maximum.total_timeout_ms
        || maximum.idle_timeout_ms > maximum.total_timeout_ms
        || maximum.close_timeout_ms > maximum.total_timeout_ms
    {
        return Err(PlanError::Configuration(
            "WebSocket policy maxima contradict their total or frame bounds".into(),
        ));
    }
    let requested_values = [
        requested.connect_timeout_ms,
        requested.action_timeout_ms,
        requested.idle_timeout_ms,
        requested.close_timeout_ms,
        requested.total_timeout_ms,
        requested.max_frame_bytes,
        requested.max_message_bytes,
        requested.max_inbound_frames,
        requested.max_outbound_frames,
        requested.max_inbound_messages,
        requested.max_outbound_messages,
        requested.max_inbound_bytes,
        requested.max_outbound_bytes,
    ];
    if requested_values.contains(&0) {
        return Err(PlanError::InvalidWebSocketSource(
            "requested WebSocket limits must all be positive".into(),
        ));
    }
    if requested.max_message_bytes < requested.max_frame_bytes
        || requested.connect_timeout_ms > requested.total_timeout_ms
        || requested.action_timeout_ms > requested.total_timeout_ms
        || requested.idle_timeout_ms > requested.total_timeout_ms
        || requested.close_timeout_ms > requested.total_timeout_ms
    {
        return Err(PlanError::InvalidWebSocketSource(
            "requested WebSocket limits contradict their total or frame bounds".into(),
        ));
    }
    Ok(WebSocketLimits {
        connect_timeout_ms: requested.connect_timeout_ms.min(maximum.connect_timeout_ms),
        action_timeout_ms: requested.action_timeout_ms.min(maximum.action_timeout_ms),
        idle_timeout_ms: requested.idle_timeout_ms.min(maximum.idle_timeout_ms),
        close_timeout_ms: requested.close_timeout_ms.min(maximum.close_timeout_ms),
        total_timeout_ms: requested.total_timeout_ms.min(maximum.total_timeout_ms),
        max_frame_bytes: requested.max_frame_bytes.min(maximum.max_frame_bytes),
        max_message_bytes: requested.max_message_bytes.min(maximum.max_message_bytes),
        max_inbound_frames: requested.max_inbound_frames.min(maximum.max_inbound_frames),
        max_outbound_frames: requested
            .max_outbound_frames
            .min(maximum.max_outbound_frames),
        max_inbound_messages: requested
            .max_inbound_messages
            .min(maximum.max_inbound_messages),
        max_outbound_messages: requested
            .max_outbound_messages
            .min(maximum.max_outbound_messages),
        max_inbound_bytes: requested.max_inbound_bytes.min(maximum.max_inbound_bytes),
        max_outbound_bytes: requested.max_outbound_bytes.min(maximum.max_outbound_bytes),
    })
}

fn tighten_websocket_action_timeouts(actions: &mut [WebSocketAction], maximum: u64) {
    for action in actions {
        let timeout = match action {
            WebSocketAction::ExpectText { timeout_ms, .. }
            | WebSocketAction::ExpectBinary { timeout_ms, .. }
            | WebSocketAction::ExpectJson { timeout_ms, .. }
            | WebSocketAction::ExpectPong { timeout_ms, .. }
            | WebSocketAction::ExpectClose { timeout_ms, .. } => timeout_ms,
            _ => continue,
        };
        *timeout = Some(timeout.map_or(maximum, |value| value.min(maximum)));
    }
}

fn origin_transport_scheme(scheme: &str) -> &str {
    match scheme {
        "wss" => "https",
        "ws" => "http",
        other => other,
    }
}

fn configured_server_matches_target(server: &ConfiguredServer, target: &Url) -> bool {
    if server.classification.as_deref() != Some("production") {
        return false;
    }
    Url::parse(&server.url).is_ok_and(|configured| {
        origin_transport_scheme(configured.scheme()) == origin_transport_scheme(target.scheme())
            && configured
                .host_str()
                .zip(target.host_str())
                .is_some_and(|(left, right)| left.eq_ignore_ascii_case(right))
            && configured.port_or_known_default() == target.port_or_known_default()
    })
}

fn validate_redaction_policy(configuration: &ProjectConfiguration) -> Result<(), PlanError> {
    for pointer in &configuration.policy.redact_response_json_pointers {
        if !pointer.starts_with('/') || pointer.len() > 2_048 {
            return Err(PlanError::Configuration(format!(
                "response redaction pointer {pointer:?} must be a bounded JSON Pointer"
            )));
        }
    }
    for header in &configuration.policy.sensitive_headers {
        if header.is_empty() || header.contains(['\r', '\n']) {
            return Err(PlanError::Configuration(
                "sensitive header names must be non-empty and contain no line breaks".into(),
            ));
        }
    }
    Ok(())
}

fn is_unsafe_address(address: IpAddr) -> bool {
    address.is_loopback()
        || address.is_unspecified()
        || address.is_multicast()
        || is_private(address)
        || is_link_local(address)
}

fn is_private(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_private(),
        IpAddr::V6(address) => address.is_unique_local(),
    }
}

fn is_link_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_link_local(),
        IpAddr::V6(address) => address.is_unicast_link_local(),
    }
}

fn default_checks(operation: &OperationDefinition) -> Vec<String> {
    let mut statuses: Vec<_> = operation
        .operation
        .get("responses")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|responses| responses.keys())
        .filter(|status| status.chars().all(|character| character.is_ascii_digit()))
        .cloned()
        .collect();
    statuses.sort();
    let mut checks = Vec::new();
    if !statuses.is_empty() {
        checks.push(format!("status:any({})", statuses.join(",")));
    }
    checks.push("response-schema:openapi".into());
    checks.extend(
        operation
            .operation
            .get("x-kahea-checks")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string),
    );
    checks.sort();
    checks.dedup();
    checks
}

fn derivation(
    field: String,
    logical_value: Value,
    source: String,
    wire_value: Option<String>,
    transformation: &str,
) -> FieldDerivation {
    FieldDerivation {
        source_location: format!("input:/{field}"),
        field,
        source,
        logical_value,
        wire_value,
        transformations: vec![transformation.into()],
    }
}

fn string_field(object: &Map<String, Value>, key: &str) -> Option<String> {
    object.get(key).and_then(Value::as_str).map(str::to_string)
}

fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

pub fn store_plan(root: &Path, plan: &RequestPlan) -> Result<PathBuf, PlanError> {
    if !plan.verify_seal()? {
        return Err(PlanError::InvalidSeal);
    }
    let directory = root.join("store/plans");
    fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{}.json", plan.id.replace(':', "-")));
    let temporary = directory.join(format!(".{}.tmp", plan.id.replace(':', "-")));
    let bytes = serde_json::to_vec(plan)?;
    fs::write(&temporary, bytes)?;
    fs::rename(&temporary, &path)?;
    Ok(path)
}

pub fn load_plan(root: &Path, reference: &str) -> Result<RequestPlan, PlanError> {
    let path = if reference.starts_with("plan:") {
        root.join("store/plans")
            .join(format!("{}.json", reference.replace(':', "-")))
    } else {
        PathBuf::from(reference)
    };
    let plan: RequestPlan = serde_json::from_slice(&fs::read(path)?)?;
    if !plan.verify_seal()? {
        return Err(PlanError::InvalidSeal);
    }
    Ok(plan)
}

pub fn store_websocket_plan(root: &Path, plan: &WebSocketPlan) -> Result<PathBuf, PlanError> {
    if !plan.verify_seal()? {
        return Err(PlanError::InvalidSeal);
    }
    let directory = root.join("store/plans");
    fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{}.json", plan.id.replace(':', "-")));
    let temporary = directory.join(format!(".{}.tmp", plan.id.replace(':', "-")));
    fs::write(&temporary, serde_json::to_vec(plan)?)?;
    fs::rename(&temporary, &path)?;
    Ok(path)
}

pub fn load_websocket_plan(root: &Path, reference: &str) -> Result<WebSocketPlan, PlanError> {
    let path = if reference.starts_with("plan:") {
        root.join("store/plans")
            .join(format!("{}.json", reference.replace(':', "-")))
    } else {
        PathBuf::from(reference)
    };
    let plan: WebSocketPlan = serde_json::from_slice(&fs::read(path)?)?;
    if !plan.verify_seal()? {
        return Err(PlanError::InvalidSeal);
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kahea_ingest::{load_openapi, resolve_operation};
    use serde_json::json;

    const SPEC: &str = r#"
openapi: 3.1.0
info: { title: Example, version: 1.0.0 }
servers: [{ url: "https://sandbox.example.test/v1" }]
paths:
  /invoices/{id}:
    post:
      operationId: updateInvoice
      parameters:
        - { in: path, name: id, required: true, schema: { type: string } }
        - { in: query, name: notify, schema: { type: boolean, default: false } }
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              additionalProperties: false
              required: [amount]
              properties:
                amount: { type: number }
                currency: { type: string, default: USD }
      responses:
        "200": { description: updated }
"#;

    fn source_and_operation() -> (OpenApiSource, OperationDefinition) {
        let source = load_openapi(Path::new("fixture.yaml"), SPEC.as_bytes()).unwrap();
        let operation = resolve_operation(&source, "updateInvoice").unwrap();
        (source, operation)
    }

    fn websocket_source() -> Value {
        serde_json::from_slice(include_bytes!("../../../fixtures/websocket/session.json")).unwrap()
    }

    fn websocket_configuration() -> ProjectConfiguration {
        let mut configuration = ProjectConfiguration {
            version: 1,
            ..ProjectConfiguration::default()
        };
        configuration
            .policy
            .allowed_hosts
            .push("socket.example.test".into());
        configuration.auth.insert(
            "chat-sandbox".into(),
            ConfiguredAuth {
                r#type: "bearer".into(),
                token: Some("secret://chat/sandbox".into()),
                ..ConfiguredAuth::default()
            },
        );
        configuration
    }

    fn websocket_plan_from_value(
        value: &Value,
        configuration: &ProjectConfiguration,
    ) -> Result<WebSocketPlan, PlanError> {
        build_websocket_plan_with_configuration(
            Path::new("session.json"),
            &serde_json::to_vec(value).unwrap(),
            configuration,
        )
    }

    #[test]
    fn websocket_fixture_plans_deterministically_with_exact_grants() {
        let source = websocket_source();
        let configuration = websocket_configuration();
        let first = websocket_plan_from_value(&source, &configuration).unwrap();
        let second = websocket_plan_from_value(&source, &configuration).unwrap();
        assert_eq!(
            serde_json::to_vec(&first).unwrap(),
            serde_json::to_vec(&second).unwrap()
        );
        assert!(first.verify_seal().unwrap());
        assert_eq!(
            first.fingerprint,
            "b3:0d7e9d6f78000a79e8ab5d22f618e40f60d1d0f66ea47e1b03e7aba02fed8e42"
        );
        assert_eq!(first.target, "wss://socket.example.test/v1/events");
        assert_eq!(first.risk, kahea_core::RiskClass::Write);
        assert_eq!(
            first.required_grants,
            [
                "net:socket.example.test:443",
                "secret:chat-sandbox",
                "websocket:connect",
            ]
        );
        assert_eq!(first.secret_refs, ["secret://chat-sandbox"]);
        assert_eq!(first.auth.as_ref().unwrap().profile, "chat-sandbox");
        assert_eq!(
            first.handshake_checks,
            [
                "extensions:none",
                "status:101",
                "subprotocol:kahea.events.v1"
            ]
        );
        assert_eq!(
            first.sensitive_headers,
            [
                "authorization",
                "cookie",
                "proxy-authorization",
                "set-cookie"
            ]
        );
        let serialized = serde_json::to_string(&first).unwrap();
        assert!(!serialized.contains("secret://chat/sandbox"));
    }

    #[test]
    fn websocket_json_and_yaml_sources_share_the_same_contract() {
        let configuration = websocket_configuration();
        let json_plan = build_websocket_plan_with_configuration(
            Path::new("session.json"),
            include_bytes!("../../../fixtures/websocket/session.json"),
            &configuration,
        )
        .unwrap();
        let fixture = include_bytes!("../../../fixtures/websocket/session.yaml");
        let fixture_plan = build_websocket_plan_with_configuration(
            Path::new("session.yaml"),
            fixture,
            &configuration,
        )
        .unwrap();
        assert!(fixture_plan.verify_seal().unwrap());
        assert_eq!(fixture_plan.target, "wss://socket.example.test/v1/events");
        assert_eq!(fixture_plan.actions.len(), 5);
        assert_ne!(
            fixture_plan.source_fingerprints,
            json_plan.source_fingerprints
        );
        assert_eq!(fixture_plan.actions, json_plan.actions);
        assert_eq!(fixture_plan.limits, json_plan.limits);
        assert_eq!(
            serde_json::to_value(&fixture_plan.headers).unwrap(),
            serde_json::to_value(&json_plan.headers).unwrap()
        );
        assert_eq!(fixture_plan.required_grants, json_plan.required_grants);
        assert_eq!(fixture_plan.handshake_checks, json_plan.handshake_checks);

        let yaml = r#"
kind: websocket-session
version: 1
operationId: receiveReady
url: wss://socket.example.test/ready
limits:
  connect_timeout_ms: 1000
  action_timeout_ms: 1000
  idle_timeout_ms: 1000
  close_timeout_ms: 1000
  total_timeout_ms: 5000
  max_frame_bytes: 1024
  max_message_bytes: 2048
  max_inbound_frames: 4
  max_outbound_frames: 4
  max_inbound_messages: 2
  max_outbound_messages: 2
  max_inbound_bytes: 4096
  max_outbound_bytes: 4096
actions:
  - type: expect-close
    codes: [1000]
"#;
        let plan = build_websocket_plan(Path::new("session.yaml"), yaml.as_bytes()).unwrap();
        assert!(plan.verify_seal().unwrap());
        assert_eq!(plan.risk, kahea_core::RiskClass::Unknown);
        assert_eq!(
            plan.required_grants,
            ["net:socket.example.test:443", "websocket:connect"]
        );
        assert!(matches!(
            plan.actions.as_slice(),
            [WebSocketAction::ExpectClose { codes, .. }] if codes == &[1000]
        ));
    }

    #[test]
    fn websocket_policy_tightens_limits_and_has_separate_fingerprints() {
        let source = websocket_source();
        let mut configuration = websocket_configuration();
        let http_policy = configuration.policy_fingerprint().unwrap();
        let websocket_policy = configuration.websocket_policy_fingerprint().unwrap();
        let config = configuration.config_fingerprint().unwrap();
        configuration
            .policy
            .websocket
            .allowed_subprotocols
            .push("kahea.events.v1".into());
        configuration.policy.websocket.max_limits.action_timeout_ms = 1_000;

        assert_eq!(http_policy, configuration.policy_fingerprint().unwrap());
        assert_ne!(
            websocket_policy,
            configuration.websocket_policy_fingerprint().unwrap()
        );
        assert_ne!(config, configuration.config_fingerprint().unwrap());

        let plan = websocket_plan_from_value(&source, &configuration).unwrap();
        assert_eq!(plan.limits.action_timeout_ms, 1_000);
        for action in &plan.actions {
            match action {
                WebSocketAction::ExpectJson { timeout_ms, .. }
                | WebSocketAction::ExpectPong { timeout_ms, .. } => {
                    assert_eq!(*timeout_ms, Some(1_000));
                }
                _ => {}
            }
        }
    }

    #[test]
    fn websocket_source_validation_fails_closed() {
        let configuration = websocket_configuration();
        let mut cases = Vec::new();

        let mut source = websocket_source();
        source["kind"] = json!("websocket");
        cases.push(source);

        let mut source = websocket_source();
        source["version"] = json!(2);
        cases.push(source);

        let mut source = websocket_source();
        source["url"] = json!("https://socket.example.test/events");
        cases.push(source);

        let mut source = websocket_source();
        source["url"] = json!("wss://user:password@socket.example.test/events");
        cases.push(source);

        let mut source = websocket_source();
        source["url"] = json!("wss://user@socket.example.test/events");
        cases.push(source);

        let mut source = websocket_source();
        source["url"] = json!("wss://:password@socket.example.test/events");
        cases.push(source);

        let mut source = websocket_source();
        source["url"] = json!("wss://socket.example.test/events#fragment");
        cases.push(source);

        let mut source = websocket_source();
        source["headers"] = json!({"authorization":"Bearer inline"});
        cases.push(source);

        let mut source = websocket_source();
        source["headers"] = json!({"X-Mode":"one","x-mode":"two"});
        cases.push(source);

        let mut source = websocket_source();
        source["headers"] = json!({"X-Mode":"one\r\nInjected: yes"});
        cases.push(source);

        let mut source = websocket_source();
        source["headers"] = json!({"Host":"attacker.example.test"});
        cases.push(source);

        let mut source = websocket_source();
        source["headers"] = json!({"Bad Header":"value"});
        cases.push(source);

        let mut source = websocket_source();
        source["headers"] = json!({"Bad:Header":"value"});
        cases.push(source);

        let mut source = websocket_source();
        source["origin"] = json!("https://client.example.test/not-an-origin");
        cases.push(source);

        let mut source = websocket_source();
        source["operationId"] = json!("");
        cases.push(source);

        let mut source = websocket_source();
        source["operationId"] = json!("a".repeat(257));
        cases.push(source);

        let mut source = websocket_source();
        source["operationId"] = json!("bad\noperation");
        cases.push(source);

        let mut source = websocket_source();
        source["limits"]["total_timeout_ms"] = json!(0);
        cases.push(source);

        let mut source = websocket_source();
        source["limits"]["unexpected"] = json!(1);
        cases.push(source);

        let mut source = websocket_source();
        source["actions"][0]["unexpected"] = json!(true);
        cases.push(source);

        let mut source = websocket_source();
        source.as_object_mut().unwrap().remove("limits");
        cases.push(source);

        let mut source = websocket_source();
        source["actions"] = json!([{"type":"send-text","text":"never terminal"}]);
        cases.push(source);

        for invalid in [
            json!([""]),
            json!(["chat.v1", "chat.v1"]),
            json!(["bad protocol"]),
            json!(["bad,protocol"]),
            json!(["bad\r\nprotocol"]),
        ] {
            let mut source = websocket_source();
            source["subprotocols"] = invalid;
            cases.push(source);
        }

        let mut source = websocket_source();
        source["unexpected"] = json!(true);
        cases.push(source);

        for source in cases {
            assert!(
                websocket_plan_from_value(&source, &configuration).is_err(),
                "accepted invalid source: {source}"
            );
        }
    }

    #[test]
    fn websocket_url_and_origin_boundaries_are_independent() {
        let configuration = websocket_configuration();
        let mut source = websocket_source();
        source["operationId"] = json!("a".repeat(256));
        assert!(websocket_plan_from_value(&source, &configuration).is_ok());

        let prefix = "wss://socket.example.test/";
        let mut source = websocket_source();
        source["url"] = json!(format!("{prefix}{}", "a".repeat(8_192 - prefix.len())));
        assert!(websocket_plan_from_value(&source, &configuration).is_ok());

        source["url"] = json!(format!("{prefix}{}", "a".repeat(8_193 - prefix.len())));
        assert!(websocket_plan_from_value(&source, &configuration).is_err());

        for invalid in [
            "ftp://client.example.test",
            "https://user@client.example.test",
            "https://:password@client.example.test",
            "https://client.example.test/path",
            "https://client.example.test?query=yes",
            "https://client.example.test#fragment",
        ] {
            let mut source = websocket_source();
            source["origin"] = json!(invalid);
            assert!(
                websocket_plan_from_value(&source, &configuration).is_err(),
                "accepted invalid Origin {invalid}"
            );
        }
    }

    #[test]
    fn websocket_host_origin_and_subprotocol_policy_fail_closed() {
        let source = websocket_source();
        let mut configuration = websocket_configuration();
        configuration.policy.denied_hosts = vec!["socket.example.test".into()];
        assert!(matches!(
            websocket_plan_from_value(&source, &configuration),
            Err(PlanError::PolicyDenied(_))
        ));

        let default = ProjectConfiguration::default();
        assert!(matches!(
            enforce_websocket_subprotocol_policy(&[String::new()], &default),
            Err(PlanError::InvalidWebSocketSource(_))
        ));
        assert!(matches!(
            enforce_websocket_subprotocol_policy(&["chat.v1".into(), "chat.v1".into()], &default),
            Err(PlanError::InvalidWebSocketSource(_))
        ));

        configuration.policy.denied_hosts.clear();
        configuration.policy.allowed_hosts = vec!["other.example.test".into()];
        assert!(matches!(
            websocket_plan_from_value(&source, &configuration),
            Err(PlanError::PolicyDenied(_))
        ));

        configuration.policy.allowed_hosts = vec!["socket.example.test".into()];
        configuration.policy.websocket.allowed_origins = vec!["https://other.example.test".into()];
        assert!(matches!(
            websocket_plan_from_value(&source, &configuration),
            Err(PlanError::PolicyDenied(_))
        ));

        configuration.policy.websocket.allowed_origins = vec!["https://client.example.test".into()];
        configuration.policy.websocket.allowed_subprotocols = vec!["other.v1".into()];
        assert!(matches!(
            websocket_plan_from_value(&source, &configuration),
            Err(PlanError::PolicyDenied(_))
        ));
    }

    #[test]
    fn invalid_websocket_policy_configuration_fails_closed() {
        let mut source = websocket_source();
        source.as_object_mut().unwrap().remove("origin");
        source.as_object_mut().unwrap().remove("subprotocols");

        let mut configuration = websocket_configuration();
        configuration.policy.websocket.allowed_origins = vec!["not-an-origin".into()];
        assert!(matches!(
            websocket_plan_from_value(&source, &configuration),
            Err(PlanError::Configuration(_))
        ));

        configuration.policy.websocket.allowed_origins.clear();
        configuration.policy.websocket.allowed_subprotocols = vec!["bad protocol".into()];
        assert!(matches!(
            websocket_plan_from_value(&source, &configuration),
            Err(PlanError::Configuration(_))
        ));

        configuration.policy.websocket.allowed_subprotocols =
            vec!["chat.v1".into(), "chat.v1".into()];
        assert!(matches!(
            websocket_plan_from_value(&source, &configuration),
            Err(PlanError::Configuration(_))
        ));

        configuration.policy.websocket.allowed_subprotocols.clear();
        configuration.policy.websocket.max_limits.max_frame_bytes = 0;
        assert!(matches!(
            websocket_plan_from_value(&source, &configuration),
            Err(PlanError::Configuration(_))
        ));

        configuration.policy.websocket.max_limits = WebSocketPolicyLimits::default();
        configuration.policy.websocket.max_limits.max_message_bytes = 1;
        assert!(matches!(
            websocket_plan_from_value(&source, &configuration),
            Err(PlanError::Configuration(_))
        ));

        configuration.policy.websocket.max_limits = WebSocketPolicyLimits::default();
        configuration.policy.websocket.max_limits.connect_timeout_ms = 120_001;
        assert!(matches!(
            websocket_plan_from_value(&source, &configuration),
            Err(PlanError::Configuration(_))
        ));

        for timeout in ["action", "idle", "close"] {
            configuration.policy.websocket.max_limits = WebSocketPolicyLimits::default();
            match timeout {
                "action" => configuration.policy.websocket.max_limits.action_timeout_ms = 120_001,
                "idle" => configuration.policy.websocket.max_limits.idle_timeout_ms = 120_001,
                "close" => configuration.policy.websocket.max_limits.close_timeout_ms = 120_001,
                _ => unreachable!(),
            }
            assert!(matches!(
                websocket_plan_from_value(&source, &configuration),
                Err(PlanError::Configuration(_))
            ));
        }

        configuration.policy.websocket.max_limits = WebSocketPolicyLimits::default();
        configuration.policy.websocket.max_limits.max_message_bytes =
            configuration.policy.websocket.max_limits.max_frame_bytes;
        configuration.policy.websocket.max_limits.connect_timeout_ms = 120_000;
        configuration.policy.websocket.max_limits.action_timeout_ms = 120_000;
        configuration.policy.websocket.max_limits.idle_timeout_ms = 120_000;
        configuration.policy.websocket.max_limits.close_timeout_ms = 120_000;
        assert!(websocket_plan_from_value(&source, &configuration).is_ok());
    }

    #[test]
    fn websocket_redaction_policy_boundaries_fail_closed() {
        let source = websocket_source();
        let mut configuration = websocket_configuration();

        configuration.policy.redact_response_json_pointers = vec!["not-a-pointer".into()];
        assert!(matches!(
            websocket_plan_from_value(&source, &configuration),
            Err(PlanError::Configuration(_))
        ));

        configuration.policy.redact_response_json_pointers =
            vec![format!("/{}", "a".repeat(2_048))];
        assert!(matches!(
            websocket_plan_from_value(&source, &configuration),
            Err(PlanError::Configuration(_))
        ));

        configuration.policy.redact_response_json_pointers =
            vec![format!("/{}", "a".repeat(2_047))];
        assert!(websocket_plan_from_value(&source, &configuration).is_ok());

        configuration.policy.redact_response_json_pointers.clear();
        for invalid in ["", "bad\rheader", "bad\nheader"] {
            configuration.policy.sensitive_headers = vec![invalid.into()];
            assert!(matches!(
                websocket_plan_from_value(&source, &configuration),
                Err(PlanError::Configuration(_))
            ));
        }

        configuration.policy.sensitive_headers = vec!["X-Sensitive".into()];
        assert!(websocket_plan_from_value(&source, &configuration).is_ok());
    }

    #[test]
    fn websocket_sensitive_headers_auth_and_handshake_checks_are_exact() {
        let source = websocket_source();
        let mut configuration = websocket_configuration();
        configuration.policy.sensitive_headers = vec!["X-Client".into()];
        assert!(matches!(
            websocket_plan_from_value(&source, &configuration),
            Err(PlanError::InvalidWebSocketSource(_))
        ));

        configuration.policy.sensitive_headers.clear();
        let mut no_auth = source.clone();
        no_auth.as_object_mut().unwrap().remove("auth");
        let plan = websocket_plan_from_value(&no_auth, &configuration).unwrap();
        assert!(plan.auth.is_none());
        assert!(plan.secret_refs.is_empty());

        for (kind, scheme, placement, extra_grant) in [
            ("basic", "basic", "header:Authorization:basic", None),
            (
                "mtls",
                "mtls",
                "tls-client-certificate",
                Some("tls-client-cert:chat-sandbox"),
            ),
        ] {
            configuration.auth.get_mut("chat-sandbox").unwrap().r#type = kind.into();
            let plan = websocket_plan_from_value(&source, &configuration).unwrap();
            let auth = plan.auth.unwrap();
            assert_eq!(auth.scheme, scheme);
            assert_eq!(auth.placement, placement);
            if let Some(grant) = extra_grant {
                assert!(plan.required_grants.contains(&grant.into()));
            }
        }

        configuration.auth.get_mut("chat-sandbox").unwrap().r#type = "digest".into();
        assert!(matches!(
            websocket_plan_from_value(&source, &configuration),
            Err(PlanError::UnsupportedSecurityScheme(_))
        ));

        let mut multiple = source;
        multiple["subprotocols"] = json!(["kahea.events.v1", "kahea.events.v2"]);
        let plan = websocket_plan_from_value(&multiple, &websocket_configuration()).unwrap();
        assert!(
            plan.handshake_checks
                .contains(&"subprotocol:any(kahea.events.v1,kahea.events.v2)".into())
        );
    }

    #[test]
    fn websocket_each_expectation_timeout_is_policy_tightened() {
        let mut source = websocket_source();
        source["actions"] = json!([
            {"type":"expect-text","equals":"ready","timeout_ms":2000},
            {"type":"expect-binary","payload_base64":"AA==","timeout_ms":2000},
            {"type":"expect-json","equals":{"ready":true},"timeout_ms":2000},
            {"type":"expect-pong","payload_base64":"","timeout_ms":2000},
            {"type":"expect-close","codes":[1000],"timeout_ms":2000}
        ]);
        let mut configuration = websocket_configuration();
        configuration.policy.websocket.max_limits.action_timeout_ms = 1_000;
        let plan = websocket_plan_from_value(&source, &configuration).unwrap();
        for action in plan.actions {
            let timeout = match action {
                WebSocketAction::ExpectText { timeout_ms, .. }
                | WebSocketAction::ExpectBinary { timeout_ms, .. }
                | WebSocketAction::ExpectJson { timeout_ms, .. }
                | WebSocketAction::ExpectPong { timeout_ms, .. }
                | WebSocketAction::ExpectClose { timeout_ms, .. } => timeout_ms,
                _ => unreachable!(),
            };
            assert_eq!(timeout, Some(1_000));
        }

        let mut source = websocket_source();
        source["actions"] = json!([
            {"type":"expect-text","equals":"ready"},
            {"type":"expect-binary","payload_base64":"AA=="},
            {"type":"expect-json","equals":{"ready":true}},
            {"type":"expect-pong","payload_base64":""},
            {"type":"expect-close","codes":[1000]}
        ]);
        let plan = websocket_plan_from_value(&source, &configuration).unwrap();
        for action in plan.actions {
            let timeout = match action {
                WebSocketAction::ExpectText { timeout_ms, .. }
                | WebSocketAction::ExpectBinary { timeout_ms, .. }
                | WebSocketAction::ExpectJson { timeout_ms, .. }
                | WebSocketAction::ExpectPong { timeout_ms, .. }
                | WebSocketAction::ExpectClose { timeout_ms, .. } => timeout_ms,
                _ => unreachable!(),
            };
            assert_eq!(timeout, Some(1_000));
        }
    }

    #[test]
    fn websocket_requested_limit_relationships_fail_before_clamping() {
        let configuration = websocket_configuration();
        for field in [
            "connect_timeout_ms",
            "action_timeout_ms",
            "idle_timeout_ms",
            "close_timeout_ms",
            "total_timeout_ms",
            "max_frame_bytes",
            "max_message_bytes",
            "max_inbound_frames",
            "max_outbound_frames",
            "max_inbound_messages",
            "max_outbound_messages",
            "max_inbound_bytes",
            "max_outbound_bytes",
        ] {
            let mut source = websocket_source();
            source["limits"][field] = json!(0);
            assert!(matches!(
                websocket_plan_from_value(&source, &configuration),
                Err(PlanError::InvalidWebSocketSource(_))
            ));
        }

        let requested: WebSocketLimits =
            serde_json::from_value(websocket_source()["limits"].clone()).unwrap();
        assert!(effective_websocket_limits(requested.clone(), &configuration).is_ok());

        let mut source = websocket_source();
        source["limits"]["max_frame_bytes"] = json!(4_194_304);
        source["limits"]["max_message_bytes"] = json!(4_194_303);
        assert!(matches!(
            websocket_plan_from_value(&source, &configuration),
            Err(PlanError::InvalidWebSocketSource(_))
        ));

        let mut invalid = requested.clone();
        invalid.max_message_bytes = invalid.max_frame_bytes - 1;
        assert!(matches!(
            effective_websocket_limits(invalid, &configuration),
            Err(PlanError::InvalidWebSocketSource(_))
        ));

        for field in [
            "connect_timeout_ms",
            "action_timeout_ms",
            "idle_timeout_ms",
            "close_timeout_ms",
        ] {
            let mut source = websocket_source();
            source["limits"][field] = json!(15_001);
            assert!(matches!(
                websocket_plan_from_value(&source, &configuration),
                Err(PlanError::InvalidWebSocketSource(_))
            ));
        }

        for field in [
            "connect_timeout_ms",
            "action_timeout_ms",
            "idle_timeout_ms",
            "close_timeout_ms",
        ] {
            let mut invalid = requested.clone();
            match field {
                "connect_timeout_ms" => invalid.connect_timeout_ms = invalid.total_timeout_ms + 1,
                "action_timeout_ms" => invalid.action_timeout_ms = invalid.total_timeout_ms + 1,
                "idle_timeout_ms" => invalid.idle_timeout_ms = invalid.total_timeout_ms + 1,
                "close_timeout_ms" => invalid.close_timeout_ms = invalid.total_timeout_ms + 1,
                _ => unreachable!(),
            }
            assert!(matches!(
                effective_websocket_limits(invalid, &configuration),
                Err(PlanError::InvalidWebSocketSource(_))
            ));
        }

        let mut inclusive = requested;
        inclusive.max_message_bytes = inclusive.max_frame_bytes;
        inclusive.connect_timeout_ms = inclusive.total_timeout_ms;
        inclusive.action_timeout_ms = inclusive.total_timeout_ms;
        inclusive.idle_timeout_ms = inclusive.total_timeout_ms;
        inclusive.close_timeout_ms = inclusive.total_timeout_ms;
        assert!(effective_websocket_limits(inclusive, &configuration).is_ok());
    }

    #[test]
    fn websocket_plaintext_literal_and_risk_grants_are_exact() {
        let mut source = websocket_source();
        source["url"] = json!("ws://127.0.0.1:8080/events");
        source.as_object_mut().unwrap().remove("auth");
        source.as_object_mut().unwrap().remove("origin");
        source.as_object_mut().unwrap().remove("risk");

        let mut configuration = ProjectConfiguration {
            version: 1,
            ..ProjectConfiguration::default()
        };
        configuration.policy.allowed_hosts = vec!["127.0.0.1".into()];
        configuration.servers.insert(
            "production-socket".into(),
            ConfiguredServer {
                url: "ws://127.0.0.1:8080".into(),
                classification: Some("production".into()),
            },
        );
        let plan = websocket_plan_from_value(&source, &configuration).unwrap();
        assert_eq!(plan.risk, kahea_core::RiskClass::Write);
        for grant in [
            "approve:production-write",
            "net-cidr:127.0.0.1/32",
            "net-insecure-websocket",
            "net:127.0.0.1:8080",
            "websocket:connect",
        ] {
            assert!(plan.required_grants.contains(&grant.into()), "{grant}");
        }
        assert!(!plan.required_grants.contains(&"approve:destructive".into()));

        source["risk"] = json!("destructive");
        let destructive = websocket_plan_from_value(&source, &configuration).unwrap();
        assert!(
            destructive
                .required_grants
                .contains(&"approve:destructive".into())
        );

        source["risk"] = json!("read");
        let inferred = websocket_plan_from_value(&source, &configuration).unwrap();
        assert_eq!(inferred.risk, kahea_core::RiskClass::Write);

        configuration.risk.insert(
            "WEBSOCKET subscribeBuildEvents".into(),
            kahea_core::RiskClass::Read,
        );
        let overridden = websocket_plan_from_value(&source, &configuration).unwrap();
        assert_eq!(overridden.risk, kahea_core::RiskClass::Read);

        let mut receive_only = source;
        receive_only["actions"] = json!([{"type":"expect-close","codes":[1000]}]);
        receive_only.as_object_mut().unwrap().remove("risk");
        configuration.risk.clear();
        let unknown = websocket_plan_from_value(&receive_only, &configuration).unwrap();
        assert_eq!(unknown.risk, kahea_core::RiskClass::Unknown);

        receive_only["risk"] = json!("read");
        let declared_read = websocket_plan_from_value(&receive_only, &configuration).unwrap();
        assert_eq!(declared_read.risk, kahea_core::RiskClass::Read);

        let mut ipv6 = receive_only;
        ipv6["url"] = json!("ws://[::1]:8080/events");
        configuration.policy.allowed_hosts = vec!["[::1]".into()];
        let ipv6_plan = websocket_plan_from_value(&ipv6, &configuration).unwrap();
        assert!(
            ipv6_plan
                .required_grants
                .contains(&"net-cidr:::1/128".into())
        );
    }

    #[test]
    fn websocket_production_server_matching_requires_every_component() {
        let mut source = websocket_source();
        source["url"] = json!("ws://127.0.0.1:8080/events");
        source.as_object_mut().unwrap().remove("auth");
        source.as_object_mut().unwrap().remove("origin");

        for (url, classification) in [
            ("ws://127.0.0.1:8080", "non-production"),
            ("wss://127.0.0.1:8080", "production"),
            ("ws://127.0.0.2:8080", "production"),
            ("ws://127.0.0.1:8081", "production"),
            ("not-a-url", "production"),
        ] {
            let mut configuration = ProjectConfiguration {
                version: 1,
                ..ProjectConfiguration::default()
            };
            configuration.policy.allowed_hosts = vec!["127.0.0.1".into()];
            configuration.servers.insert(
                "candidate".into(),
                ConfiguredServer {
                    url: url.into(),
                    classification: Some(classification.into()),
                },
            );
            let plan = websocket_plan_from_value(&source, &configuration).unwrap();
            assert!(
                !plan
                    .required_grants
                    .contains(&"approve:production-write".into()),
                "incorrectly matched {classification} server {url}"
            );
        }

        let mut secure_source = websocket_source();
        secure_source.as_object_mut().unwrap().remove("auth");
        let mut configuration = websocket_configuration();
        configuration.servers.insert(
            "production".into(),
            ConfiguredServer {
                url: "https://socket.example.test".into(),
                classification: Some("production".into()),
            },
        );
        let secure = websocket_plan_from_value(&secure_source, &configuration).unwrap();
        assert!(
            secure
                .required_grants
                .contains(&"approve:production-write".into())
        );
    }

    #[test]
    fn websocket_auth_references_and_plan_storage_never_embed_credentials() {
        let source = websocket_source();
        let mut configuration = websocket_configuration();
        let plan = websocket_plan_from_value(&source, &configuration).unwrap();
        let serialized = serde_json::to_string(&plan).unwrap();
        assert!(!serialized.contains("chat/sandbox"));

        let root =
            std::env::temp_dir().join(format!("kahea-websocket-plan-store-{}", std::process::id()));
        let path = store_websocket_plan(&root, &plan).unwrap();
        assert_eq!(
            load_websocket_plan(&root, &plan.id).unwrap().fingerprint,
            plan.fingerprint
        );
        let mut tampered: WebSocketPlan =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        tampered.target = "wss://other.example.test".into();
        fs::write(&path, serde_json::to_vec(&tampered).unwrap()).unwrap();
        assert!(matches!(
            load_websocket_plan(&root, &plan.id),
            Err(PlanError::InvalidSeal)
        ));
        fs::remove_dir_all(root).unwrap();

        configuration.auth.get_mut("chat-sandbox").unwrap().token = Some("inline-secret".into());
        assert!(matches!(
            websocket_plan_from_value(&source, &configuration),
            Err(PlanError::Configuration(_))
        ));
    }

    #[test]
    fn identical_inputs_produce_identical_sealed_plans() {
        let (source, operation) = source_and_operation();
        let options = PlanOptions {
            input: Some(serde_json::json!({
                "path": { "id": "inv 42" },
                "body": { "amount": 12.5 }
            })),
            ..PlanOptions::default()
        };
        let first = build_plan(&source, &operation, options.clone()).unwrap();
        let second = build_plan(&source, &operation, options).unwrap();
        assert_eq!(
            serde_json::to_vec(&first).unwrap(),
            serde_json::to_vec(&second).unwrap()
        );
        assert!(first.target.contains("inv%2042"));
        assert!(first.verify_seal().unwrap());
    }

    #[test]
    fn mutation_breaks_the_seal() {
        let (source, operation) = source_and_operation();
        let mut plan = build_plan(
            &source,
            &operation,
            PlanOptions {
                input: Some(serde_json::json!({
                    "path": { "id": "inv-1" },
                    "body": { "amount": 1 }
                })),
                ..PlanOptions::default()
            },
        )
        .unwrap();
        plan.target.push_str("?mutated=true");
        assert!(!plan.verify_seal().unwrap());
    }

    #[test]
    fn unknown_body_fields_fail_closed() {
        let (source, operation) = source_and_operation();
        let error = build_plan(
            &source,
            &operation,
            PlanOptions {
                input: Some(serde_json::json!({
                    "path": { "id": "inv-1" },
                    "body": { "amount": 1, "invented": true }
                })),
                ..PlanOptions::default()
            },
        )
        .unwrap_err();
        assert!(matches!(error, PlanError::UnknownInput(_)));
    }

    #[test]
    fn open_object_schemas_accept_additional_fields_by_default() {
        let mut document = serde_json::json!({
            "openapi":"3.1.0",
            "info":{"title":"Open body","version":"1"},
            "servers":[{"url":"https://example.test"}],
            "paths":{"/items":{"post":{
                "operationId":"createItem",
                "requestBody":{"required":true,"content":{"application/json":{"schema":{}}}},
                "responses":{"200":{"description":"ok"}}
            }}}
        });
        let bytes = serde_json::to_vec(&document).unwrap();
        let source = load_openapi(Path::new("open.json"), &bytes).unwrap();
        let operation = resolve_operation(&source, "createItem").unwrap();
        let plan = build_plan(
            &source,
            &operation,
            PlanOptions {
                input: Some(serde_json::json!({"name":"accepted"})),
                ..PlanOptions::default()
            },
        )
        .unwrap();
        assert_eq!(plan.body.unwrap().inline, r#"{"name":"accepted"}"#);
        document["paths"]["/items"]["post"]["requestBody"]["content"]["application/json"]["schema"]
            ["additionalProperties"] = Value::Bool(false);
        let bytes = serde_json::to_vec(&document).unwrap();
        let source = load_openapi(Path::new("closed.json"), &bytes).unwrap();
        let operation = resolve_operation(&source, "createItem").unwrap();
        assert!(matches!(
            build_plan(
                &source,
                &operation,
                PlanOptions {
                    input: Some(serde_json::json!({"name":"rejected"})),
                    ..PlanOptions::default()
                }
            ),
            Err(PlanError::UnknownInput(_))
        ));
    }

    #[test]
    fn production_write_policy_is_part_of_the_sealed_plan() {
        let (source, operation) = source_and_operation();
        let configuration: ProjectConfiguration = toml::from_str(
            r#"
version = 1
[defaults]
server = "production"
[servers.production]
url = "https://api.example.test"
classification = "production"
[policy]
allowed_hosts = ["api.example.test"]
"#,
        )
        .unwrap();
        let plan = build_plan_with_configuration(
            &source,
            &operation,
            PlanOptions {
                input: Some(serde_json::json!({
                    "path": { "id": "inv-1" },
                    "body": { "amount": 1 }
                })),
                ..PlanOptions::default()
            },
            &configuration,
        )
        .unwrap();
        assert_eq!(
            plan.target,
            "https://api.example.test/invoices/inv-1?notify=false"
        );
        assert!(
            plan.required_grants
                .contains(&"approve:production-write".into())
        );
        assert_ne!(plan.config_fingerprint, default_config_fingerprint());
    }

    #[test]
    fn multipart_file_upload_bytes_are_sealed_into_the_plan() {
        let root = std::env::temp_dir().join(format!("kahea-upload-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let upload = root.join("sample.bin");
        fs::write(&upload, [0_u8, 1, 2, 255]).unwrap();
        let spec = r#"
openapi: 3.1.0
info: { title: Upload, version: 1 }
servers: [{ url: "https://upload.example.test" }]
paths:
  /files:
    post:
      operationId: uploadFile
      requestBody:
        required: true
        content:
          multipart/form-data:
            schema:
              type: object
              required: [file]
              properties:
                file: { type: string, format: binary }
                label: { type: string }
      responses: { "201": { description: created } }
"#;
        let source = load_openapi(Path::new("upload.yaml"), spec.as_bytes()).unwrap();
        let operation = resolve_operation(&source, "uploadFile").unwrap();
        let plan = build_plan(
            &source,
            &operation,
            PlanOptions {
                input: Some(serde_json::json!({"body":{
                    "file":{"$file":upload,"filename":"sample.bin"},
                    "label":"fixture"
                }})),
                ..PlanOptions::default()
            },
        )
        .unwrap();
        let body = plan.body.unwrap();
        assert_eq!(body.encoding, "base64");
        let wire = base64::engine::general_purpose::STANDARD
            .decode(body.inline)
            .unwrap();
        assert!(wire.windows(4).any(|window| window == [0, 1, 2, 255]));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn versioned_configuration_loads_external_policy_and_rejects_inline_secrets() {
        let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/config.toml");
        let configuration = ProjectConfiguration::load(&example).unwrap();
        assert_eq!(configuration.defaults.server.as_deref(), Some("sandbox"));
        assert_eq!(
            configuration.policy.redact_response_json_pointers,
            ["/customer/email", "/payment/card"]
        );
        assert_eq!(
            configuration.auth["billing-sandbox"].token.as_deref(),
            Some("secret://billing/sandbox")
        );
        assert_eq!(
            configuration.policy.websocket.allowed_origins,
            ["https://client.example.test"]
        );
        assert_eq!(
            configuration.policy.websocket.allowed_subprotocols,
            ["kahea.events.v1"]
        );
        assert_eq!(
            configuration.policy.websocket.max_limits.max_outbound_bytes,
            67_108_864
        );

        let root = std::env::temp_dir().join(format!("kahea-config-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("config.toml");
        fs::write(
            &path,
            "version=1\n[auth.bad]\ntype='bearer'\ntoken='inline-value'\n",
        )
        .unwrap();
        assert!(ProjectConfiguration::load(&path).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn explicit_fields_and_every_input_location_are_lossless_and_strict() {
        assert_eq!(
            parse_explicit_field("query.limit=3").unwrap(),
            ("query.limit".into(), json!(3))
        );
        assert_eq!(
            parse_explicit_field("header.X-Mode=fast").unwrap().1,
            "fast"
        );
        assert!(parse_explicit_field("missing-location").is_err());
        assert!(parse_explicit_field("body.=1").is_err());

        let mut inputs = Inputs::from_options(
            Some(json!({
                "path":{"id":"one"},
                "query":{"limit":2},
                "headers":{"X-Mode":"safe"},
                "cookies":{"session":"abc"},
                "body":{"name":"fixture"}
            })),
            &[
                ("query.limit".into(), json!(3)),
                ("body.nested.value".into(), json!(true)),
            ],
        )
        .unwrap();
        assert_eq!(inputs.take("path", "id").unwrap().0, "one");
        assert_eq!(inputs.take("query", "limit").unwrap().0, 3);
        assert_eq!(inputs.take("header", "X-Mode").unwrap().0, "safe");
        assert_eq!(inputs.take("cookie", "session").unwrap().0, "abc");
        assert_eq!(inputs.body.as_ref().unwrap()["nested"]["value"], true);
        assert!(inputs.reject_unused().is_ok());

        let unused = Inputs::from_options(Some(json!({"query":{"invented":1}})), &[]).unwrap();
        assert!(matches!(
            unused.reject_unused(),
            Err(PlanError::UnknownInput(_))
        ));
        let mut scalar_parent = Some(json!({"parent":1}));
        assert!(insert_body_value(&mut scalar_parent, "parent.child", json!(2)).is_err());
    }

    #[test]
    fn body_serializers_cover_text_forms_binary_and_multipart_metadata_safety() {
        let (_, json_bytes, encoding, _, transform) =
            serialize_body("application/problem+json", &json!({"b":2,"a":1})).unwrap();
        assert_eq!(json_bytes, br#"{"a":1,"b":2}"#);
        assert_eq!(encoding, "utf-8");
        assert_eq!(transform, "canonical-json");
        assert_eq!(
            serialize_body("text/plain", &json!("hello")).unwrap().1,
            b"hello"
        );
        assert_eq!(
            serialize_body("application/x-www-form-urlencoded", &json!({"a":"x y"}))
                .unwrap()
                .1,
            b"a=x+y"
        );
        assert_eq!(
            serialize_body("application/octet-stream", &json!("AAEC/w=="))
                .unwrap()
                .1,
            [0, 1, 2, 255]
        );
        assert!(serialize_body("text/plain", &json!({"not":"text"})).is_err());
        assert!(reject_multipart_token("bad\r\nname", "name").is_err());
        assert!(reject_multipart_token("bad\"name", "name").is_err());
        assert!(reject_multipart_token("safe-name", "name").is_ok());
    }

    #[test]
    fn authentication_schemes_bind_to_exact_nonsecret_metadata() {
        let document = json!({
            "openapi":"3.1.0","info":{"title":"auth","version":"1"},
            "servers":[{"url":"https://api.example.test"}],
            "paths":{"/auth":{"get":{"operationId":"auth","responses":{"200":{"description":"ok"}}}}},
            "components":{"securitySchemes":{
                "key":{"type":"apiKey","in":"header","name":"X-Key"},
                "basic":{"type":"http","scheme":"basic"},
                "oauth":{"type":"oauth2","flows":{"clientCredentials":{"tokenUrl":"https://auth.example.test/token","scopes":{}}}},
                "oidc":{"type":"openIdConnect","openIdConnectUrl":"https://auth.example.test/.well-known"},
                "mtls":{"type":"mutualTLS"}
            }}
        });
        let bytes = serde_json::to_vec(&document).unwrap();
        let source = OpenApiSource {
            document,
            source_fingerprint: digest(&bytes),
            source_handle: "src:test".into(),
        };
        let mut operation = resolve_operation(&source, "auth").unwrap();
        for (scheme, placement) in [
            ("key", "header:X-Key"),
            ("basic", "header:Authorization:basic"),
            ("oauth", "oauth2-client-credentials"),
            ("oidc", "header:Authorization:bearer"),
            ("mtls", "tls-client-certificate"),
        ] {
            operation.operation.insert(
                "security".into(),
                Value::Array(vec![Value::Object(Map::from_iter([(
                    scheme.into(),
                    json!([]),
                )]))]),
            );
            let (auth, refs) =
                bind_auth(&source, &operation, Some(&format!("{scheme}=profile"))).unwrap();
            let auth = auth.unwrap();
            assert_eq!(auth.scheme, scheme);
            assert_eq!(auth.placement, placement);
            assert_eq!(auth.profile, "profile");
            assert_eq!(refs, ["secret://profile"]);
            assert!(
                !serde_json::to_string(&auth)
                    .unwrap()
                    .contains("credential-value")
            );
        }
        operation
            .operation
            .insert("security".into(), json!([{"key":[]} ]));
        assert!(bind_auth(&source, &operation, None).is_err());
        assert!(bind_auth(&source, &operation, Some("unknown=profile")).is_err());
    }

    #[test]
    fn schema_validation_refs_types_and_parameter_serialization_fail_closed() {
        let document = json!({
            "openapi":"3.1.0","info":{"title":"types","version":"1"},"paths":{},
            "components":{"schemas":{"Name":{"type":"string"}}}
        });
        let bytes = serde_json::to_vec(&document).unwrap();
        let source = OpenApiSource {
            document,
            source_fingerprint: digest(&bytes),
            source_handle: "src:test".into(),
        };
        assert_eq!(
            resolve_ref(&source, "#/components/schemas/Name").unwrap()["type"],
            "string"
        );
        assert!(resolve_ref(&source, "other.yaml#/Name").is_none());
        for (kind, valid, invalid) in [
            ("null", Value::Null, json!(false)),
            ("boolean", json!(true), json!(1)),
            ("integer", json!(1), json!(1.5)),
            ("number", json!(1.5), json!("1.5")),
            ("string", json!("x"), json!([])),
            ("array", json!([]), json!({})),
            ("object", json!({}), json!([])),
        ] {
            validate_value(&source, &json!({"type":kind}), &valid, kind).unwrap();
            let error = validate_value(&source, &json!({"type":kind}), &invalid, kind).unwrap_err();
            assert!(error.to_string().contains("expected"));
            assert!(error.to_string().contains(value_kind(&invalid)));
        }
        validate_value(
            &source,
            &json!({"type":["string","null"]}),
            &Value::Null,
            "union",
        )
        .unwrap();
        validate_value(
            &source,
            &json!({"$ref":"#/components/schemas/Name"}),
            &json!("ok"),
            "ref",
        )
        .unwrap();
        assert!(validate_value(&source, &json!({"$ref":"#/missing"}), &json!("x"), "ref").is_err());

        let exploded = wire_values(
            &json!([1, 2]),
            &Map::from_iter([("explode".into(), json!(true))]),
        )
        .unwrap();
        assert_eq!(exploded, ["1", "2"]);
        let compact = wire_values(
            &json!([1, 2]),
            &Map::from_iter([("explode".into(), json!(false))]),
        )
        .unwrap();
        assert_eq!(compact, ["1,2"]);
        assert_eq!(scalar_wire(&Value::Null).unwrap(), "");
        assert_eq!(scalar_wire(&json!(1.5)).unwrap(), "1.5");
        assert!(scalar_wire(&json!({})).is_err());
    }

    #[test]
    fn server_network_check_and_pointer_helpers_cover_security_boundaries() {
        let (source, operation) = source_and_operation();
        let configuration = ProjectConfiguration::default();
        assert_eq!(
            select_server(&source, &operation, None, &configuration).unwrap(),
            "https://sandbox.example.test/v1"
        );
        assert_eq!(
            select_server(
                &source,
                &operation,
                Some("https://other.example/v2"),
                &configuration
            )
            .unwrap(),
            "https://other.example/v2"
        );
        assert!(build_target("ftp://example.test", "/x").is_err());
        assert!(build_target("https://user:pass@example.test", "/x").is_err());
        assert!(build_target("https://example.test", "/x").is_ok());
        for address in [
            "127.0.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "10.0.0.1",
            "169.254.1.1",
            "::1",
            "fc00::1",
            "fe80::1",
        ] {
            assert!(is_unsafe_address(address.parse().unwrap()), "{address}");
        }
        for address in ["8.8.8.8", "2606:4700:4700::1111"] {
            assert!(!is_unsafe_address(address.parse().unwrap()), "{address}");
        }
        assert_eq!(escape_pointer("a~/b"), "a~0~1b");
        assert_eq!(
            default_checks(&operation),
            ["response-schema:openapi", "status:any(200)"]
        );
    }

    #[test]
    fn configuration_and_policy_fingerprints_are_content_sensitive() {
        let default = ProjectConfiguration::default();
        assert_eq!(
            default.config_fingerprint().unwrap(),
            default_config_fingerprint()
        );
        let mut configured = ProjectConfiguration {
            version: 1,
            ..ProjectConfiguration::default()
        };
        configured.defaults.server = Some("sandbox".into());
        let first = configured.config_fingerprint().unwrap();
        assert!(first.starts_with("b3:"));
        assert_ne!(first, default_config_fingerprint());
        assert!(self_as_value(&configured).unwrap().is_object());
        let policy = configured.policy_fingerprint().unwrap();
        configured
            .policy
            .allowed_hosts
            .push("api.example.test".into());
        assert_ne!(policy, configured.policy_fingerprint().unwrap());
    }

    #[test]
    fn stored_plan_loader_rechecks_both_material_and_identity() {
        let (source, operation) = source_and_operation();
        let plan = build_plan(
            &source,
            &operation,
            PlanOptions {
                input: Some(json!({"path":{"id":"one"},"body":{"amount":1}})),
                ..PlanOptions::default()
            },
        )
        .unwrap();
        let root = std::env::temp_dir().join(format!("kahea-plan-store-{}", std::process::id()));
        let path = store_plan(&root, &plan).unwrap();
        assert_eq!(load_plan(&root, &plan.id).unwrap().id, plan.id);
        let mut tampered: RequestPlan = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        tampered.id = "plan:000000000000".into();
        fs::write(&path, serde_json::to_vec(&tampered).unwrap()).unwrap();
        assert!(matches!(
            load_plan(&root, &plan.id),
            Err(PlanError::InvalidSeal)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn complete_wire_plan_covers_all_locations_grants_and_policy_edges() {
        let spec = r#"
openapi: 3.1.0
info: { title: Complete, version: 1 }
servers: [{ url: "http://127.0.0.1:8080" }]
paths:
  /things/{id}:
    delete:
      operationId: deleteThing
      security: [{ key: [] }]
      parameters:
        - { name: id, in: path, schema: { type: string } }
        - { name: tags, in: query, required: true, explode: false, schema: { type: array, items: { type: string } } }
        - { name: X-Mode, in: header, required: true, schema: { type: string } }
        - { name: sid, in: cookie, required: true, schema: { type: string } }
      requestBody:
        required: true
        content:
          text/plain: { schema: { type: string } }
      responses: { "204": { description: deleted } }
components:
  securitySchemes:
    key: { type: apiKey, in: header, name: X-Key }
"#;
        let source = load_openapi(Path::new("complete.yaml"), spec.as_bytes()).unwrap();
        let operation = resolve_operation(&source, "deleteThing").unwrap();
        let options = PlanOptions {
            input: Some(json!({
                "path":{"id":"a/b"},
                "query":{"tags":["one","two"]},
                "header":{"X-Mode":"strict"},
                "cookie":{"sid":"cookie-1"},
                "body":"abc"
            })),
            auth: Some("key=fixture-profile".into()),
            ..PlanOptions::default()
        };
        let mut configuration = ProjectConfiguration::default();
        configuration.policy.max_request_bytes = 3;
        configuration.policy.allowed_hosts = vec!["127.0.0.1".into()];
        configuration.policy.sensitive_headers = vec!["X-Private".into()];
        configuration.policy.redact_response_json_pointers = vec!["/secret".into()];
        let plan =
            build_plan_with_configuration(&source, &operation, options.clone(), &configuration)
                .unwrap();
        assert_eq!(
            plan.target,
            "http://127.0.0.1:8080/things/a%2Fb?tags=one%2Ctwo"
        );
        assert!(
            plan.headers
                .iter()
                .any(|header| header.name == "X-Mode" && header.value == "strict")
        );
        assert!(
            plan.headers
                .iter()
                .any(|header| header.name == "Cookie" && header.value == "sid=cookie-1")
        );
        for grant in [
            "net:127.0.0.1:8080",
            "http:DELETE",
            "net-insecure-http",
            "net-cidr:127.0.0.1/32",
            "approve:destructive",
            "secret:fixture-profile",
        ] {
            assert!(plan.required_grants.contains(&grant.into()), "{grant}");
        }
        assert_eq!(plan.sensitive_headers, ["X-Private"]);
        assert_eq!(plan.redact_response_json_pointers, ["/secret"]);
        assert_eq!(plan.body.as_ref().unwrap().bytes, 3);
        assert_eq!(plan.checks, ["response-schema:openapi", "status:any(204)"]);

        configuration.policy.max_request_bytes = 2;
        assert!(matches!(
            build_plan_with_configuration(&source, &operation, options.clone(), &configuration),
            Err(PlanError::PolicyDenied(_))
        ));
        configuration.policy.max_request_bytes = 3;
        configuration.policy.allowed_hosts = vec!["other.example".into()];
        assert!(matches!(
            build_plan_with_configuration(&source, &operation, options.clone(), &configuration),
            Err(PlanError::PolicyDenied(_))
        ));
        configuration.policy.allowed_hosts.clear();
        configuration.policy.denied_hosts = vec!["127.0.0.1".into()];
        assert!(matches!(
            build_plan_with_configuration(&source, &operation, options.clone(), &configuration),
            Err(PlanError::PolicyDenied(_))
        ));
        configuration.policy.denied_hosts.clear();
        configuration.policy.redact_response_json_pointers = vec!["not-a-pointer".into()];
        assert!(matches!(
            build_plan_with_configuration(&source, &operation, options.clone(), &configuration),
            Err(PlanError::Configuration(_))
        ));
        configuration.policy.redact_response_json_pointers = vec!["/ok".into()];
        configuration.policy.sensitive_headers = vec![String::new()];
        assert!(matches!(
            build_plan_with_configuration(&source, &operation, options, &configuration),
            Err(PlanError::Configuration(_))
        ));
    }

    #[test]
    fn parameter_shape_requiredness_and_optional_absence_are_distinct() {
        let malformed = r#"
openapi: 3.1.0
info: { title: Parameters, version: 1 }
servers: [{ url: "https://api.example.test" }]
paths:
  /things/{id}:
    get:
      operationId: malformedParameters
      parameters:
        - { in: query, required: true, schema: { type: string } }
        - { name: ignored, schema: { type: string } }
        - { name: id, in: path, schema: { type: string } }
        - { name: optional, in: query, schema: { type: string } }
      responses: { "200": { description: ok } }
"#;
        let source = load_openapi(Path::new("parameters.yaml"), malformed.as_bytes()).unwrap();
        let operation = resolve_operation(&source, "malformedParameters").unwrap();
        assert!(matches!(
            build_plan(&source, &operation, PlanOptions::default()),
            Err(PlanError::MissingParameter { location, name })
                if location == "path" && name == "id"
        ));
        let plan = build_plan(
            &source,
            &operation,
            PlanOptions {
                input: Some(json!({"path":{"id":"one"}})),
                ..PlanOptions::default()
            },
        )
        .unwrap();
        assert_eq!(plan.target, "https://api.example.test/things/one");
    }

    #[test]
    fn production_matching_auth_grants_and_policy_boundaries_are_exact() {
        let auth_spec = r#"
openapi: 3.1.0
info: { title: Auth grants, version: 1 }
servers: [{ url: "https://api.example.test" }]
paths:
  /oauth:
    post:
      operationId: oauthWrite
      security: [{ oauth: [] }]
      responses: { "204": { description: ok } }
  /mtls:
    get:
      operationId: mtlsRead
      security: [{ mtls: [] }]
      responses: { "200": { description: ok } }
  /optional:
    get:
      operationId: optionalAuth
      responses: { "200": { description: ok } }
components:
  securitySchemes:
    oauth:
      type: oauth2
      flows:
        clientCredentials:
          tokenUrl: http://auth.example.test/token
          scopes: {}
    mtls: { type: mutualTLS }
"#;
        let source = load_openapi(Path::new("auth-grants.yaml"), auth_spec.as_bytes()).unwrap();
        let oauth = build_plan(
            &source,
            &resolve_operation(&source, "oauthWrite").unwrap(),
            PlanOptions {
                auth: Some("oauth=oauth-profile".into()),
                ..PlanOptions::default()
            },
        )
        .unwrap();
        for grant in [
            "secret:oauth-profile",
            "net:auth.example.test:80",
            "http:POST",
            "net-insecure-http",
        ] {
            assert!(oauth.required_grants.contains(&grant.into()), "{grant}");
        }
        let mtls = build_plan(
            &source,
            &resolve_operation(&source, "mtlsRead").unwrap(),
            PlanOptions {
                auth: Some("mtls=certificate-profile".into()),
                ..PlanOptions::default()
            },
        )
        .unwrap();
        assert!(
            mtls.required_grants
                .contains(&"tls-client-cert:certificate-profile".into())
        );
        let optional = resolve_operation(&source, "optionalAuth").unwrap();
        assert!(bind_auth(&source, &optional, Some("mtls=profile")).is_ok());

        let (_, operation) = source_and_operation();
        let mut configuration = ProjectConfiguration::default();
        configuration.servers.insert(
            "matching-non-production".into(),
            ConfiguredServer {
                url: "https://sandbox.example.test/v1".into(),
                classification: Some("sandbox".into()),
            },
        );
        configuration.servers.insert(
            "other-production".into(),
            ConfiguredServer {
                url: "https://other.example.test".into(),
                classification: Some("production".into()),
            },
        );
        let source = source_and_operation().0;
        let plan = build_plan_with_configuration(
            &source,
            &operation,
            PlanOptions {
                input: Some(json!({"path":{"id":"one"},"body":{"amount":1}})),
                ..PlanOptions::default()
            },
            &configuration,
        )
        .unwrap();
        assert!(
            !plan
                .required_grants
                .contains(&"approve:production-write".into())
        );

        let boundary = "/".to_string() + &"a".repeat(2_047);
        configuration.policy.redact_response_json_pointers = vec![boundary];
        assert!(
            build_plan_with_configuration(
                &source,
                &operation,
                PlanOptions {
                    input: Some(json!({"path":{"id":"one"},"body":{"amount":1}})),
                    ..PlanOptions::default()
                },
                &configuration,
            )
            .is_ok()
        );
        configuration.policy.redact_response_json_pointers =
            vec!["/".to_string() + &"a".repeat(2_048)];
        assert!(matches!(
            build_plan_with_configuration(
                &source,
                &operation,
                PlanOptions {
                    input: Some(json!({"path":{"id":"one"},"body":{"amount":1}})),
                    ..PlanOptions::default()
                },
                &configuration,
            ),
            Err(PlanError::Configuration(_))
        ));
    }

    #[test]
    fn schema_edge_cases_distinguish_descriptor_union_enum_and_unsigned_values() {
        let (source, _) = source_and_operation();
        let binary = json!({"type":"string","format":"binary"});
        validate_value(&source, &binary, &json!({"$file":"file.bin"}), "file").unwrap();
        validate_value(
            &source,
            &binary,
            &json!({"$file":"file.bin","filename":"name.bin","content_type":"application/octet-stream"}),
            "file",
        )
        .unwrap();
        for invalid in [
            json!({"$file":1}),
            json!({"$file":"file.bin","filename":1}),
            json!({"$file":"file.bin","content_type":1}),
        ] {
            assert!(validate_value(&source, &binary, &invalid, "file").is_err());
        }

        assert!(
            validate_value(
                &source,
                &json!({"type":"string","nullable":true}),
                &json!(7),
                "nullable",
            )
            .is_err()
        );
        assert!(
            validate_value(
                &source,
                &json!({"type":"string","nullable":false}),
                &Value::Null,
                "nullable",
            )
            .is_err()
        );
        validate_value(&source, &json!({"enum":["a","b"]}), &json!("a"), "enum").unwrap();
        assert!(validate_value(&source, &json!({"enum":["a","b"]}), &json!("c"), "enum",).is_err());
        assert!(
            validate_value(
                &source,
                &json!({"type":["string","null"]}),
                &json!({}),
                "union",
            )
            .is_err()
        );
        validate_value(
            &source,
            &json!({"type":"integer"}),
            &json!(u64::MAX),
            "unsigned",
        )
        .unwrap();
        let error =
            validate_value(&source, &json!({"type":"string"}), &json!([]), "kind").unwrap_err();
        assert!(error.to_string().contains("received array"));
        validate_value(
            &source,
            &json!({
                "type":"object",
                "required":["server_id"],
                "properties":{"server_id":{"type":"string","readOnly":true}}
            }),
            &json!({}),
            "request",
        )
        .unwrap();
        assert!(
            validate_value(
                &source,
                &json!({
                    "type":"object",
                    "required":["client_id"],
                    "properties":{"client_id":{"type":"string"}}
                }),
                &json!({}),
                "request",
            )
            .is_err()
        );
    }

    #[test]
    fn server_selection_and_each_userinfo_form_are_unambiguous() {
        let spec = r#"
openapi: 3.1.0
info: { title: Servers, version: 1 }
servers:
  - { url: "https://one.example.test", description: primary }
  - { url: "https://two.example.test", description: secondary }
paths:
  /health:
    get:
      operationId: health
      responses: { "200": { description: ok } }
"#;
        let source = load_openapi(Path::new("servers.yaml"), spec.as_bytes()).unwrap();
        let operation = resolve_operation(&source, "health").unwrap();
        let configuration = ProjectConfiguration::default();
        assert_eq!(
            select_server(
                &source,
                &operation,
                Some("https://one.example.test"),
                &configuration,
            )
            .unwrap(),
            "https://one.example.test"
        );
        assert_eq!(
            select_server(&source, &operation, Some("secondary"), &configuration).unwrap(),
            "https://two.example.test"
        );
        assert!(matches!(
            select_server(&source, &operation, Some("missing"), &configuration),
            Err(PlanError::UnknownServer(_))
        ));
        assert!(build_target("https://user@example.test", "/x").is_err());
        assert!(build_target("https://:password@example.test", "/x").is_err());
    }
}
