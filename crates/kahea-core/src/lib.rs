//! Stable domain types and canonical `kahea/k1` protocol envelopes.

use base64::Engine;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{self, Write};

pub const PROTOCOL: &str = "kahea/k1";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DEFAULT_OPERATION_LIMIT: usize = 50;

pub fn digest(bytes: &[u8]) -> String {
    format!("b3:{}", blake3::hash(bytes).to_hex())
}

pub fn short_handle(kind: &str, parts: &[&[u8]]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kahea/k1\0");
    hasher.update(kind.as_bytes());
    for part in parts {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    let hex = hasher.finalize().to_hex();
    format!("{kind}:{}", &hex.as_str()[..12])
}

pub fn default_config_fingerprint() -> String {
    digest(b"kahea/default-config/v1")
}

pub fn write_envelope<T: Serialize>(value: &T) -> io::Result<()> {
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer(&mut lock, value)?;
    lock.write_all(b"\n")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum RiskClass {
    Read,
    Write,
    Destructive,
    Unknown,
}

impl RiskClass {
    pub fn for_http_method(method: &str) -> Self {
        match method {
            "GET" | "HEAD" | "OPTIONS" | "QUERY" => Self::Read,
            "POST" | "PUT" | "PATCH" => Self::Write,
            "DELETE" => Self::Destructive,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AbsentCapability {
    pub capability: String,
    pub reason: String,
    pub location: String,
    pub severity: DiagnosticSeverity,
    pub blocking: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OperationSummary(
    pub String,
    pub String,
    pub String,
    pub String,
    pub RiskClass,
);

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OperationIndexEnvelope {
    pub protocol: String,
    pub kind: String,
    pub version: String,
    pub config_fingerprint: String,
    pub source_fingerprints: Vec<String>,
    pub source: String,
    pub operations: Vec<OperationSummary>,
    pub next: Option<String>,
    pub absent: Vec<AbsentCapability>,
    pub exit: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ApiGraphEnvelope {
    pub protocol: String,
    pub kind: String,
    pub version: String,
    pub config_fingerprint: String,
    pub source_fingerprints: Vec<String>,
    pub source: String,
    pub operation_count: usize,
    pub absent: Vec<AbsentCapability>,
    pub exit: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PlannedBody {
    pub media_type: String,
    pub bytes: u64,
    pub blake3: String,
    pub encoding: String,
    pub inline: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PlannedHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PlannedAuth {
    pub scheme: String,
    pub kind: String,
    pub profile: String,
    pub placement: String,
    pub token_url: Option<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FieldDerivation {
    pub field: String,
    pub source: String,
    pub source_location: String,
    pub logical_value: Value,
    pub wire_value: Option<String>,
    pub transformations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RequestPlan {
    pub protocol: String,
    pub kind: String,
    pub version: String,
    pub config_fingerprint: String,
    pub policy_fingerprint: String,
    pub source_fingerprints: Vec<String>,
    pub id: String,
    pub operation: String,
    pub target: String,
    pub method: String,
    pub risk: RiskClass,
    pub required_grants: Vec<String>,
    pub secret_refs: Vec<String>,
    pub headers: Vec<PlannedHeader>,
    pub auth: Option<PlannedAuth>,
    pub body: Option<PlannedBody>,
    pub checks: Vec<String>,
    pub response_contract: Value,
    pub sensitive_headers: Vec<String>,
    pub redact_response_json_pointers: Vec<String>,
    pub derivations: Vec<FieldDerivation>,
    pub valid: bool,
    pub fingerprint: String,
    pub exit: u8,
}

impl RequestPlan {
    pub fn seal(mut self) -> Result<Self, serde_json::Error> {
        self.id.clear();
        self.fingerprint.clear();
        let bytes = serde_json::to_vec(&self)?;
        self.fingerprint = digest(&bytes);
        self.id = short_handle("plan", &[self.fingerprint.as_bytes()]);
        Ok(self)
    }

    pub fn verify_seal(&self) -> Result<bool, serde_json::Error> {
        let mut material = self.clone();
        material.id.clear();
        material.fingerprint.clear();
        let expected = digest(&serde_json::to_vec(&material)?);
        Ok(expected == self.fingerprint
            && self.id == short_handle("plan", &[self.fingerprint.as_bytes()]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebSocketLimits {
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WebSocketAction {
    SendText {
        text: String,
    },
    SendBinary {
        payload_base64: String,
    },
    ExpectText {
        equals: String,
        timeout_ms: Option<u64>,
    },
    ExpectBinary {
        payload_base64: String,
        timeout_ms: Option<u64>,
    },
    ExpectJson {
        pointer: Option<String>,
        equals: Option<Value>,
        schema: Option<Value>,
        timeout_ms: Option<u64>,
    },
    Ping {
        payload_base64: String,
    },
    ExpectPong {
        payload_base64: String,
        timeout_ms: Option<u64>,
    },
    Close {
        code: u16,
        reason: String,
    },
    ExpectClose {
        codes: Vec<u16>,
        reason: Option<String>,
        timeout_ms: Option<u64>,
    },
}

#[derive(Debug)]
pub enum WebSocketPlanError {
    Invalid(String),
    Serialization(serde_json::Error),
}

impl std::fmt::Display for WebSocketPlanError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) => write!(formatter, "invalid WebSocket plan: {reason}"),
            Self::Serialization(error) => write!(formatter, "serialize WebSocket plan: {error}"),
        }
    }
}

impl std::error::Error for WebSocketPlanError {}

impl From<serde_json::Error> for WebSocketPlanError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebSocketSessionSource {
    pub kind: String,
    pub version: u32,
    pub operation_id: String,
    pub url: String,
    #[serde(default)]
    pub risk: Option<RiskClass>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub auth: Option<String>,
    #[serde(default)]
    pub origin: Option<String>,
    #[serde(default)]
    pub subprotocols: Vec<String>,
    pub limits: WebSocketLimits,
    pub actions: Vec<WebSocketAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WebSocketPlan {
    pub protocol: String,
    pub kind: String,
    pub version: String,
    pub config_fingerprint: String,
    pub policy_fingerprint: String,
    pub source_fingerprints: Vec<String>,
    pub id: String,
    pub operation: String,
    pub target: String,
    pub risk: RiskClass,
    pub required_grants: Vec<String>,
    pub secret_refs: Vec<String>,
    pub headers: Vec<PlannedHeader>,
    pub auth: Option<PlannedAuth>,
    pub origin: Option<String>,
    pub subprotocols: Vec<String>,
    pub handshake_checks: Vec<String>,
    pub limits: WebSocketLimits,
    pub actions: Vec<WebSocketAction>,
    pub sensitive_headers: Vec<String>,
    pub redact_response_json_pointers: Vec<String>,
    pub valid: bool,
    pub fingerprint: String,
    pub exit: u8,
}

impl WebSocketPlan {
    pub fn seal(mut self) -> Result<Self, WebSocketPlanError> {
        self.normalize();
        self.validate()?;
        self.id.clear();
        self.fingerprint.clear();
        self.fingerprint = digest(&serde_json::to_vec(&self)?);
        self.id = short_handle("plan", &[self.fingerprint.as_bytes()]);
        Ok(self)
    }

    pub fn verify_seal(&self) -> Result<bool, serde_json::Error> {
        let mut material = self.clone();
        material.id.clear();
        material.fingerprint.clear();
        let expected = digest(&serde_json::to_vec(&material)?);
        Ok(expected == self.fingerprint
            && self.id == short_handle("plan", &[self.fingerprint.as_bytes()]))
    }

    pub fn validate(&self) -> Result<(), WebSocketPlanError> {
        if self.protocol != PROTOCOL
            || self.kind != "websocket-plan"
            || !self.valid
            || self.exit != 0
        {
            return Err(WebSocketPlanError::Invalid(
                "protocol, kind, valid, or exit marker is inconsistent".into(),
            ));
        }
        if self.actions.is_empty() {
            return Err(WebSocketPlanError::Invalid("actions are empty".into()));
        }
        validate_websocket_limits(&self.limits)?;
        validate_websocket_headers(&self.headers)?;
        validate_subprotocols(&self.subprotocols)?;

        let mut terminal_count = 0usize;
        let mut outbound_frames = 0u64;
        let mut outbound_messages = 0u64;
        let mut outbound_bytes = 0u64;
        for (index, action) in self.actions.iter().enumerate() {
            let (frames, messages, bytes, terminal) =
                validate_websocket_action(action, &self.limits)?;
            outbound_frames = outbound_frames.checked_add(frames).ok_or_else(|| {
                WebSocketPlanError::Invalid("outbound frame count overflow".into())
            })?;
            outbound_messages = outbound_messages.checked_add(messages).ok_or_else(|| {
                WebSocketPlanError::Invalid("outbound message count overflow".into())
            })?;
            outbound_bytes = outbound_bytes.checked_add(bytes).ok_or_else(|| {
                WebSocketPlanError::Invalid("outbound byte count overflow".into())
            })?;
            if terminal {
                terminal_count += 1;
                if index + 1 != self.actions.len() {
                    return Err(WebSocketPlanError::Invalid(
                        "the terminal close action must be last".into(),
                    ));
                }
            }
        }
        if terminal_count != 1 {
            return Err(WebSocketPlanError::Invalid(
                "exactly one terminal close action is required".into(),
            ));
        }
        if outbound_frames > self.limits.max_outbound_frames
            || outbound_messages > self.limits.max_outbound_messages
            || outbound_bytes > self.limits.max_outbound_bytes
        {
            return Err(WebSocketPlanError::Invalid(
                "sealed outbound actions exceed the session limits".into(),
            ));
        }
        Ok(())
    }

    fn normalize(&mut self) {
        self.required_grants.sort();
        self.required_grants.dedup();
        self.secret_refs.sort();
        self.secret_refs.dedup();
        self.handshake_checks.sort();
        self.handshake_checks.dedup();
        for value in &mut self.sensitive_headers {
            value.make_ascii_lowercase();
        }
        self.sensitive_headers.sort();
        self.sensitive_headers.dedup();
        self.redact_response_json_pointers.sort();
        self.redact_response_json_pointers.dedup();
        self.headers.sort_by(|left, right| {
            left.name
                .to_ascii_lowercase()
                .cmp(&right.name.to_ascii_lowercase())
                .then_with(|| left.name.cmp(&right.name))
        });
        for action in &mut self.actions {
            if let WebSocketAction::ExpectClose { codes, .. } = action {
                codes.sort_unstable();
                codes.dedup();
            }
        }
    }
}

fn validate_websocket_limits(limits: &WebSocketLimits) -> Result<(), WebSocketPlanError> {
    let values = [
        limits.connect_timeout_ms,
        limits.action_timeout_ms,
        limits.idle_timeout_ms,
        limits.close_timeout_ms,
        limits.total_timeout_ms,
        limits.max_frame_bytes,
        limits.max_message_bytes,
        limits.max_inbound_frames,
        limits.max_outbound_frames,
        limits.max_inbound_messages,
        limits.max_outbound_messages,
        limits.max_inbound_bytes,
        limits.max_outbound_bytes,
    ];
    if values.contains(&0) {
        return Err(WebSocketPlanError::Invalid(
            "all session limits must be positive".into(),
        ));
    }
    if limits.max_message_bytes < limits.max_frame_bytes
        || limits.connect_timeout_ms > limits.total_timeout_ms
        || limits.action_timeout_ms > limits.total_timeout_ms
        || limits.idle_timeout_ms > limits.total_timeout_ms
        || limits.close_timeout_ms > limits.total_timeout_ms
    {
        return Err(WebSocketPlanError::Invalid(
            "session limits contradict their total or frame bounds".into(),
        ));
    }
    Ok(())
}

fn validate_websocket_headers(headers: &[PlannedHeader]) -> Result<(), WebSocketPlanError> {
    let protocol_owned = [
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
    let mut names = std::collections::BTreeSet::new();
    for header in headers {
        let name = header.name.to_ascii_lowercase();
        if !valid_token(&header.name)
            || header.name.contains(['\r', '\n'])
            || header.value.contains(['\r', '\n'])
        {
            return Err(WebSocketPlanError::Invalid(
                "invalid handshake header".into(),
            ));
        }
        if protocol_owned.contains(&name.as_str()) {
            return Err(WebSocketPlanError::Invalid(format!(
                "header {:?} is owned by the WebSocket transport",
                header.name
            )));
        }
        if !names.insert(name) {
            return Err(WebSocketPlanError::Invalid(
                "duplicate handshake header".into(),
            ));
        }
    }
    Ok(())
}

fn validate_subprotocols(subprotocols: &[String]) -> Result<(), WebSocketPlanError> {
    let mut seen = std::collections::BTreeSet::new();
    for protocol in subprotocols {
        if !valid_token(protocol) || !seen.insert(protocol) {
            return Err(WebSocketPlanError::Invalid(
                "subprotocols must be unique RFC tokens".into(),
            ));
        }
    }
    Ok(())
}

fn valid_token(value: &str) -> bool {
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

fn decode_canonical_base64(value: &str) -> Result<Vec<u8>, WebSocketPlanError> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| WebSocketPlanError::Invalid("payload is not valid base64".into()))?;
    if base64::engine::general_purpose::STANDARD.encode(&decoded) != value {
        return Err(WebSocketPlanError::Invalid(
            "payload base64 is not canonical padded RFC 4648".into(),
        ));
    }
    Ok(decoded)
}

fn valid_close_code(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
}

fn validate_action_timeout(
    timeout_ms: Option<u64>,
    limits: &WebSocketLimits,
) -> Result<(), WebSocketPlanError> {
    if timeout_ms.is_some_and(|timeout| timeout == 0 || timeout > limits.action_timeout_ms) {
        return Err(WebSocketPlanError::Invalid(
            "action timeout must be positive and cannot loosen the session action timeout".into(),
        ));
    }
    Ok(())
}

fn validate_websocket_action(
    action: &WebSocketAction,
    limits: &WebSocketLimits,
) -> Result<(u64, u64, u64, bool), WebSocketPlanError> {
    let message_limit = |bytes: usize| {
        if bytes as u64 > limits.max_message_bytes || bytes as u64 > limits.max_frame_bytes {
            Err(WebSocketPlanError::Invalid(
                "inline message exceeds the sealed frame or message limit".into(),
            ))
        } else {
            Ok(bytes as u64)
        }
    };
    match action {
        WebSocketAction::SendText { text } => Ok((1, 1, message_limit(text.len())?, false)),
        WebSocketAction::SendBinary { payload_base64 } => Ok((
            1,
            1,
            message_limit(decode_canonical_base64(payload_base64)?.len())?,
            false,
        )),
        WebSocketAction::ExpectText { equals, timeout_ms } => {
            validate_action_timeout(*timeout_ms, limits)?;
            message_limit(equals.len())?;
            Ok((0, 0, 0, false))
        }
        WebSocketAction::ExpectBinary {
            payload_base64,
            timeout_ms,
        } => {
            validate_action_timeout(*timeout_ms, limits)?;
            message_limit(decode_canonical_base64(payload_base64)?.len())?;
            Ok((0, 0, 0, false))
        }
        WebSocketAction::ExpectJson {
            pointer,
            equals,
            schema,
            timeout_ms,
        } => {
            validate_action_timeout(*timeout_ms, limits)?;
            if equals.is_none() && schema.is_none() {
                return Err(WebSocketPlanError::Invalid(
                    "expect-json requires equals or schema".into(),
                ));
            }
            if pointer.as_ref().is_some_and(|pointer| {
                pointer.len() > 2_048 || (!pointer.is_empty() && !pointer.starts_with('/'))
            }) {
                return Err(WebSocketPlanError::Invalid(
                    "expect-json pointer is not a bounded JSON Pointer".into(),
                ));
            }
            for value in [equals, schema].into_iter().flatten() {
                message_limit(serde_json::to_vec(value)?.len())?;
            }
            Ok((0, 0, 0, false))
        }
        WebSocketAction::Ping { payload_base64 } => {
            let bytes = decode_canonical_base64(payload_base64)?.len();
            if bytes > 125 {
                return Err(WebSocketPlanError::Invalid(
                    "ping payload exceeds 125 bytes".into(),
                ));
            }
            Ok((1, 0, bytes as u64, false))
        }
        WebSocketAction::ExpectPong {
            payload_base64,
            timeout_ms,
        } => {
            validate_action_timeout(*timeout_ms, limits)?;
            if decode_canonical_base64(payload_base64)?.len() > 125 {
                return Err(WebSocketPlanError::Invalid(
                    "pong payload exceeds 125 bytes".into(),
                ));
            }
            Ok((0, 0, 0, false))
        }
        WebSocketAction::Close { code, reason } => {
            if !valid_close_code(*code) || reason.len() > 123 {
                return Err(WebSocketPlanError::Invalid(
                    "invalid close code or reason".into(),
                ));
            }
            Ok((1, 0, reason.len() as u64 + 2, true))
        }
        WebSocketAction::ExpectClose {
            codes,
            reason,
            timeout_ms,
        } => {
            validate_action_timeout(*timeout_ms, limits)?;
            if codes.is_empty()
                || codes.iter().any(|code| !valid_close_code(*code))
                || reason.as_ref().is_some_and(|reason| reason.len() > 123)
            {
                return Err(WebSocketPlanError::Invalid(
                    "invalid expected close code or reason".into(),
                ));
            }
            Ok((0, 0, 0, true))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Passed,
    Failed,
    Denied,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Observation {
    pub protocol: String,
    pub kind: String,
    pub version: String,
    pub config_fingerprint: String,
    pub policy_fingerprint: String,
    pub source_fingerprints: Vec<String>,
    pub tool_version: String,
    pub plan: String,
    pub outcome: Outcome,
    pub status: Option<u16>,
    pub response_schema: Option<String>,
    pub latency_ms: Option<f64>,
    pub response_bytes: Option<u64>,
    pub body: Option<String>,
    pub trace: Option<String>,
    pub resolved_origin: Option<String>,
    pub http_version: Option<String>,
    pub secret_refs: Vec<String>,
    pub runtime: String,
    pub exit: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum WebSocketCloseInitiator {
    Client,
    Server,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WebSocketCloseObservation {
    pub initiator: WebSocketCloseInitiator,
    pub code: u16,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum WebSocketTerminalCause {
    Completed,
    HandshakeCheckFailed,
    ExpectationFailed,
    BudgetExhausted,
    DnsFailure,
    ConnectionFailure,
    TlsFailure,
    IoFailure,
    ProtocolViolation,
    UnexpectedEof,
    ConnectTimeout,
    ActionTimeout,
    IdleTimeout,
    CloseTimeout,
    TotalTimeout,
    Cancelled,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WebSocketCounters {
    pub inbound_frames: u64,
    pub outbound_frames: u64,
    pub inbound_messages: u64,
    pub outbound_messages: u64,
    pub inbound_bytes: u64,
    pub outbound_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WebSocketObservation {
    pub protocol: String,
    pub kind: String,
    pub version: String,
    pub config_fingerprint: String,
    pub policy_fingerprint: String,
    pub source_fingerprints: Vec<String>,
    pub tool_version: String,
    pub plan: String,
    pub outcome: Outcome,
    pub handshake_status: Option<u16>,
    pub negotiated_subprotocol: Option<String>,
    pub handshake_latency_ms: Option<f64>,
    pub session_duration_ms: Option<f64>,
    pub transcript: Option<String>,
    pub handshake: Option<String>,
    pub trace: Option<String>,
    pub close: Option<WebSocketCloseObservation>,
    pub terminal_cause: WebSocketTerminalCause,
    pub counters: WebSocketCounters,
    pub resolved_origin: Option<String>,
    pub http_version: Option<String>,
    pub secret_refs: Vec<String>,
    pub runtime: String,
    pub exit: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DenialEnvelope {
    pub protocol: String,
    pub kind: String,
    pub version: String,
    pub config_fingerprint: String,
    pub plan: String,
    pub reason: String,
    pub required: String,
    pub policy: String,
    pub exit: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EvidenceEnvelope {
    pub protocol: String,
    pub kind: String,
    pub version: String,
    pub config_fingerprint: String,
    pub handle: String,
    pub media_type: String,
    pub bytes: u64,
    pub blake3: String,
    pub redacted: bool,
    pub exit: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExplanationEnvelope {
    pub protocol: String,
    pub kind: String,
    pub version: String,
    pub config_fingerprint: String,
    pub handle: String,
    pub media_type: String,
    pub selector: Option<String>,
    pub value: Option<Value>,
    pub bytes: u64,
    pub truncated: bool,
    pub exit: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WorkflowParameterBinding {
    pub name: String,
    pub location: Option<String>,
    pub value: Value,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum WorkflowStepTransport {
    #[default]
    Http,
    #[serde(rename = "websocket")]
    WebSocket,
}

impl WorkflowStepTransport {
    pub fn is_http(&self) -> bool {
        matches!(self, Self::Http)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WorkflowWebSocketBinding {
    pub pointer: String,
    pub value: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WorkflowStepTemplate {
    pub step_id: String,
    pub source_name: String,
    pub source_document: Value,
    pub source_fingerprint: String,
    pub operation: String,
    pub parameters: Vec<WorkflowParameterBinding>,
    pub request_body: Option<Value>,
    pub outputs: BTreeMap<String, Value>,
    pub deferred_bindings: Vec<String>,
    pub depends_on: Vec<String>,
    pub success_criteria: Vec<Value>,
    pub on_success: Vec<Value>,
    pub on_failure: Vec<Value>,
    pub timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "WorkflowStepTransport::is_http")]
    pub transport: WorkflowStepTransport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub websocket_plan: Option<WebSocketPlan>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub websocket_bindings: Vec<WorkflowWebSocketBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WorkflowPlan {
    pub protocol: String,
    pub kind: String,
    pub version: String,
    pub config_fingerprint: String,
    pub policy_fingerprint: String,
    pub source_fingerprints: Vec<String>,
    pub id: String,
    pub workflow: String,
    pub input: Value,
    pub steps: Vec<WorkflowStepTemplate>,
    pub risk: RiskClass,
    pub required_grants: Vec<String>,
    pub auth: Option<String>,
    pub server: Option<String>,
    pub checks: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub websocket_policy_fingerprint: Option<String>,
    pub fingerprint: String,
    pub exit: u8,
}

impl WorkflowPlan {
    pub fn seal(mut self) -> Result<Self, serde_json::Error> {
        self.id.clear();
        self.fingerprint.clear();
        self.fingerprint = digest(&serde_json::to_vec(&self)?);
        self.id = short_handle("workflow-plan", &[self.fingerprint.as_bytes()]);
        Ok(self)
    }

    pub fn verify_seal(&self) -> Result<bool, serde_json::Error> {
        let mut material = self.clone();
        material.id.clear();
        material.fingerprint.clear();
        let fingerprint = digest(&serde_json::to_vec(&material)?);
        Ok(fingerprint == self.fingerprint
            && self.id == short_handle("workflow-plan", &[self.fingerprint.as_bytes()]))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WorkflowStepObservation {
    pub step_id: String,
    pub plan: Option<String>,
    pub attempts: Vec<Value>,
    pub result: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WorkflowObservation {
    pub protocol: String,
    pub kind: String,
    pub version: String,
    pub config_fingerprint: String,
    pub policy_fingerprint: String,
    pub source_fingerprints: Vec<String>,
    pub workflow_plan: String,
    pub outcome: Outcome,
    pub steps: Vec<WorkflowStepObservation>,
    pub outputs: BTreeMap<String, Value>,
    pub exit: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ConformanceGeneration {
    Positive,
    Negative,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ConformanceCasePlan {
    pub case_id: String,
    pub generation: ConformanceGeneration,
    pub strategy: String,
    pub plan: String,
    pub plan_fingerprint: String,
    pub request_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ConformancePlan {
    pub protocol: String,
    pub kind: String,
    pub version: String,
    pub config_fingerprint: String,
    pub policy_fingerprint: String,
    pub source_fingerprints: Vec<String>,
    pub id: String,
    pub operation: String,
    pub seed: u64,
    pub requested_cases: usize,
    pub delay_ms: u64,
    pub max_failures: usize,
    pub cases: Vec<ConformanceCasePlan>,
    pub risk: RiskClass,
    pub required_grants: Vec<String>,
    pub fingerprint: String,
    pub exit: u8,
}

impl ConformancePlan {
    pub fn seal(mut self) -> Result<Self, serde_json::Error> {
        self.id.clear();
        self.fingerprint.clear();
        self.fingerprint = digest(&serde_json::to_vec(&self)?);
        self.id = short_handle("conformance-plan", &[self.fingerprint.as_bytes()]);
        Ok(self)
    }

    pub fn verify_seal(&self) -> Result<bool, serde_json::Error> {
        let mut material = self.clone();
        material.id.clear();
        material.fingerprint.clear();
        let fingerprint = digest(&serde_json::to_vec(&material)?);
        Ok(fingerprint == self.fingerprint
            && self.id == short_handle("conformance-plan", &[self.fingerprint.as_bytes()]))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ConformanceCaseObservation {
    pub case_id: String,
    pub generation: ConformanceGeneration,
    pub strategy: String,
    pub plan: String,
    pub passed: bool,
    pub status: Option<u16>,
    pub reason: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ConformanceObservation {
    pub protocol: String,
    pub kind: String,
    pub version: String,
    pub config_fingerprint: String,
    pub policy_fingerprint: String,
    pub source_fingerprints: Vec<String>,
    pub conformance_plan: String,
    pub outcome: Outcome,
    pub generated: usize,
    pub executed: usize,
    pub passed: usize,
    pub failed: usize,
    pub transport_errors: usize,
    pub cases: Vec<ConformanceCaseObservation>,
    pub required: Option<String>,
    pub exit: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ErrorEnvelope {
    pub protocol: String,
    pub kind: String,
    pub version: String,
    pub config_fingerprint: String,
    pub code: String,
    pub message: String,
    pub details: BTreeMap<String, Value>,
    pub exit: u8,
}

impl ErrorEnvelope {
    pub fn invalid(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            protocol: PROTOCOL.into(),
            kind: "error".into(),
            version: VERSION.into(),
            config_fingerprint: default_config_fingerprint(),
            code: code.into(),
            message: message.into(),
            details: BTreeMap::new(),
            exit: 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExitCodeDescription {
    pub code: u8,
    pub meaning: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FeatureAvailability {
    pub available: bool,
    pub release: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DescribeEnvelope {
    pub protocol: String,
    pub kind: String,
    pub version: String,
    pub config_fingerprint: String,
    pub executable: String,
    pub formats: Vec<String>,
    pub authentication: Vec<String>,
    pub safety_controls: Vec<String>,
    pub output_kinds: Vec<String>,
    pub exit_codes: Vec<ExitCodeDescription>,
    pub configuration_keys: Vec<String>,
    pub features: BTreeMap<String, FeatureAvailability>,
    pub exit: u8,
}

impl DescribeEnvelope {
    pub fn current() -> Self {
        let mut features = BTreeMap::new();
        for name in [
            "inspect",
            "plan",
            "invoke",
            "explain",
            "mcp",
            "workflows",
            "conformance",
        ] {
            features.insert(
                name.into(),
                FeatureAvailability {
                    available: true,
                    release: match name {
                        "inspect" => "release-0",
                        "plan" | "invoke" | "explain" => "release-1",
                        "mcp" => "release-2",
                        "workflows" => "release-3",
                        "conformance" => "release-4",
                        _ => unreachable!(),
                    }
                    .into(),
                },
            );
        }
        features.insert(
            "websockets".into(),
            FeatureAvailability {
                available: false,
                release: "release-5".into(),
            },
        );

        Self {
            protocol: PROTOCOL.into(),
            kind: "describe".into(),
            version: VERSION.into(),
            config_fingerprint: default_config_fingerprint(),
            executable: "kahea".into(),
            formats: vec![
                "openapi-3.0-json".into(),
                "openapi-3.0-yaml".into(),
                "openapi-3.1-json".into(),
                "openapi-3.1-yaml".into(),
                "openapi-3.2-json".into(),
                "openapi-3.2-yaml".into(),
                "postman-2.1-json".into(),
                "postman-3-yaml".into(),
                "har-1.2-json".into(),
                "curl".into(),
                "http-file".into(),
                "kahea-request-json-yaml".into(),
                "arazzo-1.1-json-yaml".into(),
            ],
            authentication: vec![
                "api-key".into(),
                "http-basic".into(),
                "bearer".into(),
                "oauth2-reference".into(),
                "mutual-tls-reference".into(),
            ],
            safety_controls: vec![
                "no-network-inspection".into(),
                "content-fingerprinting".into(),
                "bounded-output".into(),
                "sealed-plans".into(),
                "capability-grants".into(),
                "dns-pinning".into(),
                "redirect-deny-default".into(),
                "secret-redaction".into(),
            ],
            output_kinds: vec![
                "describe".into(),
                "schema".into(),
                "operation-index".into(),
                "plan".into(),
                "observation".into(),
                "denial".into(),
                "evidence".into(),
                "explanation".into(),
                "workflow-plan".into(),
                "workflow-observation".into(),
                "conformance-plan".into(),
                "conformance-observation".into(),
                "websocket-plan".into(),
                "websocket-observation".into(),
                "error".into(),
            ],
            exit_codes: vec![
                ExitCodeDescription {
                    code: 0,
                    meaning: "completed successfully".into(),
                },
                ExitCodeDescription {
                    code: 1,
                    meaning: "remote response failed a declared check".into(),
                },
                ExitCodeDescription {
                    code: 2,
                    meaning: "invalid source, configuration, input, plan, or internal error".into(),
                },
                ExitCodeDescription {
                    code: 3,
                    meaning: "transport, DNS, TLS, timeout, or connection failure".into(),
                },
                ExitCodeDescription {
                    code: 4,
                    meaning: "policy denied the plan or invocation".into(),
                },
            ],
            configuration_keys: vec![
                "version".into(),
                "defaults.source".into(),
                "defaults.server".into(),
                "defaults.policy".into(),
                "servers".into(),
                "risk".into(),
                "policy.allowed_hosts".into(),
                "policy.denied_hosts".into(),
                "policy.max_request_bytes".into(),
                "policy.sensitive_headers".into(),
                "policy.redact_response_json_pointers".into(),
                "defaults.auth".into(),
                "auth".into(),
            ],
            features,
            exit: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SchemaEnvelope {
    pub protocol: String,
    pub kind: String,
    pub version: String,
    pub config_fingerprint: String,
    pub name: String,
    pub schema: Value,
    pub exit: u8,
}

pub fn public_schema(name: &str) -> Option<Value> {
    let schema = match name {
        "graph" => schemars::schema_for!(ApiGraphEnvelope),
        "plan" => schemars::schema_for!(RequestPlan),
        "observation" => schemars::schema_for!(Observation),
        "websocket-session" => schemars::schema_for!(WebSocketSessionSource),
        "websocket-plan" => schemars::schema_for!(WebSocketPlan),
        "websocket-observation" => schemars::schema_for!(WebSocketObservation),
        "evidence" => schemars::schema_for!(EvidenceEnvelope),
        "explanation" => schemars::schema_for!(ExplanationEnvelope),
        "workflow-plan" => schemars::schema_for!(WorkflowPlan),
        "workflow-observation" => schemars::schema_for!(WorkflowObservation),
        "conformance-plan" => schemars::schema_for!(ConformancePlan),
        "conformance-observation" => schemars::schema_for!(ConformanceObservation),
        "operation-index" => schemars::schema_for!(OperationIndexEnvelope),
        "describe" => schemars::schema_for!(DescribeEnvelope),
        "error" => schemars::schema_for!(ErrorEnvelope),
        "denial" => schemars::schema_for!(DenialEnvelope),
        _ => return None,
    };
    serde_json::to_value(schema).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_handles_are_domain_separated() {
        let parts = [b"source".as_slice(), b"GET".as_slice(), b"/pets".as_slice()];
        assert_eq!(short_handle("op", &parts), short_handle("op", &parts));
        assert_ne!(short_handle("op", &parts), short_handle("plan", &parts));
    }

    #[test]
    fn all_public_schemas_are_available() {
        for name in [
            "graph",
            "plan",
            "observation",
            "websocket-session",
            "websocket-plan",
            "websocket-observation",
            "evidence",
            "explanation",
            "workflow-plan",
            "workflow-observation",
            "conformance-plan",
            "conformance-observation",
            "operation-index",
            "describe",
            "error",
            "denial",
        ] {
            let schema = public_schema(name).unwrap_or_else(|| panic!("missing schema: {name}"));
            assert!(schema.is_object(), "invalid schema: {name}");
            assert!(
                schema.get("$schema").is_some() || schema.get("type").is_some(),
                "empty schema: {name}"
            );
        }
    }

    #[test]
    fn risk_defaults_fail_closed() {
        assert_eq!(RiskClass::for_http_method("GET"), RiskClass::Read);
        assert_eq!(RiskClass::for_http_method("QUERY"), RiskClass::Read);
        assert_eq!(RiskClass::for_http_method("DELETE"), RiskClass::Destructive);
        assert_eq!(RiskClass::for_http_method("CONNECT"), RiskClass::Unknown);
    }

    #[test]
    fn default_fingerprint_is_the_exact_domain_digest() {
        assert_eq!(
            default_config_fingerprint(),
            digest(b"kahea/default-config/v1")
        );
        assert!(default_config_fingerprint().starts_with("b3:"));
        assert_eq!(default_config_fingerprint().len(), 67);
    }

    #[test]
    fn every_described_feature_has_the_committed_release() {
        let described = DescribeEnvelope::current();
        for (name, release) in [
            ("inspect", "release-0"),
            ("plan", "release-1"),
            ("invoke", "release-1"),
            ("explain", "release-1"),
            ("mcp", "release-2"),
            ("workflows", "release-3"),
            ("conformance", "release-4"),
        ] {
            let feature = &described.features[name];
            assert!(feature.available);
            assert_eq!(feature.release, release);
        }
        let websockets = &described.features["websockets"];
        assert!(!websockets.available);
        assert_eq!(websockets.release, "release-5");
    }

    #[test]
    fn workflow_seal_rejects_material_and_identity_mutation() {
        let plan = WorkflowPlan {
            protocol: PROTOCOL.into(),
            kind: "workflow-plan".into(),
            version: VERSION.into(),
            config_fingerprint: default_config_fingerprint(),
            policy_fingerprint: digest(b"policy"),
            source_fingerprints: vec![digest(b"source")],
            id: String::new(),
            workflow: "fixture".into(),
            input: serde_json::json!({}),
            steps: Vec::new(),
            risk: RiskClass::Read,
            required_grants: Vec::new(),
            auth: None,
            server: None,
            checks: Vec::new(),
            websocket_policy_fingerprint: None,
            fingerprint: String::new(),
            exit: 0,
        }
        .seal()
        .unwrap();
        assert!(plan.verify_seal().unwrap());
        let mut material = plan.clone();
        material.workflow.push_str("-mutated");
        assert!(!material.verify_seal().unwrap());
        let mut identity = plan.clone();
        identity.id = "workflow-plan:000000000000".into();
        assert!(!identity.verify_seal().unwrap());
    }

    #[test]
    fn conformance_seal_binds_seed_limits_and_case_fingerprints() {
        let plan = ConformancePlan {
            protocol: PROTOCOL.into(),
            kind: "conformance-plan".into(),
            version: VERSION.into(),
            config_fingerprint: default_config_fingerprint(),
            policy_fingerprint: digest(b"policy"),
            source_fingerprints: vec![digest(b"source")],
            id: String::new(),
            operation: "op:test".into(),
            seed: 42,
            requested_cases: 1,
            delay_ms: 5,
            max_failures: 1,
            cases: vec![ConformanceCasePlan {
                case_id: "case:0123456789ab".into(),
                generation: ConformanceGeneration::Positive,
                strategy: "schema-valid".into(),
                plan: "plan:0123456789ab".into(),
                plan_fingerprint: digest(b"request-plan"),
                request_digest: digest(b"request"),
            }],
            risk: RiskClass::Read,
            required_grants: vec!["conformance:execute:1".into()],
            fingerprint: String::new(),
            exit: 0,
        }
        .seal()
        .unwrap();
        assert!(plan.verify_seal().unwrap());
        let mut seed = plan.clone();
        seed.seed += 1;
        assert!(!seed.verify_seal().unwrap());
        let mut case = plan.clone();
        case.cases[0].plan_fingerprint = digest(b"mutated");
        assert!(!case.verify_seal().unwrap());
        let mut identity = plan;
        identity.id = "conformance-plan:000000000000".into();
        assert!(!identity.verify_seal().unwrap());
    }

    fn websocket_plan() -> WebSocketPlan {
        WebSocketPlan {
            protocol: PROTOCOL.into(),
            kind: "websocket-plan".into(),
            version: VERSION.into(),
            config_fingerprint: default_config_fingerprint(),
            policy_fingerprint: digest(b"policy"),
            source_fingerprints: vec![digest(b"source")],
            id: String::new(),
            operation: "op:websocket".into(),
            target: "wss://socket.example.test/v1/events".into(),
            risk: RiskClass::Write,
            required_grants: vec![
                "websocket:connect".into(),
                "net:socket.example.test:443".into(),
            ],
            secret_refs: Vec::new(),
            headers: vec![PlannedHeader {
                name: "X-Client".into(),
                value: "kahea".into(),
            }],
            auth: None,
            origin: Some("https://client.example.test".into()),
            subprotocols: vec!["kahea.events.v1".into()],
            handshake_checks: vec!["extensions:none".into(), "status:101".into()],
            limits: WebSocketLimits {
                connect_timeout_ms: 5_000,
                action_timeout_ms: 2_000,
                idle_timeout_ms: 5_000,
                close_timeout_ms: 2_000,
                total_timeout_ms: 15_000,
                max_frame_bytes: 1_048_576,
                max_message_bytes: 4_194_304,
                max_inbound_frames: 64,
                max_outbound_frames: 64,
                max_inbound_messages: 32,
                max_outbound_messages: 32,
                max_inbound_bytes: 16_777_216,
                max_outbound_bytes: 16_777_216,
            },
            actions: vec![
                WebSocketAction::ExpectJson {
                    pointer: Some("/type".into()),
                    equals: Some(serde_json::json!({"z": 1, "a": 2})),
                    schema: None,
                    timeout_ms: Some(2_000),
                },
                WebSocketAction::Close {
                    code: 1000,
                    reason: "complete".into(),
                },
            ],
            sensitive_headers: vec!["authorization".into()],
            redact_response_json_pointers: vec!["/token".into()],
            valid: true,
            fingerprint: String::new(),
            exit: 0,
        }
    }

    #[test]
    fn websocket_plan_is_canonical_and_seal_bound() {
        let mut first = websocket_plan();
        first.sensitive_headers = vec!["Authorization".into(), "authorization".into()];
        let first = first.seal().unwrap();
        let mut reordered = websocket_plan();
        reordered.required_grants.reverse();
        reordered.handshake_checks.reverse();
        reordered.sensitive_headers = vec!["authorization".into(), "Authorization".into()];
        reordered.actions[0] = WebSocketAction::ExpectJson {
            pointer: Some("/type".into()),
            equals: Some(serde_json::json!({"a": 2, "z": 1})),
            schema: None,
            timeout_ms: Some(2_000),
        };
        let reordered = reordered.seal().unwrap();
        assert_eq!(first.fingerprint, reordered.fingerprint);
        assert_eq!(first.id, reordered.id);
        assert_eq!(first.sensitive_headers, ["authorization"]);
        assert!(first.verify_seal().unwrap());
        let bytes = serde_json::to_vec(&first).unwrap();
        let restored: WebSocketPlan = serde_json::from_slice(&bytes).unwrap();
        assert!(restored.verify_seal().unwrap());
        assert_eq!(bytes, serde_json::to_vec(&restored).unwrap());

        let mut action = first.clone();
        action.actions[0] = WebSocketAction::ExpectText {
            equals: "different".into(),
            timeout_ms: Some(2_000),
        };
        assert!(!action.verify_seal().unwrap());
        let mut identity = first;
        identity.id = "plan:000000000000".into();
        assert!(!identity.verify_seal().unwrap());
    }

    #[test]
    fn websocket_plan_validation_fails_closed() {
        let mut empty = websocket_plan();
        empty.actions.clear();
        assert!(empty.seal().is_err());

        let mut terminal_not_last = websocket_plan();
        terminal_not_last.actions.reverse();
        assert!(terminal_not_last.seal().is_err());

        let mut invalid_binary = websocket_plan();
        invalid_binary.actions.insert(
            0,
            WebSocketAction::SendBinary {
                payload_base64: "not base64".into(),
            },
        );
        assert!(invalid_binary.seal().is_err());

        let mut invalid_close = websocket_plan();
        invalid_close.actions.pop();
        invalid_close.actions.push(WebSocketAction::Close {
            code: 1006,
            reason: String::new(),
        });
        assert!(invalid_close.seal().is_err());

        let mut duplicate_header = websocket_plan();
        duplicate_header.headers.push(PlannedHeader {
            name: "x-client".into(),
            value: "duplicate".into(),
        });
        assert!(duplicate_header.seal().is_err());

        let mut zero_limit = websocket_plan();
        zero_limit.limits.total_timeout_ms = 0;
        assert!(zero_limit.seal().is_err());

        let mut oversized = websocket_plan();
        oversized.limits.max_frame_bytes = 4;
        oversized.limits.max_message_bytes = 4;
        oversized.actions.insert(
            0,
            WebSocketAction::SendText {
                text: "too large".into(),
            },
        );
        assert!(oversized.seal().is_err());
    }

    #[test]
    fn websocket_error_messages_are_stable() {
        assert_eq!(
            WebSocketPlanError::Invalid("bad marker".into()).to_string(),
            "invalid WebSocket plan: bad marker"
        );
        let error = serde_json::from_str::<Value>("{").unwrap_err();
        assert!(
            WebSocketPlanError::Serialization(error)
                .to_string()
                .starts_with("serialize WebSocket plan:")
        );
    }

    #[test]
    fn websocket_plan_markers_fail_independently() {
        for marker in ["protocol", "kind", "valid", "exit"] {
            let mut plan = websocket_plan();
            match marker {
                "protocol" => plan.protocol = "other/v1".into(),
                "kind" => plan.kind = "plan".into(),
                "valid" => plan.valid = false,
                "exit" => plan.exit = 1,
                _ => unreachable!(),
            }
            assert!(plan.validate().is_err(), "accepted invalid {marker}");
        }
    }

    #[test]
    fn websocket_outbound_aggregates_enforce_exact_limits() {
        let mut frames = websocket_plan();
        frames.actions = vec![
            WebSocketAction::Ping {
                payload_base64: String::new(),
            },
            WebSocketAction::Close {
                code: 1000,
                reason: String::new(),
            },
        ];
        frames.limits.max_outbound_frames = 2;
        assert!(frames.validate().is_ok());
        frames.limits.max_outbound_frames = 1;
        assert!(frames.validate().is_err());

        let mut messages = websocket_plan();
        messages.actions = vec![
            WebSocketAction::SendText { text: "a".into() },
            WebSocketAction::SendText { text: "b".into() },
            WebSocketAction::Close {
                code: 1000,
                reason: String::new(),
            },
        ];
        messages.limits.max_outbound_messages = 2;
        assert!(messages.validate().is_ok());
        messages.limits.max_outbound_messages = 1;
        assert!(messages.validate().is_err());

        let mut bytes = websocket_plan();
        bytes.actions = vec![WebSocketAction::Close {
            code: 1000,
            reason: "x".into(),
        }];
        bytes.limits.max_outbound_bytes = 3;
        assert!(bytes.validate().is_ok());
        bytes.limits.max_outbound_bytes = 2;
        assert!(bytes.validate().is_err());
    }

    #[test]
    fn websocket_normalization_sorts_expected_close_codes() {
        let mut plan = websocket_plan();
        plan.actions = vec![WebSocketAction::ExpectClose {
            codes: vec![1001, 1000, 1001],
            reason: None,
            timeout_ms: None,
        }];
        plan.normalize();
        match &plan.actions[0] {
            WebSocketAction::ExpectClose { codes, .. } => {
                assert_eq!(codes, &[1000, 1001]);
            }
            action => panic!("unexpected action: {action:?}"),
        }
    }

    #[test]
    fn websocket_limit_relationships_are_independent_and_inclusive() {
        let baseline = websocket_plan().limits;
        assert!(validate_websocket_limits(&baseline).is_ok());

        let mut equal = baseline.clone();
        equal.max_message_bytes = equal.max_frame_bytes;
        equal.connect_timeout_ms = equal.total_timeout_ms;
        equal.action_timeout_ms = equal.total_timeout_ms;
        equal.idle_timeout_ms = equal.total_timeout_ms;
        equal.close_timeout_ms = equal.total_timeout_ms;
        assert!(validate_websocket_limits(&equal).is_ok());

        let mut invalid = baseline.clone();
        invalid.max_message_bytes = invalid.max_frame_bytes - 1;
        assert!(validate_websocket_limits(&invalid).is_err());

        macro_rules! assert_timeout_exceeds_total {
            ($field:ident) => {{
                let mut invalid = baseline.clone();
                invalid.$field = invalid.total_timeout_ms + 1;
                assert!(
                    validate_websocket_limits(&invalid).is_err(),
                    "accepted an excessive {}",
                    stringify!($field)
                );
            }};
        }
        assert_timeout_exceeds_total!(connect_timeout_ms);
        assert_timeout_exceeds_total!(action_timeout_ms);
        assert_timeout_exceeds_total!(idle_timeout_ms);
        assert_timeout_exceeds_total!(close_timeout_ms);
    }

    #[test]
    fn websocket_header_and_subprotocol_rules_are_independent() {
        let valid = PlannedHeader {
            name: "X-Client".into(),
            value: "kahea".into(),
        };
        assert!(validate_websocket_headers(std::slice::from_ref(&valid)).is_ok());

        let invalid_name = PlannedHeader {
            name: "Bad Header".into(),
            value: "safe".into(),
        };
        assert!(validate_websocket_headers(&[invalid_name]).is_err());

        let invalid_value = PlannedHeader {
            name: "X-Safe".into(),
            value: "bad\r\nvalue".into(),
        };
        assert!(validate_websocket_headers(&[invalid_value]).is_err());

        assert!(
            validate_websocket_headers(&[
                valid.clone(),
                PlannedHeader {
                    name: "x-client".into(),
                    value: "duplicate".into(),
                },
            ])
            .is_err()
        );

        assert!(validate_subprotocols(&["events.v1".into()]).is_ok());
        assert!(validate_subprotocols(&["bad protocol".into()]).is_err());
        assert!(validate_subprotocols(&["events.v1".into(), "events.v1".into()]).is_err());

        assert!(valid_token("events.v1"));
        assert!(!valid_token(""));
        assert!(!valid_token("bad protocol"));
    }

    #[test]
    fn websocket_base64_and_action_timeouts_are_exact() {
        assert_eq!(decode_canonical_base64("/w==").unwrap(), vec![255]);
        assert!(decode_canonical_base64("/x==").is_err());

        let limits = websocket_plan().limits;
        assert!(validate_action_timeout(None, &limits).is_ok());
        assert!(validate_action_timeout(Some(1), &limits).is_ok());
        assert!(validate_action_timeout(Some(limits.action_timeout_ms), &limits).is_ok());
        assert!(validate_action_timeout(Some(0), &limits).is_err());
        assert!(validate_action_timeout(Some(limits.action_timeout_ms + 1), &limits).is_err());
    }

    #[test]
    fn websocket_message_and_pointer_boundaries_are_exact() {
        let mut message_limited = websocket_plan().limits;
        message_limited.max_message_bytes = 4;
        message_limited.max_frame_bytes = 8;
        assert!(
            validate_websocket_action(
                &WebSocketAction::SendText {
                    text: "1234".into()
                },
                &message_limited
            )
            .is_ok()
        );
        assert!(
            validate_websocket_action(
                &WebSocketAction::SendText {
                    text: "12345".into()
                },
                &message_limited
            )
            .is_err()
        );

        let mut frame_limited = websocket_plan().limits;
        frame_limited.max_message_bytes = 8;
        frame_limited.max_frame_bytes = 4;
        assert!(
            validate_websocket_action(
                &WebSocketAction::SendText {
                    text: "1234".into()
                },
                &frame_limited
            )
            .is_ok()
        );
        assert!(
            validate_websocket_action(
                &WebSocketAction::SendText {
                    text: "12345".into()
                },
                &frame_limited
            )
            .is_err()
        );

        let limits = websocket_plan().limits;
        let expect_json = |pointer: String| WebSocketAction::ExpectJson {
            pointer: Some(pointer),
            equals: Some(Value::Bool(true)),
            schema: None,
            timeout_ms: None,
        };
        assert!(
            validate_websocket_action(&expect_json(format!("/{}", "a".repeat(2047))), &limits)
                .is_ok()
        );
        assert!(
            validate_websocket_action(&expect_json(format!("/{}", "a".repeat(2048))), &limits)
                .is_err()
        );
        assert!(validate_websocket_action(&expect_json("not-a-pointer".into()), &limits).is_err());
    }

    #[test]
    fn websocket_control_and_close_boundaries_are_exact() {
        let limits = websocket_plan().limits;
        let payload_125 = base64::engine::general_purpose::STANDARD.encode([0; 125]);
        let payload_126 = base64::engine::general_purpose::STANDARD.encode([0; 126]);

        assert_eq!(
            validate_websocket_action(
                &WebSocketAction::Ping {
                    payload_base64: payload_125.clone()
                },
                &limits
            )
            .unwrap(),
            (1, 0, 125, false)
        );
        assert!(
            validate_websocket_action(
                &WebSocketAction::Ping {
                    payload_base64: payload_126.clone()
                },
                &limits
            )
            .is_err()
        );
        assert!(
            validate_websocket_action(
                &WebSocketAction::ExpectPong {
                    payload_base64: payload_125,
                    timeout_ms: None
                },
                &limits
            )
            .is_ok()
        );
        assert!(
            validate_websocket_action(
                &WebSocketAction::ExpectPong {
                    payload_base64: payload_126,
                    timeout_ms: None
                },
                &limits
            )
            .is_err()
        );

        assert!(
            validate_websocket_action(
                &WebSocketAction::Close {
                    code: 1000,
                    reason: "a".repeat(123)
                },
                &limits
            )
            .is_ok()
        );
        assert!(
            validate_websocket_action(
                &WebSocketAction::Close {
                    code: 1000,
                    reason: "a".repeat(124)
                },
                &limits
            )
            .is_err()
        );
        assert_eq!(
            validate_websocket_action(
                &WebSocketAction::Close {
                    code: 1000,
                    reason: "abc".into()
                },
                &limits
            )
            .unwrap(),
            (1, 0, 5, true)
        );

        assert!(
            validate_websocket_action(
                &WebSocketAction::ExpectClose {
                    codes: vec![1000],
                    reason: Some("a".repeat(123)),
                    timeout_ms: None
                },
                &limits
            )
            .is_ok()
        );
        for invalid in [
            WebSocketAction::ExpectClose {
                codes: Vec::new(),
                reason: None,
                timeout_ms: None,
            },
            WebSocketAction::ExpectClose {
                codes: vec![1006],
                reason: None,
                timeout_ms: None,
            },
            WebSocketAction::ExpectClose {
                codes: vec![1000],
                reason: Some("a".repeat(124)),
                timeout_ms: None,
            },
        ] {
            assert!(validate_websocket_action(&invalid, &limits).is_err());
        }
    }

    #[test]
    fn websocket_public_schema_snapshot_is_stable() {
        for (name, expected) in [
            (
                "websocket-session",
                "b3:30a0df8ad6dfb78e383f21cec9b0d3a945c98665ccfa96aa1a7046f893151885",
            ),
            (
                "websocket-plan",
                "b3:2210f7f39fe5135f7b9da443018437f153e32c002145de62d1c3954528d92b88",
            ),
            (
                "websocket-observation",
                "b3:404df9bfcf0d71966cf01776df761326c6bf0ed8b4c72d2e8a9091ac03e8ca07",
            ),
        ] {
            let schema = public_schema(name).unwrap();
            assert_eq!(
                digest(&serde_json::to_vec(&schema).unwrap()),
                expected,
                "{name}"
            );
        }
    }
}
