//! Stable domain types and canonical `kahea/k1` protocol envelopes.

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

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
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
}
