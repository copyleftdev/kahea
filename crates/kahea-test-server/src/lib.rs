//! Seeded, high-entropy loopback API used for end-to-end conformance testing.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use thiserror::Error;
use url::Url;

const MAX_REQUEST_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FaultMode {
    None,
    AcceptInvalid,
    MalformedResponse,
    ServerError,
    UndocumentedStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    pub seed: u64,
    pub control_token: String,
    pub operations: Vec<OperationScenario>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationScenario {
    pub operation_id: String,
    pub method: String,
    pub path: String,
    pub identifier: ScalarRule,
    pub query: NamedRule,
    pub header: NamedRule,
    pub body: Option<BodyRule>,
    pub success_status: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedRule {
    pub name: String,
    pub rule: ScalarRule,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BodyRule {
    pub fields: Vec<NamedRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ScalarRule {
    String { min: usize, max: usize },
    Integer { min: i64, max: i64, multiple: i64 },
    Boolean,
    Enum { values: Vec<String> },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OperationDiagnostics {
    pub requests: u64,
    pub valid: u64,
    pub invalid: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Diagnostics {
    pub requests: u64,
    pub valid: u64,
    pub invalid: u64,
    pub by_operation: BTreeMap<String, OperationDiagnostics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerManifest {
    pub kind: String,
    pub seed: u64,
    pub base_url: String,
    pub openapi_url: String,
    pub diagnostics_url: String,
    pub shutdown_url: String,
    pub control_token: String,
    pub operations: Vec<String>,
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("test server I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("test server serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("test server request is invalid: {0}")]
    InvalidRequest(String),
}

#[derive(Debug)]
pub struct RunningServer {
    pub manifest: ServerManifest,
    shutdown: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<Result<(), ServerError>>>,
}

impl RunningServer {
    pub fn stop(mut self) -> Result<(), ServerError> {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| ServerError::InvalidRequest("test server worker panicked".into()))??;
        }
        Ok(())
    }

    pub fn wait(mut self) -> Result<(), ServerError> {
        let worker = self
            .worker
            .take()
            .ok_or_else(|| ServerError::InvalidRequest("server worker is unavailable".into()))?;
        worker
            .join()
            .map_err(|_| ServerError::InvalidRequest("test server worker panicked".into()))?
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub fn generate_scenario(seed: u64) -> Scenario {
    let mut rng = SplitMix64::new(seed);
    let nouns = [
        "beacon", "cipher", "delta", "ember", "fjord", "glyph", "harbor", "ion", "jigsaw",
        "keystone", "lumen", "matrix", "nebula", "orbit", "prism", "quartz",
    ];
    let field_names = [
        "alias", "batch", "channel", "density", "epoch", "flavor", "grade", "horizon", "index",
        "jitter", "kind", "level", "mode", "nonce", "phase", "quota",
    ];
    let count = 3 + rng.range(4) as usize;
    let mut operations = Vec::with_capacity(count);
    for index in 0..count {
        let noun = nouns[(rng.next() as usize) % nouns.len()];
        let suffix = format!("{:04x}", rng.next() & 0xffff);
        let method = match rng.range(4) {
            0 => "GET",
            1 => "POST",
            2 => "PUT",
            _ => "PATCH",
        }
        .to_string();
        let operation_id = format!("{}_{}_{}", method.to_ascii_lowercase(), noun, suffix);
        let path = format!("/api/v{}/{noun}-{suffix}/{{id}}", 1 + rng.range(8));
        let identifier = scalar_rule(&mut rng, false);
        let query = NamedRule {
            name: format!(
                "{}_q{index}",
                field_names[(rng.next() as usize) % field_names.len()]
            ),
            rule: scalar_rule(&mut rng, true),
        };
        let header = NamedRule {
            name: format!("X-Kahea-{}-{index}", 100 + rng.range(900)),
            rule: ScalarRule::Enum {
                values: vec![
                    format!("lane-{}", rng.range(9)),
                    format!("lane-{}", 10 + rng.range(9)),
                ],
            },
        };
        let body = (method != "GET").then(|| {
            let mut fields = Vec::new();
            for field_index in 0..(3 + rng.range(3) as usize) {
                fields.push(NamedRule {
                    name: format!(
                        "{}_{}_{field_index}",
                        field_names[(rng.next() as usize) % field_names.len()],
                        rng.range(100)
                    ),
                    rule: scalar_rule(&mut rng, true),
                });
            }
            BodyRule { fields }
        });
        operations.push(OperationScenario {
            operation_id,
            method: method.clone(),
            path,
            identifier,
            query,
            header,
            body,
            success_status: if method == "POST" { 201 } else { 200 },
        });
    }
    Scenario {
        seed,
        control_token: format!("ctl-{seed:016x}-{:016x}", rng.next()),
        operations,
    }
}

fn scalar_rule(rng: &mut SplitMix64, include_boolean: bool) -> ScalarRule {
    match rng.range(if include_boolean { 4 } else { 3 }) {
        0 => {
            let min = 1 + rng.range(4) as usize;
            ScalarRule::String {
                min,
                max: min + 3 + rng.range(10) as usize,
            }
        }
        1 => {
            let multiple = 1 + rng.range(5) as i64;
            let min = rng.range(6) as i64 * multiple;
            ScalarRule::Integer {
                min,
                max: min + multiple * (3 + rng.range(8) as i64),
                multiple,
            }
        }
        2 => ScalarRule::Enum {
            values: vec![
                format!("opt-{}", rng.range(50)),
                format!("opt-{}", 50 + rng.range(50)),
                format!("opt-{}", 100 + rng.range(50)),
            ],
        },
        _ => ScalarRule::Boolean,
    }
}

pub fn openapi_document(scenario: &Scenario, base_url: &str) -> Value {
    let mut paths = Map::new();
    for operation in &scenario.operations {
        let mut parameters = vec![json!({
            "name":"id",
            "in":"path",
            "required":true,
            "schema":schema_for_rule(&operation.identifier)
        })];
        parameters.push(json!({
            "name":operation.query.name,
            "in":"query",
            "required":true,
            "schema":schema_for_rule(&operation.query.rule)
        }));
        parameters.push(json!({
            "name":operation.header.name,
            "in":"header",
            "required":true,
            "schema":schema_for_rule(&operation.header.rule)
        }));
        let mut operation_document = Map::from_iter([
            ("operationId".into(), json!(operation.operation_id)),
            ("parameters".into(), Value::Array(parameters)),
            (
                "responses".into(),
                json!({
                    operation.success_status.to_string(): {
                        "description":"Generated request accepted",
                        "content":{"application/json":{"schema":{
                            "type":"object",
                            "additionalProperties":false,
                            "required":["accepted","operation","seed"],
                            "properties":{
                                "accepted":{"const":true},
                                "operation":{"const":operation.operation_id},
                                "seed":{"type":"integer"}
                            }
                        }}}
                    },
                    "400": {
                        "description":"Generated request rejected",
                        "content":{"application/json":{"schema":{
                            "type":"object",
                            "additionalProperties":false,
                            "required":["accepted","error","operation"],
                            "properties":{
                                "accepted":{"const":false},
                                "error":{"const":"contract-rejected"},
                                "operation":{"const":operation.operation_id}
                            }
                        }}}
                    }
                }),
            ),
        ]);
        if let Some(body) = &operation.body {
            let properties: Map<_, _> = body
                .fields
                .iter()
                .map(|field| (field.name.clone(), schema_for_rule(&field.rule)))
                .collect();
            let required: Vec<_> = body.fields.iter().map(|field| field.name.clone()).collect();
            operation_document.insert(
                "requestBody".into(),
                json!({
                    "required":true,
                    "content":{"application/json":{"schema":{
                        "type":"object",
                        "additionalProperties":false,
                        "required":required,
                        "properties":properties
                    }}}
                }),
            );
        }
        paths.insert(
            operation.path.clone(),
            Value::Object(Map::from_iter([(
                operation.method.to_ascii_lowercase(),
                Value::Object(operation_document),
            )])),
        );
    }
    json!({
        "openapi":"3.1.0",
        "info":{"title":format!("Kāhea dynamic oracle {:016x}", scenario.seed),"version":"1.0.0"},
        "servers":[{"url":base_url}],
        "paths":paths
    })
}

fn schema_for_rule(rule: &ScalarRule) -> Value {
    match rule {
        ScalarRule::String { min, max } => {
            json!({"type":"string","minLength":min,"maxLength":max})
        }
        ScalarRule::Integer { min, max, multiple } => {
            json!({"type":"integer","minimum":min,"maximum":max,"multipleOf":multiple})
        }
        ScalarRule::Boolean => json!({"type":"boolean"}),
        ScalarRule::Enum { values } => json!({"type":"string","enum":values}),
    }
}

pub fn start_server(scenario: Scenario, fault: FaultMode) -> Result<RunningServer, ServerError> {
    start_server_on(scenario, fault, 0)
}

pub fn start_server_on(
    scenario: Scenario,
    fault: FaultMode,
    port: u16,
) -> Result<RunningServer, ServerError> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let base_url = format!("http://{address}");
    let manifest = manifest(&scenario, &base_url);
    let shutdown = Arc::new(AtomicBool::new(false));
    let worker_shutdown = Arc::clone(&shutdown);
    let worker = thread::spawn(move || serve(listener, scenario, fault, worker_shutdown));
    Ok(RunningServer {
        manifest,
        shutdown,
        worker: Some(worker),
    })
}

pub fn serve_bound(
    listener: TcpListener,
    scenario: Scenario,
    fault: FaultMode,
    shutdown: Arc<AtomicBool>,
) -> Result<(), ServerError> {
    listener.set_nonblocking(true)?;
    serve(listener, scenario, fault, shutdown)
}

pub fn manifest(scenario: &Scenario, base_url: &str) -> ServerManifest {
    ServerManifest {
        kind: "kahea-dynamic-test-server".into(),
        seed: scenario.seed,
        base_url: base_url.into(),
        openapi_url: format!("{base_url}/openapi.json"),
        diagnostics_url: format!("{base_url}/__kahea/diagnostics"),
        shutdown_url: format!("{base_url}/__kahea/shutdown"),
        control_token: scenario.control_token.clone(),
        operations: scenario
            .operations
            .iter()
            .map(|operation| operation.operation_id.clone())
            .collect(),
    }
}

fn serve(
    listener: TcpListener,
    scenario: Scenario,
    fault: FaultMode,
    shutdown: Arc<AtomicBool>,
) -> Result<(), ServerError> {
    let address = listener.local_addr()?;
    let base_url = format!("http://{address}");
    let openapi = serde_json::to_vec(&openapi_document(&scenario, &base_url))?;
    let diagnostics = Arc::new(Mutex::new(Diagnostics::default()));
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                stream.set_write_timeout(Some(Duration::from_secs(5)))?;
                let request = match read_request(&mut stream) {
                    Ok(request) => request,
                    Err(error) => {
                        let _ = write_json_response(
                            &mut stream,
                            400,
                            &json!({"error":"malformed-request","message":error.to_string()}),
                        );
                        continue;
                    }
                };
                if request.method == "GET" && request.path == "/openapi.json" {
                    write_response(&mut stream, 200, "application/json", &openapi)?;
                    continue;
                }
                if request.method == "GET" && request.path == "/__kahea/manifest" {
                    write_json_response(&mut stream, 200, &manifest(&scenario, &base_url))?;
                    continue;
                }
                if request.method == "GET" && request.path == "/__kahea/diagnostics" {
                    let snapshot = diagnostics.lock().expect("diagnostics lock").clone();
                    write_json_response(&mut stream, 200, &snapshot)?;
                    continue;
                }
                if request.method == "POST" && request.path == "/__kahea/shutdown" {
                    let permitted = request
                        .headers
                        .get("x-kahea-control")
                        .is_some_and(|value| value == &scenario.control_token);
                    if permitted {
                        shutdown.store(true, Ordering::SeqCst);
                        write_json_response(&mut stream, 200, &json!({"shutdown":true}))?;
                    } else {
                        write_json_response(&mut stream, 403, &json!({"shutdown":false}))?;
                    }
                    continue;
                }
                handle_operation(&mut stream, &scenario, fault, &diagnostics, request)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(ServerError::Io(error)),
        }
    }
    Ok(())
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    target: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Result<HttpRequest, ServerError> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(ServerError::InvalidRequest(
                "connection closed before headers".into(),
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(ServerError::InvalidRequest("request exceeds 1 MiB".into()));
        }
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let header_text = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| ServerError::InvalidRequest("headers are not UTF-8".into()))?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| ServerError::InvalidRequest("request line is missing".into()))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| ServerError::InvalidRequest("method is missing".into()))?
        .to_ascii_uppercase();
    let target = request_parts
        .next()
        .ok_or_else(|| ServerError::InvalidRequest("target is missing".into()))?
        .to_string();
    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| ServerError::InvalidRequest("header is malformed".into()))?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().into());
    }
    let content_length = headers
        .get("content-length")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| ServerError::InvalidRequest("Content-Length is invalid".into()))?
        .unwrap_or(0);
    if content_length > MAX_REQUEST_BYTES {
        return Err(ServerError::InvalidRequest("body exceeds 1 MiB".into()));
    }
    while bytes.len() - header_end < content_length {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(ServerError::InvalidRequest("body ended early".into()));
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    let url = Url::parse(&format!("http://loopback{target}"))
        .map_err(|error| ServerError::InvalidRequest(error.to_string()))?;
    Ok(HttpRequest {
        method,
        target,
        path: url.path().into(),
        headers,
        body: bytes[header_end..header_end + content_length].to_vec(),
    })
}

fn handle_operation(
    stream: &mut TcpStream,
    scenario: &Scenario,
    fault: FaultMode,
    diagnostics: &Arc<Mutex<Diagnostics>>,
    request: HttpRequest,
) -> Result<(), ServerError> {
    let operation = scenario.operations.iter().find(|operation| {
        operation.method == request.method && path_identifier(operation, &request.path).is_some()
    });
    let Some(operation) = operation else {
        return write_json_response(
            stream,
            404,
            &json!({"accepted":false,"error":"unknown-operation"}),
        );
    };
    let valid = validate_request(operation, &request);
    {
        let mut diagnostics = diagnostics.lock().expect("diagnostics lock");
        diagnostics.requests += 1;
        if valid {
            diagnostics.valid += 1;
        } else {
            diagnostics.invalid += 1;
        }
        let operation_diagnostics = diagnostics
            .by_operation
            .entry(operation.operation_id.clone())
            .or_default();
        operation_diagnostics.requests += 1;
        if valid {
            operation_diagnostics.valid += 1;
        } else {
            operation_diagnostics.invalid += 1;
        }
    }
    match fault {
        FaultMode::ServerError => write_json_response(
            stream,
            500,
            &json!({"accepted":false,"error":"injected-server-error"}),
        ),
        FaultMode::UndocumentedStatus => write_json_response(
            stream,
            418,
            &json!({"accepted":false,"error":"injected-undocumented-status"}),
        ),
        FaultMode::MalformedResponse if valid => {
            write_json_response(stream, operation.success_status, &json!({"wrong":true}))
        }
        FaultMode::AcceptInvalid if !valid => write_json_response(
            stream,
            operation.success_status,
            &json!({"accepted":true,"operation":operation.operation_id,"seed":scenario.seed}),
        ),
        _ if valid => write_json_response(
            stream,
            operation.success_status,
            &json!({"accepted":true,"operation":operation.operation_id,"seed":scenario.seed}),
        ),
        _ => write_json_response(
            stream,
            400,
            &json!({"accepted":false,"error":"contract-rejected","operation":operation.operation_id}),
        ),
    }
}

fn validate_request(operation: &OperationScenario, request: &HttpRequest) -> bool {
    let Some(identifier) = path_identifier(operation, &request.path) else {
        return false;
    };
    if !validate_wire_scalar(&operation.identifier, identifier) {
        return false;
    }
    let Ok(url) = Url::parse(&format!("http://loopback{}", request.target)) else {
        return false;
    };
    let query = url
        .query_pairs()
        .find(|(name, _)| name.as_ref() == operation.query.name)
        .map(|(_, value)| value.into_owned());
    let Some(query) = query else { return false };
    if !validate_wire_scalar(&operation.query.rule, &query) {
        return false;
    }
    let header = request
        .headers
        .get(&operation.header.name.to_ascii_lowercase());
    let Some(header) = header else { return false };
    if !validate_wire_scalar(&operation.header.rule, header) {
        return false;
    }
    match &operation.body {
        None => request.body.is_empty(),
        Some(body) => {
            let Ok(value) = serde_json::from_slice::<Value>(&request.body) else {
                return false;
            };
            let Some(object) = value.as_object() else {
                return false;
            };
            if object.len() != body.fields.len() {
                return false;
            }
            body.fields.iter().all(|field| {
                object
                    .get(&field.name)
                    .is_some_and(|value| validate_scalar(&field.rule, value))
            })
        }
    }
}

fn path_identifier<'a>(operation: &OperationScenario, path: &'a str) -> Option<&'a str> {
    let (prefix, suffix) = operation.path.split_once("{id}")?;
    path.strip_prefix(prefix)?.strip_suffix(suffix)
}

fn validate_wire_scalar(rule: &ScalarRule, value: &str) -> bool {
    match rule {
        ScalarRule::String { .. } | ScalarRule::Enum { .. } => {
            validate_scalar(rule, &Value::String(value.into()))
        }
        ScalarRule::Integer { .. } => value
            .parse::<i64>()
            .ok()
            .is_some_and(|value| validate_scalar(rule, &json!(value))),
        ScalarRule::Boolean => matches!(value, "true" | "false"),
    }
}

fn validate_scalar(rule: &ScalarRule, value: &Value) -> bool {
    match rule {
        ScalarRule::String { min, max } => value.as_str().is_some_and(|value| {
            let length = value.chars().count();
            (*min..=*max).contains(&length)
        }),
        ScalarRule::Integer { min, max, multiple } => value
            .as_i64()
            .is_some_and(|value| (*min..=*max).contains(&value) && value % multiple == 0),
        ScalarRule::Boolean => value.is_boolean(),
        ScalarRule::Enum { values } => value
            .as_str()
            .is_some_and(|value| values.iter().any(|allowed| allowed == value)),
    }
}

fn write_json_response(
    stream: &mut TcpStream,
    status: u16,
    value: &impl Serialize,
) -> Result<(), ServerError> {
    write_response(
        stream,
        status,
        "application/json",
        &serde_json::to_vec(value)?,
    )
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<(), ServerError> {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        418 => "I'm a teapot",
        500 => "Internal Server Error",
        _ => "Test Response",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

#[derive(Debug)]
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e3779b97f4a7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
        value ^ (value >> 31)
    }

    fn range(&mut self, upper: u64) -> u64 {
        self.next() % upper
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kahea_ingest::load_openapi;
    use std::path::Path;

    #[test]
    fn same_seed_is_byte_identical_and_different_seeds_change_the_api() {
        let first = generate_scenario(42);
        let second = generate_scenario(42);
        let different = generate_scenario(43);
        assert_eq!(
            serde_json::to_vec(&first).unwrap(),
            serde_json::to_vec(&second).unwrap()
        );
        assert_ne!(
            serde_json::to_vec(&first).unwrap(),
            serde_json::to_vec(&different).unwrap()
        );
        assert!((3..=6).contains(&first.operations.len()));
    }

    #[test]
    fn emitted_openapi_is_ingestable_and_exposes_every_generated_operation() {
        let scenario = generate_scenario(8675309);
        let document = openapi_document(&scenario, "http://127.0.0.1:12345");
        let bytes = serde_json::to_vec(&document).unwrap();
        let source = load_openapi(Path::new("dynamic.json"), &bytes).unwrap();
        for operation in &scenario.operations {
            kahea_ingest::resolve_operation(&source, &operation.operation_id).unwrap();
        }
    }

    #[test]
    fn runtime_validation_is_independent_of_openapi_parsing() {
        let operation = &generate_scenario(100).operations[0];
        for rule in [
            ScalarRule::String { min: 2, max: 4 },
            ScalarRule::Integer {
                min: 2,
                max: 10,
                multiple: 2,
            },
            ScalarRule::Boolean,
            ScalarRule::Enum {
                values: vec!["a".into(), "b".into()],
            },
        ] {
            let valid = match &rule {
                ScalarRule::String { .. } => json!("abc"),
                ScalarRule::Integer { .. } => json!(4),
                ScalarRule::Boolean => json!(true),
                ScalarRule::Enum { .. } => json!("a"),
            };
            assert!(validate_scalar(&rule, &valid), "{}", operation.operation_id);
            assert!(!validate_scalar(&rule, &Value::Null));
        }
    }
}
