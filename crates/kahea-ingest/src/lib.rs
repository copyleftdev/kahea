//! Deterministic source ingestion behind `kahea-core` public types.

mod asyncapi;
mod imports;

pub use asyncapi::{
    AsyncApiOperation, AsyncApiSource, compile_asyncapi_websocket, inspect_asyncapi, is_asyncapi,
    load_asyncapi, resolve_asyncapi_operation,
};

use kahea_core::{
    AbsentCapability, DiagnosticSeverity, OperationIndexEnvelope, OperationSummary, PROTOCOL,
    RiskClass, VERSION, default_config_fingerprint, digest, short_handle,
};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use thiserror::Error;
use yaml_rust2::{Yaml, YamlLoader};

const HTTP_METHODS: [&str; 9] = [
    "get", "head", "options", "post", "put", "patch", "delete", "trace", "query",
];
const MAX_SOURCE_BYTES: usize = 64 * 1024 * 1024;
const MAX_DOCUMENT_DEPTH: usize = 128;
const MAX_DOCUMENT_NODES: usize = 1_000_000;

#[derive(Debug, Error)]
pub enum IngestError {
    #[error("could not read source {path}: {message}")]
    Read { path: String, message: String },
    #[error("source is not valid JSON or YAML: {0}")]
    Parse(String),
    #[error("source does not declare a supported OpenAPI version")]
    UnsupportedVersion,
    #[error("OpenAPI document is missing a paths object")]
    MissingPaths,
    #[error("cursor {cursor} is outside the filtered operation set of {len}")]
    InvalidCursor { cursor: usize, len: usize },
    #[error("operation {0:?} was not found")]
    UnknownOperation(String),
    #[error("operation selector {0:?} is ambiguous")]
    AmbiguousOperation(String),
    #[error("invalid AsyncAPI source: {0}")]
    InvalidAsyncApi(String),
}

/// Read a single source file or deterministically bundle a Postman Collection
/// v3 directory into the same no-network ingestion pipeline.
pub fn read_source_artifact(path: &Path) -> Result<Vec<u8>, IngestError> {
    if path.is_dir() {
        return imports::bundle_postman_v3_directory(path);
    }
    fs::read(path).map_err(|error| IngestError::Read {
        path: path.display().to_string(),
        message: error.to_string(),
    })
}

#[derive(Debug, Clone)]
pub struct OpenApiSource {
    pub document: Value,
    pub source_fingerprint: String,
    pub source_handle: String,
}

#[derive(Debug, Clone)]
pub struct OperationDefinition {
    pub handle: String,
    pub method: String,
    pub path: String,
    pub operation_id: String,
    pub risk: RiskClass,
    pub path_item: Map<String, Value>,
    pub operation: Map<String, Value>,
}

#[derive(Debug, Clone)]
struct IndexedOperation {
    handle: String,
    method: String,
    path: String,
    operation_id: String,
    summary: String,
    tags: Vec<String>,
    risk: RiskClass,
}

impl IndexedOperation {
    fn matches(&self, query: &str) -> bool {
        if query.is_empty() {
            return true;
        }
        let query = query.to_lowercase();
        [
            self.handle.as_str(),
            self.method.as_str(),
            self.path.as_str(),
            self.operation_id.as_str(),
            self.summary.as_str(),
        ]
        .into_iter()
        .chain(self.tags.iter().map(String::as_str))
        .any(|field| field.to_lowercase().contains(&query))
    }

    fn summary(self) -> OperationSummary {
        OperationSummary(
            self.handle,
            self.method,
            self.path,
            self.operation_id,
            self.risk,
        )
    }
}

pub fn inspect_openapi(
    path: &Path,
    bytes: &[u8],
    query: Option<&str>,
    limit: usize,
    cursor: usize,
) -> Result<OperationIndexEnvelope, IngestError> {
    inspect_source(path, bytes, query, limit, cursor)
}

pub fn inspect_source(
    path: &Path,
    bytes: &[u8],
    query: Option<&str>,
    limit: usize,
    cursor: usize,
) -> Result<OperationIndexEnvelope, IngestError> {
    let source = load_source(path, bytes)?;
    let mut absent = collect_absent(&source.document);
    let mut operations =
        collect_operations(&source.document, &source.source_fingerprint, &mut absent)?;
    operations.sort_by(|a, b| {
        (&a.path, &a.method, &a.operation_id, &a.handle).cmp(&(
            &b.path,
            &b.method,
            &b.operation_id,
            &b.handle,
        ))
    });

    let query = query.unwrap_or_default().trim();
    let filtered: Vec<_> = operations
        .into_iter()
        .filter(|operation| operation.matches(query))
        .collect();
    if cursor > filtered.len() {
        return Err(IngestError::InvalidCursor {
            cursor,
            len: filtered.len(),
        });
    }
    let end = cursor.saturating_add(limit).min(filtered.len());
    let next = (end < filtered.len()).then(|| end.to_string());
    let page = filtered
        .into_iter()
        .skip(cursor)
        .take(limit)
        .map(IndexedOperation::summary)
        .collect();

    absent.sort_by(|a, b| (&a.location, &a.capability).cmp(&(&b.location, &b.capability)));

    Ok(OperationIndexEnvelope {
        protocol: PROTOCOL.into(),
        kind: "operation-index".into(),
        version: VERSION.into(),
        config_fingerprint: default_config_fingerprint(),
        source_fingerprints: vec![source.source_fingerprint],
        source: source.source_handle,
        operations: page,
        next,
        absent,
        exit: 0,
    })
}

pub fn load_openapi(path: &Path, bytes: &[u8]) -> Result<OpenApiSource, IngestError> {
    let document = parse_document(path, bytes)?;
    validate_openapi_version(&document)?;
    Ok(OpenApiSource {
        document,
        source_fingerprint: digest(bytes),
        source_handle: short_handle("src", &[bytes]),
    })
}

pub fn load_source(path: &Path, bytes: &[u8]) -> Result<OpenApiSource, IngestError> {
    if let Some(document) = imports::import_document(path, bytes, None)? {
        return Ok(imported_source(document, bytes));
    }
    let parsed = parse_document(path, bytes)?;
    if validate_openapi_version(&parsed).is_ok() {
        return Ok(imported_source(parsed, bytes));
    }
    if let Some(document) = imports::import_document(path, bytes, Some(&parsed))? {
        return Ok(imported_source(document, bytes));
    }
    Err(IngestError::UnsupportedVersion)
}

fn imported_source(document: Value, bytes: &[u8]) -> OpenApiSource {
    OpenApiSource {
        document,
        source_fingerprint: digest(bytes),
        source_handle: short_handle("src", &[bytes]),
    }
}

pub fn parse_data_document(path: &Path, bytes: &[u8]) -> Result<Value, IngestError> {
    parse_document(path, bytes)
}

pub fn resolve_operation(
    source: &OpenApiSource,
    selector: &str,
) -> Result<OperationDefinition, IngestError> {
    let paths = source
        .document
        .get("paths")
        .and_then(Value::as_object)
        .ok_or(IngestError::MissingPaths)?;
    let normalized_selector = selector.trim();
    let mut matches = Vec::new();

    for (path, path_item) in paths {
        let Some(path_item) = path_item.as_object() else {
            continue;
        };
        for method in HTTP_METHODS {
            let Some(operation) = path_item.get(method).and_then(Value::as_object) else {
                continue;
            };
            let method_upper = method.to_ascii_uppercase();
            let operation_id = operation
                .get("operationId")
                .and_then(Value::as_str)
                .unwrap_or("");
            let handle = operation_handle(
                &source.source_fingerprint,
                &method_upper,
                path,
                operation_id,
            );
            let method_path = format!("{method_upper} {}", normalize_path(path));
            if handle == normalized_selector
                || (!operation_id.is_empty() && operation_id == normalized_selector)
                || method_path.eq_ignore_ascii_case(normalized_selector)
            {
                matches.push(OperationDefinition {
                    handle,
                    method: method_upper.clone(),
                    path: normalize_path(path),
                    operation_id: operation_id.into(),
                    risk: RiskClass::for_http_method(&method_upper),
                    path_item: path_item.clone(),
                    operation: operation.clone(),
                });
            }
        }
    }

    match matches.len() {
        0 => Err(IngestError::UnknownOperation(selector.into())),
        1 => Ok(matches.pop().expect("length checked")),
        _ => Err(IngestError::AmbiguousOperation(selector.into())),
    }
}

fn parse_document(path: &Path, bytes: &[u8]) -> Result<Value, IngestError> {
    if bytes.len() > MAX_SOURCE_BYTES {
        return Err(IngestError::Parse(format!(
            "source exceeds the {MAX_SOURCE_BYTES} byte parser limit"
        )));
    }
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let text = std::str::from_utf8(bytes).map_err(|error| IngestError::Parse(error.to_string()))?;

    if extension == "json" || text.trim_start().starts_with('{') {
        serde_json::from_str(text).map_err(|error| IngestError::Parse(error.to_string()))
    } else {
        parse_yaml_document(text)
    }
}

fn parse_yaml_document(text: &str) -> Result<Value, IngestError> {
    let mut documents =
        YamlLoader::load_from_str(text).map_err(|error| IngestError::Parse(error.to_string()))?;
    if documents.len() != 1 {
        return Err(IngestError::Parse(format!(
            "expected one YAML document, found {}",
            documents.len()
        )));
    }
    let mut nodes = 0;
    yaml_to_json(documents.pop().expect("length checked"), "#", 0, &mut nodes)
}

fn yaml_to_json(
    value: Yaml,
    location: &str,
    depth: usize,
    nodes: &mut usize,
) -> Result<Value, IngestError> {
    *nodes += 1;
    if depth > MAX_DOCUMENT_DEPTH || *nodes > MAX_DOCUMENT_NODES {
        return Err(IngestError::Parse(format!(
            "document complexity limit exceeded at {location}"
        )));
    }
    match value {
        Yaml::Null => Ok(Value::Null),
        Yaml::Boolean(value) => Ok(Value::Bool(value)),
        Yaml::Integer(value) => Ok(Value::Number(value.into())),
        Yaml::Real(value) => {
            // yaml-rust2 retains floats as strings and also represents integer
            // scalars outside i64 this way. Keep oversized integers lossless;
            // inspection never needs to evaluate their numeric value.
            if !value.contains(['.', 'e', 'E']) {
                return Ok(Value::String(value));
            }
            let number = value
                .parse::<f64>()
                .ok()
                .and_then(serde_json::Number::from_f64);
            number.map(Value::Number).ok_or_else(|| {
                IngestError::Parse(format!("non-finite number at {location}: {value}"))
            })
        }
        Yaml::String(value) => Ok(Value::String(value)),
        Yaml::Array(values) => values
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                yaml_to_json(value, &format!("{location}/{index}"), depth + 1, nodes)
            })
            .collect(),
        Yaml::Hash(values) => {
            let mut object = Map::new();
            for (key, value) in values {
                let Yaml::String(key) = key else {
                    return Err(IngestError::Parse(format!(
                        "non-string mapping key at {location}"
                    )));
                };
                let child_location = format!("{location}/{}", escape_pointer(&key));
                object.insert(key, yaml_to_json(value, &child_location, depth + 1, nodes)?);
            }
            Ok(Value::Object(object))
        }
        Yaml::Alias(_) | Yaml::BadValue => Err(IngestError::Parse(format!(
            "unsupported YAML node at {location}"
        ))),
    }
}

fn validate_openapi_version(document: &Value) -> Result<(), IngestError> {
    let Some(version) = document.get("openapi").and_then(Value::as_str) else {
        return Err(IngestError::UnsupportedVersion);
    };
    if version.starts_with("3.0.") || version.starts_with("3.1.") || version.starts_with("3.2.") {
        Ok(())
    } else {
        Err(IngestError::UnsupportedVersion)
    }
}

fn collect_operations(
    document: &Value,
    source_fingerprint: &str,
    absent: &mut Vec<AbsentCapability>,
) -> Result<Vec<IndexedOperation>, IngestError> {
    let Some(paths) = document.get("paths").and_then(Value::as_object) else {
        if document.get("webhooks").is_some() || document.get("components").is_some() {
            return Ok(Vec::new());
        }
        return Err(IngestError::MissingPaths);
    };
    let mut operations = Vec::new();
    let mut operation_ids: BTreeMap<String, String> = BTreeMap::new();

    for (path, item) in paths {
        let Some(item) = item.as_object() else {
            continue;
        };
        for method in HTTP_METHODS {
            let Some(operation) = item.get(method).and_then(Value::as_object) else {
                continue;
            };
            let method_upper = method.to_ascii_uppercase();
            let operation_id = operation
                .get("operationId")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let handle = operation_handle(source_fingerprint, &method_upper, path, &operation_id);
            if let Some(first) = (!operation_id.is_empty())
                .then(|| operation_ids.insert(operation_id.clone(), handle.clone()))
                .flatten()
            {
                absent.push(AbsentCapability {
                    capability: "unique-operation-id".into(),
                    reason: format!("operationId {operation_id:?} is also used by {first}"),
                    location: format!("#/paths/{}/{}", escape_pointer(path), method),
                    severity: DiagnosticSeverity::Error,
                    blocking: true,
                });
            }
            if operation.contains_key("callbacks") {
                absent.push(AbsentCapability {
                    capability: "openapi-callbacks".into(),
                    reason: "callbacks are not supported in release 0".into(),
                    location: format!("#/paths/{}/{}/callbacks", escape_pointer(path), method),
                    severity: DiagnosticSeverity::Warning,
                    blocking: false,
                });
            }
            absent.extend(
                operation
                    .get("x-kahea-absent")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|value| serde_json::from_value(value.clone()).ok()),
            );

            operations.push(IndexedOperation {
                handle,
                method: method_upper.clone(),
                path: normalize_path(path),
                operation_id,
                summary: operation
                    .get("summary")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .into(),
                tags: string_array(operation, "tags"),
                risk: RiskClass::for_http_method(&method_upper),
            });
        }
    }
    Ok(operations)
}

fn operation_handle(
    source_fingerprint: &str,
    method: &str,
    path: &str,
    operation_id: &str,
) -> String {
    short_handle(
        "op",
        &[
            source_fingerprint.as_bytes(),
            method.as_bytes(),
            path.as_bytes(),
            operation_id.as_bytes(),
        ],
    )
}

fn collect_absent(document: &Value) -> Vec<AbsentCapability> {
    let mut absent = Vec::new();
    if document.get("webhooks").is_some() {
        absent.push(AbsentCapability {
            capability: "openapi-webhooks".into(),
            reason: "webhooks are not indexed in release 0".into(),
            location: "#/webhooks".into(),
            severity: DiagnosticSeverity::Warning,
            blocking: false,
        });
    }
    absent.extend(
        document
            .get("x-kahea-absent")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|value| serde_json::from_value(value.clone()).ok()),
    );
    absent
}

fn string_array(object: &Map<String, Value>, key: &str) -> Vec<String> {
    object
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn normalize_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.starts_with('/') {
        trimmed.into()
    } else {
        format!("/{trimmed}")
    }
}

fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: &str = r#"
openapi: 3.1.0
info: { title: Billing, version: 1.0.0 }
paths:
  /v1/invoices/{id}:
    get:
      operationId: getInvoice
      summary: Fetch an invoice
      tags: [invoices]
      responses: { '200': { description: ok } }
  /v1/invoices:
    post:
      operationId: createInvoice
      tags: [invoices]
      responses: { '201': { description: created } }
"#;

    #[test]
    fn inspect_is_stable_and_sorted() {
        let first =
            inspect_openapi(Path::new("billing.yaml"), SPEC.as_bytes(), None, 50, 0).unwrap();
        let second =
            inspect_openapi(Path::new("renamed.yaml"), SPEC.as_bytes(), None, 50, 0).unwrap();
        assert_eq!(first.source, second.source);
        assert_eq!(first.operations, second.operations);
        assert_eq!(first.operations[0].1, "POST");
        assert_eq!(first.operations[1].1, "GET");
    }

    #[test]
    fn matching_uses_operation_metadata() {
        let index = inspect_openapi(
            Path::new("billing.yaml"),
            SPEC.as_bytes(),
            Some("fetch"),
            50,
            0,
        )
        .unwrap();
        assert_eq!(index.operations.len(), 1);
        assert_eq!(index.operations[0].3, "getInvoice");
    }

    #[test]
    fn pagination_is_stable() {
        let page = inspect_openapi(Path::new("billing.yaml"), SPEC.as_bytes(), None, 1, 0).unwrap();
        assert_eq!(page.operations.len(), 1);
        assert_eq!(page.next.as_deref(), Some("1"));
    }

    #[test]
    fn common_request_artifacts_normalize_to_operations() {
        let curl = load_source(
            Path::new("request.curl"),
            br#"curl -X POST 'https://example.test/items?dry=true' -H 'Content-Type: application/json' --data-raw '{"name":"one"}'"#,
        )
        .unwrap();
        let operation = resolve_operation(&curl, "curlRequest_0").unwrap();
        assert_eq!(operation.method, "POST");
        assert_eq!(operation.path, "/items");
        assert_eq!(operation.operation["x-kahea-captured-body"]["name"], "one");

        let http = inspect_source(
            Path::new("requests.http"),
            b"GET https://example.test/health\nAccept: application/json\n",
            None,
            50,
            0,
        )
        .unwrap();
        assert_eq!(http.operations.len(), 1);

        let http_with_body = load_source(
            Path::new("requests.http"),
            b"### Create\nPOST https://example.test/items\nContent-Type: application/json\n\n{\"name\":\"one\"}\n",
        )
        .unwrap();
        let operation = resolve_operation(&http_with_body, "httpRequest0_0").unwrap();
        assert_eq!(operation.operation["x-kahea-captured-body"]["name"], "one");

        let direct = inspect_source(
            Path::new("request.json"),
            br#"{"method":"DELETE","url":"https://example.test/items/1"}"#,
            None,
            50,
            0,
        )
        .unwrap();
        assert_eq!(direct.operations[0].4, RiskClass::Destructive);
    }

    #[test]
    fn postman_scripts_are_explicit_blocking_absence() {
        let collection = br#"{
          "info":{"name":"demo","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
          "item":[{"name":"list","request":{"method":"GET","url":"https://example.test/items"},"event":[{"listen":"test","script":{"exec":["pm.test('ok', () => {});"]}}]}]
        }"#;
        let index = inspect_source(Path::new("collection.json"), collection, None, 50, 0).unwrap();
        assert_eq!(index.operations.len(), 1);
        assert!(
            index
                .absent
                .iter()
                .any(|absence| { absence.capability == "postman-script" && absence.blocking })
        );
    }

    #[test]
    fn postman_variables_auth_metadata_and_safe_assertions_are_imported() {
        let collection = br#"{
          "info":{"name":"demo","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
          "variable":[{"key":"baseUrl","value":"https://example.test"}],
          "auth":{"type":"bearer","bearer":[{"key":"token","value":"must-not-survive"}]},
          "item":[{"name":"list","request":{"method":"GET","url":"{{baseUrl}}/items","auth":{"type":"inherit"}},"event":[{"listen":"test","script":{"exec":["pm.response.to.have.status(200);"]}}]}]
        }"#;
        let source = load_source(Path::new("collection.json"), collection).unwrap();
        let rendered = source.document.to_string();
        assert!(!rendered.contains("must-not-survive"));
        let operation = resolve_operation(&source, "list_0").unwrap();
        assert_eq!(operation.operation["x-kahea-checks"][0], "status:200");
        assert!(operation.operation.get("security").is_some());
        assert!(source.document["components"]["securitySchemes"]["importedAuth0"].is_object());
    }

    #[test]
    fn postman_structured_urls_are_normalized_and_unsupported_body_modes_are_absent() {
        let collection = br#"{
          "info":{"name":"structured","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
          "item":[
            {"name":"structured","request":{"method":"GET","url":{"protocol":"https","host":["api","example","test"],"path":["v1","items"],"query":[{"key":"limit","value":"10"}]}}},
            {"name":"form","request":{"method":"POST","url":"https://api.example.test/form","body":{"mode":"formdata","formdata":[{"key":"name","value":"one"}]}}}
          ]
        }"#;
        let source = load_source(Path::new("collection.json"), collection).unwrap();
        let structured = resolve_operation(&source, "structured_0").unwrap();
        assert_eq!(structured.path, "/v1/items");
        assert_eq!(
            structured.operation["parameters"][0]["schema"]["default"],
            "10"
        );
        let index = inspect_source(Path::new("collection.json"), collection, None, 50, 0).unwrap();
        assert!(index.absent.iter().any(|absence| {
            absence.capability == "postman-body-mode"
                && absence.location == "#/item/1/request/body"
                && absence.blocking
        }));
    }

    #[test]
    fn declared_har_and_postman_versions_are_enforced() {
        let har = br#"{"log":{"version":"1.1","entries":[]}}"#;
        assert!(load_source(Path::new("capture.har"), har).is_err());
        let postman = br#"{
          "info":{"name":"old","schema":"https://schema.getpostman.com/json/collection/v2.0.0/collection.json"},
          "item":[]
        }"#;
        assert!(load_source(Path::new("collection.json"), postman).is_err());
    }

    #[test]
    fn har_requests_are_imported_without_captured_credentials() {
        let har = br#"{"log":{"version":"1.2","entries":[{"request":{"method":"GET","url":"https://example.test/me","headers":[{"name":"Authorization","value":"Bearer should-not-survive"}]}}]}}"#;
        let source = load_source(Path::new("capture.har"), har).unwrap();
        assert!(!source.document.to_string().contains("should-not-survive"));
        let index = inspect_source(Path::new("capture.har"), har, None, 50, 0).unwrap();
        assert!(
            index
                .absent
                .iter()
                .any(|absence| absence.capability == "captured-credential")
        );
    }

    #[test]
    fn har_response_values_become_a_structural_contract_only() {
        let har = br#"{"log":{"version":"1.2","entries":[{"request":{"method":"GET","url":"https://example.test/me","headers":[]},"response":{"status":200,"headers":[{"name":"X-Trace","value":"private-trace"}],"content":{"mimeType":"application/json","text":"{\"id\":7,\"token\":\"must-not-survive\"}"}}}]}}"#;
        let source = load_source(Path::new("capture.har"), har).unwrap();
        let rendered = source.document.to_string();
        assert!(!rendered.contains("must-not-survive"));
        assert!(!rendered.contains("private-trace"));
        let operation = resolve_operation(&source, "harRequest0_0").unwrap();
        assert_eq!(
            operation.operation["responses"]["200"]["content"]["application/json"]["schema"]["properties"]
                ["id"]["type"],
            "integer"
        );
    }

    #[test]
    fn postman_v3_directories_are_bundled_deterministically() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/imports/postman-v3");
        let first = read_source_artifact(&root).unwrap();
        let second = read_source_artifact(&root).unwrap();
        assert_eq!(first, second);

        let index = inspect_source(&root, &first, None, 50, 0).unwrap();
        assert_eq!(index.operations.len(), 3);
        assert!(
            index.operations.iter().any(|operation| {
                operation.1 == "PUT" && operation.2 == "/admin/widgets/widget-1"
            })
        );
        assert!(
            index
                .absent
                .iter()
                .any(|absence| { absence.capability == "postman-script" && absence.blocking })
        );
        assert!(
            index
                .absent
                .iter()
                .any(|absence| { absence.capability == "postman-v3-example" && absence.blocking })
        );
        let source = load_source(&root, &first).unwrap();
        assert_eq!(
            source.document["info"]["title"],
            "Diverse Postman v3 fixture"
        );
    }
}
