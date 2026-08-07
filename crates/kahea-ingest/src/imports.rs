use crate::{IngestError, parse_data_document};
use kahea_core::digest;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use url::Url;

const MAX_POSTMAN_V3_FILES: usize = 10_000;
const MAX_POSTMAN_V3_BYTES: u64 = 64 * 1024 * 1024;

pub(crate) fn bundle_postman_v3_directory(root: &Path) -> Result<Vec<u8>, IngestError> {
    let mut paths = Vec::new();
    collect_directory_files(root, root, &mut paths)?;
    paths.sort();
    if paths.len() > MAX_POSTMAN_V3_FILES {
        return Err(IngestError::Parse(format!(
            "Postman v3 collection exceeds {MAX_POSTMAN_V3_FILES} files"
        )));
    }
    let script_owners: BTreeSet<String> = paths
        .iter()
        .filter(|path| is_postman_script_path(path))
        .filter_map(|path| postman_v3_resource_owner(path))
        .collect();
    let mut resource_absent: BTreeMap<String, Vec<CapturedAbsence>> = BTreeMap::new();
    for path in &paths {
        let Some(owner) = postman_v3_resource_owner(path) else {
            continue;
        };
        if is_postman_script_path(path) {
            continue;
        }
        let portable = path.to_string_lossy().replace('\\', "/");
        let example = portable.contains(".resources/examples/");
        resource_absent
            .entry(owner)
            .or_default()
            .push(CapturedAbsence {
                capability: if example {
                    "postman-v3-example".into()
                } else {
                    "postman-v3-resource".into()
                },
                reason: if example {
                    "Postman v3 example resources are not yet imported".into()
                } else {
                    "unknown Postman v3 request resource is not imported".into()
                },
                location: portable,
                blocking: true,
            });
    }
    let mut definitions = BTreeMap::new();
    for relative in &paths {
        let file_name = relative
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if file_name == "definition.yaml" || file_name == "definition.yml" {
            let absolute = root.join(relative);
            let bytes = fs::read(&absolute).map_err(|error| IngestError::Read {
                path: absolute.display().to_string(),
                message: error.to_string(),
            })?;
            definitions.insert(
                relative.parent().unwrap_or(Path::new("")).to_path_buf(),
                parse_data_document(&absolute, &bytes)?,
            );
        }
    }

    let mut total_bytes = 0_u64;
    let mut manifest = Vec::new();
    let mut items = Vec::new();
    let mut collection_events = Vec::new();
    let mut collection_variables = Value::Null;
    let mut collection_auth = Value::Null;
    let mut collection_name = root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("Postman v3 import")
        .to_string();

    for relative in paths {
        let absolute = root.join(&relative);
        let bytes = fs::read(&absolute).map_err(|error| IngestError::Read {
            path: absolute.display().to_string(),
            message: error.to_string(),
        })?;
        total_bytes = total_bytes.saturating_add(bytes.len() as u64);
        if total_bytes > MAX_POSTMAN_V3_BYTES {
            return Err(IngestError::Parse(format!(
                "Postman v3 collection exceeds {MAX_POSTMAN_V3_BYTES} bytes"
            )));
        }
        let portable_path = relative.to_string_lossy().replace('\\', "/");
        manifest.push(json!({
            "path": portable_path,
            "size": bytes.len(),
            "digest": digest(&bytes),
        }));

        let file_name = relative
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if file_name == "definition.yaml" || file_name == "definition.yml" {
            let definition = parse_data_document(&absolute, &bytes)?;
            if relative.parent().is_none() || relative.parent() == Some(Path::new("")) {
                collection_name = definition
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or(&collection_name)
                    .to_string();
                collection_variables = definition
                    .get("variables")
                    .or_else(|| definition.get("variable"))
                    .cloned()
                    .unwrap_or(Value::Null);
                collection_auth = definition.get("auth").cloned().unwrap_or(Value::Null);
            }
            if relative
                .parent()
                .is_none_or(|parent| parent.as_os_str().is_empty())
                && (definition.get("scripts").is_some() || definition.get("event").is_some())
            {
                collection_events.push(json!({"listen":"script","script":{"exec":[]}}));
            }
            continue;
        }
        if is_postman_script_path(&relative) {
            continue;
        }
        if !is_request_yaml(file_name) {
            continue;
        }

        let request_file = parse_data_document(&absolute, &bytes)?;
        let mut item = postman_v3_item(&request_file, &relative)?;
        apply_postman_v3_context(&mut item, &relative, &definitions);
        let owner = request_owner(&relative);
        if owner
            .as_ref()
            .is_some_and(|owner| script_owners.contains(owner))
        {
            item.as_object_mut()
                .expect("constructed item")
                .entry("event")
                .or_insert_with(|| Value::Array(Vec::new()))
                .as_array_mut()
                .expect("event is an array")
                .push(json!({"listen":"script","script":{"exec":[]}}));
        }
        if let Some(absent) = owner.as_ref().and_then(|owner| resource_absent.get(owner)) {
            item["x-kahea-absent"] = Value::Array(absent.iter().map(absence_value).collect());
        }
        items.push(item);
    }

    if items.is_empty() {
        return Err(IngestError::Parse(
            "Postman v3 directory contains no *.request.yaml files".into(),
        ));
    }
    items.sort_by(|left, right| {
        let left_order = left.get("_kahea_order").and_then(Value::as_f64);
        let right_order = right.get("_kahea_order").and_then(Value::as_f64);
        left_order
            .partial_cmp(&right_order)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                left.get("_kahea_path")
                    .and_then(Value::as_str)
                    .cmp(&right.get("_kahea_path").and_then(Value::as_str))
            })
    });
    for item in &mut items {
        item.as_object_mut()
            .expect("constructed item")
            .remove("_kahea_order");
    }

    serde_json::to_vec(&json!({
        "info": {
            "name": collection_name,
            "schema": "https://schema.postman.com/collection/yaml/v3.0.0/collection.json"
        },
        "item": items,
        "event": collection_events,
        "variable": collection_variables,
        "auth": collection_auth,
        "x-kahea-postman-v3": true,
        "x-kahea-source-manifest": manifest,
    }))
    .map_err(|error| IngestError::Parse(error.to_string()))
}

fn collect_directory_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), IngestError> {
    let entries = fs::read_dir(directory).map_err(|error| IngestError::Read {
        path: directory.display().to_string(),
        message: error.to_string(),
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| IngestError::Read {
            path: directory.display().to_string(),
            message: error.to_string(),
        })?;
        let file_type = entry.file_type().map_err(|error| IngestError::Read {
            path: entry.path().display().to_string(),
            message: error.to_string(),
        })?;
        if file_type.is_symlink() {
            return Err(IngestError::Parse(format!(
                "Postman v3 directory may not contain symlinks: {}",
                entry.path().display()
            )));
        }
        if file_type.is_dir() {
            collect_directory_files(root, &entry.path(), files)?;
        } else if file_type.is_file() {
            files.push(
                entry
                    .path()
                    .strip_prefix(root)
                    .expect("walk remains under root")
                    .to_path_buf(),
            );
        }
    }
    Ok(())
}

fn is_request_yaml(file_name: &str) -> bool {
    file_name.ends_with(".request.yaml") || file_name.ends_with(".request.yml")
}

fn is_postman_script_path(path: &Path) -> bool {
    let portable = path.to_string_lossy().replace('\\', "/");
    portable.contains(".resources/scripts/")
        || portable.contains(".resources/prerequest/")
        || portable.contains(".resources/tests/")
}

fn postman_v3_resource_owner(path: &Path) -> Option<String> {
    let portable = path.to_string_lossy().replace('\\', "/");
    portable
        .split_once(".resources/")
        .map(|(owner, _)| owner.to_string())
}

fn request_owner(path: &Path) -> Option<String> {
    let portable = path.to_string_lossy().replace('\\', "/");
    portable
        .strip_suffix(".request.yaml")
        .or_else(|| portable.strip_suffix(".request.yml"))
        .map(str::to_string)
}

fn apply_postman_v3_context(
    item: &mut Value,
    request_path: &Path,
    definitions: &BTreeMap<PathBuf, Value>,
) {
    let request_directory = request_path.parent().unwrap_or(Path::new(""));
    let mut contexts: Vec<_> = definitions
        .iter()
        .filter(|(directory, _)| {
            !directory.as_os_str().is_empty() && request_directory.starts_with(directory)
        })
        .collect();
    contexts.sort_by_key(|(directory, _)| directory.components().count());
    let mut variables = Vec::new();
    let mut auth = None;
    let mut scripted = false;
    for (_, definition) in contexts {
        if let Some(value) = definition
            .get("variables")
            .or_else(|| definition.get("variable"))
        {
            variables.extend(normalized_postman_variables(value));
        }
        if let Some(value) = definition.get("auth") {
            auth = Some(value.clone());
        }
        scripted |= definition.get("scripts").is_some() || definition.get("event").is_some();
    }
    let object = item.as_object_mut().expect("constructed item");
    if !variables.is_empty() {
        object.insert("variable".into(), Value::Array(variables));
    }
    if let Some(auth) = auth {
        object.insert("auth".into(), auth);
    }
    if scripted {
        object
            .entry("event")
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .expect("event is an array")
            .push(json!({"listen":"script","script":{"exec":[]}}));
    }
}

fn normalized_postman_variables(value: &Value) -> Vec<Value> {
    if let Some(values) = value.as_array() {
        return values.clone();
    }
    value
        .as_object()
        .into_iter()
        .flat_map(|variables| variables.iter())
        .map(|(key, value)| {
            if let Some(object) = value.as_object() {
                let mut variable = object.clone();
                variable.insert("key".into(), Value::String(key.clone()));
                Value::Object(variable)
            } else {
                json!({"key":key,"value":value})
            }
        })
        .collect()
}

fn postman_v3_item(value: &Value, relative: &Path) -> Result<Value, IngestError> {
    let object = value.as_object().ok_or_else(|| {
        IngestError::Parse(format!(
            "Postman v3 request {} must be an object",
            relative.display()
        ))
    })?;
    let request = object.get("request").cloned().unwrap_or_else(|| {
        let mut request = Map::new();
        for key in ["method", "url", "header", "headers", "body", "auth"] {
            if let Some(value) = object.get(key) {
                request.insert(key.into(), value.clone());
            }
        }
        Value::Object(request)
    });
    let mut request = request.as_object().cloned().ok_or_else(|| {
        IngestError::Parse(format!(
            "Postman v3 request {} has no HTTP request object",
            relative.display()
        ))
    })?;
    if request.get("header").is_none()
        && let Some(headers) = request.remove("headers")
    {
        request.insert("header".into(), headers);
    }
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .or_else(|| {
            relative
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.split(".request.").next())
        })
        .unwrap_or("request");
    let mut item = json!({
        "name": name,
        "request": request,
        "_kahea_path": relative.to_string_lossy().replace('\\', "/"),
    });
    if let Some(order) = object.get("order").and_then(Value::as_f64) {
        item["_kahea_order"] = json!(order);
    }
    if object.get("scripts").is_some() || object.get("event").is_some() {
        item["event"] = json!([{"listen":"script","script":{"exec":[]}}]);
    }
    Ok(item)
}

pub(crate) fn import_document(
    path: &Path,
    bytes: &[u8],
    parsed: Option<&Value>,
) -> Result<Option<Value>, IngestError> {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let text = std::str::from_utf8(bytes).map_err(|error| IngestError::Parse(error.to_string()))?;
    if matches!(extension.as_str(), "http" | "rest") {
        return import_http_file(text).map(Some);
    }
    if extension == "curl" || text.trim_start().starts_with("curl ") {
        return import_curl(text).map(Some);
    }
    if looks_like_http_file(text) {
        return import_http_file(text).map(Some);
    }
    let Some(parsed) = parsed else {
        return Ok(None);
    };
    if parsed
        .pointer("/log/entries")
        .and_then(Value::as_array)
        .is_some()
    {
        return import_har(parsed).map(Some);
    }
    if parsed.get("item").and_then(Value::as_array).is_some()
        && parsed.pointer("/info/schema").is_some()
    {
        return import_postman(parsed).map(Some);
    }
    if parsed.get("method").is_some()
        && (parsed.get("url").is_some() || parsed.get("target").is_some())
    {
        return import_direct(parsed).map(Some);
    }
    Ok(None)
}

fn base_document(title: &str) -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {"title": title, "version": "imported"},
        "paths": {},
        "components": {"securitySchemes": {}},
        "x-kahea-absent": [],
    })
}

#[derive(Default)]
struct CapturedRequest {
    name: String,
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
    media_type: Option<String>,
    auth: Option<CapturedAuth>,
    checks: Vec<String>,
    absent: Vec<CapturedAbsence>,
}

#[derive(Clone)]
struct CapturedAbsence {
    capability: String,
    reason: String,
    location: String,
    blocking: bool,
}

#[derive(Default)]
struct CapturedAuth {
    kind: String,
    name: Option<String>,
    location: Option<String>,
}

fn add_request(
    document: &mut Value,
    request: CapturedRequest,
    index: usize,
) -> Result<(), IngestError> {
    let url = Url::parse(&request.url).map_err(|error| {
        IngestError::Parse(format!(
            "captured request {} has invalid URL: {error}",
            request.name
        ))
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(IngestError::Parse(format!(
            "captured request {} uses unsupported scheme {:?}",
            request.name,
            url.scheme()
        )));
    }
    let host = url
        .host_str()
        .ok_or_else(|| IngestError::Parse("captured URL has no host".into()))?;
    let origin = format!(
        "{}://{}{}",
        url.scheme(),
        host,
        url.port()
            .map(|port| format!(":{port}"))
            .unwrap_or_default()
    );
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    let method = request.method.to_ascii_lowercase();
    if !matches!(
        method.as_str(),
        "get" | "head" | "options" | "post" | "put" | "patch" | "delete" | "trace" | "query"
    ) {
        return Err(IngestError::Parse(format!(
            "captured request has unsupported method {:?}",
            request.method
        )));
    }
    let mut parameters = Vec::new();
    for (name, value) in url.query_pairs() {
        parameters.push(json!({
            "name": name,
            "in": "query",
            "schema": {"type": "string", "default": value},
        }));
    }
    let mut content_type = request.media_type;
    for (name, value) in request.headers {
        if name.eq_ignore_ascii_case("content-type") {
            content_type = Some(value);
        } else if name.eq_ignore_ascii_case("authorization")
            || name.eq_ignore_ascii_case("proxy-authorization")
            || name.eq_ignore_ascii_case("cookie")
        {
            push_absent(
                document,
                "captured-credential",
                "captured credential material is never imported; configure an auth profile",
                &format!("request[{index}].headers.{name}"),
                true,
            );
        } else {
            parameters.push(json!({
                "name": name,
                "in": "header",
                "schema": {"type": "string", "default": value},
            }));
        }
    }
    let operation_id = safe_operation_id(&request.name, index);
    let mut operation = json!({
        "operationId": operation_id,
        "summary": request.name,
        "servers": [{"url": origin}],
        "parameters": parameters,
        "responses": {"default": {"description": "imported capture response"}},
        "x-kahea-imported": true,
    });
    if !request.checks.is_empty() {
        operation["x-kahea-checks"] = json!(request.checks);
    }
    if !request.absent.is_empty() {
        operation["x-kahea-absent"] = Value::Array(
            request
                .absent
                .into_iter()
                .map(|absence| absence_value(&absence))
                .collect(),
        );
    }
    if let Some(auth) = request.auth {
        let scheme_name = format!("importedAuth{index}");
        let scheme = match auth.kind.as_str() {
            "basic" => json!({"type":"http","scheme":"basic"}),
            "bearer" | "oauth2" => json!({"type":"http","scheme":"bearer"}),
            "apikey" => json!({
                "type":"apiKey",
                "name":auth.name.unwrap_or_else(|| "X-API-Key".into()),
                "in":auth.location.unwrap_or_else(|| "header".into())
            }),
            _ => unreachable!("captured auth is normalized before add_request"),
        };
        document["components"]["securitySchemes"][&scheme_name] = scheme;
        operation["security"] = json!([{scheme_name: []}]);
    }
    if let Some(body) = request.body {
        let media_type = content_type.unwrap_or_else(|| {
            if serde_json::from_str::<Value>(&body).is_ok() {
                "application/json".into()
            } else {
                "text/plain".into()
            }
        });
        let captured = if media_type.contains("json") {
            serde_json::from_str(&body).map_err(|error| {
                IngestError::Parse(format!("captured JSON body is invalid: {error}"))
            })?
        } else {
            Value::String(body)
        };
        operation["requestBody"] = json!({
            "required": true,
            "content": {media_type.clone(): {"schema": {}}},
        });
        operation["x-kahea-captured-body"] = captured;
        operation["x-kahea-captured-body-media-type"] = Value::String(media_type);
    }
    let paths = document["paths"]
        .as_object_mut()
        .expect("base paths object");
    let item = paths.entry(path.to_string()).or_insert_with(|| json!({}));
    if item.get(&method).is_some() {
        return Err(IngestError::Parse(format!(
            "multiple imported requests collide at {} {}",
            method.to_ascii_uppercase(),
            path
        )));
    }
    item[&method] = operation;
    Ok(())
}

fn import_har(value: &Value) -> Result<Value, IngestError> {
    let version = value.pointer("/log/version").and_then(Value::as_str);
    if version != Some("1.2") {
        return Err(IngestError::Parse(format!(
            "unsupported HAR version {:?}; expected 1.2",
            version.unwrap_or("missing")
        )));
    }
    let mut document = base_document("HAR import");
    let entries = value
        .pointer("/log/entries")
        .and_then(Value::as_array)
        .expect("detected HAR entries");
    for (index, entry) in entries.iter().enumerate() {
        let request = entry
            .get("request")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                IngestError::Parse(format!("HAR entry {index} has no request object"))
            })?;
        let headers = named_values(request.get("headers"));
        let post_data = request.get("postData").and_then(Value::as_object);
        let method = string(request, "method").unwrap_or("GET");
        let url = string(request, "url").unwrap_or_default();
        add_request(
            &mut document,
            CapturedRequest {
                name: format!("harRequest{index}"),
                method: method.into(),
                url: url.into(),
                headers,
                body: post_data
                    .and_then(|data| string(data, "text"))
                    .map(str::to_string),
                media_type: post_data
                    .and_then(|data| string(data, "mimeType"))
                    .map(str::to_string),
                ..CapturedRequest::default()
            },
            index,
        )?;
        if let Some(response) = entry.get("response") {
            add_har_response_contract(&mut document, method, url, response, index)?;
        }
    }
    Ok(document)
}

fn add_har_response_contract(
    document: &mut Value,
    method: &str,
    raw_url: &str,
    response: &Value,
    index: usize,
) -> Result<(), IngestError> {
    let url = Url::parse(raw_url).map_err(|error| IngestError::Parse(error.to_string()))?;
    let status = response
        .get("status")
        .and_then(Value::as_u64)
        .filter(|status| *status <= 999)
        .unwrap_or(200)
        .to_string();
    let content = response.get("content").unwrap_or(&Value::Null);
    let media_type = content
        .get("mimeType")
        .and_then(Value::as_str)
        .unwrap_or("application/octet-stream");
    let schema = content
        .get("text")
        .and_then(Value::as_str)
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .map(|value| shape_schema(&value))
        .unwrap_or_else(|| json!({}));
    let mut headers = Map::new();
    for (name, _) in named_values(response.get("headers")) {
        if !name.eq_ignore_ascii_case("set-cookie")
            && !name.eq_ignore_ascii_case("authorization")
            && !name.eq_ignore_ascii_case("proxy-authorization")
        {
            headers.insert(name, json!({"schema":{"type":"string"}}));
        }
    }
    let pointer = format!(
        "/paths/{}/{}",
        url.path().replace('~', "~0").replace('/', "~1"),
        method.to_ascii_lowercase()
    );
    let operation = document
        .pointer_mut(&pointer)
        .ok_or_else(|| IngestError::Parse("HAR response operation was not found".into()))?;
    operation["responses"] = json!({
        status.clone():{
            "description":"captured HAR response contract",
            "headers":headers,
            "content":{media_type.to_string():{"schema":schema}}
        }
    });
    push_absent(
        document,
        "har-response-body",
        "captured response values are not copied; only their structural contract is imported",
        &format!("#/log/entries/{index}/response/content/text"),
        false,
    );
    Ok(())
}

fn shape_schema(value: &Value) -> Value {
    match value {
        Value::Null => json!({"type":"null"}),
        Value::Bool(_) => json!({"type":"boolean"}),
        Value::Number(number) if number.is_i64() || number.is_u64() => json!({"type":"integer"}),
        Value::Number(_) => json!({"type":"number"}),
        Value::String(_) => json!({"type":"string"}),
        Value::Array(values) => json!({
            "type":"array",
            "items":values.first().map(shape_schema).unwrap_or_else(|| json!({}))
        }),
        Value::Object(values) => {
            let properties: Map<_, _> = values
                .iter()
                .map(|(name, value)| (name.clone(), shape_schema(value)))
                .collect();
            json!({
                "type":"object",
                "properties":properties,
                "required":values.keys().cloned().collect::<Vec<_>>()
            })
        }
    }
}

fn import_postman(value: &Value) -> Result<Value, IngestError> {
    let schema = value
        .pointer("/info/schema")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !schema.contains("/v2.1.0/")
        && !schema.contains("/v3.0.0/")
        && !value
            .get("x-kahea-postman-v3")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        return Err(IngestError::Parse(format!(
            "unsupported Postman collection schema {schema:?}"
        )));
    }
    let title = value
        .pointer("/info/name")
        .and_then(Value::as_str)
        .unwrap_or("Postman import");
    let mut document = base_document(title);
    let mut index = 0;
    let variables = postman_variables(value.get("variable"));
    if let Some(absent) = value.get("x-kahea-absent").and_then(Value::as_array) {
        document["x-kahea-absent"] = Value::Array(absent.clone());
    }
    let (checks, collection_absent) = collect_postman_events(value, "#");
    for absence in collection_absent {
        push_captured_absent(&mut document, &absence);
    }
    walk_postman_items(
        value.get("item"),
        &mut document,
        &mut index,
        "#/item",
        PostmanWalkContext {
            variables: &variables,
            auth: value.get("auth"),
            checks: &checks,
            absent: &[],
        },
    )?;
    Ok(document)
}

#[derive(Clone, Copy)]
struct PostmanWalkContext<'a> {
    variables: &'a BTreeMap<String, Option<String>>,
    auth: Option<&'a Value>,
    checks: &'a [String],
    absent: &'a [CapturedAbsence],
}

fn walk_postman_items(
    items: Option<&Value>,
    document: &mut Value,
    index: &mut usize,
    location: &str,
    context: PostmanWalkContext<'_>,
) -> Result<(), IngestError> {
    for (position, item) in items
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let item_location = format!("{location}/{position}");
        let mut checks = context.checks.to_vec();
        let (local_checks, local_absent) = collect_postman_events(item, &item_location);
        checks.extend(local_checks);
        checks.sort();
        checks.dedup();
        let mut absent = context.absent.to_vec();
        absent.extend(local_absent);
        absent.extend(
            item.get("x-kahea-absent")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(captured_absence),
        );
        let mut variables = context.variables.clone();
        variables.extend(postman_variables(item.get("variable")));
        let item_auth = item.get("auth").or(context.auth);
        if item.get("item").is_some() {
            walk_postman_items(
                item.get("item"),
                document,
                index,
                &format!("{item_location}/item"),
                PostmanWalkContext {
                    variables: &variables,
                    auth: item_auth,
                    checks: &checks,
                    absent: &absent,
                },
            )?;
            continue;
        }
        let Some(request) = item.get("request") else {
            continue;
        };
        let request_object = request.as_object();
        let request_auth = request_object.and_then(|request| request.get("auth"));
        let effective_auth = request_auth
            .filter(|auth| auth.get("type").and_then(Value::as_str) != Some("inherit"))
            .or(item_auth);
        let auth = effective_auth
            .map(|auth| normalize_postman_auth(auth, document, &item_location))
            .transpose()?
            .flatten();
        let url = request_object
            .and_then(|request| request.get("url"))
            .map(postman_url)
            .transpose()?
            .or_else(|| request.as_str().map(str::to_string))
            .unwrap_or_default();
        let url = substitute_postman_variables(&url, &variables);
        if url.contains("{{") {
            push_absent(
                document,
                "postman-variable",
                "unresolved Postman variables require explicit conversion",
                &format!("{item_location}/request/url"),
                true,
            );
            continue;
        }
        let body_object = request_object.and_then(|request| request.get("body"));
        let body = body_object
            .and_then(|body| {
                body.as_str().or_else(|| {
                    body.get("raw")
                        .or_else(|| body.get("data"))
                        .and_then(Value::as_str)
                })
            })
            .map(|body| substitute_postman_variables(body, &variables));
        if let Some(mode) = body_object
            .and_then(|body| body.get("mode"))
            .and_then(Value::as_str)
            .filter(|mode| *mode != "raw")
        {
            absent.push(CapturedAbsence {
                capability: "postman-body-mode".into(),
                reason: format!("Postman request body mode {mode:?} is not supported"),
                location: format!("{item_location}/request/body"),
                blocking: true,
            });
        }
        let headers: Vec<(String, String)> = request_object
            .and_then(|request| request.get("header"))
            .map(|headers| named_values(Some(headers)))
            .unwrap_or_default()
            .into_iter()
            .map(|(name, value)| (name, substitute_postman_variables(&value, &variables)))
            .collect();
        if body.as_deref().is_some_and(|body| body.contains("{{"))
            || headers.iter().any(|(_, value)| value.contains("{{"))
        {
            absent.push(CapturedAbsence {
                capability: "postman-variable".into(),
                reason: "unresolved or secret Postman variables require explicit input".into(),
                location: format!("{item_location}/request"),
                blocking: true,
            });
        }
        let method = request_object
            .and_then(|request| string(request, "method"))
            .unwrap_or("GET")
            .to_string();
        add_request(
            document,
            CapturedRequest {
                name: item
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("request")
                    .into(),
                method: method.clone(),
                url: url.clone(),
                headers,
                body,
                media_type: request_object
                    .and_then(|request| request.get("body"))
                    .and_then(|body| body.get("options"))
                    .and_then(|options| options.get("raw"))
                    .and_then(|raw| raw.get("language"))
                    .and_then(Value::as_str)
                    .filter(|language| *language == "json")
                    .map(|_| "application/json".into()),
                auth,
                checks,
                absent,
            },
            *index,
        )?;
        add_postman_examples(document, &method, &url, item.get("response"))?;
        *index += 1;
    }
    Ok(())
}

fn postman_url(value: &Value) -> Result<String, IngestError> {
    if let Some(url) = value.as_str() {
        return Ok(url.into());
    }
    if let Some(raw) = value.get("raw").and_then(Value::as_str) {
        return Ok(raw.into());
    }
    let object = value.as_object().ok_or_else(|| {
        IngestError::Parse("Postman request URL must be a string or object".into())
    })?;
    let protocol = object
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or("https");
    let host = string_or_segments(object.get("host"), ".");
    if host.is_empty() {
        return Err(IngestError::Parse(
            "structured Postman request URL has no host".into(),
        ));
    }
    let path = string_or_segments(object.get("path"), "/");
    let port = object
        .get("port")
        .and_then(|value| {
            value
                .as_str()
                .map(str::to_string)
                .or_else(|| value.as_u64().map(|v| v.to_string()))
        })
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    let mut url = format!("{protocol}://{host}{port}");
    if !path.is_empty() {
        url.push('/');
        url.push_str(path.trim_start_matches('/'));
    }
    if let Some(query) = object.get("query").and_then(Value::as_array) {
        let pairs: Vec<_> = query
            .iter()
            .filter(|entry| {
                !entry
                    .get("disabled")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            })
            .filter_map(|entry| {
                Some((
                    entry.get("key")?.as_str()?.to_string(),
                    entry
                        .get("value")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                ))
            })
            .collect();
        if !pairs.is_empty() {
            let mut parsed = Url::parse(&url).map_err(|error| {
                IngestError::Parse(format!("structured Postman URL is invalid: {error}"))
            })?;
            parsed.query_pairs_mut().extend_pairs(pairs);
            url = parsed.to_string();
        }
    }
    Ok(url)
}

fn string_or_segments(value: Option<&Value>, separator: &str) -> String {
    value
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            value.and_then(Value::as_array).map(|segments| {
                segments
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(separator)
            })
        })
        .unwrap_or_default()
}

fn add_postman_examples(
    document: &mut Value,
    method: &str,
    raw_url: &str,
    examples: Option<&Value>,
) -> Result<(), IngestError> {
    let Some(examples) = examples.and_then(Value::as_array) else {
        return Ok(());
    };
    if examples.is_empty() {
        return Ok(());
    }
    let url = Url::parse(raw_url).map_err(|error| IngestError::Parse(error.to_string()))?;
    let pointer = format!(
        "/paths/{}/{}",
        url.path().replace('~', "~0").replace('/', "~1"),
        method.to_ascii_lowercase()
    );
    let operation = document
        .pointer_mut(&pointer)
        .ok_or_else(|| IngestError::Parse("Postman example operation was not found".into()))?;
    let mut responses = Map::new();
    let mut names = Vec::new();
    for example in examples {
        let status = example
            .get("code")
            .and_then(Value::as_u64)
            .filter(|status| *status <= 999)
            .unwrap_or(200)
            .to_string();
        let content_type = named_values(example.get("header"))
            .into_iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| value)
            .unwrap_or_else(|| "application/octet-stream".into());
        let schema = example
            .get("body")
            .and_then(Value::as_str)
            .and_then(|body| serde_json::from_str::<Value>(body).ok())
            .map(|value| shape_schema(&value))
            .unwrap_or_else(|| json!({}));
        responses.insert(
            status,
            json!({
                "description":"Postman example structural contract",
                "content":{content_type.clone():{"schema":schema}}
            }),
        );
        if let Some(name) = example.get("name").and_then(Value::as_str) {
            names.push(name.to_string());
        }
    }
    operation["responses"] = Value::Object(responses);
    operation["x-kahea-example-names"] = json!(names);
    Ok(())
}

fn postman_variables(value: Option<&Value>) -> BTreeMap<String, Option<String>> {
    let mut variables = BTreeMap::new();
    if let Some(entries) = value.and_then(Value::as_array) {
        for entry in entries {
            let Some(key) = entry
                .get("key")
                .or_else(|| entry.get("name"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            let secret = entry
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| matches!(kind, "secret" | "password"))
                || secret_like_name(key);
            variables.insert(
                key.into(),
                (!secret)
                    .then(|| {
                        entry
                            .get("value")
                            .and_then(Value::as_str)
                            .map(str::to_string)
                    })
                    .flatten(),
            );
        }
    } else if let Some(entries) = value.and_then(Value::as_object) {
        for (key, value) in entries {
            let secret = secret_like_name(key)
                || value
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| matches!(kind, "secret" | "password"));
            let value = value
                .as_str()
                .or_else(|| value.get("value").and_then(Value::as_str));
            variables.insert(
                key.clone(),
                (!secret).then(|| value.map(str::to_string)).flatten(),
            );
        }
    }
    variables
}

fn secret_like_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "secret",
        "password",
        "passwd",
        "token",
        "api_key",
        "apikey",
        "credential",
    ]
    .iter()
    .any(|marker| name.contains(marker))
}

fn substitute_postman_variables(
    text: &str,
    variables: &BTreeMap<String, Option<String>>,
) -> String {
    let mut resolved = text.to_string();
    for (name, value) in variables {
        if let Some(value) = value {
            resolved = resolved.replace(&format!("{{{{{name}}}}}"), value);
        }
    }
    resolved
}

fn collect_postman_events(value: &Value, location: &str) -> (Vec<String>, Vec<CapturedAbsence>) {
    let mut checks = Vec::new();
    let mut absent = Vec::new();
    for (index, event) in value
        .get("event")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let kind = event
            .get("listen")
            .and_then(Value::as_str)
            .unwrap_or("script");
        if kind == "test" {
            let lines: Vec<_> = event
                .pointer("/script/exec")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .flat_map(str::lines)
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .collect();
            let translated: Vec<_> = lines
                .iter()
                .filter_map(|line| postman_status_assertion(line))
                .collect();
            let recognized = lines.iter().all(|line| {
                postman_status_assertion(line).is_some() || postman_assertion_wrapper(line)
            });
            if recognized && !translated.is_empty() {
                checks.extend(translated);
                continue;
            }
        }
        absent.push(CapturedAbsence {
            capability: "postman-script".into(),
            reason: format!("Postman {kind} JavaScript execution is not supported"),
            location: format!("{location}/event/{index}"),
            blocking: true,
        });
    }
    checks.sort();
    checks.dedup();
    (checks, absent)
}

fn postman_assertion_wrapper(line: &str) -> bool {
    let line = line.trim();
    (line.starts_with("pm.test(") && (line.ends_with("function () {") || line.ends_with("() => {")))
        || matches!(line, "});" | "}" | "};")
}

fn postman_status_assertion(line: &str) -> Option<String> {
    let status = line
        .strip_prefix("pm.response.to.have.status(")
        .and_then(|value| value.strip_suffix(");"))
        .or_else(|| {
            line.strip_prefix("pm.expect(pm.response.code).to.eql(")
                .and_then(|value| value.strip_suffix(");"))
        })?
        .trim()
        .parse::<u16>()
        .ok()?;
    Some(format!("status:{status}"))
}

fn normalize_postman_auth(
    auth: &Value,
    document: &mut Value,
    location: &str,
) -> Result<Option<CapturedAuth>, IngestError> {
    let kind = auth
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("noauth")
        .to_ascii_lowercase();
    if matches!(kind.as_str(), "noauth" | "inherit") {
        return Ok(None);
    }
    if !matches!(kind.as_str(), "basic" | "bearer" | "oauth2" | "apikey") {
        push_absent(
            document,
            "postman-auth",
            &format!("Postman authentication type {kind:?} is not supported"),
            &format!("{location}/request/auth"),
            true,
        );
        return Ok(None);
    }
    let entries = auth.get(&kind).and_then(Value::as_array);
    let setting = |key: &str| {
        entries.into_iter().flatten().find_map(|entry| {
            (entry.get("key").and_then(Value::as_str) == Some(key))
                .then(|| entry.get("value").and_then(Value::as_str))
                .flatten()
        })
    };
    let name = (kind == "apikey")
        .then(|| setting("key").map(str::to_string))
        .flatten();
    let location = (kind == "apikey")
        .then(|| setting("in").map(str::to_ascii_lowercase))
        .flatten();
    Ok(Some(CapturedAuth {
        kind,
        name,
        location,
    }))
}

fn import_curl(text: &str) -> Result<Value, IngestError> {
    let words = shell_words::split(text).map_err(|error| IngestError::Parse(error.to_string()))?;
    if words.first().map(String::as_str) != Some("curl") {
        return Err(IngestError::Parse("cURL input must begin with curl".into()));
    }
    let mut request = CapturedRequest {
        name: "curlRequest".into(),
        method: "GET".into(),
        ..CapturedRequest::default()
    };
    let mut index = 1;
    while index < words.len() {
        match words[index].as_str() {
            "-X" | "--request" => {
                index += 1;
                request.method = required_word(&words, index, "request method")?.into();
            }
            "-H" | "--header" => {
                index += 1;
                let header = required_word(&words, index, "header")?;
                let (name, value) = header
                    .split_once(':')
                    .ok_or_else(|| IngestError::Parse(format!("invalid cURL header {header:?}")))?;
                request
                    .headers
                    .push((name.trim().into(), value.trim().into()));
            }
            "-d" | "--data" | "--data-raw" | "--data-binary" => {
                index += 1;
                request.body = Some(required_word(&words, index, "request body")?.into());
                if request.method == "GET" {
                    request.method = "POST".into();
                }
            }
            "-u" | "--user" | "--oauth2-bearer" => {
                return Err(IngestError::Parse(
                    "inline cURL credentials are denied; use an auth profile".into(),
                ));
            }
            value if value.starts_with("http://") || value.starts_with("https://") => {
                request.url = value.into()
            }
            value if value.starts_with('-') => {
                return Err(IngestError::Parse(format!(
                    "unsupported cURL option {value:?}"
                )));
            }
            value => request.url = value.into(),
        }
        index += 1;
    }
    let mut document = base_document("cURL import");
    add_request(&mut document, request, 0)?;
    Ok(document)
}

fn import_http_file(text: &str) -> Result<Value, IngestError> {
    let mut document = base_document("HTTP file import");
    let mut sections: Vec<Vec<&str>> = vec![Vec::new()];
    for line in text.lines() {
        if line.trim_start().starts_with("###") {
            if sections.last().is_some_and(|section| !section.is_empty()) {
                sections.push(Vec::new());
            }
            continue;
        }
        sections.last_mut().expect("one section exists").push(line);
    }
    for (index, section) in sections.into_iter().enumerate() {
        let Some(request_line) = section.iter().position(|line| {
            let line = line.trim();
            !line.is_empty() && !line.starts_with('#')
        }) else {
            continue;
        };
        let first = section[request_line].trim();
        let mut first_parts = first.split_whitespace();
        let method = first_parts.next().unwrap_or("GET");
        let url = first_parts
            .next()
            .ok_or_else(|| IngestError::Parse(format!("HTTP request {index} has no URL")))?;
        if url.contains("{{") {
            push_absent(
                &mut document,
                "http-variable",
                "unresolved HTTP-file variable",
                &format!("request[{index}]"),
                true,
            );
            continue;
        }
        let mut headers = Vec::new();
        let mut body_lines = Vec::new();
        let mut in_body = false;
        for raw_line in section.into_iter().skip(request_line + 1) {
            let line = raw_line.trim();
            if !in_body {
                if line.is_empty() {
                    in_body = true;
                    continue;
                }
                if line.starts_with('#') {
                    continue;
                }
                if let Some((name, value)) = line.split_once(':') {
                    headers.push((name.trim().into(), value.trim().into()));
                    continue;
                }
                in_body = true;
            }
            body_lines.push(raw_line);
        }
        while body_lines.last().is_some_and(|line| line.trim().is_empty()) {
            body_lines.pop();
        }
        add_request(
            &mut document,
            CapturedRequest {
                name: format!("httpRequest{index}"),
                method: method.into(),
                url: url.into(),
                headers,
                body: (!body_lines.is_empty()).then(|| body_lines.join("\n")),
                media_type: None,
                ..CapturedRequest::default()
            },
            index,
        )?;
    }
    Ok(document)
}

fn looks_like_http_file(text: &str) -> bool {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with("###"))
        .and_then(|line| {
            let mut words = line.split_whitespace();
            Some((words.next()?, words.next()?))
        })
        .is_some_and(|(method, target)| {
            matches!(
                method.to_ascii_uppercase().as_str(),
                "GET"
                    | "HEAD"
                    | "OPTIONS"
                    | "POST"
                    | "PUT"
                    | "PATCH"
                    | "DELETE"
                    | "TRACE"
                    | "QUERY"
            ) && (target.starts_with("http://") || target.starts_with("https://"))
        })
}

fn import_direct(value: &Value) -> Result<Value, IngestError> {
    let mut document = base_document("Kāhea direct descriptor");
    let object = value
        .as_object()
        .ok_or_else(|| IngestError::Parse("direct descriptor must be an object".into()))?;
    let headers = object
        .get("headers")
        .and_then(Value::as_object)
        .map(|headers| {
            headers
                .iter()
                .map(|(name, value)| (name.clone(), value.as_str().unwrap_or_default().into()))
                .collect()
        })
        .unwrap_or_default();
    add_request(
        &mut document,
        CapturedRequest {
            name: string(object, "operationId")
                .unwrap_or("directRequest")
                .into(),
            method: string(object, "method").unwrap_or("GET").into(),
            url: string(object, "url")
                .or_else(|| string(object, "target"))
                .unwrap_or_default()
                .into(),
            headers,
            body: object.get("body").map(|body| {
                if body.is_string() {
                    body.as_str().unwrap().into()
                } else {
                    serde_json::to_string(body).expect("JSON value")
                }
            }),
            media_type: string(object, "content_type").map(str::to_string),
            ..CapturedRequest::default()
        },
        0,
    )?;
    Ok(document)
}

fn named_values(value: Option<&Value>) -> Vec<(String, String)> {
    if let Some(object) = value.and_then(Value::as_object) {
        return object
            .iter()
            .filter_map(|(name, value)| Some((name.clone(), value.as_str()?.into())))
            .collect();
    }
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|entry| {
            !entry
                .get("disabled")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .filter_map(|entry| {
            Some((
                entry
                    .get("name")
                    .or_else(|| entry.get("key"))?
                    .as_str()?
                    .into(),
                entry.get("value")?.as_str()?.into(),
            ))
        })
        .collect()
}

fn push_absent(
    document: &mut Value,
    capability: &str,
    reason: &str,
    location: &str,
    blocking: bool,
) {
    document["x-kahea-absent"]
        .as_array_mut()
        .expect("base absence array")
        .push(json!({
            "capability": capability,
            "reason": reason,
            "location": location,
            "severity": if blocking { "error" } else { "warning" },
            "blocking": blocking,
        }));
}

fn push_captured_absent(document: &mut Value, absence: &CapturedAbsence) {
    document["x-kahea-absent"]
        .as_array_mut()
        .expect("base absence array")
        .push(absence_value(absence));
}

fn absence_value(absence: &CapturedAbsence) -> Value {
    json!({
        "capability": absence.capability,
        "reason": absence.reason,
        "location": absence.location,
        "severity": if absence.blocking { "error" } else { "warning" },
        "blocking": absence.blocking,
    })
}

fn captured_absence(value: &Value) -> Option<CapturedAbsence> {
    Some(CapturedAbsence {
        capability: value.get("capability")?.as_str()?.into(),
        reason: value.get("reason")?.as_str()?.into(),
        location: value.get("location")?.as_str()?.into(),
        blocking: value.get("blocking")?.as_bool()?,
    })
}

fn string<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}

fn required_word<'a>(
    words: &'a [String],
    index: usize,
    what: &str,
) -> Result<&'a str, IngestError> {
    words
        .get(index)
        .map(String::as_str)
        .ok_or_else(|| IngestError::Parse(format!("cURL {what} is missing")))
}

fn safe_operation_id(name: &str, index: usize) -> String {
    let cleaned: String = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect();
    let cleaned = cleaned.trim_matches('_');
    if cleaned.is_empty() {
        format!("importedRequest{index}")
    } else {
        format!("{cleaned}_{index}")
    }
}
