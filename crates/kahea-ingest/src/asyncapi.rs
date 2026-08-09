use crate::{IngestError, parse_data_document};
use kahea_core::{
    AbsentCapability, DiagnosticSeverity, OperationIndexEnvelope, OperationSummary, PROTOCOL,
    RiskClass, VERSION, WebSocketAction, WebSocketLimits, WebSocketSessionSource,
    default_config_fingerprint, digest, short_handle,
};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct AsyncApiSource {
    pub document: Value,
    pub source_fingerprint: String,
    pub source_handle: String,
    pub version: String,
}

#[derive(Debug, Clone)]
pub struct AsyncApiOperation {
    pub handle: String,
    pub operation_id: String,
    pub action: String,
    pub channel_name: String,
    pub channel_address: String,
    pub server_names: Vec<String>,
    pub message_name: String,
    pub message: Value,
    pub operation: Value,
    pub channel: Value,
    pub location: String,
    pub absent: Vec<AbsentCapability>,
}

pub fn is_asyncapi(document: &Value) -> bool {
    document.get("asyncapi").and_then(Value::as_str).is_some()
}

pub fn load_asyncapi(path: &Path, bytes: &[u8]) -> Result<AsyncApiSource, IngestError> {
    let document = parse_data_document(path, bytes)?;
    let version = document
        .get("asyncapi")
        .and_then(Value::as_str)
        .ok_or_else(|| IngestError::InvalidAsyncApi("missing asyncapi version".into()))?
        .to_string();
    if !(version.starts_with("2.6.") || version.starts_with("3.0.")) {
        return Err(IngestError::InvalidAsyncApi(format!(
            "unsupported version {version:?}; supported versions are 2.6.x and 3.0.x"
        )));
    }
    validate_references(&document, &document, "#", 0)?;
    let fingerprint = digest(bytes);
    Ok(AsyncApiSource {
        document,
        source_fingerprint: fingerprint,
        source_handle: short_handle("src", &[bytes]),
        version,
    })
}

pub fn inspect_asyncapi(
    path: &Path,
    bytes: &[u8],
    query: Option<&str>,
    limit: usize,
    cursor: usize,
) -> Result<OperationIndexEnvelope, IngestError> {
    let source = load_asyncapi(path, bytes)?;
    let mut operations = collect_operations(&source)?;
    operations.sort_by(|a, b| {
        (
            &a.channel_address,
            &a.action,
            &a.operation_id,
            &a.message_name,
            &a.handle,
        )
            .cmp(&(
                &b.channel_address,
                &b.action,
                &b.operation_id,
                &b.message_name,
                &b.handle,
            ))
    });
    let query = query.unwrap_or_default().trim().to_ascii_lowercase();
    let filtered = operations
        .iter()
        .filter(|operation| {
            query.is_empty()
                || [
                    operation.handle.as_str(),
                    operation.operation_id.as_str(),
                    operation.channel_name.as_str(),
                    operation.channel_address.as_str(),
                    operation.message_name.as_str(),
                    operation.action.as_str(),
                ]
                .iter()
                .any(|value| value.to_ascii_lowercase().contains(&query))
        })
        .collect::<Vec<_>>();
    if cursor > filtered.len() {
        return Err(IngestError::InvalidCursor {
            cursor,
            len: filtered.len(),
        });
    }
    let end = cursor.saturating_add(limit).min(filtered.len());
    let next = (end < filtered.len()).then(|| end.to_string());
    let page = filtered
        .iter()
        .skip(cursor)
        .take(limit)
        .map(|operation| {
            OperationSummary(
                operation.handle.clone(),
                operation.action.to_ascii_uppercase(),
                operation.channel_address.clone(),
                operation.operation_id.clone(),
                if operation.action == "send" {
                    RiskClass::Write
                } else {
                    RiskClass::Unknown
                },
            )
        })
        .collect();
    let mut absent = operations
        .into_iter()
        .flat_map(|operation| operation.absent)
        .collect::<Vec<_>>();
    absent.sort_by(|a, b| {
        (&a.location, &a.capability, &a.reason).cmp(&(&b.location, &b.capability, &b.reason))
    });
    absent.dedup_by(|a, b| {
        a.location == b.location && a.capability == b.capability && a.reason == b.reason
    });
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

pub fn resolve_asyncapi_operation(
    source: &AsyncApiSource,
    selector: &str,
) -> Result<AsyncApiOperation, IngestError> {
    let matches = collect_operations(source)?
        .into_iter()
        .filter(|operation| {
            operation.handle == selector
                || operation.operation_id == selector
                || operation
                    .operation_id
                    .split_once('#')
                    .is_some_and(|(base, _)| base == selector)
        })
        .collect::<Vec<_>>();
    match matches.len() {
        0 => Err(IngestError::UnknownOperation(selector.into())),
        1 => Ok(matches.into_iter().next().expect("length checked")),
        _ => Err(IngestError::AmbiguousOperation(selector.into())),
    }
}

pub fn compile_asyncapi_websocket(
    source: &AsyncApiSource,
    operation: &AsyncApiOperation,
    server_selector: Option<&str>,
    auth_selector: Option<&str>,
    values: &BTreeMap<String, Value>,
    limits: WebSocketLimits,
) -> Result<WebSocketSessionSource, IngestError> {
    if let Some(absence) = operation.absent.iter().find(|absence| absence.blocking) {
        return Err(IngestError::InvalidAsyncApi(format!(
            "{} at {}: {}",
            absence.capability, absence.location, absence.reason
        )));
    }
    let server_name = select_server(operation, server_selector)?;
    let server = source.document["servers"]
        .get(&server_name)
        .ok_or_else(|| {
            IngestError::InvalidAsyncApi(format!("server {server_name:?} is missing"))
        })?;
    let server = resolve_value(
        &source.document,
        server,
        &format!("#/servers/{}", escape(&server_name)),
    )?;
    let mut server_absent = Vec::new();
    scan_bindings(
        server.get("bindings"),
        &format!("#/servers/{}/bindings", escape(&server_name)),
        &mut server_absent,
    );
    if let Some(absence) = server_absent.iter().find(|absence| absence.blocking) {
        return Err(IngestError::InvalidAsyncApi(format!(
            "{} at {}: {}",
            absence.capability, absence.location, absence.reason
        )));
    }
    let mut url = if source.version.starts_with("2.6.") {
        server
            .get("url")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    } else {
        let protocol = server
            .get("protocol")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let host = server
            .get("host")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let pathname = server
            .get("pathname")
            .and_then(Value::as_str)
            .unwrap_or_default();
        format!("{protocol}://{host}{pathname}")
    };
    let protocol = server
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            if url.starts_with("wss://") {
                "wss"
            } else if url.starts_with("ws://") {
                "ws"
            } else {
                ""
            }
        });
    if !matches!(protocol, "ws" | "wss") {
        return Err(IngestError::InvalidAsyncApi(format!(
            "server {server_name:?} protocol must be ws or wss"
        )));
    }
    substitute_variables(&mut url, server.get("variables"), "server", values)?;
    let mut address = operation.channel_address.clone();
    substitute_variables(
        &mut address,
        operation.channel.get("parameters"),
        "channel",
        values,
    )?;
    if !address.is_empty() {
        if !url.ends_with('/') && !address.starts_with('/') {
            url.push('/');
        }
        if url.ends_with('/') && address.starts_with('/') {
            url.pop();
        }
        url.push_str(&address);
    }

    let mut headers = BTreeMap::new();
    collect_binding_headers(
        &source.document,
        server.get("bindings"),
        &mut headers,
        "server",
    )?;
    collect_binding_headers(
        &source.document,
        operation.channel.get("bindings"),
        &mut headers,
        "channel",
    )?;
    collect_binding_headers(
        &source.document,
        operation.operation.get("bindings"),
        &mut headers,
        "operation",
    )?;
    let subprotocols = extension_strings(&operation.operation, "x-kahea-subprotocols")
        .or_else(|| extension_strings(&operation.channel, "x-kahea-subprotocols"))
        .or_else(|| extension_strings(server, "x-kahea-subprotocols"))
        .unwrap_or_default();
    let origin = extension_string(&operation.operation, "x-kahea-origin")
        .or_else(|| extension_string(&operation.channel, "x-kahea-origin"))
        .or_else(|| extension_string(server, "x-kahea-origin"));
    let auth = select_auth_profile(source, operation, server, auth_selector)?;
    let actions = if let Some(actions) = operation.operation.get("x-kahea-actions") {
        serde_json::from_value(actions.clone()).map_err(|error| {
            IngestError::InvalidAsyncApi(format!("invalid x-kahea-actions: {error}"))
        })?
    } else {
        let mut actions = vec![message_action(&source.document, operation)?];
        actions.push(WebSocketAction::Close {
            code: 1000,
            reason: "complete".into(),
        });
        actions
    };
    Ok(WebSocketSessionSource {
        kind: "websocket-session".into(),
        version: 1,
        operation_id: operation.operation_id.clone(),
        url,
        risk: Some(if operation.action == "send" {
            RiskClass::Write
        } else {
            RiskClass::Unknown
        }),
        headers,
        auth,
        origin,
        subprotocols,
        limits,
        actions,
    })
}

fn collect_operations(source: &AsyncApiSource) -> Result<Vec<AsyncApiOperation>, IngestError> {
    if source.version.starts_with("2.6.") {
        collect_v2(source)
    } else {
        collect_v3(source)
    }
}

fn collect_v2(source: &AsyncApiSource) -> Result<Vec<AsyncApiOperation>, IngestError> {
    let channels = source
        .document
        .get("channels")
        .and_then(Value::as_object)
        .ok_or_else(|| IngestError::InvalidAsyncApi("channels must be an object".into()))?;
    let mut result = Vec::new();
    for (channel_name, raw_channel) in channels {
        let channel = resolve_value(
            &source.document,
            raw_channel,
            &format!("#/channels/{}", escape(channel_name)),
        )?;
        for (verb, action) in [("publish", "send"), ("subscribe", "receive")] {
            let Some(raw_operation) = channel.get(verb) else {
                continue;
            };
            let operation = resolve_value(
                &source.document,
                raw_operation,
                &format!("#/channels/{}/{}", escape(channel_name), verb),
            )?;
            let base_id = operation
                .get("operationId")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| format!("{verb}:{}", channel_name));
            let raw_message = operation.get("message").ok_or_else(|| {
                IngestError::InvalidAsyncApi(format!("operation {base_id:?} has no message"))
            })?;
            let messages = message_variants(
                &source.document,
                raw_message,
                &format!("#/channels/{}/{}/message", escape(channel_name), verb),
            )?;
            for (index, (message_name, message)) in messages.iter().enumerate() {
                let operation_id = variant_id(&base_id, message_name, index, messages.len());
                result.push(make_operation(
                    source,
                    operation_id,
                    action,
                    channel_name,
                    channel_name,
                    operation,
                    channel,
                    message_name,
                    message,
                    format!("#/channels/{}/{}", escape(channel_name), verb),
                )?);
            }
        }
    }
    Ok(result)
}

fn collect_v3(source: &AsyncApiSource) -> Result<Vec<AsyncApiOperation>, IngestError> {
    let operations = source
        .document
        .get("operations")
        .and_then(Value::as_object)
        .ok_or_else(|| IngestError::InvalidAsyncApi("operations must be an object".into()))?;
    for (name, operation) in operations {
        if operation.get("reply").is_some() {
            // Replies require a multi-operation session extension to make ordering finite.
        }
        if operation.get("channel").is_none() {
            return Err(IngestError::InvalidAsyncApi(format!(
                "operation {name:?} has no channel"
            )));
        }
    }
    let mut result = Vec::new();
    for (name, raw_operation) in operations {
        let operation = resolve_value(
            &source.document,
            raw_operation,
            &format!("#/operations/{}", escape(name)),
        )?;
        let action = operation
            .get("action")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                IngestError::InvalidAsyncApi(format!("operation {name:?} has no action"))
            })?;
        if !matches!(action, "send" | "receive") {
            return Err(IngestError::InvalidAsyncApi(format!(
                "operation {name:?} has unsupported action {action:?}"
            )));
        }
        let channel = resolve_value(
            &source.document,
            &operation["channel"],
            &format!("#/operations/{}/channel", escape(name)),
        )?;
        let channel_name = ref_tail(&operation["channel"]).unwrap_or(name);
        let address = channel
            .get("address")
            .and_then(Value::as_str)
            .unwrap_or(channel_name);
        let raw_messages = operation
            .get("messages")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                IngestError::InvalidAsyncApi(format!(
                    "operation {name:?} messages must be a non-empty array"
                ))
            })?;
        if raw_messages.is_empty() {
            return Err(IngestError::InvalidAsyncApi(format!(
                "operation {name:?} has no messages"
            )));
        }
        for (index, raw_message) in raw_messages.iter().enumerate() {
            let message = resolve_value(
                &source.document,
                raw_message,
                &format!("#/operations/{}/messages/{index}", escape(name)),
            )?;
            let message_name = message
                .get("name")
                .and_then(Value::as_str)
                .or_else(|| ref_tail(raw_message))
                .unwrap_or("message");
            let operation_id = variant_id(name, message_name, index, raw_messages.len());
            result.push(make_operation(
                source,
                operation_id,
                action,
                channel_name,
                address,
                operation,
                channel,
                message_name,
                message,
                format!("#/operations/{}", escape(name)),
            )?);
        }
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn make_operation(
    source: &AsyncApiSource,
    operation_id: String,
    action: &str,
    channel_name: &str,
    channel_address: &str,
    operation: &Value,
    channel: &Value,
    message_name: &str,
    message: &Value,
    location: String,
) -> Result<AsyncApiOperation, IngestError> {
    let mut absent = Vec::new();
    if message.get("headers").is_some() {
        absent.push(absence("asyncapi-message-headers", "message headers are envelope metadata and cannot be represented by a raw WebSocket frame", &format!("{location}/message/headers"), true));
    }
    if message.get("correlationId").is_some() {
        absent.push(absence(
            "asyncapi-correlation-id",
            "correlation metadata cannot be enforced by the raw WebSocket executor",
            &format!("{location}/message/correlationId"),
            true,
        ));
    }
    if operation.get("reply").is_some() {
        absent.push(absence(
            "asyncapi-reply",
            "reply ordering requires explicit x-kahea-actions",
            &format!("{location}/reply"),
            operation.get("x-kahea-actions").is_none(),
        ));
    }
    for (owner, value, owner_location) in [
        ("operation", operation, location.as_str()),
        ("message", message, &format!("{location}/message")),
    ] {
        if value
            .get("traits")
            .and_then(Value::as_array)
            .is_some_and(|traits| !traits.is_empty())
        {
            absent.push(absence(
                "asyncapi-traits",
                &format!("{owner} traits are not applied by the finite WebSocket subset"),
                &format!("{owner_location}/traits"),
                true,
            ));
        }
    }
    if let Some(format) = message.get("schemaFormat").and_then(Value::as_str)
        && !(format.contains("schema+json") || format.contains("json-schema"))
    {
        absent.push(absence(
            "asyncapi-schema-format",
            &format!("schema format {format:?} is outside the JSON Schema subset"),
            &format!("{location}/message/schemaFormat"),
            true,
        ));
    }
    if action == "send"
        && concrete_example(message).is_none()
        && operation.get("x-kahea-actions").is_none()
    {
        absent.push(absence("asyncapi-send-payload", "a finite send requires a message example, payload example/default/const, or x-kahea-actions", &format!("{location}/message/payload"), true));
    }
    if action == "receive"
        && message.get("payload").is_none()
        && concrete_example(message).is_none()
        && operation.get("x-kahea-actions").is_none()
    {
        absent.push(absence(
            "asyncapi-receive-contract",
            "a finite receive requires a payload schema/example or x-kahea-actions",
            &format!("{location}/message/payload"),
            true,
        ));
    }
    scan_bindings(
        operation.get("bindings"),
        &format!("{location}/bindings"),
        &mut absent,
    );
    scan_bindings(
        channel.get("bindings"),
        &format!("{location}/channel/bindings"),
        &mut absent,
    );
    scan_bindings(
        message.get("bindings"),
        &format!("{location}/message/bindings"),
        &mut absent,
    );
    let server_names: Vec<String> = operation
        .get("servers")
        .or_else(|| channel.get("servers"))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| Value::as_str(value).or_else(|| ref_tail(value)))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_else(|| {
            source
                .document
                .get("servers")
                .and_then(Value::as_object)
                .map(|servers| servers.keys().cloned().collect())
                .unwrap_or_default()
        });
    for server_name in &server_names {
        if let Some(server) = source
            .document
            .get("servers")
            .and_then(|servers| servers.get(server_name))
        {
            let server = resolve_value(
                &source.document,
                server,
                &format!("#/servers/{}", escape(server_name)),
            )?;
            let protocol = server
                .get("protocol")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !matches!(protocol, "ws" | "wss") {
                absent.push(absence("asyncapi-server-protocol", &format!("server {server_name:?} uses protocol {protocol:?}, outside the WebSocket subset"), &format!("#/servers/{}/protocol", escape(server_name)), false));
            }
            scan_bindings(
                server.get("bindings"),
                &format!("#/servers/{}/bindings", escape(server_name)),
                &mut absent,
            );
        }
    }
    let handle = short_handle(
        "op",
        &[
            source.source_fingerprint.as_bytes(),
            action.as_bytes(),
            channel_name.as_bytes(),
            operation_id.as_bytes(),
            message_name.as_bytes(),
        ],
    );
    Ok(AsyncApiOperation {
        handle,
        operation_id,
        action: action.into(),
        channel_name: channel_name.into(),
        channel_address: channel_address.into(),
        server_names,
        message_name: message_name.into(),
        message: message.clone(),
        operation: operation.clone(),
        channel: channel.clone(),
        location,
        absent,
    })
}

fn message_variants<'a>(
    root: &'a Value,
    raw: &'a Value,
    location: &str,
) -> Result<Vec<(String, &'a Value)>, IngestError> {
    let resolved = resolve_value(root, raw, location)?;
    let variants = resolved.get("oneOf").and_then(Value::as_array);
    let values = variants
        .map(Vec::as_slice)
        .unwrap_or_else(|| std::slice::from_ref(raw));
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let message = resolve_value(root, value, &format!("{location}/{index}"))?;
            let name = message
                .get("name")
                .and_then(Value::as_str)
                .or_else(|| ref_tail(value))
                .map(str::to_string)
                .unwrap_or_else(|| format!("message-{}", index + 1));
            Ok((name, message))
        })
        .collect()
}

fn resolve_value<'a>(
    root: &'a Value,
    value: &'a Value,
    location: &str,
) -> Result<&'a Value, IngestError> {
    let mut current = value;
    let mut seen = BTreeSet::new();
    while let Some(reference) = current.get("$ref").and_then(Value::as_str) {
        if !seen.insert(reference) {
            return Err(IngestError::InvalidAsyncApi(format!(
                "cyclic reference {reference:?} at {location}"
            )));
        }
        let pointer = reference.strip_prefix('#').ok_or_else(|| {
            IngestError::InvalidAsyncApi(format!(
                "remote reference {reference:?} is denied at {location}"
            ))
        })?;
        current = root.pointer(pointer).ok_or_else(|| {
            IngestError::InvalidAsyncApi(format!(
                "unresolved local reference {reference:?} at {location}"
            ))
        })?;
    }
    Ok(current)
}

fn message_action(
    root: &Value,
    operation: &AsyncApiOperation,
) -> Result<WebSocketAction, IngestError> {
    let content_type = operation
        .message
        .get("contentType")
        .and_then(Value::as_str)
        .unwrap_or("application/json");
    let example = concrete_example(&operation.message);
    if operation.action == "send" {
        let example = example.ok_or_else(|| IngestError::InvalidAsyncApi(format!("send operation {:?} needs a message example, payload example/default/const, or x-kahea-actions", operation.operation_id)))?;
        if content_type.contains("json") || !example.is_string() {
            Ok(WebSocketAction::SendText {
                text: serde_json::to_string(example)
                    .map_err(|error| IngestError::InvalidAsyncApi(error.to_string()))?,
            })
        } else {
            Ok(WebSocketAction::SendText {
                text: example.as_str().unwrap_or_default().into(),
            })
        }
    } else if content_type.contains("json") {
        Ok(WebSocketAction::ExpectJson {
            pointer: None,
            equals: example.cloned(),
            schema: operation
                .message
                .get("payload")
                .map(|schema| inline_local_refs(root, schema, &mut BTreeSet::new(), 0))
                .transpose()?,
            timeout_ms: None,
        })
    } else if let Some(text) = example.and_then(Value::as_str) {
        Ok(WebSocketAction::ExpectText {
            equals: text.into(),
            timeout_ms: None,
        })
    } else {
        Err(IngestError::InvalidAsyncApi(format!(
            "receive operation {:?} needs a JSON payload schema/example or a text example",
            operation.operation_id
        )))
    }
}

fn concrete_example(message: &Value) -> Option<&Value> {
    message
        .get("examples")
        .and_then(Value::as_array)
        .and_then(|values| values.first())
        .and_then(|value| value.get("payload"))
        .or_else(|| {
            message.get("payload").and_then(|payload| {
                payload
                    .get("example")
                    .or_else(|| payload.get("default"))
                    .or_else(|| payload.get("const"))
            })
        })
}

fn select_server(
    operation: &AsyncApiOperation,
    selector: Option<&str>,
) -> Result<String, IngestError> {
    match selector {
        Some(selector) if operation.server_names.iter().any(|name| name == selector) => {
            Ok(selector.into())
        }
        Some(selector) => Err(IngestError::InvalidAsyncApi(format!(
            "server selector {selector:?} did not match the operation"
        ))),
        None if operation.server_names.len() == 1 => Ok(operation.server_names[0].clone()),
        None if operation.server_names.is_empty() => Err(IngestError::InvalidAsyncApi(
            "no WebSocket server is declared".into(),
        )),
        None => Err(IngestError::InvalidAsyncApi(
            "multiple WebSocket servers are available; select one with --server".into(),
        )),
    }
}

fn select_auth_profile(
    source: &AsyncApiSource,
    operation: &AsyncApiOperation,
    server: &Value,
    selector: Option<&str>,
) -> Result<Option<String>, IngestError> {
    let requirements = operation
        .operation
        .get("security")
        .or_else(|| server.get("security"));
    let schemes = requirements
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .flat_map(|object| object.keys().cloned())
        .collect::<BTreeSet<_>>();
    if schemes.is_empty() {
        return Ok(selector.map(str::to_string));
    }
    let Some(selector) = selector else {
        return Err(IngestError::InvalidAsyncApi(format!(
            "security is required; map one of {} with --auth SCHEME=PROFILE",
            schemes.into_iter().collect::<Vec<_>>().join(", ")
        )));
    };
    let (scheme, profile) = selector.split_once('=').ok_or_else(|| {
        IngestError::InvalidAsyncApi("AsyncAPI security requires --auth SCHEME=PROFILE".into())
    })?;
    if !schemes.contains(scheme) {
        return Err(IngestError::InvalidAsyncApi(format!(
            "security scheme {scheme:?} is not required by the operation"
        )));
    }
    let declared = source
        .document
        .pointer(&format!("/components/securitySchemes/{}", escape(scheme)))
        .ok_or_else(|| {
            IngestError::InvalidAsyncApi(format!("security scheme {scheme:?} is not declared"))
        })?;
    let supported = match declared.get("type").and_then(Value::as_str) {
        Some("http") => declared
            .get("scheme")
            .and_then(Value::as_str)
            .is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "basic" | "bearer")),
        Some("X509") => true,
        _ => false,
    };
    if !supported {
        return Err(IngestError::InvalidAsyncApi(format!(
            "security scheme {scheme:?} cannot map to a supported WebSocket auth-profile reference"
        )));
    }
    Ok(Some(profile.into()))
}

fn substitute_variables(
    target: &mut String,
    definitions: Option<&Value>,
    prefix: &str,
    values: &BTreeMap<String, Value>,
) -> Result<(), IngestError> {
    let definitions = definitions.and_then(Value::as_object);
    let mut names = BTreeSet::new();
    let bytes = target.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'{' {
            let end = target[index + 1..]
                .find('}')
                .map(|offset| index + 1 + offset)
                .ok_or_else(|| {
                    IngestError::InvalidAsyncApi(format!("unterminated variable in {target:?}"))
                })?;
            names.insert(target[index + 1..end].to_string());
            index = end + 1;
        } else {
            index += 1;
        }
    }
    for name in names {
        let definition = definitions.and_then(|object| object.get(&name));
        let selected = values.get(&format!("{prefix}.{name}")).or_else(|| {
            definition.and_then(|value| {
                value
                    .get("default")
                    .or_else(|| value.get("schema").and_then(|schema| schema.get("default")))
            })
        });
        let selected_value = selected.ok_or_else(|| {
            IngestError::InvalidAsyncApi(format!(
                "missing {prefix} variable {name:?}; provide --set {prefix}.{name}=VALUE"
            ))
        })?;
        if let Some(allowed) = definition
            .and_then(|value| {
                value
                    .get("enum")
                    .or_else(|| value.get("schema").and_then(|schema| schema.get("enum")))
            })
            .and_then(Value::as_array)
            && !allowed.contains(selected_value)
        {
            return Err(IngestError::InvalidAsyncApi(format!(
                "{prefix} variable {name:?} is outside its declared enum"
            )));
        }
        let selected = scalar(selected_value).ok_or_else(|| {
            IngestError::InvalidAsyncApi(format!("{prefix} variable {name:?} must be scalar"))
        })?;
        *target = target.replace(&format!("{{{name}}}"), &selected);
    }
    Ok(())
}

fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn collect_binding_headers(
    root: &Value,
    bindings: Option<&Value>,
    output: &mut BTreeMap<String, String>,
    label: &str,
) -> Result<(), IngestError> {
    let Some(ws) = bindings.and_then(|value| value.get("ws")) else {
        return Ok(());
    };
    let Some(headers) = ws.get("headers") else {
        return Ok(());
    };
    let headers = resolve_value(root, headers, &format!("#/{label}/bindings/ws/headers"))?;
    let required = headers
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    for (name, schema) in headers
        .get("properties")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        let value = schema
            .get("default")
            .or_else(|| schema.get("example"))
            .and_then(scalar);
        match value {
            Some(value) => {
                if output.get(name).is_some_and(|existing| existing != &value) {
                    return Err(IngestError::InvalidAsyncApi(format!(
                        "WebSocket binding header {name:?} has conflicting concrete values"
                    )));
                }
                output.insert(name.clone(), value);
            }
            None if required.contains(name.as_str()) => {
                return Err(IngestError::InvalidAsyncApi(format!(
                    "required WebSocket binding header {name:?} has no default/example"
                )));
            }
            None => {}
        }
    }
    Ok(())
}

fn scan_bindings(bindings: Option<&Value>, location: &str, absent: &mut Vec<AbsentCapability>) {
    let Some(bindings) = bindings.and_then(Value::as_object) else {
        return;
    };
    for name in bindings.keys() {
        if name != "ws" {
            absent.push(absence(
                "asyncapi-protocol-binding",
                &format!("binding {name:?} is outside the WebSocket subset"),
                &format!("{location}/{}", escape(name)),
                true,
            ));
        }
    }
    if let Some(ws) = bindings.get("ws") {
        for name in ws.as_object().into_iter().flatten().map(|(name, _)| name) {
            if !matches!(name.as_str(), "headers" | "bindingVersion") {
                absent.push(absence(
                    "asyncapi-websocket-binding",
                    &format!("WebSocket binding field {name:?} is unsupported"),
                    &format!("{location}/ws/{}", escape(name)),
                    true,
                ));
            }
        }
    }
}

fn absence(capability: &str, reason: &str, location: &str, blocking: bool) -> AbsentCapability {
    AbsentCapability {
        capability: capability.into(),
        reason: reason.into(),
        location: location.into(),
        severity: if blocking {
            DiagnosticSeverity::Error
        } else {
            DiagnosticSeverity::Warning
        },
        blocking,
    }
}
fn variant_id(base: &str, name: &str, index: usize, count: usize) -> String {
    if count == 1 {
        base.into()
    } else {
        format!("{base}#{name}-{}", index + 1)
    }
}
fn ref_tail(value: &Value) -> Option<&str> {
    value
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|value| value.rsplit('/').next())
}
fn extension_string(value: &Value, name: &str) -> Option<String> {
    value.get(name).and_then(Value::as_str).map(str::to_string)
}
fn extension_strings(value: &Value, name: &str) -> Option<Vec<String>> {
    value.get(name).and_then(Value::as_array).map(|values| {
        values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    })
}
fn escape(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn validate_references(
    root: &Value,
    value: &Value,
    location: &str,
    depth: usize,
) -> Result<(), IngestError> {
    if depth > 128 {
        return Err(IngestError::InvalidAsyncApi(format!(
            "reference scan exceeded depth at {location}"
        )));
    }
    match value {
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                let pointer = reference.strip_prefix('#').ok_or_else(|| {
                    IngestError::InvalidAsyncApi(format!(
                        "remote reference {reference:?} is denied at {location}"
                    ))
                })?;
                if root.pointer(pointer).is_none() {
                    return Err(IngestError::InvalidAsyncApi(format!(
                        "unresolved local reference {reference:?} at {location}"
                    )));
                }
            }
            for (name, child) in object {
                validate_references(
                    root,
                    child,
                    &format!("{location}/{}", escape(name)),
                    depth + 1,
                )?;
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                validate_references(root, child, &format!("{location}/{index}"), depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn inline_local_refs(
    root: &Value,
    value: &Value,
    stack: &mut BTreeSet<String>,
    depth: usize,
) -> Result<Value, IngestError> {
    if depth > 64 {
        return Err(IngestError::InvalidAsyncApi(
            "schema reference expansion exceeded 64 levels".into(),
        ));
    }
    if let Some(reference) = value.get("$ref").and_then(Value::as_str) {
        let pointer = reference.strip_prefix('#').ok_or_else(|| {
            IngestError::InvalidAsyncApi(format!("remote schema reference {reference:?} is denied"))
        })?;
        if !stack.insert(reference.into()) {
            return Err(IngestError::InvalidAsyncApi(format!(
                "cyclic schema reference {reference:?} cannot be sealed"
            )));
        }
        let resolved = root.pointer(pointer).ok_or_else(|| {
            IngestError::InvalidAsyncApi(format!("unresolved schema reference {reference:?}"))
        })?;
        let result = inline_local_refs(root, resolved, stack, depth + 1);
        stack.remove(reference);
        return result;
    }
    match value {
        Value::Object(object) => Ok(Value::Object(
            object
                .iter()
                .map(|(name, child)| {
                    Ok((
                        name.clone(),
                        inline_local_refs(root, child, stack, depth + 1)?,
                    ))
                })
                .collect::<Result<Map<String, Value>, IngestError>>()?,
        )),
        Value::Array(values) => Ok(Value::Array(
            values
                .iter()
                .map(|child| inline_local_refs(root, child, stack, depth + 1))
                .collect::<Result<Vec<_>, _>>()?,
        )),
        _ => Ok(value.clone()),
    }
}
