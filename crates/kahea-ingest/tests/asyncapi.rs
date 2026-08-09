use kahea_core::{WebSocketAction, WebSocketLimits, digest};
use kahea_ingest::{
    IngestError, compile_asyncapi_websocket, inspect_asyncapi, load_asyncapi,
    resolve_asyncapi_operation,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/asyncapi")
        .join(name)
}

fn limits() -> WebSocketLimits {
    WebSocketLimits {
        connect_timeout_ms: 1_000,
        action_timeout_ms: 1_000,
        idle_timeout_ms: 1_000,
        close_timeout_ms: 1_000,
        total_timeout_ms: 5_000,
        max_frame_bytes: 65_536,
        max_message_bytes: 65_536,
        max_inbound_frames: 16,
        max_outbound_frames: 16,
        max_inbound_messages: 8,
        max_outbound_messages: 8,
        max_inbound_bytes: 262_144,
        max_outbound_bytes: 262_144,
    }
}

#[test]
fn asyncapi_26_json_and_yaml_are_deterministic_and_compilable() {
    let path = fixture("session-2.6.yaml");
    let bytes = std::fs::read(&path).unwrap();
    let source = load_asyncapi(&path, &bytes).unwrap();
    assert_eq!(source.source_fingerprint, digest(&bytes));
    let first = inspect_asyncapi(&path, &bytes, None, 50, 0).unwrap();
    let second = inspect_asyncapi(&path, &bytes, None, 50, 0).unwrap();
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&second).unwrap()
    );
    assert_eq!(first.operations.len(), 2);
    assert_eq!(
        first
            .operations
            .iter()
            .map(|op| op.1.as_str())
            .collect::<Vec<_>>(),
        ["RECEIVE", "SEND"]
    );

    let operation = resolve_asyncapi_operation(&source, "subscribeBuilds").unwrap();
    let session = compile_asyncapi_websocket(
        &source,
        &operation,
        None,
        Some("bearerAuth=build-bot"),
        &BTreeMap::new(),
        limits(),
    )
    .unwrap();
    assert_eq!(session.url, "wss://socket.example.test/v1/events/builds");
    assert_eq!(session.auth.as_deref(), Some("build-bot"));
    assert_eq!(session.headers["X-Client"], "kahea-asyncapi");
    assert!(
        matches!(&session.actions[0], WebSocketAction::SendText { text } if text.contains("subscribe"))
    );
    assert!(matches!(
        session.actions.last(),
        Some(WebSocketAction::Close { code: 1000, .. })
    ));

    let parsed = kahea_ingest::parse_data_document(&path, &bytes).unwrap();
    let json_bytes = serde_json::to_vec(&parsed).unwrap();
    let json_index = inspect_asyncapi(Path::new("same.json"), &json_bytes, None, 50, 0).unwrap();
    assert_eq!(
        json_index
            .operations
            .iter()
            .map(|op| (&op.1, &op.2, &op.3))
            .collect::<Vec<_>>(),
        first
            .operations
            .iter()
            .map(|op| (&op.1, &op.2, &op.3))
            .collect::<Vec<_>>()
    );
}

#[test]
fn asyncapi_30_message_alternatives_require_explicit_selection() {
    let path = fixture("session-3.0.json");
    let bytes = std::fs::read(&path).unwrap();
    let source = load_asyncapi(&path, &bytes).unwrap();
    let index = inspect_asyncapi(&path, &bytes, None, 50, 0).unwrap();
    assert_eq!(index.operations.len(), 2);
    assert!(
        index
            .operations
            .iter()
            .all(|operation| operation.3.starts_with("watchBuilds#"))
    );
    assert!(matches!(
        resolve_asyncapi_operation(&source, "watchBuilds"),
        Err(IngestError::AmbiguousOperation(_))
    ));
    for operation in index.operations {
        assert_eq!(
            resolve_asyncapi_operation(&source, &operation.0)
                .unwrap()
                .handle,
            operation.0
        );
    }
}

#[test]
fn unsupported_versions_remote_refs_and_material_metadata_fail_closed() {
    for document in [
        json!({"asyncapi":"2.5.0","channels":{}}),
        json!({"asyncapi":"3.0.0","operations":{},"components":{"messages":{"x":{"$ref":"https://example.test/message.json"}}}}),
        json!({"asyncapi":"3.0.0","operations":{},"components":{"messages":{"x":{"$ref":"#/components/messages/missing"}}}}),
    ] {
        assert!(
            load_asyncapi(
                Path::new("source.json"),
                &serde_json::to_vec(&document).unwrap()
            )
            .is_err()
        );
    }
    assert!(load_asyncapi(Path::new("broken.json"), b"{\"asyncapi\":").is_err());

    let path = fixture("session-2.6.yaml");
    let mut document: Value =
        kahea_ingest::parse_data_document(&path, &std::fs::read(&path).unwrap()).unwrap();
    document
        .pointer_mut("/components/messages/Build")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "correlationId".into(),
            json!({"location":"$message.header#/correlationId"}),
        );
    let bytes = serde_json::to_vec(&document).unwrap();
    let index = inspect_asyncapi(Path::new("metadata.json"), &bytes, None, 50, 0).unwrap();
    assert!(
        index
            .absent
            .iter()
            .any(|absence| absence.capability == "asyncapi-correlation-id" && absence.blocking)
    );
}

#[test]
fn referenced_component_bytes_change_indexes_and_sealed_inputs() {
    let path = fixture("session-3.0.json");
    let original_bytes = std::fs::read(&path).unwrap();
    let original = inspect_asyncapi(&path, &original_bytes, None, 50, 0).unwrap();
    let mut document: Value = serde_json::from_slice(&original_bytes).unwrap();
    document
        .pointer_mut("/components/messages/Started/payload/properties/type/const")
        .map(|value| *value = json!("changed"))
        .unwrap();
    let changed_bytes = serde_json::to_vec(&document).unwrap();
    let changed = inspect_asyncapi(Path::new("changed.json"), &changed_bytes, None, 50, 0).unwrap();
    assert_ne!(original.source_fingerprints, changed.source_fingerprints);
    assert_ne!(
        original
            .operations
            .iter()
            .map(|operation| &operation.0)
            .collect::<Vec<_>>(),
        changed
            .operations
            .iter()
            .map(|operation| &operation.0)
            .collect::<Vec<_>>()
    );
}
