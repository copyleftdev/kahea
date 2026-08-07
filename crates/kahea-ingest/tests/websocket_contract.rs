//! Executable guardrails for ADR-0001's direct finite-session fixture.
//!
//! Production ingestion lands in #10. These tests keep the accepted source
//! contract finite and bounded while that parser is implemented.

use serde_json::Value;
use std::path::{Path, PathBuf};
use url::Url;

fn contract_fixture() -> (PathBuf, Value) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/websocket/session.json");
    let bytes =
        std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
    (path, value)
}

#[test]
fn websocket_contract_fixture_is_finite_and_bounded() {
    let (path, fixture) = contract_fixture();
    assert_eq!(fixture["kind"], "websocket-session");
    assert_eq!(fixture["version"], 1);
    assert!(
        fixture["operationId"]
            .as_str()
            .is_some_and(|id| !id.is_empty())
    );

    let target = Url::parse(fixture["url"].as_str().expect("fixture URL is a string"))
        .unwrap_or_else(|error| panic!("parse {} URL: {error}", path.display()));
    assert!(matches!(target.scheme(), "ws" | "wss"));
    assert!(target.username().is_empty());
    assert!(target.password().is_none());
    assert!(target.fragment().is_none());

    let limits = fixture["limits"].as_object().expect("limits are an object");
    for name in [
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
        assert!(
            limits
                .get(name)
                .and_then(Value::as_u64)
                .is_some_and(|value| value > 0),
            "{name} must be a positive integer"
        );
    }
    assert!(limits["max_message_bytes"].as_u64() >= limits["max_frame_bytes"].as_u64());
    assert!(limits["total_timeout_ms"].as_u64() >= limits["connect_timeout_ms"].as_u64());

    let actions = fixture["actions"].as_array().expect("actions are an array");
    assert!(!actions.is_empty());
    let allowed = [
        "send-text",
        "send-binary",
        "expect-text",
        "expect-binary",
        "expect-json",
        "ping",
        "expect-pong",
        "close",
        "expect-close",
    ];
    for action in actions {
        let kind = action["type"].as_str().expect("action type is a string");
        assert!(allowed.contains(&kind), "unknown contract action {kind:?}");
    }

    let terminal = actions
        .iter()
        .enumerate()
        .filter(|(_, action)| matches!(action["type"].as_str(), Some("close" | "expect-close")))
        .collect::<Vec<_>>();
    assert_eq!(
        terminal.len(),
        1,
        "a finite session has one terminal action"
    );
    assert_eq!(
        terminal[0].0,
        actions.len() - 1,
        "the terminal action is last"
    );
}

#[test]
fn websocket_contract_fixture_contains_references_not_secrets() {
    let (_, fixture) = contract_fixture();
    assert_eq!(fixture["auth"], "chat-sandbox");

    let serialized = serde_json::to_string(&fixture).expect("fixture serializes");
    for forbidden in ["Authorization", "Bearer ", "password", "api_key", "api-key"] {
        assert!(
            !serialized.contains(forbidden),
            "contract fixture contains secret-like material: {forbidden}"
        );
    }
}
