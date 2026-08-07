//! Executable guardrails for ADR-0001's direct finite-session fixture.
//!
//! Production ingestion lands in #10. These tests keep the accepted source
//! contract finite and bounded while that parser is implemented.

use base64::Engine;
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

fn valid_close_code(code: u64) -> bool {
    matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
}

fn decode_payload(action: &Value, field: &str) -> Result<Vec<u8>, String> {
    let encoded = action[field]
        .as_str()
        .ok_or_else(|| format!("{field} must be a string"))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| format!("{field} must be valid base64"))?;
    if base64::engine::general_purpose::STANDARD.encode(&decoded) != encoded {
        return Err(format!("{field} must use canonical padded base64"));
    }
    Ok(decoded)
}

fn validate_timeout(action: &Value, action_timeout_ms: u64) -> Result<(), String> {
    let Some(timeout) = action.get("timeout_ms") else {
        return Ok(());
    };
    let timeout = timeout
        .as_u64()
        .ok_or_else(|| "timeout_ms must be a positive integer".to_string())?;
    if timeout == 0 || timeout > action_timeout_ms {
        return Err("timeout_ms must not loosen the session action timeout".into());
    }
    Ok(())
}

fn validate_action(action: &Value, limits: &Value) -> Result<(), String> {
    let kind = action["type"]
        .as_str()
        .ok_or_else(|| "action type must be a string".to_string())?;
    let frame_limit = limits["max_frame_bytes"]
        .as_u64()
        .ok_or_else(|| "max_frame_bytes must be an integer".to_string())?;
    let message_limit = limits["max_message_bytes"]
        .as_u64()
        .ok_or_else(|| "max_message_bytes must be an integer".to_string())?;
    let action_timeout = limits["action_timeout_ms"]
        .as_u64()
        .ok_or_else(|| "action_timeout_ms must be an integer".to_string())?;
    let bounded_message = |bytes: usize| {
        if bytes as u64 > frame_limit || bytes as u64 > message_limit {
            Err("message exceeds the frame or message limit".to_string())
        } else {
            Ok(())
        }
    };

    match kind {
        "send-text" => bounded_message(
            action["text"]
                .as_str()
                .ok_or_else(|| "send-text requires text".to_string())?
                .len(),
        ),
        "send-binary" => bounded_message(decode_payload(action, "payload_base64")?.len()),
        "expect-text" => {
            bounded_message(
                action["equals"]
                    .as_str()
                    .ok_or_else(|| "expect-text requires equals".to_string())?
                    .len(),
            )?;
            validate_timeout(action, action_timeout)
        }
        "expect-binary" => {
            bounded_message(decode_payload(action, "payload_base64")?.len())?;
            validate_timeout(action, action_timeout)
        }
        "expect-json" => {
            if action.get("equals").is_none() && action.get("schema").is_none() {
                return Err("expect-json requires equals or schema".into());
            }
            if action.get("pointer").is_some_and(|pointer| {
                pointer.as_str().is_none_or(|pointer| {
                    pointer.len() > 2_048 || (!pointer.is_empty() && !pointer.starts_with('/'))
                })
            }) {
                return Err("expect-json pointer must be a bounded JSON Pointer".into());
            }
            validate_timeout(action, action_timeout)
        }
        "ping" | "expect-pong" => {
            let payload = decode_payload(action, "payload_base64")?;
            if payload.len() > 125 || payload.len() as u64 > frame_limit {
                return Err("control-frame payload exceeds its limit".into());
            }
            if kind == "expect-pong" {
                validate_timeout(action, action_timeout)?;
            }
            Ok(())
        }
        "close" => {
            let code = action["code"]
                .as_u64()
                .ok_or_else(|| "close requires a numeric code".to_string())?;
            let reason = action["reason"]
                .as_str()
                .ok_or_else(|| "close requires a reason string".to_string())?;
            if !valid_close_code(code) || reason.len() > 123 {
                return Err("close code or reason is invalid".into());
            }
            Ok(())
        }
        "expect-close" => {
            let codes = action["codes"]
                .as_array()
                .filter(|codes| !codes.is_empty())
                .ok_or_else(|| "expect-close requires codes".to_string())?;
            if codes
                .iter()
                .any(|code| code.as_u64().is_none_or(|code| !valid_close_code(code)))
                || action
                    .get("reason")
                    .is_some_and(|reason| reason.as_str().is_none_or(|reason| reason.len() > 123))
            {
                return Err("expected close code or reason is invalid".into());
            }
            validate_timeout(action, action_timeout)
        }
        _ => Err(format!("unknown contract action {kind:?}")),
    }
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
    for action in actions {
        validate_action(action, &fixture["limits"])
            .unwrap_or_else(|error| panic!("invalid contract action: {error}"));
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

    let sensitive = [
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
    for (name, value) in fixture["headers"]
        .as_object()
        .expect("headers are an object")
    {
        let normalized_name = name.to_ascii_lowercase();
        let value = value.as_str().expect("header value is a string");
        assert!(!sensitive.contains(&normalized_name.as_str()));
        assert!(!name.contains(['\r', '\n']) && !value.contains(['\r', '\n']));
        assert!(!value.to_ascii_lowercase().contains("bearer "));
    }

    let serialized = serde_json::to_string(&fixture)
        .expect("fixture serializes")
        .to_ascii_lowercase();
    for forbidden in ["authorization", "bearer ", "password", "api_key", "api-key"] {
        assert!(
            !serialized.contains(forbidden),
            "contract fixture contains secret-like material: {forbidden}"
        );
    }
}

#[test]
fn websocket_contract_action_guardrails_reject_invalid_shapes() {
    let (_, fixture) = contract_fixture();
    let limits = &fixture["limits"];
    for invalid in [
        serde_json::json!({"type":"close","code":1006,"reason":"reserved"}),
        serde_json::json!({"type":"ping","payload_base64":"not-base64"}),
        serde_json::json!({"type":"ping","payload_base64": base64::engine::general_purpose::STANDARD.encode([0; 126])}),
        serde_json::json!({"type":"expect-json","pointer":"not-a-pointer","equals":true}),
        serde_json::json!({"type":"expect-pong","payload_base64":"","timeout_ms":0}),
        serde_json::json!({"type":"expect-close","codes":[]}),
        serde_json::json!({"type":"send-text"}),
        serde_json::json!({"type":"unknown"}),
    ] {
        assert!(
            validate_action(&invalid, limits).is_err(),
            "invalid action passed: {invalid}"
        );
    }
}
