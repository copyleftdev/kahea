//! Content-addressed, compressed local evidence storage.

use base64::Engine;
use kahea_core::{
    EvidenceEnvelope, ExplanationEnvelope, Observation, PROTOCOL, VERSION, WebSocketObservation,
    default_config_fingerprint, digest, short_handle,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use serde_json_path::JsonPath;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("evidence filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("evidence index error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("evidence serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("evidence handle {0:?} was not found")]
    NotFound(String),
    #[error("stored evidence digest does not match its index")]
    DigestMismatch,
    #[error("invalid evidence selector: {0}")]
    InvalidSelector(String),
    #[error("selector did not match evidence")]
    SelectionNotFound,
    #[error("selector result exceeded the configured limit")]
    SelectionTooLarge,
}

#[derive(Debug, Clone)]
pub struct EvidenceRecord {
    pub envelope: EvidenceEnvelope,
    pub data: Vec<u8>,
}

pub struct EvidenceStore {
    root: PathBuf,
    connection: Connection,
}

impl EvidenceStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, EvidenceError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("blobs"))?;
        fs::create_dir_all(root.join("observations"))?;
        let connection = Connection::open(root.join("index.sqlite"))?;
        connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             CREATE TABLE IF NOT EXISTS evidence (
               handle TEXT PRIMARY KEY,
               kind TEXT NOT NULL,
               media_type TEXT NOT NULL,
               bytes INTEGER NOT NULL,
               blake3 TEXT NOT NULL,
               redacted INTEGER NOT NULL,
               blob_path TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS evidence_blake3 ON evidence(blake3);",
        )?;
        Ok(Self { root, connection })
    }

    pub fn put_blob(
        &self,
        kind: &str,
        media_type: &str,
        data: &[u8],
        redacted: bool,
    ) -> Result<EvidenceEnvelope, EvidenceError> {
        let blake3 = digest(data);
        let handle = short_handle(kind, &[data]);
        let hex = blake3.trim_start_matches("b3:");
        let relative = PathBuf::from("blobs")
            .join(&hex[..2])
            .join(format!("{hex}.zst"));
        let path = self.root.join(&relative);
        if !path.exists() {
            let parent = path.parent().expect("blob path has parent");
            fs::create_dir_all(parent)?;
            let compressed = zstd::stream::encode_all(Cursor::new(data), 3)?;
            let temporary = parent.join(format!(".{hex}.tmp"));
            fs::write(&temporary, compressed)?;
            match fs::rename(&temporary, &path) {
                Ok(()) => {}
                Err(error) if path.exists() => {
                    let _ = fs::remove_file(&temporary);
                    let _ = error;
                }
                Err(error) => return Err(error.into()),
            }
        }
        self.connection.execute(
            "INSERT OR IGNORE INTO evidence
             (handle, kind, media_type, bytes, blake3, redacted, blob_path)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                handle,
                kind,
                media_type,
                data.len() as i64,
                blake3,
                redacted,
                relative.to_string_lossy()
            ],
        )?;
        Ok(EvidenceEnvelope {
            protocol: PROTOCOL.into(),
            kind: "evidence".into(),
            version: VERSION.into(),
            config_fingerprint: default_config_fingerprint(),
            handle,
            media_type: media_type.into(),
            bytes: data.len() as u64,
            blake3,
            redacted,
            exit: 0,
        })
    }

    pub fn put_json<T: serde::Serialize>(
        &self,
        kind: &str,
        value: &T,
        redacted: bool,
    ) -> Result<EvidenceEnvelope, EvidenceError> {
        self.put_blob(
            kind,
            "application/json",
            &serde_json::to_vec(value)?,
            redacted,
        )
    }

    pub fn get(&self, handle: &str) -> Result<EvidenceRecord, EvidenceError> {
        let row = self
            .connection
            .query_row(
                "SELECT media_type, bytes, blake3, redacted, blob_path
                 FROM evidence WHERE handle = ?1",
                [handle],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, bool>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| EvidenceError::NotFound(handle.into()))?;
        let compressed = fs::read(self.root.join(&row.4))?;
        let data = zstd::stream::decode_all(Cursor::new(compressed))?;
        if digest(&data) != row.2 || data.len() as i64 != row.1 {
            return Err(EvidenceError::DigestMismatch);
        }
        Ok(EvidenceRecord {
            envelope: EvidenceEnvelope {
                protocol: PROTOCOL.into(),
                kind: "evidence".into(),
                version: VERSION.into(),
                config_fingerprint: default_config_fingerprint(),
                handle: handle.into(),
                media_type: row.0,
                bytes: row.1 as u64,
                blake3: row.2,
                redacted: row.3,
                exit: 0,
            },
            data,
        })
    }

    pub fn explain(
        &self,
        handle: &str,
        selector: Option<&str>,
    ) -> Result<ExplanationEnvelope, EvidenceError> {
        const INLINE_LIMIT: usize = 4 * 1024;
        const SELECTION_LIMIT: usize = 64 * 1024;
        let record = self.get(handle)?;
        let value = match selector {
            Some(selector) if selector.len() > 2_048 => {
                return Err(EvidenceError::SelectionTooLarge);
            }
            Some(selector) if selector.starts_with("bytes:") => {
                select_bytes(&record.data, selector, SELECTION_LIMIT)?
            }
            Some(selector) if selector.starts_with("header:") => {
                select_header(&record.data, selector)?
            }
            Some(selector) if record.envelope.media_type.contains("json") => {
                select_json(&record.data, selector)?
            }
            Some(selector) if record.envelope.media_type.contains("xml") => {
                select_xml(&record.data, selector)?
            }
            Some(selector) => {
                return Err(EvidenceError::InvalidSelector(format!(
                    "{selector:?} is not valid for {}",
                    record.envelope.media_type
                )));
            }
            None if record.data.len() <= INLINE_LIMIT => inline_value(&record)?,
            None => None,
        };
        Ok(ExplanationEnvelope {
            protocol: PROTOCOL.into(),
            kind: "explanation".into(),
            version: VERSION.into(),
            config_fingerprint: default_config_fingerprint(),
            handle: handle.into(),
            media_type: record.envelope.media_type,
            selector: selector.map(str::to_string),
            value,
            bytes: record.data.len() as u64,
            truncated: selector.is_none() && record.data.len() > INLINE_LIMIT,
            exit: 0,
        })
    }

    pub fn persist_observation(
        &self,
        observation: &Observation,
    ) -> Result<EvidenceEnvelope, EvidenceError> {
        let envelope = self.put_json("observation", observation, true)?;
        let path = self
            .root
            .join("observations")
            .join(format!("{}.json", envelope.handle.replace(':', "-")));
        let temporary = path.with_extension("json.tmp");
        fs::write(&temporary, serde_json::to_vec(observation)?)?;
        fs::rename(temporary, path)?;
        Ok(envelope)
    }

    pub fn persist_websocket_observation(
        &self,
        observation: &WebSocketObservation,
    ) -> Result<EvidenceEnvelope, EvidenceError> {
        let envelope = self.put_json("websocket-observation", observation, true)?;
        let path = self
            .root
            .join("observations")
            .join(format!("{}.json", envelope.handle.replace(':', "-")));
        let temporary = path.with_extension("json.tmp");
        fs::write(&temporary, serde_json::to_vec(observation)?)?;
        fs::rename(temporary, path)?;
        Ok(envelope)
    }

    pub fn export_bundle(
        &self,
        root_handle: &str,
        path: impl AsRef<Path>,
    ) -> Result<(), EvidenceError> {
        let mut pending = vec![root_handle.to_string()];
        let mut visited = BTreeSet::new();
        let mut records = BTreeMap::new();
        while let Some(handle) = pending.pop() {
            if !visited.insert(handle.clone()) {
                continue;
            }
            if visited.len() > 1_000 {
                return Err(EvidenceError::SelectionTooLarge);
            }
            let record = self.get(&handle)?;
            if record.envelope.media_type.contains("json")
                && let Ok(value) = serde_json::from_slice::<Value>(&record.data)
            {
                collect_handles(&value, &mut pending);
            }
            records.insert(
                handle,
                json!({
                    "media_type": record.envelope.media_type,
                    "bytes": record.envelope.bytes,
                    "blake3": record.envelope.blake3,
                    "redacted": record.envelope.redacted,
                    "encoding": "base64",
                    "data": base64::engine::general_purpose::STANDARD.encode(record.data),
                }),
            );
        }
        let bundle = json!({
            "protocol": PROTOCOL,
            "kind": "evidence-bundle",
            "version": VERSION,
            "root": root_handle,
            "records": records,
        });
        let path = path.as_ref();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, serde_json::to_vec(&bundle)?)?;
        fs::rename(temporary, path)?;
        Ok(())
    }
}

fn collect_handles(value: &Value, pending: &mut Vec<String>) {
    match value {
        Value::String(value) => {
            if let Some((kind, id)) = value.split_once(':')
                && matches!(
                    kind,
                    "body"
                        | "trace"
                        | "schema-error"
                        | "request-derivation"
                        | "observation"
                        | "certificate"
                )
                && id.len() >= 8
            {
                pending.push(value.clone());
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_handles(value, pending);
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                collect_handles(value, pending);
            }
        }
        _ => {}
    }
}

fn inline_value(record: &EvidenceRecord) -> Result<Option<Value>, EvidenceError> {
    if record.envelope.media_type.contains("json") {
        return Ok(Some(serde_json::from_slice(&record.data)?));
    }
    if record.envelope.media_type.starts_with("text/") || record.envelope.media_type.contains("xml")
    {
        return Ok(Some(Value::String(
            String::from_utf8_lossy(&record.data).into_owned(),
        )));
    }
    Ok(Some(json!({
        "encoding": "base64",
        "data": base64::engine::general_purpose::STANDARD.encode(&record.data),
    })))
}

fn select_json(data: &[u8], selector: &str) -> Result<Option<Value>, EvidenceError> {
    let document: Value = serde_json::from_slice(data)?;
    if selector.starts_with('/') || selector.is_empty() {
        return document
            .pointer(selector)
            .cloned()
            .map(Some)
            .ok_or(EvidenceError::SelectionNotFound);
    }
    if !selector.starts_with('$') {
        return Err(EvidenceError::InvalidSelector(
            "JSON selectors must be JSON Pointer or RFC 9535 JSONPath".into(),
        ));
    }
    let path = JsonPath::parse(selector)
        .map_err(|error| EvidenceError::InvalidSelector(error.to_string()))?;
    let nodes = path.query(&document).all();
    if nodes.is_empty() {
        return Err(EvidenceError::SelectionNotFound);
    }
    if nodes.len() > 100 {
        return Err(EvidenceError::SelectionTooLarge);
    }
    Ok(Some(if nodes.len() == 1 {
        nodes[0].clone()
    } else {
        Value::Array(nodes.into_iter().cloned().collect())
    }))
}

fn select_header(data: &[u8], selector: &str) -> Result<Option<Value>, EvidenceError> {
    let document: Value = serde_json::from_slice(data)?;
    let spec = selector.trim_start_matches("header:");
    let (side, name) = spec.split_once(':').unwrap_or(("response", spec));
    if name.is_empty() || !matches!(side, "request" | "response") {
        return Err(EvidenceError::InvalidSelector(
            "header selector must be header:NAME or header:request|response:NAME".into(),
        ));
    }
    let headers = document
        .get(side)
        .and_then(|value| value.get("headers"))
        .and_then(Value::as_object)
        .ok_or(EvidenceError::SelectionNotFound)?;
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| Some(value.clone()))
        .ok_or(EvidenceError::SelectionNotFound)
}

fn select_bytes(data: &[u8], selector: &str, limit: usize) -> Result<Option<Value>, EvidenceError> {
    let range = selector.trim_start_matches("bytes:");
    let (start, end) = range.split_once('-').ok_or_else(|| {
        EvidenceError::InvalidSelector("byte range must be bytes:START-END (inclusive)".into())
    })?;
    let start = start
        .parse::<usize>()
        .map_err(|_| EvidenceError::InvalidSelector("invalid byte range start".into()))?;
    let end = end
        .parse::<usize>()
        .map_err(|_| EvidenceError::InvalidSelector("invalid byte range end".into()))?;
    if start > end || start >= data.len() {
        return Err(EvidenceError::SelectionNotFound);
    }
    let end = end.min(data.len() - 1);
    if end - start + 1 > limit {
        return Err(EvidenceError::SelectionTooLarge);
    }
    Ok(Some(json!({
        "encoding": "base64",
        "start": start,
        "end": end,
        "data": base64::engine::general_purpose::STANDARD.encode(&data[start..=end]),
    })))
}

fn select_xml(data: &[u8], selector: &str) -> Result<Option<Value>, EvidenceError> {
    let xml = std::str::from_utf8(data)
        .map_err(|error| EvidenceError::InvalidSelector(error.to_string()))?;
    let package = sxd_document::parser::parse(xml)
        .map_err(|error| EvidenceError::InvalidSelector(error.to_string()))?;
    let document = package.as_document();
    let selected = sxd_xpath::evaluate_xpath(&document, selector)
        .map_err(|error| EvidenceError::InvalidSelector(error.to_string()))?;
    let value = match selected {
        sxd_xpath::Value::Boolean(value) => Value::Bool(value),
        sxd_xpath::Value::Number(value) => json!(value),
        sxd_xpath::Value::String(value) => Value::String(value),
        sxd_xpath::Value::Nodeset(nodes) => {
            if nodes.size() > 100 {
                return Err(EvidenceError::SelectionTooLarge);
            }
            let values: Vec<_> = nodes
                .document_order()
                .into_iter()
                .map(|node| Value::String(node.string_value()))
                .collect();
            if values.is_empty() {
                return Err(EvidenceError::SelectionNotFound);
            }
            if values.len() == 1 {
                values.into_iter().next().expect("length checked")
            } else {
                Value::Array(values)
            }
        }
    };
    Ok(Some(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blobs_are_content_addressed_and_round_trip() {
        let root = std::env::temp_dir().join(format!("kahea-evidence-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let store = EvidenceStore::open(&root).unwrap();
        let first = store
            .put_blob("body", "application/json", br#"{"ok":true}"#, false)
            .unwrap();
        let second = store
            .put_blob("body", "application/json", br#"{"ok":true}"#, false)
            .unwrap();
        assert_eq!(first.handle, second.handle);
        assert_eq!(store.get(&first.handle).unwrap().data, br#"{"ok":true}"#);
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn explanation_supports_bounded_structured_selectors() {
        let root =
            std::env::temp_dir().join(format!("kahea-evidence-select-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let store = EvidenceStore::open(&root).unwrap();
        let json = store
            .put_blob(
                "body",
                "application/json",
                br#"{"invoice":{"id":"inv_1"},"items":[1,2]}"#,
                false,
            )
            .unwrap();
        assert_eq!(
            store
                .explain(&json.handle, Some("/invoice/id"))
                .unwrap()
                .value,
            Some(json!("inv_1"))
        );
        assert_eq!(
            store
                .explain(&json.handle, Some("$.items[*]"))
                .unwrap()
                .value,
            Some(json!([1, 2]))
        );
        let xml = store
            .put_blob(
                "body",
                "application/xml",
                b"<root><id>42</id></root>",
                false,
            )
            .unwrap();
        assert_eq!(
            store.explain(&xml.handle, Some("/root/id")).unwrap().value,
            Some(json!("42"))
        );
        let bytes = store.explain(&xml.handle, Some("bytes:0-4")).unwrap();
        assert_eq!(bytes.value.unwrap()["data"], json!("PHJvb3Q="));
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn export_bundle_follows_evidence_handles() {
        let root =
            std::env::temp_dir().join(format!("kahea-evidence-export-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let store = EvidenceStore::open(&root).unwrap();
        let body = store
            .put_blob("body", "application/json", br#"{"ok":true}"#, false)
            .unwrap();
        let trace = store
            .put_json("trace", &json!({"body": body.handle}), true)
            .unwrap();
        let bundle_path = root.join("bundle.json");
        store.export_bundle(&trace.handle, &bundle_path).unwrap();
        let bundle: Value = serde_json::from_slice(&fs::read(bundle_path).unwrap()).unwrap();
        assert_eq!(bundle["records"].as_object().unwrap().len(), 2);
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }
}
