use kahea_core::{RiskClass, digest};
use kahea_ingest::{IngestError, inspect_openapi};
use std::fs;
use std::path::{Path, PathBuf};

fn corpus_file(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/corpus")
        .join(name)
}

fn inspect(name: &str) -> kahea_core::OperationIndexEnvelope {
    let path = corpus_file(name);
    let bytes = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    inspect_openapi(&path, &bytes, None, 1_000, 0)
        .unwrap_or_else(|error| panic!("inspect {}: {error}", path.display()))
}

#[test]
fn public_openapi_corpus_has_stable_operation_counts() {
    for (name, expected) in [
        ("swagger-petstore-3.0.json", 19),
        ("swagger-generator-3.0.json", 10),
        ("pokeapi-3.1.yaml", 100),
        ("openai-3.1.yaml", 288),
        ("openapi-3.2-query-webhook.yaml", 1),
    ] {
        let index = inspect(name);
        assert_eq!(index.operations.len(), expected, "fixture drift: {name}");
    }
}

#[test]
fn public_corpus_inspection_is_byte_stable() {
    for name in [
        "swagger-petstore-3.0.json",
        "swagger-generator-3.0.json",
        "pokeapi-3.1.yaml",
        "openai-3.1.yaml",
        "openapi-3.2-query-webhook.yaml",
    ] {
        let first = serde_json::to_vec(&inspect(name)).unwrap();
        let second = serde_json::to_vec(&inspect(name)).unwrap();
        assert_eq!(first, second, "non-deterministic inspection: {name}");
    }
}

#[test]
fn openapi_3_2_query_is_read_and_webhooks_are_explicitly_absent() {
    let index = inspect("openapi-3.2-query-webhook.yaml");
    assert_eq!(index.operations[0].1, "QUERY");
    assert_eq!(index.operations[0].4, RiskClass::Read);
    assert_eq!(index.absent.len(), 1);
    assert_eq!(index.absent[0].capability, "openapi-webhooks");
    assert!(!index.absent[0].blocking);
}

#[test]
fn swagger_2_is_an_intentional_rejection_fixture() {
    let path = corpus_file("httpbin-swagger-2.0.json");
    let bytes = fs::read(&path).unwrap();
    let error = inspect_openapi(&path, &bytes, None, 1_000, 0).unwrap_err();
    assert!(matches!(error, IngestError::UnsupportedVersion));
}

#[test]
fn snapshots_are_manifested_and_fingerprintable() {
    let manifest_path = corpus_file("manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    for fixture in manifest["fixtures"].as_array().unwrap() {
        let name = fixture["file"].as_str().unwrap();
        let bytes = fs::read(corpus_file(name)).unwrap();
        assert!(
            digest(&bytes).starts_with("b3:"),
            "BLAKE3 failed for {name}"
        );
        assert!(!bytes.is_empty(), "empty fixture: {name}");
    }
}
