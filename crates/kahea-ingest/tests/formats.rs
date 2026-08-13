//! Cross-format ingestion contracts: every advertised source family is
//! detected from content, loads deterministically, is content-addressed,
//! never carries captured credentials, and fails closed when unsupported.

use kahea_core::digest;
use kahea_ingest::{
    IngestError, inspect_source, load_source, read_source_artifact, resolve_operation,
};
use kahea_test_server::{remove_temporary_store, temporary_store_path};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const HTTP_METHODS: [&str; 9] = [
    "GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE", "QUERY",
];

/// Every advertised non-workflow source family. Arazzo is deliberately absent:
/// it is dispatched to `kahea-workflow`, not to this ingestion pipeline.
const FAMILIES: [&str; 12] = [
    "billing.openapi.yaml",
    "corpus/swagger-petstore-3.0.json",
    "corpus/pokeapi-3.1.yaml",
    "corpus/openapi-3.2-query-webhook.yaml",
    "imports/postman-2.1.json",
    "imports/postman-v3",
    "imports/request.har",
    "imports/request.curl",
    "imports/requests.http",
    "imports/request.rest",
    "imports/direct-request.json",
    "imports/direct-request.yaml",
];

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn scratch(name: &str) -> PathBuf {
    temporary_store_path(&format!("formats-{name}"))
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn contains_text(value: &serde_json::Value, needle: &str) -> bool {
    value.to_string().contains(needle)
}

#[test]
fn every_advertised_source_family_loads_and_inspects_deterministically() {
    for name in FAMILIES {
        let path = fixture(name);
        let first = read_source_artifact(&path).unwrap_or_else(|error| panic!("{name}: {error}"));
        let second = read_source_artifact(&path).unwrap();
        assert_eq!(first, second, "{name} did not read reproducibly");

        let source = load_source(&path, &first).unwrap_or_else(|error| panic!("{name}: {error}"));
        let repeated = load_source(&path, &first).unwrap();
        assert_eq!(source.document, repeated.document, "{name} load drifted");
        assert_eq!(source.source_fingerprint, repeated.source_fingerprint);

        let index = inspect_source(&path, &first, None, 1_000, 0).unwrap();
        assert_eq!(
            serde_json::to_vec(&index).unwrap(),
            serde_json::to_vec(&inspect_source(&path, &first, None, 1_000, 0).unwrap()).unwrap(),
            "{name} inspection is not byte-stable"
        );
        assert!(
            !index.operations.is_empty(),
            "{name} produced no operations"
        );
        for operation in &index.operations {
            assert!(operation.0.starts_with("op:"), "{name} handle is malformed");
            assert!(
                HTTP_METHODS.contains(&operation.1.as_str()),
                "{name} produced method {:?}",
                operation.1
            );
            assert!(operation.2.starts_with('/'), "{name} path is not rooted");
            resolve_operation(&source, &operation.0)
                .unwrap_or_else(|error| panic!("{name} handle does not resolve: {error}"));
        }
        for absence in &index.absent {
            assert!(!absence.capability.is_empty(), "{name} absence has no name");
            assert!(!absence.location.is_empty(), "{name} absence has no site");
            assert!(!absence.reason.is_empty(), "{name} absence has no reason");
        }
    }
}

#[test]
fn source_fingerprints_are_content_addressed_and_move_with_every_byte() {
    for name in FAMILIES {
        if name == "imports/postman-v3" {
            continue;
        }
        let path = fixture(name);
        let bytes = fs::read(&path).unwrap();
        let source = load_source(&path, &bytes).unwrap();
        assert_eq!(
            source.source_fingerprint,
            digest(&bytes),
            "{name} is not addressed by its own bytes"
        );

        let mut altered = bytes.clone();
        altered.push(b'\n');
        let altered = load_source(&path, &altered).unwrap();
        assert_ne!(
            source.source_fingerprint, altered.source_fingerprint,
            "{name} fingerprint survived a byte change"
        );
        assert_ne!(source.source_handle, altered.source_handle);
    }
}

#[test]
fn capture_formats_are_detected_from_content_not_from_the_file_name() {
    for (name, disguises) in [
        ("imports/request.har", ["capture.dat", "capture.txt"]),
        ("imports/postman-2.1.json", ["collection.dat", "export.txt"]),
        ("imports/direct-request.json", ["request.dat", "call.txt"]),
        ("imports/direct-request.yaml", ["request.dat", "call.txt"]),
        ("imports/request.curl", ["snippet.dat", "snippet.txt"]),
        ("imports/requests.http", ["requests.dat", "requests.txt"]),
        ("imports/request.rest", ["lookup.dat", "lookup.txt"]),
    ] {
        let path = fixture(name);
        let bytes = fs::read(&path).unwrap();
        let canonical = load_source(&path, &bytes).unwrap();
        for disguise in disguises {
            let disguised = load_source(Path::new(disguise), &bytes)
                .unwrap_or_else(|error| panic!("{name} as {disguise}: {error}"));
            assert_eq!(
                canonical.document, disguised.document,
                "{name} was misdetected when named {disguise}"
            );
        }
    }
}

#[test]
fn no_capture_format_ever_imports_credential_material() {
    const TOKEN: &str = "super-secret-token";
    const COOKIE: &str = "super-secret-cookie";
    let bearer = format!("Bearer {TOKEN}");
    let cookie = format!("session={COOKIE}");

    let har = serde_json::json!({"log":{"version":"1.2","entries":[{"request":{
        "method":"GET","url":"https://api.example.test/me",
        "headers":[{"name":"Authorization","value":bearer},{"name":"Cookie","value":cookie}]
    }}]}})
    .to_string();
    let postman = serde_json::json!({
        "info":{"name":"leak","schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item":[{"name":"me","request":{"method":"GET","url":"https://api.example.test/me","header":[
            {"key":"Authorization","value":bearer},{"key":"Cookie","value":cookie}
        ]}}]
    })
    .to_string();
    let direct = serde_json::json!({
        "operationId":"me","method":"GET","url":"https://api.example.test/me",
        "headers":{"Authorization":bearer,"Cookie":cookie}
    })
    .to_string();
    let curl = format!(
        "curl -X GET 'https://api.example.test/me' -H 'Authorization: {bearer}' -H 'Cookie: {cookie}'"
    );
    let http =
        format!("GET https://api.example.test/me\nAuthorization: {bearer}\nCookie: {cookie}\n");

    for (name, bytes) in [
        ("capture.har", har.as_bytes()),
        ("collection.json", postman.as_bytes()),
        ("request.json", direct.as_bytes()),
        ("request.curl", curl.as_bytes()),
        ("requests.http", http.as_bytes()),
    ] {
        let source = load_source(Path::new(name), bytes).unwrap();
        assert!(
            !contains_text(&source.document, TOKEN),
            "{name} imported a bearer token"
        );
        assert!(
            !contains_text(&source.document, COOKIE),
            "{name} imported a cookie value"
        );
        let index = inspect_source(Path::new(name), bytes, None, 50, 0).unwrap();
        assert!(
            index
                .absent
                .iter()
                .any(|absence| absence.capability == "captured-credential" && absence.blocking),
            "{name} dropped credentials without a blocking absence"
        );
    }
}

#[test]
fn malformed_or_unsupported_sources_fail_closed() {
    let swagger = br#"{"swagger":"2.0","info":{"title":"old","version":"1"},"paths":{}}"#;
    let deep_yaml = format!("{}x\n", "- ".repeat(200));
    for (name, bytes) in [
        ("empty.json", b"".as_slice()),
        ("truncated.json", br#"{"openapi":"#),
        ("multi.yaml", b"---\na: 1\n---\nb: 2\n"),
        ("swagger.json", swagger),
        ("capture.har", br#"{"log":{"version":"1.1","entries":[]}}"#),
        (
            "collection.json",
            br#"{"info":{"name":"old","schema":"https://schema.getpostman.com/json/collection/v2.0.0/collection.json"},"item":[]}"#,
        ),
        ("unknown.json", br#"{"hello":"world"}"#),
        ("binary.bin", &[0xff, 0xfe, 0x00, 0x01]),
        ("nested.yaml", deep_yaml.as_bytes()),
    ] {
        assert!(
            load_source(Path::new(name), bytes).is_err(),
            "{name} was accepted instead of failing closed"
        );
    }

    let colliding =
        b"GET https://api.example.test/health\n\n###\nGET https://api.example.test/health\n";
    assert!(
        load_source(Path::new("collide.http"), colliding).is_err(),
        "two captures collided onto one operation without an error"
    );
}

#[test]
fn a_document_without_paths_yields_no_operations_rather_than_guessing() {
    let pathless = br#"{"openapi":"3.1.0","info":{"title":"x","version":"1"}}"#;
    assert!(
        load_source(Path::new("pathless.json"), pathless).is_ok(),
        "3.1 permits a document without paths"
    );
    assert!(matches!(
        inspect_source(Path::new("pathless.json"), pathless, None, 50, 0),
        Err(IngestError::MissingPaths)
    ));

    let components =
        br#"{"openapi":"3.1.0","info":{"title":"x","version":"1"},"components":{"schemas":{}}}"#;
    let index = inspect_source(Path::new("components.json"), components, None, 50, 0).unwrap();
    assert!(index.operations.is_empty());
    assert!(index.next.is_none());
}

#[test]
fn swagger_2_and_declared_capture_versions_report_their_own_rejection() {
    let swagger = br#"{"swagger":"2.0","info":{"title":"old","version":"1"},"paths":{}}"#;
    assert!(matches!(
        load_source(Path::new("swagger.json"), swagger),
        Err(IngestError::UnsupportedVersion)
    ));
    assert!(matches!(
        load_source(Path::new("unknown.json"), br#"{"hello":"world"}"#),
        Err(IngestError::UnsupportedVersion)
    ));
    let har = load_source(
        Path::new("capture.har"),
        br#"{"log":{"version":"1.1","entries":[]}}"#,
    );
    assert!(
        matches!(&har, Err(IngestError::Parse(message)) if message.contains("HAR")),
        "HAR version rejection lost its reason: {har:?}"
    );
}

#[test]
fn pagination_partitions_the_operation_index_without_gaps_or_repeats() {
    let path = fixture("corpus/swagger-petstore-3.0.json");
    let bytes = fs::read(&path).unwrap();
    let whole = inspect_source(&path, &bytes, None, 1_000, 0).unwrap();
    assert!(whole.next.is_none());

    let mut paged = Vec::new();
    let mut cursor = 0_usize;
    loop {
        let page = inspect_source(&path, &bytes, None, 4, cursor).unwrap();
        assert!(page.operations.len() <= 4);
        paged.extend(page.operations.clone());
        match page.next {
            Some(next) => {
                let next: usize = next.parse().unwrap();
                assert!(next > cursor, "cursor did not advance");
                cursor = next;
            }
            None => break,
        }
    }
    assert_eq!(
        paged, whole.operations,
        "paging is not a faithful partition"
    );

    let handles: BTreeSet<_> = paged.iter().map(|operation| &operation.0).collect();
    assert_eq!(handles.len(), paged.len(), "paging repeated an operation");

    assert!(matches!(
        inspect_source(&path, &bytes, None, 4, whole.operations.len() + 1),
        Err(IngestError::InvalidCursor { .. })
    ));
}

#[test]
fn query_filtering_is_case_insensitive_and_always_a_subset() {
    let path = fixture("corpus/swagger-petstore-3.0.json");
    let bytes = fs::read(&path).unwrap();
    let all = inspect_source(&path, &bytes, None, 1_000, 0).unwrap();
    let empty = inspect_source(&path, &bytes, Some("  "), 1_000, 0).unwrap();
    assert_eq!(empty.operations, all.operations, "blank query filtered");

    let lower = inspect_source(&path, &bytes, Some("pet"), 1_000, 0).unwrap();
    for variant in ["PET", "Pet", "pEt"] {
        let other = inspect_source(&path, &bytes, Some(variant), 1_000, 0).unwrap();
        assert_eq!(
            lower.operations, other.operations,
            "{variant} filtered apart"
        );
    }
    assert!(!lower.operations.is_empty());
    assert!(lower.operations.len() < all.operations.len());
    for operation in &lower.operations {
        assert!(
            all.operations.contains(operation),
            "filtering invented an operation"
        );
    }
}

#[test]
fn operations_resolve_by_handle_operation_id_and_method_path() {
    let path = fixture("billing.openapi.yaml");
    let bytes = fs::read(&path).unwrap();
    let source = load_source(&path, &bytes).unwrap();

    let by_id = resolve_operation(&source, "createInvoice").unwrap();
    let by_handle = resolve_operation(&source, &by_id.handle).unwrap();
    let by_route = resolve_operation(&source, "post /v1/invoices").unwrap();
    assert_eq!(by_id.handle, by_handle.handle);
    assert_eq!(by_id.handle, by_route.handle);
    assert_eq!(by_route.method, "POST");
    assert_eq!(by_route.path, "/v1/invoices");

    assert!(matches!(
        resolve_operation(&source, "noSuchOperation"),
        Err(IngestError::UnknownOperation(_))
    ));

    let duplicated = br#"{
      "openapi":"3.1.0","info":{"title":"dup","version":"1"},
      "servers":[{"url":"https://api.example.test"}],
      "paths":{
        "/a":{"get":{"operationId":"shared","responses":{"200":{"description":"ok"}}}},
        "/b":{"get":{"operationId":"shared","responses":{"200":{"description":"ok"}}}}
      }
    }"#;
    let ambiguous = load_source(Path::new("dup.json"), duplicated).unwrap();
    assert!(matches!(
        resolve_operation(&ambiguous, "shared"),
        Err(IngestError::AmbiguousOperation(_))
    ));
}

#[test]
fn multi_request_text_captures_keep_stable_distinct_operations() {
    let path = fixture("imports/requests.http");
    let bytes = fs::read(&path).unwrap();
    let source = load_source(&path, &bytes).unwrap();
    let index = inspect_source(&path, &bytes, None, 50, 0).unwrap();
    assert_eq!(index.operations.len(), 2);

    let ids: BTreeSet<_> = index
        .operations
        .iter()
        .map(|operation| {
            resolve_operation(&source, &operation.0)
                .unwrap()
                .operation_id
        })
        .collect();
    assert_eq!(ids.len(), 2, "captured requests share an operation id");

    let health = resolve_operation(&source, "httpRequest0_0").unwrap();
    assert_eq!(health.method, "GET");
    assert_eq!(health.path, "/health");
    let create = resolve_operation(&source, "httpRequest1_1").unwrap();
    assert_eq!(create.method, "POST");
    assert_eq!(create.operation["x-kahea-captured-body"]["name"], "fixture");
}

#[test]
fn postman_v3_unknown_resources_block_only_their_own_request() {
    let root = scratch("v3-resource");
    copy_tree(&fixture("imports/postman-v3"), &root);
    fs::create_dir_all(root.join("100-list.resources")).unwrap();
    fs::write(
        root.join("100-list.resources/unknown.yaml"),
        b"kind: mystery\n",
    )
    .unwrap();

    let bundled = read_source_artifact(&root).unwrap();
    let index = inspect_source(&root, &bundled, None, 50, 0).unwrap();
    assert_eq!(
        index.operations.len(),
        3,
        "an unknown resource lost requests"
    );

    let resource = index
        .absent
        .iter()
        .find(|absence| absence.capability == "postman-v3-resource")
        .expect("unknown v3 resource is not reported");
    assert!(resource.blocking);
    assert!(
        resource
            .location
            .contains("100-list.resources/unknown.yaml"),
        "absence points at {:?}",
        resource.location
    );
    assert!(
        index
            .absent
            .iter()
            .any(|absence| absence.capability == "postman-v3-example"),
        "pre-existing example absence disappeared"
    );

    remove_temporary_store(&root);
}

#[test]
fn postman_v3_directories_are_bounded_and_reject_traversal() {
    let root = scratch("v3-bounds");
    copy_tree(&fixture("imports/postman-v3"), &root);
    let baseline = read_source_artifact(&root).unwrap();
    assert_eq!(baseline, read_source_artifact(&root).unwrap());

    let empty = scratch("v3-empty");
    fs::create_dir_all(&empty).unwrap();
    fs::write(empty.join("readme.md"), b"no requests here\n").unwrap();
    assert!(
        read_source_artifact(&empty).is_err(),
        "a directory without request files was accepted"
    );
    remove_temporary_store(&empty);

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/etc/passwd", root.join("escape.request.yaml")).unwrap();
        let error = read_source_artifact(&root).unwrap_err();
        assert!(
            error.to_string().contains("symlink"),
            "symlink was not refused: {error}"
        );
    }

    remove_temporary_store(&root);
}
