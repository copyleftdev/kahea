//! Cookie parameters, and the neighbouring-parameter invariants that only a
//! multi-parameter operation can express.
//!
//! Mutating one cookie means rewriting a header that carries the others, and
//! dropping one query parameter means rebuilding a query string that carries
//! the others. Both are easy to get right for a single parameter and easy to
//! get wrong for two, so every assertion here checks the untouched neighbour
//! as well as the targeted one.

use kahea_conformance::{
    ConformanceMode, ConformanceOptions, build_conformance_plan, invoke_conformance,
    store_conformance_plan,
};
use kahea_core::{ConformanceGeneration, RequestPlan};
use kahea_evidence::EvidenceStore;
use kahea_exec::InvokeOptions;
use kahea_ingest::{OpenApiSource, OperationDefinition, load_openapi, resolve_operation};
use kahea_plan::ProjectConfiguration;
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn cookie_source(spec: &str) -> (OpenApiSource, OperationDefinition) {
    let source = load_openapi(Path::new("cookies.yaml"), spec.as_bytes()).unwrap();
    let operation = resolve_operation(&source, "touchSession").unwrap();
    (source, operation)
}

fn fixture_spec() -> String {
    let path = fixture_path("conformance/cookies.openapi.yaml");
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn fixture() -> (OpenApiSource, OperationDefinition) {
    cookie_source(&fixture_spec())
}

fn build(
    source: &OpenApiSource,
    operation: &OperationDefinition,
    mode: ConformanceMode,
    cases: usize,
    seed: u64,
) -> (kahea_core::ConformancePlan, Vec<RequestPlan>) {
    build_conformance_plan(
        source,
        operation,
        ConformanceOptions {
            cases,
            seed,
            mode,
            max_failures: cases,
            ..ConformanceOptions::default()
        },
        &ProjectConfiguration::default(),
    )
    .unwrap_or_else(|error| panic!("cookie campaign failed to generate: {error}"))
}

fn cookie_header(plan: &RequestPlan) -> Option<&str> {
    plan.headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("cookie"))
        .map(|header| header.value.as_str())
}

/// The cookie header parsed back into pairs, so an assertion can name the
/// cookie it cares about instead of matching a substring of the whole header.
fn cookies(plan: &RequestPlan) -> BTreeMap<String, String> {
    cookie_header(plan)
        .into_iter()
        .flat_map(|value| value.split(';'))
        .filter_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}

fn query(plan: &RequestPlan) -> BTreeMap<String, String> {
    url::Url::parse(&plan.target)
        .unwrap()
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

fn cases_by_strategy(
    campaign: &kahea_core::ConformancePlan,
    plans: &[RequestPlan],
) -> BTreeMap<String, RequestPlan> {
    campaign
        .cases
        .iter()
        .zip(plans)
        .map(|(case, plan)| (case.strategy.clone(), plan.clone()))
        .collect()
}

#[test]
fn cookie_parameters_reach_the_wire_as_one_sorted_header() {
    let (source, operation) = fixture();
    let (_, plans) = build(&source, &operation, ConformanceMode::Positive, 6, 4);
    assert!(!plans.is_empty());
    for plan in &plans {
        let header = cookie_header(plan).expect("cookie parameters produced no Cookie header");
        assert_eq!(
            plan.headers
                .iter()
                .filter(|h| h.name.eq_ignore_ascii_case("cookie"))
                .count(),
            1,
            "cookies were split across several headers: {header}"
        );
        let jar = cookies(plan);
        assert!(jar.contains_key("session"), "session cookie is missing");
        assert!(jar.contains_key("theme"), "theme cookie is missing");
        assert!(
            ["light", "dark"].contains(&jar["theme"].as_str()),
            "theme cookie left its enum: {}",
            jar["theme"]
        );
        let length = jar["session"].chars().count();
        assert!(
            (3..=8).contains(&length),
            "session cookie left its declared length: {}",
            jar["session"]
        );
    }
}

#[test]
fn omitting_one_required_cookie_leaves_its_neighbour_intact() {
    let (source, operation) = fixture();
    let (campaign, plans) = build(&source, &operation, ConformanceMode::Negative, 40, 7);
    let by_strategy = cases_by_strategy(&campaign, &plans);

    for (target, neighbour) in [("session", "theme"), ("theme", "session")] {
        let strategy = format!("omit-required-cookie:{target}");
        let plan = by_strategy
            .get(&strategy)
            .unwrap_or_else(|| panic!("no negative case was generated for {strategy}"));
        let jar = cookies(plan);
        assert!(
            !jar.contains_key(target),
            "{strategy} left {target} on the wire: {jar:?}"
        );
        assert!(
            jar.contains_key(neighbour),
            "{strategy} also dropped {neighbour}: {jar:?}"
        );
        assert!(!plan.valid);
    }
}

#[test]
fn corrupting_one_cookie_rewrites_only_that_cookie() {
    let (source, operation) = fixture();
    let (campaign, plans) = build(&source, &operation, ConformanceMode::Negative, 40, 7);
    let by_strategy = cases_by_strategy(&campaign, &plans);
    let (_, positives) = build(&source, &operation, ConformanceMode::Positive, 40, 7);

    let strategy = "invalid-cookie:theme".to_string();
    let plan = by_strategy
        .get(&strategy)
        .unwrap_or_else(|| panic!("no negative case was generated for {strategy}"));
    let jar = cookies(plan);
    assert_eq!(
        jar.get("theme").map(String::as_str),
        Some("__kahea_outside_enum__"),
        "the corrupted cookie never reached the wire: {jar:?}"
    );
    assert!(
        jar.contains_key("session"),
        "corrupting one cookie dropped its neighbour: {jar:?}"
    );

    let untouched: Vec<_> = positives
        .iter()
        .map(|plan| cookies(plan).get("session").cloned())
        .collect();
    assert!(
        untouched
            .iter()
            .any(|value| value.as_deref() == jar.get("session").map(String::as_str)),
        "the neighbouring cookie was rewritten rather than carried through"
    );
}

#[test]
fn dropping_one_required_query_parameter_keeps_the_others() {
    let (source, operation) = fixture();
    let (campaign, plans) = build(&source, &operation, ConformanceMode::Negative, 40, 7);
    let by_strategy = cases_by_strategy(&campaign, &plans);

    for (target, neighbour) in [("region", "limit"), ("limit", "region")] {
        let strategy = format!("omit-required-query:{target}");
        let plan = by_strategy
            .get(&strategy)
            .unwrap_or_else(|| panic!("no negative case was generated for {strategy}"));
        let pairs = query(plan);
        assert!(
            !pairs.contains_key(target),
            "{strategy} left {target} in the query: {pairs:?}"
        );
        assert!(
            pairs.contains_key(neighbour),
            "{strategy} discarded the surviving parameter {neighbour}: {pairs:?}"
        );
    }
}

#[test]
fn every_cookie_strategy_is_generated_and_marked_negative() {
    let (source, operation) = fixture();
    let (campaign, plans) = build(&source, &operation, ConformanceMode::Negative, 40, 7);
    let strategies: Vec<&str> = campaign
        .cases
        .iter()
        .map(|case| case.strategy.as_str())
        .collect();

    for expected in [
        "omit-required-cookie:session",
        "omit-required-cookie:theme",
        "invalid-cookie:theme",
        "invalid-cookie:session",
    ] {
        assert!(
            strategies.contains(&expected),
            "the negative generator never produced {expected}: {strategies:?}"
        );
    }
    assert!(
        campaign
            .cases
            .iter()
            .all(|case| case.generation == ConformanceGeneration::Negative)
    );
    assert!(plans.iter().all(|plan| !plan.valid));
}

struct CookieServer {
    port: u16,
    stop: Arc<AtomicBool>,
    seen: Arc<AtomicUsize>,
    worker: Option<JoinHandle<()>>,
}

/// Enforces every constraint the fixture declares. A server that only checked
/// cookies would answer 200 to a corrupted query parameter, and the oracle
/// would rightly call that an accepted invalid request: the campaign's verdict
/// is only meaningful against a server as strict as the contract.
fn request_conforms(request: &str) -> bool {
    let Some(line) = request.lines().next() else {
        return false;
    };
    let Some(target) = line.split_whitespace().nth(1) else {
        return false;
    };
    let (path, query) = target.split_once('?').unwrap_or((target, ""));

    let Some(id) = path.strip_prefix("/sessions/") else {
        return false;
    };
    if !(2..=6).contains(&id.chars().count()) {
        return false;
    }

    let pairs: BTreeMap<&str, &str> = query
        .split('&')
        .filter(|part| !part.is_empty())
        .filter_map(|part| part.split_once('='))
        .collect();
    if !pairs
        .get("region")
        .is_some_and(|r| *r == "eu" || *r == "us")
    {
        return false;
    }
    if !pairs
        .get("limit")
        .and_then(|l| l.parse::<i64>().ok())
        .is_some_and(|l| (1..=9).contains(&l))
    {
        return false;
    }

    let jar: BTreeMap<&str, &str> = request
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("cookie:"))
        .map(|line| line[7..].split(';').map(str::trim).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|part| part.split_once('='))
        .collect();
    if !jar
        .get("session")
        .is_some_and(|s| (3..=8).contains(&s.chars().count()))
    {
        return false;
    }
    jar.get("theme")
        .is_some_and(|t| *t == "light" || *t == "dark")
}

impl CookieServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(AtomicUsize::new(0));
        let worker = thread::spawn({
            let stop = Arc::clone(&stop);
            let seen = Arc::clone(&seen);
            move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            stream.set_nonblocking(false).unwrap();
                            let mut buffer = vec![0_u8; 16 * 1024];
                            let read = stream.read(&mut buffer).unwrap_or(0);
                            let request = String::from_utf8_lossy(&buffer[..read]).into_owned();
                            let status = if request_conforms(&request) {
                                "200 OK"
                            } else {
                                "400 Bad Request"
                            };
                            let _ = write!(
                                stream,
                                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
                            );
                            let _ = stream.flush();
                            seen.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(_) => break,
                    }
                }
            }
        });
        Self {
            port,
            stop,
            seen,
            worker: Some(worker),
        }
    }
}

impl Drop for CookieServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn scratch(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("kahea-cookies-{name}-{nonce}"))
}

#[test]
fn a_cookie_aware_server_accepts_the_positives_and_rejects_the_mutations() {
    let server = CookieServer::start();
    let (source, operation) = cookie_source(&fixture_spec().replace(
        "https://api.example.test",
        &format!("http://127.0.0.1:{}", server.port),
    ));
    let (campaign, plans) = build(&source, &operation, ConformanceMode::Mixed, 10, 9);
    assert!(
        campaign
            .cases
            .iter()
            .any(|case| case.strategy.contains("cookie")),
        "the mixed campaign carried no cookie mutation"
    );

    let root = scratch("live");
    store_conformance_plan(&root, &campaign, &plans).unwrap();
    let evidence = EvidenceStore::open(root.join("store")).unwrap();
    let observation = invoke_conformance(
        &campaign,
        &InvokeOptions {
            grants: campaign.required_grants.iter().cloned().collect(),
            expected_config_fingerprint: Some(campaign.config_fingerprint.clone()),
            expected_policy_fingerprint: Some(campaign.policy_fingerprint.clone()),
            ..InvokeOptions::default()
        },
        &root,
        &evidence,
    )
    .unwrap();

    assert_eq!(
        observation.transport_errors, 0,
        "the campaign failed at the transport rather than the contract"
    );
    assert_eq!(observation.executed, campaign.cases.len());
    assert_eq!(
        observation.exit, 0,
        "a cookie-aware server did not agree with the generated cases"
    );
    assert_eq!(observation.failed, 0);
    assert_eq!(server.seen.load(Ordering::SeqCst), observation.executed);

    drop(evidence);
    fs::remove_dir_all(root).unwrap();
}
