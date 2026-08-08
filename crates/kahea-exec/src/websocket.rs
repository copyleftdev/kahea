use super::{ExecError, InvokeOptions, secret_redactions, unsafe_address};
use base64::Engine;
use kahea_core::{
    DenialEnvelope, Outcome, PROTOCOL, VERSION, WebSocketCounters, WebSocketObservation,
    WebSocketPlan, WebSocketTerminalCause,
};
use kahea_evidence::EvidenceStore;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use serde_json::{Map, Value, json};
use sha1::{Digest, Sha1};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tungstenite::WebSocket;
use tungstenite::client::IntoClientRequest;
use tungstenite::handshake::client::Response;
use tungstenite::http::header::{HeaderName, HeaderValue};
use tungstenite::http::{HeaderMap, Request};
use tungstenite::protocol::{Role, WebSocketConfig};
use tungstenite::stream::MaybeTlsStream;
use url::Url;

type Socket = WebSocket<MaybeTlsStream<DeadlineTcpStream>>;

pub struct WebSocketConnection {
    pub metadata: WebSocketHandshakeMetadata,
    pub(crate) socket: Socket,
    pub(crate) deadline: Arc<Mutex<Instant>>,
    pub(crate) started: Instant,
    total_deadline: Instant,
}

impl WebSocketConnection {
    pub fn is_open(&self) -> bool {
        self.socket.can_read() || self.socket.can_write()
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    pub fn set_deadline_after(&self, duration: Duration) -> Result<(), ExecError> {
        let requested = Instant::now()
            .checked_add(duration)
            .unwrap_or_else(Instant::now);
        *self
            .deadline
            .lock()
            .map_err(|_| ExecError::Transport("WebSocket deadline state failed".into()))? =
            requested.min(self.total_deadline);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct WebSocketHandshakeMetadata {
    pub status: u16,
    pub negotiated_subprotocol: Option<String>,
    pub latency: Duration,
    pub resolved_origin: SocketAddr,
    pub http_version: String,
    pub handshake: String,
    pub trace: String,
}

pub enum WebSocketConnectResult {
    Connected(Box<WebSocketConnection>),
    Observation(Box<WebSocketObservation>),
    Denied(DenialEnvelope),
}

impl WebSocketConnectResult {
    pub fn exit(&self) -> Option<u8> {
        match self {
            Self::Connected(_) => None,
            Self::Observation(observation) => Some(observation.exit),
            Self::Denied(denial) => Some(denial.exit),
        }
    }
}

pub fn connect_websocket(
    plan: &WebSocketPlan,
    options: &InvokeOptions,
    store: &EvidenceStore,
) -> Result<WebSocketConnectResult, ExecError> {
    connect_websocket_resolving(plan, options, store, &system_resolve)
}

fn connect_websocket_resolving(
    plan: &WebSocketPlan,
    options: &InvokeOptions,
    store: &EvidenceStore,
    resolver: &dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>>,
) -> Result<WebSocketConnectResult, ExecError> {
    if !plan.verify_seal()? {
        return Err(ExecError::InvalidSeal);
    }
    if options
        .expected_config_fingerprint
        .as_ref()
        .is_some_and(|expected| expected != &plan.config_fingerprint)
    {
        return Err(ExecError::ConfigurationMismatch);
    }
    if options
        .expected_policy_fingerprint
        .as_ref()
        .is_some_and(|expected| expected != &plan.policy_fingerprint)
    {
        return Err(ExecError::PolicyMismatch);
    }
    if let Some(missing) = plan
        .required_grants
        .iter()
        .find(|grant| !options.grants.contains(*grant))
    {
        return Ok(WebSocketConnectResult::Denied(denial(
            plan,
            "invocation is missing a required capability",
            missing,
        )));
    }

    let started = Instant::now();
    let total_deadline = deadline(started, plan.limits.total_timeout_ms);
    let connect_deadline = deadline(started, plan.limits.connect_timeout_ms).min(total_deadline);
    let target =
        Url::parse(&plan.target).map_err(|error| ExecError::InvalidTarget(error.to_string()))?;
    validate_transport_binding(plan, &target)?;
    let addresses = match evaluate_runtime_target(plan, &target, options, resolver) {
        Ok(RuntimeTarget::Allowed { addresses }) => addresses,
        Ok(RuntimeTarget::Denied(denial)) => return Ok(WebSocketConnectResult::Denied(denial)),
        Err(RuntimeTargetError::Dns) => {
            return failed_observation(
                plan,
                store,
                started,
                Outcome::Error,
                WebSocketTerminalCause::DnsFailure,
                3,
                None,
                None,
                None,
                None,
                None,
                None,
            );
        }
    };

    let (request, redactions) = websocket_request(plan, options)?;
    let trace = store_websocket_trace(plan, store, &request, &redactions)?;

    let tls = if target.scheme() == "wss" {
        Some(build_tls_config(plan, options)?)
    } else {
        None
    };
    let (stream, selected_address) = match connect_pinned(&addresses, connect_deadline) {
        Ok(connection) => connection,
        Err(ConnectFailure::Timeout) => {
            return failed_observation(
                plan,
                store,
                started,
                Outcome::Error,
                WebSocketTerminalCause::ConnectTimeout,
                3,
                None,
                None,
                None,
                None,
                Some(trace.handle),
                None,
            );
        }
        Err(ConnectFailure::Connection) => {
            return failed_observation(
                plan,
                store,
                started,
                Outcome::Error,
                WebSocketTerminalCause::ConnectionFailure,
                3,
                None,
                None,
                None,
                None,
                Some(trace.handle),
                None,
            );
        }
    };

    let deadline_handle = Arc::new(Mutex::new(connect_deadline));
    let stream = DeadlineTcpStream::new(stream, Arc::clone(&deadline_handle));
    let config = websocket_config(plan)?;
    let stream = match websocket_stream(stream, &target, tls) {
        Ok(stream) => stream,
        Err(()) => {
            return failed_observation(
                plan,
                store,
                started,
                Outcome::Error,
                WebSocketTerminalCause::TlsFailure,
                3,
                None,
                None,
                Some(selected_address),
                None,
                Some(trace.handle),
                None,
            );
        }
    };
    let handshake = perform_upgrade(request, stream, config, target.scheme() == "wss");
    let (socket, response) = match handshake {
        Ok(result) => result,
        Err(failure) => {
            let subprotocol = failure
                .response
                .as_ref()
                .and_then(|response| selected_subprotocol(response));
            let version = failure
                .response
                .as_ref()
                .map(|response| http_version(response.version()));
            let handshake = failure
                .response
                .as_ref()
                .map(|response| store_handshake(plan, store, response, &redactions))
                .transpose()?
                .map(|handle| handle.handle);
            return failed_observation(
                plan,
                store,
                started,
                failure.outcome,
                failure.cause,
                failure.exit,
                failure.status,
                subprotocol,
                Some(selected_address),
                handshake,
                Some(trace.handle),
                version,
            );
        }
    };

    let handshake = store_handshake(plan, store, &response, &redactions)?;
    let latency = started.elapsed();
    *deadline_handle
        .lock()
        .map_err(|_| ExecError::Transport("WebSocket deadline state failed".into()))? =
        total_deadline;
    let metadata = WebSocketHandshakeMetadata {
        status: response.status().as_u16(),
        negotiated_subprotocol: selected_subprotocol(&response),
        latency,
        resolved_origin: selected_address,
        http_version: http_version(response.version()),
        handshake: handshake.handle,
        trace: trace.handle,
    };
    Ok(WebSocketConnectResult::Connected(Box::new(
        WebSocketConnection {
            metadata,
            socket,
            deadline: deadline_handle,
            started,
            total_deadline,
        },
    )))
}

fn validate_transport_binding(plan: &WebSocketPlan, target: &Url) -> Result<(), ExecError> {
    let host = target.host_str().ok_or(ExecError::InvalidSeal)?;
    let port = target
        .port_or_known_default()
        .ok_or(ExecError::InvalidSeal)?;
    let mut grants = vec![format!("net:{host}:{port}"), "websocket:connect".into()];
    if target.scheme() == "ws" {
        grants.push("net-insecure-websocket".into());
    }
    if let Some(auth) = &plan.auth {
        grants.push(format!("secret:{}", auth.profile));
        if !plan
            .secret_refs
            .contains(&format!("secret://{}", auth.profile))
        {
            return Err(ExecError::InvalidSeal);
        }
        if auth.placement == "tls-client-certificate" {
            grants.push(format!("tls-client-cert:{}", auth.profile));
        }
    }
    if grants
        .iter()
        .any(|grant| !plan.required_grants.contains(grant))
    {
        return Err(ExecError::InvalidSeal);
    }

    let mut checks = vec!["extensions:none".to_owned(), "status:101".to_owned()];
    match plan.subprotocols.as_slice() {
        [] => {}
        [protocol] => checks.push(format!("subprotocol:{protocol}")),
        protocols => checks.push(format!("subprotocol:any({})", protocols.join(","))),
    }
    checks.sort();
    if plan.handshake_checks != checks {
        return Err(ExecError::InvalidSeal);
    }
    Ok(())
}

enum RuntimeTarget {
    Allowed { addresses: Vec<SocketAddr> },
    Denied(DenialEnvelope),
}

enum RuntimeTargetError {
    Dns,
}

fn evaluate_runtime_target(
    plan: &WebSocketPlan,
    target: &Url,
    options: &InvokeOptions,
    resolver: &dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>>,
) -> Result<RuntimeTarget, RuntimeTargetError> {
    if !matches!(target.scheme(), "ws" | "wss")
        || !target.username().is_empty()
        || target.password().is_some()
        || target.fragment().is_some()
    {
        return Ok(RuntimeTarget::Denied(denial(
            plan,
            "runtime WebSocket target is incompatible with the sealed transport",
            "websocket:connect",
        )));
    }
    let Some(host) = target.host_str() else {
        return Ok(RuntimeTarget::Denied(denial(
            plan,
            "runtime WebSocket target has no host",
            "websocket:connect",
        )));
    };
    let Some(port) = target.port_or_known_default() else {
        return Ok(RuntimeTarget::Denied(denial(
            plan,
            "runtime WebSocket target has no port",
            "websocket:connect",
        )));
    };
    let required = [format!("net:{host}:{port}"), "websocket:connect".into()];
    for grant in &required {
        if !options.grants.contains(grant) {
            return Ok(RuntimeTarget::Denied(denial(
                plan,
                "runtime target requires an explicit capability",
                grant,
            )));
        }
    }
    if target.scheme() == "ws" && !options.grants.contains("net-insecure-websocket") {
        return Ok(RuntimeTarget::Denied(denial(
            plan,
            "plaintext WebSocket requires an explicit grant",
            "net-insecure-websocket",
        )));
    }
    let resolver_host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    let addresses = resolver(resolver_host, port).map_err(|_| RuntimeTargetError::Dns)?;
    if addresses.is_empty() || addresses.iter().any(|address| address.port() != port) {
        return Err(RuntimeTargetError::Dns);
    }
    for address in &addresses {
        if unsafe_address(address.ip()) {
            let grant = match address.ip() {
                IpAddr::V4(address) => format!("net-cidr:{address}/32"),
                IpAddr::V6(address) => format!("net-cidr:{address}/128"),
            };
            if !options.grants.contains(&grant) {
                return Ok(RuntimeTarget::Denied(denial(
                    plan,
                    "resolved address is denied by the network boundary",
                    &grant,
                )));
            }
        }
    }
    Ok(RuntimeTarget::Allowed { addresses })
}

fn system_resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    Ok((host, port).to_socket_addrs()?.collect())
}

fn websocket_request(
    plan: &WebSocketPlan,
    options: &InvokeOptions,
) -> Result<(Request<()>, Vec<Vec<u8>>), ExecError> {
    let mut request = plan
        .target
        .as_str()
        .into_client_request()
        .map_err(|_| ExecError::InvalidTarget("WebSocket request URI is invalid".into()))?;
    for planned in &plan.headers {
        insert_header(request.headers_mut(), &planned.name, &planned.value, false)?;
    }
    if let Some(origin) = &plan.origin {
        insert_header(request.headers_mut(), "origin", origin, false)?;
    }
    if !plan.subprotocols.is_empty() {
        insert_header(
            request.headers_mut(),
            "sec-websocket-protocol",
            &plan.subprotocols.join(", "),
            false,
        )?;
    }
    if let Some(auth) = &plan.auth
        && auth.placement != "tls-client-certificate"
    {
        let secret = options
            .secrets
            .get(&auth.profile)
            .ok_or_else(|| ExecError::MissingSecret(auth.profile.clone()))?;
        match auth.placement.as_str() {
            "header:Authorization:basic" => {
                let encoded = base64::engine::general_purpose::STANDARD.encode(secret);
                insert_header(
                    request.headers_mut(),
                    "authorization",
                    &format!("Basic {encoded}"),
                    true,
                )?;
            }
            "header:Authorization:bearer" => insert_header(
                request.headers_mut(),
                "authorization",
                &format!("Bearer {secret}"),
                true,
            )?,
            other => return Err(ExecError::UnsupportedAuth(other.into())),
        }
    }
    let mut redactions = secret_redactions(options);
    redactions.sort_by_key(|value| std::cmp::Reverse(value.len()));
    redactions.dedup();
    Ok((request, redactions))
}

fn insert_header(
    headers: &mut HeaderMap,
    name: &str,
    value: &str,
    sensitive: bool,
) -> Result<(), ExecError> {
    if name.contains(['\r', '\n']) || value.contains(['\r', '\n']) {
        return Err(ExecError::InvalidHeader("CR/LF is denied".into()));
    }
    let name = HeaderName::from_str(name)
        .map_err(|_| ExecError::InvalidHeader("invalid WebSocket header name".into()))?;
    let mut value = HeaderValue::from_str(value)
        .map_err(|_| ExecError::InvalidHeader("invalid WebSocket header value".into()))?;
    value.set_sensitive(sensitive);
    headers.append(name, value);
    Ok(())
}

fn build_tls_config(
    plan: &WebSocketPlan,
    options: &InvokeOptions,
) -> Result<Arc<ClientConfig>, ExecError> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    roots.add_parsable_certificates(native.certs);
    for pem in &options.additional_root_certificates {
        let certificates: Vec<_> = CertificateDer::pem_slice_iter(pem)
            .collect::<Result<_, _>>()
            .map_err(|_| ExecError::Transport("TLS root certificate could not be loaded".into()))?;
        let expected = certificates.len();
        let (added, ignored) = roots.add_parsable_certificates(certificates);
        if expected == 0 || added != expected || ignored != 0 {
            return Err(ExecError::Transport(
                "TLS root certificate could not be loaded".into(),
            ));
        }
    }
    if roots.is_empty() {
        return Err(ExecError::Transport(
            "TLS trust store contains no usable certificates".into(),
        ));
    }
    let builder = ClientConfig::builder().with_root_certificates(roots);
    let config = if let Some(auth) = plan
        .auth
        .as_ref()
        .filter(|auth| auth.placement == "tls-client-certificate")
    {
        let pem = options
            .secrets
            .get(&auth.profile)
            .ok_or_else(|| ExecError::MissingSecret(auth.profile.clone()))?;
        let certificates = CertificateDer::pem_slice_iter(pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ExecError::InvalidClientIdentity)?;
        let key = PrivateKeyDer::from_pem_slice(pem.as_bytes())
            .map_err(|_| ExecError::InvalidClientIdentity)?;
        builder
            .with_client_auth_cert(certificates, key)
            .map_err(|_| ExecError::InvalidClientIdentity)?
    } else {
        builder.with_no_client_auth()
    };
    Ok(Arc::new(config))
}

fn websocket_config(plan: &WebSocketPlan) -> Result<WebSocketConfig, ExecError> {
    let frame = usize::try_from(plan.limits.max_frame_bytes).map_err(|_| ExecError::InvalidSeal)?;
    let message =
        usize::try_from(plan.limits.max_message_bytes).map_err(|_| ExecError::InvalidSeal)?;
    Ok(WebSocketConfig::default()
        .read_buffer_size(frame.clamp(1024, 16 * 1024))
        .write_buffer_size(0)
        .max_write_buffer_size(frame.saturating_add(32).max(33))
        .max_frame_size(Some(frame))
        .max_message_size(Some(message))
        .accept_unmasked_frames(false))
}

fn websocket_stream(
    stream: DeadlineTcpStream,
    target: &Url,
    tls: Option<Arc<ClientConfig>>,
) -> Result<MaybeTlsStream<DeadlineTcpStream>, ()> {
    let Some(config) = tls else {
        return Ok(MaybeTlsStream::Plain(stream));
    };
    let host = target.host_str().ok_or(())?;
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
        .to_owned();
    let server_name = ServerName::try_from(host).map_err(|_| ())?;
    let connection = ClientConnection::new(config, server_name).map_err(|_| ())?;
    Ok(MaybeTlsStream::Rustls(StreamOwned::new(connection, stream)))
}

fn perform_upgrade(
    request: Request<()>,
    mut stream: MaybeTlsStream<DeadlineTcpStream>,
    config: WebSocketConfig,
    tls: bool,
) -> Result<(Socket, Response), HandshakeFailure> {
    let key = request
        .headers()
        .get("sec-websocket-key")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(handshake_check_failure)?
        .to_owned();
    let offered_subprotocols = request
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .map(|value| value.trim().to_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    const MAX_HANDSHAKE_BYTES: usize = 64 * 1024;
    const MAX_HEADERS: usize = 128;
    let mut outbound = Vec::with_capacity(2 * 1024);
    write!(outbound, "GET {path} HTTP/1.1\r\n").map_err(|_| handshake_check_failure())?;
    for (name, value) in request.headers() {
        let value = value.to_str().map_err(|_| handshake_check_failure())?;
        write!(outbound, "{name}: {value}\r\n").map_err(|_| handshake_check_failure())?;
        if outbound.len() > MAX_HANDSHAKE_BYTES {
            return Err(handshake_check_failure());
        }
    }
    if outbound.len().saturating_add(2) > MAX_HANDSHAKE_BYTES {
        return Err(handshake_check_failure());
    }
    outbound.extend_from_slice(b"\r\n");
    stream
        .write_all(&outbound)
        .and_then(|()| stream.flush())
        .map_err(|error| io_handshake_failure(error, tls))?;

    let mut received = Vec::with_capacity(4 * 1024);
    let header_end = loop {
        if let Some(offset) = received.windows(4).position(|window| window == b"\r\n\r\n") {
            break offset + 4;
        }
        if received.len() >= MAX_HANDSHAKE_BYTES {
            return Err(handshake_check_failure());
        }
        let mut chunk = [0_u8; 4 * 1024];
        let bytes = stream
            .read(&mut chunk)
            .map_err(|error| io_handshake_failure(error, tls))?;
        if bytes == 0 {
            return Err(HandshakeFailure {
                outcome: Outcome::Error,
                cause: WebSocketTerminalCause::UnexpectedEof,
                exit: 3,
                status: None,
                response: None,
            });
        }
        if received.len().saturating_add(bytes) > MAX_HANDSHAKE_BYTES + chunk.len() {
            return Err(handshake_check_failure());
        }
        received.extend_from_slice(&chunk[..bytes]);
    };

    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Response::new(&mut headers);
    let parsed_bytes = match parsed.parse(&received[..header_end]) {
        Ok(httparse::Status::Complete(bytes)) => bytes,
        _ => return Err(handshake_check_failure()),
    };
    if parsed_bytes != header_end {
        return Err(handshake_check_failure());
    }
    if header_end > MAX_HANDSHAKE_BYTES {
        return Err(handshake_check_failure());
    }
    let status = parsed.code.ok_or_else(handshake_check_failure)?;
    let version = match parsed.version {
        Some(1) => tungstenite::http::Version::HTTP_11,
        Some(0) => tungstenite::http::Version::HTTP_10,
        _ => return Err(handshake_check_failure()),
    };
    let mut response = tungstenite::http::Response::builder()
        .status(status)
        .version(version);
    for header in parsed.headers.iter() {
        response = response.header(header.name, header.value);
    }
    let response = response.body(None).map_err(|_| handshake_check_failure())?;

    let expected_accept = {
        let mut hash = Sha1::new();
        hash.update(key.as_bytes());
        hash.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        base64::engine::general_purpose::STANDARD.encode(hash.finalize())
    };
    let upgrade_valid = response
        .headers()
        .get_all("upgrade")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.eq_ignore_ascii_case("websocket"));
    let connection_valid = response
        .headers()
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
    let accepts: Vec<_> = response
        .headers()
        .get_all("sec-websocket-accept")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    let extensions_absent = !response.headers().contains_key("sec-websocket-extensions");
    let selected: Vec<_> = response
        .headers()
        .get_all("sec-websocket-protocol")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    let subprotocol_valid = match selected.as_slice() {
        [] => offered_subprotocols.is_empty(),
        [selected] => {
            !selected.contains(',')
                && offered_subprotocols
                    .iter()
                    .any(|offered| offered == selected)
        }
        _ => false,
    };
    if status != 101
        || version != tungstenite::http::Version::HTTP_11
        || !upgrade_valid
        || !connection_valid
        || accepts.as_slice() != [expected_accept.as_str()]
        || !extensions_absent
        || !subprotocol_valid
    {
        return Err(HandshakeFailure {
            outcome: Outcome::Failed,
            cause: WebSocketTerminalCause::HandshakeCheckFailed,
            exit: 1,
            status: Some(status),
            response: Some(Box::new(response)),
        });
    }
    let buffered = received[header_end..].to_vec();
    let socket = WebSocket::from_partially_read(stream, buffered, Role::Client, Some(config));
    Ok((socket, response))
}

fn store_websocket_trace(
    plan: &WebSocketPlan,
    store: &EvidenceStore,
    request: &Request<()>,
    redactions: &[Vec<u8>],
) -> Result<kahea_core::EvidenceEnvelope, ExecError> {
    let trace = json!({
        "method": "GET",
        "target": plan.target,
        "headers": safe_headers(request.headers(), &plan.sensitive_headers, redactions, true),
    });
    Ok(store.put_json("websocket-trace", &trace, true)?)
}

fn store_handshake(
    plan: &WebSocketPlan,
    store: &EvidenceStore,
    response: &Response,
    redactions: &[Vec<u8>],
) -> Result<kahea_core::EvidenceEnvelope, ExecError> {
    let evidence = json!({
        "status": response.status().as_u16(),
        "http_version": http_version(response.version()),
        "headers": safe_headers(response.headers(), &plan.sensitive_headers, redactions, false),
    });
    Ok(store.put_json("websocket-handshake", &evidence, true)?)
}

fn safe_headers(
    headers: &HeaderMap,
    configured: &[String],
    redactions: &[Vec<u8>],
    request: bool,
) -> Map<String, Value> {
    let mut result = Map::new();
    for (name, value) in headers {
        let normalized = name.as_str().to_ascii_lowercase();
        let generated = (request && normalized == "sec-websocket-key")
            || (!request && normalized == "sec-websocket-accept");
        let sensitive = value.is_sensitive()
            || configured
                .iter()
                .any(|configured| configured.eq_ignore_ascii_case(&normalized))
            || matches!(
                normalized.as_str(),
                "authorization" | "proxy-authorization" | "cookie" | "set-cookie" | "x-api-key"
            );
        let display = if generated {
            "[GENERATED]".into()
        } else if sensitive {
            "[REDACTED]".into()
        } else {
            redact_text(value.to_str().unwrap_or("[NON-UTF8]"), redactions)
        };
        result.insert(normalized, Value::String(display));
    }
    result
}

fn redact_text(value: &str, redactions: &[Vec<u8>]) -> String {
    let mut value = value.as_bytes().to_vec();
    for secret in redactions.iter().filter(|secret| !secret.is_empty()) {
        let mut cursor = 0;
        while cursor + secret.len() <= value.len() {
            let Some(offset) = value[cursor..]
                .windows(secret.len())
                .position(|window| window == secret.as_slice())
            else {
                break;
            };
            let start = cursor + offset;
            value.splice(start..start + secret.len(), b"[REDACTED]".iter().copied());
            cursor = start + b"[REDACTED]".len();
        }
    }
    String::from_utf8_lossy(&value).into_owned()
}

struct HandshakeFailure {
    outcome: Outcome,
    cause: WebSocketTerminalCause,
    exit: u8,
    status: Option<u16>,
    response: Option<Box<Response>>,
}

fn handshake_check_failure() -> HandshakeFailure {
    HandshakeFailure {
        outcome: Outcome::Failed,
        cause: WebSocketTerminalCause::HandshakeCheckFailed,
        exit: 1,
        status: None,
        response: None,
    }
}

fn io_handshake_failure(error: io::Error, tls: bool) -> HandshakeFailure {
    let cause = if matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        WebSocketTerminalCause::ConnectTimeout
    } else if tls && error.kind() == io::ErrorKind::InvalidData {
        WebSocketTerminalCause::TlsFailure
    } else if error.kind() == io::ErrorKind::UnexpectedEof {
        WebSocketTerminalCause::UnexpectedEof
    } else {
        WebSocketTerminalCause::IoFailure
    };
    HandshakeFailure {
        outcome: Outcome::Error,
        cause,
        exit: 3,
        status: None,
        response: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn failed_observation(
    plan: &WebSocketPlan,
    store: &EvidenceStore,
    started: Instant,
    outcome: Outcome,
    cause: WebSocketTerminalCause,
    exit: u8,
    status: Option<u16>,
    subprotocol: Option<String>,
    resolved: Option<SocketAddr>,
    handshake: Option<String>,
    trace: Option<String>,
    http_version: Option<String>,
) -> Result<WebSocketConnectResult, ExecError> {
    let elapsed = started.elapsed();
    let observation = WebSocketObservation {
        protocol: PROTOCOL.into(),
        kind: "websocket-observation".into(),
        version: VERSION.into(),
        config_fingerprint: plan.config_fingerprint.clone(),
        policy_fingerprint: plan.policy_fingerprint.clone(),
        source_fingerprints: plan.source_fingerprints.clone(),
        tool_version: env!("CARGO_PKG_VERSION").into(),
        plan: plan.id.clone(),
        outcome,
        handshake_status: status,
        negotiated_subprotocol: subprotocol,
        handshake_latency_ms: Some(elapsed.as_secs_f64() * 1_000.0),
        session_duration_ms: Some(elapsed.as_secs_f64() * 1_000.0),
        transcript: None,
        handshake,
        trace,
        close: None,
        terminal_cause: cause,
        counters: WebSocketCounters::default(),
        resolved_origin: resolved.map(|address| address.to_string()),
        http_version,
        secret_refs: plan.secret_refs.clone(),
        runtime: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        exit,
    };
    store.persist_websocket_observation(&observation)?;
    Ok(WebSocketConnectResult::Observation(Box::new(observation)))
}

fn selected_subprotocol(response: &Response) -> Option<String> {
    response
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn http_version(version: tungstenite::http::Version) -> String {
    match version {
        tungstenite::http::Version::HTTP_09 => "0.9",
        tungstenite::http::Version::HTTP_10 => "1.0",
        tungstenite::http::Version::HTTP_11 => "1.1",
        tungstenite::http::Version::HTTP_2 => "2",
        tungstenite::http::Version::HTTP_3 => "3",
        _ => "unknown",
    }
    .into()
}

fn denial(plan: &WebSocketPlan, reason: &str, required: &str) -> DenialEnvelope {
    DenialEnvelope {
        protocol: PROTOCOL.into(),
        kind: "denial".into(),
        version: VERSION.into(),
        config_fingerprint: plan.config_fingerprint.clone(),
        plan: plan.id.clone(),
        reason: reason.into(),
        required: required.into(),
        policy: plan.policy_fingerprint.clone(),
        exit: 4,
    }
}

enum ConnectFailure {
    Timeout,
    Connection,
}

fn connect_pinned(
    addresses: &[SocketAddr],
    deadline: Instant,
) -> Result<(TcpStream, SocketAddr), ConnectFailure> {
    let mut timed_out = false;
    for address in addresses {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err(ConnectFailure::Timeout);
        };
        match TcpStream::connect_timeout(address, remaining.max(Duration::from_millis(1))) {
            Ok(stream) => {
                stream
                    .set_nodelay(true)
                    .map_err(|_| ConnectFailure::Connection)?;
                return Ok((stream, *address));
            }
            Err(error) if error.kind() == io::ErrorKind::TimedOut => timed_out = true,
            Err(_) => {}
        }
    }
    if timed_out || Instant::now() >= deadline {
        Err(ConnectFailure::Timeout)
    } else {
        Err(ConnectFailure::Connection)
    }
}

fn deadline(started: Instant, milliseconds: u64) -> Instant {
    started
        .checked_add(Duration::from_millis(milliseconds))
        .unwrap_or(started)
}

pub(crate) struct DeadlineTcpStream {
    stream: TcpStream,
    deadline: Arc<Mutex<Instant>>,
}

impl DeadlineTcpStream {
    fn new(stream: TcpStream, deadline: Arc<Mutex<Instant>>) -> Self {
        Self { stream, deadline }
    }

    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .lock()
            .map_err(|_| io::Error::other("deadline state failed"))?
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "WebSocket deadline elapsed"))
    }
}

impl Read for DeadlineTcpStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buffer).map_err(normalize_timeout)
    }
}

impl Write for DeadlineTcpStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(buffer).map_err(normalize_timeout)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.flush().map_err(normalize_timeout)
    }
}

fn normalize_timeout(error: io::Error) -> io::Error {
    if error.kind() == io::ErrorKind::WouldBlock {
        io::Error::new(io::ErrorKind::TimedOut, "WebSocket deadline elapsed")
    } else {
        error
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::result_large_err)]

    use super::*;
    use kahea_core::{
        PlannedAuth, PlannedHeader, RiskClass, WebSocketAction, WebSocketLimits,
        default_config_fingerprint, digest,
    };
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use rustls::{ServerConfig, ServerConnection, StreamOwned};
    use std::fs;
    use std::net::{Ipv6Addr, TcpListener};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tungstenite::http::StatusCode;

    fn store() -> (std::path::PathBuf, EvidenceStore) {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "kahea-websocket-exec-{}-{nonce}",
            std::process::id()
        ));
        let store = EvidenceStore::open(&root).unwrap();
        (root, store)
    }

    fn plan(target: String, cidr_grant: String) -> WebSocketPlan {
        let target_url = Url::parse(&target).unwrap();
        let host = target_url.host_str().unwrap();
        let port = target_url.port_or_known_default().unwrap();
        WebSocketPlan {
            protocol: PROTOCOL.into(),
            kind: "websocket-plan".into(),
            version: VERSION.into(),
            config_fingerprint: default_config_fingerprint(),
            policy_fingerprint: digest(b"websocket-test-policy"),
            source_fingerprints: vec![digest(b"websocket-test-source")],
            id: String::new(),
            operation: "op:websocket-test".into(),
            target,
            risk: RiskClass::Read,
            required_grants: vec![
                format!("net:{host}:{port}"),
                cidr_grant,
                "websocket:connect".into(),
            ],
            secret_refs: Vec::new(),
            headers: Vec::new(),
            auth: None,
            origin: None,
            subprotocols: Vec::new(),
            handshake_checks: vec!["extensions:none".into(), "status:101".into()],
            limits: WebSocketLimits {
                connect_timeout_ms: 1_000,
                action_timeout_ms: 1_000,
                idle_timeout_ms: 1_000,
                close_timeout_ms: 1_000,
                total_timeout_ms: 2_000,
                max_frame_bytes: 64 * 1024,
                max_message_bytes: 128 * 1024,
                max_inbound_frames: 8,
                max_outbound_frames: 8,
                max_inbound_messages: 4,
                max_outbound_messages: 4,
                max_inbound_bytes: 256 * 1024,
                max_outbound_bytes: 256 * 1024,
            },
            actions: vec![WebSocketAction::ExpectClose {
                codes: vec![1000],
                reason: None,
                timeout_ms: None,
            }],
            sensitive_headers: vec!["authorization".into(), "cookie".into()],
            redact_response_json_pointers: Vec::new(),
            valid: true,
            fingerprint: String::new(),
            exit: 0,
        }
        .seal()
        .unwrap()
    }

    fn ws_plan(listener: &TcpListener) -> WebSocketPlan {
        let address = listener.local_addr().unwrap();
        let mut plan = plan(
            format!("ws://{address}/socket"),
            match address.ip() {
                IpAddr::V4(address) => format!("net-cidr:{address}/32"),
                IpAddr::V6(address) => format!("net-cidr:{address}/128"),
            },
        );
        plan.required_grants.push("net-insecure-websocket".into());
        plan.seal().unwrap()
    }

    fn options(plan: &WebSocketPlan) -> InvokeOptions {
        InvokeOptions {
            grants: plan.required_grants.iter().cloned().collect(),
            expected_config_fingerprint: Some(plan.config_fingerprint.clone()),
            expected_policy_fingerprint: Some(plan.policy_fingerprint.clone()),
            ..InvokeOptions::default()
        }
    }

    #[test]
    fn redaction_marker_as_a_secret_terminates_without_revealing_it() {
        assert_eq!(
            redact_text("prefix [REDACTED] suffix", &[b"[REDACTED]".to_vec()]),
            "prefix [REDACTED] suffix"
        );
    }

    #[test]
    fn missing_grant_and_tampered_target_never_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let plan = ws_plan(&listener);
        let (root, store) = store();
        let result = connect_websocket(&plan, &InvokeOptions::default(), &store).unwrap();
        assert!(matches!(result, WebSocketConnectResult::Denied(_)));
        assert_eq!(result.exit(), Some(4));

        let mut tampered = plan.clone();
        tampered.target = tampered.target.replace("ws://", "wss://");
        assert!(matches!(
            connect_websocket(&tampered, &options(&plan), &store),
            Err(ExecError::InvalidSeal)
        ));
        let mut weakened = plan.clone();
        weakened
            .required_grants
            .retain(|grant| grant != "websocket:connect");
        let weakened = weakened.seal().unwrap();
        assert!(matches!(
            connect_websocket(&weakened, &options(&plan), &store),
            Err(ExecError::InvalidSeal)
        ));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_auth_secret_is_rejected_before_tcp_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut plan = ws_plan(&listener);
        plan.auth = Some(PlannedAuth {
            scheme: "bearer".into(),
            kind: "http".into(),
            profile: "missing-profile".into(),
            placement: "header:Authorization:bearer".into(),
            token_url: None,
            scopes: Vec::new(),
        });
        plan.secret_refs = vec!["secret://missing-profile".into()];
        plan.required_grants.push("secret:missing-profile".into());
        let plan = plan.seal().unwrap();
        let (root, store) = store();
        assert!(matches!(
            connect_websocket(&plan, &options(&plan), &store),
            Err(ExecError::MissingSecret(profile)) if profile == "missing-profile"
        ));
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn dns_is_resolved_once_then_the_address_is_pinned_without_changing_host() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut plan = plan(
            format!("ws://socket.example.test:{}/socket", address.port()),
            "net-cidr:127.0.0.1/32".into(),
        );
        plan.required_grants.push("net-insecure-websocket".into());
        let plan = plan.seal().unwrap();
        let expected_host = format!("socket.example.test:{}", address.port());
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            tungstenite::accept_hdr(
                stream,
                move |request: &Request<()>, response: tungstenite::http::Response<()>| {
                    assert_eq!(request.headers()["host"], expected_host);
                    Ok(response)
                },
            )
            .unwrap()
        });
        let (root, store) = store();
        let calls = std::cell::Cell::new(0_u8);
        let resolver = |host: &str, port: u16| {
            assert_eq!(host, "socket.example.test");
            assert_eq!(port, address.port());
            calls.set(calls.get() + 1);
            Ok(vec![address])
        };
        let WebSocketConnectResult::Connected(connection) =
            connect_websocket_resolving(&plan, &options(&plan), &store, &resolver).unwrap()
        else {
            panic!("expected a pinned WebSocket connection")
        };
        assert_eq!(calls.get(), 1);
        assert_eq!(connection.metadata.resolved_origin, address);
        drop(connection);
        server.join().unwrap();

        let dns_error = |_host: &str, _port: u16| {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "controlled DNS failure",
            ))
        };
        let WebSocketConnectResult::Observation(observation) =
            connect_websocket_resolving(&plan, &options(&plan), &store, &dns_error).unwrap()
        else {
            panic!("DNS failure must return an observation")
        };
        assert_eq!(observation.exit, 3);
        assert!(matches!(
            observation.terminal_cause,
            WebSocketTerminalCause::DnsFailure
        ));
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn handshake_injects_sealed_intent_and_redacts_secrets_and_entropy() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut plan = ws_plan(&listener);
        plan.headers.push(PlannedHeader {
            name: "X-Client".into(),
            value: "kahea-test".into(),
        });
        plan.origin = Some("https://client.example.test".into());
        plan.subprotocols = vec!["kahea.test.v1".into()];
        plan.auth = Some(PlannedAuth {
            scheme: "bearer".into(),
            kind: "http".into(),
            profile: "test-profile".into(),
            placement: "header:Authorization:bearer".into(),
            token_url: None,
            scopes: Vec::new(),
        });
        plan.secret_refs = vec!["secret://test-profile".into()];
        plan.required_grants.push("secret:test-profile".into());
        plan.handshake_checks
            .push("subprotocol:kahea.test.v1".into());
        let plan = plan.seal().unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            tungstenite::accept_hdr(
                stream,
                |request: &Request<()>, mut response: tungstenite::http::Response<()>| {
                    assert_eq!(request.headers()["x-client"], "kahea-test");
                    assert_eq!(request.headers()["origin"], "https://client.example.test");
                    assert_eq!(
                        request.headers()["authorization"],
                        "Bearer top-secret-value"
                    );
                    assert_eq!(request.headers()["sec-websocket-protocol"], "kahea.test.v1");
                    assert!(request.headers().contains_key("sec-websocket-key"));
                    response.headers_mut().insert(
                        "sec-websocket-protocol",
                        HeaderValue::from_static("kahea.test.v1"),
                    );
                    response.headers_mut().insert(
                        "connection",
                        HeaderValue::from_static("keep-alive, Upgrade"),
                    );
                    response
                        .headers_mut()
                        .insert("x-reflected", HeaderValue::from_static("top-secret-value"));
                    Ok(response)
                },
            )
            .unwrap()
        });
        let (root, store) = store();
        let mut options = options(&plan);
        options
            .secrets
            .insert("test-profile".into(), "top-secret-value".into());
        let WebSocketConnectResult::Connected(connection) =
            connect_websocket(&plan, &options, &store).unwrap()
        else {
            panic!("expected a live WebSocket connection")
        };
        assert_eq!(connection.metadata.status, 101);
        assert_eq!(
            connection.metadata.negotiated_subprotocol.as_deref(),
            Some("kahea.test.v1")
        );
        assert!(connection.is_open());
        for handle in [&connection.metadata.trace, &connection.metadata.handshake] {
            let evidence = store.get(handle).unwrap();
            let text = String::from_utf8(evidence.data).unwrap();
            assert!(text.contains("[REDACTED]") || text.contains("[GENERATED]"));
            assert!(!text.contains("top-secret-value"));
            assert!(!text.contains("Bearer top-secret-value"));
        }
        drop(connection);
        server.join().unwrap();
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn redirects_and_negotiated_extensions_fail_closed() {
        let redirect_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let redirect_plan = ws_plan(&redirect_listener);
        let redirect_server = thread::spawn(move || {
            let (mut stream, _) = redirect_listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: ws://127.0.0.1:9/stolen\r\nContent-Length: 0\r\n\r\n",
                )
                .unwrap();
        });
        let (root, store) = store();
        let WebSocketConnectResult::Observation(observation) =
            connect_websocket(&redirect_plan, &options(&redirect_plan), &store).unwrap()
        else {
            panic!("redirect must be a failed observation")
        };
        assert_eq!(observation.exit, 1);
        assert_eq!(observation.handshake_status, Some(302));
        redirect_server.join().unwrap();

        let extension_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let extension_plan = ws_plan(&extension_listener);
        let extension_server = thread::spawn(move || {
            let (stream, _) = extension_listener.accept().unwrap();
            tungstenite::accept_hdr(
                stream,
                |_request: &Request<()>, mut response: tungstenite::http::Response<()>| {
                    response.headers_mut().insert(
                        "sec-websocket-extensions",
                        HeaderValue::from_static("permessage-deflate"),
                    );
                    Ok(response)
                },
            )
        });
        let WebSocketConnectResult::Observation(observation) =
            connect_websocket(&extension_plan, &options(&extension_plan), &store).unwrap()
        else {
            panic!("extension negotiation must fail closed")
        };
        assert_eq!(observation.exit, 1);
        assert!(matches!(
            observation.terminal_cause,
            WebSocketTerminalCause::HandshakeCheckFailed
        ));
        let _ = extension_server.join().unwrap();
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_accept_and_silent_peer_map_deterministically() {
        let malformed_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let malformed_plan = ws_plan(&malformed_listener);
        let malformed_server = thread::spawn(move || {
            let (mut stream, _) = malformed_listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: invalid\r\n\r\n")
                .unwrap();
        });
        let (root, store) = store();
        let WebSocketConnectResult::Observation(observation) =
            connect_websocket(&malformed_plan, &options(&malformed_plan), &store).unwrap()
        else {
            panic!("bad accept key must fail the handshake")
        };
        assert_eq!(observation.exit, 1);
        assert!(matches!(
            observation.terminal_cause,
            WebSocketTerminalCause::HandshakeCheckFailed
        ));
        malformed_server.join().unwrap();

        let silent_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut silent_plan = ws_plan(&silent_listener);
        silent_plan.limits.connect_timeout_ms = 30;
        silent_plan = silent_plan.seal().unwrap();
        let silent_server = thread::spawn(move || {
            let (_stream, _) = silent_listener.accept().unwrap();
            thread::sleep(Duration::from_millis(80));
        });
        let WebSocketConnectResult::Observation(observation) =
            connect_websocket(&silent_plan, &options(&silent_plan), &store).unwrap()
        else {
            panic!("silent peer must time out")
        };
        assert_eq!(observation.exit, 3);
        assert!(matches!(
            observation.terminal_cause,
            WebSocketTerminalCause::ConnectTimeout
        ));
        silent_server.join().unwrap();
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ipv6_loopback_handshake_uses_the_exact_runtime_grants() {
        let Ok(listener) = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)) else {
            return;
        };
        let plan = ws_plan(&listener);
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            tungstenite::accept(stream).unwrap()
        });
        let (root, store) = store();
        let WebSocketConnectResult::Connected(connection) =
            connect_websocket(&plan, &options(&plan), &store).unwrap()
        else {
            panic!("expected IPv6 WebSocket handshake")
        };
        assert_eq!(
            connection.metadata.resolved_origin.ip(),
            Ipv6Addr::LOCALHOST
        );
        drop(connection);
        server.join().unwrap();
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wss_uses_rustls_hostname_validation_and_controlled_roots() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let certificate_der = cert.der().clone();
        let certificate_pem = cert.pem().into_bytes();
        let key = PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der], key)
            .unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let connection = ServerConnection::new(Arc::new(server_config)).unwrap();
            let stream = StreamOwned::new(connection, stream);
            tungstenite::accept(stream).unwrap()
        });
        let tls_plan = plan(
            format!("wss://127.0.0.1:{}/secure", address.port()),
            "net-cidr:127.0.0.1/32".into(),
        );
        let (root, store) = store();
        let mut tls_options = options(&tls_plan);
        tls_options
            .additional_root_certificates
            .push(certificate_pem);
        let WebSocketConnectResult::Connected(connection) =
            connect_websocket(&tls_plan, &tls_options, &store).unwrap()
        else {
            panic!("expected controlled Rustls WebSocket handshake")
        };
        assert_eq!(connection.metadata.status, StatusCode::SWITCHING_PROTOCOLS);
        drop(connection);
        server.join().unwrap();

        let mismatch_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mismatch_address = mismatch_listener.local_addr().unwrap();
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["wrong.example.test".into()]).unwrap();
        let certificate_der = cert.der().clone();
        let certificate_pem = cert.pem().into_bytes();
        let key = PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der], key)
            .unwrap();
        let mismatch_server = thread::spawn(move || {
            let (stream, _) = mismatch_listener.accept().unwrap();
            let connection = ServerConnection::new(Arc::new(server_config)).unwrap();
            let stream = StreamOwned::new(connection, stream);
            assert!(tungstenite::accept(stream).is_err());
        });
        let mismatch_plan = plan(
            format!("wss://127.0.0.1:{}/secure", mismatch_address.port()),
            "net-cidr:127.0.0.1/32".into(),
        );
        let mut mismatch_options = options(&mismatch_plan);
        mismatch_options
            .additional_root_certificates
            .push(certificate_pem);
        let WebSocketConnectResult::Observation(observation) =
            connect_websocket(&mismatch_plan, &mismatch_options, &store).unwrap()
        else {
            panic!("hostname mismatch must produce an error observation")
        };
        assert_eq!(observation.exit, 3);
        assert!(matches!(
            observation.terminal_cause,
            WebSocketTerminalCause::TlsFailure
        ));
        mismatch_server.join().unwrap();
        drop(store);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn mutual_tls_identity_is_resolved_only_from_the_secret_profile() {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["client.example.test".into()]).unwrap();
        let mut plan = plan(
            "wss://127.0.0.1:443/secure".into(),
            "net-cidr:127.0.0.1/32".into(),
        );
        plan.auth = Some(PlannedAuth {
            scheme: "mtls".into(),
            kind: "mutualTLS".into(),
            profile: "client-identity".into(),
            placement: "tls-client-certificate".into(),
            token_url: None,
            scopes: Vec::new(),
        });
        plan.secret_refs = vec!["secret://client-identity".into()];
        plan.required_grants.extend([
            "secret:client-identity".into(),
            "tls-client-cert:client-identity".into(),
        ]);
        let plan = plan.seal().unwrap();
        let certificate_pem = cert.pem();
        let mut missing_options = options(&plan);
        missing_options
            .additional_root_certificates
            .push(certificate_pem.as_bytes().to_vec());
        assert!(matches!(
            build_tls_config(&plan, &missing_options),
            Err(ExecError::MissingSecret(profile)) if profile == "client-identity"
        ));

        let mut options = missing_options;
        options.secrets.insert(
            "client-identity".into(),
            format!("{}{}", certificate_pem, signing_key.serialize_pem()),
        );
        assert!(build_tls_config(&plan, &options).is_ok());
    }
}
