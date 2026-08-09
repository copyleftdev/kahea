//! Deterministic loopback WebSocket oracle and protocol fault injector.

use crate::ServerError;
use base64::Engine;
use clap::ValueEnum;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use rustls_pki_types::PrivatePkcs8KeyDer;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tungstenite::http::{HeaderValue, StatusCode};
use tungstenite::protocol::frame::CloseFrame;
use tungstenite::protocol::frame::Frame;
use tungstenite::protocol::frame::coding::{CloseCode, Data, OpCode};
use tungstenite::{Message, WebSocket};

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const SILENT_FAULT_DURATION: Duration = Duration::from_millis(750);
const MAX_UPGRADE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum WebSocketFaultMode {
    #[default]
    None,
    BadAcceptKey,
    BadStatus,
    MissingUpgradeHeader,
    Redirect,
    NegotiatedExtension,
    InvalidUtf8,
    MaskedServerFrame,
    ReservedOpcode,
    ReservedBit,
    FragmentedControlFrame,
    InvalidClosePayload,
    InvalidCloseCode,
    TruncatedFrame,
    OversizedFrame,
    UnexpectedText,
    AbruptClose,
    SilentHandshake,
    SilentFrame,
    SilentClose,
}

impl WebSocketFaultMode {
    pub const ALL: [Self; 20] = [
        Self::None,
        Self::BadAcceptKey,
        Self::BadStatus,
        Self::MissingUpgradeHeader,
        Self::Redirect,
        Self::NegotiatedExtension,
        Self::InvalidUtf8,
        Self::MaskedServerFrame,
        Self::ReservedOpcode,
        Self::ReservedBit,
        Self::FragmentedControlFrame,
        Self::InvalidClosePayload,
        Self::InvalidCloseCode,
        Self::TruncatedFrame,
        Self::OversizedFrame,
        Self::UnexpectedText,
        Self::AbruptClose,
        Self::SilentHandshake,
        Self::SilentFrame,
        Self::SilentClose,
    ];

    pub fn slug(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::BadAcceptKey => "bad-accept-key",
            Self::BadStatus => "bad-status",
            Self::MissingUpgradeHeader => "missing-upgrade-header",
            Self::Redirect => "redirect",
            Self::NegotiatedExtension => "negotiated-extension",
            Self::InvalidUtf8 => "invalid-utf8",
            Self::MaskedServerFrame => "masked-server-frame",
            Self::ReservedOpcode => "reserved-opcode",
            Self::ReservedBit => "reserved-bit",
            Self::FragmentedControlFrame => "fragmented-control-frame",
            Self::InvalidClosePayload => "invalid-close-payload",
            Self::InvalidCloseCode => "invalid-close-code",
            Self::TruncatedFrame => "truncated-frame",
            Self::OversizedFrame => "oversized-frame",
            Self::UnexpectedText => "unexpected-text",
            Self::AbruptClose => "abrupt-close",
            Self::SilentHandshake => "silent-handshake",
            Self::SilentFrame => "silent-frame",
            Self::SilentClose => "silent-close",
        }
    }

    fn is_handshake_fault(self) -> bool {
        matches!(
            self,
            Self::BadAcceptKey
                | Self::BadStatus
                | Self::MissingUpgradeHeader
                | Self::Redirect
                | Self::SilentHandshake
        )
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum WebSocketOracleTransport {
    #[default]
    Plaintext,
    Tls,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum WebSocketOracleStep {
    ExpectText { value: String },
    ExpectBinary { value: Vec<u8> },
    EchoText,
    EchoBinary,
    SendText { value: String },
    SendBinary { value: Vec<u8> },
    SendPing { value: Vec<u8> },
    ExpectPong { value: Vec<u8> },
    SendFragmentedText { fragments: Vec<String> },
    ExpectClose { code: u16, reason: String },
    SendClose { code: u16, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebSocketOracleScenario {
    pub seed: u64,
    pub path: String,
    pub expected_origin: Option<String>,
    pub subprotocol: Option<String>,
    pub handshake_delay_ms: u64,
    pub frame_delay_ms: u64,
    pub close_delay_ms: u64,
    pub oversized_payload_bytes: usize,
    pub steps: Vec<WebSocketOracleStep>,
}

pub fn generate_websocket_scenario(seed: u64) -> WebSocketOracleScenario {
    let client_binary = seed.to_be_bytes().to_vec();
    let mut server_binary = client_binary.clone();
    server_binary.reverse();
    WebSocketOracleScenario {
        seed,
        path: format!("/websocket/{seed:016x}"),
        expected_origin: Some("https://oracle.kahea.test".into()),
        subprotocol: Some(format!("kahea.oracle.{:04x}", seed & 0xffff)),
        handshake_delay_ms: 0,
        frame_delay_ms: 0,
        close_delay_ms: 0,
        oversized_payload_bytes: 1024 * 1024 + 1,
        steps: vec![
            WebSocketOracleStep::ExpectText {
                value: format!("client-{seed:016x}"),
            },
            WebSocketOracleStep::SendText {
                value: format!("server-{seed:016x}"),
            },
            WebSocketOracleStep::ExpectBinary {
                value: client_binary,
            },
            WebSocketOracleStep::SendBinary {
                value: server_binary,
            },
            WebSocketOracleStep::SendPing {
                value: b"oracle-ping".to_vec(),
            },
            WebSocketOracleStep::ExpectPong {
                value: b"oracle-ping".to_vec(),
            },
            WebSocketOracleStep::SendFragmentedText {
                fragments: vec!["seeded-".into(), format!("{seed:016x}")],
            },
            WebSocketOracleStep::SendClose {
                code: 1000,
                reason: "oracle-complete".into(),
            },
        ],
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebSocketOracleManifest {
    pub kind: String,
    pub seed: u64,
    pub case_id: String,
    pub url: String,
    pub fault: WebSocketFaultMode,
    pub transport: WebSocketOracleTransport,
    pub root_certificate_pem: Option<String>,
    pub expected_origin: Option<String>,
    pub subprotocol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebSocketOracleObservation {
    pub kind: String,
    pub seed: u64,
    pub case_id: String,
    pub fault: WebSocketFaultMode,
    pub connections: u64,
    pub handshake_completed: bool,
    pub completed_steps: usize,
    pub outcome: String,
    pub failure: Option<String>,
}

impl WebSocketOracleObservation {
    fn new(seed: u64, case_id: String, fault: WebSocketFaultMode) -> Self {
        Self {
            kind: "kahea-websocket-oracle-observation".into(),
            seed,
            case_id,
            fault,
            connections: 0,
            handshake_completed: false,
            completed_steps: 0,
            outcome: "ready".into(),
            failure: None,
        }
    }
}

#[derive(Debug)]
pub struct RunningWebSocketOracle {
    pub manifest: WebSocketOracleManifest,
    observation: Arc<Mutex<WebSocketOracleObservation>>,
    shutdown: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<Result<(), ServerError>>>,
}

impl RunningWebSocketOracle {
    pub fn observation(&self) -> WebSocketOracleObservation {
        self.observation
            .lock()
            .expect("oracle observation lock")
            .clone()
    }

    pub fn stop(mut self) -> Result<WebSocketOracleObservation, ServerError> {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| {
                ServerError::InvalidRequest("WebSocket oracle worker panicked".into())
            })??;
        }
        Ok(self.observation())
    }

    pub fn wait(mut self) -> Result<WebSocketOracleObservation, ServerError> {
        let worker = self.worker.take().ok_or_else(|| {
            ServerError::InvalidRequest("WebSocket oracle worker is unavailable".into())
        })?;
        worker.join().map_err(|_| {
            ServerError::InvalidRequest("WebSocket oracle worker panicked".into())
        })??;
        Ok(self.observation())
    }
}

impl Drop for RunningWebSocketOracle {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub fn start_websocket_oracle(
    scenario: WebSocketOracleScenario,
    fault: WebSocketFaultMode,
    transport: WebSocketOracleTransport,
) -> Result<RunningWebSocketOracle, ServerError> {
    start_websocket_oracle_on(
        scenario,
        fault,
        transport,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
    )
}

pub fn start_websocket_oracle_on(
    scenario: WebSocketOracleScenario,
    fault: WebSocketFaultMode,
    transport: WebSocketOracleTransport,
    interface: IpAddr,
    port: u16,
) -> Result<RunningWebSocketOracle, ServerError> {
    if !interface.is_loopback() {
        return Err(ServerError::InvalidRequest(
            "WebSocket oracle may bind only a loopback interface".into(),
        ));
    }
    let listener = TcpListener::bind(SocketAddr::new(interface, port))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let (tls_config, root_certificate_pem) = match transport {
        WebSocketOracleTransport::Plaintext => (None, None),
        WebSocketOracleTransport::Tls => {
            let CertifiedKey { cert, signing_key } =
                generate_simple_self_signed(vec![interface.to_string()])
                    .map_err(|error| ServerError::InvalidRequest(error.to_string()))?;
            let key = PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into();
            let config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert.der().clone()], key)
                .map_err(|error| ServerError::InvalidRequest(error.to_string()))?;
            (Some(Arc::new(config)), Some(cert.pem()))
        }
    };
    let host = match address.ip() {
        IpAddr::V4(address) => address.to_string(),
        IpAddr::V6(address) => format!("[{address}]"),
    };
    let scheme = match transport {
        WebSocketOracleTransport::Plaintext => "ws",
        WebSocketOracleTransport::Tls => "wss",
    };
    let case_id = format!("ws-{:016x}-{}", scenario.seed, fault.slug());
    let manifest = WebSocketOracleManifest {
        kind: "kahea-websocket-oracle".into(),
        seed: scenario.seed,
        case_id: case_id.clone(),
        url: format!("{scheme}://{host}:{}{}", address.port(), scenario.path),
        fault,
        transport,
        root_certificate_pem,
        expected_origin: scenario.expected_origin.clone(),
        subprotocol: scenario.subprotocol.clone(),
    };
    let observation = Arc::new(Mutex::new(WebSocketOracleObservation::new(
        scenario.seed,
        case_id,
        fault,
    )));
    let shutdown = Arc::new(AtomicBool::new(false));
    let worker_observation = Arc::clone(&observation);
    let worker_shutdown = Arc::clone(&shutdown);
    let worker = thread::spawn(move || {
        serve_websocket_oracle(
            listener,
            scenario,
            fault,
            tls_config,
            worker_observation,
            worker_shutdown,
        )
    });
    Ok(RunningWebSocketOracle {
        manifest,
        observation,
        shutdown,
        worker: Some(worker),
    })
}

fn serve_websocket_oracle(
    listener: TcpListener,
    scenario: WebSocketOracleScenario,
    fault: WebSocketFaultMode,
    tls_config: Option<Arc<ServerConfig>>,
    observation: Arc<Mutex<WebSocketOracleObservation>>,
    shutdown: Arc<AtomicBool>,
) -> Result<(), ServerError> {
    let stream = accept_connection(&listener, &shutdown)?;
    let Some(stream) = stream else {
        return Ok(());
    };
    {
        let mut observation = observation.lock().expect("oracle observation lock");
        observation.connections = 1;
        observation.outcome = "running".into();
    }
    let result = if let Some(config) = tls_config {
        let connection = ServerConnection::new(config)
            .map_err(|error| ServerError::InvalidRequest(error.to_string()))?;
        let stream = StreamOwned::new(connection, stream);
        serve_stream(stream, &scenario, fault, &observation, &shutdown)
    } else {
        serve_stream(stream, &scenario, fault, &observation, &shutdown)
    };
    let mut state = observation.lock().expect("oracle observation lock");
    match result {
        Ok(()) => state.outcome = "completed".into(),
        Err(error) => {
            state.outcome = "failed".into();
            state.failure = Some(error.to_string());
        }
    }
    Ok(())
}

fn accept_connection(
    listener: &TcpListener,
    shutdown: &AtomicBool,
) -> Result<Option<TcpStream>, ServerError> {
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                stream.set_read_timeout(Some(IO_TIMEOUT))?;
                stream.set_write_timeout(Some(IO_TIMEOUT))?;
                return Ok(Some(stream));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(ServerError::Io(error)),
        }
    }
    Ok(None)
}

// Tungstenite's mandatory server callback returns its large HTTP ErrorResponse by value.
#[allow(clippy::result_large_err)]
fn serve_stream<S: Read + Write>(
    mut stream: S,
    scenario: &WebSocketOracleScenario,
    fault: WebSocketFaultMode,
    observation: &Arc<Mutex<WebSocketOracleObservation>>,
    shutdown: &AtomicBool,
) -> Result<(), ServerError> {
    wait_or_shutdown(Duration::from_millis(scenario.handshake_delay_ms), shutdown);
    if fault.is_handshake_fault() {
        return inject_handshake_fault(&mut stream, fault, scenario, shutdown);
    }
    let expected_path = scenario.path.clone();
    let expected_origin = scenario.expected_origin.clone();
    let selected_subprotocol = scenario.subprotocol.clone();
    let mut socket =
        tungstenite::accept_hdr(stream, move |request: &Request, mut response: Response| {
            validate_upgrade_request(request, &expected_path, expected_origin.as_deref())?;
            if let Some(protocol) = selected_subprotocol.as_deref() {
                let offered = request
                    .headers()
                    .get("sec-websocket-protocol")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|offered| {
                        offered.split(',').any(|value| value.trim() == protocol)
                    });
                if !offered {
                    return Err(error_response(
                        StatusCode::BAD_REQUEST,
                        "required subprotocol was not offered",
                    ));
                }
                response.headers_mut().insert(
                    "sec-websocket-protocol",
                    HeaderValue::from_str(protocol).map_err(|_| {
                        error_response(StatusCode::INTERNAL_SERVER_ERROR, "invalid subprotocol")
                    })?,
                );
            }
            if fault == WebSocketFaultMode::NegotiatedExtension {
                response.headers_mut().insert(
                    "sec-websocket-extensions",
                    HeaderValue::from_static("permessage-deflate"),
                );
            }
            Ok(response)
        })
        .map_err(|error| {
            ServerError::InvalidRequest(format!("WebSocket upgrade failed: {error}"))
        })?;
    observation
        .lock()
        .expect("oracle observation lock")
        .handshake_completed = true;

    if fault != WebSocketFaultMode::None {
        return inject_post_upgrade_fault(&mut socket, fault, scenario, shutdown);
    }
    execute_script(&mut socket, scenario, observation, shutdown)
}

#[allow(clippy::result_large_err)]
fn validate_upgrade_request(
    request: &Request,
    expected_path: &str,
    expected_origin: Option<&str>,
) -> Result<(), ErrorResponse> {
    if request.uri().path() != expected_path {
        return Err(error_response(StatusCode::NOT_FOUND, "unexpected path"));
    }
    if let Some(expected_origin) = expected_origin {
        let matches = request
            .headers()
            .get("origin")
            .and_then(|value| value.to_str().ok())
            == Some(expected_origin);
        if !matches {
            return Err(error_response(StatusCode::FORBIDDEN, "origin rejected"));
        }
    }
    Ok(())
}

fn error_response(status: StatusCode, message: &str) -> ErrorResponse {
    tungstenite::http::Response::builder()
        .status(status)
        .body(Some(message.into()))
        .expect("static oracle response is valid")
}

fn inject_handshake_fault<S: Read + Write>(
    stream: &mut S,
    fault: WebSocketFaultMode,
    scenario: &WebSocketOracleScenario,
    shutdown: &AtomicBool,
) -> Result<(), ServerError> {
    if fault == WebSocketFaultMode::SilentHandshake {
        wait_or_shutdown(SILENT_FAULT_DURATION, shutdown);
        return Ok(());
    }
    let request = read_upgrade_request(stream)?;
    if request.path != scenario.path {
        return Err(ServerError::InvalidRequest(
            "unexpected WebSocket path".into(),
        ));
    }
    let key = request
        .headers
        .get("sec-websocket-key")
        .ok_or_else(|| ServerError::InvalidRequest("Sec-WebSocket-Key is missing".into()))?;
    let accept = websocket_accept(key);
    match fault {
        WebSocketFaultMode::BadAcceptKey => write!(
            stream,
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: invalid\r\n\r\n"
        )?,
        WebSocketFaultMode::BadStatus => write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )?,
        WebSocketFaultMode::MissingUpgradeHeader => write!(
            stream,
            "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        )?,
        WebSocketFaultMode::Redirect => write!(
            stream,
            "HTTP/1.1 302 Found\r\nLocation: ws://127.0.0.1:9/redirected\r\nContent-Length: 0\r\n\r\n"
        )?,
        _ => unreachable!("only handshake faults are routed here"),
    }
    stream.flush()?;
    Ok(())
}

fn inject_post_upgrade_fault<S: Read + Write>(
    socket: &mut WebSocket<S>,
    fault: WebSocketFaultMode,
    scenario: &WebSocketOracleScenario,
    shutdown: &AtomicBool,
) -> Result<(), ServerError> {
    match fault {
        WebSocketFaultMode::NegotiatedExtension => {}
        WebSocketFaultMode::InvalidUtf8 => write_wire(socket, &[0x81, 0x01, 0xff])?,
        WebSocketFaultMode::MaskedServerFrame => {
            write_wire(socket, &[0x81, 0x81, 1, 2, 3, 4, b'x' ^ 1])?
        }
        WebSocketFaultMode::ReservedOpcode => write_wire(socket, &[0x83, 0x00])?,
        WebSocketFaultMode::ReservedBit => write_wire(socket, &[0xc1, 0x00])?,
        WebSocketFaultMode::FragmentedControlFrame => write_wire(socket, &[0x09, 0x00])?,
        WebSocketFaultMode::InvalidClosePayload => write_wire(socket, &[0x88, 0x01, 0x00])?,
        // 1005 is a reserved sentinel and is forbidden on the wire.
        WebSocketFaultMode::InvalidCloseCode => write_wire(socket, &[0x88, 0x02, 0x03, 0xed])?,
        WebSocketFaultMode::TruncatedFrame => write_wire(socket, &[0x81, 0x05, b'a', b'b'])?,
        WebSocketFaultMode::OversizedFrame => {
            let length = scenario.oversized_payload_bytes as u64;
            let mut wire = vec![0x82, 127];
            wire.extend_from_slice(&length.to_be_bytes());
            wire.resize(wire.len() + scenario.oversized_payload_bytes, 0x5a);
            write_wire(socket, &wire)?;
        }
        WebSocketFaultMode::UnexpectedText => socket
            .send(Message::Text("oracle-unexpected".into()))
            .map_err(|error| ServerError::InvalidRequest(error.to_string()))?,
        WebSocketFaultMode::AbruptClose => {}
        WebSocketFaultMode::SilentFrame => wait_or_shutdown(SILENT_FAULT_DURATION, shutdown),
        WebSocketFaultMode::SilentClose => {
            consume_client_close(socket.get_mut())?;
            wait_or_shutdown(SILENT_FAULT_DURATION, shutdown);
        }
        _ => unreachable!("handshake and no-fault modes are routed elsewhere"),
    }
    Ok(())
}

fn execute_script<S: Read + Write>(
    socket: &mut WebSocket<S>,
    scenario: &WebSocketOracleScenario,
    observation: &Arc<Mutex<WebSocketOracleObservation>>,
    shutdown: &AtomicBool,
) -> Result<(), ServerError> {
    for step in &scenario.steps {
        let delay = if matches!(
            step,
            WebSocketOracleStep::ExpectClose { .. } | WebSocketOracleStep::SendClose { .. }
        ) {
            scenario.close_delay_ms
        } else {
            scenario.frame_delay_ms
        };
        wait_or_shutdown(Duration::from_millis(delay), shutdown);
        match step {
            WebSocketOracleStep::ExpectText { value } => {
                expect_message(socket, Message::Text(value.clone().into()))?
            }
            WebSocketOracleStep::ExpectBinary { value } => {
                expect_message(socket, Message::Binary(value.clone().into()))?
            }
            WebSocketOracleStep::EchoText => {
                let message = socket
                    .read()
                    .map_err(|error| ServerError::InvalidRequest(error.to_string()))?;
                if !message.is_text() {
                    return Err(ServerError::InvalidRequest("expected text to echo".into()));
                }
                socket
                    .send(message)
                    .map_err(|error| ServerError::InvalidRequest(error.to_string()))?;
            }
            WebSocketOracleStep::EchoBinary => {
                let message = socket
                    .read()
                    .map_err(|error| ServerError::InvalidRequest(error.to_string()))?;
                if !message.is_binary() {
                    return Err(ServerError::InvalidRequest(
                        "expected binary to echo".into(),
                    ));
                }
                socket
                    .send(message)
                    .map_err(|error| ServerError::InvalidRequest(error.to_string()))?;
            }
            WebSocketOracleStep::SendText { value } => socket
                .send(Message::Text(value.clone().into()))
                .map_err(|error| ServerError::InvalidRequest(error.to_string()))?,
            WebSocketOracleStep::SendBinary { value } => socket
                .send(Message::Binary(value.clone().into()))
                .map_err(|error| ServerError::InvalidRequest(error.to_string()))?,
            WebSocketOracleStep::SendPing { value } => socket
                .send(Message::Ping(value.clone().into()))
                .map_err(|error| ServerError::InvalidRequest(error.to_string()))?,
            WebSocketOracleStep::ExpectPong { value } => {
                expect_message(socket, Message::Pong(value.clone().into()))?
            }
            WebSocketOracleStep::SendFragmentedText { fragments } => {
                if fragments.is_empty() {
                    return Err(ServerError::InvalidRequest(
                        "fragmented text requires at least one fragment".into(),
                    ));
                }
                for (index, fragment) in fragments.iter().enumerate() {
                    let opcode = if index == 0 {
                        OpCode::Data(Data::Text)
                    } else {
                        OpCode::Data(Data::Continue)
                    };
                    let frame = Frame::message(
                        fragment.as_bytes().to_vec(),
                        opcode,
                        index + 1 == fragments.len(),
                    );
                    socket
                        .write(Message::Frame(frame))
                        .map_err(|error| ServerError::InvalidRequest(error.to_string()))?;
                }
                socket
                    .flush()
                    .map_err(|error| ServerError::InvalidRequest(error.to_string()))?;
            }
            WebSocketOracleStep::ExpectClose { code, reason } => {
                let message = socket
                    .read()
                    .map_err(|error| ServerError::InvalidRequest(error.to_string()))?;
                let Message::Close(Some(close)) = message else {
                    return Err(ServerError::InvalidRequest("expected close frame".into()));
                };
                if u16::from(close.code) != *code || close.reason != reason.as_str() {
                    return Err(ServerError::InvalidRequest(
                        "close frame did not match".into(),
                    ));
                }
                let _ = socket.flush();
            }
            WebSocketOracleStep::SendClose { code, reason } => {
                socket
                    .send(Message::Close(Some(CloseFrame {
                        code: CloseCode::from(*code),
                        reason: reason.clone().into(),
                    })))
                    .map_err(|error| ServerError::InvalidRequest(error.to_string()))?;
                let _ = socket.flush();
            }
        }
        observation
            .lock()
            .expect("oracle observation lock")
            .completed_steps += 1;
    }
    Ok(())
}

fn expect_message<S: Read + Write>(
    socket: &mut WebSocket<S>,
    expected: Message,
) -> Result<(), ServerError> {
    let actual = socket
        .read()
        .map_err(|error| ServerError::InvalidRequest(error.to_string()))?;
    if actual != expected {
        return Err(ServerError::InvalidRequest(format!(
            "expected {expected:?}, received {actual:?}"
        )));
    }
    Ok(())
}

fn write_wire<S: Read + Write>(socket: &mut WebSocket<S>, bytes: &[u8]) -> Result<(), ServerError> {
    socket.get_mut().write_all(bytes)?;
    socket.get_mut().flush()?;
    Ok(())
}

fn consume_client_close<S: Read>(stream: &mut S) -> Result<(), ServerError> {
    let mut header = [0_u8; 2];
    stream.read_exact(&mut header)?;
    if header[0] & 0x0f != 0x08 || header[1] & 0x80 == 0 {
        return Err(ServerError::InvalidRequest(
            "silent-close fault expected a masked client close frame".into(),
        ));
    }
    let mut length = usize::from(header[1] & 0x7f);
    if length == 126 {
        let mut extended = [0_u8; 2];
        stream.read_exact(&mut extended)?;
        length = usize::from(u16::from_be_bytes(extended));
    } else if length == 127 {
        let mut extended = [0_u8; 8];
        stream.read_exact(&mut extended)?;
        length = usize::try_from(u64::from_be_bytes(extended)).map_err(|_| {
            ServerError::InvalidRequest("client close payload length overflows usize".into())
        })?;
    }
    if length > 125 {
        return Err(ServerError::InvalidRequest(
            "client close payload exceeds the control-frame limit".into(),
        ));
    }
    let mut mask = [0_u8; 4];
    stream.read_exact(&mut mask)?;
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload)?;
    Ok(())
}

#[derive(Debug)]
struct UpgradeRequest {
    path: String,
    headers: std::collections::BTreeMap<String, String>,
}

fn read_upgrade_request<S: Read>(stream: &mut S) -> Result<UpgradeRequest, ServerError> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 2048];
    while !bytes.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(ServerError::InvalidRequest(
                "connection closed before WebSocket upgrade".into(),
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > MAX_UPGRADE_BYTES {
            return Err(ServerError::InvalidRequest(
                "WebSocket upgrade exceeds 64 KiB".into(),
            ));
        }
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| ServerError::InvalidRequest("upgrade is not UTF-8".into()))?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| ServerError::InvalidRequest("request line is missing".into()))?;
    let path = request_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| ServerError::InvalidRequest("request target is missing".into()))?
        .into();
    let headers = lines
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| ServerError::InvalidRequest("upgrade header is malformed".into()))?;
            Ok((name.trim().to_ascii_lowercase(), value.trim().into()))
        })
        .collect::<Result<_, ServerError>>()?;
    Ok(UpgradeRequest { path, headers })
}

fn websocket_accept(key: &str) -> String {
    let mut digest = Sha1::new();
    digest.update(key.as_bytes());
    digest.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(digest.finalize())
}

fn wait_or_shutdown(duration: Duration, shutdown: &AtomicBool) {
    let deadline = Instant::now()
        .checked_add(duration)
        .unwrap_or_else(Instant::now);
    while !shutdown.load(Ordering::SeqCst) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_scenarios_and_case_ids_are_reproducible() {
        let first = generate_websocket_scenario(42);
        let second = generate_websocket_scenario(42);
        let different = generate_websocket_scenario(43);
        assert_eq!(first, second);
        assert_ne!(first, different);
        assert_eq!(WebSocketFaultMode::ALL.len(), 20);

        let server = start_websocket_oracle(
            first,
            WebSocketFaultMode::None,
            WebSocketOracleTransport::Plaintext,
        )
        .unwrap();
        assert_eq!(server.manifest.case_id, "ws-000000000000002a-none");
        assert!(server.manifest.url.starts_with("ws://127.0.0.1:"));
        assert_eq!(server.observation().outcome, "ready");
        let observation = server.stop().unwrap();
        assert_eq!(observation.connections, 0);
    }

    #[test]
    fn non_loopback_binding_is_rejected() {
        let error = start_websocket_oracle_on(
            generate_websocket_scenario(1),
            WebSocketFaultMode::None,
            WebSocketOracleTransport::Plaintext,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            0,
        )
        .unwrap_err();
        assert!(error.to_string().contains("only a loopback interface"));
    }

    #[test]
    fn scripted_text_and_binary_echo_are_ordered() {
        let mut scenario = generate_websocket_scenario(7);
        scenario.expected_origin = None;
        scenario.subprotocol = None;
        scenario.steps = vec![
            WebSocketOracleStep::EchoText,
            WebSocketOracleStep::EchoBinary,
            WebSocketOracleStep::ExpectClose {
                code: 1000,
                reason: "echo-complete".into(),
            },
        ];
        let oracle = start_websocket_oracle(
            scenario,
            WebSocketFaultMode::None,
            WebSocketOracleTransport::Plaintext,
        )
        .unwrap();
        let url = url::Url::parse(&oracle.manifest.url).unwrap();
        let address = SocketAddr::new(
            url.host_str().unwrap().parse().unwrap(),
            url.port().unwrap(),
        );
        let stream = TcpStream::connect(address).unwrap();
        let (mut socket, _) = tungstenite::client(oracle.manifest.url.as_str(), stream).unwrap();
        socket.send(Message::Text("echo-text".into())).unwrap();
        assert_eq!(socket.read().unwrap(), Message::Text("echo-text".into()));
        socket
            .send(Message::Binary(vec![0, 1, 2, 3].into()))
            .unwrap();
        assert_eq!(
            socket.read().unwrap(),
            Message::Binary(vec![0, 1, 2, 3].into())
        );
        socket
            .send(Message::Close(Some(CloseFrame {
                code: CloseCode::Normal,
                reason: "echo-complete".into(),
            })))
            .unwrap();
        assert_eq!(oracle.wait().unwrap().completed_steps, 3);
    }
}
