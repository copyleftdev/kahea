use super::{
    ExecError, InvokeOptions, redact_bytes, redact_json_pointers, secret_redactions,
    unsafe_address, validate_schema_value,
};
use base64::Engine;
use kahea_core::{
    DenialEnvelope, Outcome, PROTOCOL, VERSION, WebSocketAction, WebSocketCloseInitiator,
    WebSocketCloseObservation, WebSocketCounters, WebSocketLimits, WebSocketObservation,
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tungstenite::client::IntoClientRequest;
use tungstenite::handshake::client::Response;
use tungstenite::http::header::{HeaderName, HeaderValue};
use tungstenite::http::{HeaderMap, Request};
use tungstenite::protocol::frame::CloseFrame;
use tungstenite::protocol::frame::coding::CloseCode;
use tungstenite::protocol::{Role, WebSocketConfig};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Error as WebSocketError, Message, WebSocket};
use url::Url;

type Transport = MaybeTlsStream<DeadlineTcpStream>;
type Socket = WebSocket<AccountedStream<Transport>>;

#[derive(Debug, Default)]
struct WireAccounting {
    counters: WebSocketCounters,
    inbound_reserved_bytes: u64,
    outbound_reserved_bytes: u64,
    failure: Option<WebSocketTerminalCause>,
}

#[derive(Clone)]
struct WireParser {
    header: [u8; 14],
    header_len: usize,
    header_needed: usize,
    payload_remaining: u64,
    inbound: bool,
}

impl WireParser {
    fn new(inbound: bool) -> Self {
        Self {
            header: [0; 14],
            header_len: 0,
            header_needed: 2,
            payload_remaining: 0,
            inbound,
        }
    }

    fn observe(
        &mut self,
        mut bytes: &[u8],
        limits: &WebSocketLimits,
        accounting: &mut WireAccounting,
    ) -> io::Result<()> {
        while !bytes.is_empty() {
            if self.payload_remaining != 0 {
                let consumed = usize::try_from(self.payload_remaining)
                    .unwrap_or(usize::MAX)
                    .min(bytes.len());
                if self.inbound {
                    accounting.counters.inbound_bytes = accounting
                        .counters
                        .inbound_bytes
                        .saturating_add(consumed as u64);
                } else {
                    accounting.counters.outbound_bytes = accounting
                        .counters
                        .outbound_bytes
                        .saturating_add(consumed as u64);
                }
                self.payload_remaining -= consumed as u64;
                bytes = &bytes[consumed..];
                continue;
            }

            let copied = (self.header_needed - self.header_len).min(bytes.len());
            self.header[self.header_len..self.header_len + copied]
                .copy_from_slice(&bytes[..copied]);
            self.header_len += copied;
            bytes = &bytes[copied..];
            if self.header_len == 2 {
                let extended = match self.header[1] & 0x7f {
                    126 => 2,
                    127 => 8,
                    _ => 0,
                };
                let masked = self.header[1] & 0x80 != 0;
                self.header_needed = 2 + extended + usize::from(masked) * 4;
            }
            if self.header_len != self.header_needed {
                continue;
            }

            let short = self.header[1] & 0x7f;
            let payload = match short {
                126 => u16::from_be_bytes([self.header[2], self.header[3]]) as u64,
                127 => {
                    if self.header[2] & 0x80 != 0 {
                        accounting.failure = Some(WebSocketTerminalCause::ProtocolViolation);
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid WebSocket frame length",
                        ));
                    }
                    u64::from_be_bytes(self.header[2..10].try_into().expect("fixed header"))
                }
                value => value as u64,
            };
            let (frames, reserved, max_frames, max_bytes) = if self.inbound {
                (
                    &mut accounting.counters.inbound_frames,
                    &mut accounting.inbound_reserved_bytes,
                    limits.max_inbound_frames,
                    limits.max_inbound_bytes,
                )
            } else {
                (
                    &mut accounting.counters.outbound_frames,
                    &mut accounting.outbound_reserved_bytes,
                    limits.max_outbound_frames,
                    limits.max_outbound_bytes,
                )
            };
            if *frames >= max_frames
                || payload > limits.max_frame_bytes
                || reserved.saturating_add(payload) > max_bytes
            {
                accounting.failure = Some(WebSocketTerminalCause::BudgetExhausted);
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "WebSocket wire budget exhausted",
                ));
            }
            *frames += 1;
            *reserved += payload;
            self.payload_remaining = payload;
            self.header_len = 0;
            self.header_needed = 2;
        }
        Ok(())
    }
}

struct AccountedStream<S> {
    inner: S,
    limits: WebSocketLimits,
    accounting: Arc<Mutex<WireAccounting>>,
    inbound: WireParser,
    outbound: WireParser,
}

impl<S> AccountedStream<S> {
    fn new(inner: S, limits: WebSocketLimits, accounting: Arc<Mutex<WireAccounting>>) -> Self {
        Self {
            inner,
            limits,
            accounting,
            inbound: WireParser::new(true),
            outbound: WireParser::new(false),
        }
    }

    fn observe_buffered_inbound(&mut self, bytes: &[u8]) -> io::Result<()> {
        let mut accounting = self
            .accounting
            .lock()
            .map_err(|_| io::Error::other("WebSocket accounting state failed"))?;
        self.inbound.observe(bytes, &self.limits, &mut accounting)
    }
}

impl<S: Read> Read for AccountedStream<S> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        if read != 0 {
            let mut accounting = self
                .accounting
                .lock()
                .map_err(|_| io::Error::other("WebSocket accounting state failed"))?;
            self.inbound
                .observe(&buffer[..read], &self.limits, &mut accounting)?;
        }
        Ok(read)
    }
}

impl<S: Write> Write for AccountedStream<S> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut accounting = self
            .accounting
            .lock()
            .map_err(|_| io::Error::other("WebSocket accounting state failed"))?;
        self.outbound
            .observe(buffer, &self.limits, &mut accounting)?;
        drop(accounting);
        self.inner.write_all(buffer)?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub struct WebSocketConnection {
    pub metadata: WebSocketHandshakeMetadata,
    socket: Socket,
    deadline: Arc<Mutex<DeadlineState>>,
    started: Instant,
    total_deadline: Instant,
    accounting: Arc<Mutex<WireAccounting>>,
    redactions: Vec<Vec<u8>>,
}

#[derive(Clone, Default)]
pub struct WebSocketCancellation {
    cancelled: Arc<AtomicBool>,
}

impl WebSocketCancellation {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
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
            DeadlineState::fixed(
                requested.min(self.total_deadline),
                WebSocketTerminalCause::ActionTimeout,
            );
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

#[derive(Debug, Clone, Copy)]
enum TranscriptPayloadKind {
    Text,
    Binary,
    Control,
}

#[derive(Debug)]
struct TranscriptEntry {
    direction: &'static str,
    kind: &'static str,
    bytes: u64,
    action_index: Option<usize>,
    check: &'static str,
    code: Option<u16>,
    payload_kind: Option<TranscriptPayloadKind>,
    payload: Option<Vec<u8>>,
}

#[derive(Debug, Default)]
struct Transcript {
    entries: Vec<TranscriptEntry>,
}

impl Transcript {
    fn push(&mut self, entry: TranscriptEntry) {
        self.entries.push(entry);
    }
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

/// Execute every sealed action in a WebSocket plan and persist exactly one terminal result.
pub fn execute_websocket(
    plan: &WebSocketPlan,
    options: &InvokeOptions,
    store: &EvidenceStore,
) -> Result<WebSocketConnectResult, ExecError> {
    match connect_websocket(plan, options, store)? {
        WebSocketConnectResult::Connected(connection) => {
            execute_connected_websocket(plan, *connection, store)
        }
        terminal => Ok(terminal),
    }
}

pub fn execute_websocket_with_cancellation(
    plan: &WebSocketPlan,
    options: &InvokeOptions,
    store: &EvidenceStore,
    cancellation: &WebSocketCancellation,
) -> Result<WebSocketConnectResult, ExecError> {
    match connect_websocket_resolving_cancellable(
        plan,
        options,
        store,
        &system_resolve,
        Some(Arc::clone(&cancellation.cancelled)),
    )? {
        WebSocketConnectResult::Connected(connection) => {
            execute_connected_websocket(plan, *connection, store)
        }
        terminal => Ok(terminal),
    }
}

fn connect_websocket_resolving(
    plan: &WebSocketPlan,
    options: &InvokeOptions,
    store: &EvidenceStore,
    resolver: &dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>>,
) -> Result<WebSocketConnectResult, ExecError> {
    connect_websocket_resolving_cancellable(plan, options, store, resolver, None)
}

fn connect_websocket_resolving_cancellable(
    plan: &WebSocketPlan,
    options: &InvokeOptions,
    store: &EvidenceStore,
    resolver: &dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>>,
    cancellation: Option<Arc<AtomicBool>>,
) -> Result<WebSocketConnectResult, ExecError> {
    if !plan.verify_seal()? || plan.validate().is_err() {
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
        .filter(|grant| !is_address_dependent_grant(grant))
        .find(|grant| !options.grants.contains(*grant))
    {
        return Ok(WebSocketConnectResult::Denied(denial(
            plan,
            "invocation is missing a required capability",
            missing,
        )));
    }

    let started = Instant::now();
    if cancellation
        .as_ref()
        .is_some_and(|cancelled| cancelled.load(Ordering::Acquire))
    {
        return failed_observation(
            plan,
            store,
            started,
            Outcome::Error,
            WebSocketTerminalCause::Cancelled,
            3,
            FailureDetails::default(),
        );
    }
    let total_deadline =
        bounded_total_deadline(started, plan.limits.total_timeout_ms, options.timeout);
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
                FailureDetails::default(),
            );
        }
    };
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
                FailureDetails {
                    trace: Some(trace.handle),
                    ..FailureDetails::default()
                },
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
                FailureDetails {
                    trace: Some(trace.handle),
                    ..FailureDetails::default()
                },
            );
        }
    };

    let deadline_handle = Arc::new(Mutex::new(DeadlineState::fixed(
        connect_deadline,
        WebSocketTerminalCause::ConnectTimeout,
    )));
    let stream = DeadlineTcpStream::new(stream, Arc::clone(&deadline_handle), cancellation);
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
                FailureDetails {
                    resolved: Some(selected_address),
                    trace: Some(trace.handle),
                    ..FailureDetails::default()
                },
            );
        }
    };
    let accounting = Arc::new(Mutex::new(WireAccounting::default()));
    let handshake = perform_upgrade(
        request,
        stream,
        config,
        target.scheme() == "wss",
        plan.limits.clone(),
        Arc::clone(&accounting),
    );
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
                FailureDetails {
                    status: failure.status,
                    subprotocol,
                    resolved: Some(selected_address),
                    handshake,
                    trace: Some(trace.handle),
                    http_version: version,
                    counters: failure.counters,
                },
            );
        }
    };

    let handshake = store_handshake(plan, store, &response, &redactions)?;
    let latency = started.elapsed();
    *deadline_handle
        .lock()
        .map_err(|_| ExecError::Transport("WebSocket deadline state failed".into()))? =
        DeadlineState::fixed(total_deadline, WebSocketTerminalCause::TotalTimeout);
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
            accounting,
            redactions,
        },
    )))
}

#[derive(Debug)]
struct SessionTerminal {
    outcome: Outcome,
    cause: WebSocketTerminalCause,
    exit: u8,
    close: Option<WebSocketCloseObservation>,
}

impl SessionTerminal {
    fn passed(close: Option<WebSocketCloseObservation>) -> Self {
        Self {
            outcome: Outcome::Passed,
            cause: WebSocketTerminalCause::Completed,
            exit: 0,
            close,
        }
    }

    fn failed(cause: WebSocketTerminalCause) -> Self {
        Self {
            outcome: Outcome::Failed,
            cause,
            exit: 1,
            close: None,
        }
    }

    fn error(cause: WebSocketTerminalCause) -> Self {
        Self {
            outcome: Outcome::Error,
            cause,
            exit: 3,
            close: None,
        }
    }
}

fn execute_connected_websocket(
    plan: &WebSocketPlan,
    mut connection: WebSocketConnection,
    store: &EvidenceStore,
) -> Result<WebSocketConnectResult, ExecError> {
    let mut counters = WebSocketCounters::default();
    let mut transcript = Transcript::default();
    let mut terminal = None;
    for (action_index, action) in plan.actions.iter().enumerate() {
        let action_deadline = action_deadline(&connection, plan, action);
        let expected_payload = match action {
            WebSocketAction::ExpectBinary { payload_base64, .. }
            | WebSocketAction::ExpectPong { payload_base64, .. } => {
                Some(decode_sealed_base64(payload_base64).map_err(|()| ExecError::InvalidSeal)?)
            }
            _ => None,
        };
        let result = match action {
            WebSocketAction::SendText { text } => send_recorded(
                &mut connection,
                plan,
                &mut counters,
                Message::Text(text.clone().into()),
                true,
                text.as_bytes(),
                action_deadline,
                &mut transcript,
                action_index,
                "text",
                TranscriptPayloadKind::Text,
            )
            .map(|()| None),
            WebSocketAction::SendBinary { payload_base64 } => {
                let payload =
                    decode_sealed_base64(payload_base64).map_err(|()| ExecError::InvalidSeal)?;
                send_recorded(
                    &mut connection,
                    plan,
                    &mut counters,
                    Message::Binary(payload.clone().into()),
                    true,
                    &payload,
                    action_deadline,
                    &mut transcript,
                    action_index,
                    "binary",
                    TranscriptPayloadKind::Binary,
                )
                .map(|()| None)
            }
            WebSocketAction::Ping { payload_base64 } => {
                let payload =
                    decode_sealed_base64(payload_base64).map_err(|()| ExecError::InvalidSeal)?;
                send_recorded(
                    &mut connection,
                    plan,
                    &mut counters,
                    Message::Ping(payload.clone().into()),
                    false,
                    &payload,
                    action_deadline,
                    &mut transcript,
                    action_index,
                    "ping",
                    TranscriptPayloadKind::Control,
                )
                .map(|()| None)
            }
            WebSocketAction::Close { code, reason } => execute_client_close(
                &mut connection,
                plan,
                &mut counters,
                *code,
                reason,
                &mut transcript,
                action_index,
            )
            .map(|()| {
                Some(WebSocketCloseObservation {
                    initiator: WebSocketCloseInitiator::Client,
                    code: *code,
                    reason: reason.clone(),
                })
            }),
            expectation => read_expectation(
                &mut connection,
                plan,
                &mut counters,
                expectation,
                expected_payload.as_deref(),
                action_deadline,
                &mut transcript,
                action_index,
            ),
        };
        match result {
            Ok(Some(close)) => {
                terminal = Some(SessionTerminal::passed(Some(close)));
                break;
            }
            Ok(None) => {}
            Err(result) => {
                terminal = Some(result);
                break;
            }
        }
    }
    let terminal = terminal.unwrap_or_else(|| SessionTerminal::passed(None));
    finish_session(plan, connection, store, counters, transcript, terminal)
}

#[allow(clippy::too_many_arguments)]
fn send_recorded(
    connection: &mut WebSocketConnection,
    plan: &WebSocketPlan,
    counters: &mut WebSocketCounters,
    message: Message,
    data_message: bool,
    payload: &[u8],
    phase_deadline: Instant,
    transcript: &mut Transcript,
    action_index: usize,
    kind: &'static str,
    payload_kind: TranscriptPayloadKind,
) -> Result<(), SessionTerminal> {
    send_message(
        connection,
        plan,
        counters,
        message,
        data_message,
        payload.len() as u64,
        phase_deadline,
    )?;
    transcript.push(TranscriptEntry {
        direction: "outbound",
        kind,
        bytes: payload.len() as u64,
        action_index: Some(action_index),
        check: "sent",
        code: None,
        payload_kind: Some(payload_kind),
        payload: Some(payload.to_vec()),
    });
    Ok(())
}

fn action_deadline(
    connection: &WebSocketConnection,
    plan: &WebSocketPlan,
    action: &WebSocketAction,
) -> Instant {
    let timeout = match action {
        WebSocketAction::ExpectText { timeout_ms, .. }
        | WebSocketAction::ExpectBinary { timeout_ms, .. }
        | WebSocketAction::ExpectJson { timeout_ms, .. }
        | WebSocketAction::ExpectPong { timeout_ms, .. }
        | WebSocketAction::ExpectClose { timeout_ms, .. } => {
            timeout_ms.unwrap_or(plan.limits.action_timeout_ms)
        }
        WebSocketAction::Close { .. } => plan.limits.close_timeout_ms,
        _ => plan.limits.action_timeout_ms,
    };
    deadline(Instant::now(), timeout).min(connection.total_deadline)
}

fn configure_session_deadline(
    connection: &WebSocketConnection,
    plan: &WebSocketPlan,
    phase_deadline: Instant,
    phase_cause: WebSocketTerminalCause,
) -> Result<WebSocketTerminalCause, ExecError> {
    let idle_deadline = deadline(Instant::now(), plan.limits.idle_timeout_ms);
    let (active_deadline, cause) = select_deadline(
        connection.total_deadline,
        phase_deadline,
        idle_deadline,
        phase_cause,
    );
    *connection
        .deadline
        .lock()
        .map_err(|_| ExecError::Transport("WebSocket deadline state failed".into()))? =
        DeadlineState {
            active_deadline,
            total_deadline: connection.total_deadline,
            phase_deadline,
            idle_timeout: Some(Duration::from_millis(plan.limits.idle_timeout_ms)),
            phase_cause,
            cause,
        };
    Ok(cause)
}

fn select_deadline(
    total_deadline: Instant,
    phase_deadline: Instant,
    idle_deadline: Instant,
    phase_cause: WebSocketTerminalCause,
) -> (Instant, WebSocketTerminalCause) {
    if total_deadline <= phase_deadline && total_deadline <= idle_deadline {
        (total_deadline, WebSocketTerminalCause::TotalTimeout)
    } else if phase_deadline <= idle_deadline {
        (phase_deadline, phase_cause)
    } else {
        (idle_deadline, WebSocketTerminalCause::IdleTimeout)
    }
}

fn send_message(
    connection: &mut WebSocketConnection,
    plan: &WebSocketPlan,
    counters: &mut WebSocketCounters,
    message: Message,
    data_message: bool,
    payload_bytes: u64,
    phase_deadline: Instant,
) -> Result<(), SessionTerminal> {
    if exceeds_outbound(plan, counters, data_message, payload_bytes) {
        return Err(SessionTerminal::failed(
            WebSocketTerminalCause::BudgetExhausted,
        ));
    }
    let phase_cause = if matches!(message, Message::Close(_)) {
        WebSocketTerminalCause::CloseTimeout
    } else {
        WebSocketTerminalCause::ActionTimeout
    };
    let timeout_cause = configure_session_deadline(connection, plan, phase_deadline, phase_cause)
        .map_err(|_| SessionTerminal::error(WebSocketTerminalCause::IoFailure))?;
    if let Err(error) = connection.socket.send(message) {
        return Err(socket_error(connection, error, timeout_cause));
    }
    sync_wire_counters(connection, counters)?;
    if data_message {
        counters.outbound_messages += 1;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn read_expectation(
    connection: &mut WebSocketConnection,
    plan: &WebSocketPlan,
    counters: &mut WebSocketCounters,
    action: &WebSocketAction,
    expected_payload: Option<&[u8]>,
    phase_deadline: Instant,
    transcript: &mut Transcript,
    action_index: usize,
) -> Result<Option<WebSocketCloseObservation>, SessionTerminal> {
    loop {
        let timeout_cause = configure_session_deadline(
            connection,
            plan,
            phase_deadline,
            WebSocketTerminalCause::ActionTimeout,
        )
        .map_err(|_| SessionTerminal::error(WebSocketTerminalCause::IoFailure))?;
        let message = match connection.socket.read() {
            Ok(message) => message,
            Err(error) => return Err(socket_error(connection, error, timeout_cause)),
        };
        sync_wire_counters(connection, counters)?;
        account_inbound(plan, counters, &message)?;
        match message {
            Message::Ping(payload) => {
                transcript.push(TranscriptEntry {
                    direction: "inbound",
                    kind: "ping",
                    bytes: payload.len() as u64,
                    action_index: Some(action_index),
                    check: "automatic",
                    code: None,
                    payload_kind: Some(TranscriptPayloadKind::Control),
                    payload: Some(payload.to_vec()),
                });
                account_automatic_control(plan, counters, payload.len() as u64)?;
                let timeout_cause = configure_session_deadline(
                    connection,
                    plan,
                    phase_deadline,
                    WebSocketTerminalCause::ActionTimeout,
                )
                .map_err(|_| SessionTerminal::error(WebSocketTerminalCause::IoFailure))?;
                if let Err(error) = connection.socket.flush() {
                    return Err(socket_error(connection, error, timeout_cause));
                }
                sync_wire_counters(connection, counters)?;
                transcript.push(TranscriptEntry {
                    direction: "outbound",
                    kind: "pong",
                    bytes: payload.len() as u64,
                    action_index: Some(action_index),
                    check: "automatic",
                    code: None,
                    payload_kind: Some(TranscriptPayloadKind::Control),
                    payload: Some(payload.to_vec()),
                });
            }
            Message::Pong(payload) => {
                let matched = matches!(action, WebSocketAction::ExpectPong { .. })
                    && expected_payload.is_some_and(|expected| payload.as_ref() == expected);
                transcript.push(TranscriptEntry {
                    direction: "inbound",
                    kind: "pong",
                    bytes: payload.len() as u64,
                    action_index: Some(action_index),
                    check: if matched { "matched" } else { "ignored" },
                    code: None,
                    payload_kind: Some(TranscriptPayloadKind::Control),
                    payload: Some(payload.to_vec()),
                });
                if matched {
                    return Ok(None);
                }
            }
            Message::Text(actual) => {
                let matched = expectation_matches_text(action, actual.as_str());
                transcript.push(TranscriptEntry {
                    direction: "inbound",
                    kind: "text",
                    bytes: actual.len() as u64,
                    action_index: Some(action_index),
                    check: if matched { "matched" } else { "mismatched" },
                    code: None,
                    payload_kind: Some(TranscriptPayloadKind::Text),
                    payload: Some(actual.as_bytes().to_vec()),
                });
                return if matched {
                    Ok(None)
                } else {
                    Err(SessionTerminal::failed(
                        WebSocketTerminalCause::ExpectationFailed,
                    ))
                };
            }
            Message::Binary(actual) => {
                let matched = matches!(action, WebSocketAction::ExpectBinary { .. })
                    && expected_payload.is_some_and(|expected| actual.as_ref() == expected);
                transcript.push(TranscriptEntry {
                    direction: "inbound",
                    kind: "binary",
                    bytes: actual.len() as u64,
                    action_index: Some(action_index),
                    check: if matched { "matched" } else { "mismatched" },
                    code: None,
                    payload_kind: Some(TranscriptPayloadKind::Binary),
                    payload: Some(actual.to_vec()),
                });
                return if matched {
                    Ok(None)
                } else {
                    Err(SessionTerminal::failed(
                        WebSocketTerminalCause::ExpectationFailed,
                    ))
                };
            }
            Message::Close(frame) => {
                let close = close_observation(WebSocketCloseInitiator::Server, frame.as_ref());
                let matched = if let WebSocketAction::ExpectClose { codes, reason, .. } = action {
                    close_matches(frame.as_ref(), codes, reason.as_deref())
                } else {
                    false
                };
                let reason = frame
                    .as_ref()
                    .map_or_else(Vec::new, |frame| frame.reason.as_bytes().to_vec());
                transcript.push(TranscriptEntry {
                    direction: "inbound",
                    kind: "close",
                    bytes: close_payload_bytes(frame.as_ref()),
                    action_index: Some(action_index),
                    check: if matched { "matched" } else { "mismatched" },
                    code: frame.as_ref().map(|frame| u16::from(frame.code)),
                    payload_kind: Some(TranscriptPayloadKind::Text),
                    payload: Some(reason.clone()),
                });
                account_automatic_control(plan, counters, close_payload_bytes(frame.as_ref()))?;
                let acknowledged = connection.socket.flush();
                if acknowledged.is_ok() {
                    sync_wire_counters(connection, counters)?;
                    transcript.push(TranscriptEntry {
                        direction: "outbound",
                        kind: "close",
                        bytes: close_payload_bytes(frame.as_ref()),
                        action_index: Some(action_index),
                        check: "automatic",
                        code: frame.as_ref().map(|frame| u16::from(frame.code)),
                        payload_kind: Some(TranscriptPayloadKind::Text),
                        payload: Some(reason),
                    });
                }
                return match close_precedence(matched, acknowledged.is_ok()) {
                    ClosePrecedence::Accepted => Ok(Some(close)),
                    ClosePrecedence::Rejected => Err(SessionTerminal {
                        outcome: Outcome::Failed,
                        cause: WebSocketTerminalCause::ExpectationFailed,
                        exit: 1,
                        close: Some(close),
                    }),
                    ClosePrecedence::NotAcknowledged => Err(socket_error(
                        connection,
                        acknowledged.expect_err("only reached when the flush failed"),
                        timeout_cause,
                    )),
                };
            }
            Message::Frame(frame) => {
                transcript.push(TranscriptEntry {
                    direction: "inbound",
                    kind: "frame",
                    bytes: frame.payload().len() as u64,
                    action_index: Some(action_index),
                    check: "protocol-error",
                    code: None,
                    payload_kind: Some(TranscriptPayloadKind::Binary),
                    payload: Some(frame.payload().to_vec()),
                });
                return Err(SessionTerminal::error(
                    WebSocketTerminalCause::ProtocolViolation,
                ));
            }
        }
    }
}

fn execute_client_close(
    connection: &mut WebSocketConnection,
    plan: &WebSocketPlan,
    counters: &mut WebSocketCounters,
    code: u16,
    reason: &str,
    transcript: &mut Transcript,
    action_index: usize,
) -> Result<(), SessionTerminal> {
    let phase_deadline =
        deadline(Instant::now(), plan.limits.close_timeout_ms).min(connection.total_deadline);
    let frame = CloseFrame {
        code: CloseCode::from(code),
        reason: reason.to_owned().into(),
    };
    send_message(
        connection,
        plan,
        counters,
        Message::Close(Some(frame)),
        false,
        reason.len() as u64 + 2,
        phase_deadline,
    )?;
    transcript.push(TranscriptEntry {
        direction: "outbound",
        kind: "close",
        bytes: reason.len() as u64 + 2,
        action_index: Some(action_index),
        check: "sent",
        code: Some(code),
        payload_kind: Some(TranscriptPayloadKind::Text),
        payload: Some(reason.as_bytes().to_vec()),
    });
    loop {
        let timeout_cause = configure_session_deadline(
            connection,
            plan,
            phase_deadline,
            WebSocketTerminalCause::CloseTimeout,
        )
        .map_err(|_| SessionTerminal::error(WebSocketTerminalCause::IoFailure))?;
        match connection.socket.read() {
            Ok(message) => {
                sync_wire_counters(connection, counters)?;
                account_inbound(plan, counters, &message)?;
                match message {
                    Message::Ping(payload) => {
                        transcript.push(TranscriptEntry {
                            direction: "inbound",
                            kind: "ping",
                            bytes: payload.len() as u64,
                            action_index: Some(action_index),
                            check: "automatic",
                            code: None,
                            payload_kind: Some(TranscriptPayloadKind::Control),
                            payload: Some(payload.to_vec()),
                        });
                        account_automatic_control(plan, counters, payload.len() as u64)?;
                        if let Err(error) = connection.socket.flush() {
                            return Err(socket_error(connection, error, timeout_cause));
                        }
                        sync_wire_counters(connection, counters)?;
                        transcript.push(TranscriptEntry {
                            direction: "outbound",
                            kind: "pong",
                            bytes: payload.len() as u64,
                            action_index: Some(action_index),
                            check: "automatic",
                            code: None,
                            payload_kind: Some(TranscriptPayloadKind::Control),
                            payload: Some(payload.to_vec()),
                        });
                    }
                    Message::Close(frame) => {
                        let reason = frame
                            .as_ref()
                            .map_or_else(Vec::new, |frame| frame.reason.as_bytes().to_vec());
                        transcript.push(TranscriptEntry {
                            direction: "inbound",
                            kind: "close",
                            bytes: close_payload_bytes(frame.as_ref()),
                            action_index: Some(action_index),
                            check: "acknowledged",
                            code: frame.as_ref().map(|frame| u16::from(frame.code)),
                            payload_kind: Some(TranscriptPayloadKind::Text),
                            payload: Some(reason),
                        });
                        return Ok(());
                    }
                    Message::Pong(payload) => {
                        transcript.push(TranscriptEntry {
                            direction: "inbound",
                            kind: "pong",
                            bytes: payload.len() as u64,
                            action_index: Some(action_index),
                            check: "ignored",
                            code: None,
                            payload_kind: Some(TranscriptPayloadKind::Control),
                            payload: Some(payload.to_vec()),
                        });
                    }
                    Message::Text(payload) => {
                        transcript.push(TranscriptEntry {
                            direction: "inbound",
                            kind: "text",
                            bytes: payload.len() as u64,
                            action_index: Some(action_index),
                            check: "unexpected",
                            code: None,
                            payload_kind: Some(TranscriptPayloadKind::Text),
                            payload: Some(payload.as_bytes().to_vec()),
                        });
                        return Err(SessionTerminal::failed(
                            WebSocketTerminalCause::ExpectationFailed,
                        ));
                    }
                    Message::Binary(payload) => {
                        transcript.push(TranscriptEntry {
                            direction: "inbound",
                            kind: "binary",
                            bytes: payload.len() as u64,
                            action_index: Some(action_index),
                            check: "unexpected",
                            code: None,
                            payload_kind: Some(TranscriptPayloadKind::Binary),
                            payload: Some(payload.to_vec()),
                        });
                        return Err(SessionTerminal::failed(
                            WebSocketTerminalCause::ExpectationFailed,
                        ));
                    }
                    Message::Frame(frame) => {
                        transcript.push(TranscriptEntry {
                            direction: "inbound",
                            kind: "frame",
                            bytes: frame.payload().len() as u64,
                            action_index: Some(action_index),
                            check: "protocol-error",
                            code: None,
                            payload_kind: Some(TranscriptPayloadKind::Binary),
                            payload: Some(frame.payload().to_vec()),
                        });
                        return Err(SessionTerminal::failed(
                            WebSocketTerminalCause::ExpectationFailed,
                        ));
                    }
                }
            }
            Err(WebSocketError::ConnectionClosed) => return Ok(()),
            Err(error) => return Err(socket_error(connection, error, timeout_cause)),
        }
    }
}

fn decode_sealed_base64(value: &str) -> Result<Vec<u8>, ()> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| ())
}

fn expectation_matches_text(action: &WebSocketAction, text: &str) -> bool {
    match action {
        WebSocketAction::ExpectText { equals, .. } => text == equals,
        WebSocketAction::ExpectJson {
            pointer,
            equals,
            schema,
            ..
        } => serde_json::from_str::<Value>(text).is_ok_and(|document| {
            let Some(value) = pointer
                .as_deref()
                .map_or(Some(&document), |pointer| document.pointer(pointer))
            else {
                return false;
            };
            if equals.as_ref().is_some_and(|expected| expected != value) {
                return false;
            }
            if let Some(schema) = schema {
                let mut failures = Vec::new();
                validate_schema_value(schema, schema, value, "$", &mut failures, 0);
                failures.is_empty()
            } else {
                true
            }
        }),
        _ => false,
    }
}

fn account_inbound(
    plan: &WebSocketPlan,
    counters: &mut WebSocketCounters,
    message: &Message,
) -> Result<(), SessionTerminal> {
    let (data_message, bytes) = match message {
        Message::Text(value) => (true, value.len() as u64),
        Message::Binary(value) => (true, value.len() as u64),
        Message::Ping(value) | Message::Pong(value) => (false, value.len() as u64),
        Message::Close(frame) => (false, close_payload_bytes(frame.as_ref())),
        Message::Frame(frame) => (false, frame.payload().len() as u64),
    };
    if data_message {
        counters.inbound_messages = counters.inbound_messages.saturating_add(1);
    }
    if counters.inbound_messages > plan.limits.max_inbound_messages
        || bytes > plan.limits.max_message_bytes
    {
        Err(SessionTerminal::failed(
            WebSocketTerminalCause::BudgetExhausted,
        ))
    } else {
        Ok(())
    }
}

fn account_automatic_control(
    plan: &WebSocketPlan,
    counters: &mut WebSocketCounters,
    bytes: u64,
) -> Result<(), SessionTerminal> {
    if exceeds_outbound(plan, counters, false, bytes) {
        return Err(SessionTerminal::failed(
            WebSocketTerminalCause::BudgetExhausted,
        ));
    }
    Ok(())
}

fn exceeds_outbound(
    plan: &WebSocketPlan,
    counters: &WebSocketCounters,
    data_message: bool,
    bytes: u64,
) -> bool {
    counters.outbound_frames >= plan.limits.max_outbound_frames
        || counters.outbound_bytes.saturating_add(bytes) > plan.limits.max_outbound_bytes
        || (data_message && counters.outbound_messages >= plan.limits.max_outbound_messages)
        || bytes > plan.limits.max_frame_bytes
}

fn close_payload_bytes(frame: Option<&CloseFrame>) -> u64 {
    frame.map_or(0, |frame| frame.reason.len() as u64 + 2)
}

fn close_matches(frame: Option<&CloseFrame>, codes: &[u16], reason: Option<&str>) -> bool {
    let code = frame.map_or(1005, |frame| u16::from(frame.code));
    codes.contains(&code)
        && reason.is_none_or(|reason| frame.is_some_and(|frame| frame.reason == reason))
}

fn close_observation(
    initiator: WebSocketCloseInitiator,
    frame: Option<&CloseFrame>,
) -> WebSocketCloseObservation {
    WebSocketCloseObservation {
        initiator,
        code: frame.map_or(1005, |frame| u16::from(frame.code)),
        reason: frame.map_or_else(String::new, |frame| frame.reason.to_string()),
    }
}

fn sync_wire_counters(
    connection: &WebSocketConnection,
    counters: &mut WebSocketCounters,
) -> Result<(), SessionTerminal> {
    let accounting = connection
        .accounting
        .lock()
        .map_err(|_| SessionTerminal::error(WebSocketTerminalCause::IoFailure))?;
    counters.inbound_frames = accounting.counters.inbound_frames;
    counters.outbound_frames = accounting.counters.outbound_frames;
    counters.inbound_bytes = accounting.counters.inbound_bytes;
    counters.outbound_bytes = accounting.counters.outbound_bytes;
    if let Some(cause) = accounting.failure {
        return Err(if cause == WebSocketTerminalCause::BudgetExhausted {
            SessionTerminal::failed(cause)
        } else {
            SessionTerminal::error(cause)
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClosePrecedence {
    Accepted,
    Rejected,
    NotAcknowledged,
}

/// What to report when the peer's close frame has been read and acknowledging it may have failed.
///
/// The verdict is settled the moment the frame is read; the acknowledgement is courtesy. A peer that
/// closes with our bytes still unread resets the connection, and that reset surfaces on the
/// acknowledging write rather than on the read that already told us what happened. Reporting the I/O
/// error would replace the diagnosis the operator needs — an unacceptable close code — with the
/// failure to reply to it, and would do so only on the runs where the reset won the race. An I/O
/// failure is reported only when there is no verdict of its own to report.
const fn close_precedence(matched: bool, acknowledged: bool) -> ClosePrecedence {
    match (matched, acknowledged) {
        (false, _) => ClosePrecedence::Rejected,
        (true, true) => ClosePrecedence::Accepted,
        (true, false) => ClosePrecedence::NotAcknowledged,
    }
}

fn socket_error(
    connection: &WebSocketConnection,
    error: WebSocketError,
    timeout: WebSocketTerminalCause,
) -> SessionTerminal {
    let timeout = connection
        .deadline
        .lock()
        .map(|deadline| deadline.cause)
        .unwrap_or(timeout);
    if let Ok(accounting) = connection.accounting.lock()
        && let Some(cause) = accounting.failure
    {
        return if cause == WebSocketTerminalCause::BudgetExhausted {
            SessionTerminal::failed(cause)
        } else {
            SessionTerminal::error(cause)
        };
    }
    match error {
        WebSocketError::Io(error) if error.kind() == io::ErrorKind::Interrupted => {
            SessionTerminal::error(WebSocketTerminalCause::Cancelled)
        }
        WebSocketError::Io(error)
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) =>
        {
            SessionTerminal::error(timeout)
        }
        WebSocketError::Io(error)
            if matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
            ) =>
        {
            SessionTerminal::error(WebSocketTerminalCause::UnexpectedEof)
        }
        WebSocketError::ConnectionClosed | WebSocketError::AlreadyClosed => {
            SessionTerminal::error(WebSocketTerminalCause::UnexpectedEof)
        }
        WebSocketError::Capacity(_) | WebSocketError::WriteBufferFull(_) => {
            SessionTerminal::failed(WebSocketTerminalCause::BudgetExhausted)
        }
        WebSocketError::Protocol(_) | WebSocketError::Utf8(_) | WebSocketError::AttackAttempt => {
            SessionTerminal::error(WebSocketTerminalCause::ProtocolViolation)
        }
        _ => SessionTerminal::error(WebSocketTerminalCause::IoFailure),
    }
}

fn finish_session(
    plan: &WebSocketPlan,
    connection: WebSocketConnection,
    store: &EvidenceStore,
    mut counters: WebSocketCounters,
    transcript: Transcript,
    mut terminal: SessionTerminal,
) -> Result<WebSocketConnectResult, ExecError> {
    if let Ok(accounting) = connection.accounting.lock() {
        counters.inbound_frames = accounting.counters.inbound_frames;
        counters.outbound_frames = accounting.counters.outbound_frames;
        counters.inbound_bytes = accounting.counters.inbound_bytes;
        counters.outbound_bytes = accounting.counters.outbound_bytes;
    }
    if let Some(close) = &mut terminal.close {
        sanitize_close(close, &connection.redactions);
    }
    let transcript = store_transcript(
        plan,
        store,
        &transcript,
        &connection.redactions,
        terminal.outcome.clone(),
        terminal.cause,
        terminal.exit,
    )?;
    let observation = WebSocketObservation {
        protocol: PROTOCOL.into(),
        kind: "websocket-observation".into(),
        version: VERSION.into(),
        config_fingerprint: plan.config_fingerprint.clone(),
        policy_fingerprint: plan.policy_fingerprint.clone(),
        source_fingerprints: plan.source_fingerprints.clone(),
        tool_version: env!("CARGO_PKG_VERSION").into(),
        plan: plan.id.clone(),
        outcome: terminal.outcome,
        handshake_status: Some(connection.metadata.status),
        negotiated_subprotocol: connection.metadata.negotiated_subprotocol,
        handshake_latency_ms: Some(connection.metadata.latency.as_secs_f64() * 1_000.0),
        session_duration_ms: Some(connection.started.elapsed().as_secs_f64() * 1_000.0),
        transcript: Some(transcript.handle),
        handshake: Some(connection.metadata.handshake),
        trace: Some(connection.metadata.trace),
        close: terminal.close,
        terminal_cause: terminal.cause,
        counters,
        resolved_origin: Some(connection.metadata.resolved_origin.to_string()),
        http_version: Some(connection.metadata.http_version),
        secret_refs: plan.secret_refs.clone(),
        runtime: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        exit: terminal.exit,
    };
    store.persist_websocket_observation(&observation)?;
    Ok(WebSocketConnectResult::Observation(Box::new(observation)))
}

fn is_address_dependent_grant(grant: &str) -> bool {
    grant.starts_with("net-cidr:")
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
    const HANDSHAKE_CONTROLLED_HEADERS: [&str; 9] = [
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
    let mut request = plan
        .target
        .as_str()
        .into_client_request()
        .map_err(|_| ExecError::InvalidTarget("WebSocket request URI is invalid".into()))?;
    for planned in &plan.headers {
        if HANDSHAKE_CONTROLLED_HEADERS
            .iter()
            .any(|owned| planned.name.eq_ignore_ascii_case(owned))
        {
            return Err(ExecError::InvalidHeader(
                "planned header collides with a handshake-controlled header".into(),
            ));
        }
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
    static NATIVE_ROOTS: OnceLock<Result<RootCertStore, ()>> = OnceLock::new();
    let mut roots = NATIVE_ROOTS
        .get_or_init(|| {
            let native = rustls_native_certs::load_native_certs();
            if !native.errors.is_empty() {
                return Err(());
            }
            let mut roots = RootCertStore::empty();
            roots.add_parsable_certificates(native.certs);
            Ok(roots)
        })
        .as_ref()
        .map_err(|()| {
            ExecError::Transport("native TLS trust store could not be loaded completely".into())
        })?
        .clone();
    for pem in &options.additional_root_certificates_pem {
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
    mut stream: Transport,
    config: WebSocketConfig,
    tls: bool,
    limits: WebSocketLimits,
    accounting: Arc<Mutex<WireAccounting>>,
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
                counters: WebSocketCounters::default(),
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
        // RFC 6455 section 4.1 mandates SHA-1 for Sec-WebSocket-Accept. This is a protocol
        // constant, not a security hash.
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
        .map(|value| value.to_str().unwrap_or("\0invalid"))
        .collect();
    let extensions_absent = !response.headers().contains_key("sec-websocket-extensions");
    let selected: Vec<_> = response
        .headers()
        .get_all("sec-websocket-protocol")
        .iter()
        .map(|value| value.to_str().unwrap_or("\0invalid"))
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
            counters: WebSocketCounters::default(),
        });
    }
    let buffered = received[header_end..].to_vec();
    let mut stream = AccountedStream::new(stream, limits, Arc::clone(&accounting));
    if stream.observe_buffered_inbound(&buffered).is_err() {
        let (cause, counters) = accounting.lock().map_or(
            (
                WebSocketTerminalCause::IoFailure,
                WebSocketCounters::default(),
            ),
            |accounting| {
                (
                    accounting
                        .failure
                        .unwrap_or(WebSocketTerminalCause::IoFailure),
                    accounting.counters.clone(),
                )
            },
        );
        let (outcome, exit) = if cause == WebSocketTerminalCause::BudgetExhausted {
            (Outcome::Failed, 1)
        } else {
            (Outcome::Error, 3)
        };
        return Err(HandshakeFailure {
            outcome,
            cause,
            exit,
            status: Some(status),
            response: Some(Box::new(response)),
            counters,
        });
    }
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
        "request": {
            "method": "GET",
            "target": redact_text(&plan.target, redactions),
            "headers": safe_headers(request.headers(), &plan.sensitive_headers, redactions, true),
        },
    });
    Ok(store.put_json("websocket-trace", &trace, true)?)
}

fn store_transcript(
    plan: &WebSocketPlan,
    store: &EvidenceStore,
    transcript: &Transcript,
    redactions: &[Vec<u8>],
    outcome: Outcome,
    cause: WebSocketTerminalCause,
    exit: u8,
) -> Result<kahea_core::EvidenceEnvelope, ExecError> {
    let mut entries = Vec::with_capacity(transcript.entries.len());
    for (sequence, entry) in transcript.entries.iter().enumerate() {
        let payload = entry
            .payload
            .as_deref()
            .zip(entry.payload_kind)
            .map(|(payload, payload_kind)| {
                store_transcript_payload(
                    plan,
                    store,
                    entry.direction,
                    payload_kind,
                    payload,
                    redactions,
                )
            })
            .transpose()?
            .map(|envelope| envelope.handle);
        entries.push(json!({
            "sequence": sequence,
            "direction": entry.direction,
            "kind": entry.kind,
            "bytes": entry.bytes,
            "action_index": entry.action_index,
            "check": entry.check,
            "code": entry.code,
            "payload": payload,
        }));
    }
    let value = json!({
        "version": 1,
        "entries": entries,
        "terminal": {
            "outcome": outcome,
            "cause": cause,
            "exit": exit,
        },
    });
    Ok(store.put_json("transcript", &value, true)?)
}

fn store_transcript_payload(
    plan: &WebSocketPlan,
    store: &EvidenceStore,
    direction: &str,
    kind: TranscriptPayloadKind,
    payload: &[u8],
    redactions: &[Vec<u8>],
) -> Result<kahea_core::EvidenceEnvelope, ExecError> {
    let configured = if direction == "inbound" && matches!(kind, TranscriptPayloadKind::Text) {
        redact_json_pointers(payload, &plan.redact_response_json_pointers)
    } else {
        payload.to_vec()
    };
    let redacted = redact_bytes(&configured, redactions);
    let (evidence_kind, media_type) = match kind {
        TranscriptPayloadKind::Text if serde_json::from_slice::<Value>(&redacted).is_ok() => {
            ("websocket-json", "application/json")
        }
        TranscriptPayloadKind::Text => ("websocket-text", "text/plain; charset=utf-8"),
        TranscriptPayloadKind::Binary => ("websocket-binary", "application/octet-stream"),
        TranscriptPayloadKind::Control => ("websocket-control", "application/octet-stream"),
    };
    Ok(store.put_blob(evidence_kind, media_type, &redacted, true)?)
}

fn sanitize_close(close: &mut WebSocketCloseObservation, redactions: &[Vec<u8>]) {
    close.reason = bounded_text(&redact_text(&close.reason, redactions), 256);
}

fn bounded_text(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn store_handshake(
    plan: &WebSocketPlan,
    store: &EvidenceStore,
    response: &Response,
    redactions: &[Vec<u8>],
) -> Result<kahea_core::EvidenceEnvelope, ExecError> {
    let evidence = json!({
        "response": {
            "status": response.status().as_u16(),
            "http_version": http_version(response.version()),
            "headers": safe_headers(response.headers(), &plan.sensitive_headers, redactions, false),
        },
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
    counters: WebSocketCounters,
}

fn handshake_check_failure() -> HandshakeFailure {
    HandshakeFailure {
        outcome: Outcome::Failed,
        cause: WebSocketTerminalCause::HandshakeCheckFailed,
        exit: 1,
        status: None,
        response: None,
        counters: WebSocketCounters::default(),
    }
}

fn io_handshake_failure(error: io::Error, tls: bool) -> HandshakeFailure {
    let cause = if error.kind() == io::ErrorKind::Interrupted {
        WebSocketTerminalCause::Cancelled
    } else if matches!(
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
        counters: WebSocketCounters::default(),
    }
}

#[derive(Default)]
struct FailureDetails {
    status: Option<u16>,
    subprotocol: Option<String>,
    resolved: Option<SocketAddr>,
    handshake: Option<String>,
    trace: Option<String>,
    http_version: Option<String>,
    counters: WebSocketCounters,
}

fn failed_observation(
    plan: &WebSocketPlan,
    store: &EvidenceStore,
    started: Instant,
    outcome: Outcome,
    cause: WebSocketTerminalCause,
    exit: u8,
    details: FailureDetails,
) -> Result<WebSocketConnectResult, ExecError> {
    let elapsed = started.elapsed();
    let transcript = store_transcript(
        plan,
        store,
        &Transcript::default(),
        &[],
        outcome.clone(),
        cause,
        exit,
    )?;
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
        handshake_status: details.status,
        negotiated_subprotocol: details.subprotocol,
        handshake_latency_ms: Some(elapsed.as_secs_f64() * 1_000.0),
        session_duration_ms: Some(elapsed.as_secs_f64() * 1_000.0),
        transcript: Some(transcript.handle),
        handshake: details.handshake,
        trace: details.trace,
        close: None,
        terminal_cause: cause,
        counters: details.counters,
        resolved_origin: details.resolved.map(|address| address.to_string()),
        http_version: details.http_version,
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

fn bounded_total_deadline(
    started: Instant,
    plan_total_timeout_ms: u64,
    invocation_timeout: Duration,
) -> Instant {
    let plan_deadline = deadline(started, plan_total_timeout_ms);
    started
        .checked_add(invocation_timeout)
        .map_or(plan_deadline, |invocation_deadline| {
            plan_deadline.min(invocation_deadline)
        })
}

#[derive(Clone, Copy)]
struct DeadlineState {
    active_deadline: Instant,
    total_deadline: Instant,
    phase_deadline: Instant,
    idle_timeout: Option<Duration>,
    phase_cause: WebSocketTerminalCause,
    cause: WebSocketTerminalCause,
}

impl DeadlineState {
    fn fixed(deadline: Instant, cause: WebSocketTerminalCause) -> Self {
        Self {
            active_deadline: deadline,
            total_deadline: deadline,
            phase_deadline: deadline,
            idle_timeout: None,
            phase_cause: cause,
            cause,
        }
    }

    fn note_activity(&mut self) {
        let Some(idle_timeout) = self.idle_timeout else {
            return;
        };
        let idle_deadline = deadline(Instant::now(), idle_timeout.as_millis() as u64);
        (self.active_deadline, self.cause) = select_deadline(
            self.total_deadline,
            self.phase_deadline,
            idle_deadline,
            self.phase_cause,
        );
    }
}

pub(crate) struct DeadlineTcpStream {
    stream: TcpStream,
    deadline: Arc<Mutex<DeadlineState>>,
    cancellation: Option<Arc<AtomicBool>>,
}

impl DeadlineTcpStream {
    fn new(
        stream: TcpStream,
        deadline: Arc<Mutex<DeadlineState>>,
        cancellation: Option<Arc<AtomicBool>>,
    ) -> Self {
        Self {
            stream,
            deadline,
            cancellation,
        }
    }

    fn remaining(&self) -> io::Result<Duration> {
        if self
            .cancellation
            .as_ref()
            .is_some_and(|cancelled| cancelled.load(Ordering::Acquire))
        {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "WebSocket session cancelled",
            ));
        }
        let remaining = self
            .deadline
            .lock()
            .map_err(|_| io::Error::other("deadline state failed"))?
            .active_deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "WebSocket deadline elapsed"))?;
        Ok(if self.cancellation.is_some() {
            remaining.min(Duration::from_millis(25))
        } else {
            remaining
        })
    }

    fn note_activity(&self) -> io::Result<()> {
        self.deadline
            .lock()
            .map_err(|_| io::Error::other("deadline state failed"))?
            .note_activity();
        Ok(())
    }
}

impl Read for DeadlineTcpStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            self.stream.set_read_timeout(Some(self.remaining()?))?;
            match self.stream.read(buffer).map_err(normalize_timeout) {
                Ok(read) => {
                    if read != 0 {
                        self.note_activity()?;
                    }
                    return Ok(read);
                }
                Err(error)
                    if error.kind() == io::ErrorKind::TimedOut && self.cancellation.is_some() =>
                {
                    self.remaining()?;
                }
                Err(error) => return Err(error),
            }
        }
    }
}

impl Write for DeadlineTcpStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        loop {
            self.stream.set_write_timeout(Some(self.remaining()?))?;
            match self.stream.write(buffer).map_err(normalize_timeout) {
                Ok(written) => {
                    if written != 0 {
                        self.note_activity()?;
                    }
                    return Ok(written);
                }
                Err(error)
                    if error.kind() == io::ErrorKind::TimedOut && self.cancellation.is_some() =>
                {
                    self.remaining()?;
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        loop {
            self.stream.set_write_timeout(Some(self.remaining()?))?;
            match self.stream.flush().map_err(normalize_timeout) {
                Ok(()) => return Ok(()),
                Err(error)
                    if error.kind() == io::ErrorKind::TimedOut && self.cancellation.is_some() =>
                {
                    self.remaining()?;
                }
                Err(error) => return Err(error),
            }
        }
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
    use kahea_test_server::remove_temporary_store;
    use kahea_test_server::{
        WebSocketFaultMode, WebSocketOracleTransport, generate_websocket_scenario,
        start_websocket_oracle, start_websocket_oracle_on,
    };
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use rustls::{ServerConfig, ServerConnection, StreamOwned};
    use std::fs;
    use std::net::{Ipv6Addr, TcpListener};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tungstenite::http::StatusCode;
    use tungstenite::protocol::frame::Frame;
    use tungstenite::protocol::frame::coding::{Data, OpCode};

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

    fn assert_files_absent(root: &std::path::Path, needle: &[u8]) {
        for entry in fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                assert_files_absent(&path, needle);
            } else {
                let data = fs::read(&path).unwrap();
                assert!(
                    !data.windows(needle.len()).any(|window| window == needle),
                    "secret bytes persisted in {}",
                    path.display()
                );
            }
        }
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
                // Tests that assert a deadline set their own budget. These defaults exist only so
                // successful sessions are not cut short by a loaded runner, so they are generous.
                connect_timeout_ms: 10_000,
                action_timeout_ms: 10_000,
                idle_timeout_ms: 10_000,
                close_timeout_ms: 10_000,
                total_timeout_ms: 30_000,
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

    fn oracle_plan(
        manifest: &kahea_test_server::WebSocketOracleManifest,
        scenario: &kahea_test_server::WebSocketOracleScenario,
    ) -> WebSocketPlan {
        let parsed = Url::parse(&manifest.url).unwrap();
        let host = parsed.host_str().unwrap();
        let address = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host)
            .parse::<IpAddr>()
            .unwrap();
        let cidr_grant = match address {
            IpAddr::V4(address) => format!("net-cidr:{address}/32"),
            IpAddr::V6(address) => format!("net-cidr:{address}/128"),
        };
        let mut plan = plan(manifest.url.clone(), cidr_grant);
        if manifest.transport == WebSocketOracleTransport::Plaintext {
            plan.required_grants.push("net-insecure-websocket".into());
        }
        plan.origin = scenario.expected_origin.clone();
        plan.subprotocols = scenario.subprotocol.iter().cloned().collect();
        if let Some(protocol) = &scenario.subprotocol {
            plan.handshake_checks
                .push(format!("subprotocol:{protocol}"));
        }
        plan.actions = vec![
            WebSocketAction::SendText {
                text: format!("client-{:016x}", scenario.seed),
            },
            WebSocketAction::ExpectText {
                equals: format!("server-{:016x}", scenario.seed),
                timeout_ms: Some(10_000),
            },
            WebSocketAction::SendBinary {
                payload_base64: base64::engine::general_purpose::STANDARD
                    .encode(scenario.seed.to_be_bytes()),
            },
            WebSocketAction::ExpectBinary {
                payload_base64: base64::engine::general_purpose::STANDARD.encode(
                    scenario
                        .seed
                        .to_be_bytes()
                        .into_iter()
                        .rev()
                        .collect::<Vec<_>>(),
                ),
                timeout_ms: Some(10_000),
            },
            WebSocketAction::ExpectText {
                equals: format!("seeded-{:016x}", scenario.seed),
                timeout_ms: Some(10_000),
            },
            WebSocketAction::ExpectClose {
                codes: vec![1000],
                reason: Some("oracle-complete".into()),
                timeout_ms: Some(10_000),
            },
        ];
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

    fn accept_test_connection(listener: &TcpListener) -> TcpStream {
        const TEST_IO_TIMEOUT: Duration = Duration::from_secs(5);
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + TEST_IO_TIMEOUT;
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    // Accepted sockets inherit O_NONBLOCK on some Unix platforms.
                    stream.set_nonblocking(false).unwrap();
                    stream.set_read_timeout(Some(TEST_IO_TIMEOUT)).unwrap();
                    stream.set_write_timeout(Some(TEST_IO_TIMEOUT)).unwrap();
                    return stream;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "test WebSocket peer did not connect within five seconds"
                    );
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("test WebSocket accept failed: {error}"),
            }
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
        remove_temporary_store(&root);
    }

    #[test]
    fn transport_grants_are_enforced_before_tcp_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let socket_plan = ws_plan(&listener);
        let (root, store) = store();

        let mut plaintext_options = options(&socket_plan);
        plaintext_options.grants.remove("net-insecure-websocket");
        let WebSocketConnectResult::Denied(denial) =
            connect_websocket(&socket_plan, &plaintext_options, &store).unwrap()
        else {
            panic!("plaintext WebSocket without its grant must be denied")
        };
        assert_eq!(denial.required, "net-insecure-websocket");

        let mut missing_connect_options = options(&socket_plan);
        missing_connect_options.grants.remove("websocket:connect");
        let resolver_calls = std::cell::Cell::new(0_u8);
        let resolver = |_host: &str, _port: u16| {
            resolver_calls.set(resolver_calls.get() + 1);
            Ok(vec![address])
        };
        let WebSocketConnectResult::Denied(denial) =
            connect_websocket_resolving(&socket_plan, &missing_connect_options, &store, &resolver)
                .unwrap()
        else {
            panic!("missing WebSocket connect grant must be denied")
        };
        assert_eq!(denial.required, "websocket:connect");
        assert_eq!(resolver_calls.get(), 0);

        let hostname_plan = plan(
            format!("ws://socket.example.test:{}/socket", address.port()),
            "net-cidr:127.0.0.1/32".into(),
        );
        let mut hostname_plan = hostname_plan;
        hostname_plan
            .required_grants
            .push("net-insecure-websocket".into());
        let hostname_plan = hostname_plan.seal().unwrap();
        let mut unsafe_options = options(&hostname_plan);
        unsafe_options.grants.remove("net-cidr:127.0.0.1/32");
        let resolver = |_host: &str, port: u16| Ok(vec![SocketAddr::new(address.ip(), port)]);
        let WebSocketConnectResult::Denied(denial) =
            connect_websocket_resolving(&hostname_plan, &unsafe_options, &store, &resolver)
                .unwrap()
        else {
            panic!("unsafe resolved address without its CIDR grant must be denied")
        };
        assert_eq!(denial.required, "net-cidr:127.0.0.1/32");
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(store);
        remove_temporary_store(&root);
    }

    #[test]
    fn executor_rejects_handshake_controlled_planned_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut plan = ws_plan(&listener);
        plan.headers.push(PlannedHeader {
            name: "Sec-WebSocket-Key".into(),
            value: "attacker-controlled".into(),
        });
        assert!(matches!(
            websocket_request(&plan, &options(&plan)),
            Err(ExecError::InvalidHeader(message))
                if message == "planned header collides with a handshake-controlled header"
        ));
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
        remove_temporary_store(&root);
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
            let stream = accept_test_connection(&listener);
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
        remove_temporary_store(&root);
    }

    #[test]
    fn handshake_injects_sealed_intent_and_redacts_secrets_and_entropy() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut plan = ws_plan(&listener);
        plan.target.push_str("?access_token=top-secret-value");
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
            let stream = accept_test_connection(&listener);
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
        assert_eq!(
            store
                .explain(
                    &connection.metadata.trace,
                    Some("header:request:authorization"),
                )
                .unwrap()
                .value,
            Some(Value::String("[REDACTED]".into()))
        );
        assert_eq!(
            store
                .explain(
                    &connection.metadata.handshake,
                    Some("header:response:x-reflected"),
                )
                .unwrap()
                .value,
            Some(Value::String("[REDACTED]".into()))
        );
        drop(connection);
        server.join().unwrap();
        drop(store);
        remove_temporary_store(&root);
    }

    #[test]
    fn redirects_and_negotiated_extensions_fail_closed() {
        let redirect_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let redirect_plan = ws_plan(&redirect_listener);
        let redirect_server = thread::spawn(move || {
            let mut stream = accept_test_connection(&redirect_listener);
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
            let stream = accept_test_connection(&extension_listener);
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
        remove_temporary_store(&root);
    }

    #[test]
    fn malformed_accept_and_silent_peer_map_deterministically() {
        let malformed_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let malformed_plan = ws_plan(&malformed_listener);
        let malformed_server = thread::spawn(move || {
            let mut stream = accept_test_connection(&malformed_listener);
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
        // The sealed handshake budget is deliberately generous; the stricter invocation budget
        // must still terminate a silent peer promptly on loaded cross-platform runners.
        silent_plan.limits.connect_timeout_ms = 2_000;
        silent_plan = silent_plan.seal().unwrap();
        let silent_server = thread::spawn(move || {
            let _stream = accept_test_connection(&silent_listener);
            thread::sleep(Duration::from_millis(1_200));
        });
        let mut silent_options = options(&silent_plan);
        silent_options.timeout = Duration::from_millis(300);
        let started = Instant::now();
        let WebSocketConnectResult::Observation(observation) =
            connect_websocket(&silent_plan, &silent_options, &store).unwrap()
        else {
            panic!("silent peer must time out")
        };
        assert!(started.elapsed() < Duration::from_millis(1_000));
        assert_eq!(observation.exit, 3);
        assert!(matches!(
            observation.terminal_cause,
            WebSocketTerminalCause::ConnectTimeout
        ));
        silent_server.join().unwrap();
        drop(store);
        remove_temporary_store(&root);
    }

    #[test]
    fn controlled_oracle_is_seeded_scripted_bounded_and_tls_capable() {
        let mut scenario = generate_websocket_scenario(0x51_0c_e7);
        scenario.handshake_delay_ms = 5;
        scenario.frame_delay_ms = 5;
        scenario.close_delay_ms = 5;
        let oracle = start_websocket_oracle(
            scenario.clone(),
            WebSocketFaultMode::None,
            WebSocketOracleTransport::Plaintext,
        )
        .unwrap();
        let plan = oracle_plan(&oracle.manifest, &scenario);
        let (root, evidence_store) = store();
        let WebSocketConnectResult::Observation(observation) =
            execute_websocket(&plan, &options(&plan), &evidence_store).unwrap()
        else {
            panic!("seeded oracle must produce a terminal observation")
        };
        assert_eq!(observation.exit, 0);
        assert_eq!(
            observation.terminal_cause,
            WebSocketTerminalCause::Completed
        );
        assert_eq!(observation.negotiated_subprotocol, scenario.subprotocol);
        let oracle_observation = oracle.wait().unwrap();
        assert_eq!(oracle_observation.seed, scenario.seed);
        assert_eq!(oracle_observation.case_id, "ws-0000000000510ce7-none");
        assert_eq!(oracle_observation.completed_steps, scenario.steps.len());
        assert_eq!(oracle_observation.outcome, "completed");
        drop(evidence_store);
        remove_temporary_store(&root);

        let mut tls_scenario = generate_websocket_scenario(0x715);
        tls_scenario.expected_origin = None;
        tls_scenario.subprotocol = None;
        tls_scenario.steps = vec![kahea_test_server::WebSocketOracleStep::SendClose {
            code: 1000,
            reason: "oracle-complete".into(),
        }];
        let tls_oracle = start_websocket_oracle(
            tls_scenario.clone(),
            WebSocketFaultMode::None,
            WebSocketOracleTransport::Tls,
        )
        .unwrap();
        let mut tls_plan = oracle_plan(&tls_oracle.manifest, &tls_scenario);
        tls_plan.actions = vec![WebSocketAction::ExpectClose {
            codes: vec![1000],
            reason: Some("oracle-complete".into()),
            timeout_ms: Some(10_000),
        }];
        let tls_plan = tls_plan.seal().unwrap();
        let mut tls_options = options(&tls_plan);
        tls_options.additional_root_certificates_pem.push(
            tls_oracle
                .manifest
                .root_certificate_pem
                .as_deref()
                .unwrap()
                .as_bytes()
                .to_vec(),
        );
        let (tls_root, tls_store) = store();
        let WebSocketConnectResult::Observation(observation) =
            execute_websocket(&tls_plan, &tls_options, &tls_store).unwrap()
        else {
            panic!("TLS oracle must produce a terminal observation")
        };
        assert_eq!(observation.exit, 0);
        assert_eq!(tls_oracle.wait().unwrap().completed_steps, 1);
        drop(tls_store);
        remove_temporary_store(&tls_root);
    }

    #[test]
    fn controlled_oracle_fault_matrix_is_reproducible_and_fails_closed() {
        for fault in WebSocketFaultMode::ALL
            .into_iter()
            .filter(|fault| *fault != WebSocketFaultMode::None)
        {
            let mut scenario = generate_websocket_scenario(0xfa017);
            scenario.expected_origin = None;
            scenario.subprotocol = None;
            scenario.oversized_payload_bytes = 129;
            scenario.steps.clear();
            let oracle =
                start_websocket_oracle(scenario, fault, WebSocketOracleTransport::Plaintext)
                    .unwrap();
            let mut plan = plan(oracle.manifest.url.clone(), "net-cidr:127.0.0.1/32".into());
            plan.required_grants.push("net-insecure-websocket".into());
            let silent_handshake = fault == WebSocketFaultMode::SilentHandshake;
            plan.limits.connect_timeout_ms = if silent_handshake { 200 } else { 1_000 };
            plan.limits.action_timeout_ms = 200;
            plan.limits.close_timeout_ms = 200;
            plan.limits.idle_timeout_ms = 400;
            plan.limits.total_timeout_ms = if silent_handshake { 500 } else { 1_500 };
            plan.limits.max_frame_bytes = 128;
            plan.actions = if fault == WebSocketFaultMode::SilentClose {
                vec![WebSocketAction::Close {
                    code: 1000,
                    reason: "client-finished".into(),
                }]
            } else {
                vec![
                    WebSocketAction::ExpectText {
                        equals: "oracle-expected".into(),
                        timeout_ms: Some(200),
                    },
                    WebSocketAction::ExpectClose {
                        codes: vec![1000],
                        reason: None,
                        timeout_ms: Some(200),
                    },
                ]
            };
            let plan = plan.seal().unwrap();
            let (root, store) = store();
            let WebSocketConnectResult::Observation(observation) =
                execute_websocket(&plan, &options(&plan), &store).unwrap()
            else {
                panic!("fault {fault:?} must produce a terminal observation")
            };
            let expected_cause = match fault {
                WebSocketFaultMode::BadAcceptKey
                | WebSocketFaultMode::BadStatus
                | WebSocketFaultMode::MissingUpgradeHeader
                | WebSocketFaultMode::Redirect
                | WebSocketFaultMode::NegotiatedExtension => {
                    WebSocketTerminalCause::HandshakeCheckFailed
                }
                WebSocketFaultMode::InvalidUtf8
                | WebSocketFaultMode::MaskedServerFrame
                | WebSocketFaultMode::ReservedOpcode
                | WebSocketFaultMode::ReservedBit
                | WebSocketFaultMode::FragmentedControlFrame
                | WebSocketFaultMode::InvalidClosePayload
                | WebSocketFaultMode::TruncatedFrame
                | WebSocketFaultMode::AbruptClose => WebSocketTerminalCause::ProtocolViolation,
                WebSocketFaultMode::OversizedFrame => WebSocketTerminalCause::BudgetExhausted,
                WebSocketFaultMode::InvalidCloseCode | WebSocketFaultMode::UnexpectedText => {
                    WebSocketTerminalCause::ExpectationFailed
                }
                WebSocketFaultMode::SilentHandshake => WebSocketTerminalCause::ConnectTimeout,
                WebSocketFaultMode::SilentFrame => WebSocketTerminalCause::ActionTimeout,
                WebSocketFaultMode::SilentClose => WebSocketTerminalCause::CloseTimeout,
                WebSocketFaultMode::None => unreachable!(),
            };
            assert_ne!(observation.exit, 0, "fault {fault:?} passed unexpectedly");
            assert_eq!(
                observation.terminal_cause, expected_cause,
                "fault {fault:?} mapped to the wrong terminal cause"
            );
            let oracle_observation = oracle.wait().unwrap();
            assert_eq!(oracle_observation.seed, 0xfa017);
            assert_eq!(
                oracle_observation.case_id,
                format!("ws-00000000000fa017-{}", fault.slug())
            );
            assert_eq!(oracle_observation.connections, 1);
            drop(store);
            remove_temporary_store(&root);
        }
    }

    #[test]
    fn controlled_oracle_proves_idle_total_and_connection_deadlines() {
        let mut idle_scenario = generate_websocket_scenario(0xd1e);
        idle_scenario.expected_origin = None;
        idle_scenario.subprotocol = None;
        idle_scenario.steps.clear();
        let idle_oracle = start_websocket_oracle(
            idle_scenario,
            WebSocketFaultMode::SilentFrame,
            WebSocketOracleTransport::Plaintext,
        )
        .unwrap();
        let mut idle_plan = plan(
            idle_oracle.manifest.url.clone(),
            "net-cidr:127.0.0.1/32".into(),
        );
        idle_plan
            .required_grants
            .push("net-insecure-websocket".into());
        // Only the idle deadline is under test, so every other budget is generous. A connect budget
        // tight enough to expire on a loaded runner makes this assert the wrong deadline and fail
        // for a reason that has nothing to do with idleness.
        idle_plan.limits.connect_timeout_ms = 5_000;
        idle_plan.limits.action_timeout_ms = 200;
        idle_plan.limits.idle_timeout_ms = 50;
        idle_plan.limits.close_timeout_ms = 200;
        idle_plan.limits.total_timeout_ms = 5_000;
        idle_plan.actions = vec![
            WebSocketAction::ExpectText {
                equals: "never".into(),
                timeout_ms: Some(200),
            },
            WebSocketAction::ExpectClose {
                codes: vec![1000],
                reason: None,
                timeout_ms: Some(200),
            },
        ];
        let idle_plan = idle_plan.seal().unwrap();
        let (idle_root, idle_store) = store();
        let WebSocketConnectResult::Observation(observation) =
            execute_websocket(&idle_plan, &options(&idle_plan), &idle_store).unwrap()
        else {
            panic!("idle deadline must return an observation")
        };
        assert_eq!(
            observation.terminal_cause,
            WebSocketTerminalCause::IdleTimeout
        );
        assert_eq!(observation.exit, 3);
        assert_eq!(
            idle_oracle.wait().unwrap().case_id,
            "ws-0000000000000d1e-silent-frame"
        );
        drop(idle_store);
        remove_temporary_store(&idle_root);

        let mut total_scenario = generate_websocket_scenario(0x707a1);
        total_scenario.expected_origin = None;
        total_scenario.subprotocol = None;
        total_scenario.frame_delay_ms = 800;
        total_scenario.steps = vec![
            kahea_test_server::WebSocketOracleStep::SendText {
                value: "first".into(),
            },
            kahea_test_server::WebSocketOracleStep::SendText {
                value: "second".into(),
            },
        ];
        let total_oracle = start_websocket_oracle(
            total_scenario,
            WebSocketFaultMode::None,
            WebSocketOracleTransport::Plaintext,
        )
        .unwrap();
        let mut total_plan = plan(
            total_oracle.manifest.url.clone(),
            "net-cidr:127.0.0.1/32".into(),
        );
        total_plan
            .required_grants
            .push("net-insecure-websocket".into());
        // The total deadline is the one under test, and it can only be proven by a wall clock: it
        // has to expire before two delayed frames arrive. It cannot be given headroom, so every
        // margin is widened instead — each frame is delayed well inside its own action budget, and
        // the total budget still expires during the second one.
        total_plan.limits.connect_timeout_ms = 1_200;
        total_plan.limits.action_timeout_ms = 1_200;
        total_plan.limits.idle_timeout_ms = 1_200;
        total_plan.limits.close_timeout_ms = 1_200;
        total_plan.limits.total_timeout_ms = 1_400;
        total_plan.actions = vec![
            WebSocketAction::ExpectText {
                equals: "first".into(),
                timeout_ms: Some(1_200),
            },
            WebSocketAction::ExpectText {
                equals: "second".into(),
                timeout_ms: Some(1_200),
            },
            WebSocketAction::ExpectClose {
                codes: vec![1000],
                reason: None,
                timeout_ms: Some(1_200),
            },
        ];
        let total_plan = total_plan.seal().unwrap();
        let (total_root, total_store) = store();
        let WebSocketConnectResult::Observation(observation) =
            execute_websocket(&total_plan, &options(&total_plan), &total_store).unwrap()
        else {
            panic!("total deadline must return an observation")
        };
        assert_eq!(
            observation.terminal_cause,
            WebSocketTerminalCause::TotalTimeout
        );
        assert_eq!(observation.exit, 3);
        assert_eq!(
            total_oracle.wait().unwrap().case_id,
            "ws-00000000000707a1-none"
        );
        drop(total_store);
        remove_temporary_store(&total_root);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let mut plan = plan(
            format!("ws://{address}/unbound"),
            "net-cidr:127.0.0.1/32".into(),
        );
        plan.required_grants.push("net-insecure-websocket".into());
        let plan = plan.seal().unwrap();
        let (root, store) = store();
        let WebSocketConnectResult::Observation(observation) =
            connect_websocket(&plan, &options(&plan), &store).unwrap()
        else {
            panic!("refused loopback connection must return an observation")
        };
        // A closed loopback port is refused immediately on Unix, while Windows can
        // surface the same bounded `connect_timeout` attempt as a timeout.
        assert!(matches!(
            observation.terminal_cause,
            WebSocketTerminalCause::ConnectionFailure | WebSocketTerminalCause::ConnectTimeout
        ));
        drop(store);
        remove_temporary_store(&root);
    }

    #[test]
    fn ipv6_loopback_handshake_uses_the_exact_runtime_grants() {
        let mut scenario = generate_websocket_scenario(0x1_6);
        scenario.expected_origin = None;
        scenario.subprotocol = None;
        scenario.steps = vec![kahea_test_server::WebSocketOracleStep::SendClose {
            code: 1000,
            reason: "ipv6-complete".into(),
        }];
        let oracle = match start_websocket_oracle_on(
            scenario.clone(),
            WebSocketFaultMode::None,
            WebSocketOracleTransport::Plaintext,
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            0,
        ) {
            Ok(oracle) => oracle,
            Err(error) => {
                eprintln!("skipping IPv6 WebSocket test: {error}");
                return;
            }
        };
        let mut plan = oracle_plan(&oracle.manifest, &scenario);
        plan.actions = vec![WebSocketAction::ExpectClose {
            codes: vec![1000],
            reason: Some("ipv6-complete".into()),
            timeout_ms: Some(10_000),
        }];
        let plan = plan.seal().unwrap();
        let (root, store) = store();
        let WebSocketConnectResult::Observation(observation) =
            execute_websocket(&plan, &options(&plan), &store).unwrap()
        else {
            panic!("expected terminal IPv6 WebSocket observation")
        };
        assert_eq!(
            observation
                .resolved_origin
                .as_deref()
                .unwrap()
                .parse::<SocketAddr>()
                .unwrap()
                .ip(),
            Ipv6Addr::LOCALHOST
        );
        assert_eq!(observation.exit, 0);
        assert_eq!(oracle.wait().unwrap().completed_steps, 1);
        drop(store);
        remove_temporary_store(&root);
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
            let stream = accept_test_connection(&listener);
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
            .additional_root_certificates_pem
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
            let stream = accept_test_connection(&mismatch_listener);
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
            .additional_root_certificates_pem
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
        remove_temporary_store(&root);
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
            .additional_root_certificates_pem
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

    #[test]
    fn executes_ordered_messages_control_frames_and_client_close() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut plan = ws_plan(&listener);
        plan.actions = vec![
            WebSocketAction::SendText {
                text: "hello".into(),
            },
            WebSocketAction::ExpectText {
                equals: "world".into(),
                timeout_ms: None,
            },
            WebSocketAction::SendBinary {
                payload_base64: "AAE=".into(),
            },
            WebSocketAction::ExpectBinary {
                payload_base64: "AgM=".into(),
                timeout_ms: None,
            },
            WebSocketAction::Ping {
                payload_base64: "cGk=".into(),
            },
            WebSocketAction::ExpectPong {
                payload_base64: "cGk=".into(),
                timeout_ms: None,
            },
            WebSocketAction::Close {
                code: 1000,
                reason: "done".into(),
            },
        ];
        let plan = plan.seal().unwrap();
        let server = thread::spawn(move || {
            let mut socket = tungstenite::accept(accept_test_connection(&listener)).unwrap();
            assert_eq!(socket.read().unwrap(), Message::Text("hello".into()));
            socket.send(Message::Text("world".into())).unwrap();
            assert_eq!(
                socket.read().unwrap(),
                Message::Binary(vec![0_u8, 1].into())
            );
            socket.send(Message::Binary(vec![2_u8, 3].into())).unwrap();
            assert_eq!(socket.read().unwrap(), Message::Ping(b"pi".to_vec().into()));
            socket.flush().unwrap();
            assert!(matches!(socket.read().unwrap(), Message::Close(Some(_))));
            let _ = socket.flush();
        });
        let (root, store) = store();
        let WebSocketConnectResult::Observation(observation) =
            execute_websocket(&plan, &options(&plan), &store).unwrap()
        else {
            panic!("execution must return an observation")
        };
        assert_eq!(observation.exit, 0);
        assert_eq!(
            observation.terminal_cause,
            WebSocketTerminalCause::Completed
        );
        assert_eq!(observation.counters.inbound_frames, 4);
        assert_eq!(observation.counters.outbound_frames, 4);
        assert_eq!(observation.counters.inbound_messages, 2);
        assert_eq!(observation.counters.outbound_messages, 2);
        let transcript_handle = observation
            .transcript
            .as_deref()
            .expect("completed sessions reference transcript evidence");
        let transcript: Value =
            serde_json::from_slice(&store.get(transcript_handle).unwrap().data).unwrap();
        let entries = transcript["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 8);
        assert!(entries.iter().enumerate().all(|(sequence, entry)| {
            entry["sequence"] == sequence && entry["payload"].as_str().is_some()
        }));
        assert_eq!(entries[1]["action_index"], 1);
        assert_eq!(entries[1]["check"], "matched");
        assert_eq!(entries[5]["kind"], "pong");
        assert_eq!(entries[5]["check"], "matched");
        for (index, expected) in [(2, &[0_u8, 1][..]), (3, &[2_u8, 3][..])] {
            let handle = entries[index]["payload"].as_str().unwrap();
            let record = store.get(handle).unwrap();
            assert_eq!(record.envelope.media_type, "application/octet-stream");
            assert_eq!(record.data, expected);
        }
        assert_eq!(
            observation.close,
            Some(WebSocketCloseObservation {
                initiator: WebSocketCloseInitiator::Client,
                code: 1000,
                reason: "done".into(),
            })
        );
        server.join().unwrap();
        drop(store);
        remove_temporary_store(&root);
    }

    #[test]
    fn fragmented_message_and_interleaved_ping_are_reassembled_and_counted() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut plan = ws_plan(&listener);
        plan.actions = vec![
            WebSocketAction::ExpectText {
                equals: "hello".into(),
                timeout_ms: None,
            },
            WebSocketAction::ExpectClose {
                codes: vec![1000],
                reason: Some("finished".into()),
                timeout_ms: None,
            },
        ];
        let plan = plan.seal().unwrap();
        let server = thread::spawn(move || {
            let mut socket = tungstenite::accept(accept_test_connection(&listener)).unwrap();
            socket
                .write(Message::Frame(Frame::message(
                    b"hel".to_vec(),
                    OpCode::Data(Data::Text),
                    false,
                )))
                .unwrap();
            socket.write(Message::Ping(b"x".to_vec().into())).unwrap();
            socket
                .write(Message::Frame(Frame::message(
                    b"lo".to_vec(),
                    OpCode::Data(Data::Continue),
                    true,
                )))
                .unwrap();
            socket
                .write(Message::Close(Some(CloseFrame {
                    code: CloseCode::Normal,
                    reason: "finished".into(),
                })))
                .unwrap();
            socket.flush().unwrap();
            assert_eq!(socket.read().unwrap(), Message::Pong(b"x".to_vec().into()));
            assert!(matches!(socket.read().unwrap(), Message::Close(Some(_))));
        });
        let (root, store) = store();
        let WebSocketConnectResult::Observation(observation) =
            execute_websocket(&plan, &options(&plan), &store).unwrap()
        else {
            panic!("execution must return an observation")
        };
        assert_eq!(observation.exit, 0);
        assert_eq!(observation.counters.inbound_frames, 4);
        assert_eq!(observation.counters.inbound_messages, 1);
        assert_eq!(observation.counters.outbound_frames, 2);
        assert_eq!(observation.counters.outbound_messages, 0);
        assert_eq!(observation.counters.inbound_bytes, 16);
        assert_eq!(observation.counters.outbound_bytes, 11);
        assert_eq!(observation.close.unwrap().reason, "finished");
        server.join().unwrap();
        drop(store);
        remove_temporary_store(&root);
    }

    #[test]
    fn fragmented_transcript_payloads_are_redacted_before_stable_persistence() {
        const SECRET: &str = "split-secret-value";
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut plan = ws_plan(&listener);
        plan.redact_response_json_pointers = vec!["/private".into()];
        plan.actions = vec![
            WebSocketAction::ExpectJson {
                pointer: Some("/ok".into()),
                equals: Some(Value::Bool(true)),
                schema: None,
                timeout_ms: None,
            },
            WebSocketAction::ExpectClose {
                codes: vec![1000],
                reason: None,
                timeout_ms: None,
            },
        ];
        let plan = plan.seal().unwrap();
        let server = thread::spawn(move || {
            let mut socket = tungstenite::accept(accept_test_connection(&listener)).unwrap();
            socket
                .write(Message::Frame(Frame::message(
                    br#"{"token":"split-"#.to_vec(),
                    OpCode::Data(Data::Text),
                    false,
                )))
                .unwrap();
            socket
                .write(Message::Ping(b"audit".to_vec().into()))
                .unwrap();
            socket
                .write(Message::Frame(Frame::message(
                    br#"secret-value","private":"keep-out","ok":true}"#.to_vec(),
                    OpCode::Data(Data::Continue),
                    true,
                )))
                .unwrap();
            socket
                .write(Message::Close(Some(CloseFrame {
                    code: CloseCode::Normal,
                    reason: format!("bye {SECRET}").into(),
                })))
                .unwrap();
            socket.flush().unwrap();
            assert_eq!(
                socket.read().unwrap(),
                Message::Pong(b"audit".to_vec().into())
            );
            assert!(matches!(socket.read().unwrap(), Message::Close(Some(_))));
        });
        let (root, store) = store();
        let mut invoke_options = options(&plan);
        invoke_options
            .secrets
            .insert("runtime-profile".into(), SECRET.into());
        let WebSocketConnectResult::Observation(observation) =
            execute_websocket(&plan, &invoke_options, &store).unwrap()
        else {
            panic!("execution must return an observation")
        };
        assert_eq!(observation.exit, 0);
        assert_eq!(observation.close.as_ref().unwrap().reason, "bye [REDACTED]");
        assert!(
            !serde_json::to_vec(&plan)
                .unwrap()
                .windows(SECRET.len())
                .any(|window| window == SECRET.as_bytes())
        );
        assert!(
            !serde_json::to_vec(&observation)
                .unwrap()
                .windows(SECRET.len())
                .any(|window| window == SECRET.as_bytes())
        );

        let transcript_handle = observation.transcript.as_deref().unwrap();
        let transcript_record = store.get(transcript_handle).unwrap();
        let transcript: Value = serde_json::from_slice(&transcript_record.data).unwrap();
        let entries = transcript["entries"].as_array().unwrap();
        assert!(
            entries
                .iter()
                .enumerate()
                .all(|(sequence, entry)| entry["sequence"] == sequence)
        );
        let message = entries
            .iter()
            .find(|entry| entry["kind"] == "text")
            .unwrap();
        assert_eq!(message["action_index"], 0);
        assert_eq!(message["check"], "matched");
        let message_handle = message["payload"].as_str().unwrap();
        let message_record = store.get(message_handle).unwrap();
        assert_eq!(message_record.envelope.media_type, "application/json");
        let message_json: Value = serde_json::from_slice(&message_record.data).unwrap();
        assert_eq!(message_json["token"], "[REDACTED]");
        assert_eq!(message_json["private"], "[REDACTED]");
        assert_eq!(
            store.explain(message_handle, Some("/ok")).unwrap().value,
            Some(Value::Bool(true))
        );
        assert!(
            store
                .explain(transcript_handle, Some("/entries/0"))
                .unwrap()
                .value
                .is_some()
        );
        for handle in entries
            .iter()
            .filter_map(|entry| entry["payload"].as_str())
            .chain(observation.trace.iter().map(String::as_str))
            .chain(observation.handshake.iter().map(String::as_str))
        {
            assert!(
                !store
                    .get(handle)
                    .unwrap()
                    .data
                    .windows(SECRET.len())
                    .any(|window| window == SECRET.as_bytes())
            );
        }
        let stable_transcript = || Transcript {
            entries: vec![TranscriptEntry {
                direction: "inbound",
                kind: "text",
                bytes: SECRET.len() as u64,
                action_index: Some(0),
                check: "matched",
                code: None,
                payload_kind: Some(TranscriptPayloadKind::Text),
                payload: Some(SECRET.as_bytes().to_vec()),
            }],
        };
        let first = stable_transcript();
        let duplicate = store_transcript(
            &plan,
            &store,
            &first,
            &[SECRET.as_bytes().to_vec()],
            Outcome::Passed,
            WebSocketTerminalCause::Completed,
            0,
        )
        .unwrap();
        let second = stable_transcript();
        let duplicate_again = store_transcript(
            &plan,
            &store,
            &second,
            &[SECRET.as_bytes().to_vec()],
            Outcome::Passed,
            WebSocketTerminalCause::Completed,
            0,
        )
        .unwrap();
        assert_eq!(duplicate.handle, duplicate_again.handle);
        assert_files_absent(&root, SECRET.as_bytes());
        server.join().unwrap();
        drop(store);
        remove_temporary_store(&root);
    }

    /// The precedence rule itself, which is the part a socket test cannot pin down.
    ///
    /// Whether the acknowledging write fails depends on when the peer's reset lands, so the
    /// interesting branch appears only on some runs and some platforms — that is exactly how this
    /// arrived as a macOS-only CI flake. The truth table is deterministic even though the race is
    /// not.
    #[test]
    fn a_close_verdict_outranks_a_failure_to_acknowledge_it() {
        assert_eq!(close_precedence(true, true), ClosePrecedence::Accepted);
        assert_eq!(
            close_precedence(true, false),
            ClosePrecedence::NotAcknowledged,
            "with nothing to report about the close itself, the I/O failure is the result"
        );
        for acknowledged in [true, false] {
            assert_eq!(
                close_precedence(false, acknowledged),
                ClosePrecedence::Rejected,
                "an unacceptable close code is the diagnosis whether or not the reply landed"
            );
        }
    }

    /// End-to-end cover for the same path against a server that closes abruptly.
    ///
    /// This exercises the ordinary ordering rather than the reset; the branch where the
    /// acknowledgement fails is covered by the truth table above, because forcing a reset portably
    /// needs `SO_LINGER`, which is not stable.
    #[test]
    fn an_unacceptable_close_code_fails_the_expectation_when_the_peer_hangs_up() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut plan = ws_plan(&listener);
        plan.actions = vec![WebSocketAction::ExpectClose {
            codes: vec![1000],
            reason: None,
            timeout_ms: None,
        }];
        let plan = plan.seal().unwrap();
        let server = thread::spawn(move || {
            let stream = accept_test_connection(&listener);
            let raw = stream.try_clone().unwrap();
            let mut socket = tungstenite::accept(stream).unwrap();
            // 1005 is a reserved sentinel the plan cannot accept.
            socket
                .write(Message::Frame(Frame::close(Some(CloseFrame {
                    code: CloseCode::from(1005),
                    reason: "".into(),
                }))))
                .unwrap();
            socket.flush().unwrap();
            let mut pending = [0_u8; 1];
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                match raw.peek(&mut pending) {
                    Ok(0) => break,
                    Ok(_) => break,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => break,
                }
            }
            drop(socket);
        });
        let (root, store) = store();
        let WebSocketConnectResult::Observation(observation) =
            execute_websocket(&plan, &options(&plan), &store).unwrap()
        else {
            panic!("a reset close must still return an observation")
        };
        assert_eq!(
            observation.terminal_cause,
            WebSocketTerminalCause::ExpectationFailed,
            "the close code is the diagnosis, not the failure to acknowledge it"
        );
        assert_eq!(observation.exit, 1);
        // 1005 never reaches the plan as itself: the client library rejects the reserved sentinel
        // and reports the close as 1002, which is what the plan then declines.
        assert_eq!(
            observation.close.as_ref().map(|close| close.code),
            Some(1002)
        );
        server.join().unwrap();
        drop(store);
        remove_temporary_store(&root);
    }

    #[test]
    fn unexpected_data_and_fragment_budget_exhaustion_fail_without_scanning() {
        let mismatch_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut mismatch_plan = ws_plan(&mismatch_listener);
        mismatch_plan.actions = vec![
            WebSocketAction::ExpectText {
                equals: "expected".into(),
                timeout_ms: None,
            },
            WebSocketAction::ExpectClose {
                codes: vec![1000],
                reason: None,
                timeout_ms: None,
            },
        ];
        let mismatch_plan = mismatch_plan.seal().unwrap();
        let mismatch_server = thread::spawn(move || {
            let mut socket =
                tungstenite::accept(accept_test_connection(&mismatch_listener)).unwrap();
            socket.send(Message::Binary(vec![7_u8].into())).unwrap();
        });
        let (root, store) = store();
        let WebSocketConnectResult::Observation(observation) =
            execute_websocket(&mismatch_plan, &options(&mismatch_plan), &store).unwrap()
        else {
            panic!("mismatch must return an observation")
        };
        assert_eq!(observation.exit, 1);
        assert_eq!(
            observation.terminal_cause,
            WebSocketTerminalCause::ExpectationFailed
        );
        assert_eq!(observation.counters.inbound_messages, 1);
        mismatch_server.join().unwrap();

        let budget_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut budget_plan = ws_plan(&budget_listener);
        budget_plan.limits.max_inbound_frames = 1;
        budget_plan.actions = vec![
            WebSocketAction::ExpectText {
                equals: "hello".into(),
                timeout_ms: None,
            },
            WebSocketAction::ExpectClose {
                codes: vec![1000],
                reason: None,
                timeout_ms: None,
            },
        ];
        let budget_plan = budget_plan.seal().unwrap();
        let budget_server = thread::spawn(move || {
            let mut socket = tungstenite::accept(accept_test_connection(&budget_listener)).unwrap();
            let mut wire = Vec::new();
            Frame::message(b"hel".to_vec(), OpCode::Data(Data::Text), false)
                .format(&mut wire)
                .unwrap();
            Frame::message(b"lo".to_vec(), OpCode::Data(Data::Continue), true)
                .format(&mut wire)
                .unwrap();
            socket.get_mut().write_all(&wire).unwrap();
            socket.get_mut().flush().unwrap();
            // Keep the peer alive long enough for kernels that discard unread data on an
            // immediate close to deliver both deliberately over-budget frames.
            thread::sleep(Duration::from_millis(100));
        });
        let WebSocketConnectResult::Observation(observation) =
            execute_websocket(&budget_plan, &options(&budget_plan), &store).unwrap()
        else {
            panic!("budget failure must return an observation")
        };
        assert_eq!(
            observation.terminal_cause,
            WebSocketTerminalCause::BudgetExhausted
        );
        assert_eq!(observation.exit, 1);
        assert_eq!(observation.counters.inbound_frames, 1);
        budget_server.join().unwrap();
        drop(store);
        remove_temporary_store(&root);
    }

    #[test]
    fn extended_frame_lengths_and_invalid_text_fail_closed() {
        for (maximum, payload_bytes) in [(125_u64, 126_usize), (65_535, 65_536)] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let mut plan = ws_plan(&listener);
            plan.limits.max_frame_bytes = maximum;
            plan.actions = vec![
                WebSocketAction::ExpectBinary {
                    payload_base64: "AA==".into(),
                    timeout_ms: None,
                },
                WebSocketAction::ExpectClose {
                    codes: vec![1000],
                    reason: None,
                    timeout_ms: None,
                },
            ];
            let plan = plan.seal().unwrap();
            let server = thread::spawn(move || {
                let mut socket = tungstenite::accept(accept_test_connection(&listener)).unwrap();
                let mut wire = Vec::new();
                Frame::message(vec![0_u8; payload_bytes], OpCode::Data(Data::Binary), true)
                    .format(&mut wire)
                    .unwrap();
                let _ = socket.get_mut().write_all(&wire);
                let _ = socket.get_mut().flush();
                thread::sleep(Duration::from_millis(50));
            });
            let (root, store) = store();
            let WebSocketConnectResult::Observation(observation) =
                execute_websocket(&plan, &options(&plan), &store).unwrap()
            else {
                panic!("oversized frame must return an observation")
            };
            assert_eq!(
                observation.terminal_cause,
                WebSocketTerminalCause::BudgetExhausted
            );
            assert_eq!(observation.exit, 1);
            assert_eq!(observation.counters.inbound_frames, 0);
            server.join().unwrap();
            drop(store);
            remove_temporary_store(&root);
        }

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut plan = ws_plan(&listener);
        plan.actions = vec![
            WebSocketAction::ExpectText {
                equals: "valid".into(),
                timeout_ms: None,
            },
            WebSocketAction::ExpectClose {
                codes: vec![1000],
                reason: None,
                timeout_ms: None,
            },
        ];
        let plan = plan.seal().unwrap();
        let server = thread::spawn(move || {
            let mut socket = tungstenite::accept(accept_test_connection(&listener)).unwrap();
            let mut wire = Vec::new();
            Frame::message(vec![0xff], OpCode::Data(Data::Text), true)
                .format(&mut wire)
                .unwrap();
            socket.get_mut().write_all(&wire).unwrap();
            socket.get_mut().flush().unwrap();
            thread::sleep(Duration::from_millis(50));
        });
        let (root, store) = store();
        let WebSocketConnectResult::Observation(observation) =
            execute_websocket(&plan, &options(&plan), &store).unwrap()
        else {
            panic!("invalid UTF-8 must return an observation")
        };
        assert_eq!(
            observation.terminal_cause,
            WebSocketTerminalCause::ProtocolViolation
        );
        assert_eq!(observation.exit, 3);
        assert_eq!(observation.counters.inbound_frames, 1);
        assert_eq!(observation.counters.inbound_bytes, 1);
        server.join().unwrap();
        drop(store);
        remove_temporary_store(&root);
    }

    #[test]
    fn json_expectations_and_deadline_precedence_are_deterministic() {
        let action = WebSocketAction::ExpectJson {
            pointer: Some("/payload".into()),
            equals: Some(json!({"id": 7})),
            schema: Some(json!({
                "type": "object",
                "required": ["id"],
                "properties": {"id": {"type": "integer", "minimum": 1}},
                "additionalProperties": false
            })),
            timeout_ms: None,
        };
        assert!(expectation_matches_text(&action, r#"{"payload":{"id":7}}"#));
        assert!(!expectation_matches_text(
            &action,
            r#"{"payload":{"id":0}}"#
        ));
        assert!(!expectation_matches_text(&action, "not-json"));

        let origin = Instant::now();
        assert_eq!(
            bounded_total_deadline(origin, 250, Duration::MAX),
            deadline(origin, 250)
        );
        assert_eq!(
            bounded_total_deadline(origin, 250, Duration::from_millis(50)),
            origin + Duration::from_millis(50)
        );
        assert_eq!(
            select_deadline(
                origin + Duration::from_millis(30),
                origin + Duration::from_millis(20),
                origin + Duration::from_millis(10),
                WebSocketTerminalCause::CloseTimeout,
            )
            .1,
            WebSocketTerminalCause::IdleTimeout
        );
        assert_eq!(
            select_deadline(
                origin + Duration::from_millis(30),
                origin + Duration::from_millis(10),
                origin + Duration::from_millis(20),
                WebSocketTerminalCause::CloseTimeout,
            )
            .1,
            WebSocketTerminalCause::CloseTimeout
        );
        assert_eq!(
            select_deadline(
                origin + Duration::from_millis(10),
                origin + Duration::from_millis(10),
                origin + Duration::from_millis(10),
                WebSocketTerminalCause::ActionTimeout,
            )
            .1,
            WebSocketTerminalCause::TotalTimeout
        );
    }

    #[test]
    fn cancellation_interrupts_a_silent_session_and_emits_one_terminal_observation() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut plan = ws_plan(&listener);
        plan.limits.action_timeout_ms = 1_000;
        plan.limits.idle_timeout_ms = 1_000;
        plan.actions = vec![
            WebSocketAction::ExpectText {
                equals: "never".into(),
                timeout_ms: None,
            },
            WebSocketAction::ExpectClose {
                codes: vec![1000],
                reason: None,
                timeout_ms: None,
            },
        ];
        let plan = plan.seal().unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (server_done_tx, server_done_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let _socket = tungstenite::accept(accept_test_connection(&listener)).unwrap();
            ready_tx.send(()).unwrap();
            server_done_rx.recv().unwrap();
        });
        let cancellation = WebSocketCancellation::default();
        let trigger = cancellation.clone();
        let canceller = thread::spawn(move || {
            ready_rx.recv().unwrap();
            thread::sleep(Duration::from_millis(40));
            trigger.cancel();
        });
        let (root, store) = store();
        let WebSocketConnectResult::Observation(observation) =
            execute_websocket_with_cancellation(&plan, &options(&plan), &store, &cancellation)
                .unwrap()
        else {
            panic!("cancellation must return an observation")
        };
        server_done_tx.send(()).unwrap();
        assert_eq!(observation.exit, 3);
        assert_eq!(
            observation.terminal_cause,
            WebSocketTerminalCause::Cancelled
        );
        assert!(cancellation.is_cancelled());
        canceller.join().unwrap();
        server.join().unwrap();
        drop(store);
        remove_temporary_store(&root);
    }
}
