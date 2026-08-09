use clap::{Parser, ValueEnum};
use kahea_test_server::{
    FaultMode, ServerError, WebSocketFaultMode, WebSocketOracleTransport, generate_scenario,
    generate_websocket_scenario, openapi_document, start_server_on, start_websocket_oracle_on,
};
use std::fs;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Parser)]
#[command(
    name = "kahea-test-server",
    about = "Seeded loopback HTTP and WebSocket conformance oracle"
)]
struct Cli {
    /// Oracle protocol. HTTP remains the compatibility default.
    #[arg(long, value_enum, default_value_t = ProtocolArg::Http)]
    protocol: ProtocolArg,
    /// Reproduce one exact API. Defaults to a new seed on every startup.
    #[arg(long)]
    seed: Option<u64>,
    /// Loopback port. Zero asks the OS for an unused port.
    #[arg(long, default_value_t = 0)]
    port: u16,
    /// HTTP oracle fault to inject.
    #[arg(long, value_enum)]
    fault: Option<FaultArg>,
    /// WebSocket protocol or transport fault to inject.
    #[arg(long, value_enum)]
    websocket_fault: Option<WebSocketFaultMode>,
    /// Serve the WebSocket oracle over controlled plaintext or self-signed TLS.
    #[arg(long, value_enum)]
    websocket_transport: Option<WebSocketOracleTransport>,
    /// Loopback interface for the WebSocket oracle (for example 127.0.0.1 or ::1).
    #[arg(long)]
    websocket_interface: Option<IpAddr>,
    /// Write the exact OpenAPI document served by this process.
    #[arg(long)]
    write_openapi: Option<PathBuf>,
    /// Write the startup manifest atomically for lifecycle harnesses.
    #[arg(long)]
    write_manifest: Option<PathBuf>,
    /// Write the terminal seeded WebSocket oracle observation after one case.
    #[arg(long)]
    write_observation: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProtocolArg {
    Http,
    Websocket,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FaultArg {
    None,
    AcceptInvalid,
    MalformedResponse,
    ServerError,
    UndocumentedStatus,
}

impl From<FaultArg> for FaultMode {
    fn from(value: FaultArg) -> Self {
        match value {
            FaultArg::None => Self::None,
            FaultArg::AcceptInvalid => Self::AcceptInvalid,
            FaultArg::MalformedResponse => Self::MalformedResponse,
            FaultArg::ServerError => Self::ServerError,
            FaultArg::UndocumentedStatus => Self::UndocumentedStatus,
        }
    }
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("kahea-test-server: {error}");
        std::process::exit(2);
    }
}

fn run(cli: Cli) -> Result<(), ServerError> {
    validate_protocol_options(&cli)?;
    let seed = cli.seed.unwrap_or_else(startup_seed);
    match cli.protocol {
        ProtocolArg::Http => run_http(cli, seed),
        ProtocolArg::Websocket => run_websocket(cli, seed),
    }
}

fn validate_protocol_options(cli: &Cli) -> Result<(), ServerError> {
    let incompatible = match cli.protocol {
        ProtocolArg::Http => [
            cli.websocket_fault.map(|_| "--websocket-fault"),
            cli.websocket_transport.map(|_| "--websocket-transport"),
            cli.websocket_interface.map(|_| "--websocket-interface"),
        ]
        .into_iter()
        .flatten()
        .next(),
        ProtocolArg::Websocket => cli.fault.map(|_| "--fault"),
    };
    if let Some(option) = incompatible {
        return Err(ServerError::InvalidRequest(format!(
            "{option} is incompatible with --protocol {}",
            match cli.protocol {
                ProtocolArg::Http => "http",
                ProtocolArg::Websocket => "websocket",
            }
        )));
    }
    Ok(())
}

fn run_http(cli: Cli, seed: u64) -> Result<(), ServerError> {
    if cli.write_observation.is_some() {
        return Err(ServerError::InvalidRequest(
            "--write-observation is available only for the WebSocket oracle".into(),
        ));
    }
    let scenario = generate_scenario(seed);
    let server = start_server_on(
        scenario.clone(),
        cli.fault.unwrap_or(FaultArg::None).into(),
        cli.port,
    )?;
    let openapi = openapi_document(&scenario, &server.manifest.base_url);
    if let Some(path) = cli.write_openapi.as_deref() {
        write_atomic(path, &serde_json::to_vec(&openapi)?)?;
    }
    if let Some(path) = cli.write_manifest.as_deref() {
        write_atomic(path, &serde_json::to_vec(&server.manifest)?)?;
    }
    serde_json::to_writer(io::stdout().lock(), &server.manifest)?;
    io::stdout().lock().write_all(b"\n")?;
    io::stdout().lock().flush()?;
    server.wait()
}

fn run_websocket(cli: Cli, seed: u64) -> Result<(), ServerError> {
    if cli.write_openapi.is_some() {
        return Err(ServerError::InvalidRequest(
            "--write-openapi is available only for the HTTP oracle".into(),
        ));
    }
    let scenario = generate_websocket_scenario(seed);
    let server = start_websocket_oracle_on(
        scenario,
        cli.websocket_fault.unwrap_or(WebSocketFaultMode::None),
        cli.websocket_transport
            .unwrap_or(WebSocketOracleTransport::Plaintext),
        cli.websocket_interface
            .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        cli.port,
    )?;
    if let Some(path) = cli.write_manifest.as_deref() {
        write_atomic(path, &serde_json::to_vec(&server.manifest)?)?;
    }
    serde_json::to_writer(io::stdout().lock(), &server.manifest)?;
    io::stdout().lock().write_all(b"\n")?;
    io::stdout().lock().flush()?;
    let observation = server.wait()?;
    if let Some(path) = cli.write_observation.as_deref() {
        write_atomic(path, &serde_json::to_vec(&observation)?)?;
    }
    Ok(())
}

fn startup_seed() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    (nanos as u64) ^ ((nanos >> 64) as u64) ^ u64::from(std::process::id())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ServerError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, bytes)?;
    fs::rename(temporary, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(arguments: &[&str]) -> Cli {
        Cli::try_parse_from(arguments).expect("test CLI must parse")
    }

    #[test]
    fn protocol_specific_options_fail_closed() {
        for arguments in [
            ["kahea-test-server", "--websocket-fault", "invalid-utf8"].as_slice(),
            ["kahea-test-server", "--websocket-transport", "tls"].as_slice(),
            ["kahea-test-server", "--websocket-interface", "::1"].as_slice(),
            [
                "kahea-test-server",
                "--protocol",
                "websocket",
                "--fault",
                "server-error",
            ]
            .as_slice(),
        ] {
            assert!(validate_protocol_options(&parse(arguments)).is_err());
        }
    }

    #[test]
    fn websocket_interface_accepts_both_loopback_families() {
        for interface in ["127.0.0.1", "::1"] {
            let cli = parse(&[
                "kahea-test-server",
                "--protocol",
                "websocket",
                "--websocket-interface",
                interface,
            ]);
            validate_protocol_options(&cli).unwrap();
            assert!(
                cli.websocket_interface
                    .is_some_and(|value| value.is_loopback())
            );
        }
    }
}
