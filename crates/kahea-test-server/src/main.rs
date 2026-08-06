use clap::{Parser, ValueEnum};
use kahea_test_server::{
    FaultMode, ServerError, generate_scenario, openapi_document, start_server_on,
};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Parser)]
#[command(
    name = "kahea-test-server",
    about = "Seeded high-entropy loopback API oracle"
)]
struct Cli {
    /// Reproduce one exact API. Defaults to a new seed on every startup.
    #[arg(long)]
    seed: Option<u64>,
    /// Loopback port. Zero asks the OS for an unused port.
    #[arg(long, default_value_t = 0)]
    port: u16,
    #[arg(long, value_enum, default_value_t = FaultArg::None)]
    fault: FaultArg,
    /// Write the exact OpenAPI document served by this process.
    #[arg(long)]
    write_openapi: Option<PathBuf>,
    /// Write the startup manifest atomically for lifecycle harnesses.
    #[arg(long)]
    write_manifest: Option<PathBuf>,
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
    let seed = cli.seed.unwrap_or_else(startup_seed);
    let scenario = generate_scenario(seed);
    let server = start_server_on(scenario.clone(), cli.fault.into(), cli.port)?;
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
