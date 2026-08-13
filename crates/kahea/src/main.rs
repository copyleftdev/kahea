use clap::{Parser, Subcommand, ValueEnum};
use kahea_conformance::{
    ConformanceMode, ConformanceOptions, build_conformance_plan, invoke_conformance,
    load_conformance_plan, store_conformance_plan,
};
use kahea_core::{
    DEFAULT_OPERATION_LIMIT, DescribeEnvelope, ErrorEnvelope, PROTOCOL, SchemaEnvelope, VERSION,
    default_config_fingerprint, public_schema, write_envelope,
};
use kahea_evidence::EvidenceStore;
use kahea_exec::{
    ExecError, InvocationResult, InvokeOptions, WebSocketConnectResult, execute_websocket, invoke,
};
use kahea_ingest::{
    inspect_asyncapi, inspect_source, is_asyncapi, load_source, parse_data_document,
    read_source_artifact, resolve_operation,
};
use kahea_plan::{
    PlanOptions, ProjectConfiguration, build_asyncapi_websocket_plan_with_configuration,
    build_plan_with_configuration, build_websocket_plan_with_configuration,
    inspect_websocket_session, is_websocket_session, load_plan, load_websocket_plan,
    parse_explicit_field, store_plan, store_websocket_plan,
};
use kahea_workflow::{
    build_workflow_plan, inspect_workflows, invoke_workflow, is_arazzo, load_workflow_plan,
    store_workflow_plan,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(name = "kahea", version, about = "The Agentic Invocation Kernel")]
struct Cli {
    /// Stable machine output. A single JSON envelope is also one valid NDJSON record.
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Json)]
    format: OutputFormat,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Json,
    Ndjson,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ConformanceModeArg {
    Positive,
    Negative,
    Mixed,
}

impl From<ConformanceModeArg> for ConformanceMode {
    fn from(value: ConformanceModeArg) -> Self {
        match value {
            ConformanceModeArg::Positive => Self::Positive,
            ConformanceModeArg::Negative => Self::Negative,
            ConformanceModeArg::Mixed => Self::Mixed,
        }
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Describe the executable protocol and available capabilities.
    Describe,
    /// Emit JSON Schema for a public kahea/k1 envelope.
    Schema {
        /// A public k1 envelope name (for example plan, observation, or workflow-plan).
        kind: String,
    },
    /// Inspect a supported local API, workflow, or WebSocket source without network access.
    Inspect {
        source: PathBuf,
        #[arg(long, value_name = "QUERY")]
        r#match: Option<String>,
        #[arg(long, default_value_t = DEFAULT_OPERATION_LIMIT)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        cursor: usize,
    },
    /// Build and seal an exact HTTP, workflow, or WebSocket plan without network access.
    Plan {
        source: PathBuf,
        operation: String,
        #[arg(long, value_name = "FILE")]
        input: Option<String>,
        #[arg(long = "set", value_name = "LOCATION.NAME=VALUE")]
        explicit: Vec<String>,
        #[arg(long, value_name = "URL_OR_DESCRIPTION")]
        server: Option<String>,
        #[arg(long, value_name = "PROFILE_OR_SCHEME=PROFILE")]
        auth: Option<String>,
        #[arg(long)]
        content_type: Option<String>,
        #[arg(long = "check")]
        checks: Vec<String>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, default_value = ".kahea")]
        store: PathBuf,
    },
    /// Generate and seal a deterministic OpenAPI conformance campaign without network access.
    Conform {
        source: PathBuf,
        operation: String,
        /// Baseline values that the generator must preserve, useful for resource identifiers.
        #[arg(long, value_name = "FILE")]
        input: Option<String>,
        #[arg(long = "set", value_name = "LOCATION.NAME=VALUE")]
        explicit: Vec<String>,
        #[arg(long, value_name = "URL_OR_DESCRIPTION")]
        server: Option<String>,
        #[arg(long, value_name = "PROFILE_OR_SCHEME=PROFILE")]
        auth: Option<String>,
        #[arg(long)]
        content_type: Option<String>,
        #[arg(long = "check")]
        checks: Vec<String>,
        #[arg(long, default_value_t = 32)]
        cases: usize,
        #[arg(long, default_value_t = 0)]
        seed: u64,
        #[arg(long, value_enum, default_value_t = ConformanceModeArg::Mixed)]
        mode: ConformanceModeArg,
        /// Delay between requests when this campaign is invoked.
        #[arg(long, default_value_t = 0)]
        delay_ms: u64,
        /// Stop campaign execution after this many findings.
        #[arg(long, default_value_t = 10)]
        max_failures: usize,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, default_value = ".kahea")]
        store: PathBuf,
    },
    /// Execute a sealed plan under explicit capability grants.
    Invoke {
        /// A plan handle from --store, or a path to a sealed plan JSON file.
        plan: String,
        /// Capability grant, repeatable (for example net:api.example.com:443).
        #[arg(long = "grant", value_name = "CAPABILITY")]
        grants: Vec<String>,
        /// Resolve a secret profile from an environment variable: PROFILE=ENV_VAR.
        #[arg(long = "secret-env", value_name = "PROFILE=ENV_VAR")]
        secret_env: Vec<String>,
        #[arg(long, default_value_t = 30_000)]
        timeout_ms: u64,
        #[arg(long, default_value_t = 16 * 1024 * 1024)]
        max_response_bytes: u64,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, default_value = ".kahea")]
        store: PathBuf,
    },
    /// Resolve local evidence, optionally selecting only the needed value.
    Explain {
        handle: String,
        /// JSON Pointer, RFC 9535 JSONPath, XPath, header:NAME, or bytes:START-END.
        #[arg(long)]
        select: Option<String>,
        /// Export this evidence and all referenced records as a self-contained JSON bundle.
        #[arg(long)]
        export: Option<PathBuf>,
        #[arg(long, default_value = ".kahea")]
        store: PathBuf,
    },
    /// Run the thin Model Context Protocol adapter.
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
}

#[derive(Debug, Subcommand)]
enum McpCommand {
    /// Serve newline-delimited JSON-RPC over standard input/output.
    Serve {
        #[arg(long, default_value_t = true)]
        stdio: bool,
        /// Store root every tool call reads and writes. Tool arguments cannot relocate it.
        #[arg(long, default_value = ".kahea")]
        store: PathBuf,
        /// Configuration file whose policy every plan is measured against.
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(exit) => ExitCode::from(exit),
        Err(error) => {
            let mut envelope = ErrorEnvelope::invalid(error.code, error.message);
            envelope.exit = error.exit;
            let _ = write_envelope(&envelope);
            ExitCode::from(error.exit)
        }
    }
}

#[derive(Debug)]
struct CliError {
    code: &'static str,
    message: String,
    exit: u8,
}

fn run(cli: Cli) -> Result<u8, CliError> {
    let _format = cli.format;
    match cli.command {
        Command::Describe => write_envelope(&DescribeEnvelope::current())
            .map(|()| 0)
            .map_err(io_error),
        Command::Schema { kind } => {
            let normalized = kind.to_ascii_lowercase();
            let schema = public_schema(&normalized).ok_or_else(|| CliError {
                code: "unknown-schema",
                message: format!("unknown public schema {kind:?}"),
                exit: 2,
            })?;
            write_envelope(&SchemaEnvelope {
                protocol: PROTOCOL.into(),
                kind: "schema".into(),
                version: VERSION.into(),
                config_fingerprint: default_config_fingerprint(),
                name: normalized,
                schema,
                exit: 0,
            })
            .map(|()| 0)
            .map_err(io_error)
        }
        Command::Inspect {
            source,
            r#match,
            limit,
            cursor,
        } => {
            if !(1..=1000).contains(&limit) {
                return Err(CliError {
                    code: "invalid-limit",
                    message: "--limit must be between 1 and 1000".into(),
                    exit: 2,
                });
            }
            let bytes = read_source(&source, "source-read-failed")?;
            let parsed = parse_data_document(&source, &bytes).ok();
            let envelope = if parsed.as_ref().is_some_and(is_websocket_session) {
                inspect_websocket_session(&source, &bytes, r#match.as_deref(), limit, cursor)
                    .map_err(|error| CliError {
                        code: "invalid-source",
                        message: error.to_string(),
                        exit: 2,
                    })?
            } else if parsed.as_ref().is_some_and(is_asyncapi) {
                inspect_asyncapi(&source, &bytes, r#match.as_deref(), limit, cursor).map_err(
                    |error| CliError {
                        code: "invalid-source",
                        message: error.to_string(),
                        exit: 2,
                    },
                )?
            } else if parsed.as_ref().is_some_and(is_arazzo) {
                inspect_workflows(
                    parsed.as_ref().expect("checked"),
                    &bytes,
                    r#match.as_deref(),
                    limit,
                    cursor,
                )
                .map_err(|error| CliError {
                    code: "invalid-source",
                    message: error.to_string(),
                    exit: 2,
                })?
            } else {
                inspect_source(&source, &bytes, r#match.as_deref(), limit, cursor).map_err(
                    |error| CliError {
                        code: "invalid-source",
                        message: error.to_string(),
                        exit: 2,
                    },
                )?
            };
            write_envelope(&envelope).map(|()| 0).map_err(io_error)
        }
        Command::Plan {
            source,
            operation,
            input,
            explicit,
            server,
            auth,
            content_type,
            checks,
            config,
            store,
        } => {
            let source_bytes = read_source(&source, "source-read-failed")?;
            let input = input
                .map(|input| {
                    let path = PathBuf::from(input.strip_prefix('@').unwrap_or(&input));
                    let bytes = read_file(&path, "input-read-failed")?;
                    parse_data_document(&path, &bytes).map_err(|error| CliError {
                        code: "invalid-input",
                        message: error.to_string(),
                        exit: 2,
                    })
                })
                .transpose()?;
            let explicit = explicit
                .iter()
                .map(|field| {
                    parse_explicit_field(field).map_err(|error| CliError {
                        code: "invalid-input",
                        message: error.to_string(),
                        exit: 2,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let configuration = config
                .or_else(|| {
                    let default = store.join("config.toml");
                    default.exists().then_some(default)
                })
                .as_deref()
                .map(ProjectConfiguration::load)
                .transpose()
                .map_err(|error| CliError {
                    code: "invalid-configuration",
                    message: error.to_string(),
                    exit: 2,
                })?
                .unwrap_or_default();
            let raw_source = parse_data_document(&source, &source_bytes).ok();
            if raw_source.as_ref().is_some_and(is_websocket_session) {
                if input.is_some()
                    || !explicit.is_empty()
                    || server.is_some()
                    || auth.is_some()
                    || content_type.is_some()
                    || !checks.is_empty()
                {
                    return Err(CliError {
                        code: "invalid-websocket-plan-options",
                        message: "WebSocket sessions seal target, auth, actions, checks, and payloads in the source; HTTP plan overrides are not accepted".into(),
                        exit: 2,
                    });
                }
                let websocket_plan =
                    build_websocket_plan_with_configuration(&source, &source_bytes, &configuration)
                        .map_err(|error| CliError {
                            code: "invalid-websocket-plan",
                            message: error.to_string(),
                            exit: 2,
                        })?;
                let operation_id = raw_source
                    .as_ref()
                    .and_then(|document| document.get("operationId"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                if operation != operation_id && operation != websocket_plan.operation {
                    return Err(CliError {
                        code: "unknown-operation",
                        message: format!("WebSocket operation {operation:?} was not found"),
                        exit: 2,
                    });
                }
                store_websocket_plan(&store, &websocket_plan).map_err(|error| CliError {
                    code: "plan-store-failed",
                    message: error.to_string(),
                    exit: 2,
                })?;
                write_envelope(&websocket_plan).map_err(io_error)?;
                return Ok(0);
            }
            if raw_source.as_ref().is_some_and(is_asyncapi) {
                if input.is_some() || content_type.is_some() || !checks.is_empty() {
                    return Err(CliError {
                        code: "invalid-asyncapi-plan-options",
                        message: "AsyncAPI WebSocket plans accept only --server, --auth SCHEME=PROFILE, and --set server.NAME/channel.NAME inputs".into(),
                        exit: 2,
                    });
                }
                let websocket_plan = build_asyncapi_websocket_plan_with_configuration(
                    &source,
                    &source_bytes,
                    &operation,
                    PlanOptions {
                        server,
                        auth,
                        content_type: None,
                        input: None,
                        explicit,
                        checks: Vec::new(),
                    },
                    &configuration,
                )
                .map_err(|error| CliError {
                    code: "invalid-asyncapi-plan",
                    message: error.to_string(),
                    exit: 2,
                })?;
                store_websocket_plan(&store, &websocket_plan).map_err(|error| CliError {
                    code: "plan-store-failed",
                    message: error.to_string(),
                    exit: 2,
                })?;
                write_envelope(&websocket_plan).map_err(io_error)?;
                return Ok(0);
            }
            if raw_source.as_ref().is_some_and(is_arazzo) {
                if !explicit.is_empty() {
                    return Err(CliError {
                        code: "invalid-workflow-input",
                        message: "workflow inputs must be supplied through --input, not --set"
                            .into(),
                        exit: 2,
                    });
                }
                let workflow_plan = build_workflow_plan(
                    &source,
                    raw_source.as_ref().expect("checked as Arazzo"),
                    &operation,
                    input.unwrap_or_else(|| serde_json::json!({})),
                    auth,
                    server,
                    checks,
                    &configuration,
                )
                .map_err(|error| CliError {
                    code: "invalid-workflow-plan",
                    message: error.to_string(),
                    exit: 2,
                })?;
                store_workflow_plan(&store, &workflow_plan).map_err(|error| CliError {
                    code: "plan-store-failed",
                    message: error.to_string(),
                    exit: 2,
                })?;
                write_envelope(&workflow_plan).map_err(io_error)?;
                return Ok(0);
            }
            let source_document =
                load_source(&source, &source_bytes).map_err(|error| CliError {
                    code: "invalid-source",
                    message: error.to_string(),
                    exit: 2,
                })?;
            let operation =
                resolve_operation(&source_document, &operation).map_err(|error| CliError {
                    code: "unknown-operation",
                    message: error.to_string(),
                    exit: 2,
                })?;
            let plan = build_plan_with_configuration(
                &source_document,
                &operation,
                PlanOptions {
                    server,
                    auth,
                    content_type,
                    input,
                    explicit,
                    checks,
                },
                &configuration,
            )
            .map_err(|error| CliError {
                code: "invalid-plan",
                message: error.to_string(),
                exit: 2,
            })?;
            store_plan(&store, &plan).map_err(|error| CliError {
                code: "plan-store-failed",
                message: error.to_string(),
                exit: 2,
            })?;
            write_envelope(&plan).map(|()| 0).map_err(io_error)
        }
        Command::Conform {
            source,
            operation,
            input,
            explicit,
            server,
            auth,
            content_type,
            checks,
            cases,
            seed,
            mode,
            delay_ms,
            max_failures,
            config,
            store,
        } => {
            let source_bytes = read_source(&source, "source-read-failed")?;
            let baseline = input
                .map(|input| {
                    let path = PathBuf::from(input.strip_prefix('@').unwrap_or(&input));
                    let bytes = read_file(&path, "input-read-failed")?;
                    parse_data_document(&path, &bytes).map_err(|error| CliError {
                        code: "invalid-input",
                        message: error.to_string(),
                        exit: 2,
                    })
                })
                .transpose()?;
            let explicit = explicit
                .iter()
                .map(|field| {
                    parse_explicit_field(field).map_err(|error| CliError {
                        code: "invalid-input",
                        message: error.to_string(),
                        exit: 2,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let configuration = config
                .or_else(|| {
                    let default = store.join("config.toml");
                    default.exists().then_some(default)
                })
                .as_deref()
                .map(ProjectConfiguration::load)
                .transpose()
                .map_err(|error| CliError {
                    code: "invalid-configuration",
                    message: error.to_string(),
                    exit: 2,
                })?
                .unwrap_or_default();
            let source_document =
                load_source(&source, &source_bytes).map_err(|error| CliError {
                    code: "invalid-source",
                    message: error.to_string(),
                    exit: 2,
                })?;
            let operation =
                resolve_operation(&source_document, &operation).map_err(|error| CliError {
                    code: "unknown-operation",
                    message: error.to_string(),
                    exit: 2,
                })?;
            let (campaign, requests) = build_conformance_plan(
                &source_document,
                &operation,
                ConformanceOptions {
                    cases,
                    seed,
                    mode: mode.into(),
                    delay_ms,
                    max_failures,
                    input: baseline,
                    plan: PlanOptions {
                        server,
                        auth,
                        content_type,
                        input: None,
                        explicit,
                        checks,
                    },
                },
                &configuration,
            )
            .map_err(|error| CliError {
                code: "invalid-conformance-plan",
                message: error.to_string(),
                exit: 2,
            })?;
            store_conformance_plan(&store, &campaign, &requests).map_err(|error| CliError {
                code: "plan-store-failed",
                message: error.to_string(),
                exit: 2,
            })?;
            write_envelope(&campaign).map(|()| 0).map_err(io_error)
        }
        Command::Invoke {
            plan,
            grants,
            secret_env,
            timeout_ms,
            max_response_bytes,
            config,
            store,
        } => {
            if timeout_ms == 0 || max_response_bytes == 0 {
                return Err(CliError {
                    code: "invalid-invoke-options",
                    message: "--timeout-ms and --max-response-bytes must be greater than zero"
                        .into(),
                    exit: 2,
                });
            }
            let configuration = config
                .or_else(|| {
                    let default = store.join("config.toml");
                    default.exists().then_some(default)
                })
                .as_deref()
                .map(ProjectConfiguration::load)
                .transpose()
                .map_err(|error| CliError {
                    code: "invalid-configuration",
                    message: error.to_string(),
                    exit: 2,
                })?
                .unwrap_or_default();
            let secrets = resolve_secret_environment(&secret_env)?;
            let evidence = EvidenceStore::open(store.join("store")).map_err(|error| CliError {
                code: "evidence-store-failed",
                message: error.to_string(),
                exit: 2,
            })?;
            let plan_kind = stored_plan_kind(&store, &plan);
            let expected_policy_fingerprint = if plan_kind.as_deref() == Some("websocket-plan") {
                configuration.websocket_policy_fingerprint()
            } else {
                configuration.policy_fingerprint()
            }
            .map_err(|error| CliError {
                code: "invalid-configuration",
                message: error.to_string(),
                exit: 2,
            })?;
            let invoke_options = InvokeOptions {
                grants: grants.into_iter().collect::<BTreeSet<_>>(),
                secrets,
                timeout: std::time::Duration::from_millis(timeout_ms),
                max_response_bytes,
                expected_config_fingerprint: Some(configuration.config_fingerprint().map_err(
                    |error| CliError {
                        code: "invalid-configuration",
                        message: error.to_string(),
                        exit: 2,
                    },
                )?),
                expected_policy_fingerprint: Some(expected_policy_fingerprint),
                additional_root_certificates_pem: Vec::new(),
            };
            if plan_kind.as_deref() == Some("websocket-plan") {
                let websocket_plan =
                    load_websocket_plan(&store, &plan).map_err(|error| CliError {
                        code: "invalid-websocket-plan",
                        message: error.to_string(),
                        exit: 2,
                    })?;
                let result = execute_websocket(&websocket_plan, &invoke_options, &evidence)
                    .map_err(exec_error)?;
                let exit = result.exit().unwrap_or(3);
                match result {
                    WebSocketConnectResult::Observation(observation) => {
                        write_envelope(&observation).map_err(io_error)?;
                    }
                    WebSocketConnectResult::Denied(denial) => {
                        write_envelope(&denial).map_err(io_error)?;
                    }
                    WebSocketConnectResult::Connected(_) => {
                        return Err(CliError {
                            code: "websocket-invocation-failed",
                            message: "WebSocket executor returned a non-terminal connection".into(),
                            exit: 3,
                        });
                    }
                }
                return Ok(exit);
            }
            if plan_kind.as_deref() == Some("conformance-plan") {
                let campaign = load_conformance_plan(&store, &plan).map_err(|error| CliError {
                    code: "invalid-conformance-plan",
                    message: error.to_string(),
                    exit: 2,
                })?;
                let observation = invoke_conformance(&campaign, &invoke_options, &store, &evidence)
                    .map_err(|error| CliError {
                        code: "conformance-invocation-failed",
                        message: error.to_string(),
                        exit: 2,
                    })?;
                let exit = observation.exit;
                write_envelope(&observation).map_err(io_error)?;
                return Ok(exit);
            }
            if plan_kind.as_deref() == Some("workflow-plan") {
                let workflow_plan =
                    load_workflow_plan(&store, &plan).map_err(|error| CliError {
                        code: "invalid-workflow-plan",
                        message: error.to_string(),
                        exit: 2,
                    })?;
                let observation = invoke_workflow(
                    &workflow_plan,
                    &invoke_options,
                    &configuration,
                    &store,
                    &evidence,
                )
                .map_err(|error| CliError {
                    code: "workflow-invocation-failed",
                    message: error.to_string(),
                    exit: 2,
                })?;
                let exit = observation.exit;
                write_envelope(&observation).map_err(io_error)?;
                return Ok(exit);
            }
            let plan = load_plan(&store, &plan).map_err(|error| CliError {
                code: "invalid-plan",
                message: error.to_string(),
                exit: 2,
            })?;
            let result = invoke(&plan, &invoke_options, &evidence).map_err(exec_error)?;
            let exit = result.exit();
            match result {
                InvocationResult::Observation(observation) => {
                    write_envelope(&observation).map_err(io_error)?;
                }
                InvocationResult::Denied(denial) => {
                    write_envelope(&denial).map_err(io_error)?;
                }
            }
            Ok(exit)
        }
        Command::Explain {
            handle,
            select,
            export,
            store,
        } => {
            let evidence = EvidenceStore::open(store.join("store")).map_err(|error| CliError {
                code: "evidence-store-failed",
                message: error.to_string(),
                exit: 2,
            })?;
            let explanation = evidence
                .explain(&handle, select.as_deref())
                .map_err(|error| CliError {
                    code: "evidence-explain-failed",
                    message: error.to_string(),
                    exit: 2,
                })?;
            if let Some(export) = export {
                evidence
                    .export_bundle(&handle, export)
                    .map_err(|error| CliError {
                        code: "evidence-export-failed",
                        message: error.to_string(),
                        exit: 2,
                    })?;
            }
            write_envelope(&explanation).map(|()| 0).map_err(io_error)
        }
        Command::Mcp {
            command:
                McpCommand::Serve {
                    stdio,
                    store,
                    config,
                },
        } => {
            if !stdio {
                return Err(CliError {
                    code: "unsupported-mcp-transport",
                    message: "v1 MCP supports only --stdio".into(),
                    exit: 2,
                });
            }
            kahea_mcp::serve_stdio(kahea_mcp::ServerOptions { store, config }).map_err(
                |error| CliError {
                    code: "mcp-server-failed",
                    message: error.to_string(),
                    exit: 2,
                },
            )?;
            Ok(0)
        }
    }
}

fn read_file(path: &PathBuf, code: &'static str) -> Result<Vec<u8>, CliError> {
    if path.as_os_str() == "-" {
        let mut bytes = Vec::new();
        io::stdin()
            .lock()
            .read_to_end(&mut bytes)
            .map_err(|error| CliError {
                code,
                message: format!("could not read standard input: {error}"),
                exit: 2,
            })?;
        return Ok(bytes);
    }
    fs::read(path).map_err(|error| CliError {
        code,
        message: format!("could not read {}: {error}", path.display()),
        exit: 2,
    })
}

fn read_source(path: &PathBuf, code: &'static str) -> Result<Vec<u8>, CliError> {
    if path.as_os_str() == "-" {
        return read_file(path, code);
    }
    read_source_artifact(path).map_err(|error| CliError {
        code,
        message: error.to_string(),
        exit: 2,
    })
}

fn stored_plan_kind(root: &std::path::Path, reference: &str) -> Option<String> {
    let path = if reference.starts_with("workflow-plan:")
        || reference.starts_with("conformance-plan:")
        || reference.starts_with("plan:")
    {
        root.join("store/plans")
            .join(format!("{}.json", reference.replace(':', "-")))
    } else {
        PathBuf::from(reference)
    };
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|value| {
            value
                .get("kind")
                .and_then(|kind| kind.as_str())
                .map(str::to_string)
        })
}

fn resolve_secret_environment(values: &[String]) -> Result<BTreeMap<String, String>, CliError> {
    let mut secrets = BTreeMap::new();
    for value in values {
        let (profile, variable) = value.split_once('=').ok_or_else(|| CliError {
            code: "invalid-secret-reference",
            message: format!("invalid --secret-env {value:?}; expected PROFILE=ENV_VAR"),
            exit: 2,
        })?;
        if profile.is_empty() || variable.is_empty() {
            return Err(CliError {
                code: "invalid-secret-reference",
                message: format!("invalid --secret-env {value:?}; names cannot be empty"),
                exit: 2,
            });
        }
        let secret = std::env::var(variable).map_err(|_| CliError {
            code: "secret-unavailable",
            message: format!(
                "environment variable {variable:?} is unavailable for profile {profile:?}"
            ),
            exit: 2,
        })?;
        secrets.insert(profile.into(), secret);
    }
    Ok(secrets)
}

fn exec_error(error: ExecError) -> CliError {
    let exit = match error {
        ExecError::Transport(_) | ExecError::ResponseTooLarge(_) => 3,
        _ => 2,
    };
    CliError {
        code: if exit == 3 {
            "transport-failed"
        } else {
            "invalid-invocation"
        },
        message: error.to_string(),
        exit,
    }
}

fn io_error(error: std::io::Error) -> CliError {
    CliError {
        code: "output-failed",
        message: error.to_string(),
        exit: 2,
    }
}
