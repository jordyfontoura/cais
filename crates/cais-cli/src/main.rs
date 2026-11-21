mod mcp;
mod private_file;
mod transport;

use cais_core::{CaisError, ClientConfig, ErrorCode, ProjectConfig, Result, decode_config};
use cais_protocol::{Operation, Outcome};
use clap::{Parser, Subcommand, ValueEnum, error::ErrorKind};
use serde_json::{Value, json};
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(
    name = "cais",
    version,
    about = "Cais: declarative application operations for people and agents."
)]
struct Cli {
    /// Emit structured JSON; db-tunnel emits documented readiness/closed events.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the typed operations to a local MCP client over stdio. No shell access.
    Mcp {
        /// Client configuration whose targets the tools may use.
        #[arg(long)]
        config: PathBuf,
        /// Workspace directory; file arguments must stay inside it.
        #[arg(long, default_value = ".")]
        root: PathBuf,
    },
    #[command(name = "__tunnel-supervisor", hide = true)]
    TunnelSupervisor,
    /// Open psql on the server as the SSH login. Human output; unavailable with --json.
    DbPsql {
        project: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        config: PathBuf,
    },
    /// Hold a loopback-only SSH forward. JSON mode emits readiness/closed events.
    DbTunnel {
        project: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value_t = 0)]
        local_port: u16,
        #[arg(long, default_value_t = 3600, value_parser=clap::value_parser!(u32).range(1..=86400))]
        duration_seconds: u32,
    },
    /// Export credentials into a NEW private directory, never JSON output.
    DbConfig {
        project: String,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long)]
        config: PathBuf,
    },
    /// Provision a project-owned PostgreSQL database using a saved status revision.
    DbCreate {
        project: String,
        #[arg(long)]
        expected: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long)]
        config: PathBuf,
    },
    /// Verify an interrupted database provision without repeating CREATE statements.
    DbReconcile {
        project: String,
        #[arg(long)]
        expected: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long)]
        config: PathBuf,
    },
    /// Inspect registration, service, last deployment and unresolved operations.
    Status {
        project: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        config: PathBuf,
    },
    /// Register a new isolated project from a saved native plan.
    Register {
        #[arg(long, default_value = "cais.json")]
        file: PathBuf,
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        deploy_public_key: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long)]
        config: PathBuf,
    },
    /// Replace application environment from a private JSON object; values are never returned.
    EnvSet {
        project: String,
        #[arg(long)]
        values: PathBuf,
        #[arg(long)]
        expected: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long)]
        config: PathBuf,
    },
    /// Restart an HTTP service using a saved status revision.
    Restart {
        project: String,
        #[arg(long)]
        expected: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long)]
        config: PathBuf,
    },
    /// Replace the project's presentation metadata for catalog consumers.
    MetadataSet {
        project: String,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        expected: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long)]
        config: PathBuf,
    },
    /// Publish the project's declared route in the reverse proxy, then reload it.
    ProxyApply {
        project: String,
        #[arg(long)]
        expected: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long)]
        config: PathBuf,
    },
    /// Take the project's route out of the reverse proxy, then reload it.
    ProxyRemove {
        project: String,
        #[arg(long)]
        expected: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long)]
        config: PathBuf,
    },
    /// Declare the project's backup paths and database to the host's backup tool.
    BackupRegister {
        project: String,
        #[arg(long)]
        expected: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long)]
        config: PathBuf,
    },
    /// Publish an artifact through a separate project deployment identity.
    Deploy {
        #[arg(long, default_value = "cais.json")]
        file: PathBuf,
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        expected: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long)]
        config: PathBuf,
    },
    /// Create a deterministic Linux artifact locally; never overwrites an existing file.
    Package {
        #[arg(long, default_value = "cais.json")]
        file: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Validate a configuration locally. Does not inspect an artifact or contact a server.
    Validate {
        #[arg(long, default_value = "cais.json")]
        file: PathBuf,
        #[arg(long, value_enum, default_value = "project")]
        kind: ConfigKind,
    },
    /// Print a JSON Schema document (always raw JSON, suitable for an editor).
    Schema {
        #[arg(value_enum)]
        kind: ConfigKind,
    },
    /// Discover local commands or the capabilities of a named server.
    Capabilities {
        #[arg(long, requires = "config")]
        target: Option<String>,
        #[arg(long, requires = "target")]
        config: Option<PathBuf>,
    },
    /// List project names visible to the authenticated SSH operating-system account.
    List {
        #[arg(long)]
        target: String,
        #[arg(long)]
        config: PathBuf,
    },
    /// Validate intent against current server policy and save a state revision.
    Plan {
        #[arg(long, default_value = "cais.json")]
        file: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long)]
        config: PathBuf,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum ConfigKind {
    Project,
    Client,
    Server,
    Metadata,
}
impl ConfigKind {
    fn name(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Client => "client",
            Self::Server => "server",
            Self::Metadata => "metadata",
        }
    }
}

fn main() {
    let json_requested = std::env::args_os().any(|a| a == "--json");
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            let _ = error.print();
            return;
        }
        Err(_) => {
            emit_error(
                &CaisError::new(
                    ErrorCode::InvalidRequest,
                    "Invalid CLI arguments. Run cais --help.",
                ),
                json_requested,
            );
            std::process::exit(2);
        }
    };
    if let Command::Mcp { config, root } = &cli.command {
        std::process::exit(mcp::serve(config, root));
    }
    if matches!(&cli.command, Command::TunnelSupervisor) {
        if let Err(error) = transport::supervise_database_tunnel() {
            std::process::exit(error.code.exit_code());
        }
        return;
    }
    if matches!(
        cli.command,
        Command::DbPsql { .. } | Command::DbTunnel { .. }
    ) {
        if let Err(error) = database_session(&cli.command, cli.json) {
            emit_error(&error, cli.json);
            std::process::exit(exit_code(error.code));
        }
        return;
    }
    match execute(&cli.command) {
        Ok((data, raw)) => {
            if raw {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&data).expect("serializable JSON")
                );
            } else if cli.json {
                println!(
                    "{}",
                    json!({"schema_version":1,"outcome":"success","data":data})
                );
            } else {
                print_human(&data);
            }
        }
        Err(error) => {
            emit_error(&error, cli.json);
            std::process::exit(exit_code(error.code));
        }
    }
}

fn execute(command: &Command) -> Result<(Value, bool)> {
    let data = match command {
        Command::Mcp { .. }
        | Command::TunnelSupervisor
        | Command::DbPsql { .. }
        | Command::DbTunnel { .. } => {
            return Err(cais_protocol::protocol());
        }
        Command::DbConfig {
            project,
            output_dir,
            target,
            config,
        } => {
            let settings = decode_config::<ClientConfig>(&read_config(config)?)?;
            let profile = settings.targets.get(target).ok_or_else(|| {
                CaisError::new(ErrorCode::InvalidConfig, "Target is not configured.")
            })?;
            let file = private_file::create(output_dir)?;
            let received = file
                .as_file()
                .try_clone()
                .map_err(|_| CaisError::new(ErrorCode::Internal, "Cannot open private export."))
                .and_then(|handle| {
                    transport::download(
                        profile,
                        config.parent().unwrap_or_else(|| Path::new(".")),
                        Operation::DatabaseCredentials {
                            project: project.clone(),
                        },
                        handle,
                    )
                })
                .and_then(outcome);
            if let Err(error) = received {
                // Nothing was published: leave no trace, so the directory name stays usable.
                drop(file);
                let _ = std::fs::remove_dir(output_dir);
                return Err(error);
            }
            let path = output_dir.join("credentials.private.json");
            file.persist_noclobber(&path).map_err(|_| {
                CaisError::new(ErrorCode::Conflict, "Private export destination exists.")
            })?;
            json!({"project":project,"file":path,"exported":true})
        }
        Command::DbCreate {
            project,
            expected,
            target,
            config,
        } => remote(
            config,
            target,
            Operation::DatabaseCreate {
                project: project.clone(),
                expected: expected_from(expected)?,
            },
        )?,
        Command::DbReconcile {
            project,
            expected,
            target,
            config,
        } => remote(
            config,
            target,
            Operation::DatabaseReconcile {
                project: project.clone(),
                expected: expected_from(expected)?,
            },
        )?,
        Command::Status {
            project,
            target,
            config,
        } => remote(
            config,
            target,
            Operation::Status {
                project: project.clone(),
            },
        )?,
        Command::Register {
            file,
            plan,
            deploy_public_key,
            target,
            config,
        } => {
            let project: ProjectConfig = decode_config(&read_config(file)?)?;
            let value: Value = cais_core::decode_json(&read_config(plan)?)?;
            let value = value.get("data").unwrap_or(&value);
            if value.get("configuration_sha256").and_then(Value::as_str)
                != Some(&cais_core::configuration_sha256(&project)?)
            {
                return Err(CaisError::new(
                    ErrorCode::Conflict,
                    "Configuration changed since planning.",
                ));
            }
            let key = String::from_utf8(read_config(deploy_public_key)?)
                .ok()
                // Checked here so that a mistaken path never sends another file's content.
                .filter(|key| {
                    key.trim_end().lines().count() == 1
                        && ["ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-nistp256 "]
                            .iter()
                            .any(|kind| key.starts_with(kind))
                })
                .ok_or_else(|| {
                    CaisError::new(ErrorCode::InvalidConfig, "Invalid public deployment key.")
                })?;
            remote(
                config,
                target,
                Operation::Register {
                    project: Box::new(project),
                    deploy_public_key: key,
                    expected: expected_from(plan)?,
                },
            )?
        }
        Command::EnvSet {
            project,
            values,
            expected,
            target,
            config,
        } => {
            let values = cais_core::decode_json(&read_config(values)?)?;
            remote(
                config,
                target,
                Operation::Environment {
                    project: project.clone(),
                    values,
                    expected: expected_from(expected)?,
                },
            )?
        }
        Command::Restart {
            project,
            expected,
            target,
            config,
        } => remote(
            config,
            target,
            Operation::Restart {
                project: project.clone(),
                expected: expected_from(expected)?,
            },
        )?,
        Command::MetadataSet {
            project,
            file,
            expected,
            target,
            config,
        } => remote(
            config,
            target,
            Operation::Metadata {
                project: project.clone(),
                metadata: Box::new(decode_config(&read_config(file)?)?),
                expected: expected_from(expected)?,
            },
        )?,
        Command::ProxyApply {
            project,
            expected,
            target,
            config,
        } => remote(
            config,
            target,
            Operation::ProxyApply {
                project: project.clone(),
                expected: expected_from(expected)?,
            },
        )?,
        Command::ProxyRemove {
            project,
            expected,
            target,
            config,
        } => remote(
            config,
            target,
            Operation::ProxyRemove {
                project: project.clone(),
                expected: expected_from(expected)?,
            },
        )?,
        Command::BackupRegister {
            project,
            expected,
            target,
            config,
        } => remote(
            config,
            target,
            Operation::BackupRegister {
                project: project.clone(),
                expected: expected_from(expected)?,
            },
        )?,
        Command::Deploy {
            file,
            artifact,
            expected,
            target,
            config,
        } => {
            let project: ProjectConfig = decode_config(&read_config(file)?)?;
            let mut input = File::open(artifact)
                .map_err(|_| CaisError::new(ErrorCode::InvalidConfig, "Cannot open artifact."))?;
            let size = input
                .metadata()
                .map_err(|_| CaisError::new(ErrorCode::InvalidConfig, "Cannot inspect artifact."))?
                .len();
            if size == 0 || size > 1024 * 1024 * 1024 {
                return Err(CaisError::new(
                    ErrorCode::InvalidConfig,
                    "Artifact size is outside supported limits.",
                ));
            }
            use sha2::{Digest, Sha256};
            let mut hash = Sha256::new();
            let mut buffer = [0; 65536];
            loop {
                let count = input.read(&mut buffer).map_err(|_| {
                    CaisError::new(ErrorCode::InvalidConfig, "Cannot read artifact.")
                })?;
                if count == 0 {
                    break;
                }
                hash.update(&buffer[..count]);
            }
            use std::io::{Seek, SeekFrom};
            input
                .seek(SeekFrom::Start(0))
                .map_err(|_| CaisError::new(ErrorCode::InvalidConfig, "Cannot read artifact."))?;
            let operation = Operation::Deploy {
                project: project.project.clone(),
                expected: expected_from(expected)?,
                compressed_bytes: size,
                sha256: cais_core::hex(hash.finalize()),
                configuration_sha256: cais_core::configuration_sha256(&project)?,
            };
            let settings = decode_config::<ClientConfig>(&read_config(config)?)?;
            let profile = settings.targets.get(target).ok_or_else(|| {
                CaisError::new(ErrorCode::InvalidConfig, "Target is not configured.")
            })?;
            outcome(transport::upload(
                profile,
                config.parent().unwrap_or_else(|| Path::new(".")),
                operation,
                input,
                size,
            )?)?
        }
        Command::Package { file, output } => {
            let project = decode_config::<ProjectConfig>(&read_config(file)?)?;
            let project_root = file.parent().unwrap_or_else(|| Path::new("."));
            let descriptor = cais_artifacts::package(
                project_root,
                &project,
                output,
                cais_artifacts::Limits::default(),
            )?;
            serde_json::to_value(descriptor)
                .map_err(|_| CaisError::new(ErrorCode::Internal, "Result serialization failed."))?
        }
        Command::Validate { file, kind } => {
            let bytes = read_config(file)?;
            match kind {
                ConfigKind::Project => {
                    decode_config::<ProjectConfig>(&bytes)?;
                }
                ConfigKind::Client => {
                    decode_config::<ClientConfig>(&bytes)?;
                }
                ConfigKind::Server => {
                    decode_config::<cais_core::ServerConfig>(&bytes)?;
                }
                ConfigKind::Metadata => {
                    decode_config::<cais_core::ProjectMetadata>(&bytes)?;
                }
            }
            json!({"valid":true,"kind":kind.name(),"scope":"configuration_only"})
        }
        Command::Schema { kind } => return Ok((cais_core::schema(kind.name())?, true)),
        Command::Capabilities { target: None, .. } => json!({
            "client_version":env!("CARGO_PKG_VERSION"),
            "configuration_versions":[1],
            "commands":["validate","schema","capabilities","list","plan","package","status","register","env-set","restart","metadata-set","proxy-apply","proxy-remove","backup-register","deploy","db-create","db-reconcile","db-config","db-psql","db-tunnel","mcp"],
            "server_operations":cais_core::Capabilities::default(),
            "transport":"openssh",
            "server_platform":"linux"
        }),
        Command::Capabilities {
            target: Some(target),
            config: Some(config),
        } => remote(config, target, Operation::Capabilities {})?,
        Command::Capabilities { .. } => {
            return Err(CaisError::new(
                ErrorCode::InvalidRequest,
                "Target and client configuration are required together.",
            ));
        }
        Command::List { target, config } => remote(config, target, Operation::List {})?,
        Command::Plan {
            file,
            target,
            config,
        } => {
            let project = decode_config::<ProjectConfig>(&read_config(file)?)?;
            remote(
                config,
                target,
                Operation::Plan {
                    project: Box::new(project),
                },
            )?
        }
    };
    Ok((data, false))
}

fn database_session(command: &Command, json_output: bool) -> Result<()> {
    use cais_core::Validate;
    let (project, target, config) = match command {
        Command::DbPsql {
            project,
            target,
            config,
        }
        | Command::DbTunnel {
            project,
            target,
            config,
            ..
        } => (project, target, config),
        _ => return Err(cais_protocol::protocol()),
    };
    if matches!(command, Command::DbPsql { .. }) && json_output {
        return Err(CaisError::new(
            ErrorCode::Unsupported,
            "Interactive psql is a human session and has no JSON or MCP terminal interface.",
        ));
    }
    if !cais_core::identifier(project) {
        return Err(CaisError::new(
            ErrorCode::InvalidConfig,
            "Invalid project identifier.",
        ));
    }
    let settings = decode_config::<ClientConfig>(&read_config(config)?)?;
    let profile = settings
        .targets
        .get(target)
        .ok_or_else(|| CaisError::new(ErrorCode::InvalidConfig, "Target is not configured."))?;
    let base = config.parent().unwrap_or_else(|| Path::new("."));
    if matches!(command, Command::DbPsql { .. }) {
        return transport::psql(profile, base, project);
    }
    let data = outcome(transport::call(
        profile,
        base,
        Operation::DatabaseConnection {
            project: project.clone(),
        },
    )?)?;
    let info: cais_core::DatabaseConnection =
        serde_json::from_value(data).map_err(|_| cais_protocol::protocol())?;
    info.validate()?;
    if info.project != *project {
        return Err(cais_protocol::protocol());
    }
    let Command::DbTunnel {
        local_port,
        duration_seconds,
        ..
    } = command
    else {
        return Err(cais_protocol::protocol());
    };
    let mut tunnel = transport::database_tunnel(profile, base, &info, *local_port)?;
    let seconds = (*duration_seconds).min(info.session_seconds.saturating_sub(2));
    if json_output {
        println!(
            "{}",
            json!({"schema_version":1,"event":"tunnel_ready","data":{"project":project,"host":"127.0.0.1","port":tunnel.port,"database":info.database,"username":info.username,"duration_seconds":seconds}})
        );
    } else {
        println!(
            "Database tunnel: 127.0.0.1:{} ({} seconds)",
            tunnel.port, seconds
        );
    }
    use std::io::Write;
    std::io::stdout()
        .flush()
        .map_err(|_| cais_protocol::transport())?;
    let until = std::time::Instant::now() + std::time::Duration::from_secs(seconds.into());
    while std::time::Instant::now() < until {
        if !tunnel.running()? {
            return Err(CaisError::new(
                ErrorCode::Transport,
                "Database tunnel closed before its requested duration.",
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    tunnel.close()?;
    drop(tunnel);
    if json_output {
        println!(
            "{}",
            json!({"schema_version":1,"event":"tunnel_closed","data":{"project":project,"reason":"time_limit"}})
        );
    }
    Ok(())
}

fn remote(config_path: &Path, target_name: &str, operation: Operation) -> Result<Value> {
    let config = decode_config::<ClientConfig>(&read_config(config_path)?)?;
    let target = config
        .targets
        .get(target_name)
        .ok_or_else(|| CaisError::new(ErrorCode::InvalidConfig, "Target is not configured."))?;
    let base = config_path.parent().unwrap_or_else(|| Path::new("."));
    outcome(transport::call(target, base, operation)?)
}

fn outcome(result: Outcome) -> Result<Value> {
    match result {
        Outcome::Success { data } => Ok(data),
        Outcome::Error { error } => Err(error),
        Outcome::UploadReady { .. } | Outcome::PrivateFileReady { .. } => {
            Err(cais_protocol::protocol())
        }
    }
}

fn expected_from(path: &Path) -> Result<cais_core::Expected> {
    let value: Value = cais_core::decode_json(&read_config(path)?)?;
    let value = value.get("data").unwrap_or(&value);
    serde_json::from_value(value.get("expected").unwrap_or(value).clone()).map_err(|_| {
        CaisError::new(
            ErrorCode::InvalidConfig,
            "A saved native plan or status is required.",
        )
    })
}

fn read_config(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| {
            file.take(cais_core::CONFIG_LIMIT as u64 + 1)
                .read_to_end(&mut bytes)
        })
        .map_err(|_| CaisError::new(ErrorCode::InvalidConfig, "Cannot read configuration file."))?;
    Ok(bytes)
}

fn emit_error(error: &CaisError, json_mode: bool) {
    if json_mode {
        println!(
            "{}",
            json!({"schema_version":1,"outcome":"error","error":error})
        );
    } else {
        eprintln!("{}", terminal_text(&error.message));
        for issue in error.issues.iter().take(64) {
            eprintln!(
                "{}: {}",
                terminal_text(&issue.path),
                terminal_text(&issue.message)
            );
        }
    }
}

fn exit_code(code: ErrorCode) -> i32 {
    code.exit_code()
}

fn print_human(data: &Value) {
    if let Some(project) = data.get("project").and_then(Value::as_str)
        && let Some(supported) = data.get("execution_supported").and_then(Value::as_bool)
    {
        println!(
            "Project: {}\nPolicy: checked\nExecution: {}",
            terminal_text(project),
            if supported {
                "supported; current revision required"
            } else {
                "unavailable (planning preview)"
            }
        );
        if let Some(notes) = data.get("notes").and_then(Value::as_array) {
            for note in notes.iter().take(16) {
                if let Some(note) = note.as_str() {
                    println!("- {}", terminal_text(note));
                }
            }
        }
    } else {
        let rendered = serde_json::to_string_pretty(data).expect("serializable JSON");
        let safe: String = rendered
            .chars()
            .take(8192)
            .map(|ch| {
                if (ch.is_control() && ch != '\n')
                    || matches!(ch, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
                {
                    '\u{fffd}'
                } else {
                    ch
                }
            })
            .collect();
        println!("{safe}");
        if rendered.chars().nth(8192).is_some() {
            println!("... (truncated; use --json for the complete result)");
        }
    }
}

/// Treat peer text as text, never terminal instructions. JSON mode remains lossless.
fn terminal_text(value: &str) -> String {
    value
        .chars()
        .take(2048)
        .map(|ch| {
            if ch.is_control() || matches!(ch, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
                '\u{fffd}'
            } else {
                ch
            }
        })
        .collect()
}
