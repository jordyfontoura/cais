use cais_core::{CaisError, ErrorCode, Result, ServerConfig, decode_config};
use cais_protocol::{
    Hello, Operation, Outcome, PROTOCOL_VERSION, Request, Response, read_frame, send_hello,
    write_frame,
};
use clap::Parser;
#[cfg(target_os = "linux")]
mod database_session;
use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(
    version,
    about = "Cais server entry point. One framed request over stdio; Linux only."
)]
struct Args {
    /// Administrative host policy. Never supplied in a protocol request.
    #[arg(long, default_value = "/etc/cais/server.json")]
    config: PathBuf,
    /// Human PostgreSQL session as the SSH login, never as root.
    #[arg(long, conflicts_with = "db_hold")]
    db_psql: Option<String>,
    /// Bounded unprivileged lifetime for an explicit SSH database forward.
    #[arg(long, conflicts_with = "db_psql")]
    db_hold: Option<String>,
}

fn main() {
    let args = Args::parse();
    let result = if let Some(project) = args.db_psql.as_ref().or(args.db_hold.as_ref()) {
        #[cfg(target_os = "linux")]
        {
            load_policy(&args.config).and_then(|policy| {
                database_session::run(&args.config, &policy, project, args.db_psql.is_some())
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = project;
            Err(CaisError::new(
                ErrorCode::Unsupported,
                "Database sessions require Linux.",
            ))
        }
    } else {
        run(&args.config)
    };
    if let Err(error) = result {
        // Only fixed diagnostics from our error catalog reach stderr.
        eprintln!("{}", error.message);
        std::process::exit(error.code.exit_code());
    }
}

fn run(path: &Path) -> Result<()> {
    if !cfg!(target_os = "linux") {
        return Err(CaisError::new(
            ErrorCode::Unsupported,
            "The Cais server supports Linux only.",
        ));
    }
    let config = load_policy(path)?;
    #[cfg(target_os = "linux")]
    if config.host.is_some() {
        return cais_host::enter_broker(path, &config);
    }
    // OS account lookup; deliberately ignore USER, LOGNAME, SUDO_USER and wire fields.
    // Run this server as the SSH login, not through sudo.
    let caller = whoami::username().map_err(|_| {
        CaisError::new(
            ErrorCode::NotAuthorized,
            "Cannot determine the operating-system identity.",
        )
    })?;
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    send_hello(&mut output, &Hello::default())?;
    let request = read_frame::<Request>(&mut input);
    let (request_id, result) = match request {
        Ok(request) => {
            // Only echo a validated identifier. A malicious identifier can contain secrets.
            let id = if valid_id(&request.request_id) {
                request.request_id.clone()
            } else {
                "invalid".into()
            };
            let result = request
                .validate()
                .and_then(|_| dispatch(request.operation, &config, &caller));
            (id, result)
        }
        Err(error) => ("invalid".into(), Err(error)),
    };
    let result = match result {
        Ok(data) => Outcome::Success { data },
        Err(error) => Outcome::Error { error },
    };
    write_frame(
        &mut output,
        &Response {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            result,
        },
    )
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}

fn dispatch(
    operation: Operation,
    policy: &ServerConfig,
    caller: &str,
) -> Result<serde_json::Value> {
    match operation {
        Operation::Capabilities {} => to_json(cais_core::Capabilities::default()),
        Operation::List {} => to_json(policy.visible_projects(caller)),
        Operation::Plan { project } => to_json(policy.plan(*project, caller)?),
        _ => Err(CaisError::new(
            ErrorCode::Unsupported,
            "Native host operations are not configured.",
        )),
    }
}

fn to_json(value: impl serde::Serialize) -> Result<serde_json::Value> {
    serde_json::to_value(value)
        .map_err(|_| CaisError::new(ErrorCode::Internal, "Result serialization failed."))
}

fn load_policy(path: &Path) -> Result<ServerConfig> {
    if !path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(CaisError::new(
            ErrorCode::InvalidConfig,
            "Server policy requires an absolute path without traversal.",
        ));
    }
    trusted_path(path)?;
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|file| {
            file.take(cais_core::CONFIG_LIMIT as u64 + 1)
                .read_to_end(&mut bytes)
        })
        .map_err(|_| {
            CaisError::new(
                ErrorCode::InvalidConfig,
                "Cannot read the administrative policy.",
            )
        })?;
    decode_config(&bytes)
}

#[cfg(unix)]
fn trusted_path(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    // Effective identity from procfs; no caller-controlled environment is consulted.
    let uid = fs::metadata("/proc/self")
        .map_err(|_| CaisError::new(ErrorCode::NotAuthorized, "Cannot verify policy ownership."))?
        .uid();
    for (index, component) in path.ancestors().enumerate() {
        let meta = fs::symlink_metadata(component)
            .map_err(|_| CaisError::new(ErrorCode::InvalidConfig, "Cannot verify policy path."))?;
        let owned = meta.uid() == 0 || meta.uid() == uid;
        // Deliberately reject writable parents even when they have the sticky bit.
        let safe_mode = meta.mode() & 0o022 == 0;
        let expected_type = if index == 0 {
            meta.is_file()
        } else {
            meta.is_dir()
        };
        if !owned || !safe_mode || !expected_type || meta.file_type().is_symlink() {
            return Err(CaisError::new(
                ErrorCode::NotAuthorized,
                "Policy and parent directories must have trusted ownership and permissions, without symlinks.",
            ));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn trusted_path(_: &Path) -> Result<()> {
    Err(CaisError::new(
        ErrorCode::Unsupported,
        "Server policy ownership requires Linux.",
    ))
}
