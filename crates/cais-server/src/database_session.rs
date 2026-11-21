//! Unprivileged human/session entrypoints. No terminal is exposed through the broker.
use cais_core::{CaisError, DatabaseConnection, ErrorCode, Result, ServerConfig, Validate};
use cais_postgres::Credentials;
use cais_protocol::{
    Operation, Outcome, PROTOCOL_VERSION, Request, Response, read_frame, read_hello, write_frame,
};
use std::{
    io::{self, Read, Seek, SeekFrom, Write},
    os::fd::AsRawFd,
    path::Path,
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

pub fn run(path: &Path, policy: &ServerConfig, project: &str, interactive: bool) -> Result<()> {
    if rustix::process::geteuid().is_root()
        || path != Path::new(cais_host::DEFAULT_POLICY)
        || !cais_core::identifier(project)
    {
        return Err(CaisError::new(
            ErrorCode::NotAuthorized,
            "Database sessions require an unprivileged SSH operator and the fixed host policy.",
        ));
    }
    let caller = whoami::username().map_err(|_| failure())?;
    if !policy.operators.contains_key(&caller)
        && !policy
            .projects
            .values()
            .any(|p| p.operators.contains(&caller))
    {
        return Err(CaisError::new(
            ErrorCode::NotAuthorized,
            "Database access is not authorized for this SSH identity.",
        ));
    }
    let terminated = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    if interactive {
        // Catch in the parent, while psql installs its own foreground query-cancel
        // handlers after exec. No unsafe signal callback or inherited ignore state.
        for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGQUIT] {
            signal_hook::flag::register(
                signal,
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            )
            .map_err(|_| failure())?;
        }
        for signal in [signal_hook::consts::SIGHUP, signal_hook::consts::SIGTERM] {
            signal_hook::flag::register(signal, terminated.clone()).map_err(|_| failure())?;
        }
    }
    let (_, info) = broker(
        path,
        policy,
        Operation::DatabaseConnection {
            project: project.into(),
        },
    )?;
    let info: DatabaseConnection =
        serde_json::from_value(info).map_err(|_| cais_protocol::protocol())?;
    info.validate()?;
    if info.project != project {
        return Err(cais_protocol::protocol());
    }
    if !interactive {
        let mut out = io::stdout().lock();
        out.write_all(cais_protocol::DATABASE_SESSION_MAGIC)
            .map_err(|_| failure())?;
        write_frame(&mut out, &info)?;
        out.flush().map_err(|_| failure())?;
        drop(out);
        // The local watchdog owns OpenSSH and explicitly closes all forwarding
        // channels. This unprivileged hold additionally ends on its stdin lease.
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(io::stdin().read(&mut [0]));
        });
        let _ = rx.recv_timeout(Duration::from_secs(info.session_seconds.into()));
        return Ok(());
    }
    let (private, _) = broker(
        path,
        policy,
        Operation::DatabaseCredentials {
            project: project.into(),
        },
    )?;
    let credentials = Credentials::decode_private_file(&private.ok_or_else(failure)?)?;
    if credentials.database != info.database
        || credentials.username != info.username
        || credentials.port != info.port
    {
        return Err(cais_protocol::protocol());
    }
    let settings = policy
        .host
        .as_ref()
        .and_then(|h| h.postgres.as_ref())
        .ok_or_else(failure)?;
    let psql = cais_host::postgres_client_path(settings)?;
    if terminated.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(failure());
    }
    // Anonymous/unlinked from creation. Even SIGKILL cannot leave a named password
    // file. libpq reads the inherited descriptor after exec; apply 0600 explicitly
    // because the O_TMPFILE path can otherwise use the default OpenOptions mode.
    let mut pass = tempfile::tempfile().map_err(|_| failure())?;
    {
        use std::os::unix::fs::PermissionsExt;
        pass.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|_| failure())?;
    }
    let secret = credentials
        .password_for_child()
        .replace('\\', "\\\\")
        .replace(':', "\\:");
    writeln!(
        pass,
        "*:{}:{}:{}:{}",
        info.port, info.database, info.username, secret
    )
    .map_err(|_| failure())?;
    pass.seek(SeekFrom::Start(0)).map_err(|_| failure())?;
    rustix::io::fcntl_setfd(&pass, rustix::io::FdFlags::empty()).map_err(|_| failure())?;
    let pass_path = format!("/proc/self/fd/{}", pass.as_raw_fd());
    let socket_directory = Path::new(&info.socket).parent().ok_or_else(failure)?;
    let mut command = Command::new(psql);
    command.env_clear();
    if let Ok(term) = std::env::var("TERM")
        && !term.is_empty()
        && term.len() <= 64
        && term
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.+".contains(&b))
    {
        command.env("TERM", term);
    }
    let mut child = command
        .args(["-X", "-w", "-h"])
        .arg(socket_directory)
        .args([
            "-p",
            &info.port.to_string(),
            "-U",
            &info.username,
            "-d",
            &format!("dbname={} require_auth=scram-sha-256", info.database),
        ])
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/")
        .env("LANG", "C.UTF-8")
        .env("PGPASSFILE", pass_path)
        .env("PGCONNECT_TIMEOUT", "5")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|_| failure())?;
    let until = Instant::now() + Duration::from_secs(info.session_seconds.into());
    loop {
        if let Some(status) = child.try_wait().map_err(|_| failure())? {
            return if status.success() {
                Ok(())
            } else {
                Err(CaisError::new(
                    ErrorCode::OperationFailed,
                    "PostgreSQL session ended without success.",
                ))
            };
        }
        if terminated.load(std::sync::atomic::Ordering::Relaxed) || Instant::now() >= until {
            let _ = child.kill();
            let _ = child.wait();
            if terminated.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(CaisError::new(
                    ErrorCode::Transport,
                    "PostgreSQL session was interrupted.",
                ));
            }
            return Err(CaisError::new(
                ErrorCode::Timeout,
                "PostgreSQL session reached the administrative time limit.",
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn broker(
    path: &Path,
    policy: &ServerConfig,
    operation: Operation,
) -> Result<(Option<Vec<u8>>, serde_json::Value)> {
    let private = matches!(operation, Operation::DatabaseCredentials { .. });
    let mut child = cais_host::broker_command(path, policy)?
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| failure())?;
    let mut input = child.stdin.take().ok_or_else(failure)?;
    let mut output = child.stdout.take().ok_or_else(failure)?;
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let result = (|| {
            read_hello(&mut output)?;
            let request = Request {
                protocol_version: PROTOCOL_VERSION,
                request_id: "database-session".into(),
                operation,
            };
            write_frame(&mut input, &request)?;
            drop(input);
            let mut response: Response = read_frame(&mut output)?;
            check(&response)?;
            let mut secret = None;
            if private {
                match response.result {
                    Outcome::PrivateFileReady { bytes } if (1..=65536).contains(&bytes) => {
                        let mut data = vec![0; bytes as usize];
                        output
                            .read_exact(&mut data)
                            .map_err(|_| cais_protocol::transport())?;
                        secret = Some(data);
                        response = read_frame(&mut output)?;
                        check(&response)?;
                    }
                    Outcome::Error { error } => return Err(error),
                    _ => return Err(cais_protocol::protocol()),
                }
            }
            let data = match response.result {
                Outcome::Success { data } => data,
                Outcome::Error { error } => return Err(error),
                _ => return Err(cais_protocol::protocol()),
            };
            if output
                .read(&mut [0])
                .map_err(|_| cais_protocol::transport())?
                != 0
            {
                return Err(cais_protocol::protocol());
            }
            Ok((secret, data))
        })();
        let _ = tx.send(result);
    });
    let until = Instant::now() + Duration::from_secs(20);
    let result = rx
        .recv_timeout(Duration::from_secs(20))
        .map_err(|_| failure())
        .and_then(|r| r);
    if result.is_ok() {
        while Instant::now() < until {
            if let Some(status) = child.try_wait().map_err(|_| failure())? {
                return if status.success() {
                    result
                } else {
                    Err(failure())
                };
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    result.and(Err(failure()))
}
fn check(response: &Response) -> Result<()> {
    if response.protocol_version == PROTOCOL_VERSION && response.request_id == "database-session" {
        Ok(())
    } else {
        Err(cais_protocol::protocol())
    }
}
fn failure() -> CaisError {
    CaisError::new(
        ErrorCode::Transport,
        "Cannot establish the authorized PostgreSQL session.",
    )
}
