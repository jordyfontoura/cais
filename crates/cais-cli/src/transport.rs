use cais_core::{CaisError, ErrorCode, Result, Target};
use cais_protocol::{
    Operation, Outcome, PROTOCOL_VERSION, Request, Response, read_frame, read_hello, write_frame,
};
use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(crate) fn ssh_command(target: &Target, base: &Path) -> Result<Command> {
    ssh_command_mode(target, base, true)
}
fn ssh_command_mode(target: &Target, base: &Path, clear_forwardings: bool) -> Result<Command> {
    let known_hosts = file_path(base, &target.known_hosts)?;
    let mut command = Command::new(ssh_executable(target, base)?);
    if !clear_forwardings {
        // Forwarding must not inherit additive LocalForward/RemoteForward entries.
        command.args(["-F", "none"]);
    } else if let Some(config) = &target.ssh_config {
        command.arg("-F").arg(file_path(base, config)?);
    }
    command
        .args([
            "-T",
            "-a",
            "-x",
            "-o",
            if clear_forwardings {
                "ClearAllForwardings=yes"
            } else {
                "ClearAllForwardings=no"
            },
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            "-o",
            "ControlPersist=no",
            "-o",
            "Tunnel=no",
            "-o",
            "VerifyHostKeyDNS=no",
            "-o",
            "UpdateHostKeys=no",
            "-o",
            "KnownHostsCommand=none",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "NoHostAuthenticationForLocalhost=no",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "ServerAliveInterval=5",
            "-o",
            "ServerAliveCountMax=2",
        ])
        .arg("-o")
        .arg(format!("ConnectTimeout={}", target.timeout_seconds))
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", option_path(&known_hosts)?))
        .arg("-o")
        .arg("GlobalKnownHostsFile=none");
    if let Some(port) = target.port {
        command.arg("-p").arg(port.to_string());
    }
    if let Some(identity) = &target.identity_file {
        command.arg("-i").arg(file_path(base, identity)?);
    }
    Ok(command)
}

pub fn psql(target: &Target, base: &Path, project: &str) -> Result<()> {
    use std::io::IsTerminal;
    if !cais_core::identifier(project) {
        return Err(cais_protocol::protocol());
    }
    let mut command = ssh_command(target, base)?;
    if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        command.arg("-t");
    }
    let status = command
        .arg("--")
        .arg(&target.ssh)
        .arg(&target.server_path)
        .args(["--db-psql", project])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|_| cais_protocol::transport())?;
    if status.success() {
        Ok(())
    } else if status.code() == Some(255) {
        Err(cais_protocol::transport())
    } else {
        Err(CaisError::new(
            status
                .code()
                .and_then(ErrorCode::from_exit_code)
                .unwrap_or(ErrorCode::OperationFailed),
            "PostgreSQL session ended without success; inspect its diagnostic.",
        ))
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TunnelLaunch {
    target: Target,
    base: PathBuf,
    connection: cais_core::DatabaseConnection,
    port: u16,
}

pub struct DatabaseTunnel {
    child: std::process::Child,
    input: Option<std::process::ChildStdin>,
    pub port: u16,
}
impl DatabaseTunnel {
    pub fn running(&mut self) -> Result<bool> {
        self.child
            .try_wait()
            .map(|v| v.is_none())
            .map_err(|_| cais_protocol::transport())
    }
    pub fn close(&mut self) -> Result<()> {
        self.input.take();
        let until = Instant::now() + Duration::from_secs(5);
        while Instant::now() < until {
            if let Some(status) = self
                .child
                .try_wait()
                .map_err(|_| cais_protocol::transport())?
            {
                return if status.success() {
                    Ok(())
                } else {
                    Err(cais_protocol::transport())
                };
            }
            thread::sleep(Duration::from_millis(10));
        }
        // Leave the watchdog alive to observe EOF, rather than killing the only
        // process that can terminate all active forwarding channels.
        Err(CaisError::new(
            ErrorCode::Timeout,
            "Tunnel shutdown is not confirmed.",
        ))
    }
}
impl Drop for DatabaseTunnel {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
fn check_forward_target(target: &Target, port: u16) -> Result<()> {
    if !target.ssh.contains('@') || target.identity_file.is_none() || (port != 0 && port < 1024) {
        return Err(CaisError::new(
            ErrorCode::InvalidConfig,
            "Database forwarding requires an explicit user@hostname and identity_file; use port zero or an unprivileged local port.",
        ));
    }
    Ok(())
}
pub fn database_tunnel(
    target: &Target,
    base: &Path,
    connection: &cais_core::DatabaseConnection,
    local_port: u16,
) -> Result<DatabaseTunnel> {
    use cais_core::Validate;
    connection.validate()?;
    check_forward_target(target, local_port)?;
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, local_port))
        .map_err(|_| CaisError::new(ErrorCode::Conflict, "Local tunnel port is unavailable."))?;
    let port = listener
        .local_addr()
        .map_err(|_| cais_protocol::transport())?
        .port();
    drop(listener);
    let launch = TunnelLaunch {
        target: target.clone(),
        base: std::fs::canonicalize(base).map_err(|_| cais_protocol::transport())?,
        connection: connection.clone(),
        port,
    };
    let mut command =
        Command::new(std::env::current_exe().map_err(|_| cais_protocol::transport())?);
    command.arg("__tunnel-supervisor");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW for the private watchdog.
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| cais_protocol::transport())?;
    let input = child.stdin.take().ok_or_else(cais_protocol::transport)?;
    let mut output = child.stdout.take().ok_or_else(cais_protocol::transport)?;
    let mut tunnel = DatabaseTunnel {
        child,
        input: Some(input),
        port,
    };
    write_frame(
        tunnel.input.as_mut().ok_or_else(cais_protocol::transport)?,
        &launch,
    )?;
    let wanted = connection.clone();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let result = read_tunnel_ready(&mut output, &wanted);
        let _ = tx.send(result);
    });
    rx.recv_timeout(Duration::from_secs(target.timeout_seconds.into()))
        .map_err(|_| {
            CaisError::new(ErrorCode::Timeout, "Database tunnel readiness timed out.")
        })??;
    if !tunnel.running()? {
        return Err(cais_protocol::transport());
    }
    Ok(tunnel)
}
fn read_tunnel_ready(output: &mut impl Read, wanted: &cais_core::DatabaseConnection) -> Result<()> {
    use cais_core::Validate;
    let mut magic = [0; 8];
    output
        .read_exact(&mut magic)
        .map_err(|_| cais_protocol::transport())?;
    if &magic != cais_protocol::DATABASE_SESSION_MAGIC {
        return Err(cais_protocol::protocol());
    }
    let actual: cais_core::DatabaseConnection = read_frame(output)?;
    actual.validate()?;
    if &actual != wanted {
        return Err(CaisError::new(
            ErrorCode::Conflict,
            "Database connection changed before forwarding.",
        ));
    }
    Ok(())
}

/// Private portable watchdog. The CLI's input pipe is its lifetime lease; EOF
/// explicitly kills OpenSSH even when forwarded database connections remain active.
pub fn supervise_database_tunnel() -> Result<()> {
    use cais_core::Validate;
    use std::io::Write;
    let launch: TunnelLaunch = { read_frame(&mut std::io::stdin().lock())? };
    cais_core::ClientConfig {
        schema_version: cais_core::SchemaVersion,
        targets: std::collections::BTreeMap::from([("owned".into(), launch.target.clone())]),
    }
    .validate()?;
    launch.connection.validate()?;
    check_forward_target(&launch.target, launch.port)?;
    if launch.port == 0 || !launch.base.is_absolute() {
        return Err(cais_protocol::protocol());
    }
    let mut command = ssh_command_mode(&launch.target, &launch.base, false)?;
    command
        .args([
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "GatewayPorts=no",
            "-L",
        ])
        .arg(format!(
            "127.0.0.1:{}:{}",
            launch.port, launch.connection.socket
        ))
        .arg("--")
        .arg(&launch.target.ssh)
        .arg(&launch.target.server_path)
        .args(["--db-hold", &launch.connection.project]);
    let child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| cais_protocol::transport())?;
    let mut ssh = OwnedSsh(child);
    let mut output = ssh.0.stdout.take().ok_or_else(cais_protocol::transport)?;
    enum Notice {
        ParentClosed,
        Ready,
        Broken,
    }
    let (tx, rx) = mpsc::channel();
    let parent = tx.clone();
    thread::spawn(move || {
        let result = std::io::stdin().read(&mut [0]);
        let _ = parent.send(if matches!(result, Ok(0)) {
            Notice::ParentClosed
        } else {
            Notice::Broken
        });
    });
    let wanted = launch.connection.clone();
    thread::spawn(move || {
        if read_tunnel_ready(&mut output, &wanted).is_err() {
            let _ = tx.send(Notice::Broken);
            return;
        }
        let _ = tx.send(Notice::Ready);
        if !matches!(output.read(&mut [0]), Ok(0)) {
            let _ = tx.send(Notice::Broken);
        }
    });
    let mut ready = false;
    let mut until = Instant::now() + Duration::from_secs(launch.target.timeout_seconds.into());
    loop {
        match rx.recv_timeout(Duration::from_millis(25)) {
            Ok(Notice::ParentClosed) => return Ok(()),
            Ok(Notice::Broken) => return Err(cais_protocol::transport()),
            Ok(Notice::Ready) => {
                let mut out = std::io::stdout().lock();
                out.write_all(cais_protocol::DATABASE_SESSION_MAGIC)
                    .map_err(|_| cais_protocol::transport())?;
                write_frame(&mut out, &launch.connection)?;
                out.flush().map_err(|_| cais_protocol::transport())?;
                ready = true;
                until =
                    Instant::now() + Duration::from_secs(launch.connection.session_seconds.into());
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(cais_protocol::transport()),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if ssh
            .0
            .try_wait()
            .map_err(|_| cais_protocol::transport())?
            .is_some()
        {
            return Err(cais_protocol::transport());
        }
        if Instant::now() >= until {
            return if ready {
                Ok(())
            } else {
                Err(CaisError::new(
                    ErrorCode::Timeout,
                    "Database tunnel readiness timed out.",
                ))
            };
        }
    }
}
struct OwnedSsh(std::process::Child);
impl Drop for OwnedSsh {
    fn drop(&mut self) {
        self.0.stdin.take();
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub fn call(target: &Target, base: &Path, operation: Operation) -> Result<Outcome> {
    exchange(target, base, operation, None, None)
}

pub fn upload(
    target: &Target,
    base: &Path,
    operation: Operation,
    file: std::fs::File,
    size: u64,
) -> Result<Outcome> {
    exchange(target, base, operation, Some((file, size)), None)
}

pub fn download(
    target: &Target,
    base: &Path,
    operation: Operation,
    file: std::fs::File,
) -> Result<Outcome> {
    exchange(target, base, operation, None, Some(file))
}

fn exchange(
    target: &Target,
    base: &Path,
    operation: Operation,
    upload: Option<(std::fs::File, u64)>,
    download: Option<std::fs::File>,
) -> Result<Outcome> {
    let mutating = operation.is_mutation();
    let submitted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let submitted_worker = submitted.clone();
    let mut command = ssh_command(target, base)?;
    // A validated absolute POSIX executable path is the entire remote command.
    // OpenSSH may invoke a remote shell, so it must never contain shell syntax.
    command.arg("--").arg(&target.ssh).arg(&target.server_path);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| {
            CaisError::new(
                ErrorCode::Transport,
                "Cannot start the system OpenSSH client.",
            )
        })?;
    let mut input = child.stdin.take().ok_or_else(cais_protocol::transport)?;
    let mut output = child.stdout.take().ok_or_else(cais_protocol::transport)?;
    let id = format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let mut deadline = Instant::now() + Duration::from_secs(target.timeout_seconds.into());
    enum Event {
        Negotiated(Option<cais_protocol::ExecutionLimits>),
        Finished(Result<Outcome>),
    }
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let result = (|| {
            let hello = read_hello(&mut output)?;
            sender
                .send(Event::Negotiated(hello.execution_limits))
                .map_err(|_| cais_protocol::transport())?;
            let request = Request {
                protocol_version: PROTOCOL_VERSION,
                request_id: id.clone(),
                operation,
            };
            // Refused before anything is sent, so it is never an unknown outcome.
            if serde_json::to_vec(&request)
                .map_or(true, |bytes| bytes.len() > cais_protocol::MAX_FRAME)
            {
                return Err(CaisError::new(
                    ErrorCode::InvalidConfig,
                    "The request is larger than the protocol allows.",
                ));
            }
            submitted_worker.store(true, std::sync::atomic::Ordering::Release);
            write_frame(&mut input, &request)?;
            if let Some((mut file, size)) = upload {
                let ready: Response = read_frame(&mut output)?;
                if ready.protocol_version != PROTOCOL_VERSION || ready.request_id != id {
                    return Err(cais_protocol::protocol());
                }
                match ready.result {
                    Outcome::UploadReady { compressed_bytes } if compressed_bytes == size => {
                        let copied = std::io::copy(&mut file.by_ref().take(size), &mut input)
                            .map_err(|_| cais_protocol::transport())?;
                        if copied != size {
                            return Err(cais_protocol::transport());
                        }
                    }
                    Outcome::Error { error } => {
                        drop(input);
                        ensure_eof(&mut output)?;
                        return Ok(Outcome::Error { error });
                    }
                    _ => return Err(cais_protocol::protocol()),
                }
            }
            drop(input);
            let mut response: Response = read_frame(&mut output)?;
            if response.protocol_version != PROTOCOL_VERSION || response.request_id != id {
                return Err(cais_protocol::protocol());
            }
            if let Some(mut file) = download {
                match response.result {
                    Outcome::PrivateFileReady { bytes } if (1..=65536).contains(&bytes) => {
                        let count = std::io::copy(&mut output.by_ref().take(bytes), &mut file)
                            .map_err(|_| cais_protocol::transport())?;
                        if count != bytes {
                            return Err(cais_protocol::protocol());
                        }
                        file.sync_all().map_err(|_| cais_protocol::transport())?;
                        response = read_frame(&mut output)?;
                    }
                    Outcome::Error { .. } => {}
                    _ => return Err(cais_protocol::protocol()),
                }
            }
            if response.protocol_version != PROTOCOL_VERSION || response.request_id != id {
                return Err(cais_protocol::protocol());
            }
            if matches!(
                response.result,
                Outcome::UploadReady { .. } | Outcome::PrivateFileReady { .. }
            ) {
                return Err(cais_protocol::protocol());
            }
            // One request permits exactly one result. The overall deadline also covers EOF.
            let mut trailing = [0];
            if output
                .read(&mut trailing)
                .map_err(|_| cais_protocol::transport())?
                != 0
            {
                return Err(cais_protocol::protocol());
            }
            Ok(response.result)
        })();
        let _ = sender.send(Event::Finished(result));
    });
    let result = loop {
        match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(Event::Negotiated(limits)) => {
                if mutating && let Some(limits) = limits {
                    deadline = Instant::now()
                        + Duration::from_secs(
                            u64::from(limits.upload_seconds)
                                + u64::from(limits.execution_seconds)
                                + 5,
                        );
                }
            }
            Ok(Event::Finished(result)) => break result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                break Err(CaisError::new(
                    ErrorCode::Timeout,
                    "SSH request timed out without a confirmed result.",
                ));
            }
            Err(_) => break Err(cais_protocol::transport()),
        }
    };
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return uncertain(result, mutating, &submitted);
    }
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return result,
            Ok(Some(_)) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return uncertain(Err(cais_protocol::transport()), mutating, &submitted);
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return uncertain(
                    Err(CaisError::new(
                        ErrorCode::Timeout,
                        "SSH session did not finish before its deadline.",
                    )),
                    mutating,
                    &submitted,
                );
            }
        }
    }
}

fn uncertain(
    result: Result<Outcome>,
    mutating: bool,
    submitted: &std::sync::atomic::AtomicBool,
) -> Result<Outcome> {
    result.map_err(|error| if mutating && submitted.load(std::sync::atomic::Ordering::Acquire) {
        CaisError::new(ErrorCode::UnknownOutcome, "No confirmed mutation result. Inspect status before retrying; the request may have taken effect.")
    } else { error })
}

fn ensure_eof(output: &mut impl Read) -> Result<()> {
    if output
        .read(&mut [0])
        .map_err(|_| cais_protocol::transport())?
        == 0
    {
        Ok(())
    } else {
        Err(cais_protocol::protocol())
    }
}

fn ssh_executable(target: &Target, base: &Path) -> Result<PathBuf> {
    if let Some(path) = &target.ssh_executable {
        return file_path(base, path);
    }
    #[cfg(windows)]
    {
        let directory = std::env::var_os("SystemRoot").ok_or_else(|| {
            CaisError::new(
                ErrorCode::Unsupported,
                "Native Windows OpenSSH is unavailable; configure ssh_executable.",
            )
        })?;
        let path = PathBuf::from(directory).join("System32/OpenSSH/ssh.exe");
        if !path.is_file() {
            return Err(CaisError::new(
                ErrorCode::Unsupported,
                "Native Windows OpenSSH is unavailable; configure ssh_executable.",
            ));
        }
        Ok(path)
    }
    #[cfg(not(windows))]
    {
        Ok(PathBuf::from("ssh"))
    }
}

fn file_path(base: &Path, value: &str) -> Result<PathBuf> {
    let path = base.join(value).canonicalize().map_err(|_| {
        CaisError::new(
            ErrorCode::InvalidConfig,
            "SSH identity or known_hosts file is unavailable.",
        )
    })?;
    if !path.is_file() {
        return Err(CaisError::new(
            ErrorCode::InvalidConfig,
            "SSH configuration requires a regular file.",
        ));
    }
    // Windows canonical paths use the verbatim prefix, which OpenSSH cannot reliably parse.
    #[cfg(windows)]
    let path = {
        let text = path.to_string_lossy();
        if let Some(unc) = text.strip_prefix("\\\\?\\UNC\\") {
            PathBuf::from(format!("\\\\{unc}"))
        } else {
            PathBuf::from(text.strip_prefix("\\\\?\\").unwrap_or(&text))
        }
    };
    Ok(path)
}

fn option_path(path: &Path) -> Result<String> {
    let text = path.to_str().ok_or_else(|| {
        CaisError::new(
            ErrorCode::InvalidConfig,
            "SSH paths require Unicode filenames.",
        )
    })?;
    // -o values are parsed again by OpenSSH. Quote a single path, including spaces;
    // prevent percent-token expansion or option-parser interpolation.
    if text.contains(['"', '%', '\r', '\n']) {
        return Err(CaisError::new(
            ErrorCode::InvalidConfig,
            "SSH known_hosts path contains unsupported option syntax.",
        ));
    }
    let text = if cfg!(windows) {
        text.replace('\\', "/")
    } else {
        text.replace('\\', "\\\\")
    };
    Ok(format!("\"{text}\""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cais_core::{ClientConfig, decode_config};
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn effective_openssh_configuration_locks_trust_and_preserves_alias_port() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("hosts"), "").unwrap();
        std::fs::write(directory.path().join("config"), "Host fixture\n HostName 127.0.0.1\n Port 2222\n ForwardAgent yes\n ForwardX11 yes\n PermitLocalCommand yes\n VerifyHostKeyDNS yes\n UpdateHostKeys yes\n KnownHostsCommand no-such-binary\n LocalForward 49123 localhost:5432\n ControlMaster auto\n ControlPath /tmp/untrusted-master\n ControlPersist yes\n Tunnel yes\n").unwrap();
        let config: ClientConfig = decode_config(&serde_json::to_vec(&json!({"schema_version":1,"targets":{"test":{
            "ssh":"fixture","server_path":"/bin/cais-server","known_hosts":"hosts","ssh_config":"config"
        }}})).unwrap()).unwrap();
        let mut target = config.targets["test"].clone();
        for explicit_port in [None, Some(3333)] {
            target.port = explicit_port;
            let output = ssh_command(&target, directory.path())
                .unwrap()
                .arg("-G")
                .arg("--")
                .arg("fixture")
                .output()
                .unwrap();
            assert!(output.status.success());
            let text = String::from_utf8(output.stdout).unwrap();
            let fields: BTreeMap<_, _> = text
                .lines()
                .filter_map(|line| line.split_once(' '))
                .collect();
            assert_eq!(
                fields.get("port"),
                Some(&if explicit_port.is_some() {
                    "3333"
                } else {
                    "2222"
                })
            );
            for field in [
                "forwardagent",
                "forwardx11",
                "permitlocalcommand",
                "verifyhostkeydns",
                "updatehostkeys",
            ] {
                assert!(
                    matches!(fields.get(field), Some(&"no") | Some(&"false")),
                    "unsafe effective SSH setting {field}"
                );
            }
            assert_eq!(fields.get("clearallforwardings"), Some(&"yes"));
            for field in ["controlmaster", "controlpersist", "tunnel"] {
                assert!(
                    matches!(fields.get(field), Some(&"no") | Some(&"false")),
                    "unsafe multiplex/tunnel setting {field}"
                );
            }
            assert!(matches!(fields.get("controlpath"), None | Some(&"none")));
            assert!(!text.contains("no-such-binary"));
            assert!(!fields.contains_key("localforward"));
        }
    }
}
