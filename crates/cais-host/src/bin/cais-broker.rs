#[cfg(target_os = "linux")]
mod native {
    use cais_core::{CaisError, Capabilities, ErrorCode, Result};
    use cais_host::{Actor, DEFAULT_POLICY, Host, authenticated_actor};
    use cais_protocol::{
        Hello, Operation, Outcome, PROTOCOL_VERSION, Request, Response, read_frame, send_hello,
        write_frame,
    };
    use std::{
        io::{self, Read, Write},
        path::Path,
        sync::mpsc,
        time::{Duration, Instant},
    };

    pub fn run() -> Result<()> {
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        if args.len() == 4
            && args[3] == "--acknowledge-inspected"
            && (args[0] == "--resolve"
                || args[0] == "--forget-failed-registration"
                || args[0] == "--forget-empty-database")
        {
            let host = Host::open(Path::new(DEFAULT_POLICY))?;
            let project = args[1].to_str().ok_or_else(cais_protocol::protocol)?;
            let revision = args[2].to_str().ok_or_else(cais_protocol::protocol)?;
            if args[0] == "--resolve" {
                let status = host.resolve_after_inspection(project, revision)?;
                println!(
                    "{}",
                    serde_json::to_string(&status).map_err(|_| cais_protocol::protocol())?
                );
            } else if args[0] == "--forget-empty-database" {
                host.forget_empty_database(project, revision)?;
                println!(
                    "Empty database provisioning checkpoint released after administrative inspection. No resources were deleted."
                );
            } else {
                host.forget_failed_registration(project, revision)?;
                println!(
                    "Failed registration archived after administrative cleanup. No application data was deleted."
                );
            }
            return Ok(());
        }
        if args.len() == 1 && args[0] == "--init" {
            let host = Host::initialize(Path::new(DEFAULT_POLICY))?;
            host.initialize_postgres()?;
            host.initialize_integrations()?;
            host.initialize_catalog()?;
            host.install_operator_access()?;
            println!("Cais host initialized.");
            return Ok(());
        }
        if !args.is_empty() {
            return Err(CaisError::new(
                ErrorCode::InvalidRequest,
                "The broker accepts no operation arguments.",
            ));
        }
        let host = Host::open(Path::new(DEFAULT_POLICY))?;
        let actor = authenticated_actor()?;
        let mut input = TimedInput::new(Duration::from_secs(
            host.settings.limits.upload_seconds.into(),
        ));
        let mut output = io::stdout().lock();
        send_hello(
            &mut output,
            &Hello {
                capabilities: capabilities(&host, &actor),
                execution_limits: Some(cais_protocol::ExecutionLimits {
                    upload_seconds: host.settings.limits.upload_seconds,
                    execution_seconds: host.settings.limits.execution_seconds,
                }),
                ..Hello::default()
            },
        )?;
        let request = read_frame::<Request>(&mut input);
        let (request_id, result) = match request {
            Ok(request) => {
                let id = if request.validate().is_ok() {
                    request.request_id.clone()
                } else {
                    "invalid".into()
                };
                let result = request
                    .validate()
                    .and_then(|_| dispatch(&host, &actor, request, &mut input, &mut output));
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

    fn capabilities(host: &Host, actor: &Actor) -> Capabilities {
        let operator = host.policy.operators.contains_key(actor.name())
            || host
                .policy
                .external_projects
                .values()
                .any(|p| p.operators.iter().any(|s| s == actor.name()))
            || host
                .policy
                .projects
                .values()
                .any(|p| p.operators.iter().any(|s| s == actor.name()));
        let mut operations = if operator {
            [
                "capabilities",
                "list",
                "plan",
                "status",
                "register",
                "environment",
                "restart",
                "metadata",
            ]
            .map(String::from)
            .to_vec()
        } else {
            ["capabilities", "status", "deploy"]
                .map(String::from)
                .to_vec()
        };
        if operator && host.settings.postgres.is_some() {
            operations.extend(
                [
                    "database_connection",
                    "database_create",
                    "database_reconcile",
                    "database_credentials",
                ]
                .map(String::from),
            );
        }
        if operator && host.settings.caddy.is_some() {
            operations.extend(["proxy_apply", "proxy_remove"].map(String::from));
        }
        if operator && host.settings.backup.is_some() {
            operations.push("backup_register".into());
        }
        Capabilities {
            operations,
            deployment: true,
            proxy_management: host.settings.caddy.is_some(),
            database_management: host.settings.postgres.is_some(),
            ..Capabilities::default()
        }
    }

    fn json(value: impl serde::Serialize) -> Result<serde_json::Value> {
        serde_json::to_value(value)
            .map_err(|_| CaisError::new(ErrorCode::Internal, "Result serialization failed."))
    }

    fn dispatch(
        host: &Host,
        actor: &Actor,
        request: Request,
        input: &mut impl Read,
        output: &mut impl Write,
    ) -> Result<serde_json::Value> {
        host.start_execution();
        match request.operation {
            Operation::DatabaseConnection { project } => {
                json(host.database_connection(actor, &project)?)
            }
            Operation::DatabaseCredentials { project } => {
                let bytes = host.database_private_file(actor, &project)?;
                write_frame(
                    output,
                    &Response {
                        protocol_version: PROTOCOL_VERSION,
                        request_id: request.request_id.clone(),
                        result: Outcome::PrivateFileReady {
                            bytes: bytes.len() as u64,
                        },
                    },
                )?;
                output
                    .write_all(&bytes)
                    .map_err(|_| cais_protocol::transport())?;
                output.flush().map_err(|_| cais_protocol::transport())?;
                Ok(serde_json::json!({"project":project,"exported":true}))
            }
            Operation::DatabaseCreate { project, expected } => {
                json(host.database_create(actor, &project, &expected)?)
            }
            Operation::DatabaseReconcile { project, expected } => {
                json(host.database_reconcile(actor, &project, &expected)?)
            }
            Operation::Capabilities {} => json(capabilities(host, actor)),
            Operation::List {} => json(host.list(actor)?),
            Operation::Plan { project } => host.plan(actor, *project),
            Operation::Status { project } => host.inspect(actor, &project),
            Operation::Register {
                project,
                deploy_public_key,
                expected,
            } => json(host.register(actor, *project, &deploy_public_key, &expected)?),
            Operation::Environment {
                project,
                values,
                expected,
            } => json(host.set_environment(actor, &project, values, &expected)?),
            Operation::Restart { project, expected } => {
                json(host.restart(actor, &project, &expected)?)
            }
            Operation::Metadata {
                project,
                metadata,
                expected,
            } => json(host.set_metadata(actor, &project, *metadata, &expected)?),
            Operation::ProxyApply { project, expected } => {
                json(host.proxy_apply(actor, &project, &expected)?)
            }
            Operation::ProxyRemove { project, expected } => {
                json(host.proxy_remove(actor, &project, &expected)?)
            }
            Operation::BackupRegister { project, expected } => {
                json(host.backup_register(actor, &project, &expected)?)
            }
            Operation::Deploy {
                project,
                expected,
                compressed_bytes,
                sha256,
                configuration_sha256,
            } => {
                let status = host.deploy(
                    actor,
                    cais_host::UploadDeclaration {
                        project: &project,
                        expected: &expected,
                        size: compressed_bytes,
                        digest: &sha256,
                        configuration_sha256: &configuration_sha256,
                        request_id: &request.request_id,
                    },
                    input,
                    || {
                        write_frame(
                            output,
                            &Response {
                                protocol_version: PROTOCOL_VERSION,
                                request_id: request.request_id.clone(),
                                result: Outcome::UploadReady { compressed_bytes },
                            },
                        )
                    },
                )?;
                json(status)
            }
        }
    }

    /// Bounds idle and total input time without unsafe descriptor operations. At most two
    /// small chunks are buffered; process exit closes the reader even for a stalled peer.
    struct TimedInput {
        rx: mpsc::Receiver<io::Result<Vec<u8>>>,
        current: io::Cursor<Vec<u8>>,
        deadline: Instant,
    }
    impl TimedInput {
        fn new(timeout: Duration) -> Self {
            let (tx, rx) = mpsc::sync_channel(1);
            std::thread::spawn(move || {
                let mut input = io::stdin().lock();
                loop {
                    let mut bytes = vec![0; 8192];
                    let result = input.read(&mut bytes).map(|count| {
                        bytes.truncate(count);
                        bytes
                    });
                    let end = result.as_ref().map_or(true, |bytes| bytes.is_empty());
                    if tx.send(result).is_err() || end {
                        break;
                    }
                }
            });
            Self {
                rx,
                current: io::Cursor::new(Vec::new()),
                deadline: Instant::now() + timeout,
            }
        }
    }
    impl Read for TimedInput {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if buffer.is_empty() {
                return Ok(0);
            }
            if self.current.position() >= self.current.get_ref().len() as u64 {
                let bytes = self
                    .rx
                    .recv_timeout(self.deadline.saturating_duration_since(Instant::now()))
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "input deadline"))??;
                self.current = io::Cursor::new(bytes);
            }
            self.current.read(buffer)
        }
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    if let Err(error) = native::run() {
        eprintln!("{}", error.message);
        std::process::exit(1);
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("The Cais administrative broker supports Linux only.");
        std::process::exit(1);
    }
}
