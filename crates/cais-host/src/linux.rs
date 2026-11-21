use super::*;
mod catalog;
mod integrations;
mod postgres;
use cais_core::{
    App, CaisError, ErrorCode, HostSettings, ProjectPolicy, Result, Runtime, ServerConfig,
    Validate, decode_config, decode_json, identifier,
};
use fs2::FileExt;
pub use postgres::postgres_client_path;
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MIB: u64 = 1024 * 1024;
pub const DEFAULT_POLICY: &str = "/etc/cais/server.json";

pub struct Actor {
    name: String,
}

struct Delegated {
    exposure: bool,
    backup: bool,
    database: bool,
}

pub struct UploadDeclaration<'a> {
    pub project: &'a str,
    pub expected: &'a Expected,
    pub size: u64,
    pub digest: &'a str,
    pub configuration_sha256: &'a str,
    pub request_id: &'a str,
}
impl Actor {
    pub fn name(&self) -> &str {
        &self.name
    }
}

pub struct Host {
    pub policy: ServerConfig,
    pub settings: HostSettings,
    pub instance: String,
    pub policy_sha256: String,
    execution_deadline: Cell<Instant>,
}

/// The unprivileged entrypoint may select native mode only from the fixed root policy.
pub fn enter_broker(path: &Path, policy: &ServerConfig) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let _error = broker_command(path, policy)?.exec();
    Err(internal())
}

/// Builds only the fixed no-argument sudo entrypoint; broker reauthorizes each request.
pub fn broker_command(path: &Path, policy: &ServerConfig) -> Result<Command> {
    if path != Path::new(DEFAULT_POLICY) {
        return Err(denied());
    }
    trusted_file(path)?;
    let settings = policy.host.as_ref().ok_or_else(denied)?;
    trusted_file(Path::new(&settings.paths.broker))?;
    let mut command = Command::new("/usr/bin/sudo");
    command
        .args(["-n", "--", &settings.paths.broker])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    Ok(command)
}

pub fn authenticated_actor() -> Result<Actor> {
    require_root()?;
    let uid = std::env::var("SUDO_UID").ok();
    match (uid, std::env::var("SUDO_USER").ok()) {
        (Some(uid), Some(name)) => {
            let expected: u32 = uid.parse().map_err(|_| denied())?;
            let actual = command("/usr/bin/id", &["-u", "--", &name], 10)?;
            if !actual.success || actual.text.trim().parse::<u32>().ok() != Some(expected) {
                return Err(denied());
            }
            Ok(Actor { name })
        }
        (None, None) => Ok(Actor {
            name: "root".into(),
        }),
        _ => Err(denied()),
    }
}

impl Host {
    pub fn initialize(path: &Path) -> Result<Self> {
        let (policy, settings, policy_sha256) = load_policy(path)?;
        if Path::new(&settings.paths.state).join("instance").exists() {
            return Self::open(path);
        }
        let roots = [
            (&settings.paths.apps, 0o755),
            (&settings.paths.state, 0o700),
            (&settings.paths.config, 0o711),
            (&settings.paths.data, 0o755),
        ];
        for (root, _) in &roots {
            trusted_existing_ancestors(Path::new(root))?;
            if Path::new(root).exists() && fs::read_dir(root).map_err(io_error)?.next().is_some() {
                return Err(CaisError::new(
                    ErrorCode::Conflict,
                    "Host roots must be new or empty; existing installations are not adopted.",
                ));
            }
        }
        trusted_existing_ancestors(Path::new(&settings.paths.units))?;
        let instance = fs::read_to_string("/proc/sys/kernel/random/uuid")
            .map_err(io_error)?
            .trim()
            .to_owned();
        for (root, mode) in roots {
            fs::create_dir_all(root).map_err(io_error)?;
            permissions(Path::new(root), mode)?;
            atomic_write(
                &Path::new(root).join(".cais-root"),
                instance.as_bytes(),
                0o600,
            )?;
        }
        for directory in ["records", "locks", "incoming"] {
            private_directory(&Path::new(&settings.paths.state).join(directory), 0o700)?;
        }
        private_directory(&Path::new(&settings.paths.apps).join(".deploy"), 0o755)?;
        atomic_write(
            &Path::new(&settings.paths.state).join("instance"),
            instance.as_bytes(),
            0o600,
        )?;
        Ok(Self {
            execution_deadline: Cell::new(
                Instant::now() + Duration::from_secs(settings.limits.execution_seconds.into()),
            ),
            policy,
            settings,
            instance,
            policy_sha256,
        })
    }

    pub fn open(path: &Path) -> Result<Self> {
        let (policy, settings, policy_sha256) = load_policy(path)?;
        let instance_path = Path::new(&settings.paths.state).join("instance");
        if policy.external_projects.keys().any(|name| {
            Path::new(&settings.paths.state)
                .join("records")
                .join(format!("{name}.json"))
                .exists()
        }) {
            return Err(CaisError::new(
                ErrorCode::Conflict,
                "External project references cannot shadow native records.",
            ));
        }
        trusted_file(&instance_path)?;
        let instance = fs::read_to_string(instance_path).map_err(io_error)?;
        if instance.len() != 36 || !instance.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
            return Err(internal());
        }
        for root in [
            &settings.paths.apps,
            &settings.paths.state,
            &settings.paths.config,
            &settings.paths.data,
        ] {
            trusted_existing_ancestors(Path::new(root))?;
            let marker = Path::new(root).join(".cais-root");
            trusted_file(&marker)?;
            if fs::read_to_string(marker).map_err(io_error)? != instance {
                return Err(CaisError::new(
                    ErrorCode::Conflict,
                    "Host roots belong to another installation.",
                ));
            }
        }
        Ok(Self {
            execution_deadline: Cell::new(
                Instant::now() + Duration::from_secs(settings.limits.execution_seconds.into()),
            ),
            policy,
            settings,
            instance,
            policy_sha256,
        })
    }

    pub fn start_execution(&self) {
        self.execution_deadline.set(
            Instant::now() + Duration::from_secs(self.settings.limits.execution_seconds.into()),
        );
    }

    /// Administrative acknowledgement only; never repeats a mutation or claims it succeeded.
    pub fn resolve_after_inspection(&self, project: &str, revision: &str) -> Result<Status> {
        require_root()?;
        let _lock = self.lock(project)?;
        let mut record = self.record(project)?;
        if hash_json(&record)? != revision
            || !matches!(record.registration, Registration::Complete {})
        {
            return Err(conflict());
        }
        let operation = record
            .last_operation
            .as_mut()
            .filter(|op| {
                matches!(
                    op.state,
                    OperationState::Unknown | OperationState::InProgress
                )
            })
            .ok_or_else(conflict)?;
        let actor = authenticated_actor()?;
        operation.state = OperationState::Resolved;
        operation.updated_at = now();
        operation.inspection = Some(Inspection {
            by: actor.name,
            at: now(),
        });
        record.deployment = match record.deployment {
            Deployment::Updating { sha256, request_id }
            | Deployment::Failed {
                sha256, request_id, ..
            } if operation.kind == "deploy" => Deployment::Unknown {
                sha256,
                request_id,
                inspected_at: now(),
            },
            deployment => deployment,
        };
        self.save(&mut record)?;
        self.finished_status(record)
    }

    /// Releases a failed name only after an administrator has quarantined all resources.
    /// Never deletes accounts, application files, credentials, persistent data or backups.
    pub fn forget_failed_registration(&self, project: &str, revision: &str) -> Result<()> {
        require_root()?;
        let _global = file_lock(&self.state("locks").join(".global.lock"))?;
        let _lock = self.lock(project)?;
        let record = self.record(project)?;
        if hash_json(&record)? != revision
            || matches!(record.registration, Registration::Complete {})
            || !matches!(record.deployment, Deployment::None {})
        {
            return Err(conflict());
        }
        for path in [
            self.app(project),
            self.data(project),
            Path::new(&self.settings.paths.config).join(project),
            Path::new(&self.settings.paths.units).join(unit_name(project)),
            Path::new(&self.settings.paths.apps)
                .join(".deploy")
                .join(&record.deploy_user),
            Path::new(&self.settings.paths.sudoers).join(format!("cais-{}", record.deploy_user)),
        ] {
            match fs::symlink_metadata(path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(conflict()),
            }
        }
        for user in [&record.runtime_user, &record.deploy_user] {
            if command("/usr/bin/id", &["-u", "--", user], self.timeout())?.success
                || command("/usr/bin/getent", &["group", user], self.timeout())?.success
            {
                return Err(conflict());
            }
        }
        let archive = self.state("retired");
        if !archive.exists() {
            private_directory(&archive, 0o700)?;
        }
        trusted_existing_ancestors(&archive)?;
        let target = archive.join(format!("{project}-{}.json", revision));
        let bytes = serde_json::to_vec(&record).map_err(|_| internal())?;
        if target.exists() {
            trusted_file(&target)?;
            if fs::read(&target).map_err(io_error)? != bytes {
                return Err(conflict());
            }
        } else {
            let mut file = tempfile::NamedTempFile::new_in(&archive).map_err(io_error)?;
            file.write_all(&bytes).map_err(io_error)?;
            file.as_file().sync_all().map_err(io_error)?;
            file.persist_noclobber(&target).map_err(|_| conflict())?;
        }
        File::open(&target)
            .map_err(io_error)?
            .sync_all()
            .map_err(io_error)?;
        File::open(&archive)
            .map_err(io_error)?
            .sync_all()
            .map_err(io_error)?;
        let records = self.state("records");
        fs::remove_file(records.join(format!("{project}.json"))).map_err(io_error)?;
        File::open(records)
            .map_err(io_error)?
            .sync_all()
            .map_err(io_error)?;
        Ok(())
    }

    pub fn list(&self, actor: &Actor) -> Result<Vec<String>> {
        let mut names = self.policy.visible_projects(actor.name());
        names.extend(
            self.policy
                .external_projects
                .iter()
                .filter(|(_, project)| project.operators.iter().any(|name| name == actor.name()))
                .map(|(name, _)| name.clone()),
        );
        for entry in fs::read_dir(self.state("records")).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            if let Some(name) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.strip_suffix(".json"))
                && identifier(name)
            {
                let record = self.record(name)?;
                if self.authorize(actor, &record, false).is_ok() {
                    names.push(name.into());
                }
            }
        }
        names.sort();
        names.dedup();
        Ok(names)
    }

    pub fn plan(&self, actor: &Actor, project: ProjectConfig) -> Result<serde_json::Value> {
        project.validate()?;
        let record = self.optional_record(&project.project)?;
        if let Some(record) = &record {
            self.authorize(actor, record, false)?;
        } else {
            self.creation_policy(actor, &project)?;
        }
        self.supported_project(&project)?;
        Ok(
            serde_json::json!({"project":project.project,"execution_supported":true,"policy_checked":true,
            "expected":self.expected(record.as_ref())?, "configuration_sha256":cais_core::configuration_sha256(&project)?, "actions":[if record.is_some(){"deploy_registered_project"}else{"register_project"}],
            "requested":project,"notes":["Artifacts are validated at upload; a plan is not an exactly-once guarantee."]}),
        )
    }

    pub fn register(
        &self,
        actor: &Actor,
        project: ProjectConfig,
        key: &str,
        expected: &Expected,
    ) -> Result<Status> {
        project.validate()?;
        self.supported_project(&project)?;
        let policy = self.creation_policy(actor, &project)?;
        let _global = file_lock(&self.state("locks").join(".global.lock"))?;
        let _project = self.lock(&project.project)?;
        self.revalidate(expected, None)?;
        if self.optional_record(&project.project)?.is_some() {
            return Err(conflict());
        }
        self.host_unclaimed(&project)?;
        let id = short_id(&project.project);
        let runtime_user = format!("ca-{id}");
        let deploy_user = format!("cd-{id}");
        let app = self.app(&project.project);
        let config = Path::new(&self.settings.paths.config).join(&project.project);
        let data = self.data(&project.project);
        let unit = Path::new(&self.settings.paths.units).join(unit_name(&project.project));
        let deploy_home = Path::new(&self.settings.paths.apps)
            .join(".deploy")
            .join(&deploy_user);
        let sudoers = Path::new(&self.settings.paths.sudoers).join(format!("cais-{deploy_user}"));
        for path in [&app, &config, &data, &unit, &deploy_home, &sudoers] {
            if fs::symlink_metadata(path).is_ok() {
                return Err(CaisError::new(
                    ErrorCode::Conflict,
                    "An application path is already occupied; existing resources are not adopted.",
                ));
            }
        }
        for user in [&runtime_user, &deploy_user] {
            if command("/usr/bin/id", &["-u", "--", user], 10)?.success
                || command("/usr/bin/getent", &["group", user], 10)?.success
            {
                return Err(conflict());
            }
        }
        let key = self.validate_public_key(key)?;
        let port = if matches!(project.app, App::Http { .. }) {
            Some(self.allocate_port()?)
        } else {
            None
        };
        let mut record = Record {
            database_allowed: policy.database,
            database: None,
            backup_allowed: policy.backup,
            metadata: None,
            schema_version: SchemaVersion,
            project,
            members: policy.operators,
            created_by: actor.name.clone(),
            runtime_user,
            deploy_user,
            port,
            registration: Registration::Pending {},
            deployment: Deployment::None {},
            sequence: 0,
            updated_at: now(),
            last_operation: None,
        };
        self.begin_operation(&mut record, actor, "register")?;
        let code_group = self.code_group(&record);
        let result = (|| {
            checked(
                "/usr/sbin/useradd",
                &[
                    "--system",
                    "--user-group",
                    "--no-create-home",
                    "--home-dir",
                    text(&data)?,
                    "--shell",
                    "/usr/sbin/nologin",
                    &record.runtime_user,
                ],
                self.timeout(),
            )?;
            checked(
                "/usr/sbin/useradd",
                &[
                    "--system",
                    "--user-group",
                    "--no-create-home",
                    "--home-dir",
                    text(&deploy_home)?,
                    "--shell",
                    "/bin/sh",
                    &record.deploy_user,
                ],
                self.timeout(),
            )?;
            private_directory(&app, 0o750)?;
            private_directory(&app.join("current"), 0o750)?;
            checked(
                "/usr/bin/chown",
                &[
                    &format!("root:{code_group}"),
                    text(&app)?,
                    text(&app.join("current"))?,
                ],
                self.timeout(),
            )?;
            private_directory(&app.join(".staging"), 0o700)?;
            private_directory(&config, 0o750)?;
            private_directory(&data, 0o700)?;
            checked(
                "/usr/bin/chown",
                &[&format!("root:{}", record.runtime_user), text(&config)?],
                self.timeout(),
            )?;
            atomic_write(&config.join("runtime.env"), b"", 0o640)?;
            checked(
                "/usr/bin/chown",
                &[
                    &format!("root:{}", record.runtime_user),
                    text(&config.join("runtime.env"))?,
                ],
                self.timeout(),
            )?;
            for name in &record.project.data.preserve {
                let link = app.join("current").join(name);
                if let Some(parent) = link.parent() {
                    fs::create_dir_all(parent).map_err(io_error)?;
                }
                if name == ".env" {
                    symlink(config.join("runtime.env"), link).map_err(io_error)?;
                } else {
                    let target = data.join(name);
                    fs::create_dir_all(&target).map_err(io_error)?;
                    checked(
                        "/usr/bin/chown",
                        &[
                            "--recursive",
                            "--no-dereference",
                            &format!("{}:{}", record.runtime_user, record.runtime_user),
                            "--",
                            text(&target)?,
                        ],
                        self.timeout(),
                    )?;
                    symlink(target, link).map_err(io_error)?;
                }
            }
            checked(
                "/usr/bin/chown",
                &[
                    &format!("{}:{}", record.runtime_user, record.runtime_user),
                    text(&data)?,
                ],
                self.timeout(),
            )?;
            private_directory(&deploy_home, 0o755)?;
            private_directory(&deploy_home.join(".ssh"), 0o755)?;
            let authorized = format!(
                "restrict,command=\"{}\" {key}\n",
                self.settings.paths.server
            );
            atomic_write(
                &deploy_home.join(".ssh/authorized_keys"),
                authorized.as_bytes(),
                0o644,
            )?;
            self.install_sudoers(&record.deploy_user)?;
            if matches!(record.project.app, App::Http { .. }) {
                atomic_write(&unit, self.unit(&record)?.as_bytes(), 0o644)?;
                checked("/usr/bin/systemctl", &["daemon-reload"], self.timeout())?;
                checked(
                    "/usr/bin/systemctl",
                    &["enable", &unit_name(&record.project.project)],
                    self.timeout(),
                )?;
            }
            Ok(())
        })();
        record.registration = if result.is_ok() {
            Registration::Complete {}
        } else {
            Registration::Failed {}
        };
        self.finish_operation(&mut record, &result)?;
        result?;
        // Best effort: status reports a stale catalog, and metadata or --init rewrites it.
        let _ = self.write_catalog();
        self.finished_status(record)
    }

    pub fn status(&self, actor: &Actor, project: &str) -> Result<Status> {
        let record = self.record(project)?;
        self.authorize(actor, &record, true)?;
        self.status_record(record)
    }

    pub fn inspect(&self, actor: &Actor, project: &str) -> Result<serde_json::Value> {
        if let Some(reference) = self.policy.external_projects.get(project) {
            if !reference.operators.iter().any(|user| user == actor.name()) {
                return Err(denied());
            }
            let service = match &reference.app {
                cais_core::ExternalApp::Static {} => "static".to_owned(),
                cais_core::ExternalApp::Service { unit } => {
                    let result = command(
                        "/usr/bin/systemctl",
                        &["is-active", "--", unit],
                        self.timeout().min(10),
                    )?;
                    match result.text.trim() {
                        "active" | "inactive" | "failed" | "activating" | "deactivating" => {
                            result.text.trim().to_owned()
                        }
                        _ => "unknown".into(),
                    }
                }
            };
            return Ok(serde_json::json!({
                "project":project,"management":"external","service":service,
                "app":reference.app,"directory":reference.directory,"database_references":reference.databases,
                "database_management":false,"operations":["status"],
                "notes":["Read-only reference. Deployment, environment, restart and databases remain managed by the existing installation."]
            }));
        }
        serde_json::to_value(self.status(actor, project)?).map_err(|_| internal())
    }

    pub fn set_environment(
        &self,
        actor: &Actor,
        project: &str,
        values: BTreeMap<String, String>,
        expected: &Expected,
    ) -> Result<Status> {
        let _lock = self.lock(project)?;
        let mut record = self.record(project)?;
        self.authorize(actor, &record, false)?;
        self.revalidate(expected, Some(&record))?;
        complete(&record)?;
        let mut env = String::new();
        for (key, value) in values {
            if key.is_empty()
                || !key.bytes().enumerate().all(|(i, b)| {
                    b.is_ascii_alphabetic() || b == b'_' || (i > 0 && b.is_ascii_digit())
                })
                || matches!(key.as_str(), "PORT" | "APP_DATA_DIR")
                || value.contains(['\r', '\n', '\0'])
                || value.len() > 16_384
            {
                return Err(CaisError::new(
                    ErrorCode::InvalidConfig,
                    "Environment keys/values are invalid or reserved.",
                ));
            }
            env.push_str(&format!(
                "{key}=\"{}\"\n",
                value.replace('\\', "\\\\").replace('"', "\\\"")
            ));
        }
        let path = Path::new(&self.settings.paths.config)
            .join(project)
            .join("runtime.env");
        if env.len() > 65_536 {
            return Err(CaisError::new(
                ErrorCode::InvalidConfig,
                "Environment exceeds 64 KiB.",
            ));
        }
        self.begin_operation(&mut record, actor, "set_environment")?;
        let result = (|| {
            atomic_write(&path, env.as_bytes(), 0o640)?;
            checked(
                "/usr/bin/chown",
                &[&format!("root:{}", record.runtime_user), text(&path)?],
                self.timeout(),
            )
        })();
        self.finish_operation(&mut record, &result)?;
        result?;
        self.finished_status(record)
    }

    pub fn restart(&self, actor: &Actor, project: &str, expected: &Expected) -> Result<Status> {
        let _lock = self.lock(project)?;
        let mut record = self.record(project)?;
        self.authorize(actor, &record, false)?;
        self.revalidate(expected, Some(&record))?;
        complete(&record)?;
        if !matches!(record.project.app, App::Http { .. }) {
            return Err(CaisError::new(
                ErrorCode::Unsupported,
                "Static projects have no service to restart.",
            ));
        }
        self.begin_operation(&mut record, actor, "restart")?;
        let result = self
            .refresh_unit(&record)
            .and_then(|_| {
                checked(
                    "/usr/bin/systemctl",
                    &["restart", &unit_name(project)],
                    self.timeout(),
                )
            })
            .and_then(|_| self.health(&record));
        self.finish_operation(&mut record, &result)?;
        result?;
        self.finished_status(record)
    }

    pub fn deploy<R: Read>(
        &self,
        actor: &Actor,
        declaration: UploadDeclaration<'_>,
        input: &mut R,
        ready: impl FnOnce() -> Result<()>,
    ) -> Result<Status> {
        let UploadDeclaration {
            project,
            expected,
            size,
            digest,
            configuration_sha256,
            request_id,
        } = declaration;
        let _lock = self.lock(project)?;
        let mut record = self.record(project)?;
        self.authorize(actor, &record, true)?;
        self.revalidate(expected, Some(&record))?;
        complete(&record)?;
        if actor.name() != record.deploy_user {
            return Err(denied());
        }
        if cais_core::configuration_sha256(&record.project)? != configuration_sha256 {
            return Err(conflict());
        }
        if size == 0
            || size > self.settings.limits.upload_mb as u64 * MIB
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(CaisError::new(
                ErrorCode::InvalidRequest,
                "Invalid upload declaration.",
            ));
        }
        let mut upload =
            tempfile::NamedTempFile::new_in(self.state("incoming")).map_err(io_error)?;
        ready()?;
        let mut remaining = size;
        let mut hash = Sha256::new();
        let mut buffer = [0; 64 * 1024];
        while remaining > 0 {
            let maximum = remaining.min(buffer.len() as u64) as usize;
            let count = input.read(&mut buffer[..maximum]).map_err(|_| {
                CaisError::new(ErrorCode::Transport, "Upload ended before completion.")
            })?;
            if count == 0 {
                return Err(CaisError::new(
                    ErrorCode::Transport,
                    "Upload ended before completion.",
                ));
            }
            upload.write_all(&buffer[..count]).map_err(io_error)?;
            hash.update(&buffer[..count]);
            remaining -= count as u64;
        }
        if cais_core::hex(hash.finalize()) != digest {
            return Err(CaisError::new(
                ErrorCode::InvalidRequest,
                "Upload checksum does not match.",
            ));
        }
        upload.flush().map_err(io_error)?;
        self.start_execution();
        let staging = tempfile::tempdir_in(self.app(project).join(".staging")).map_err(io_error)?;
        let files = staging.path().join("files");
        cais_artifacts::stage_before(
            upload.path(),
            &files,
            &record.project,
            cais_artifacts::Limits {
                compressed_bytes: self.settings.limits.upload_mb as u64 * MIB,
                expanded_bytes: self.settings.limits.expanded_mb as u64 * MIB,
                entries: self.settings.limits.entries as usize,
            },
            Some(self.execution_deadline.get()),
        )?;
        if let App::Static { public } = &record.project.app
            && !files.join(public).is_dir()
        {
            return Err(CaisError::new(
                ErrorCode::InvalidConfig,
                "Static public path must be a directory.",
            ));
        }
        let code_group = self.code_group(&record);
        checked(
            "/usr/bin/chown",
            &[
                "--recursive",
                "--no-dereference",
                &format!("root:{code_group}"),
                "--",
                text(&files)?,
            ],
            self.timeout(),
        )?;
        record.deployment = Deployment::Updating {
            sha256: digest.into(),
            request_id: request_id.into(),
        };
        self.begin_operation(&mut record, actor, "deploy")?;
        let result = (|| {
            // Also tighten pre-release registrations created by older development builds.
            for path in [self.app(project), self.app(project).join("current")] {
                checked(
                    "/usr/bin/chown",
                    &[&format!("root:{code_group}"), text(&path)?],
                    self.timeout(),
                )?;
                permissions(&path, 0o750)?;
            }
            let service = unit_name(project);
            if matches!(record.project.app, App::Http { .. }) {
                self.refresh_unit(&record)?;
                checked("/usr/bin/systemctl", &["stop", &service], self.timeout())?;
            }
            for name in &record.project.artifact.publish {
                let target = self.safe_target(project, name)?;
                if target.is_dir() {
                    fs::remove_dir_all(&target).map_err(io_error)?;
                } else if target.exists() {
                    fs::remove_file(&target).map_err(io_error)?;
                }
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).map_err(io_error)?;
                }
                fs::rename(files.join(name), target).map_err(io_error)?;
            }
            if matches!(record.project.app, App::Http { .. }) {
                checked(
                    "/usr/bin/systemctl",
                    &["reset-failed", &service],
                    self.timeout(),
                )?;
                checked("/usr/bin/systemctl", &["start", &service], self.timeout())?;
                self.health(&record)?;
            }
            Ok(())
        })();
        record.deployment = if result.is_ok() {
            Deployment::Success {
                sha256: digest.into(),
                request_id: request_id.into(),
                completed_at: now(),
            }
        } else {
            Deployment::Failed {
                sha256: digest.into(),
                request_id: request_id.into(),
                completed_at: now(),
            }
        };
        self.finish_operation(&mut record, &result)?;
        result?;
        self.finished_status(record)
    }

    fn supported_project(&self, project: &ProjectConfig) -> Result<()> {
        self.supported_integrations(project)?;
        match &project.app {
            App::Http {
                runtime: Runtime::Node,
                ..
            } if self.settings.runtimes.node.is_none() => Err(CaisError::new(
                ErrorCode::Unsupported,
                "Node runtime is not administratively configured.",
            )),
            App::Http {
                runtime: Runtime::Python,
                ..
            } if self.settings.runtimes.python.is_none() => Err(CaisError::new(
                ErrorCode::Unsupported,
                "Python runtime is not administratively configured.",
            )),
            _ => Ok(()),
        }
    }

    pub fn install_operator_access(&self) -> Result<()> {
        let mut names: Vec<String> = self.policy.operators.keys().cloned().collect();
        names.extend(
            self.policy
                .external_projects
                .values()
                .flat_map(|p| p.operators.iter().cloned()),
        );
        for policy in self.policy.projects.values() {
            names.extend(policy.operators.clone());
        }
        names.sort();
        names.dedup();
        for name in names {
            self.install_sudoers(&name)?;
        }
        Ok(())
    }

    fn install_sudoers(&self, user: &str) -> Result<()> {
        if !cais_core::account_name(user) {
            return Err(denied());
        }
        trusted_existing_ancestors(Path::new(&self.settings.paths.sudoers))?;
        trusted_file(Path::new(&self.settings.paths.broker))?;
        trusted_file(Path::new(&self.settings.paths.server))?;
        let content = format!(
            "{user} ALL=(root) NOPASSWD: {} \"\"\n",
            self.settings.paths.broker
        );
        let target = Path::new(&self.settings.paths.sudoers).join(format!("cais-{user}"));
        if target.exists() {
            trusted_file(&target)?;
            if fs::read(&target).map_err(io_error)? == content.as_bytes() {
                return Ok(());
            }
            return Err(conflict());
        }
        let mut candidate =
            tempfile::NamedTempFile::new_in(&self.settings.paths.sudoers).map_err(io_error)?;
        candidate.write_all(content.as_bytes()).map_err(io_error)?;
        checked(
            "/usr/sbin/visudo",
            &["-c", "-f", text(candidate.path())?],
            self.timeout(),
        )?;
        permissions(candidate.path(), 0o440)?;
        candidate.as_file().sync_all().map_err(io_error)?;
        candidate
            .persist_noclobber(&target)
            .map_err(|_| conflict())?;
        Ok(())
    }
    fn creation_policy(&self, actor: &Actor, project: &ProjectConfig) -> Result<ProjectPolicy> {
        self.require_native(&project.project)?;
        let backup_denied = || {
            CaisError::new(
                ErrorCode::PolicyDenied,
                "Backup requests are not enabled for this project.",
            )
        };
        if let Some(policy) = self.policy.projects.get(&project.project) {
            if !policy.operators.iter().any(|s| s == actor.name()) {
                return Err(denied());
            }
            if let Some(exposure) = &project.exposure
                && (!policy.hosts.contains(&exposure.host)
                    || !policy.access_profiles.contains(&exposure.access_profile))
            {
                return Err(CaisError::new(
                    ErrorCode::PolicyDenied,
                    "Requested exposure is not delegated to this project.",
                ));
            }
            if !project.data.backup.is_empty() && !policy.backup {
                return Err(backup_denied());
            }
            return Ok(policy.clone());
        }
        let role = self
            .policy
            .operators
            .get(actor.name())
            .filter(|p| p.create)
            .ok_or_else(denied)?;
        let mut members = role.share_with.clone();
        members.push(actor.name.clone());
        members.sort();
        members.dedup();
        if let Some(exposure) = &project.exposure
            && !self.role_exposes(role, exposure)
        {
            return Err(denied());
        }
        if !project.data.backup.is_empty() && !role.backup {
            return Err(backup_denied());
        }
        Ok(ProjectPolicy {
            database: role.database,
            operators: members,
            hosts: project.exposure.iter().map(|p| p.host.clone()).collect(),
            access_profiles: role.access_profiles.clone(),
            backup: role.backup,
        })
    }
    /// A suffix never reaches a hostname the policy names for a project.
    fn role_exposes(
        &self,
        role: &cais_core::OperatorPolicy,
        exposure: &cais_core::Exposure,
    ) -> bool {
        role.domain_suffixes.iter().any(|suffix| {
            exposure
                .host
                .strip_suffix(suffix.as_str())
                .is_some_and(|prefix| prefix.ends_with('.'))
        }) && role.access_profiles.contains(&exposure.access_profile)
            && !self
                .policy
                .projects
                .values()
                .any(|project| project.hosts.contains(&exposure.host))
    }
    /// Authority always comes from the policy as it is now. A record keeps who created
    /// the project, so removing a delegation from the policy takes effect at once.
    fn authorize(&self, actor: &Actor, record: &Record, deploy: bool) -> Result<()> {
        let operator = match self.policy.projects.get(&record.project.project) {
            Some(project) => project.operators.iter().any(|s| s == actor.name()),
            None => {
                self.policy.operators.contains_key(actor.name())
                    && self
                        .policy
                        .operators
                        .get(&record.created_by)
                        .is_some_and(|role| {
                            record.created_by == actor.name()
                                || role.share_with.iter().any(|s| s == actor.name())
                        })
            }
        };
        if operator || (deploy && record.deploy_user == actor.name()) {
            Ok(())
        } else {
            Err(denied())
        }
    }
    /// What the current policy still delegates to a registered project.
    fn delegated(&self, record: &Record) -> Delegated {
        let exposure = record.project.exposure.as_ref();
        if let Some(project) = self.policy.projects.get(&record.project.project) {
            return Delegated {
                exposure: exposure.is_none_or(|exposure| {
                    project.hosts.contains(&exposure.host)
                        && project.access_profiles.contains(&exposure.access_profile)
                }),
                backup: project.backup,
                database: project.database,
            };
        }
        match self.policy.operators.get(&record.created_by) {
            Some(role) => Delegated {
                exposure: exposure.is_none_or(|exposure| self.role_exposes(role, exposure)),
                backup: role.backup && record.backup_allowed,
                database: role.database && record.database_allowed,
            },
            None => Delegated {
                exposure: false,
                backup: false,
                database: false,
            },
        }
    }
    fn expected(&self, record: Option<&Record>) -> Result<Expected> {
        Ok(Expected {
            instance: self.instance.clone(),
            policy_sha256: self.policy_sha256.clone(),
            revision: record.map(hash_json).transpose()?,
        })
    }
    fn revalidate(&self, expected: &Expected, record: Option<&Record>) -> Result<()> {
        let actual = self.expected(record)?;
        if actual.instance != expected.instance
            || actual.policy_sha256 != expected.policy_sha256
            || actual.revision != expected.revision
        {
            Err(conflict())
        } else {
            Ok(())
        }
    }
    fn optional_record(&self, project: &str) -> Result<Option<Record>> {
        self.require_native(project)?;
        if !identifier(project) {
            return Err(denied());
        }
        let path = self.state("records").join(format!("{project}.json"));
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(io_error(error)),
            Ok(_) => {
                trusted_file(&path)?;
                let bytes = fs::read(path).map_err(io_error)?;
                if bytes.len() > 512 * 1024 {
                    return Err(internal());
                }
                let record: Record = decode_json(&bytes)?;
                if record.project.project != project
                    || record.runtime_user != format!("ca-{}", short_id(project))
                    || record.deploy_user != format!("cd-{}", short_id(project))
                {
                    return Err(internal());
                }
                Ok(Some(record))
            }
        }
    }
    fn record(&self, project: &str) -> Result<Record> {
        self.optional_record(project)?
            .ok_or_else(|| CaisError::new(ErrorCode::OperationFailed, "Project is not registered."))
    }
    fn require_native(&self, project: &str) -> Result<()> {
        if self.policy.external_projects.contains_key(project) {
            return Err(CaisError::new(
                ErrorCode::Unsupported,
                "External projects are read-only; use their existing deployment and database tools.",
            ));
        }
        Ok(())
    }
    fn save(&self, record: &mut Record) -> Result<()> {
        record.sequence = record.sequence.checked_add(1).ok_or_else(internal)?;
        record.updated_at = now();
        atomic_write(
            &self
                .state("records")
                .join(format!("{}.json", record.project.project)),
            &serde_json::to_vec(record).map_err(|_| internal())?,
            0o600,
        )
    }
    fn begin_operation(&self, record: &mut Record, actor: &Actor, kind: &str) -> Result<()> {
        record.last_operation = Some(OperationStatus {
            kind: kind.into(),
            actor: actor.name.clone(),
            state: OperationState::InProgress,
            updated_at: now(),
            inspection: None,
        });
        self.save(record)
    }
    fn finish_operation(&self, record: &mut Record, result: &Result<()>) -> Result<()> {
        if let Some(operation) = &mut record.last_operation {
            operation.state = match result {
                Ok(_) => OperationState::Success,
                Err(error) if error.code == ErrorCode::UnknownOutcome => OperationState::Unknown,
                Err(_) => OperationState::Failed,
            };
            operation.updated_at = now();
        }
        self.save(record).map_err(|_| {
            CaisError::new(
                ErrorCode::UnknownOutcome,
                "Operation result could not be persisted; inspect project state before retrying.",
            )
        })
    }
    fn finished_status(&self, record: Record) -> Result<Status> {
        let mut status = self.status_record(record)?;
        status.operation_lock_held = false;
        Ok(status)
    }

    fn status_record(&self, mut record: Record) -> Result<Status> {
        if !self.operation_lock_held(&record.project.project)?
            && record
                .last_operation
                .as_ref()
                .is_some_and(|op| matches!(op.state, OperationState::InProgress))
        {
            record = self.record(&record.project.project)?;
        }
        let service = if matches!(record.project.app, App::Static { .. }) {
            "static".into()
        } else {
            let output = command(
                "/usr/bin/systemctl",
                &["is-active", &unit_name(&record.project.project)],
                self.timeout().min(10),
            )?;
            match output.text.trim() {
                "active" | "inactive" | "failed" | "activating" | "deactivating" => {
                    output.text.trim().to_owned()
                }
                _ => "unknown".into(),
            }
        };
        let listener = record.port.map(|port| {
            self.runtime_uid(&record)
                .and_then(|owner| listener(port, owner))
                .unwrap_or("unknown")
                .to_owned()
        });
        let busy = self.operation_lock_held(&record.project.project)?;
        let requires_inspection = record.last_operation.as_ref().is_some_and(|op| {
            matches!(op.state, OperationState::Unknown)
                || (matches!(op.state, OperationState::InProgress) && !busy)
        });
        Ok(Status {
            route: self.route_status(&record),
            catalog: self.catalog_status(&record),
            metadata: record.metadata.clone(),
            backup: self.backup_status(&record),
            database: record.database.clone(),
            expected: self.expected(Some(&record))?,
            project: record.project.project,
            registration: record.registration,
            deployment: record.deployment,
            runtime_user: record.runtime_user,
            deploy_user: record.deploy_user,
            port: record.port,
            service,
            listener,
            last_operation: record.last_operation,
            operation_lock_held: busy,
            requires_inspection,
        })
    }
    fn allocate_port(&self) -> Result<u16> {
        let mut occupied = Vec::new();
        for entry in fs::read_dir(self.state("records")).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            if let Some(name) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.strip_suffix(".json"))
                && let Some(port) = self.record(name)?.port
            {
                occupied.push(port);
            }
        }
        for port in self.settings.ports.first..=self.settings.ports.last {
            if !occupied.contains(&port) && TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
                return Ok(port);
            }
        }
        Err(CaisError::new(
            ErrorCode::OperationFailed,
            "No application port is available.",
        ))
    }
    fn validate_public_key(&self, key: &str) -> Result<String> {
        let parts: Vec<_> = key.split_whitespace().collect();
        if parts.len() < 2
            || key.len() > 16_384
            || !matches!(parts[0], "ssh-ed25519" | "ssh-rsa" | "ecdsa-sha2-nistp256")
            || !parts[1]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
        {
            return Err(CaisError::new(
                ErrorCode::InvalidConfig,
                "A valid public SSH deployment key is required.",
            ));
        }
        let key = format!("{} {}", parts[0], parts[1]);
        let mut file = tempfile::NamedTempFile::new_in(self.state("incoming")).map_err(io_error)?;
        file.write_all(key.as_bytes()).map_err(io_error)?;
        file.flush().map_err(io_error)?;
        checked("/usr/bin/ssh-keygen", &["-l", "-f", text(file.path())?], 10)?;
        Ok(key)
    }
    fn unit(&self, record: &Record) -> Result<String> {
        let App::Http {
            runtime,
            entrypoint,
            ..
        } = &record.project.app
        else {
            return Err(internal());
        };
        let current = self.app(&record.project.project).join("current");
        let entry = current.join(entrypoint);
        let command = match runtime {
            Runtime::Binary => quote(text(&entry)?),
            Runtime::Node => format!(
                "{} {}",
                quote(
                    self.settings
                        .runtimes
                        .node
                        .as_deref()
                        .ok_or_else(internal)?
                ),
                quote(text(&entry)?)
            ),
            Runtime::Python => format!(
                "{} {}",
                quote(
                    self.settings
                        .runtimes
                        .python
                        .as_deref()
                        .ok_or_else(internal)?
                ),
                quote(text(&entry)?)
            ),
        };
        let data = self.data(&record.project.project);
        let env = Path::new(&self.settings.paths.config)
            .join(&record.project.project)
            .join("runtime.env");
        let limits = &self.settings.limits;
        Ok(format!(
            "[Unit]\nDescription=Cais application\nAfter=network.target\n[Service]\nType=exec\nUser={}\nGroup={}\nWorkingDirectory={}\nEnvironmentFile={}\nEnvironmentFile=-{}\nEnvironment=PORT={}\nEnvironment=APP_DATA_DIR={}\nEnvironment=PYTHONDONTWRITEBYTECODE=1\nExecStart={}\nRestart=on-failure\nRestartSec=3\nTimeoutStartSec=30\nTimeoutStopSec=20\nKillMode=control-group\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectHome=yes\nProtectSystem=strict\nReadWritePaths={}\nInaccessiblePaths={} /root /home\nUMask=0077\nMemoryMax={}M\nCPUQuota={}%\nTasksMax={}\n[Install]\nWantedBy=multi-user.target\n",
            record.runtime_user,
            record.runtime_user,
            text(&current)?,
            text(&env)?,
            text(&env.with_file_name("database.env"))?,
            record.port.ok_or_else(internal)?,
            text(&data)?,
            command,
            text(&data)?,
            self.settings.paths.state,
            limits.memory_mb,
            limits.cpu_percent,
            limits.tasks
        ))
    }

    fn refresh_unit(&self, record: &Record) -> Result<()> {
        let path = Path::new(&self.settings.paths.units).join(unit_name(&record.project.project));
        let content = self.unit(record)?;
        if path.exists() {
            trusted_file(&path)?;
            if fs::read(&path).map_err(io_error)? == content.as_bytes() {
                return Ok(());
            }
        }
        trusted_existing_ancestors(path.parent().ok_or_else(internal)?)?;
        atomic_write(&path, content.as_bytes(), 0o644)?;
        checked("/usr/bin/systemctl", &["daemon-reload"], self.timeout())
    }
    fn health(&self, record: &Record) -> Result<()> {
        let App::Http { health, .. } = &record.project.app else {
            return Ok(());
        };
        let until = (Instant::now() + Duration::from_secs(25)).min(self.execution_deadline.get());
        let port = record.port.ok_or_else(internal)?;
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let owner = self.runtime_uid(record)?;
        while Instant::now() < until {
            if let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(300))
            {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
                let request = format!(
                    "GET {health} HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                );
                if stream.write_all(request.as_bytes()).is_ok() {
                    let mut line = Vec::new();
                    let mut byte = [0];
                    while line.len() < 512 && Instant::now() < until {
                        match stream.read(&mut byte) {
                            Ok(1) => {
                                line.push(byte[0]);
                                if byte[0] == b'\n' {
                                    break;
                                }
                            }
                            _ => break,
                        }
                    }
                    if line.last() == Some(&b'\n')
                        && String::from_utf8_lossy(&line).split_whitespace().nth(1) == Some("200")
                    {
                        // The port is loopback, where any local account can listen. An
                        // answer counts only when the project's own account holds the port.
                        return match listener(port, owner)? {
                            "loopback" => Ok(()),
                            // Reachable without the proxy, so an access profile would
                            // not protect it.
                            "exposed" => Err(CaisError::new(
                                ErrorCode::OperationFailed,
                                "The application listens beyond loopback; bind it to 127.0.0.1.",
                            )),
                            _ => Err(CaisError::new(
                                ErrorCode::OperationFailed,
                                "Another process answers on the application port; inspect the host.",
                            )),
                        };
                    }
                }
            }
            thread::sleep(Duration::from_millis(250));
        }
        Err(CaisError::new(
            ErrorCode::OperationFailed,
            "Application health was not confirmed; inspect status. Files may have changed.",
        ))
    }
    fn runtime_uid(&self, record: &Record) -> Result<u32> {
        command(
            "/usr/bin/id",
            &["-u", "--", &record.runtime_user],
            self.timeout().min(10),
        )?
        .text
        .trim()
        .parse()
        .map_err(|_| internal())
    }
    fn lock(&self, project: &str) -> Result<File> {
        if !identifier(project) {
            return Err(denied());
        }
        let path = self.state("locks").join(format!("{project}.lock"));
        file_lock(&path)
    }
    fn operation_lock_held(&self, project: &str) -> Result<bool> {
        let path = self.state("locks").join(format!("{project}.lock"));
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(io_error(error)),
        };
        // Observe kernel lock metadata without acquiring a lock that can obstruct a writer.
        // Read as a stream: other accounts can make this table arbitrarily long.
        let locks = BufReader::new(File::open("/proc/locks").map_err(io_error)?);
        for line in locks.lines() {
            let line = line.map_err(io_error)?;
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 6 || fields[1] != "FLOCK" || fields[3] != "WRITE" {
                continue;
            }
            let device: Vec<_> = fields[5].split(':').collect();
            if device.len() == 3
                && u32::from_str_radix(device[0], 16).ok()
                    == Some(rustix::fs::major(metadata.dev()))
                && u32::from_str_radix(device[1], 16).ok()
                    == Some(rustix::fs::minor(metadata.dev()))
                && device[2].parse::<u64>().ok() == Some(metadata.ino())
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn safe_target(&self, project: &str, name: &str) -> Result<PathBuf> {
        if !cais_core::relative_path(name) {
            return Err(denied());
        }
        let mut path = self.app(project).join("current");
        for component in name.split('/') {
            path.push(component);
            match fs::symlink_metadata(&path) {
                Ok(meta) if meta.file_type().is_symlink() => return Err(denied()),
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(io_error(e)),
            }
        }
        Ok(path)
    }
    fn state(&self, name: &str) -> PathBuf {
        Path::new(&self.settings.paths.state).join(name)
    }
    fn app(&self, project: &str) -> PathBuf {
        Path::new(&self.settings.paths.apps).join(project)
    }
    fn data(&self, project: &str) -> PathBuf {
        Path::new(&self.settings.paths.data).join(project)
    }
    fn timeout(&self) -> u64 {
        let remaining = self
            .execution_deadline
            .get()
            .saturating_duration_since(Instant::now());
        u64::from(self.settings.limits.command_seconds)
            .min(remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0))
    }
}

fn load_policy(path: &Path) -> Result<(ServerConfig, HostSettings, String)> {
    require_root()?;
    trusted_file(path)?;
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(io_error)?
        .take(cais_core::CONFIG_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    let policy: ServerConfig = decode_config(&bytes)?;
    let mut settings = policy.host.clone().ok_or_else(|| {
        CaisError::new(
            ErrorCode::Unsupported,
            "Native host operations are not configured.",
        )
    })?;
    for runtime in settings
        .runtimes
        .node
        .iter_mut()
        .chain(settings.runtimes.python.iter_mut())
    {
        *runtime = trusted_executable(Path::new(runtime))?
            .to_str()
            .ok_or_else(internal)?
            .to_owned();
    }
    let digest = cais_core::hex(Sha256::digest(&bytes));
    Ok((policy, settings, digest))
}
fn require_root() -> Result<()> {
    if rustix::process::geteuid().is_root() {
        Ok(())
    } else {
        Err(denied())
    }
}
fn trusted_file(path: &Path) -> Result<()> {
    trusted_existing_ancestors(path)?;
    if !fs::symlink_metadata(path).map_err(io_error)?.is_file() {
        return Err(denied());
    }
    Ok(())
}

fn trusted_executable(path: &Path) -> Result<PathBuf> {
    // Distribution-managed /usr/bin/python3 symlinks are permitted, but every original
    // ancestor and the fully resolved target must remain under administrative control.
    for component in path.ancestors() {
        let meta = fs::symlink_metadata(component).map_err(io_error)?;
        if meta.uid() != 0 || (!meta.file_type().is_symlink() && meta.mode() & 0o022 != 0) {
            return Err(denied());
        }
    }
    let resolved = fs::canonicalize(path).map_err(io_error)?;
    trusted_file(&resolved)?;
    if fs::metadata(&resolved).map_err(io_error)?.mode() & 0o111 == 0 {
        return Err(denied());
    }
    // Unit files pin the trusted canonical path, never a mutable intermediate link.
    Ok(resolved)
}
fn trusted_existing_ancestors(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|p| matches!(p, std::path::Component::ParentDir))
    {
        return Err(denied());
    }
    for parent in path.ancestors() {
        match fs::symlink_metadata(parent) {
            Ok(meta) => {
                if meta.uid() != 0 || meta.mode() & 0o022 != 0 || meta.file_type().is_symlink() {
                    return Err(denied());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_error(e)),
        }
    }
    Ok(())
}
fn private_directory(path: &Path, mode: u32) -> Result<()> {
    fs::create_dir(path).map_err(io_error)?;
    permissions(path, mode)
}
fn permissions(path: &Path, mode: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(io_error)
}
fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    atomic_write_group(path, bytes, mode, None)
}
fn atomic_write_group(path: &Path, bytes: &[u8], mode: u32, gid: Option<u32>) -> Result<()> {
    let parent = path.parent().ok_or_else(internal)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(io_error)?;
    temp.write_all(bytes).map_err(io_error)?;
    if let Some(gid) = gid {
        rustix::fs::fchown(
            temp.as_file(),
            Some(rustix::process::Uid::ROOT),
            Some(rustix::process::Gid::from_raw(gid)),
        )
        .map_err(|_| internal())?;
    }
    permissions(temp.path(), mode)?;
    temp.as_file().sync_all().map_err(io_error)?;
    temp.persist(path).map_err(|_| internal())?;
    File::open(parent)
        .map_err(io_error)?
        .sync_all()
        .map_err(io_error)
}
/// Who listens on the port: `loopback` when only the given account does, and only on
/// loopback addresses; `foreign` when another account holds it; `exposed` when the
/// account also listens on other addresses; `absent` when nothing listens.
fn listener(port: u16, owner: u32) -> Result<&'static str> {
    let (mut found, mut exposed) = (false, false);
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let file = match File::open(table) {
            Ok(file) => file,
            // IPv6 can be absent from the kernel.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(io_error(error)),
        };
        for line in BufReader::new(file).lines().skip(1) {
            let line = line.map_err(io_error)?;
            let fields: Vec<_> = line.split_whitespace().collect();
            // sl local remote state queues timer retransmit uid ...; state 0A is LISTEN.
            if fields.len() < 8 || fields[3] != "0A" {
                continue;
            }
            let Some((address, text)) = fields[1].rsplit_once(':') else {
                continue;
            };
            if u16::from_str_radix(text, 16).ok() != Some(port) {
                continue;
            }
            if fields[7].parse::<u32>().ok() != Some(owner) {
                return Ok("foreign");
            }
            found = true;
            // Addresses are printed as host-order words: 127.0.0.0/8, ::1 and the
            // IPv4-mapped form of the former.
            exposed |= !(address.len() == 8 && address.ends_with("7F")
                || address == "00000000000000000000000001000000"
                || (address.starts_with("0000000000000000FFFF0000") && address.ends_with("7F")));
        }
    }
    Ok(match (found, exposed) {
        (false, _) => "absent",
        (true, true) => "exposed",
        (true, false) => "loopback",
    })
}

struct Output {
    success: bool,
    code: Option<i32>,
    text: String,
}
fn command(program: &str, args: &[&str], seconds: u64) -> Result<Output> {
    if seconds == 0 {
        return Err(CaisError::new(
            ErrorCode::UnknownOutcome,
            "Operation budget ended; inspect status before retrying.",
        ));
    }
    let mut output = tempfile::tempfile().map_err(io_error)?;
    let mut child = Command::new(program)
        .process_group(0)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::null())
        .stdout(output.try_clone().map_err(io_error)?)
        .stderr(Stdio::null())
        .spawn()
        .map_err(io_error)?;
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        if let Some(status) = child.try_wait().map_err(io_error)? {
            output.seek(SeekFrom::Start(0)).map_err(io_error)?;
            let mut bytes = Vec::new();
            output
                .take(8192)
                .read_to_end(&mut bytes)
                .map_err(io_error)?;
            return Ok(Output {
                success: status.success(),
                code: status.code(),
                text: String::from_utf8_lossy(&bytes).into_owned(),
            });
        }
        if Instant::now() >= deadline {
            kill_group(&mut child);
            return Err(CaisError::new(
                ErrorCode::UnknownOutcome,
                "Administrative command timed out; inspect project state before retrying.",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}
fn kill_group(child: &mut std::process::Child) {
    if let Some(pid) = rustix::process::Pid::from_raw(child.id() as i32) {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn checked(program: &str, args: &[&str], seconds: u64) -> Result<()> {
    if command(program, args, seconds)?.success {
        Ok(())
    } else {
        Err(CaisError::new(
            ErrorCode::OperationFailed,
            "Administrative operation failed; inspect project state before retrying.",
        ))
    }
}
fn quote(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$")
    )
}
fn short_id(project: &str) -> String {
    cais_core::hex(Sha256::digest(project.as_bytes()))[..12].into()
}
fn unit_name(project: &str) -> String {
    format!("cais-app-{}.service", short_id(project))
}
fn text(path: &Path) -> Result<&str> {
    path.to_str().ok_or_else(internal)
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn hash_json(value: &impl Serialize) -> Result<String> {
    Ok(cais_core::hex(Sha256::digest(
        serde_json::to_vec(value).map_err(|_| internal())?,
    )))
}
fn complete(record: &Record) -> Result<()> {
    // Recovery/list/port allocation can inspect older invalid configurations, but no
    // application mutation may use their paths until current validation passes.
    record.project.validate()?;
    if !matches!(record.registration, Registration::Complete {}) {
        return Err(CaisError::new(
            ErrorCode::Conflict,
            "Registration is incomplete; an administrator must inspect or quarantine its resources.",
        ));
    }
    if matches!(record.registration, Registration::Complete {})
        && !record.last_operation.as_ref().is_some_and(|op| {
            matches!(
                op.state,
                OperationState::InProgress | OperationState::Unknown
            )
        })
    {
        Ok(())
    } else {
        Err(CaisError::new(
            ErrorCode::Conflict,
            "An interrupted operation requires administrative inspection and explicit resolution.",
        ))
    }
}
fn file_lock(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(io_error)?;
    FileExt::try_lock_exclusive(&file).map_err(|e| {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            CaisError::new(ErrorCode::Busy, "Another operation is in progress.")
        } else {
            io_error(e)
        }
    })?;
    Ok(file)
}
fn denied() -> CaisError {
    CaisError::new(
        ErrorCode::NotAuthorized,
        "Project or operation is unavailable to this identity.",
    )
}
fn conflict() -> CaisError {
    CaisError::new(
        ErrorCode::Conflict,
        "State or policy changed; inspect status and plan again.",
    )
}
fn internal() -> CaisError {
    CaisError::new(
        ErrorCode::Internal,
        "Native host operation could not be completed.",
    )
}
fn io_error(_: std::io::Error) -> CaisError {
    internal()
}

#[cfg(test)]
mod process_tests {
    #[test]
    fn external_references_are_read_only_and_authorized_without_reading_app_files() {
        use super::*;
        let mut value: serde_json::Value =
            serde_json::from_str(include_str!("../../../examples/server-quickstart.json")).unwrap();
        value["external_projects"] = serde_json::json!({"existing":{"operators":["alice"],"app":{"kind":"static"},"directory":"/nonexistent-app","databases":["existing_db"]}});
        let policy: ServerConfig = decode_config(&serde_json::to_vec(&value).unwrap()).unwrap();
        let host = Host {
            settings: policy.host.clone().unwrap(),
            policy,
            instance: "fixture".into(),
            policy_sha256: "fixture".into(),
            execution_deadline: Cell::new(Instant::now() + Duration::from_secs(10)),
        };
        let actor = Actor {
            name: "alice".into(),
        };
        let status = host.inspect(&actor, "existing").unwrap();
        assert_eq!(status["management"], "external");
        assert_eq!(status["database_management"], false);
        assert_eq!(status["operations"], serde_json::json!(["status"]));
        assert_eq!(
            host.inspect(
                &Actor {
                    name: "outsider".into()
                },
                "existing"
            )
            .unwrap_err()
            .code,
            ErrorCode::NotAuthorized
        );
        assert_eq!(
            host.record("existing").unwrap_err().code,
            ErrorCode::Unsupported
        );
        let project: ProjectConfig = decode_config(br#"{"schema_version":1,"project":"existing","artifact":{"directory":"dist","publish":["public"]},"app":{"kind":"static","public":"public"}}"#).unwrap();
        assert_eq!(
            host.creation_policy(&actor, &project).unwrap_err().code,
            ErrorCode::Unsupported
        );
    }
    #[test]
    #[ignore = "requires root and util-linux setpriv in an isolated Linux fixture"]
    fn dropped_identity_timeout_cannot_leave_a_writer() {
        use std::os::unix::fs::PermissionsExt;
        assert!(rustix::process::geteuid().is_root());
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let marker = directory.path().join("write");
        let path = marker.to_str().unwrap();
        let args = [
            "--reuid",
            "nobody",
            "--regid",
            "nogroup",
            "--init-groups",
            "--",
            "/bin/sh",
            "-c",
            "printf control > \"$1\"",
            "fixture",
            path,
        ];
        assert!(
            super::command("/usr/bin/setpriv", &args, 2)
                .unwrap()
                .success
        );
        assert!(marker.exists());
        std::fs::remove_file(&marker).unwrap();
        let args = [
            "--reuid",
            "nobody",
            "--regid",
            "nogroup",
            "--init-groups",
            "--",
            "/bin/sh",
            "-c",
            "sleep 2; printf late > \"$1\"",
            "fixture",
            path,
        ];
        let error = super::command("/usr/bin/setpriv", &args, 1)
            .err()
            .expect("deadline must expire");
        assert_eq!(error.code, cais_core::ErrorCode::UnknownOutcome);
        std::thread::sleep(std::time::Duration::from_millis(1400));
        assert!(!marker.exists());
    }
    #[test]
    fn administrative_timeout_stops_descendant_side_effects() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("late-write");
        let error = super::command(
            "/bin/sh",
            &[
                "-c",
                "sleep 2; printf late > \"$1\"",
                "fixture",
                marker.to_str().unwrap(),
            ],
            1,
        )
        .err()
        .expect("deadline must expire");
        assert_eq!(error.code, cais_core::ErrorCode::UnknownOutcome);
        std::thread::sleep(std::time::Duration::from_millis(1400));
        assert!(
            !marker.exists(),
            "timed-out grandchildren must not continue mutating"
        );
    }
}
