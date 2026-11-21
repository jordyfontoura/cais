use super::*;
use cais_core::PostgresSettings;
use cais_postgres::Credentials;

impl Host {
    pub fn database_connection(
        &self,
        actor: &Actor,
        project: &str,
    ) -> Result<cais_core::DatabaseConnection> {
        let _lock = self.lock(project)?;
        let record = self.record(project)?;
        self.database_permission(actor, &record)?;
        let database = record
            .database
            .as_ref()
            .filter(|db| db.state == DatabaseState::Ready)
            .ok_or_else(conflict)?;
        let pg = self.postgres_settings()?;
        if pg.port != database.port {
            return Err(conflict());
        }
        let (socket, uid) = self.pg_socket(&pg)?;
        let info = cais_core::DatabaseConnection {
            schema_version: cais_core::SchemaVersion,
            project: project.into(),
            database: database.name.clone(),
            username: database.username.clone(),
            cluster: database.cluster.clone(),
            port: pg.port,
            socket: text(&socket)?.into(),
            owner_uid: uid,
            session_seconds: self.settings.limits.database_session_seconds,
        };
        info.validate()?;
        Ok(info)
    }
    fn pg_socket(&self, pg: &PostgresSettings) -> Result<(PathBuf, u32)> {
        use std::os::unix::fs::FileTypeExt;
        let uid = command("/usr/bin/id", &["-u", "--", &pg.os_user], self.timeout())?;
        if !uid.success {
            return Err(denied());
        }
        let uid: u32 = uid.text.trim().parse().map_err(|_| internal())?;
        let gid = self.pg_gid(pg)?;
        let directory = Path::new(&pg.socket_directory);
        let canonical = fs::canonicalize(directory).map_err(io_error)?;
        for path in directory.ancestors().chain(canonical.ancestors()) {
            let meta = fs::symlink_metadata(path).map_err(io_error)?;
            if meta.file_type().is_symlink() {
                if meta.uid() != 0 {
                    return Err(denied());
                }
            } else if (meta.uid() != 0 && meta.uid() != uid)
                || meta.mode() & 0o002 != 0
                || (meta.mode() & 0o020 != 0 && meta.gid() != gid)
                || !meta.is_dir()
            {
                return Err(denied());
            }
        }
        let socket = canonical.join(format!(".s.PGSQL.{}", pg.port));
        let meta = fs::symlink_metadata(&socket).map_err(io_error)?;
        if !meta.file_type().is_socket() || meta.uid() != uid {
            return Err(denied());
        }
        let peer = std::os::unix::net::UnixStream::connect(&socket).map_err(io_error)?;
        if rustix::net::sockopt::socket_peercred(&peer)
            .map_err(|_| denied())?
            .uid
            .as_raw()
            != uid
        {
            return Err(denied());
        }
        Ok((socket, uid))
    }
    pub fn initialize_postgres(&self) -> Result<()> {
        let Some(pg) = &self.settings.postgres else {
            return Ok(());
        };
        trusted_executable(Path::new(&pg.psql))?;
        let directory = Path::new(&pg.hba_directory);
        trusted_existing_ancestors(directory)?;
        let marker = directory.join(".cais-owner");
        if marker.exists() {
            trusted_file(&marker)?;
            if fs::read_to_string(marker).map_err(io_error)? != self.instance {
                return Err(conflict());
            }
            return Ok(());
        }
        if directory.exists() && fs::read_dir(directory).map_err(io_error)?.next().is_some() {
            return Err(conflict());
        }
        fs::create_dir_all(directory).map_err(io_error)?;
        permissions(directory, 0o750)?;
        let group = command("/usr/bin/id", &["-g", "--", &pg.os_user], self.timeout())?;
        let gid: u32 = group.text.trim().parse().map_err(|_| internal())?;
        checked(
            "/usr/bin/chown",
            &[&format!("root:{gid}"), &pg.hba_directory],
            self.timeout(),
        )?;
        atomic_write(&marker, self.instance.as_bytes(), 0o600)
    }

    pub fn database_create(
        &self,
        actor: &Actor,
        project: &str,
        expected: &Expected,
    ) -> Result<Status> {
        let _project = self.lock(project)?;
        let _postgres = file_lock(&self.state("locks").join(".postgres.lock"))?;
        let mut record = self.record(project)?;
        self.database_permission(actor, &record)?;
        self.revalidate(expected, Some(&record))?;
        complete(&record)?;
        if record.database.is_some() {
            return Err(conflict());
        }
        let pg = self.postgres_settings()?;
        self.pg_preflight(&pg)?;
        let credentials = Credentials::generate(project, &pg)?;
        let name = &credentials.database;
        let exists = self.pg_admin(&pg, &format!("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='{name}') OR EXISTS(SELECT 1 FROM pg_catalog.pg_database WHERE datname='{name}');"))?;
        if exists.trim() != "f"
            || fs::symlink_metadata(self.pg_secret(project)).is_ok()
            || fs::symlink_metadata(Path::new(&pg.hba_directory).join(format!("{name}.conf")))
                .is_ok()
        {
            return Err(conflict());
        }
        let cluster = self
            .pg_admin(
                &pg,
                "SELECT system_identifier::text FROM pg_catalog.pg_control_system();",
            )?
            .trim()
            .to_owned();
        if cluster.is_empty() || !cluster.bytes().all(|b| b.is_ascii_digit()) {
            return Err(internal());
        }
        record.database = Some(DatabaseRecord {
            name: name.clone(),
            username: credentials.username.clone(),
            port: pg.port,
            cluster,
            state: DatabaseState::Provisioning,
        });
        self.begin_operation(&mut record, actor, "database_create")?;
        let result: Result<()> = (|| {
            atomic_write(
                &self.pg_secret(project),
                &credentials.encode_private_file()?,
                0o600,
            )?;
            let fragment = Path::new(&pg.hba_directory).join(format!("{name}.conf"));
            atomic_write_group(
                &fragment,
                hba(name).as_bytes(),
                0o640,
                Some(self.pg_gid(&pg)?),
            )?;
            self.pg_preflight(&pg)?;
            self.pg_admin(&pg, "SELECT pg_catalog.pg_reload_conf();")?;
            let verifier = credentials.scram_verifier()?;
            self.pg_admin(&pg, &format!("SET log_statement='none'; SET log_min_error_statement='panic'; SET log_min_duration_statement=-1; SET log_min_duration_sample=-1; SET log_transaction_sample_rate=0; CREATE ROLE {name} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT {} PASSWORD '{verifier}';", pg.connection_limit))?;
            self.pg_admin(
                &pg,
                &format!("CREATE DATABASE {name} OWNER {name} TEMPLATE template0 ENCODING 'UTF8';"),
            )?;
            self.pg_admin(&pg, &format!("REVOKE ALL ON DATABASE {name} FROM PUBLIC;"))?;
            self.pg_verify(&pg, &record, &credentials)?;
            self.pg_environment(&record, &credentials)?;
            Ok(())
        })();
        record.database.as_mut().ok_or_else(internal)?.state = if result.is_ok() {
            DatabaseState::Ready
        } else if result
            .as_ref()
            .err()
            .is_some_and(|e| e.code == ErrorCode::UnknownOutcome)
        {
            DatabaseState::Unknown
        } else {
            DatabaseState::Failed
        };
        self.finish_operation(&mut record, &result)?;
        result?;
        self.finished_status(record)
    }

    pub fn database_reconcile(
        &self,
        actor: &Actor,
        project: &str,
        expected: &Expected,
    ) -> Result<Status> {
        let _project = self.lock(project)?;
        let _postgres = file_lock(&self.state("locks").join(".postgres.lock"))?;
        let mut record = self.record(project)?;
        self.database_permission(actor, &record)?;
        self.revalidate(expected, Some(&record))?;
        record.project.validate()?;
        if record.last_operation.as_ref().is_some_and(|op| {
            matches!(
                op.state,
                OperationState::InProgress | OperationState::Unknown
            ) && !matches!(op.kind.as_str(), "database_create" | "database_reconcile")
        }) {
            return Err(conflict());
        }
        if !matches!(record.registration, Registration::Complete {}) {
            return Err(conflict());
        }
        let pg = self.postgres_settings()?;
        let credentials = self.pg_credentials(&record)?;
        self.pg_preflight(&pg)?;
        self.pg_verify(&pg, &record, &credentials)?;
        // Reconciliation verifies existing SQL objects; it never repeats CREATE/ALTER.
        self.begin_operation(&mut record, actor, "database_reconcile")?;
        let result = self.pg_environment(&record, &credentials);
        if result.is_ok() {
            record.database.as_mut().ok_or_else(conflict)?.state = DatabaseState::Ready;
        }
        self.finish_operation(&mut record, &result)?;
        result?;
        self.finished_status(record)
    }

    pub fn database_private_file(&self, actor: &Actor, project: &str) -> Result<Vec<u8>> {
        let _lock = self.lock(project)?;
        let record = self.record(project)?;
        self.database_permission(actor, &record)?;
        if record
            .database
            .as_ref()
            .is_none_or(|db| db.state != DatabaseState::Ready)
        {
            return Err(conflict());
        }
        self.pg_credentials(&record)?.encode_private_file()
    }

    /// Administrative recovery of an empty, abandoned provisioning checkpoint.
    /// Does not remove SQL objects, credentials, HBA files or application data.
    pub fn forget_empty_database(&self, project: &str, revision: &str) -> Result<()> {
        require_root()?;
        let _project = self.lock(project)?;
        let _postgres = file_lock(&self.state("locks").join(".postgres.lock"))?;
        let mut record = self.record(project)?;
        if hash_json(&record)? != revision
            || !matches!(record.registration, Registration::Complete {})
        {
            return Err(conflict());
        }
        let database = record.database.as_ref().ok_or_else(conflict)?;
        if database.state == DatabaseState::Ready
            || !cais_core::postgres_identifier(&database.name)
            || database.username != database.name
            || record.last_operation.as_ref().is_some_and(|op| {
                matches!(
                    op.state,
                    OperationState::Unknown | OperationState::InProgress
                ) && !matches!(op.kind.as_str(), "database_create" | "database_reconcile")
            })
        {
            return Err(conflict());
        }
        let pg = self.postgres_settings()?;
        for path in [
            self.pg_secret(project),
            Path::new(&self.settings.paths.config)
                .join(project)
                .join("database.env"),
            Path::new(&pg.hba_directory).join(format!("{}.conf", database.name)),
        ] {
            match fs::symlink_metadata(path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => return Err(conflict()),
            }
        }
        self.pg_preflight(&pg)?;
        if self
            .pg_admin(
                &pg,
                "SELECT system_identifier::text FROM pg_catalog.pg_control_system();",
            )?
            .trim()
            != database.cluster
        {
            return Err(conflict());
        }
        let name = &database.name;
        let application = format!("cais/{}", self.instance);
        if self.pg_admin(&pg, &format!("SELECT NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='{name}') AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_database WHERE datname='{name}') AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE application_name='{application}' AND usename='{admin}' AND pid<>pg_catalog.pg_backend_pid());", admin=pg.os_user))?.trim() != "t" {
            return Err(conflict());
        }
        record.database = None;
        record.last_operation = Some(OperationStatus {
            kind: "database_abandoned_empty".into(),
            actor: authenticated_actor()?.name,
            state: OperationState::Resolved,
            updated_at: now(),
            inspection: Some(Inspection {
                by: authenticated_actor()?.name,
                at: now(),
            }),
        });
        self.save(&mut record)
    }

    fn database_permission(&self, actor: &Actor, record: &Record) -> Result<()> {
        self.authorize(actor, record, false)?;
        if self.delegated(record).database {
            Ok(())
        } else {
            Err(denied())
        }
    }
    fn pg_gid(&self, pg: &PostgresSettings) -> Result<u32> {
        let output = command("/usr/bin/id", &["-g", "--", &pg.os_user], self.timeout())?;
        if !output.success {
            return Err(pg_failed());
        }
        output.text.trim().parse().map_err(|_| internal())
    }
    fn postgres_settings(&self) -> Result<PostgresSettings> {
        let pg = self.settings.postgres.clone().ok_or_else(|| {
            CaisError::new(ErrorCode::Unsupported, "PostgreSQL is not configured.")
        })?;
        postgres_client_path(&pg)?;
        Ok(pg)
    }
    fn pg_secret(&self, project: &str) -> PathBuf {
        Path::new(&self.settings.paths.config)
            .join(project)
            .join("database.private.json")
    }
    fn pg_credentials(&self, record: &Record) -> Result<Credentials> {
        let db = record.database.as_ref().ok_or_else(conflict)?;
        let path = self.pg_secret(&record.project.project);
        trusted_file(&path)?;
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(io_error)?
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        let credentials = Credentials::decode_private_file(&bytes)?;
        if credentials.database != db.name
            || credentials.username != db.username
            || credentials.port != db.port
        {
            return Err(conflict());
        }
        Ok(credentials)
    }
    fn pg_preflight(&self, pg: &PostgresSettings) -> Result<()> {
        // Verify the local server endpoint before any administrative SQL, not only
        // when checking the generated application's authentication afterwards.
        self.pg_socket(pg)?;
        let marker = Path::new(&pg.hba_directory).join(".cais-owner");
        trusted_file(&marker)?;
        if fs::read_to_string(marker).map_err(io_error)? != self.instance {
            return Err(conflict());
        }
        let version: u32 = self
            .pg_admin(pg, "SHOW server_version_num;")?
            .trim()
            .parse()
            .map_err(|_| internal())?;
        if version < 160000 {
            return Err(CaisError::new(
                ErrorCode::Unsupported,
                "PostgreSQL 16 or newer is required.",
            ));
        }
        let main = self.pg_admin(pg, "SHOW hba_file;")?.trim().to_owned();
        if !cais_core::absolute_host_path(&main) {
            return Err(internal());
        }
        let mut contents = String::new();
        File::open(main)
            .map_err(io_error)?
            .take(131073)
            .read_to_string(&mut contents)
            .map_err(io_error)?;
        let first = contents
            .lines()
            .map(|line| line.split('#').next().unwrap_or("").trim())
            .find(|line| !line.is_empty())
            .unwrap_or("");
        let tokens: Vec<_> = first.split_whitespace().collect();
        if contents.len() > 131072
            || tokens.len() != 2
            || tokens[0] != "include_dir"
            || tokens[1].trim_matches('"') != pg.hba_directory
        {
            return Err(CaisError::new(
                ErrorCode::PolicyDenied,
                "PostgreSQL requires its managed HBA include as the first active directive.",
            ));
        }
        if self.pg_admin(pg, "SELECT NOT EXISTS(SELECT 1 FROM pg_catalog.pg_hba_file_rules WHERE error IS NOT NULL);")?.trim() != "t" { return Err(pg_failed()); }
        Ok(())
    }
    fn pg_verify(
        &self,
        pg: &PostgresSettings,
        record: &Record,
        credentials: &Credentials,
    ) -> Result<()> {
        let db = record.database.as_ref().ok_or_else(conflict)?;
        let name = &db.name;
        if !cais_core::postgres_identifier(name) || db.username != *name || pg.port != db.port {
            return Err(conflict());
        }
        if self
            .pg_admin(
                pg,
                "SELECT system_identifier::text FROM pg_catalog.pg_control_system();",
            )?
            .trim()
            != db.cluster
        {
            return Err(conflict());
        }
        let valid = self.pg_admin(pg, &format!("SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_roles r JOIN pg_catalog.pg_database d ON d.datdba=r.oid WHERE r.rolname='{name}' AND d.datname='{name}' AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolreplication AND NOT r.rolbypassrls AND NOT r.rolinherit AND r.rolconnlimit BETWEEN 1 AND {limit} AND d.datallowconn AND NOT d.datistemplate AND NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(d.datacl,pg_catalog.acldefault('d',d.datdba))) a WHERE a.grantee<>r.oid) AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member=r.oid OR m.roleid=r.oid));", limit=pg.connection_limit))?;
        if valid.trim() != "t" {
            return Err(conflict());
        }
        let fragment = Path::new(&pg.hba_directory).join(format!("{name}.conf"));
        trusted_file(&fragment)?;
        if fs::read_to_string(fragment).map_err(io_error)? != hba(name) {
            return Err(conflict());
        }
        self.pg_socket(pg)?;
        let until = (Instant::now() + Duration::from_secs(5)).min(self.execution_deadline.get());
        loop {
            let own = self.pg_client(
                pg,
                credentials,
                &pg.socket_directory,
                &credentials.database,
                true,
            )?;
            let other = self.pg_client(
                pg,
                credentials,
                &pg.socket_directory,
                &pg.admin_database,
                false,
            )?;
            let control = self.pg_client(
                pg,
                credentials,
                &pg.socket_directory,
                &credentials.database,
                true,
            )?;
            let tcp = self.pg_client(pg, credentials, "127.0.0.1", &credentials.database, true)?;
            if own.success
                && own.text.trim() == credentials.username
                && other.code == Some(2)
                && control.success
                && control.text.trim() == credentials.username
                && tcp.success
                && tcp.text.trim() == credentials.username
            {
                return Ok(());
            }
            if Instant::now() >= until {
                return Err(pg_failed());
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
    fn pg_environment(&self, record: &Record, credentials: &Credentials) -> Result<()> {
        let data = format!(
            "PGHOST=127.0.0.1\nPGPORT={}\nPGDATABASE={}\nPGUSER={}\nPGPASSWORD={}\nDATABASE_URL=postgresql://{}:{}@127.0.0.1:{}/{}\n",
            credentials.port,
            credentials.database,
            credentials.username,
            credentials.password_for_child(),
            credentials.username,
            credentials.password_for_child(),
            credentials.port,
            credentials.database
        );
        let path = Path::new(&self.settings.paths.config)
            .join(&record.project.project)
            .join("database.env");
        let group = command(
            "/usr/bin/id",
            &["-g", "--", &record.runtime_user],
            self.timeout(),
        )?;
        if !group.success {
            return Err(pg_failed());
        }
        let gid = group.text.trim().parse().map_err(|_| internal())?;
        atomic_write_group(&path, data.as_bytes(), 0o640, Some(gid))
    }
    fn pg_admin(&self, pg: &PostgresSettings, sql: &str) -> Result<String> {
        let output = self.pg_command(
            pg,
            &pg.os_user,
            &pg.socket_directory,
            &pg.os_user,
            &pg.admin_database,
            None,
            false,
            sql,
        )?;
        if output.success {
            Ok(output.text)
        } else {
            Err(pg_failed())
        }
    }
    fn pg_client(
        &self,
        pg: &PostgresSettings,
        credentials: &Credentials,
        host: &str,
        database: &str,
        require_scram: bool,
    ) -> Result<Output> {
        self.pg_command(
            pg,
            &pg.os_user,
            host,
            &credentials.username,
            database,
            Some(credentials.password_for_child()),
            require_scram,
            "SELECT current_user;",
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn pg_command(
        &self,
        pg: &PostgresSettings,
        user: &str,
        host: &str,
        role: &str,
        database: &str,
        password: Option<&str>,
        require_scram: bool,
        sql: &str,
    ) -> Result<Output> {
        let seconds = self.timeout();
        if seconds == 0 {
            return Err(CaisError::new(
                ErrorCode::UnknownOutcome,
                "PostgreSQL operation budget expired; inspect state.",
            ));
        }
        let mut input = tempfile::tempfile().map_err(io_error)?;
        input.write_all(sql.as_bytes()).map_err(io_error)?;
        input.seek(SeekFrom::Start(0)).map_err(io_error)?;
        let mut output = tempfile::tempfile().map_err(io_error)?;
        let group = command("/usr/bin/id", &["-g", "--", user], self.timeout())?;
        if !group.success {
            return Err(pg_failed());
        }
        let gid: u32 = group.text.trim().parse().map_err(|_| internal())?;
        trusted_executable(Path::new("/usr/bin/setpriv"))?;
        let mut command = Command::new("/usr/bin/setpriv");
        // Fail closed on libpq clients too old to require SCRAM, and never allow a
        // peer to downgrade the generated credential to cleartext authentication.
        let connection = if require_scram {
            format!("dbname={database} require_auth=scram-sha-256")
        } else {
            database.to_owned()
        };
        command
            .process_group(0)
            .args([
                "--reuid",
                user,
                "--regid",
                &gid.to_string(),
                "--init-groups",
                "--",
                &pg.psql,
                "-X",
                "-w",
                "-qAt",
                "-v",
                "ON_ERROR_STOP=1",
                "-h",
                host,
                "-p",
                &pg.port.to_string(),
                "-U",
                role,
                "-d",
                &connection,
            ])
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LANG", "C.UTF-8")
            .env("HOME", "/")
            .env("PSQLRC", "/dev/null")
            .env("PGCONNECT_TIMEOUT", "5")
            .env("PGAPPNAME", format!("cais/{}", self.instance))
            .env(
                "PGOPTIONS",
                "-c search_path=pg_catalog -c statement_timeout=10000",
            )
            .stdin(input)
            .stdout(output.try_clone().map_err(io_error)?)
            .stderr(Stdio::null());
        if let Some(password) = password {
            command.env("PGPASSWORD", password);
        }
        let mut child = command.spawn().map_err(io_error)?;
        let until = Instant::now() + Duration::from_secs(seconds);
        loop {
            if let Some(status) = child.try_wait().map_err(io_error)? {
                output.seek(SeekFrom::Start(0)).map_err(io_error)?;
                let mut text = String::new();
                output
                    .take(8193)
                    .read_to_string(&mut text)
                    .map_err(io_error)?;
                if text.len() > 8192 {
                    return Err(pg_failed());
                }
                return Ok(Output {
                    success: status.success(),
                    code: status.code(),
                    text,
                });
            }
            if Instant::now() >= until {
                kill_group(&mut child);
                return Err(CaisError::new(
                    ErrorCode::UnknownOutcome,
                    "PostgreSQL result is unconfirmed; inspect state before retrying.",
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

pub fn postgres_client_path(pg: &PostgresSettings) -> Result<PathBuf> {
    pg.validate()?;
    trusted_executable(Path::new(&pg.psql))?;
    trusted_alias(Path::new(&pg.psql), 0)?;
    Ok(PathBuf::from(&pg.psql))
}

fn hba(name: &str) -> String {
    format!(
        "local {name} {name} scram-sha-256\nlocal all {name} reject\nhost {name} {name} 127.0.0.1/32 scram-sha-256\nhost {name} {name} ::1/128 scram-sha-256\nhost all {name} 0.0.0.0/0 reject\nhost all {name} ::/0 reject\n"
    )
}
fn pg_failed() -> CaisError {
    CaisError::new(
        ErrorCode::OperationFailed,
        "PostgreSQL operation or isolation verification failed; inspect managed state.",
    )
}

// Debian's psql is a multicall wrapper: its original basename is significant.
// Preserve argv[0], checking every link target rather than bypassing mutable intermediates.
fn trusted_alias(path: &Path, depth: usize) -> Result<()> {
    use std::path::Component;
    if depth >= 40 || !path.is_absolute() {
        return Err(denied());
    }
    let mut current = PathBuf::new();
    let mut parts = path.components();
    while let Some(part) = parts.next() {
        match part {
            Component::ParentDir => {
                current.pop();
                continue;
            }
            Component::CurDir => continue,
            _ => current.push(part.as_os_str()),
        }
        let meta = fs::symlink_metadata(&current).map_err(io_error)?;
        if meta.uid() != 0 || (!meta.file_type().is_symlink() && meta.mode() & 0o022 != 0) {
            return Err(denied());
        }
        if meta.file_type().is_symlink() {
            let target = fs::read_link(&current).map_err(io_error)?;
            let mut resolved = if target.is_absolute() {
                target
            } else {
                current.parent().ok_or_else(denied)?.join(target)
            };
            for remaining in parts {
                resolved.push(remaining.as_os_str());
            }
            return trusted_alias(&resolved, depth + 1);
        }
    }
    Ok(())
}
