//! Optional reverse-proxy routes and backup manifests. Cais writes only inside its own
//! marked directories; the administrator's proxy and backup configuration is never edited.
use super::*;
use cais_core::{AccessProfile, BackupSettings, CaddySettings};

const ROUTE_HEADER: &str = "# Managed by Cais. Do not edit: changes are overwritten.\n";

fn unsupported(message: &str) -> CaisError {
    CaisError::new(ErrorCode::Unsupported, message)
}

impl Host {
    fn caddy(&self) -> Result<&CaddySettings> {
        self.settings
            .caddy
            .as_ref()
            .ok_or_else(|| unsupported("Proxy management is not administratively configured."))
    }
    fn backup(&self) -> Result<&BackupSettings> {
        self.settings
            .backup
            .as_ref()
            .ok_or_else(|| unsupported("Backup registration is not administratively configured."))
    }

    /// Creates the dedicated directories on `--init`. Populated foreign directories are
    /// refused; an unchanged installation can be initialized again.
    pub fn initialize_integrations(&self) -> Result<()> {
        require_root()?;
        let roots = self
            .settings
            .caddy
            .iter()
            .map(|caddy| &caddy.routes)
            .chain(self.settings.backup.iter().map(|backup| &backup.manifests));
        for root in roots {
            let root = Path::new(root);
            trusted_existing_ancestors(root)?;
            let marker = root.join(".cais-root");
            if marker.exists() {
                self.integration_root(root)?;
                continue;
            }
            if root.exists() && fs::read_dir(root).map_err(io_error)?.next().is_some() {
                return Err(CaisError::new(
                    ErrorCode::Conflict,
                    "Integration directories must be new or empty; existing files are not adopted.",
                ));
            }
            fs::create_dir_all(root).map_err(io_error)?;
            permissions(root, 0o755)?;
            atomic_write(&marker, self.instance.as_bytes(), 0o600)?;
        }
        Ok(())
    }

    fn integration_root(&self, root: &Path) -> Result<PathBuf> {
        let marker = root.join(".cais-root");
        match fs::symlink_metadata(&marker) {
            Ok(_) => {}
            Err(_) => {
                return Err(unsupported(
                    "Integration directory is not initialized; an administrator must run the broker initialization.",
                ));
            }
        }
        trusted_file(&marker)?;
        if fs::read_to_string(marker).map_err(io_error)? != self.instance {
            return Err(CaisError::new(
                ErrorCode::Conflict,
                "Integration directory belongs to another installation.",
            ));
        }
        Ok(root.to_owned())
    }

    /// Exposed static sites are read by the proxy, not by a runtime process.
    pub(super) fn code_group(&self, record: &Record) -> String {
        match (&record.project.app, &self.settings.caddy) {
            (App::Static { .. }, Some(caddy)) if record.project.exposure.is_some() => {
                caddy.group.clone()
            }
            _ => record.runtime_user.clone(),
        }
    }

    /// Registration and planning refuse intent the configured providers cannot serve.
    pub(super) fn supported_integrations(&self, project: &ProjectConfig) -> Result<()> {
        if let Some(exposure) = &project.exposure {
            self.caddy()?;
            self.profile_import(&exposure.access_profile)?;
        }
        if !project.data.backup.is_empty() {
            self.backup()?;
        }
        Ok(())
    }

    fn profile_import(&self, profile: &str) -> Result<Option<&str>> {
        match self.policy.access_profiles.get(profile) {
            Some(AccessProfile::Public {}) => Ok(None),
            Some(AccessProfile::Private {
                snippet: Some(snippet),
                ..
            }) => Ok(Some(snippet)),
            _ => Err(unsupported(
                "Access profile has no administratively configured proxy snippet.",
            )),
        }
    }

    /// A hostname belongs to one project, including failed registrations not yet released.
    pub(super) fn host_unclaimed(&self, project: &ProjectConfig) -> Result<()> {
        let Some(exposure) = &project.exposure else {
            return Ok(());
        };
        for entry in fs::read_dir(self.state("records")).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            if let Some(name) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.strip_suffix(".json"))
                && identifier(name)
                && name != project.project
                && self
                    .record(name)?
                    .project
                    .exposure
                    .is_some_and(|other| other.host == exposure.host)
            {
                return Err(CaisError::new(
                    ErrorCode::Conflict,
                    "Hostname is already used by another project.",
                ));
            }
        }
        Ok(())
    }

    fn route(&self, record: &Record) -> Result<String> {
        let exposure = record
            .project
            .exposure
            .as_ref()
            .ok_or_else(|| unsupported("Project declares no exposure."))?;
        if !cais_core::host_name(&exposure.host) || !cais_core::exposure_path(&exposure.path) {
            return Err(internal());
        }
        let prefix = (exposure.path != "/").then_some(exposure.path.as_str());
        // Under a prefix the handler is nested one level deeper.
        let indent = if prefix.is_some() { "\t\t" } else { "\t" };
        let (handler, strip) = match &record.project.app {
            App::Http { .. } => (
                format!(
                    "{indent}reverse_proxy 127.0.0.1:{}\n",
                    record.port.ok_or_else(internal)?
                ),
                exposure.strip_prefix,
            ),
            App::Static { public } => {
                let root = self
                    .app(&record.project.project)
                    .join("current")
                    .join(public);
                let root = text(&root)?;
                if root.contains(['"', '\\', '{', '}', '\n', '\r']) {
                    return Err(internal());
                }
                (
                    format!("{indent}root * \"{root}\"\n{indent}file_server\n"),
                    true,
                )
            }
        };
        let mut body = format!("{ROUTE_HEADER}{} {{\n", exposure.host);
        if let Some(snippet) = self.profile_import(&exposure.access_profile)? {
            body.push_str(&format!("\timport {snippet}\n"));
        }
        match prefix {
            None => body.push_str(&handler),
            Some(prefix) => {
                let directive = if strip { "handle_path" } else { "handle" };
                // Everything outside the prefix is answered explicitly, never left to
                // another site or a default.
                body.push_str(&format!(
                    "\tredir {prefix} {prefix}/ 308\n\t{directive} {prefix}/* {{\n{handler}\t}}\n\thandle {{\n\t\trespond 404\n\t}}\n"
                ));
            }
        }
        body.push_str("}\n");
        Ok(body)
    }

    fn route_path(&self, project: &str) -> Result<PathBuf> {
        if !identifier(project) {
            return Err(denied());
        }
        Ok(self
            .integration_root(Path::new(&self.caddy()?.routes))?
            .join(format!("{project}.caddy")))
    }

    pub fn proxy_apply(&self, actor: &Actor, project: &str, expected: &Expected) -> Result<Status> {
        self.proxy_change(actor, project, expected, true)
    }

    pub fn proxy_remove(
        &self,
        actor: &Actor,
        project: &str,
        expected: &Expected,
    ) -> Result<Status> {
        self.proxy_change(actor, project, expected, false)
    }

    fn proxy_change(
        &self,
        actor: &Actor,
        project: &str,
        expected: &Expected,
        publish: bool,
    ) -> Result<Status> {
        let _lock = self.lock(project)?;
        let mut record = self.record(project)?;
        self.authorize(actor, &record, false)?;
        self.revalidate(expected, Some(&record))?;
        complete(&record)?;
        let caddy = self.caddy()?.clone();
        let content = if publish {
            if !self.delegated(&record).exposure {
                return Err(CaisError::new(
                    ErrorCode::PolicyDenied,
                    "The policy no longer delegates this exposure to the project.",
                ));
            }
            self.host_unclaimed(&record.project)?;
            Some(self.route(&record)?)
        } else {
            None
        };
        let path = self.route_path(project)?;
        // Route files are validated together, so changes are serialized across projects.
        let _routes = file_lock(&self.state("locks").join(".proxy.lock"))?;
        let kind = if publish {
            "proxy_apply"
        } else {
            "proxy_remove"
        };
        self.begin_operation(&mut record, actor, kind)?;
        let result = self.replace_route(&caddy, &path, content.as_deref());
        self.finish_operation(&mut record, &result)?;
        result?;
        self.finished_status(record)
    }

    /// Writes one route file, checks the whole proxy configuration and reloads. A rejected
    /// change restores the previous file, so later unrelated reloads cannot pick it up.
    fn replace_route(&self, caddy: &CaddySettings, path: &Path, new: Option<&str>) -> Result<()> {
        let previous = match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(io_error(error)),
            Ok(_) => {
                trusted_file(path)?;
                Some(fs::read(path).map_err(io_error)?)
            }
        };
        let write = |content: Option<&[u8]>| -> Result<()> {
            match content {
                Some(bytes) => atomic_write(path, bytes, 0o644),
                None => match fs::remove_file(path) {
                    Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                        Err(io_error(error))
                    }
                    _ => Ok(()),
                },
            }
        };
        let restore = |error: CaisError| -> CaisError {
            if write(previous.as_deref()).is_err() {
                return CaisError::new(
                    ErrorCode::UnknownOutcome,
                    "The route change was rejected and the previous route file could not be restored; an administrator must inspect the proxy routes.",
                );
            }
            if error.code == ErrorCode::UnknownOutcome {
                error
            } else {
                CaisError::new(
                    ErrorCode::OperationFailed,
                    "The proxy did not accept the configuration; the previous route file was restored and the running proxy was not changed.",
                )
            }
        };
        write(new.map(str::as_bytes))?;
        self.proxy_validate(caddy).map_err(&restore)?;
        match checked(
            "/usr/bin/systemctl",
            &["reload", "--", &caddy.unit],
            self.timeout(),
        ) {
            Ok(()) => {}
            // The reload may or may not have been applied: leave the file for inspection.
            Err(error) if error.code == ErrorCode::UnknownOutcome => return Err(error),
            Err(error) => return Err(restore(error)),
        }
        let active = command(
            "/usr/bin/systemctl",
            &["is-active", "--", &caddy.unit],
            self.timeout().min(10),
        )?;
        if active.text.trim() != "active" {
            return Err(CaisError::new(
                ErrorCode::UnknownOutcome,
                "The proxy is not active after the reload; an administrator must inspect it.",
            ));
        }
        Ok(())
    }

    /// Checks the administrator's whole configuration with the proxy's own identity, so
    /// root never creates files in the proxy's storage.
    fn proxy_validate(&self, caddy: &CaddySettings) -> Result<()> {
        let executable = trusted_executable(Path::new(&caddy.executable))?;
        trusted_executable(Path::new("/usr/bin/setpriv"))?;
        trusted_file(Path::new(&caddy.caddyfile))?;
        let account = command(
            "/usr/bin/getent",
            &["passwd", "--", &caddy.user],
            self.timeout().min(10),
        )?;
        let home = account
            .text
            .trim()
            .split(':')
            .nth(5)
            .filter(|home| account.success && cais_core::absolute_host_path(home))
            .ok_or_else(|| unsupported("The configured proxy account is unavailable."))?
            .to_owned();
        checked(
            "/usr/bin/setpriv",
            &[
                "--reuid",
                &caddy.user,
                "--regid",
                &caddy.group,
                "--init-groups",
                "--",
                "/usr/bin/env",
                "-i",
                &format!("HOME={home}"),
                "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                text(&executable)?,
                "validate",
                "--config",
                &caddy.caddyfile,
                "--adapter",
                "caddyfile",
            ],
            self.timeout(),
        )
    }

    pub(super) fn route_status(&self, record: &Record) -> Option<RouteStatus> {
        let exposure = record.project.exposure.as_ref()?;
        let state = match (self.route(record), self.route_path(&record.project.project)) {
            (Ok(expected), Ok(path)) => match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => "absent",
                Ok(meta) if meta.is_file() && meta.len() <= 65_536 => match fs::read(&path) {
                    Ok(bytes) if bytes == expected.as_bytes() => "published",
                    Ok(_) => "stale",
                    Err(_) => "unknown",
                },
                _ => "unknown",
            },
            _ => "unavailable",
        };
        Some(RouteStatus {
            host: exposure.host.clone(),
            access_profile: exposure.access_profile.clone(),
            state: state.into(),
        })
    }

    fn manifest(&self, record: &Record) -> Result<Vec<u8>> {
        let data = self.data(&record.project.project);
        let paths = record
            .project
            .data
            .backup
            .iter()
            .map(|name| text(&data.join(name)).map(str::to_owned))
            .collect::<Result<Vec<_>>>()?;
        let databases: Vec<_> = record
            .database
            .iter()
            .filter(|database| database.state == DatabaseState::Ready)
            .map(|database| {
                serde_json::json!({"name":database.name,"cluster":database.cluster,"port":database.port})
            })
            .collect();
        if paths.is_empty() && databases.is_empty() {
            return Err(unsupported(
                "Project has no backup paths or ready database to register.",
            ));
        }
        let mut bytes = serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version":1,"project":record.project.project,"instance":self.instance,
            "paths":paths,"databases":databases
        }))
        .map_err(|_| internal())?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    fn manifest_path(&self, project: &str) -> Result<PathBuf> {
        if !identifier(project) {
            return Err(denied());
        }
        Ok(self
            .integration_root(Path::new(&self.backup()?.manifests))?
            .join(format!("{project}.json")))
    }

    /// Declares what a backup tool must cover. Cais copies nothing and stores no dumps.
    pub fn backup_register(
        &self,
        actor: &Actor,
        project: &str,
        expected: &Expected,
    ) -> Result<Status> {
        let _lock = self.lock(project)?;
        let mut record = self.record(project)?;
        self.authorize(actor, &record, false)?;
        self.revalidate(expected, Some(&record))?;
        complete(&record)?;
        if !record.backup_allowed || !self.delegated(&record).backup {
            return Err(CaisError::new(
                ErrorCode::PolicyDenied,
                "Backup registration is not enabled for this project.",
            ));
        }
        let path = self.manifest_path(project)?;
        let manifest = self.manifest(&record)?;
        self.begin_operation(&mut record, actor, "backup_register")?;
        let result = atomic_write(&path, &manifest, 0o644);
        self.finish_operation(&mut record, &result)?;
        result?;
        self.finished_status(record)
    }

    pub(super) fn backup_status(&self, record: &Record) -> Option<BackupStatus> {
        if record.project.data.backup.is_empty()
            && (record.database.is_none() || !record.backup_allowed)
        {
            return None;
        }
        let mut status = BackupStatus {
            manifest: "unavailable".into(),
            coverage: "unverified".into(),
            last_success_at: None,
        };
        let (Ok(expected), Ok(path)) = (
            self.manifest(record),
            self.manifest_path(&record.project.project),
        ) else {
            return Some(status);
        };
        status.manifest = match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => "absent",
            Ok(meta) if meta.is_file() && meta.len() <= 1_048_576 => match fs::read(&path) {
                Ok(bytes) if bytes == expected => "registered",
                Ok(_) => "stale",
                Err(_) => "unknown",
            },
            _ => "unknown",
        }
        .into();
        if status.manifest != "registered" {
            status.coverage = "not_covered".into();
            return Some(status);
        }
        let Some(check) = self.settings.backup.as_ref().and_then(|b| b.check.as_ref()) else {
            return Some(status);
        };
        // A provider failure is reported as such, never as coverage.
        status.coverage = "check_failed".into();
        let Ok(executable) = trusted_executable(Path::new(check)) else {
            return Some(status);
        };
        let Ok(executable) = text(&executable) else {
            return Some(status);
        };
        if let Ok(output) = command(
            executable,
            &[&record.project.project],
            self.timeout().min(10),
        ) {
            match output.code {
                Some(0) => {
                    status.coverage = "covered".into();
                    status.last_success_at = output.text.trim().parse().ok();
                }
                Some(3) => status.coverage = "not_covered".into(),
                _ => {}
            }
        }
        Some(status)
    }
}
