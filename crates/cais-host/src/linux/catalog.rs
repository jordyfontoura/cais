//! Project metadata and the optional catalog: a nonsecret projection of the host's
//! records that any consumer can read. Nothing here depends on a consumer existing.
use super::*;
use cais_core::{CatalogSettings, ExternalApp, ProjectMetadata};

impl Host {
    fn catalog(&self) -> Option<&CatalogSettings> {
        self.settings.catalog.as_ref()
    }

    /// Creates the dedicated catalog directory on `--init` and writes the first catalog.
    pub fn initialize_catalog(&self) -> Result<()> {
        require_root()?;
        let Some(settings) = self.catalog() else {
            return Ok(());
        };
        let root = Path::new(&settings.directory);
        trusted_existing_ancestors(root)?;
        let marker = root.join(".cais-root");
        if !marker.exists() {
            if root.exists() && fs::read_dir(root).map_err(io_error)?.next().is_some() {
                return Err(CaisError::new(
                    ErrorCode::Conflict,
                    "Integration directories must be new or empty; existing files are not adopted.",
                ));
            }
            fs::create_dir_all(root).map_err(io_error)?;
            atomic_write(&marker, self.instance.as_bytes(), 0o600)?;
        }
        let gid = self.catalog_gid(settings)?;
        if let Some(gid) = gid {
            rustix::fs::chown(
                root,
                Some(rustix::process::Uid::ROOT),
                Some(rustix::process::Gid::from_raw(gid)),
            )
            .map_err(|_| internal())?;
        }
        permissions(root, if gid.is_some() { 0o750 } else { 0o755 })?;
        self.write_catalog()
    }

    fn catalog_gid(&self, settings: &CatalogSettings) -> Result<Option<u32>> {
        let Some(group) = &settings.group else {
            return Ok(None);
        };
        let output = command(
            "/usr/bin/getent",
            &["group", "--", group],
            self.timeout().min(10),
        )?;
        output
            .text
            .trim()
            .split(':')
            .nth(2)
            .filter(|_| output.success)
            .and_then(|gid| gid.parse().ok())
            .map(Some)
            .ok_or_else(|| {
                CaisError::new(
                    ErrorCode::Unsupported,
                    "The configured catalog group is unavailable.",
                )
            })
    }

    fn catalog_entry(&self, record: &Record) -> serde_json::Value {
        let project = &record.project;
        let mut entry = serde_json::json!({
            "project": project.project,
            "management": "native",
            "kind": if matches!(project.app, App::Http { .. }) { "http" } else { "static" },
        });
        if matches!(project.app, App::Http { .. }) {
            entry["unit"] = unit_name(&project.project).into();
            entry["port"] = record.port.into();
        }
        if let Some(exposure) = &project.exposure {
            entry["host"] = exposure.host.clone().into();
            entry["access_profile"] = exposure.access_profile.clone().into();
        }
        if let Some(metadata) = &record.metadata {
            let mut metadata = metadata.clone();
            metadata.schema = None;
            entry["metadata"] = serde_json::to_value(metadata).unwrap_or_default();
        }
        entry
    }

    /// Rebuilds the whole catalog from complete registrations and policy references.
    pub(super) fn write_catalog(&self) -> Result<()> {
        let Some(settings) = self.catalog() else {
            return Ok(());
        };
        let root = Path::new(&settings.directory);
        let marker = root.join(".cais-root");
        if fs::symlink_metadata(&marker).is_err() {
            return Err(CaisError::new(
                ErrorCode::Unsupported,
                "Integration directory is not initialized; an administrator must run the broker initialization.",
            ));
        }
        trusted_file(&marker)?;
        if fs::read_to_string(&marker).map_err(io_error)? != self.instance {
            return Err(conflict());
        }
        // Concurrent writers could otherwise publish an older snapshot last.
        let _lock = file_lock(&self.state("locks").join(".catalog.lock"))?;
        let mut projects = BTreeMap::new();
        for entry in fs::read_dir(self.state("records")).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            if let Some(name) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.strip_suffix(".json"))
                && identifier(name)
            {
                let record = self.record(name)?;
                if matches!(record.registration, Registration::Complete {}) {
                    projects.insert(name.to_owned(), self.catalog_entry(&record));
                }
            }
        }
        for (name, reference) in &self.policy.external_projects {
            let mut entry = serde_json::json!({"project":name,"management":"external"});
            match &reference.app {
                ExternalApp::Service { unit } => {
                    entry["kind"] = "service".into();
                    entry["unit"] = unit.clone().into();
                }
                ExternalApp::Static {} => entry["kind"] = "static".into(),
            }
            projects.insert(name.clone(), entry);
        }
        let mut bytes = serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": 1,
            "instance": self.instance,
            "generated_at": now(),
            "projects": projects.into_values().collect::<Vec<_>>(),
        }))
        .map_err(|_| internal())?;
        bytes.push(b'\n');
        let gid = self.catalog_gid(settings)?;
        atomic_write_group(
            &root.join("catalog.json"),
            &bytes,
            if gid.is_some() { 0o640 } else { 0o644 },
            gid,
        )
    }

    /// Replaces the project's presentation metadata. Separate from deployment: a
    /// publication is never repeated to repair metadata.
    pub fn set_metadata(
        &self,
        actor: &Actor,
        project: &str,
        metadata: ProjectMetadata,
        expected: &Expected,
    ) -> Result<Status> {
        metadata.validate()?;
        let _lock = self.lock(project)?;
        let mut record = self.record(project)?;
        self.authorize(actor, &record, false)?;
        self.revalidate(expected, Some(&record))?;
        complete(&record)?;
        if let Some(host) = metadata.url_host()
            && record
                .project
                .exposure
                .as_ref()
                .is_none_or(|exposure| exposure.host != host)
        {
            return Err(CaisError::new(
                ErrorCode::PolicyDenied,
                "The metadata address must use the project's own declared hostname.",
            ));
        }
        record.metadata = Some(ProjectMetadata {
            schema: None,
            ..metadata
        });
        self.begin_operation(&mut record, actor, "metadata")?;
        // The record already holds the metadata; a catalog failure is reported and the
        // same command repairs it.
        let result = self.write_catalog();
        self.finish_operation(&mut record, &result)?;
        result?;
        self.finished_status(record)
    }

    pub(super) fn catalog_status(&self, record: &Record) -> Option<String> {
        let settings = self.catalog()?;
        let path = Path::new(&settings.directory).join("catalog.json");
        let state = match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => "absent",
            Ok(meta) if meta.is_file() && meta.len() <= 4 * MIB => {
                match fs::read(&path)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                {
                    Some(catalog)
                        if catalog["instance"] == self.instance.as_str()
                            && catalog["projects"].as_array().is_some_and(|projects| {
                                projects
                                    .iter()
                                    .any(|entry| *entry == self.catalog_entry(record))
                            }) =>
                    {
                        "current"
                    }
                    Some(_) => "stale",
                    None => "unknown",
                }
            }
            _ => "unknown",
        };
        Some(state.into())
    }
}
