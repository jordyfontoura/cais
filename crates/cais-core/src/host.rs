use crate::{Result, Validate, check, finish, overlaps};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Expected {
    pub instance: String,
    pub policy_sha256: String,
    pub revision: Option<String>,
}

/// Authorized, nonsecret connection metadata; never accepts a requested destination.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConnection {
    pub schema_version: crate::SchemaVersion,
    pub project: String,
    pub database: String,
    pub username: String,
    pub port: u16,
    pub cluster: String,
    pub socket: String,
    pub owner_uid: u32,
    pub session_seconds: u32,
}
impl Validate for DatabaseConnection {
    fn validate(&self) -> Result<()> {
        let mut issues = Vec::new();
        check(
            &mut issues,
            crate::identifier(&self.project)
                && postgres_identifier(&self.database)
                && self.database == self.username
                && self.port > 0
                && absolute_host_path(&self.socket)
                && !self.cluster.is_empty()
                && self.cluster.bytes().all(|b| b.is_ascii_digit())
                && self.owner_uid > 0
                && (10..=86400).contains(&self.session_seconds),
            "/database",
            "Invalid database connection metadata.",
        );
        finish(issues)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostSettings {
    pub paths: HostPaths,
    #[serde(default)]
    pub ports: PortRange,
    #[serde(default)]
    pub runtimes: Runtimes,
    #[serde(default)]
    pub limits: HostLimits,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postgres: Option<PostgresSettings>,
    /// Optional reverse proxy. Cais writes only inside `routes`; the main file is never edited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caddy: Option<CaddySettings>,
    /// Optional backup adapter: manifests any tool can read, plus an optional coverage check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<BackupSettings>,
    /// Optional catalog of projects for dashboards and other read-only consumers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog: Option<CatalogSettings>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CatalogSettings {
    /// Dedicated directory holding `catalog.json`.
    #[serde(default = "default_catalog")]
    pub directory: String,
    /// When set, only root and this group can read the catalog; otherwise any local account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}
fn default_catalog() -> String {
    "/var/lib/cais-catalog".into()
}
impl Validate for CatalogSettings {
    fn validate(&self) -> Result<()> {
        let mut issues = Vec::new();
        check(
            &mut issues,
            absolute_host_path(&self.directory)
                && self.group.iter().all(|group| crate::account_name(group)),
            "/host/catalog",
            "Use a safe absolute catalog directory and a valid group name.",
        );
        finish(issues)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct CaddySettings {
    pub executable: String,
    /// Administrator-owned main configuration. Validated as a whole, never modified.
    pub caddyfile: String,
    /// Dedicated directory the administrator imports once, e.g. `import /etc/caddy/cais/*.caddy`.
    pub routes: String,
    /// Account the proxy runs as; configuration checks run with this identity, not root.
    pub user: String,
    /// Group given read access to exposed static sites.
    pub group: String,
    /// systemd unit reloaded after a route change.
    pub unit: String,
}
impl Default for CaddySettings {
    fn default() -> Self {
        Self {
            executable: "/usr/bin/caddy".into(),
            caddyfile: "/etc/caddy/Caddyfile".into(),
            routes: "/etc/caddy/cais".into(),
            user: "caddy".into(),
            group: "caddy".into(),
            unit: "caddy.service".into(),
        }
    }
}
pub fn service_unit(value: &str) -> bool {
    value.len() <= 128
        && value.ends_with(".service")
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
}
/// Name of an administrator-written proxy snippet; never proxy syntax.
pub fn snippet_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
}
impl Validate for CaddySettings {
    fn validate(&self) -> Result<()> {
        let mut issues = Vec::new();
        check(
            &mut issues,
            [&self.executable, &self.caddyfile, &self.routes]
                .iter()
                .all(|p| absolute_host_path(p))
                && !overlaps(&self.caddyfile, &self.routes),
            "/host/caddy",
            "Use safe absolute proxy paths and a dedicated routes directory.",
        );
        check(
            &mut issues,
            crate::account_name(&self.user)
                && crate::account_name(&self.group)
                && self.user != "root"
                && service_unit(&self.unit),
            "/host/caddy",
            "Proxy account, group or service unit is invalid.",
        );
        finish(issues)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupSettings {
    /// Dedicated directory of nonsecret manifests, one per project.
    #[serde(default = "default_manifests")]
    pub manifests: String,
    /// Optional administrator-installed executable: `<check> <project>`. Exit 0 means the
    /// latest backup covered the manifest, 3 means it did not; anything else is a failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<String>,
}
fn default_manifests() -> String {
    "/var/lib/cais-backup".into()
}
impl Validate for BackupSettings {
    fn validate(&self) -> Result<()> {
        let mut issues = Vec::new();
        check(
            &mut issues,
            absolute_host_path(&self.manifests)
                && self.check.iter().all(|path| absolute_host_path(path)),
            "/host/backup",
            "Use safe absolute backup manifest and check paths.",
        );
        finish(issues)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct PostgresSettings {
    pub psql: String,
    pub os_user: String,
    pub socket_directory: String,
    pub port: u16,
    pub admin_database: String,
    pub hba_directory: String,
    pub role_prefix: String,
    pub connection_limit: u16,
}
impl Default for PostgresSettings {
    fn default() -> Self {
        Self {
            psql: "/usr/bin/psql".into(),
            os_user: "postgres".into(),
            socket_directory: "/var/run/postgresql".into(),
            port: 5432,
            admin_database: "postgres".into(),
            hba_directory: "/etc/cais/postgres-hba".into(),
            role_prefix: "cais_".into(),
            connection_limit: 5,
        }
    }
}
pub fn postgres_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
impl Validate for PostgresSettings {
    fn validate(&self) -> Result<()> {
        let mut issues = Vec::new();
        check(
            &mut issues,
            [&self.psql, &self.socket_directory, &self.hba_directory]
                .iter()
                .all(|p| absolute_host_path(p)),
            "/host/postgres",
            "Use safe absolute PostgreSQL paths.",
        );
        check(
            &mut issues,
            crate::account_name(&self.os_user)
                && self.os_user != "root"
                && postgres_identifier(&self.admin_database)
                && postgres_identifier(&self.role_prefix)
                && self.role_prefix.len() <= 16
                && !self.role_prefix.starts_with("pg_")
                && self.port > 0
                && (1..=100).contains(&self.connection_limit),
            "/host/postgres",
            "PostgreSQL identity, namespace, port or connection limit is invalid.",
        );
        finish(issues)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostPaths {
    pub apps: String,
    pub state: String,
    pub config: String,
    #[serde(default = "default_data")]
    pub data: String,
    #[serde(default = "default_server")]
    pub server: String,
    #[serde(default = "default_units")]
    pub units: String,
    #[serde(default = "default_broker")]
    pub broker: String,
    #[serde(default = "default_sudoers")]
    pub sudoers: String,
}
fn default_sudoers() -> String {
    "/etc/sudoers.d".into()
}
fn default_units() -> String {
    "/etc/systemd/system".into()
}
fn default_broker() -> String {
    "/usr/local/libexec/cais/cais-broker".into()
}
fn default_data() -> String {
    "/var/lib/cais-data".into()
}
fn default_server() -> String {
    "/usr/local/bin/cais-server".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PortRange {
    pub first: u16,
    pub last: u16,
}
impl Default for PortRange {
    fn default() -> Self {
        Self {
            first: 8200,
            last: 8299,
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Runtimes {
    pub node: Option<String>,
    pub python: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct HostLimits {
    pub upload_mb: u32,
    pub expanded_mb: u32,
    pub entries: u32,
    pub memory_mb: u32,
    pub cpu_percent: u16,
    pub tasks: u32,
    pub command_seconds: u32,
    pub upload_seconds: u32,
    pub execution_seconds: u32,
    pub database_session_seconds: u32,
}
impl Default for HostLimits {
    fn default() -> Self {
        Self {
            upload_mb: 128,
            expanded_mb: 512,
            entries: 50_000,
            memory_mb: 512,
            cpu_percent: 100,
            tasks: 128,
            command_seconds: 60,
            upload_seconds: 120,
            execution_seconds: 180,
            database_session_seconds: 3600,
        }
    }
}

pub fn absolute_host_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= 240
        && !value.contains(['\\', '\r', '\n', '\0'])
        && value.split('/').skip(1).all(|part| {
            !part.is_empty()
                && !matches!(part, "." | "..")
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        })
}

impl Validate for HostSettings {
    fn validate(&self) -> Result<()> {
        if let Some(postgres) = &self.postgres {
            postgres.validate()?;
        }
        if let Some(caddy) = &self.caddy {
            caddy.validate()?;
        }
        if let Some(backup) = &self.backup {
            backup.validate()?;
        }
        if let Some(catalog) = &self.catalog {
            catalog.validate()?;
        }
        let mut issues = Vec::new();
        let mut paths = vec![
            &self.paths.apps,
            &self.paths.state,
            &self.paths.config,
            &self.paths.data,
            &self.paths.units,
            &self.paths.broker,
            &self.paths.server,
            &self.paths.sudoers,
        ];
        paths.extend(self.caddy.iter().map(|caddy| &caddy.routes));
        paths.extend(self.backup.iter().map(|backup| &backup.manifests));
        paths.extend(self.catalog.iter().map(|catalog| &catalog.directory));
        check(
            &mut issues,
            paths.iter().all(|path| absolute_host_path(path)),
            "/host/paths",
            "Use safe, non-root absolute Linux paths.",
        );
        for (index, path) in paths.iter().enumerate() {
            check(
                &mut issues,
                !paths[..index].iter().any(|other| overlaps(path, other)),
                "/host/paths",
                "Host paths must not overlap.",
            );
        }
        check(
            &mut issues,
            self.ports.first >= 1024
                && self.ports.last >= self.ports.first
                && self.ports.last - self.ports.first <= 1000,
            "/host/ports",
            "Use an unprivileged port range containing at most 1001 ports.",
        );
        check(
            &mut issues,
            self.runtimes
                .node
                .iter()
                .chain(self.runtimes.python.iter())
                .all(|path| absolute_host_path(path)),
            "/host/runtimes",
            "Runtime executables require safe absolute administrative paths.",
        );
        let limits = &self.limits;
        check(
            &mut issues,
            (1..=1024).contains(&limits.upload_mb)
                && limits.expanded_mb >= limits.upload_mb
                && limits.expanded_mb <= 4096
                && (1..=200_000).contains(&limits.entries),
            "/host/limits",
            "Artifact limits are out of range.",
        );
        check(
            &mut issues,
            (32..=65_536).contains(&limits.memory_mb)
                && (1..=1000).contains(&limits.cpu_percent)
                && (16..=100_000).contains(&limits.tasks)
                && (1..=300).contains(&limits.command_seconds),
            "/host/limits",
            "Runtime or command limits are out of range.",
        );
        check(
            &mut issues,
            (1..=600).contains(&limits.upload_seconds)
                && (10..=1800).contains(&limits.execution_seconds)
                && (10..=86400).contains(&limits.database_session_seconds)
                && limits.command_seconds <= limits.execution_seconds,
            "/host/limits",
            "Upload/execution budgets are out of range.",
        );
        finish(issues)
    }
}
