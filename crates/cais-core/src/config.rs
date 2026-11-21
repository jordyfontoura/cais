use crate::{Result, Validate, check, finish};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "u32", into = "u32")]
pub struct SchemaVersion;

impl JsonSchema for SchemaVersion {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "SchemaVersion".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({ "type": "integer", "const": 1 })
    }
}

impl TryFrom<u32> for SchemaVersion {
    type Error = &'static str;
    fn try_from(value: u32) -> std::result::Result<Self, Self::Error> {
        if value == 1 {
            Ok(Self)
        } else {
            Err("Unsupported configuration version")
        }
    }
}
impl From<SchemaVersion> for u32 {
    fn from(_: SchemaVersion) -> u32 {
        1
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub schema_version: SchemaVersion,
    pub project: String,
    pub artifact: Artifact,
    pub app: App,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposure: Option<Exposure>,
    #[serde(default)]
    pub data: Data,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub directory: String,
    pub publish: Vec<String>,
    #[serde(default)]
    pub executables: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum App {
    Http {
        runtime: Runtime,
        entrypoint: String,
        health: String,
    },
    Static {
        public: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Runtime {
    Binary,
    Node,
    Python,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Exposure {
    pub host: String,
    /// `/` for the whole host, or a prefix such as `/docs`. A hostname belongs to one project.
    pub path: String,
    pub access_profile: String,
    /// Remove the prefix before the request reaches an HTTP application. Static sites
    /// are always served relative to the prefix.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub strip_prefix: bool,
}

/// `/`, or one to eight plain segments without a trailing slash.
pub fn exposure_path(value: &str) -> bool {
    value == "/"
        || (value.starts_with('/')
            && value.len() <= 120
            && value.split('/').skip(1).count() <= 8
            && value.split('/').skip(1).all(|part| {
                !part.is_empty()
                    && !matches!(part, "." | "..")
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            }))
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Data {
    #[serde(default)]
    pub preserve: Vec<String>,
    #[serde(default)]
    pub backup: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub schema_version: SchemaVersion,
    pub targets: BTreeMap<String, Target>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// A verified OpenSSH alias or user@host, never shell syntax.
    pub ssh: String,
    pub server_path: String,
    pub known_hosts: String,
    /// When omitted, preserve the Port configured in the OpenSSH alias.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_config: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_file: Option<String>,
    /// Optional local OpenSSH executable. Windows defaults to native System32 OpenSSH.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_executable: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u32,
}

fn default_timeout() -> u32 {
    15
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub schema_version: SchemaVersion,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<crate::HostSettings>,
    #[serde(default)]
    pub operators: BTreeMap<String, OperatorPolicy>,
    /// Administrative policies, not projects adopted from the filesystem.
    pub projects: BTreeMap<String, ProjectPolicy>,
    /// Explicit references to existing installations. Read-only; never adopted.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub external_projects: BTreeMap<String, ExternalProject>,
    #[serde(default)]
    pub access_profiles: BTreeMap<String, AccessProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExternalProject {
    pub operators: Vec<String>,
    pub app: ExternalApp,
    /// Display-only references; Cais never reads application files or connects to these databases.
    pub directory: String,
    #[serde(default)]
    pub databases: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExternalApp {
    Service { unit: String },
    Static {},
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectPolicy {
    #[serde(default)]
    pub database: bool,
    /// Operating-system account names. Identity never comes from a request.
    pub operators: Vec<String>,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub access_profiles: Vec<String>,
    #[serde(default)]
    pub backup: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperatorPolicy {
    #[serde(default)]
    pub database: bool,
    #[serde(default)]
    pub create: bool,
    #[serde(default)]
    pub share_with: Vec<String>,
    #[serde(default)]
    pub domain_suffixes: Vec<String>,
    #[serde(default)]
    pub access_profiles: Vec<String>,
    #[serde(default)]
    pub backup: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AccessProfile {
    Private {
        provider: String,
        /// Administrator-written proxy snippet imported into this profile's routes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        snippet: Option<String>,
    },
    Public {},
}

pub fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !value.ends_with('-')
}

pub fn account_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && (value.as_bytes()[0].is_ascii_lowercase() || value.starts_with('_'))
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
}

pub fn relative_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 240
        && !value.contains(['\\', ':', '*', '?', '[', ']'])
        && value.bytes().all(|b| (32..127).contains(&b))
        && value
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != "..")
}

pub fn portable_path(value: &str) -> bool {
    relative_path(value)
        && value.split('/').all(|part| {
            let stem = part.split('.').next().unwrap_or("").to_ascii_uppercase();
            !part.starts_with(['-', '~', '$'])
                && !part.ends_with([' ', '.'])
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-@+ ".contains(&b))
                && !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                && !(stem.len() == 4
                    && (stem.starts_with("COM") || stem.starts_with("LPT"))
                    && matches!(stem.as_bytes()[3], b'1'..=b'9'))
        })
}

pub fn artifact_path(value: &str) -> bool {
    portable_path(value)
        && value.split('/').all(|p| {
            !matches!(p.to_ascii_lowercase().as_str(), ".git" | ".ssh" | ".env")
                && !p.to_ascii_lowercase().starts_with(".env.")
        })
}

pub fn host_name(value: &str) -> bool {
    value.len() <= 253
        && value.contains('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        && value.bytes().any(|b| b.is_ascii_lowercase())
}

pub fn overlaps(a: &str, b: &str) -> bool {
    a == b
        || a.strip_prefix(b).is_some_and(|s| s.starts_with('/'))
        || b.strip_prefix(a).is_some_and(|s| s.starts_with('/'))
}

fn inside(path: &str, roots: &[String]) -> bool {
    roots
        .iter()
        .any(|root| path == root || path.strip_prefix(root).is_some_and(|s| s.starts_with('/')))
}

impl Validate for ProjectConfig {
    fn validate(&self) -> Result<()> {
        let mut issues = Vec::new();
        // Bound work and diagnostics even when called directly from the protocol adapter.
        if self.artifact.publish.len() > 32
            || self.artifact.executables.len() > 128
            || self.data.preserve.len() > 128
            || self.data.backup.len() > 128
        {
            check(
                &mut issues,
                false,
                "/",
                "Configuration has too many path entries.",
            );
            return finish(issues);
        }
        check(
            &mut issues,
            identifier(&self.project),
            "/project",
            "Use 1-63 lowercase letters, digits or hyphens, starting with a letter and ending without a hyphen.",
        );
        let directory = self
            .artifact
            .directory
            .strip_prefix("./")
            .unwrap_or(&self.artifact.directory);
        check(
            &mut issues,
            portable_path(directory),
            "/artifact/directory",
            "Use a relative artifact directory without traversal.",
        );
        check(
            &mut issues,
            !self.artifact.publish.is_empty() && self.artifact.publish.len() <= 32,
            "/artifact/publish",
            "Declare 1-32 explicit publish paths.",
        );
        for (i, path) in self.artifact.publish.iter().enumerate() {
            check(
                &mut issues,
                artifact_path(path),
                &format!("/artifact/publish/{i}"),
                "Invalid artifact path or reserved secret path.",
            );
            check(
                &mut issues,
                !self.artifact.publish[..i]
                    .iter()
                    .any(|other| overlaps(&path.to_ascii_lowercase(), &other.to_ascii_lowercase())),
                &format!("/artifact/publish/{i}"),
                "Publish paths must not overlap or repeat.",
            );
            check(
                &mut issues,
                !self
                    .data
                    .preserve
                    .iter()
                    .any(|other| overlaps(&path.to_ascii_lowercase(), &other.to_ascii_lowercase())),
                &format!("/artifact/publish/{i}"),
                "Publish and preserve paths must not overlap.",
            );
        }
        for (i, path) in self.artifact.executables.iter().enumerate() {
            check(
                &mut issues,
                artifact_path(path) && inside(path, &self.artifact.publish),
                &format!("/artifact/executables/{i}"),
                "An executable must be inside a publish path.",
            );
        }
        for (i, path) in self.data.preserve.iter().enumerate() {
            check(
                &mut issues,
                portable_path(path)
                    && !self.data.preserve[..i].iter().any(|other| {
                        overlaps(&path.to_ascii_lowercase(), &other.to_ascii_lowercase())
                    }),
                &format!("/data/preserve/{i}"),
                "Preserved directories must be portable, distinct and non-overlapping.",
            );
        }
        for (i, path) in self.data.backup.iter().enumerate() {
            check(
                &mut issues,
                relative_path(path) && self.data.preserve.contains(path),
                &format!("/data/backup/{i}"),
                "Backup paths must be explicitly preserved.",
            );
        }
        match &self.app {
            App::Http {
                runtime,
                entrypoint,
                health,
            } => {
                check(
                    &mut issues,
                    artifact_path(entrypoint) && inside(entrypoint, &self.artifact.publish),
                    "/app/entrypoint",
                    "Entrypoint must be inside a publish path.",
                );
                check(
                    &mut issues,
                    *runtime != Runtime::Binary || self.artifact.executables.contains(entrypoint),
                    "/artifact/executables",
                    "Declare the binary entrypoint as executable.",
                );
                check(
                    &mut issues,
                    health.starts_with('/')
                        && !health.starts_with("//")
                        && !health.contains(['?', '#', '\\', '\r', '\n'])
                        && health.len() <= 240
                        && health.bytes().all(|b| (33..127).contains(&b)),
                    "/app/health",
                    "Use an absolute health path without query, fragment or control characters.",
                );
            }
            App::Static { public } => check(
                &mut issues,
                artifact_path(public) && inside(public, &self.artifact.publish),
                "/app/public",
                "Public directory must be inside a publish path.",
            ),
        }
        if let Some(exposure) = &self.exposure {
            check(
                &mut issues,
                host_name(&exposure.host),
                "/exposure/host",
                "Use a lowercase DNS hostname without URL, port or wildcard.",
            );
            check(
                &mut issues,
                exposure_path(&exposure.path),
                "/exposure/path",
                "Use / or a prefix of plain segments without a trailing slash.",
            );
            check(
                &mut issues,
                !exposure.strip_prefix || exposure.path != "/",
                "/exposure/strip_prefix",
                "Only a prefix below the root can be stripped.",
            );
            check(
                &mut issues,
                identifier(&exposure.access_profile),
                "/exposure/access_profile",
                "Invalid access profile identifier.",
            );
        }
        finish(issues)
    }
}

impl Validate for ClientConfig {
    fn validate(&self) -> Result<()> {
        let mut issues = Vec::new();
        for (name, target) in &self.targets {
            check(
                &mut issues,
                target
                    .ssh_executable
                    .as_ref()
                    .is_none_or(|s| !s.is_empty() && !s.contains(['\r', '\n', '\0'])),
                "/targets/*/ssh_executable",
                "Invalid local OpenSSH executable path.",
            );
            // Do not echo target names or configuration values in diagnostics.
            check(
                &mut issues,
                identifier(name),
                "/targets",
                "Invalid target identifier.",
            );
            check(
                &mut issues,
                !target.ssh.is_empty()
                    && !target.ssh.starts_with('-')
                    && target.ssh.len() <= 255
                    && target
                        .ssh
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-._@[]:".contains(&b)),
                "/targets/*/ssh",
                "Invalid OpenSSH destination.",
            );
            check(
                &mut issues,
                target.server_path.starts_with('/')
                    && target.server_path.split('/').skip(1).all(|s| {
                        !s.is_empty()
                            && s != "."
                            && s != ".."
                            && s.bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                    }),
                "/targets/*/server_path",
                "Use an absolute server executable path with safe components.",
            );
            check(
                &mut issues,
                !target.known_hosts.is_empty() && !target.known_hosts.contains(['\r', '\n', '\0']),
                "/targets/*/known_hosts",
                "A verified known_hosts file is required.",
            );
            check(
                &mut issues,
                target
                    .identity_file
                    .as_ref()
                    .is_none_or(|s| !s.is_empty() && !s.contains(['\r', '\n', '\0'])),
                "/targets/*/identity_file",
                "Invalid identity file path.",
            );
            check(
                &mut issues,
                target
                    .ssh_config
                    .as_ref()
                    .is_none_or(|s| !s.is_empty() && !s.contains(['\r', '\n', '\0'])),
                "/targets/*/ssh_config",
                "Invalid SSH configuration path.",
            );
            check(
                &mut issues,
                target.port.is_none_or(|port| port > 0),
                "/targets/*/port",
                "SSH port must be 1-65535.",
            );
            check(
                &mut issues,
                (1..=120).contains(&target.timeout_seconds),
                "/targets/*/timeout_seconds",
                "Timeout must be 1-120 seconds.",
            );
        }
        finish(issues)
    }
}

impl Validate for ServerConfig {
    fn validate(&self) -> Result<()> {
        if let Some(host) = &self.host {
            host.validate()?;
            if self
                .operators
                .keys()
                .chain(self.projects.values().flat_map(|p| p.operators.iter()))
                .any(|user| !account_name(user))
            {
                return Err(crate::CaisError::new(
                    crate::ErrorCode::InvalidConfig,
                    "Native policies require safe Linux account names.",
                ));
            }
        }
        let mut issues = Vec::new();
        for (name, operator) in &self.operators {
            check(
                &mut issues,
                !name.is_empty() && name.len() <= 128 && !name.chars().any(char::is_control),
                "/operators",
                "Invalid operating-system account name.",
            );
            check(
                &mut issues,
                operator
                    .share_with
                    .iter()
                    .all(|user| self.operators.contains_key(user)),
                "/operators/*/share_with",
                "Shared accounts must be administratively configured operators.",
            );
            check(
                &mut issues,
                operator.domain_suffixes.iter().all(|host| host_name(host)),
                "/operators/*/domain_suffixes",
                "Domain suffixes require lowercase DNS names.",
            );
            check(
                &mut issues,
                operator
                    .access_profiles
                    .iter()
                    .all(|profile| self.access_profiles.contains_key(profile)),
                "/operators/*/access_profiles",
                "Unknown delegated access profile.",
            );
        }
        check(
            &mut issues,
            self.projects.len() <= 128,
            "/projects",
            "At most 128 project policies are supported.",
        );
        let mut hosts = BTreeSet::new();
        check(
            &mut issues,
            self.external_projects.len() <= 128
                && (self.external_projects.is_empty() || self.host.is_some()),
            "/external_projects",
            "External projects require a native host and support at most 128 references.",
        );
        for (name, project) in &self.external_projects {
            check(
                &mut issues,
                identifier(name) && !self.projects.contains_key(name),
                "/external_projects",
                "Use unique project identifiers without native policy collisions.",
            );
            check(
                &mut issues,
                !project.operators.is_empty()
                    && project.operators.iter().all(|user| account_name(user)),
                "/external_projects/*/operators",
                "Declare explicit Linux operator accounts.",
            );
            check(
                &mut issues,
                crate::absolute_host_path(&project.directory)
                    && project.databases.len() <= 16
                    && project
                        .databases
                        .iter()
                        .all(|db| crate::postgres_identifier(db)),
                "/external_projects/*",
                "Use absolute reference paths and database identifiers, never credentials.",
            );
            if let ExternalApp::Service { unit } = &project.app {
                check(
                    &mut issues,
                    unit.len() <= 128
                        && unit.ends_with(".service")
                        && unit
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))
                        && unit
                            .as_bytes()
                            .first()
                            .is_some_and(u8::is_ascii_alphanumeric),
                    "/external_projects/*/app/unit",
                    "Use a service unit name without paths or options.",
                );
            }
        }
        for (name, policy) in &self.projects {
            check(
                &mut issues,
                identifier(name),
                "/projects",
                "Invalid project identifier.",
            );
            check(
                &mut issues,
                !policy.operators.is_empty()
                    && policy.operators.iter().all(|s| {
                        !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control)
                    }),
                "/projects/*/operators",
                "Declare operating-system account names.",
            );
            for host in &policy.hosts {
                check(
                    &mut issues,
                    host_name(host) && hosts.insert(host),
                    "/projects/*/hosts",
                    "Invalid or multiply delegated hostname.",
                );
            }
            check(
                &mut issues,
                policy
                    .access_profiles
                    .iter()
                    .all(|s| self.access_profiles.contains_key(s)),
                "/projects/*/access_profiles",
                "Every delegated profile must be administratively defined.",
            );
        }
        for (name, profile) in &self.access_profiles {
            check(
                &mut issues,
                identifier(name),
                "/access_profiles",
                "Invalid profile identifier.",
            );
            if let AccessProfile::Private { provider, snippet } = profile {
                check(
                    &mut issues,
                    identifier(provider),
                    "/access_profiles/*/provider",
                    "Invalid provider identifier.",
                );
                check(
                    &mut issues,
                    snippet.iter().all(|name| crate::snippet_name(name)),
                    "/access_profiles/*/snippet",
                    "Use the name of an administrator-written proxy snippet.",
                );
            }
        }
        finish(issues)
    }
}
