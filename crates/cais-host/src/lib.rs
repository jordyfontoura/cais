//! Administrative Linux host operations. Never linked to a web process.
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

pub use cais_core::Expected;
use cais_core::{ProjectConfig, SchemaVersion};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Registration {
    Pending {},
    Complete {},
    Failed {},
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Deployment {
    Unknown {
        sha256: String,
        request_id: String,
        inspected_at: u64,
    },
    None {},
    Updating {
        sha256: String,
        request_id: String,
    },
    Success {
        sha256: String,
        request_id: String,
        completed_at: u64,
    },
    Failed {
        sha256: String,
        request_id: String,
        completed_at: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub database_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<DatabaseRecord>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub backup_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<cais_core::ProjectMetadata>,
    pub schema_version: SchemaVersion,
    pub project: ProjectConfig,
    pub members: Vec<String>,
    pub created_by: String,
    pub runtime_user: String,
    pub deploy_user: String,
    pub port: Option<u16>,
    pub registration: Registration,
    pub deployment: Deployment,
    pub sequence: u64,
    pub updated_at: u64,
    #[serde(default)]
    pub last_operation: Option<OperationStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Resolved,
    InProgress,
    Success,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationStatus {
    pub kind: String,
    pub actor: String,
    pub state: OperationState,
    pub updated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inspection: Option<Inspection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inspection {
    pub by: String,
    pub at: u64,
}

#[derive(Debug, Serialize)]
pub struct Status {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<DatabaseRecord>,
    pub project: String,
    pub expected: Expected,
    pub registration: Registration,
    pub deployment: Deployment,
    pub runtime_user: String,
    pub deploy_user: String,
    pub port: Option<u16>,
    pub service: String,
    /// Who holds the application port: `loopback`, `absent`, `exposed` beyond loopback,
    /// `foreign` when another account listens there, or `unknown`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listener: Option<String>,
    pub last_operation: Option<OperationStatus>,
    pub operation_lock_held: bool,
    pub requires_inspection: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<RouteStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup: Option<BackupStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<cais_core::ProjectMetadata>,
    /// `current`, `stale`, `absent` or `unknown`; present when a catalog is configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog: Option<String>,
}

/// Observed from the managed route file; it does not prove DNS, TLS or reachability.
#[derive(Debug, Serialize)]
pub struct RouteStatus {
    pub host: String,
    pub access_profile: String,
    /// `published`, `absent`, `stale`, `unavailable` or `unknown`.
    pub state: String,
}

#[derive(Debug, Serialize)]
pub struct BackupStatus {
    /// `registered`, `absent`, `stale`, `unavailable` or `unknown`.
    pub manifest: String,
    /// `covered`, `not_covered`, `unverified` (no check configured) or `check_failed`.
    pub coverage: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseRecord {
    pub name: String,
    pub username: String,
    pub port: u16,
    pub cluster: String,
    pub state: DatabaseState,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseState {
    Provisioning,
    Unknown,
    Ready,
    Failed,
}
