use crate::{CaisError, ErrorCode, ProjectConfig, Result, ServerConfig, Validate};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    pub configuration_versions: Vec<u32>,
    pub operations: Vec<String>,
    pub deployment: bool,
    pub proxy_management: bool,
    pub database_management: bool,
    pub observations: bool,
    pub mcp: bool,
}

pub fn configuration_sha256(project: &ProjectConfig) -> Result<String> {
    let mut normalized = project.clone();
    normalized.schema = None;
    normalized.artifact.directory = normalized
        .artifact
        .directory
        .strip_prefix("./")
        .unwrap_or(&normalized.artifact.directory)
        .to_owned();
    let bytes = serde_json::to_vec(&normalized)
        .map_err(|_| CaisError::new(ErrorCode::Internal, "Configuration serialization failed."))?;
    Ok(hex(Sha256::digest(bytes)))
}

/// Lowercase hexadecimal text of a digest.
pub fn hex(bytes: impl AsRef<[u8]>) -> String {
    use std::fmt::Write;
    let bytes = bytes.as_ref();
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

impl Default for Capabilities {
    fn default() -> Self {
        Self {
            configuration_versions: vec![1],
            operations: ["capabilities", "list", "plan"].map(String::from).to_vec(),
            deployment: false,
            proxy_management: false,
            database_management: false,
            observations: false,
            mcp: false,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub project: String,
    pub configuration_sha256: String,
    pub policy_checked: bool,
    pub execution_supported: bool,
    pub current_runtime_state: RuntimeState,
    pub requested: ProjectConfig,
    pub notes: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeState {
    NotObserved,
}

impl ServerConfig {
    /// The caller is supplied by the host's OS identity adapter, never by the wire request.
    pub fn authorize(&self, project: &str, caller: &str) -> Result<&crate::ProjectPolicy> {
        self.projects
            .get(project)
            .filter(|p| p.operators.iter().any(|s| s == caller))
            .ok_or_else(|| {
                CaisError::new(
                    ErrorCode::NotAuthorized,
                    "Project is unavailable to this identity.",
                )
            })
    }

    pub fn visible_projects(&self, caller: &str) -> Vec<String> {
        self.projects
            .iter()
            .filter(|(_, p)| p.operators.iter().any(|s| s == caller))
            .map(|(name, _)| name.clone())
            .collect()
    }

    pub fn plan(&self, project: ProjectConfig, caller: &str) -> Result<Plan> {
        project.validate()?;
        let policy = self.authorize(&project.project, caller)?;
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
            return Err(CaisError::new(
                ErrorCode::PolicyDenied,
                "Backup requests are not enabled for this project.",
            ));
        }
        // Editor hints and a redundant ./ do not change deployment intent.
        let digest = configuration_sha256(&project)?;
        Ok(Plan {
            project: project.project.clone(), configuration_sha256: digest,
            policy_checked: true, execution_supported: false,
            current_runtime_state: RuntimeState::NotObserved,
            requested: project,
            notes: vec![
                "Planning preview only: no deployment or route changes are supported in this build.".into(),
                "Runtime, filesystem, DNS, TLS and application health have not been inspected.".into(),
                "A configuration digest identifies intent; it is not an idempotency key or an executable approval.".into(),
            ],
        })
    }
}
