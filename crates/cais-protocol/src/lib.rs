//! Length-bounded control messages over a byte stream; no PTY or artifact payloads.
use cais_core::{CaisError, Capabilities, ErrorCode, Expected, ProjectConfig, Result};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::io::{Read, Write};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAGIC: &[u8; 8] = b"CAIS\0\0\0\x01";
/// Separate readiness preamble for a bounded unprivileged SSH forwarding session.
pub const DATABASE_SESSION_MAGIC: &[u8; 8] = b"CAISDB01";
pub const MAX_FRAME: usize = 131_072;

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub protocol_versions: Vec<u32>,
    pub server_version: String,
    pub capabilities: Capabilities,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_limits: Option<ExecutionLimits>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecutionLimits {
    pub upload_seconds: u32,
    pub execution_seconds: u32,
}

impl Default for Hello {
    fn default() -> Self {
        Self {
            protocol_versions: vec![PROTOCOL_VERSION],
            server_version: env!("CARGO_PKG_VERSION").into(),
            capabilities: Capabilities::default(),
            execution_limits: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub protocol_version: u32,
    pub request_id: String,
    pub operation: Operation,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "name", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    DatabaseConnection {
        project: String,
    },
    DatabaseCredentials {
        project: String,
    },
    DatabaseCreate {
        project: String,
        expected: Expected,
    },
    DatabaseReconcile {
        project: String,
        expected: Expected,
    },
    Capabilities {},
    List {},
    Plan {
        project: Box<ProjectConfig>,
    },
    Status {
        project: String,
    },
    Register {
        project: Box<ProjectConfig>,
        deploy_public_key: String,
        expected: Expected,
    },
    Environment {
        project: String,
        values: std::collections::BTreeMap<String, String>,
        expected: Expected,
    },
    Restart {
        project: String,
        expected: Expected,
    },
    Metadata {
        project: String,
        metadata: Box<cais_core::ProjectMetadata>,
        expected: Expected,
    },
    ProxyApply {
        project: String,
        expected: Expected,
    },
    ProxyRemove {
        project: String,
        expected: Expected,
    },
    BackupRegister {
        project: String,
        expected: Expected,
    },
    Deploy {
        project: String,
        expected: Expected,
        compressed_bytes: u64,
        sha256: String,
        configuration_sha256: String,
    },
}

impl Operation {
    pub fn is_mutation(&self) -> bool {
        match self {
            Self::DatabaseCredentials { .. }
            | Self::DatabaseConnection { .. }
            | Self::Capabilities {}
            | Self::List {}
            | Self::Plan { .. }
            | Self::Status { .. } => false,
            Self::DatabaseCreate { .. }
            | Self::DatabaseReconcile { .. }
            | Self::Register { .. }
            | Self::Environment { .. }
            | Self::Restart { .. }
            | Self::Metadata { .. }
            | Self::ProxyApply { .. }
            | Self::ProxyRemove { .. }
            | Self::BackupRegister { .. }
            | Self::Deploy { .. } => true,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub protocol_version: u32,
    pub request_id: String,
    pub result: Outcome,
}

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum Outcome {
    PrivateFileReady { bytes: u64 },
    UploadReady { compressed_bytes: u64 },
    Success { data: Value },
    Error { error: CaisError },
}

impl Request {
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(CaisError::new(
                ErrorCode::IncompatibleVersion,
                "No common protocol version.",
            ));
        }
        if self.request_id.is_empty()
            || self.request_id.len() > 64
            || !self
                .request_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        {
            return Err(CaisError::new(
                ErrorCode::InvalidRequest,
                "Invalid request identifier.",
            ));
        }
        Ok(())
    }
}

pub fn send_hello(writer: &mut impl Write, hello: &Hello) -> Result<()> {
    writer.write_all(MAGIC).map_err(|_| transport())?;
    write_frame(writer, hello)
}

pub fn read_hello(reader: &mut impl Read) -> Result<Hello> {
    let mut magic = [0; 8];
    reader.read_exact(&mut magic).map_err(|_| transport())?;
    if &magic != MAGIC {
        return Err(CaisError::new(
            ErrorCode::Protocol,
            "Peer is not Cais or its stdout is polluted.",
        ));
    }
    let hello: Hello = read_frame(reader)?;
    if hello.execution_limits.as_ref().is_some_and(|limits| {
        !(1..=600).contains(&limits.upload_seconds)
            || !(10..=1800).contains(&limits.execution_seconds)
    }) {
        return Err(protocol());
    }
    if !hello.protocol_versions.contains(&PROTOCOL_VERSION) {
        return Err(CaisError::new(
            ErrorCode::IncompatibleVersion,
            "No common protocol version.",
        ));
    }
    Ok(hello)
}

pub fn write_frame<T: Serialize>(writer: &mut impl Write, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| protocol())?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(protocol());
    }
    writer
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .map_err(|_| transport())?;
    writer.write_all(&bytes).map_err(|_| transport())?;
    writer.flush().map_err(|_| transport())
}

pub fn read_frame<T: DeserializeOwned>(reader: &mut impl Read) -> Result<T> {
    let mut size = [0; 4];
    reader.read_exact(&mut size).map_err(|_| transport())?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > MAX_FRAME {
        return Err(protocol());
    }
    let mut bytes = vec![0; size];
    reader.read_exact(&mut bytes).map_err(|_| transport())?;
    cais_core::decode_json(&bytes).map_err(|_| protocol())
}

pub fn transport() -> CaisError {
    CaisError::new(
        ErrorCode::Transport,
        "Transport ended without a complete result.",
    )
}
pub fn protocol() -> CaisError {
    CaisError::new(
        ErrorCode::Protocol,
        "Invalid, oversized or unexpected protocol message.",
    )
}
