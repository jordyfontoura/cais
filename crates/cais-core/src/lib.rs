//! Portable Cais configuration and policy. No commands or network I/O.
mod config;
mod host;
mod metadata;
mod planning;

pub use config::*;
pub use host::*;
pub use metadata::*;
pub use planning::*;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const CONFIG_LIMIT: usize = 65_536;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Busy,
    Conflict,
    OperationFailed,
    UnknownOutcome,
    InvalidConfig,
    InvalidRequest,
    IncompatibleVersion,
    NotAuthorized,
    PolicyDenied,
    Unsupported,
    Transport,
    Timeout,
    Protocol,
    Internal,
}
impl ErrorCode {
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Internal => 1,
            Self::InvalidConfig | Self::InvalidRequest => 2,
            Self::NotAuthorized | Self::PolicyDenied => 3,
            Self::IncompatibleVersion | Self::Unsupported => 4,
            Self::Transport | Self::Timeout | Self::Protocol => 5,
            Self::Busy | Self::Conflict => 6,
            Self::OperationFailed => 7,
            Self::UnknownOutcome => 8,
        }
    }
    pub fn from_exit_code(code: i32) -> Option<Self> {
        Some(match code {
            1 => Self::Internal,
            2 => Self::InvalidConfig,
            3 => Self::NotAuthorized,
            4 => Self::Unsupported,
            5 => Self::Transport,
            6 => Self::Conflict,
            7 => Self::OperationFailed,
            8 => Self::UnknownOutcome,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaisError {
    pub code: ErrorCode,
    pub message: String,
    /// JSON Pointer paths and fixed diagnostics only; never input values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issues: Vec<Issue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Issue {
    pub path: String,
    pub message: String,
}

impl CaisError {
    pub fn new(code: ErrorCode, message: &str) -> Self {
        Self {
            code,
            message: message.into(),
            issues: Vec::new(),
        }
    }

    pub fn invalid(issues: Vec<Issue>) -> Self {
        Self {
            code: ErrorCode::InvalidConfig,
            message: "Configuration is invalid.".into(),
            issues,
        }
    }
}

impl std::fmt::Display for CaisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CaisError {}

pub type Result<T> = std::result::Result<T, CaisError>;

pub trait Validate {
    fn validate(&self) -> Result<()>;
}

pub fn decode_config<T: serde::de::DeserializeOwned + Validate>(bytes: &[u8]) -> Result<T> {
    if bytes.len() > CONFIG_LIMIT {
        return Err(CaisError::new(
            ErrorCode::InvalidConfig,
            "Configuration exceeds 64 KiB.",
        ));
    }
    // Do not forward serde errors: they can contain user-provided secrets.
    let value: T = decode_json(bytes).map_err(|_| {
        CaisError::new(
            ErrorCode::InvalidConfig,
            "Invalid configuration JSON, unknown field, or incorrect field type.",
        )
    })?;
    value.validate()?;
    Ok(value)
}

pub fn schema(kind: &str) -> Result<serde_json::Value> {
    let schema = match kind {
        "project" => schemars::schema_for!(ProjectConfig),
        "client" => schemars::schema_for!(ClientConfig),
        "server" => schemars::schema_for!(ServerConfig),
        "metadata" => schemars::schema_for!(ProjectMetadata),
        _ => {
            return Err(CaisError::new(
                ErrorCode::InvalidRequest,
                "Unknown schema kind.",
            ));
        }
    };
    serde_json::to_value(schema)
        .map_err(|_| CaisError::new(ErrorCode::Internal, "Schema generation failed."))
}

/// Strict JSON including nested map keys, which serde would otherwise overwrite.
pub fn decode_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let invalid = || {
        CaisError::new(
            ErrorCode::InvalidConfig,
            "Invalid JSON, duplicate or unknown field, or incorrect field type.",
        )
    };
    serde_json::from_slice::<UniqueKeys>(bytes).map_err(|_| invalid())?;
    serde_json::from_slice(bytes).map_err(|_| invalid())
}

struct UniqueKeys;
impl<'de> Deserialize<'de> for UniqueKeys {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueKeys;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("JSON without duplicate object keys")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> std::result::Result<UniqueKeys, M::Error> {
                let mut keys = std::collections::BTreeSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !keys.insert(key) {
                        return Err(serde::de::Error::custom("Duplicate JSON object key"));
                    }
                    map.next_value::<UniqueKeys>()?;
                }
                Ok(UniqueKeys)
            }
            fn visit_seq<S: serde::de::SeqAccess<'de>>(
                self,
                mut seq: S,
            ) -> std::result::Result<UniqueKeys, S::Error> {
                while seq.next_element::<UniqueKeys>()?.is_some() {}
                Ok(UniqueKeys)
            }
            fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<UniqueKeys, E> {
                Ok(UniqueKeys)
            }
            fn visit_bool<E: serde::de::Error>(
                self,
                _: bool,
            ) -> std::result::Result<UniqueKeys, E> {
                Ok(UniqueKeys)
            }
            fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<UniqueKeys, E> {
                Ok(UniqueKeys)
            }
            fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<UniqueKeys, E> {
                Ok(UniqueKeys)
            }
            fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<UniqueKeys, E> {
                Ok(UniqueKeys)
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<UniqueKeys, E> {
                Ok(UniqueKeys)
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

pub(crate) fn check(issues: &mut Vec<Issue>, ok: bool, path: &str, message: &str) {
    if !ok && issues.len() < 64 {
        issues.push(Issue {
            path: path.into(),
            message: message.into(),
        });
    }
}

pub(crate) fn finish(issues: Vec<Issue>) -> Result<()> {
    if issues.is_empty() {
        Ok(())
    } else {
        Err(CaisError::invalid(issues))
    }
}
