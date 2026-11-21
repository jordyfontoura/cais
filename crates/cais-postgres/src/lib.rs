//! PostgreSQL credential primitives. No generic SQL, SSH or shell API.
//! Administrative provisioning is not wired into capabilities until verified.
use base64::{Engine, engine::general_purpose::STANDARD};
use cais_core::{CaisError, ErrorCode, PostgresSettings, Result, Validate};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Intentionally has no Debug/Serialize/Display: ordinary JSON results must not contain it.
pub struct Credentials {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateFile {
    schema_version: cais_core::SchemaVersion,
    host: String,
    port: u16,
    database: String,
    username: String,
    password: String,
}

impl Credentials {
    pub fn generate(project: &str, settings: &PostgresSettings) -> Result<Self> {
        settings.validate()?;
        if !cais_core::identifier(project) {
            return Err(invalid());
        }
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| internal())?;
        let password: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let digest = format!("{:x}", Sha256::digest(project.as_bytes()));
        let name = format!("{}{}", settings.role_prefix, &digest[..12]);
        Ok(Self {
            host: "127.0.0.1".into(),
            port: settings.port,
            database: name.clone(),
            username: name,
            password,
        })
    }

    /// Only for writing a private file or the explicit bounded private-file transfer phase.
    pub fn encode_private_file(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&PrivateFile {
            schema_version: cais_core::SchemaVersion,
            host: self.host.clone(),
            port: self.port,
            database: self.database.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
        })
        .map_err(|_| internal())
    }

    pub fn decode_private_file(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > cais_core::CONFIG_LIMIT {
            return Err(invalid());
        }
        let file: PrivateFile = cais_core::decode_json(bytes).map_err(|_| invalid())?;
        if !matches!(file.host.as_str(), "127.0.0.1" | "::1")
            || file.port == 0
            || !cais_core::postgres_identifier(&file.database)
            || !cais_core::postgres_identifier(&file.username)
            || file.password.is_empty()
            || file.password.len() > 1024
            || file.password.chars().any(char::is_control)
        {
            return Err(invalid());
        }
        Ok(Self {
            host: file.host,
            port: file.port,
            database: file.database,
            username: file.username,
            password: file.password,
        })
    }

    pub fn scram_verifier(&self) -> Result<String> {
        let mut salt = [0; 16];
        getrandom::fill(&mut salt).map_err(|_| internal())?;
        let mut salted = [0; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(self.password.as_bytes(), &salt, 4096, &mut salted);
        let mut client = Hmac::<Sha256>::new_from_slice(&salted).map_err(|_| internal())?;
        client.update(b"Client Key");
        let stored = Sha256::digest(client.finalize().into_bytes());
        let mut server = Hmac::<Sha256>::new_from_slice(&salted).map_err(|_| internal())?;
        server.update(b"Server Key");
        Ok(format!(
            "SCRAM-SHA-256$4096:{}${}:{}",
            STANDARD.encode(salt),
            STANDARD.encode(stored),
            STANDARD.encode(server.finalize().into_bytes())
        ))
    }

    /// Passing a password to a child environment is explicit; never put it in argv/logs.
    pub fn password_for_child(&self) -> &str {
        &self.password
    }
}

fn invalid() -> CaisError {
    CaisError::new(
        ErrorCode::InvalidConfig,
        "Invalid private PostgreSQL credential file.",
    )
}
fn internal() -> CaisError {
    CaisError::new(
        ErrorCode::Internal,
        "PostgreSQL credentials could not be prepared.",
    )
}
