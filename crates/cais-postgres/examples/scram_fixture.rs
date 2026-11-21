//! Synthetic-only verifier fixture. Writes a new private file; never prints credentials.
#[cfg(unix)]
use cais_postgres::Credentials;
#[cfg(unix)]
use std::io::Write;

#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or("a private output path is required")?;
    let mut nonce = [0; 8];
    getrandom::fill(&mut nonce).map_err(|_| "entropy unavailable")?;
    let project = format!(
        "crypto-{}",
        nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let settings = cais_core::PostgresSettings {
        role_prefix: "cais_test_".into(),
        ..Default::default()
    };
    let credentials = Credentials::generate(&project, &settings)?;
    let private: serde_json::Value = serde_json::from_slice(&credentials.encode_private_file()?)?;
    let bytes = serde_json::to_vec(
        &serde_json::json!({"credentials":private,"verifier":credentials.scram_verifier()?}),
    )?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(unix)]
    {
        let mut file = options.open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        println!("Synthetic verifier fixture written privately.");
        Ok(())
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("Run the private credential fixture on Unix.");
    std::process::exit(1);
}
