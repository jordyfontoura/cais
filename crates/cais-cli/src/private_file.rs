use cais_core::{CaisError, ErrorCode, Result};
use std::{fs, path::Path};

pub fn create(directory: &Path) -> Result<tempfile::NamedTempFile> {
    let parent = directory
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent).map_err(|_| failure())?;
    for ancestor in parent.ancestors() {
        if ancestor.join(".git").exists() {
            return Err(CaisError::new(
                ErrorCode::InvalidConfig,
                "Export credentials outside a Git worktree.",
            ));
        }
    }
    // A new directory avoids changing permissions on any preexisting user folder.
    #[allow(unused_mut)] // DirBuilderExt::mode is Unix-only.
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(directory).map_err(|_| {
        CaisError::new(
            ErrorCode::Conflict,
            "Private export requires a new directory with an existing parent.",
        )
    })?;
    protect(directory, true)?;
    let file = tempfile::NamedTempFile::new_in(directory).map_err(|_| failure())?;
    protect(file.path(), false)?;
    Ok(file)
}

#[cfg(unix)]
fn protect(path: &Path, directory: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if directory { 0o700 } else { 0o600 }),
    )
    .map_err(|_| failure())
}
#[cfg(windows)]
fn protect(path: &Path, _directory: bool) -> Result<()> {
    use std::process::{Command, Stdio};
    let system = std::env::var_os("SystemRoot").ok_or_else(failure)?;
    let system = std::path::PathBuf::from(system).join("System32");
    let who = Command::new(system.join("whoami.exe"))
        .args(["/user", "/fo", "csv", "/nh"])
        .stderr(Stdio::null())
        .output()
        .map_err(|_| failure())?;
    if !who.status.success() {
        return Err(failure());
    }
    let text = String::from_utf8_lossy(&who.stdout);
    let sid = text
        .trim()
        .split(',')
        .next_back()
        .unwrap_or("")
        .trim_matches('"');
    if !sid.starts_with("S-1-")
        || !sid
            .bytes()
            .all(|b| b.is_ascii_digit() || b"S-".contains(&b))
    {
        return Err(failure());
    }
    // tempfile may create explicit SYSTEM/logon-session ACEs. Removing inheritance
    // alone preserves those, so first reset this newly-created empty object.
    let reset = Command::new(system.join("icacls.exe"))
        .arg(path)
        .arg("/reset")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| failure())?;
    if !reset.success() {
        return Err(failure());
    }
    let result = Command::new(system.join("icacls.exe"))
        .arg(path)
        .args(["/inheritance:r", "/grant:r", &format!("*{sid}:(F)")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| failure())?;
    if result.success() {
        Ok(())
    } else {
        Err(failure())
    }
}
fn failure() -> CaisError {
    CaisError::new(
        ErrorCode::Internal,
        "Cannot protect private export permissions.",
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn export_directory_is_new_and_file_has_private_permissions() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("export");
        let file = super::create(&directory).unwrap();
        assert!(super::create(&directory).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                directory.metadata().unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                file.as_file().metadata().unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        #[cfg(windows)]
        {
            let system = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
                .join("System32/WindowsPowerShell/v1.0/powershell.exe");
            let script = "$a=[IO.File]::GetAccessControl($env:CAIS_ACL_TEST_PATH); $sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; $r=@($a.Access); if(-not $a.AreAccessRulesProtected -or $r.Count -ne 1 -or $r[0].IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -ne $sid){exit 1}";
            let result = std::process::Command::new(system)
                .args(["-NoProfile", "-Command", script])
                .env("CAIS_ACL_TEST_PATH", file.path())
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "Export DACL must contain only its owner"
            );
            let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/windows/private_acl.ps1");
            let result = std::process::Command::new(
                std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
                    .join("System32/WindowsPowerShell/v1.0/powershell.exe"),
            )
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(script)
            .env("CAIS_ACL_TEST_PATH", file.path())
            .output()
            .unwrap();
            assert!(
                result.status.success(),
                "Private export must deny a restricted token with its owner SID disabled"
            );
        }
    }
}
