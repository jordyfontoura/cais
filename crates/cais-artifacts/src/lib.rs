//! Deterministic packages and strict extraction into private, inactive staging.
use cais_core::{CaisError, ErrorCode, ProjectConfig, Result, Validate, overlaps};
use flate2::{Compression, GzBuilder, read::GzDecoder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use tar::{Archive, Builder, Header};

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub compressed_bytes: u64,
    pub expanded_bytes: u64,
    pub entries: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            compressed_bytes: 128 * 1024 * 1024,
            expanded_bytes: 512 * 1024 * 1024,
            entries: 50_000,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Descriptor {
    pub sha256: String,
    pub compressed_bytes: u64,
    pub expanded_bytes: u64,
    pub entries: usize,
}

fn invalid() -> CaisError {
    CaisError::new(
        ErrorCode::InvalidConfig,
        "Artifact is invalid, exceeds limits, or conflicts with publication policy.",
    )
}
fn io_error(_: std::io::Error) -> CaisError {
    CaisError::new(ErrorCode::Internal, "Artifact I/O failed.")
}

fn portable(path: &str) -> bool {
    cais_core::artifact_path(path)
}

fn included(name: &str, config: &ProjectConfig) -> bool {
    config
        .artifact
        .publish
        .iter()
        .any(|root| name == root || name.strip_prefix(root).is_some_and(|s| s.starts_with('/')))
}

fn allowed(name: &str, config: &ProjectConfig) -> bool {
    portable(name)
        && included(name, config)
        && !config
            .data
            .preserve
            .iter()
            .any(|p| overlaps(&name.to_ascii_lowercase(), &p.to_ascii_lowercase()))
}

fn regular_metadata(path: &Path) -> Result<fs::Metadata> {
    let meta = fs::symlink_metadata(path).map_err(io_error)?;
    if meta.file_type().is_symlink() || (!meta.is_file() && !meta.is_dir()) {
        return Err(invalid());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(invalid());
        }
    }
    Ok(meta)
}

fn collect(
    base: &Path,
    name: &str,
    config: &ProjectConfig,
    files: &mut BTreeMap<String, PathBuf>,
    limits: Limits,
    expanded: &mut u64,
) -> Result<()> {
    if !allowed(name, config) || files.len() >= limits.entries {
        return Err(invalid());
    }
    let path = base.join(name);
    let meta = regular_metadata(&path)?;
    if meta.is_file() {
        *expanded = expanded.checked_add(meta.len()).ok_or_else(invalid)?;
        if *expanded > limits.expanded_bytes {
            return Err(invalid());
        }
    }
    if files.insert(name.to_owned(), path.clone()).is_some() {
        return Err(invalid());
    }
    if meta.is_dir() {
        let mut children: Vec<_> = fs::read_dir(&path)
            .map_err(io_error)?
            .collect::<std::io::Result<_>>()
            .map_err(io_error)?;
        children.sort_by_key(|item| item.file_name());
        for child in children {
            let filename = child.file_name().into_string().map_err(|_| invalid())?;
            collect(
                base,
                &format!("{name}/{filename}"),
                config,
                files,
                limits,
                expanded,
            )?;
        }
    }
    Ok(())
}

/// Creates a new deterministic tar.gz, never overwriting an existing output file.
pub fn package(
    project_root: &Path,
    config: &ProjectConfig,
    output: &Path,
    limits: Limits,
) -> Result<Descriptor> {
    config.validate()?;
    let directory = config
        .artifact
        .directory
        .strip_prefix("./")
        .unwrap_or(&config.artifact.directory);
    let mut base = project_root.to_owned();
    for component in directory.split('/') {
        base.push(component);
        if !regular_metadata(&base)?.is_dir() {
            return Err(invalid());
        }
    }
    let mut files = BTreeMap::new();
    let mut expanded = 0;
    for name in &config.artifact.publish {
        let mut parent = base.clone();
        for component in name.split('/') {
            parent.push(component);
            regular_metadata(&parent)?;
        }
        collect(&base, name, config, &mut files, limits, &mut expanded)?;
    }
    let mut unique = BTreeSet::new();
    if !files
        .keys()
        .all(|name| unique.insert(name.to_ascii_lowercase()))
    {
        return Err(invalid());
    }
    for executable in &config.artifact.executables {
        if !files.get(executable).is_some_and(|path| path.is_file()) {
            return Err(invalid());
        }
    }
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let output_path = parent
        .canonicalize()
        .map_err(io_error)?
        .join(output.file_name().ok_or_else(invalid)?);
    for path in files.values() {
        let canonical = path.canonicalize().map_err(io_error)?;
        if output_path == canonical || (path.is_dir() && output_path.starts_with(&canonical)) {
            return Err(invalid());
        }
    }
    let output_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(io_error)?;
    let result = (|| {
        let writer = BoundedWriter {
            inner: output_file,
            size: 0,
            limit: limits.compressed_bytes,
        };
        let gzip = GzBuilder::new()
            .mtime(0)
            .operating_system(255)
            .write(writer, Compression::default());
        let mut archive = Builder::new(gzip);
        for (name, path) in &files {
            let meta = regular_metadata(path)?;
            let mut header = Header::new_gnu();
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_mode(
                if meta.is_dir() || config.artifact.executables.contains(name) {
                    0o755
                } else {
                    0o644
                },
            );
            header.set_entry_type(if meta.is_dir() {
                tar::EntryType::Directory
            } else {
                tar::EntryType::Regular
            });
            header.set_size(if meta.is_file() { meta.len() } else { 0 });
            header.set_cksum();
            if meta.is_file() {
                archive
                    .append_data(&mut header, name, File::open(path).map_err(io_error)?)
                    .map_err(io_error)?;
            } else {
                archive
                    .append_data(&mut header, name, std::io::empty())
                    .map_err(io_error)?;
            }
        }
        archive
            .into_inner()
            .map_err(io_error)?
            .finish()
            .map_err(io_error)?
            .inner
            .sync_all()
            .map_err(io_error)?;
        let size = fs::metadata(output).map_err(io_error)?.len();
        let mut hash = Sha256::new();
        std::io::copy(&mut File::open(output).map_err(io_error)?, &mut hash).map_err(io_error)?;
        Ok(Descriptor {
            sha256: format!("{:x}", hash.finalize()),
            compressed_bytes: size,
            expanded_bytes: expanded,
            entries: files.len(),
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(output);
    }
    result
}

struct BoundedWriter<W> {
    inner: W,
    size: u64,
    limit: u64,
}
impl<W: Write> Write for BoundedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.size.saturating_add(bytes.len() as u64) > self.limit {
            return Err(std::io::Error::other("Compressed artifact exceeds limit"));
        }
        let count = self.inner.write(bytes)?;
        self.size += count as u64;
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Extracts into a newly created, empty staging directory controlled by the installer.
/// The directory is not a live release. A failed extraction must never be activated.
pub fn stage(
    archive_path: &Path,
    stage_path: &Path,
    config: &ProjectConfig,
    limits: Limits,
) -> Result<Descriptor> {
    stage_before(archive_path, stage_path, config, limits, None)
}

pub fn stage_before(
    archive_path: &Path,
    stage_path: &Path,
    config: &ProjectConfig,
    limits: Limits,
    deadline: Option<std::time::Instant>,
) -> Result<Descriptor> {
    config.validate()?;
    let metadata = regular_metadata(archive_path)?;
    if !metadata.is_file() {
        return Err(invalid());
    }
    let size = metadata.len();
    if size == 0 || size > limits.compressed_bytes {
        return Err(invalid());
    }
    fs::create_dir(stage_path).map_err(io_error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(stage_path, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    }
    let result = (|| {
        let input = File::open(archive_path).map_err(io_error)?;
        let mut archive = Archive::new(GzDecoder::new(input));
        let mut expanded = 0u64;
        let mut seen = BTreeSet::new();
        let mut members = BTreeSet::new();
        let mut long_name = None;
        // Raw iteration prevents tar from allocating unbounded extension payloads.
        for entry in archive.entries().map_err(|_| invalid())?.raw(true) {
            check_deadline(deadline)?;
            let mut entry = entry.map_err(|_| invalid())?;
            let kind = entry.header().entry_type();
            if kind.is_gnu_longname() {
                if long_name.is_some()
                    || entry.header().as_gnu().is_none()
                    || !(1..=241).contains(&entry.size())
                {
                    return Err(invalid());
                }
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes).map_err(|_| invalid())?;
                if bytes.pop() != Some(0) {
                    return Err(invalid());
                }
                let name = String::from_utf8(bytes).map_err(|_| invalid())?;
                if !allowed(&name, config) {
                    return Err(invalid());
                }
                long_name = Some(name);
                continue;
            }
            let name = match long_name.take() {
                Some(name) => name,
                None => std::str::from_utf8(&entry.path_bytes())
                    .map_err(|_| invalid())?
                    .to_owned(),
            };
            if !allowed(&name, config)
                || seen.len() >= limits.entries
                || !seen.insert(name.to_ascii_lowercase())
                || (!kind.is_file() && !kind.is_dir())
            {
                return Err(invalid());
            }
            expanded = expanded.checked_add(entry.size()).ok_or_else(invalid)?;
            if expanded > limits.expanded_bytes || (kind.is_dir() && entry.size() != 0) {
                return Err(invalid());
            }
            let target = stage_path.join(&name);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(io_error)?;
            }
            if kind.is_dir() {
                if target.exists() && !target.is_dir() {
                    return Err(invalid());
                }
                fs::create_dir_all(&target).map_err(io_error)?;
            } else {
                let mut output = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&target)
                    .map_err(io_error)?;
                let mut copied = 0;
                let mut buffer = [0; 65536];
                loop {
                    check_deadline(deadline)?;
                    let count = entry.read(&mut buffer).map_err(|_| invalid())?;
                    if count == 0 {
                        break;
                    }
                    output.write_all(&buffer[..count]).map_err(io_error)?;
                    copied += count as u64;
                }
                if copied != entry.size() {
                    return Err(invalid());
                }
                output.sync_all().map_err(io_error)?;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(
                    &target,
                    fs::Permissions::from_mode(
                        if kind.is_dir() || config.artifact.executables.contains(&name) {
                            0o750
                        } else {
                            0o640
                        },
                    ),
                )
                .map_err(io_error)?;
            }
            members.insert(name);
        }
        if long_name.is_some()
            || !config
                .artifact
                .publish
                .iter()
                .all(|root| members.contains(root))
            || !config
                .artifact
                .executables
                .iter()
                .all(|name| stage_path.join(name).is_file())
        {
            return Err(invalid());
        }
        let mut hash = Sha256::new();
        std::io::copy(&mut File::open(archive_path).map_err(io_error)?, &mut hash)
            .map_err(io_error)?;
        Ok(Descriptor {
            sha256: format!("{:x}", hash.finalize()),
            compressed_bytes: size,
            expanded_bytes: expanded,
            entries: seen.len(),
        })
    })();
    // A failed staging directory stays private and unactivated for explicit cleanup.
    result
}

fn check_deadline(deadline: Option<std::time::Instant>) -> Result<()> {
    if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
        Err(CaisError::new(
            ErrorCode::Timeout,
            "Artifact staging exceeded the execution budget.",
        ))
    } else {
        Ok(())
    }
}
