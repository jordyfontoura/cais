use cais_artifacts::*;
use cais_core::{ProjectConfig, decode_config};
use flate2::{Compression, GzBuilder};
use serde_json::json;
use std::{
    fs::{self, File},
    path::Path,
};
use tar::{Builder, EntryType, Header};

fn project() -> ProjectConfig {
    decode_config(
        &serde_json::to_vec(&json!({"schema_version":1,"project":"example",
        "artifact":{"directory":"dist","publish":["api","public"],"executables":["api"]},
        "app":{"kind":"http","runtime":"binary","entrypoint":"api","health":"/health"},
        "data":{"preserve":["uploads"],"backup":[]}}))
        .unwrap(),
    )
    .unwrap()
}

fn files(root: &Path) {
    fs::create_dir_all(root.join("dist/public")).unwrap();
    fs::write(root.join("dist/api"), b"synthetic Linux binary bytes").unwrap();
    fs::write(
        root.join("dist/public/index.html"),
        b"<!doctype html><p>fixture</p>",
    )
    .unwrap();
}

#[test]
fn packages_with_long_portable_paths_remain_accepted() {
    let root = tempfile::tempdir().unwrap();
    files(root.path());
    let long_name = format!("public/{}.txt", "a".repeat(110));
    fs::write(
        root.path().join("dist").join(&long_name),
        b"long path fixture",
    )
    .unwrap();
    let path = root.path().join("long.tar.gz");
    package(root.path(), &project(), &path, Limits::default()).unwrap();
    let destination = root.path().join("stage");
    stage(&path, &destination, &project(), Limits::default()).unwrap();
    assert_eq!(
        fs::read(destination.join(long_name)).unwrap(),
        b"long path fixture"
    );
}

#[test]
fn malformed_compression_is_an_invalid_artifact_not_an_internal_failure() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("bad.tar.gz");
    fs::write(&archive, b"x").unwrap();
    let error = stage(
        &archive,
        &root.path().join("stage"),
        &project(),
        Limits::default(),
    )
    .unwrap_err();
    assert_eq!(error.code, cais_core::ErrorCode::InvalidConfig);
}

#[test]
fn extension_paths_are_validated_before_activation() {
    let root = tempfile::tempdir().unwrap();
    let archive_path = root.path().join("gnu.tar.gz");
    let gzip = GzBuilder::new()
        .mtime(0)
        .write(File::create(&archive_path).unwrap(), Compression::default());
    let mut archive = Builder::new(gzip);
    let mut header = Header::new_gnu();
    header.set_path("././@LongLink").unwrap();
    header.set_entry_type(EntryType::GNULongName);
    header.set_size(7);
    header.set_cksum();
    archive.append(&header, &b"../bad\0"[..]).unwrap();
    let mut directory = Header::new_gnu();
    directory.set_path("ignored").unwrap();
    directory.set_entry_type(EntryType::Directory);
    directory.set_size(0);
    directory.set_cksum();
    archive.append(&directory, std::io::empty()).unwrap();
    archive.into_inner().unwrap().finish().unwrap();
    let config: ProjectConfig = decode_config(br#"{"schema_version":1,"project":"example","artifact":{"directory":"dist","publish":["public"]},"app":{"kind":"static","public":"public"}}"#).unwrap();
    assert_eq!(
        stage(
            &archive_path,
            &root.path().join("stage"),
            &config,
            Limits::default()
        )
        .unwrap_err()
        .code,
        cais_core::ErrorCode::InvalidConfig
    );
}

#[test]
fn declared_long_name_payload_is_bounded_before_reading_it() {
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("oversized-name.tar.gz");
    let mut gzip = GzBuilder::new()
        .mtime(0)
        .write(File::create(&path).unwrap(), Compression::default());
    let mut header = Header::new_gnu();
    header.set_path("././@LongLink").unwrap();
    header.set_entry_type(EntryType::GNULongName);
    header.set_size(2 * 1024 * 1024);
    header.set_cksum();
    gzip.write_all(header.as_bytes()).unwrap();
    gzip.finish().unwrap();
    assert_eq!(
        stage(
            &path,
            &root.path().join("stage"),
            &project(),
            Limits::default()
        )
        .unwrap_err()
        .code,
        cais_core::ErrorCode::InvalidConfig
    );
}

#[test]
fn gnu_name_boundaries_and_incomplete_sequences_are_checked() {
    let root = tempfile::tempdir().unwrap();
    let config: ProjectConfig = decode_config(br#"{"schema_version":1,"project":"example","artifact":{"directory":"dist","publish":["public"]},"app":{"kind":"static","public":"public"}}"#).unwrap();
    for (index, name, repeats, finish, accepted) in [
        (0, format!("public/{}", "a".repeat(233)), 1, true, true),
        (1, format!("public/{}", "a".repeat(234)), 1, true, false),
        (2, ".".into(), 1, true, false),
        (3, "..".into(), 1, true, false),
        (4, "public/file".into(), 2, true, false),
        (5, "public/file".into(), 1, false, false),
    ] {
        let path = root.path().join(format!("boundary-{index}.tar.gz"));
        let gzip = GzBuilder::new()
            .mtime(0)
            .write(File::create(&path).unwrap(), Compression::default());
        let mut tar = Builder::new(gzip);
        let mut directory = Header::new_gnu();
        directory.set_entry_type(EntryType::Directory);
        directory.set_size(0);
        directory.set_mode(0o755);
        tar.append_data(&mut directory, "public", std::io::empty())
            .unwrap();
        for _ in 0..repeats {
            let bytes = [name.as_bytes(), &[0]].concat();
            let mut header = Header::new_gnu();
            header.set_path("././@LongLink").unwrap();
            header.set_entry_type(EntryType::GNULongName);
            header.set_size(bytes.len() as u64);
            header.set_cksum();
            tar.append(&header, &bytes[..]).unwrap();
        }
        if finish {
            let mut header = Header::new_gnu();
            header.set_path("ignored").unwrap();
            header.set_size(0);
            header.set_cksum();
            tar.append(&header, std::io::empty()).unwrap();
        }
        tar.into_inner().unwrap().finish().unwrap();
        assert_eq!(
            stage(
                &path,
                &root.path().join(format!("stage-{index}")),
                &config,
                Limits::default()
            )
            .is_ok(),
            accepted,
            "boundary case {index}"
        );
    }
}

#[test]
fn deterministic_package_and_unprivileged_stage_preserve_bytes_and_explicit_modes() {
    let root = tempfile::tempdir().unwrap();
    files(root.path());
    let config = project();
    let first = root.path().join("first.tar.gz");
    let second = root.path().join("second.tar.gz");
    let a = package(root.path(), &config, &first, Limits::default()).unwrap();
    File::options()
        .write(true)
        .open(root.path().join("dist/api"))
        .unwrap()
        .set_modified(std::time::SystemTime::now())
        .unwrap();
    let b = package(root.path(), &config, &second, Limits::default()).unwrap();
    assert_eq!(a.sha256, b.sha256);
    assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
    let stage_dir = root.path().join("stage");
    let staged = stage(&first, &stage_dir, &config, Limits::default()).unwrap();
    // The fixture contains two regular files and their public directory.
    assert_eq!(staged.sha256, a.sha256);
    assert_eq!(staged.entries, 3);
    assert_eq!(
        fs::read(stage_dir.join("api")).unwrap(),
        fs::read(root.path().join("dist/api")).unwrap()
    );
    assert!(!stage_dir.join("uploads").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(stage_dir.join("api"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o750
        );
        assert_eq!(
            fs::metadata(stage_dir.join("public/index.html"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        assert_eq!(
            fs::metadata(&stage_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}

#[test]
fn refuses_secrets_collisions_missing_inputs_and_existing_outputs() {
    let root = tempfile::tempdir().unwrap();
    files(root.path());
    let config = project();
    fs::write(
        root.path().join("dist/public/.env.local"),
        b"synthetic-canary",
    )
    .unwrap();
    let output = root.path().join("bundle.tar.gz");
    assert!(package(root.path(), &config, &output, Limits::default()).is_err());
    assert!(!output.exists());
    fs::remove_file(root.path().join("dist/public/.env.local")).unwrap();
    assert!(
        package(
            root.path(),
            &config,
            &root.path().join("dist/public/bundle.tar.gz"),
            Limits::default()
        )
        .is_err()
    );
    assert!(!root.path().join("dist/public/bundle.tar.gz").exists());
    fs::write(&output, b"original").unwrap();
    assert!(package(root.path(), &config, &output, Limits::default()).is_err());
    assert_eq!(fs::read(&output).unwrap(), b"original");
    let mut config = project();
    config.artifact.publish.push("Public".into());
    fs::create_dir_all(root.path().join("dist/Public")).unwrap();
    assert!(
        package(
            root.path(),
            &config,
            &root.path().join("collision.tar.gz"),
            Limits::default()
        )
        .is_err()
    );
}

fn malicious_archive(output: &Path, entries: &[(&str, EntryType)]) {
    let gzip = GzBuilder::new()
        .mtime(0)
        .write(File::create(output).unwrap(), Compression::default());
    let mut archive = Builder::new(gzip);
    for (name, kind) in entries {
        let mut header = Header::new_gnu();
        header.set_mode(0o777);
        header.set_uid(0);
        header.set_gid(0);
        header.set_entry_type(*kind);
        header.set_size(0);
        let bytes = header.as_mut_bytes();
        bytes[..100].fill(0);
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        header.set_cksum();
        archive.append(&header, std::io::empty()).unwrap();
    }
    archive.into_inner().unwrap().finish().unwrap();
}

#[test]
fn receiver_rejects_traversal_links_special_files_duplicate_names_and_preserved_paths() {
    let root = tempfile::tempdir().unwrap();
    let config = project();
    for (index, (name, kind)) in [
        ("../escape", EntryType::Regular),
        ("/etc/example", EntryType::Regular),
        ("uploads/file", EntryType::Regular),
        ("public/.env", EntryType::Regular),
        ("public/link", EntryType::Symlink),
        ("public/link", EntryType::Link),
        ("public/fifo", EntryType::Fifo),
        ("public/NUL", EntryType::Regular),
        ("public/pax", EntryType::XHeader),
        ("public/sparse", EntryType::GNUSparse),
        ("public/file\\name", EntryType::Regular),
    ]
    .into_iter()
    .enumerate()
    {
        let archive = root.path().join(format!("attack{index}.tar.gz"));
        malicious_archive(&archive, &[(name, kind)]);
        assert!(
            stage(
                &archive,
                &root.path().join(format!("stage{index}")),
                &config,
                Limits::default()
            )
            .is_err()
        );
        assert!(!root.path().join("escape").exists());
    }
    let archive = root.path().join("duplicates.tar.gz");
    malicious_archive(
        &archive,
        &[
            ("public", EntryType::Directory),
            ("public/A", EntryType::Regular),
            ("public/a", EntryType::Regular),
        ],
    );
    assert!(
        stage(
            &archive,
            &root.path().join("duplicates-stage"),
            &config,
            Limits::default()
        )
        .is_err()
    );
}

#[test]
fn enforces_expansion_and_entry_limits_before_activation() {
    let root = tempfile::tempdir().unwrap();
    files(root.path());
    let config = project();
    let archive = root.path().join("valid.tar.gz");
    package(root.path(), &config, &archive, Limits::default()).unwrap();
    for (index, limits) in [
        Limits {
            expanded_bytes: 1,
            ..Limits::default()
        },
        Limits {
            entries: 1,
            ..Limits::default()
        },
        Limits {
            compressed_bytes: 1,
            ..Limits::default()
        },
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            stage(
                &archive,
                &root.path().join(format!("stage{index}")),
                &config,
                limits
            )
            .is_err()
        );
        assert!(
            package(
                root.path(),
                &config,
                &root.path().join(format!("invalid{index}.tar.gz")),
                limits
            )
            .is_err()
        );
    }
}

#[cfg(unix)]
#[test]
fn refuses_source_symlinks() {
    let root = tempfile::tempdir().unwrap();
    files(root.path());
    let config = project();
    std::os::unix::fs::symlink("/etc/passwd", root.path().join("dist/public/link")).unwrap();
    assert!(
        package(
            root.path(),
            &config,
            &root.path().join("invalid.tar.gz"),
            Limits::default()
        )
        .is_err()
    );
}
