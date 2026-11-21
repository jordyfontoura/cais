use serde_json::{Value, json};
use std::{fs, process::Command};

#[test]
fn packages_from_the_project_directory_and_never_overwrites_output() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir_all(root.path().join("dist/public")).unwrap();
    fs::write(root.path().join("dist/public/index.html"), b"fixture").unwrap();
    let config = root.path().join("cais.json");
    fs::write(&config, serde_json::to_vec(&json!({"schema_version":1,"project":"website",
        "artifact":{"directory":"dist","publish":["public"]}, "app":{"kind":"static","public":"public"}})).unwrap()).unwrap();
    let output = root.path().join("application.tar.gz");
    let result = Command::new(env!("CARGO_BIN_EXE_cais"))
        .args(["package", "--file"])
        .arg(&config)
        .arg("--output")
        .arg(&output)
        .arg("--json")
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(result.stderr.is_empty());
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["outcome"], "success");
    assert_eq!(value["data"]["entries"], 2);
    let original = fs::read(&output).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_cais"))
        .args(["package", "--file"])
        .arg(&config)
        .arg("--output")
        .arg(&output)
        .arg("--json")
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert_eq!(fs::read(&output).unwrap(), original);
}
