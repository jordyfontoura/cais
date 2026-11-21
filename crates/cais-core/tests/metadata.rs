use cais_core::{ProjectMetadata, ServerConfig, decode_config};
use serde_json::{Value, json};

fn accepted(value: Value) -> bool {
    decode_config::<ProjectMetadata>(&serde_json::to_vec(&value).unwrap()).is_ok()
}

fn with(field: &str, value: Value) -> Value {
    let mut metadata = json!({"schema_version":1,"title":"Example"});
    metadata[field] = value;
    metadata
}

#[test]
fn metadata_is_presentation_only() {
    assert!(accepted(json!({"schema_version":1,"title":"Example"})));
    assert!(accepted(json!({
        "$schema":"../schemas/metadata.schema.json","schema_version":1,"title":"Example",
        "description":"Short text.","url":"https://app.example.org/docs/",
        "labels":{"dashboard":true,"tier":"internal"}
    })));
    for field in ["unit", "path", "command", "directory", "env"] {
        assert!(!accepted(with(field, json!("x"))), "accepted {field}");
    }
    assert!(!accepted(json!({"schema_version":2,"title":"Example"})));
}

#[test]
fn text_is_bounded_and_free_of_control_characters() {
    for title in ["", " ", " padded", "line\nbreak", "tab\there"] {
        assert!(!accepted(with("title", json!(title))), "accepted {title:?}");
    }
    assert!(accepted(with("title", json!("a".repeat(80)))));
    assert!(!accepted(with("title", json!("a".repeat(81)))));
    assert!(!accepted(with("description", json!("a".repeat(281)))));
}

#[test]
fn address_is_plain_https_on_a_hostname() {
    for url in [
        "https://app.example.org",
        "https://app.example.org/",
        "https://app.example.org/a/b-c_d.html",
    ] {
        assert!(accepted(with("url", json!(url))), "rejected {url}");
    }
    for url in [
        "http://app.example.org/",
        "https://user:secret@app.example.org/",
        "https://app.example.org:8443/",
        "https://app.example.org/?token=1",
        "https://app.example.org/#fragment",
        "https://app.example.org/../admin",
        "https://localhost/",
        "https://APP.example.org/",
        "javascript:alert(1)",
        "//app.example.org/",
    ] {
        assert!(!accepted(with("url", json!(url))), "accepted {url}");
    }
    let metadata: ProjectMetadata = decode_config(
        &serde_json::to_vec(&with("url", json!("https://app.example.org/docs"))).unwrap(),
    )
    .unwrap();
    assert_eq!(metadata.url_host(), Some("app.example.org"));
}

#[test]
fn labels_are_bounded_flags_or_short_text() {
    assert!(accepted(with("labels", json!({"a":false,"b-2":"text"}))));
    for labels in [
        json!({"Upper":true}),
        json!({"a":1}),
        json!({"a":["x"]}),
        json!({"a":{"nested":true}}),
        json!({"a":"line\nbreak"}),
        json!({"a":"x".repeat(121)}),
    ] {
        assert!(
            !accepted(with("labels", labels.clone())),
            "accepted {labels}"
        );
    }
    let many: serde_json::Map<String, Value> = (0..17)
        .map(|i| (format!("label-{i}"), json!(true)))
        .collect();
    assert!(!accepted(with("labels", Value::Object(many))));
}

#[test]
fn catalog_settings_use_a_dedicated_directory_and_a_group_name() {
    let native = |catalog: Value| {
        let value = json!({"schema_version":1,"projects":{},"host":{"paths":{
            "apps":"/srv/cais-apps","state":"/var/lib/cais","config":"/etc/cais-apps"},
            "catalog":catalog}});
        decode_config::<ServerConfig>(&serde_json::to_vec(&value).unwrap()).is_ok()
    };
    assert!(native(json!({})));
    assert!(native(json!({"group":"dashboards"})));
    assert!(!native(json!({"directory":"/var/lib/cais/catalog"})));
    assert!(!native(json!({"directory":"relative"})));
    assert!(!native(json!({"group":"bad group"})));
    assert!(!native(json!({"path":"/tmp/x"})));
}
