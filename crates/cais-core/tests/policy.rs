use cais_core::*;
use serde_json::{Value, json};

fn project() -> Value {
    json!({"schema_version":1,"project":"example","artifact":{"directory":"./dist-linux","publish":["api","public"],"executables":["api"]},"app":{"kind":"http","runtime":"binary","entrypoint":"api","health":"/health"},"exposure":{"host":"api.example.org","path":"/","access_profile":"private"},"data":{"preserve":["uploads"],"backup":[]}})
}
fn policy() -> ServerConfig {
    decode_config(&serde_json::to_vec(&json!({"schema_version":1,"projects":{"example":{"operators":["alice"],"hosts":["api.example.org"],"access_profiles":["private"]}},"access_profiles":{"private":{"kind":"private","provider":"sso"}}})).unwrap()).unwrap()
}
fn decode(value: Value) -> Result<ProjectConfig> {
    decode_config(&serde_json::to_vec(&value).unwrap())
}

#[test]
fn external_references_reject_commands_credentials_and_name_collisions() {
    let mut value: Value =
        serde_json::from_str(include_str!("../../../examples/server-quickstart.json")).unwrap();
    value["external_projects"] = json!({"existing":{"operators":["alice"],"app":{"kind":"service","unit":"example.service"},"directory":"/srv/existing","databases":["existing_db"]}});
    let check = |v: &Value| decode_config::<ServerConfig>(&serde_json::to_vec(v).unwrap());
    assert!(check(&value).is_ok());
    for unit in ["--all.service", "../bad.service", "example.service;restart"] {
        let mut invalid = value.clone();
        invalid["external_projects"]["existing"]["app"]["unit"] = json!(unit);
        assert!(check(&invalid).is_err());
    }
    let mut invalid = value.clone();
    invalid["external_projects"]["existing"]["password"] = json!("not-a-real-secret");
    assert!(check(&invalid).is_err());
    let mut invalid = value.clone();
    invalid["projects"]["existing"] = json!({"operators":["alice"]});
    assert!(check(&invalid).is_err());
    let mut invalid = value.clone();
    invalid["external_projects"]["existing"]["app"] =
        json!({"kind":"static","unit":"example.service"});
    assert!(check(&invalid).is_err());
}

#[test]
fn preserve_paths_are_disjoint_and_portable_before_any_host_side_effect() {
    for paths in [
        json!(["data", "data"]),
        json!(["a", "a/b"]),
        json!(["Data", "data/cache"]),
        json!(["NUL"]),
        json!(["data."]),
    ] {
        let mut value = project();
        value["data"]["preserve"] = paths;
        assert!(
            decode(value).is_err(),
            "Invalid preserve paths must not reach registration"
        );
    }
    let mut value = project();
    value["artifact"]["publish"] = json!(["api", "public", "Public"]);
    assert!(decode(value).is_err());
}

#[test]
fn policy_checks_identity_host_profile_and_backup_independently() {
    let host = policy();
    let intent = decode(project()).unwrap();
    let plan = host.plan(intent.clone(), "alice").unwrap();
    assert!(plan.policy_checked);
    assert!(!plan.execution_supported);
    assert_eq!(host.visible_projects("alice"), ["example"]);
    assert!(host.visible_projects("mallory").is_empty());
    assert_eq!(
        host.plan(intent, "mallory").unwrap_err().code,
        ErrorCode::NotAuthorized
    );
    for pointer in ["/exposure/host", "/exposure/access_profile"] {
        let mut value = project();
        *value.pointer_mut(pointer).unwrap() = json!(if pointer.ends_with("host") {
            "other.example.org"
        } else {
            "public"
        });
        assert_eq!(
            host.plan(decode(value).unwrap(), "alice").unwrap_err().code,
            ErrorCode::PolicyDenied
        );
    }
    let mut value = project();
    value["data"]["backup"] = json!(["uploads"]);
    assert_eq!(
        host.plan(decode(value).unwrap(), "alice").unwrap_err().code,
        ErrorCode::PolicyDenied
    );
}

#[test]
fn rejects_paths_that_escape_publish_or_overwrite_preserved_data() {
    for path in [
        "../x",
        "/tmp/x",
        "C:/x",
        "public\\x",
        "public/.env",
        "public/.env.local",
        ".git",
        "public/*",
    ] {
        let mut value = project();
        value["artifact"]["publish"] = json!(["api", path]);
        assert!(
            decode(value).is_err(),
            "accepted reserved or nonliteral path"
        );
    }
    let mut value = project();
    value["data"]["preserve"] = json!(["public/uploads"]);
    assert!(decode(value).is_err());
    let mut value = project();
    value["artifact"]["executables"] = json!([]);
    assert!(decode(value).is_err());
}

#[test]
fn refuses_new_versions_unknown_fields_and_secret_echoes() {
    let mut value = project();
    value["schema_version"] = json!(99);
    assert!(decode(value).is_err());
    let mut value = project();
    value["secret-canary"] = json!("sensitive-canary-value");
    let error = decode(value).unwrap_err();
    let message = serde_json::to_string(&error).unwrap();
    assert!(!message.contains("secret-canary"));
    assert!(!message.contains("sensitive-canary-value"));
    assert!(decode_config::<ProjectConfig>(&vec![b' '; CONFIG_LIMIT + 1]).is_err());
}

#[test]
fn configuration_digest_is_stable_and_sensitive_to_intent() {
    let host = policy();
    let a = host.plan(decode(project()).unwrap(), "alice").unwrap();
    let b = host.plan(decode(project()).unwrap(), "alice").unwrap();
    assert_eq!(a.configuration_sha256, b.configuration_sha256);
    let mut editor_only = project();
    editor_only["$schema"] = json!("./elsewhere/project.schema.json");
    editor_only["artifact"]["directory"] = json!("dist-linux");
    let same = host.plan(decode(editor_only).unwrap(), "alice").unwrap();
    assert_eq!(a.configuration_sha256, same.configuration_sha256);
    let mut value = project();
    value["app"]["health"] = json!("/ready");
    let c = host.plan(decode(value).unwrap(), "alice").unwrap();
    assert_ne!(a.configuration_sha256, c.configuration_sha256);
}

#[test]
fn rejects_unsafe_ssh_commands_or_implicit_host_trust() {
    let base = json!({"schema_version":1,"targets":{"test":{"ssh":"operator@example.org","server_path":"/usr/local/bin/cais-server","known_hosts":"known_hosts"}}});
    assert!(decode_config::<ClientConfig>(&serde_json::to_vec(&base).unwrap()).is_ok());
    for (key, value) in [
        ("ssh", "-oProxyCommand=id"),
        ("ssh", "server;id"),
        ("server_path", "/bin/server;id"),
        ("server_path", "/tmp/../bin/server"),
        ("known_hosts", ""),
    ] {
        let mut config = base.clone();
        config["targets"]["test"][key] = json!(value);
        assert!(decode_config::<ClientConfig>(&serde_json::to_vec(&config).unwrap()).is_err());
    }
}

#[test]
fn conflicting_delegations_and_missing_profiles_are_invalid() {
    let mut config = serde_json::to_value(policy()).unwrap();
    config["projects"]["second"] = config["projects"]["example"].clone();
    assert!(decode_config::<ServerConfig>(&serde_json::to_vec(&config).unwrap()).is_err());
    let mut config = serde_json::to_value(policy()).unwrap();
    config["access_profiles"] = json!({});
    assert!(decode_config::<ServerConfig>(&serde_json::to_vec(&config).unwrap()).is_err());
}

#[test]
fn all_access_profile_variants_reject_unknown_fields() {
    for (profile, accepted) in [
        (json!({"kind":"public"}), true),
        (json!({"kind":"public","provider":"sso"}), false),
        (json!({"kind":"private","provider":"sso"}), true),
        (json!({"kind":"private","provider":"sso","x":1}), false),
        (
            json!({"kind":"private","provider":"sso","snippet":"sso_gate"}),
            true,
        ),
        // A snippet is a name the administrator defined, never proxy syntax.
        (
            json!({"kind":"private","provider":"sso","snippet":"x {\n respond 200"}),
            false,
        ),
        (
            json!({"kind":"private","provider":"sso","snippet":"../other"}),
            false,
        ),
    ] {
        let mut value = serde_json::to_value(policy()).unwrap();
        value["access_profiles"]["private"] = profile;
        assert_eq!(
            decode_config::<ServerConfig>(&serde_json::to_vec(&value).unwrap()).is_ok(),
            accepted
        );
    }
    for app in [
        json!({"kind":"static","public":"public","x":1}),
        json!({"kind":"http","runtime":"binary","entrypoint":"api","health":"/health","x":1}),
    ] {
        let mut value = project();
        value["app"] = app;
        assert!(decode(value).is_err());
    }
}

#[test]
fn duplicate_object_keys_are_not_silently_overwritten() {
    let bytes = br#"{"schema_version":1,"projects":{"example":{"operators":["alice"]},"example":{"operators":["mallory"]}}}"#;
    assert!(decode_config::<ServerConfig>(bytes).is_err());
    assert!(decode_json::<Value>(br#"{"nested":[{"x":1,"x":2}]}"#).is_err());
    assert!(decode_json::<Value>(br#"{"nested":[null,true,"string",1,-1,1.5]}"#).is_ok());
}

#[test]
fn proxy_and_backup_settings_require_dedicated_safe_locations() {
    let native = |extra: Value| {
        let mut value = json!({"schema_version":1,"projects":{},"host":{"paths":{
            "apps":"/srv/cais-apps","state":"/var/lib/cais","config":"/etc/cais-apps"}}});
        for (key, setting) in extra.as_object().unwrap() {
            value["host"][key] = setting.clone();
        }
        decode_config::<ServerConfig>(&serde_json::to_vec(&value).unwrap()).is_ok()
    };
    assert!(native(json!({})));
    assert!(native(json!({"caddy":{},"backup":{}})));
    assert!(native(
        json!({"backup":{"check":"/usr/local/libexec/backup-check"}})
    ));
    for rejected in [
        json!({"caddy":{"routes":"/srv/cais-apps/routes"}}),
        json!({"caddy":{"routes":"/etc/caddy/Caddyfile"}}),
        json!({"caddy":{"routes":"relative"}}),
        json!({"caddy":{"user":"root"}}),
        json!({"caddy":{"unit":"caddy.service --no-block"}}),
        json!({"caddy":{"unit":"../caddy.timer"}}),
        json!({"caddy":{"unknown":true}}),
        json!({"backup":{"manifests":"/var/lib/cais/manifests"}}),
        json!({"backup":{"check":"backup-check --all"}}),
        json!({"caddy":{"routes":"/etc/shared"},"backup":{"manifests":"/etc/shared"}}),
    ] {
        assert!(!native(rejected.clone()), "accepted {rejected}");
    }
}

#[test]
fn exposure_accepts_the_root_or_a_plain_prefix() {
    let accepted = |exposure: Value| {
        let mut value = project();
        value["exposure"] = exposure;
        decode(value).is_ok()
    };
    let at = |path: &str| json!({"host":"api.example.org","path":path,"access_profile":"private"});
    for path in [
        "/",
        "/docs",
        "/api/v1",
        "/a/b/c/d/e/f/g/h",
        "/Mixed-Case_1.0",
    ] {
        assert!(accepted(at(path)), "rejected {path}");
    }
    for path in [
        "",
        "docs",
        "/docs/",
        "//docs",
        "/docs//v1",
        "/../etc",
        "/docs/.",
        "/docs?x=1",
        "/docs#top",
        "/do cs",
        "/docs/*",
        "/{path}",
        "/docs\n",
        "/a/b/c/d/e/f/g/h/i",
    ] {
        assert!(!accepted(at(path)), "accepted {path:?}");
    }
    let stripped = |path: &str| json!({"host":"api.example.org","path":path,"access_profile":"private","strip_prefix":true});
    assert!(accepted(stripped("/api")));
    assert!(!accepted(stripped("/")));
    // An unstripped prefix keeps the configuration digest of earlier versions.
    let plain: cais_core::ProjectConfig =
        cais_core::decode_config(&serde_json::to_vec(&project()).unwrap()).unwrap();
    assert!(
        !serde_json::to_string(&plain)
            .unwrap()
            .contains("strip_prefix")
    );
}

#[test]
fn digests_are_written_as_lowercase_hexadecimal() {
    assert_eq!(cais_core::hex([0x00, 0x0f, 0xab]), "000fab");
    // FIPS 180-2 test vector.
    assert_eq!(
        cais_core::hex(<sha2::Sha256 as sha2::Digest>::digest(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}
