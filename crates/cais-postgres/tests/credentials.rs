use cais_postgres::Credentials;

#[test]
fn private_file_roundtrips_and_invalid_input_never_echoes_values() {
    let settings = cais_core::PostgresSettings::default();
    let original = Credentials::generate("example", &settings).unwrap();
    let bytes = original.encode_private_file().unwrap();
    let decoded = Credentials::decode_private_file(&bytes).unwrap();
    assert!(decoded.password_for_child() == original.password_for_child());
    assert!(decoded.password_for_child().len() == 64);
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["unexpected"] = "private-input-marker".into();
    let error = Credentials::decode_private_file(&serde_json::to_vec(&value).unwrap())
        .err()
        .expect("unknown keys must fail");
    assert!(!error.to_string().contains("private-input-marker"));
    value.as_object_mut().unwrap().remove("unexpected");
    value["schema_version"] = 2.into();
    assert!(Credentials::decode_private_file(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn administrative_identity_and_system_role_names_are_rejected() {
    use cais_core::Validate;
    let settings = cais_core::PostgresSettings {
        os_user: "root".into(),
        ..Default::default()
    };
    assert!(settings.validate().is_err());
    let settings = cais_core::PostgresSettings {
        role_prefix: "pg_".into(),
        ..Default::default()
    };
    assert!(settings.validate().is_err());
}
