use crate::{Result, SchemaVersion, Validate, check, finish, host_name, identifier};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Presentation metadata a project publishes for catalog consumers. It never carries
/// units, paths, commands or credentials; those come from the host's own records.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProjectMetadata {
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub schema_version: SchemaVersion,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// HTTPS address on the project's own declared hostname.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Free-form hints for consumers, for example an opt-in a dashboard understands.
    /// Cais stores and publishes them without interpreting any.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, LabelValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(untagged)]
pub enum LabelValue {
    Flag(bool),
    Text(String),
}

fn display_text(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty()
        && value.chars().count() <= maximum
        && value == value.trim()
        // No control, invisible or direction-changing characters: catalog readers show
        // this text to people.
        && !value.chars().any(|ch| {
            ch.is_control()
                || matches!(ch, '\u{061c}' | '\u{200b}' | '\u{200e}' | '\u{200f}'
                    | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}')
        })
}

impl ProjectMetadata {
    /// The hostname of `url`, when it is a plain HTTPS address without credentials,
    /// port, query or fragment.
    pub fn url_host(&self) -> Option<&str> {
        let rest = self.url.as_deref()?.strip_prefix("https://")?;
        let (host, path) = match rest.find('/') {
            Some(index) => rest.split_at(index),
            None => (rest, "/"),
        };
        (host_name(host)
            && rest.len() <= 240
            && path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/-._~".contains(&b))
            && !path.split('/').any(|part| part == ".."))
        .then_some(host)
    }
}

impl Validate for ProjectMetadata {
    fn validate(&self) -> Result<()> {
        let mut issues = Vec::new();
        check(
            &mut issues,
            display_text(&self.title, 80),
            "/title",
            "Use a title of 1-80 characters without control characters.",
        );
        check(
            &mut issues,
            self.description.iter().all(|text| display_text(text, 280)),
            "/description",
            "Use a description of at most 280 characters without control characters.",
        );
        check(
            &mut issues,
            self.url.is_none() || self.url_host().is_some(),
            "/url",
            "Use an HTTPS address without credentials, port, query or fragment.",
        );
        check(
            &mut issues,
            self.labels.len() <= 16
                && self.labels.iter().all(|(key, value)| {
                    identifier(key)
                        && match value {
                            LabelValue::Flag(_) => true,
                            LabelValue::Text(text) => display_text(text, 120),
                        }
                }),
            "/labels",
            "Use at most 16 labels with identifier keys and boolean or short text values.",
        );
        finish(issues)
    }
}
