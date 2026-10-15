// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! How a Kubernetes Secret declares the provider credentials it backs.
//!
//! A Secret opts in with the [`SYNC_LABEL`] label and names its targets with
//! annotations. The credential list is explicit: only the listed keys are
//! read, so an unrelated key added to the Secret never becomes a provider
//! credential.
//!
//! ```yaml
//! metadata:
//!   labels:
//!     openshell.nvidia.com/provider-sync: "true"
//!   annotations:
//!     openshell.nvidia.com/provider-workspace: pm          # optional
//!     openshell.nvidia.com/provider-credentials: >-
//!       slack-pm:SLACK_BOT_TOKEN, slack-pm:SLACK_APP_TOKEN,
//!       linear:LINEAR_API_KEY=linear-key
//! ```
//!
//! Each credential entry is `[provider:]CREDENTIAL_KEY[=secret-key]`. The
//! Secret key defaults to the credential key. An entry without a provider
//! goes to the provider named by [`PROVIDER_ANNOTATION`], which is required
//! only when such an entry exists. One Secret can feed several providers, all
//! in one workspace.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use k8s_openapi::ByteString;

/// Label selecting the Secrets this controller watches.
pub const SYNC_LABEL: &str = "openshell.nvidia.com/provider-sync";
/// Label value that enables sync.
pub const SYNC_LABEL_VALUE: &str = "true";
/// Annotation naming the provider for entries without a `provider:` prefix.
pub const PROVIDER_ANNOTATION: &str = "openshell.nvidia.com/provider";
/// Annotation naming the providers' workspace. Optional.
pub const WORKSPACE_ANNOTATION: &str = "openshell.nvidia.com/provider-workspace";
/// Annotation listing the credential keys to sync.
pub const CREDENTIALS_ANNOTATION: &str = "openshell.nvidia.com/provider-credentials";

/// Label selector for [`SYNC_LABEL`].
pub fn label_selector() -> String {
    format!("{SYNC_LABEL}={SYNC_LABEL_VALUE}")
}

/// Credential key -> Secret data key for one provider. Ordered so updates
/// are deterministic.
pub type KeyMap = BTreeMap<String, String>;

/// The providers a Secret feeds, and which of its keys feed which credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncTarget {
    pub workspace: String,
    /// Provider name -> its keys. Never empty, and every provider has a key.
    pub providers: BTreeMap<String, KeyMap>,
}

/// Credential values read from a Secret, keyed by credential key.
///
/// `Debug` prints only the keys.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct CredentialValues(pub BTreeMap<String, String>);

impl fmt::Debug for CredentialValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.0.keys()).finish()
    }
}

impl CredentialValues {
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.0.keys()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MappingError {
    #[error("annotation {0} is missing or empty")]
    MissingAnnotation(&'static str),
    #[error("annotation {annotation} has an invalid value: {reason}")]
    InvalidAnnotation {
        annotation: &'static str,
        reason: String,
    },
    #[error(
        "secret key '{secret_key}' for credential {credential_key} is missing or empty, but other keys of the same provider are set"
    )]
    MissingSecretKey {
        credential_key: String,
        secret_key: String,
    },
    #[error("secret key '{secret_key}' for credential {credential_key} is not UTF-8")]
    NotUtf8 {
        credential_key: String,
        secret_key: String,
    },
}

/// Parse a Secret's annotations into a [`SyncTarget`].
pub fn parse_target(
    annotations: &BTreeMap<String, String>,
    default_workspace: &str,
) -> Result<SyncTarget, MappingError> {
    let default_provider = optional(annotations, PROVIDER_ANNOTATION);
    if let Some(provider) = default_provider
        && !is_provider_name(provider)
    {
        return Err(MappingError::InvalidAnnotation {
            annotation: PROVIDER_ANNOTATION,
            reason: format!("'{provider}' is not a valid provider name"),
        });
    }
    let workspace = optional(annotations, WORKSPACE_ANNOTATION)
        .unwrap_or(default_workspace)
        .to_string();
    let raw = optional(annotations, CREDENTIALS_ANNOTATION)
        .ok_or(MappingError::MissingAnnotation(CREDENTIALS_ANNOTATION))?;
    let providers = parse_credentials(raw, default_provider)?;
    Ok(SyncTarget {
        workspace,
        providers,
    })
}

fn optional<'a>(annotations: &'a BTreeMap<String, String>, annotation: &str) -> Option<&'a str> {
    annotations
        .get(annotation)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
}

fn parse_credentials(
    raw: &str,
    default_provider: Option<&str>,
) -> Result<BTreeMap<String, KeyMap>, MappingError> {
    let invalid = |reason: String| MappingError::InvalidAnnotation {
        annotation: CREDENTIALS_ANNOTATION,
        reason,
    };
    let mut providers: BTreeMap<String, KeyMap> = BTreeMap::new();
    let mut secret_keys = BTreeSet::new();
    for entry in raw
        .split([',', '\n'])
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let (provider, mapping) = match entry.split_once(':') {
            Some((provider, mapping)) => (provider.trim(), mapping.trim()),
            None => (
                default_provider.ok_or(MappingError::MissingAnnotation(PROVIDER_ANNOTATION))?,
                entry,
            ),
        };
        if !is_provider_name(provider) {
            return Err(invalid(format!(
                "'{provider}' is not a valid provider name (letters, digits, '-', '_' and '.')"
            )));
        }
        let (credential_key, secret_key) = match mapping.split_once('=') {
            Some((credential, secret)) => (credential.trim(), secret.trim()),
            None => (mapping, mapping),
        };
        if !is_credential_key(credential_key) {
            return Err(invalid(format!(
                "'{credential_key}' is not a valid credential key (letters, digits and '_', not starting with a digit)"
            )));
        }
        if !is_secret_data_key(secret_key) {
            return Err(invalid(format!(
                "'{secret_key}' is not a valid Secret key (letters, digits, '-', '_' and '.')"
            )));
        }
        if !secret_keys.insert(secret_key.to_string()) {
            // One Secret key feeding two credentials is almost certainly a
            // typo, and would let one value leak into a second binding.
            return Err(invalid(format!(
                "Secret key '{secret_key}' is mapped more than once"
            )));
        }
        if providers
            .entry(provider.to_string())
            .or_default()
            .insert(credential_key.to_string(), secret_key.to_string())
            .is_some()
        {
            return Err(invalid(format!(
                "credential '{provider}:{credential_key}' is listed more than once"
            )));
        }
    }
    if providers.is_empty() {
        return Err(MappingError::MissingAnnotation(CREDENTIALS_ANNOTATION));
    }
    Ok(providers)
}

fn is_provider_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn is_credential_key(key: &str) -> bool {
    let mut chars = key.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn is_secret_data_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 253
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// What a Secret holds for one provider.
#[derive(Debug, PartialEq, Eq)]
pub enum Extracted {
    /// Every mapped key is set.
    Present(CredentialValues),
    /// None of the mapped keys is set: each is missing or empty. The Secret
    /// does not back this provider right now, as when only one of two
    /// alternative credentials is set.
    Absent,
}

/// Read one provider's credential values from a Secret's data.
///
/// A key counts as set when it is present and not empty, so a Secret that
/// writes every known key and leaves unused ones empty behaves like one that
/// omits them. Every mapped key must be set and UTF-8, or none may be set.
/// Anything in between is an error and nothing is returned, so a
/// half-written Secret never produces a partial update.
pub fn extract_values(
    keys: &KeyMap,
    data: Option<&BTreeMap<String, ByteString>>,
) -> Result<Extracted, MappingError> {
    let lookup = |secret_key: &String| {
        data.and_then(|data| data.get(secret_key))
            .filter(|bytes| !bytes.0.is_empty())
    };
    if keys.values().all(|secret_key| lookup(secret_key).is_none()) {
        return Ok(Extracted::Absent);
    }
    let mut values = BTreeMap::new();
    for (credential_key, secret_key) in keys {
        let bytes = lookup(secret_key).ok_or_else(|| MappingError::MissingSecretKey {
            credential_key: credential_key.clone(),
            secret_key: secret_key.clone(),
        })?;
        let value = String::from_utf8(bytes.0.clone()).map_err(|_| MappingError::NotUtf8 {
            credential_key: credential_key.clone(),
            secret_key: secret_key.clone(),
        })?;
        values.insert(credential_key.clone(), value);
    }
    Ok(Extracted::Present(CredentialValues(values)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn annotations(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn data(pairs: &[(&str, &[u8])]) -> BTreeMap<String, ByteString> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), ByteString(v.to_vec())))
            .collect()
    }

    fn keys(pairs: &[(&str, &str)]) -> KeyMap {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn parses_plain_and_renamed_keys() {
        let target = parse_target(
            &annotations(&[
                (PROVIDER_ANNOTATION, " github-triage "),
                (
                    CREDENTIALS_ANNOTATION,
                    "GITHUB_TOKEN,\n LINEAR_API_KEY = linear-key ,",
                ),
            ]),
            "default",
        )
        .unwrap();
        assert_eq!(target.workspace, "default");
        assert_eq!(
            target.providers,
            BTreeMap::from([(
                "github-triage".to_string(),
                keys(&[
                    ("GITHUB_TOKEN", "GITHUB_TOKEN"),
                    ("LINEAR_API_KEY", "linear-key")
                ]),
            )])
        );
    }

    #[test]
    fn one_secret_feeds_several_providers() {
        let target = parse_target(
            &annotations(&[
                (WORKSPACE_ANNOTATION, "pm"),
                (
                    CREDENTIALS_ANNOTATION,
                    "slack-pm:SLACK_BOT_TOKEN, slack-pm:SLACK_APP_TOKEN,\n linear : LINEAR_API_KEY=linear-key",
                ),
            ]),
            "default",
        )
        .unwrap();
        assert_eq!(target.workspace, "pm");
        assert_eq!(
            target.providers,
            BTreeMap::from([
                (
                    "linear".to_string(),
                    keys(&[("LINEAR_API_KEY", "linear-key")])
                ),
                (
                    "slack-pm".to_string(),
                    keys(&[
                        ("SLACK_APP_TOKEN", "SLACK_APP_TOKEN"),
                        ("SLACK_BOT_TOKEN", "SLACK_BOT_TOKEN")
                    ]),
                ),
            ])
        );
    }

    #[test]
    fn unprefixed_entries_use_the_provider_annotation() {
        let target = parse_target(
            &annotations(&[
                (PROVIDER_ANNOTATION, "github"),
                (
                    CREDENTIALS_ANNOTATION,
                    "GITHUB_TOKEN, linear:LINEAR_API_KEY",
                ),
            ]),
            "default",
        )
        .unwrap();
        assert_eq!(
            target.providers.keys().collect::<Vec<_>>(),
            ["github", "linear"]
        );
    }

    #[test]
    fn workspace_annotation_overrides_default() {
        let target = parse_target(
            &annotations(&[
                (PROVIDER_ANNOTATION, "p"),
                (WORKSPACE_ANNOTATION, "oncall"),
                (CREDENTIALS_ANNOTATION, "TOKEN"),
            ]),
            "default",
        )
        .unwrap();
        assert_eq!(target.workspace, "oncall");
    }

    #[test]
    fn requires_credentials_and_a_provider_for_each_entry() {
        assert_eq!(
            parse_target(&annotations(&[(CREDENTIALS_ANNOTATION, "TOKEN")]), "d"),
            Err(MappingError::MissingAnnotation(PROVIDER_ANNOTATION))
        );
        assert_eq!(
            parse_target(
                &annotations(&[(PROVIDER_ANNOTATION, "p"), (CREDENTIALS_ANNOTATION, " , ")]),
                "d"
            ),
            Err(MappingError::MissingAnnotation(CREDENTIALS_ANNOTATION))
        );
        assert_eq!(
            parse_target(&annotations(&[(PROVIDER_ANNOTATION, "p")]), "d"),
            Err(MappingError::MissingAnnotation(CREDENTIALS_ANNOTATION))
        );
    }

    #[test]
    fn rejects_invalid_and_duplicate_entries() {
        for raw in [
            "1TOKEN",
            "TO-KEN",
            "TOKEN=bad/key",
            "A=x,B=x",
            "A=x,A=y",
            "a:A=x,b:B=x",
            "a:A=x,a:A=y",
            ":TOKEN",
            "bad/name:TOKEN",
        ] {
            let result = parse_target(
                &annotations(&[(PROVIDER_ANNOTATION, "p"), (CREDENTIALS_ANNOTATION, raw)]),
                "d",
            );
            assert!(
                matches!(result, Err(MappingError::InvalidAnnotation { .. })),
                "{raw}: {result:?}"
            );
        }
        assert!(matches!(
            parse_target(
                &annotations(&[
                    (PROVIDER_ANNOTATION, "bad name"),
                    (CREDENTIALS_ANNOTATION, "A")
                ]),
                "d"
            ),
            Err(MappingError::InvalidAnnotation {
                annotation: PROVIDER_ANNOTATION,
                ..
            })
        ));
    }

    #[test]
    fn same_credential_key_on_two_providers_is_allowed() {
        let target = parse_target(
            &annotations(&[(CREDENTIALS_ANNOTATION, "a:TOKEN=one, b:TOKEN=two")]),
            "d",
        )
        .unwrap();
        assert_eq!(target.providers.len(), 2);
    }

    #[test]
    fn extracts_only_mapped_keys() {
        let values = extract_values(
            &keys(&[("A", "a")]),
            Some(&data(&[("a", b"one"), ("unrelated", b"two")])),
        )
        .unwrap();
        assert_eq!(
            values,
            Extracted::Present(CredentialValues(BTreeMap::from([(
                "A".to_string(),
                "one".to_string()
            )])))
        );
    }

    #[test]
    fn provider_with_no_keys_set_is_absent() {
        let mapped = keys(&[("A", "a"), ("B", "b")]);
        assert_eq!(
            extract_values(&mapped, Some(&data(&[("a", b""), ("b", b"")]))),
            Ok(Extracted::Absent)
        );
        assert_eq!(
            extract_values(&mapped, Some(&data(&[("other", b"x")]))),
            Ok(Extracted::Absent)
        );
        assert_eq!(extract_values(&mapped, None), Ok(Extracted::Absent));
    }

    #[test]
    fn partly_set_or_binary_values_fail_the_provider() {
        let mapped = keys(&[("A", "a"), ("B", "b")]);
        assert!(matches!(
            extract_values(&mapped, Some(&data(&[("a", b"one")]))),
            Err(MappingError::MissingSecretKey { .. })
        ));
        assert!(matches!(
            extract_values(&mapped, Some(&data(&[("a", b"one"), ("b", b"")]))),
            Err(MappingError::MissingSecretKey { .. })
        ));
        assert!(matches!(
            extract_values(&mapped, Some(&data(&[("a", b"one"), ("b", &[0xff, 0xfe])]))),
            Err(MappingError::NotUtf8 { .. })
        ));
    }

    #[test]
    fn debug_never_prints_values() {
        let values = CredentialValues(BTreeMap::from([(
            "TOKEN".to_string(),
            "super-secret".to_string(),
        )]));
        let rendered = format!("{values:?}");
        assert!(rendered.contains("TOKEN"));
        assert!(!rendered.contains("super-secret"));
    }
}
