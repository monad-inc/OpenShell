// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! How a Kubernetes Secret declares the provider credentials it backs.
//!
//! A Secret opts in with the [`SYNC_LABEL`] label and names its target with
//! annotations. The credential list is explicit: only the listed keys are
//! read, so an unrelated key added to the Secret never becomes a provider
//! credential.
//!
//! ```yaml
//! metadata:
//!   labels:
//!     openshell.nvidia.com/provider-sync: "true"
//!   annotations:
//!     openshell.nvidia.com/provider: github-triage
//!     openshell.nvidia.com/provider-workspace: oncall      # optional
//!     openshell.nvidia.com/provider-credentials: GITHUB_TOKEN, LINEAR_API_KEY=linear-key
//! ```
//!
//! Each credential entry is `CREDENTIAL_KEY` (read from the Secret key of the
//! same name) or `CREDENTIAL_KEY=secret-key`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use k8s_openapi::ByteString;

/// Label selecting the Secrets this controller watches.
pub const SYNC_LABEL: &str = "openshell.nvidia.com/provider-sync";
/// Label value that enables sync.
pub const SYNC_LABEL_VALUE: &str = "true";
/// Annotation naming the target provider.
pub const PROVIDER_ANNOTATION: &str = "openshell.nvidia.com/provider";
/// Annotation naming the provider's workspace. Optional.
pub const WORKSPACE_ANNOTATION: &str = "openshell.nvidia.com/provider-workspace";
/// Annotation listing the credential keys to sync.
pub const CREDENTIALS_ANNOTATION: &str = "openshell.nvidia.com/provider-credentials";

/// Label selector for [`SYNC_LABEL`].
pub fn label_selector() -> String {
    format!("{SYNC_LABEL}={SYNC_LABEL_VALUE}")
}

/// The provider a Secret feeds, and which of its keys feed which credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncTarget {
    pub workspace: String,
    pub provider: String,
    /// Credential key -> Secret data key. Ordered so updates are deterministic.
    pub keys: BTreeMap<String, String>,
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
    #[error("secret has no key '{secret_key}' for credential {credential_key}")]
    MissingSecretKey {
        credential_key: String,
        secret_key: String,
    },
    #[error("secret key '{secret_key}' for credential {credential_key} is empty")]
    EmptyValue {
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
    let provider = required(annotations, PROVIDER_ANNOTATION)?;
    let workspace = annotations
        .get(WORKSPACE_ANNOTATION)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .unwrap_or(default_workspace)
        .to_string();
    let keys = parse_credentials(required(annotations, CREDENTIALS_ANNOTATION)?)?;
    Ok(SyncTarget {
        workspace,
        provider: provider.to_string(),
        keys,
    })
}

fn required<'a>(
    annotations: &'a BTreeMap<String, String>,
    annotation: &'static str,
) -> Result<&'a str, MappingError> {
    annotations
        .get(annotation)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .ok_or(MappingError::MissingAnnotation(annotation))
}

fn parse_credentials(raw: &str) -> Result<BTreeMap<String, String>, MappingError> {
    let invalid = |reason: String| MappingError::InvalidAnnotation {
        annotation: CREDENTIALS_ANNOTATION,
        reason,
    };
    let mut keys = BTreeMap::new();
    let mut secret_keys = BTreeSet::new();
    for entry in raw
        .split([',', '\n'])
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let (credential_key, secret_key) = match entry.split_once('=') {
            Some((credential, secret)) => (credential.trim(), secret.trim()),
            None => (entry, entry),
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
        if keys
            .insert(credential_key.to_string(), secret_key.to_string())
            .is_some()
        {
            return Err(invalid(format!(
                "credential '{credential_key}' is listed more than once"
            )));
        }
    }
    if keys.is_empty() {
        return Err(MappingError::MissingAnnotation(CREDENTIALS_ANNOTATION));
    }
    Ok(keys)
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

/// Read the target's credential values from a Secret's data.
///
/// Every mapped key must be present, non-empty and UTF-8; otherwise nothing is
/// returned, so a half-written Secret never produces a partial update.
pub fn extract_values(
    target: &SyncTarget,
    data: Option<&BTreeMap<String, ByteString>>,
) -> Result<CredentialValues, MappingError> {
    let mut values = BTreeMap::new();
    for (credential_key, secret_key) in &target.keys {
        let bytes = data.and_then(|data| data.get(secret_key)).ok_or_else(|| {
            MappingError::MissingSecretKey {
                credential_key: credential_key.clone(),
                secret_key: secret_key.clone(),
            }
        })?;
        if bytes.0.is_empty() {
            return Err(MappingError::EmptyValue {
                credential_key: credential_key.clone(),
                secret_key: secret_key.clone(),
            });
        }
        let value = String::from_utf8(bytes.0.clone()).map_err(|_| MappingError::NotUtf8 {
            credential_key: credential_key.clone(),
            secret_key: secret_key.clone(),
        })?;
        values.insert(credential_key.clone(), value);
    }
    Ok(CredentialValues(values))
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
        assert_eq!(target.provider, "github-triage");
        assert_eq!(target.workspace, "default");
        assert_eq!(
            target.keys,
            BTreeMap::from([
                ("GITHUB_TOKEN".to_string(), "GITHUB_TOKEN".to_string()),
                ("LINEAR_API_KEY".to_string(), "linear-key".to_string()),
            ])
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
    fn requires_provider_and_credentials() {
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
    }

    #[test]
    fn rejects_invalid_and_duplicate_entries() {
        for raw in ["1TOKEN", "TO-KEN", "TOKEN=bad/key", "A=x,B=x", "A=x,A=y"] {
            let result = parse_target(
                &annotations(&[(PROVIDER_ANNOTATION, "p"), (CREDENTIALS_ANNOTATION, raw)]),
                "d",
            );
            assert!(
                matches!(result, Err(MappingError::InvalidAnnotation { .. })),
                "{raw}: {result:?}"
            );
        }
    }

    #[test]
    fn extracts_only_mapped_keys() {
        let target = parse_target(
            &annotations(&[(PROVIDER_ANNOTATION, "p"), (CREDENTIALS_ANNOTATION, "A=a")]),
            "d",
        )
        .unwrap();
        let values = extract_values(
            &target,
            Some(&data(&[("a", b"one"), ("unrelated", b"two")])),
        )
        .unwrap();
        assert_eq!(
            values.0,
            BTreeMap::from([("A".to_string(), "one".to_string())])
        );
    }

    #[test]
    fn missing_empty_or_binary_values_fail_the_whole_secret() {
        let target = parse_target(
            &annotations(&[
                (PROVIDER_ANNOTATION, "p"),
                (CREDENTIALS_ANNOTATION, "A=a,B=b"),
            ]),
            "d",
        )
        .unwrap();
        assert!(matches!(
            extract_values(&target, Some(&data(&[("a", b"one")]))),
            Err(MappingError::MissingSecretKey { .. })
        ));
        assert!(matches!(
            extract_values(&target, Some(&data(&[("a", b"one"), ("b", b"")]))),
            Err(MappingError::EmptyValue { .. })
        ));
        assert!(matches!(
            extract_values(&target, Some(&data(&[("a", b"one"), ("b", &[0xff, 0xfe])]))),
            Err(MappingError::NotUtf8 { .. })
        ));
        assert!(matches!(
            extract_values(&target, None),
            Err(MappingError::MissingSecretKey { .. })
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
