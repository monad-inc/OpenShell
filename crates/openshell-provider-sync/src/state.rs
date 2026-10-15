// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! What has been pushed to the gateway, so only changed keys are sent.
//!
//! Values are never stored: each applied value is kept as a salted SHA-256
//! fingerprint. The salt and fingerprints can be persisted (see
//! [`PersistedState`]) so a restart of this controller recognizes values it
//! already applied, and does not treat them as rotations that restart agents.
//! Without persisted state every Secret is pushed once more after a restart,
//! as a baseline that restarts nothing.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use sha2::{Digest, Sha256};

use crate::mapping::{CredentialValues, KeyMap, SyncTarget};

/// `namespace/name` of a Secret.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SecretRef {
    pub namespace: String,
    pub name: String,
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.namespace, self.name)
    }
}

/// One provider credential, which at most one Secret may feed.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct CredentialSlot {
    workspace: String,
    provider: String,
    credential_key: String,
}

impl fmt::Display for CredentialSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}:{}",
            self.workspace, self.provider, self.credential_key
        )
    }
}

/// What a Secret last pushed to one provider.
#[derive(Clone)]
struct Applied {
    workspace: String,
    fingerprints: BTreeMap<String, [u8; 32]>,
}

/// A Secret and one provider it feeds.
type AppliedKey = (SecretRef, String);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("credential {slot} is already synced from Secret {owner}")]
pub struct Conflict {
    pub slot: String,
    pub owner: SecretRef,
}

pub struct SyncState {
    salt: [u8; 32],
    applied: HashMap<AppliedKey, Applied>,
    owners: HashMap<CredentialSlot, SecretRef>,
}

/// Fingerprints of applied values, kept across controller restarts.
///
/// Holds no values. It is stored in a Secret because the salt and the
/// fingerprints together would let anyone who reads them test guesses.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PersistedState {
    salt: String,
    applied: Vec<PersistedApplied>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct PersistedApplied {
    namespace: String,
    secret: String,
    provider: String,
    workspace: String,
    fingerprints: BTreeMap<String, String>,
}

fn to_hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

fn from_hex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(bytes)
}

impl Default for SyncState {
    fn default() -> Self {
        Self::new()
    }
}

fn slots(workspace: &str, provider: &str, keys: &KeyMap) -> Vec<CredentialSlot> {
    keys.keys()
        .map(|credential_key| CredentialSlot {
            workspace: workspace.to_string(),
            provider: provider.to_string(),
            credential_key: credential_key.clone(),
        })
        .collect()
}

impl SyncState {
    pub fn new() -> Self {
        Self {
            salt: rand::random(),
            applied: HashMap::new(),
            owners: HashMap::new(),
        }
    }

    /// Resume from persisted fingerprints. Entries that do not parse are
    /// dropped, which only makes their next value a baseline.
    pub fn from_persisted(persisted: PersistedState) -> Self {
        let Some(salt) = from_hex(&persisted.salt) else {
            return Self::new();
        };
        let applied = persisted
            .applied
            .into_iter()
            .filter_map(|entry| {
                let fingerprints = entry
                    .fingerprints
                    .into_iter()
                    .map(|(key, fingerprint)| Some((key, from_hex(&fingerprint)?)))
                    .collect::<Option<BTreeMap<_, _>>>()?;
                Some((
                    (
                        SecretRef {
                            namespace: entry.namespace,
                            name: entry.secret,
                        },
                        entry.provider,
                    ),
                    Applied {
                        workspace: entry.workspace,
                        fingerprints,
                    },
                ))
            })
            .collect();
        Self {
            salt,
            applied,
            owners: HashMap::new(),
        }
    }

    /// The fingerprints to persist. Claims are rebuilt from the watch.
    pub fn to_persisted(&self) -> PersistedState {
        let mut applied: Vec<PersistedApplied> = self
            .applied
            .iter()
            .map(|((secret, provider), applied)| PersistedApplied {
                namespace: secret.namespace.clone(),
                secret: secret.name.clone(),
                provider: provider.clone(),
                workspace: applied.workspace.clone(),
                fingerprints: applied
                    .fingerprints
                    .iter()
                    .map(|(key, fingerprint)| (key.clone(), to_hex(fingerprint)))
                    .collect(),
            })
            .collect();
        applied.sort_by(|left, right| {
            (&left.namespace, &left.secret, &left.provider).cmp(&(
                &right.namespace,
                &right.secret,
                &right.provider,
            ))
        });
        PersistedState {
            salt: to_hex(&self.salt),
            applied,
        }
    }

    /// Whether `secret` has applied values to `provider` before, so a change
    /// now is a rotation rather than a baseline.
    pub fn has_applied(&self, secret: &SecretRef, workspace: &str, provider: &str) -> bool {
        self.applied
            .get(&(secret.clone(), provider.to_string()))
            .is_some_and(|applied| applied.workspace == workspace)
    }

    fn fingerprint(&self, value: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.salt);
        hasher.update(value.as_bytes());
        hasher.finalize().into()
    }

    /// Drop the claims and applied state `secret` holds outside `target`, as
    /// when an entry is removed or the workspace changes.
    pub fn retain(&mut self, secret: &SecretRef, target: &SyncTarget) {
        let wanted: HashSet<CredentialSlot> = target
            .providers
            .iter()
            .flat_map(|(provider, keys)| slots(&target.workspace, provider, keys))
            .collect();
        self.release(secret, |slot| !wanted.contains(slot));
        self.applied.retain(|(owner, provider), applied| {
            owner != secret
                || (applied.workspace == target.workspace
                    && target.providers.contains_key(provider))
        });
    }

    /// Claim one provider's credentials for `secret`.
    ///
    /// `owner_exists` reports whether a Secret that holds a claim still
    /// exists and is still labelled; a claim from a deleted Secret is taken
    /// over rather than blocking its replacement.
    pub fn claim(
        &mut self,
        secret: &SecretRef,
        workspace: &str,
        provider: &str,
        keys: &KeyMap,
        owner_exists: impl Fn(&SecretRef) -> bool,
    ) -> Result<(), Conflict> {
        let slots = slots(workspace, provider, keys);
        for slot in &slots {
            if let Some(owner) = self.owners.get(slot)
                && owner != secret
                && owner_exists(owner)
            {
                return Err(Conflict {
                    slot: slot.to_string(),
                    owner: owner.clone(),
                });
            }
        }
        for slot in slots {
            if let Some(previous) = self.owners.insert(slot, secret.clone())
                && &previous != secret
            {
                self.applied.remove(&(previous, provider.to_string()));
            }
        }
        Ok(())
    }

    /// The values that differ from what `secret` last applied to `provider`.
    pub fn changed(
        &self,
        secret: &SecretRef,
        workspace: &str,
        provider: &str,
        values: &CredentialValues,
    ) -> CredentialValues {
        let applied = self
            .applied
            .get(&(secret.clone(), provider.to_string()))
            .filter(|applied| applied.workspace == workspace);
        CredentialValues(
            values
                .0
                .iter()
                .filter(|(key, value)| {
                    applied
                        .and_then(|applied| applied.fingerprints.get(*key))
                        .is_none_or(|fingerprint| *fingerprint != self.fingerprint(value))
                })
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        )
    }

    /// Record that `values` are now what the gateway holds for `provider`.
    pub fn commit(
        &mut self,
        secret: &SecretRef,
        workspace: &str,
        provider: &str,
        values: &CredentialValues,
    ) {
        let fingerprints = values
            .0
            .iter()
            .map(|(key, value)| (key.clone(), self.fingerprint(value)))
            .collect();
        self.applied.insert(
            (secret.clone(), provider.to_string()),
            Applied {
                workspace: workspace.to_string(),
                fingerprints,
            },
        );
    }

    /// Forget what `secret` pushed to `provider`, so the next values it holds
    /// are sent in full. The claim is kept.
    pub fn clear_applied(&mut self, secret: &SecretRef, provider: &str) {
        self.applied.remove(&(secret.clone(), provider.to_string()));
    }

    /// Drop everything known about a Secret that was deleted, unlabelled or
    /// made invalid. Provider credentials are left as they are.
    pub fn forget(&mut self, secret: &SecretRef) {
        self.applied.retain(|(owner, _), _| owner != secret);
        self.release(secret, |_| true);
    }

    fn release(
        &mut self,
        secret: &SecretRef,
        mut should_release: impl FnMut(&CredentialSlot) -> bool,
    ) {
        self.owners
            .retain(|slot, owner| owner != secret || !should_release(slot));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(name: &str) -> SecretRef {
        SecretRef {
            namespace: "agents".to_string(),
            name: name.to_string(),
        }
    }

    fn keys(names: &[&str]) -> KeyMap {
        names
            .iter()
            .map(|k| ((*k).to_string(), (*k).to_lowercase()))
            .collect()
    }

    fn target(providers: &[(&str, &[&str])]) -> SyncTarget {
        SyncTarget {
            workspace: "default".to_string(),
            providers: providers
                .iter()
                .map(|(provider, names)| ((*provider).to_string(), keys(names)))
                .collect(),
        }
    }

    fn values(pairs: &[(&str, &str)]) -> CredentialValues {
        CredentialValues(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        )
    }

    fn changed_keys(values: &CredentialValues) -> Vec<&str> {
        values.keys().map(String::as_str).collect()
    }

    #[test]
    fn first_sight_pushes_everything_then_only_changes() {
        let mut state = SyncState::new();
        let s = secret("gh");
        let v1 = values(&[("A", "1"), ("B", "2")]);
        state
            .claim(&s, "default", "github", &keys(&["A", "B"]), |_| true)
            .unwrap();
        assert_eq!(
            changed_keys(&state.changed(&s, "default", "github", &v1)),
            ["A", "B"]
        );
        state.commit(&s, "default", "github", &v1);
        assert!(state.changed(&s, "default", "github", &v1).is_empty());

        let v2 = values(&[("A", "1"), ("B", "3")]);
        assert_eq!(
            changed_keys(&state.changed(&s, "default", "github", &v2)),
            ["B"]
        );
    }

    #[test]
    fn providers_of_one_secret_are_tracked_apart() {
        let mut state = SyncState::new();
        let s = secret("pm");
        let token = values(&[("TOKEN", "1")]);
        state.commit(&s, "default", "slack", &token);
        assert!(state.changed(&s, "default", "slack", &token).is_empty());
        assert_eq!(
            changed_keys(&state.changed(&s, "default", "linear", &token)),
            ["TOKEN"]
        );
    }

    #[test]
    fn failed_push_is_retried() {
        let state = SyncState::new();
        let v = values(&[("A", "1")]);
        // No commit: the gateway call failed.
        assert_eq!(
            changed_keys(&state.changed(&secret("gh"), "default", "github", &v)),
            ["A"]
        );
    }

    #[test]
    fn removed_provider_releases_its_claims_and_state() {
        let mut state = SyncState::new();
        let s = secret("gh");
        let v = values(&[("A", "1")]);
        state
            .claim(&s, "default", "github", &keys(&["A"]), |_| true)
            .unwrap();
        state.commit(&s, "default", "github", &v);

        state.retain(&s, &target(&[("github-2", &["A"])]));
        // The old slot is free for another Secret.
        assert!(
            state
                .claim(&secret("other"), "default", "github", &keys(&["A"]), |_| {
                    true
                })
                .is_ok()
        );
        // And returning to it pushes in full.
        assert_eq!(
            changed_keys(&state.changed(&s, "default", "github", &v)),
            ["A"]
        );
    }

    #[test]
    fn workspace_change_pushes_in_full() {
        let mut state = SyncState::new();
        let s = secret("gh");
        let v = values(&[("A", "1")]);
        state.commit(&s, "default", "github", &v);
        let mut moved = target(&[("github", &["A"])]);
        moved.workspace = "oncall".to_string();
        state.retain(&s, &moved);
        assert_eq!(
            changed_keys(&state.changed(&s, "oncall", "github", &v)),
            ["A"]
        );
    }

    #[test]
    fn two_live_secrets_cannot_feed_one_credential() {
        let mut state = SyncState::new();
        state
            .claim(&secret("first"), "default", "github", &keys(&["A"]), |_| {
                true
            })
            .unwrap();
        let err = state
            .claim(
                &secret("second"),
                "default",
                "github",
                &keys(&["A"]),
                |_| true,
            )
            .unwrap_err();
        assert_eq!(err.owner, secret("first"));
        // A different key of the same provider is fine.
        assert!(
            state
                .claim(
                    &secret("second"),
                    "default",
                    "github",
                    &keys(&["B"]),
                    |_| { true }
                )
                .is_ok()
        );
    }

    #[test]
    fn claim_of_a_deleted_secret_is_taken_over() {
        let mut state = SyncState::new();
        let v = values(&[("A", "1")]);
        state
            .claim(&secret("first"), "default", "github", &keys(&["A"]), |_| {
                true
            })
            .unwrap();
        state.commit(&secret("first"), "default", "github", &v);
        state
            .claim(
                &secret("second"),
                "default",
                "github",
                &keys(&["A"]),
                |owner| owner != &secret("first"),
            )
            .unwrap();
        assert_eq!(
            changed_keys(&state.changed(&secret("second"), "default", "github", &v)),
            ["A"]
        );
    }

    #[test]
    fn persisted_state_recognizes_applied_values_after_a_restart() {
        let mut state = SyncState::new();
        let secret = secret("a");
        let applied = values(&[("TOKEN", "v1")]);
        state.commit(&secret, "w", "p", &applied);
        assert!(state.has_applied(&secret, "w", "p"));

        let persisted = state.to_persisted();
        let serialized = serde_json::to_string(&persisted).unwrap();
        assert!(!serialized.contains("v1"), "values are never persisted");
        let restarted = SyncState::from_persisted(serde_json::from_str(&serialized).unwrap());

        assert!(restarted.has_applied(&secret, "w", "p"));
        assert!(changed_keys(&restarted.changed(&secret, "w", "p", &applied)).is_empty());
        assert_eq!(
            changed_keys(&restarted.changed(&secret, "w", "p", &values(&[("TOKEN", "v2")]))),
            ["TOKEN"]
        );
        assert!(!restarted.has_applied(&secret, "other", "p"));
    }

    #[test]
    fn unreadable_persisted_state_starts_fresh() {
        let restarted = SyncState::from_persisted(PersistedState {
            salt: "not hex".to_string(),
            applied: Vec::new(),
        });
        assert!(!restarted.has_applied(&secret("a"), "w", "p"));
    }

    #[test]
    fn forget_releases_claims() {
        let mut state = SyncState::new();
        state
            .claim(&secret("first"), "default", "github", &keys(&["A"]), |_| {
                true
            })
            .unwrap();
        state.forget(&secret("first"));
        assert!(
            state
                .claim(
                    &secret("second"),
                    "default",
                    "github",
                    &keys(&["A"]),
                    |_| { true }
                )
                .is_ok()
        );
    }
}
