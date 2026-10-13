// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! What has been pushed to the gateway, so only changed keys are sent.
//!
//! State is in memory only. Values are never stored: each applied value is
//! kept as a salted SHA-256 fingerprint, and the salt is random per process so
//! a fingerprint is useless outside it. After a restart every Secret is pushed
//! once more, which is a value-only update and harmless to running sandboxes.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use sha2::{Digest, Sha256};

use crate::mapping::{CredentialValues, SyncTarget};

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

#[derive(Clone)]
struct Applied {
    workspace: String,
    provider: String,
    fingerprints: BTreeMap<String, [u8; 32]>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("credential {slot} is already synced from Secret {owner}")]
pub struct Conflict {
    pub slot: String,
    pub owner: SecretRef,
}

/// The keys a Secret needs to push, from [`SyncState::plan`].
#[derive(Debug)]
pub struct Plan {
    pub changed: CredentialValues,
}

pub struct SyncState {
    salt: [u8; 32],
    applied: HashMap<SecretRef, Applied>,
    owners: HashMap<CredentialSlot, SecretRef>,
}

impl Default for SyncState {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncState {
    pub fn new() -> Self {
        Self {
            salt: rand::random(),
            applied: HashMap::new(),
            owners: HashMap::new(),
        }
    }

    fn fingerprint(&self, value: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.salt);
        hasher.update(value.as_bytes());
        hasher.finalize().into()
    }

    /// Claim the target's credentials for `secret` and return the keys whose
    /// values differ from what was last applied.
    ///
    /// `owner_exists` reports whether a Secret that holds a claim still
    /// exists and is still labelled; a claim from a deleted Secret is taken
    /// over rather than blocking its replacement.
    pub fn plan(
        &mut self,
        secret: &SecretRef,
        target: &SyncTarget,
        values: &CredentialValues,
        owner_exists: impl Fn(&SecretRef) -> bool,
    ) -> Result<Plan, Conflict> {
        let slots: Vec<CredentialSlot> = target
            .keys
            .keys()
            .map(|credential_key| CredentialSlot {
                workspace: target.workspace.clone(),
                provider: target.provider.clone(),
                credential_key: credential_key.clone(),
            })
            .collect();
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

        self.release(secret, |slot| !slots.contains(slot));
        for slot in slots {
            if let Some(previous) = self.owners.insert(slot, secret.clone())
                && &previous != secret
            {
                self.applied.remove(&previous);
            }
        }

        let applied = self.applied.get(secret).filter(|applied| {
            applied.workspace == target.workspace && applied.provider == target.provider
        });
        let changed = values
            .0
            .iter()
            .filter(|(key, value)| {
                applied
                    .and_then(|applied| applied.fingerprints.get(*key))
                    .is_none_or(|fingerprint| *fingerprint != self.fingerprint(value))
            })
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        Ok(Plan {
            changed: CredentialValues(changed),
        })
    }

    /// Record that `values` are now what the gateway holds for `secret`.
    pub fn commit(&mut self, secret: &SecretRef, target: &SyncTarget, values: &CredentialValues) {
        let fingerprints = values
            .0
            .iter()
            .map(|(key, value)| (key.clone(), self.fingerprint(value)))
            .collect();
        self.applied.insert(
            secret.clone(),
            Applied {
                workspace: target.workspace.clone(),
                provider: target.provider.clone(),
                fingerprints,
            },
        );
    }

    /// Drop everything known about a Secret that was deleted, unlabelled or
    /// made invalid. Provider credentials are left as they are.
    pub fn forget(&mut self, secret: &SecretRef) {
        self.applied.remove(secret);
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

    fn target(provider: &str, keys: &[&str]) -> SyncTarget {
        SyncTarget {
            workspace: "default".to_string(),
            provider: provider.to_string(),
            keys: keys
                .iter()
                .map(|k| ((*k).to_string(), (*k).to_lowercase()))
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

    fn changed_keys(plan: &Plan) -> Vec<&str> {
        plan.changed.keys().map(String::as_str).collect()
    }

    #[test]
    fn first_sight_pushes_everything_then_only_changes() {
        let mut state = SyncState::new();
        let s = secret("gh");
        let t = target("github", &["A", "B"]);
        let v1 = values(&[("A", "1"), ("B", "2")]);

        let plan = state.plan(&s, &t, &v1, |_| true).unwrap();
        assert_eq!(changed_keys(&plan), ["A", "B"]);
        state.commit(&s, &t, &v1);

        assert!(
            state
                .plan(&s, &t, &v1, |_| true)
                .unwrap()
                .changed
                .is_empty()
        );

        let v2 = values(&[("A", "1"), ("B", "3")]);
        assert_eq!(
            changed_keys(&state.plan(&s, &t, &v2, |_| true).unwrap()),
            ["B"]
        );
    }

    #[test]
    fn failed_push_is_retried() {
        let mut state = SyncState::new();
        let s = secret("gh");
        let t = target("github", &["A"]);
        let v = values(&[("A", "1")]);
        state.plan(&s, &t, &v, |_| true).unwrap();
        // No commit: the gateway call failed.
        assert_eq!(
            changed_keys(&state.plan(&s, &t, &v, |_| true).unwrap()),
            ["A"]
        );
    }

    #[test]
    fn retargeting_pushes_all_keys_to_the_new_provider() {
        let mut state = SyncState::new();
        let s = secret("gh");
        let v = values(&[("A", "1")]);
        let old = target("github", &["A"]);
        state.plan(&s, &old, &v, |_| true).unwrap();
        state.commit(&s, &old, &v);

        let new = target("github-2", &["A"]);
        assert_eq!(
            changed_keys(&state.plan(&s, &new, &v, |_| true).unwrap()),
            ["A"]
        );
        // The old slot is released.
        assert!(state.plan(&secret("other"), &old, &v, |_| true).is_ok());
    }

    #[test]
    fn two_live_secrets_cannot_feed_one_credential() {
        let mut state = SyncState::new();
        let t = target("github", &["A"]);
        let v = values(&[("A", "1")]);
        state.plan(&secret("first"), &t, &v, |_| true).unwrap();
        let err = state.plan(&secret("second"), &t, &v, |_| true).unwrap_err();
        assert_eq!(err.owner, secret("first"));
    }

    #[test]
    fn claim_of_a_deleted_secret_is_taken_over() {
        let mut state = SyncState::new();
        let t = target("github", &["A"]);
        let v = values(&[("A", "1")]);
        state.plan(&secret("first"), &t, &v, |_| true).unwrap();
        state.commit(&secret("first"), &t, &v);
        let plan = state
            .plan(&secret("second"), &t, &v, |owner| owner != &secret("first"))
            .unwrap();
        assert_eq!(changed_keys(&plan), ["A"]);
    }

    #[test]
    fn forget_releases_claims() {
        let mut state = SyncState::new();
        let t = target("github", &["A"]);
        let v = values(&[("A", "1")]);
        state.plan(&secret("first"), &t, &v, |_| true).unwrap();
        state.forget(&secret("first"));
        assert!(state.plan(&secret("second"), &t, &v, |_| true).is_ok());
    }
}
