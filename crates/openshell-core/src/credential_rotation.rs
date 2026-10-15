// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Close tunnels that carry a rotated static provider credential.
//!
//! A value-only rotation replaces a credential without changing policy, so it
//! must not advance the policy generation and close every tunnel in the
//! sandbox. Rotation must still be immediate: a connection that authenticated
//! with the old value, such as a WebSocket that carried it in its handshake,
//! must not keep working. Each credential-bearing relay therefore watches for
//! rotations whose static credential bindings match its destination, and
//! only those relays close.

use crate::host_pattern::HostPattern;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::watch;

/// Rotations kept for relays that have not yet observed them. A relay whose
/// captured epoch is older than the retained history closes conservatively.
const MAX_RETAINED_ROTATIONS: usize = 64;

/// One endpoint a rotated credential is bound to.
#[derive(Debug, Clone)]
pub struct RotatedEndpoint {
    host: HostPattern,
    port: u16,
}

impl RotatedEndpoint {
    /// Compile a binding endpoint. Invalid patterns were already rejected when
    /// the credential was installed, so they are reported rather than skipped.
    pub fn new(host: &str, port: u32) -> Result<Self, String> {
        let host = HostPattern::new(host)?;
        let port = u16::try_from(port).map_err(|_| format!("invalid port {port}"))?;
        Ok(Self { host, port })
    }

    pub(crate) fn from_compiled(host: HostPattern, port: u16) -> Self {
        Self { host, port }
    }

    fn matches(&self, endpoint: &TunnelEndpoint) -> bool {
        self.port == endpoint.port && self.host.matches(&endpoint.host)
    }
}

#[derive(Debug)]
struct RotationRecord {
    epoch: u64,
    keys: Arc<[String]>,
    endpoints: Vec<RotatedEndpoint>,
}

#[derive(Debug)]
struct TunnelEndpoint {
    host: String,
    port: u16,
}

#[derive(Debug, Default)]
struct RotationsInner {
    records: VecDeque<RotationRecord>,
    tunnels: Vec<Weak<TunnelEndpoint>>,
}

/// Rotation history shared by the supervisor, which announces rotations, and
/// the network relays, which close on them.
#[derive(Debug)]
pub struct CredentialRotations {
    inner: Mutex<RotationsInner>,
    epoch_tx: watch::Sender<u64>,
}

impl Default for CredentialRotations {
    fn default() -> Self {
        Self::new()
    }
}

/// What an announcement reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationAnnouncement {
    pub epoch: u64,
    /// Credential-bearing tunnels open to a rotated credential's endpoints.
    /// Each of them closes.
    pub tunnels: usize,
    /// Rotated binding endpoints as `host:port`, for diagnosis. Never values,
    /// placeholders or credential identities: a stable credential's identity
    /// embeds its workload placeholder handle.
    pub endpoints: Vec<String>,
}

/// Why a watched relay must close.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotatedCredential {
    /// Environment keys of the rotated credentials bound to this destination.
    /// Empty when the relay fell behind the retained history; it closes anyway.
    pub keys: Arc<[String]>,
}

impl CredentialRotations {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(RotationsInner::default()),
            epoch_tx: watch::Sender::new(0),
        }
    }

    /// Start watching rotations for one relay destination.
    ///
    /// Call this before the relay can send credential material upstream, so a
    /// rotation that lands while the relay is starting is not missed.
    #[must_use]
    pub fn watch(self: &Arc<Self>, host: &str, port: u16) -> CredentialRotationWatch {
        let endpoint = Arc::new(TunnelEndpoint {
            host: host.to_ascii_lowercase(),
            port,
        });
        let mut inner = self.inner.lock().expect("credential rotations poisoned");
        inner.tunnels.retain(|tunnel| tunnel.strong_count() > 0);
        inner.tunnels.push(Arc::downgrade(&endpoint));
        CredentialRotationWatch {
            rotations: Arc::clone(self),
            endpoint,
            captured_epoch: *self.epoch_tx.borrow(),
        }
    }

    /// Record a rotation and wake the relays bound to its endpoints.
    ///
    /// Call after the new values are installed, so a relay that reconnects
    /// after closing resolves the new value.
    pub fn announce(
        &self,
        keys: Vec<String>,
        endpoints: Vec<RotatedEndpoint>,
    ) -> RotationAnnouncement {
        let mut inner = self.inner.lock().expect("credential rotations poisoned");
        inner.tunnels.retain(|tunnel| tunnel.strong_count() > 0);
        let tunnels = inner
            .tunnels
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|tunnel| endpoints.iter().any(|endpoint| endpoint.matches(tunnel)))
            .count();
        let mut described = endpoints
            .iter()
            .map(|endpoint| format!("{}:{}", endpoint.host.source(), endpoint.port))
            .collect::<Vec<_>>();
        described.sort();
        described.dedup();
        let epoch = *self.epoch_tx.borrow() + 1;
        inner.records.push_back(RotationRecord {
            epoch,
            keys: keys.into(),
            endpoints,
        });
        while inner.records.len() > MAX_RETAINED_ROTATIONS {
            inner.records.pop_front();
        }
        // Publish while holding the lock so a relay that observes the epoch
        // always finds its record.
        self.epoch_tx.send_replace(epoch);
        RotationAnnouncement {
            epoch,
            tunnels,
            endpoints: described,
        }
    }

    fn rotated_since(&self, epoch: u64, endpoint: &TunnelEndpoint) -> Option<RotatedCredential> {
        let inner = self.inner.lock().expect("credential rotations poisoned");
        if inner
            .records
            .front()
            .is_some_and(|oldest| oldest.epoch > epoch + 1)
        {
            return Some(RotatedCredential {
                keys: Arc::from(Vec::new()),
            });
        }
        let mut keys = Vec::new();
        for record in inner.records.iter().filter(|record| record.epoch > epoch) {
            if record
                .endpoints
                .iter()
                .any(|rotated| rotated.matches(endpoint))
            {
                keys.extend(record.keys.iter().cloned());
            }
        }
        if keys.is_empty() {
            return None;
        }
        keys.sort();
        keys.dedup();
        Some(RotatedCredential { keys: keys.into() })
    }
}

/// One relay's subscription to rotations of credentials bound to its
/// destination. Dropping it stops the relay being counted as open.
#[derive(Debug)]
pub struct CredentialRotationWatch {
    rotations: Arc<CredentialRotations>,
    endpoint: Arc<TunnelEndpoint>,
    captured_epoch: u64,
}

impl CredentialRotationWatch {
    /// Resolve when a credential bound to this destination rotates.
    ///
    /// Rotations of credentials bound elsewhere are ignored, so other
    /// providers' tunnels stay open.
    pub async fn rotated(&self) -> RotatedCredential {
        let mut receiver = self.rotations.epoch_tx.subscribe();
        let mut seen = self.captured_epoch;
        loop {
            let current = *receiver.borrow_and_update();
            if current > seen {
                if let Some(rotated) = self.rotations.rotated_since(seen, &self.endpoint) {
                    return rotated;
                }
                seen = current;
            }
            if receiver.changed().await.is_err() {
                return std::future::pending().await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn endpoint(host: &str, port: u32) -> RotatedEndpoint {
        RotatedEndpoint::new(host, port).expect("valid endpoint")
    }

    async fn rotated_within(watch: &CredentialRotationWatch) -> Option<RotatedCredential> {
        tokio::time::timeout(Duration::from_millis(50), watch.rotated())
            .await
            .ok()
    }

    #[tokio::test]
    async fn rotation_wakes_only_relays_bound_to_the_rotated_endpoints() {
        let rotations = Arc::new(CredentialRotations::new());
        let slack = rotations.watch("Slack.com", 443);
        let linear = rotations.watch("api.linear.app", 443);

        let announced = rotations.announce(
            vec!["SLACK_BOT_TOKEN".to_string()],
            vec![endpoint("slack.com", 443)],
        );

        assert_eq!(announced.tunnels, 1);
        assert_eq!(
            rotated_within(&slack).await,
            Some(RotatedCredential {
                keys: Arc::from(vec!["SLACK_BOT_TOKEN".to_string()]),
            })
        );
        assert_eq!(rotated_within(&linear).await, None);
    }

    #[tokio::test]
    async fn rotation_matches_wildcard_hosts_and_requires_the_port() {
        let rotations = Arc::new(CredentialRotations::new());
        let wss = rotations.watch("wss-primary.slack.com", 443);
        let other_port = rotations.watch("wss-primary.slack.com", 8443);

        rotations.announce(
            vec!["SLACK_APP_TOKEN".to_string()],
            vec![endpoint("*.slack.com", 443)],
        );

        assert!(rotated_within(&wss).await.is_some());
        assert_eq!(rotated_within(&other_port).await, None);
    }

    #[tokio::test]
    async fn a_relay_opened_after_a_rotation_ignores_it() {
        let rotations = Arc::new(CredentialRotations::new());
        rotations.announce(
            vec!["KEY".to_string()],
            vec![endpoint("api.example.com", 443)],
        );

        let reconnected = rotations.watch("api.example.com", 443);

        assert_eq!(rotated_within(&reconnected).await, None);
    }

    #[tokio::test]
    async fn an_unrelated_rotation_does_not_hide_a_later_matching_one() {
        let rotations = Arc::new(CredentialRotations::new());
        let watch = rotations.watch("api.example.com", 443);
        rotations.announce(
            vec!["OTHER".to_string()],
            vec![endpoint("other.example.com", 443)],
        );
        assert_eq!(rotated_within(&watch).await, None);

        rotations.announce(
            vec!["KEY".to_string()],
            vec![endpoint("api.example.com", 443)],
        );

        assert_eq!(
            rotated_within(&watch).await.map(|rotated| rotated.keys),
            Some(Arc::from(vec!["KEY".to_string()]))
        );
    }

    #[tokio::test]
    async fn a_relay_behind_the_retained_history_closes() {
        let rotations = Arc::new(CredentialRotations::new());
        let watch = rotations.watch("api.example.com", 443);
        for _ in 0..=MAX_RETAINED_ROTATIONS {
            rotations.announce(
                vec!["OTHER".to_string()],
                vec![endpoint("other.example.com", 443)],
            );
        }

        assert_eq!(
            rotated_within(&watch)
                .await
                .map(|rotated| rotated.keys.len()),
            Some(0)
        );
    }

    #[test]
    fn closed_relays_are_not_counted() {
        let rotations = Arc::new(CredentialRotations::new());
        let open = rotations.watch("api.example.com", 443);
        drop(rotations.watch("api.example.com", 443));

        let announced = rotations.announce(
            vec!["KEY".to_string()],
            vec![endpoint("api.example.com", 443)],
        );

        assert_eq!(announced.tunnels, 1);
        drop(open);
    }
}
