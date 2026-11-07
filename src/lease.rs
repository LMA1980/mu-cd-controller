//! Cluster idle worker discovery and TTL-bounded deployment lease coordination.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};

use mu_cd_ipc::{
    DeploymentLeaseGrant, DeploymentLeaseRequest, DeploymentLeaseRevoke, DeploymentSlot,
    RollbackCommand,
};

use crate::error::LeaseError;
use crate::tls::TlsConfig;

/// Default ActionRunner controller URL used across continuous delivery fabric.
pub const DEFAULT_CONTROLLER_URL: &str = "https://controller.ci.ci.internal:8443";

/// Cluster node status matching ActionRunner-controller `GET /api/cluster/nodes` response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterNodeStatus {
    pub node_id: String,
    #[serde(alias = "is_online")]
    pub online: bool,
    pub active_slots: u32,
    pub max_slots: u32,
    pub exclusive_locked: bool,
}

impl ClusterNodeStatus {
    /// Returns `true` if the node is online, has zero running stages, and is not exclusively locked.
    pub fn is_idle_for_deployment(&self) -> bool {
        self.online && self.active_slots == 0 && !self.exclusive_locked
    }
}

/// Polls ActionRunner-controller for worker node utilization and idle scheduling windows.
#[derive(Debug, Clone)]
pub struct ClusterIdlePoller {
    base_url: String,
    client: Client,
}

impl ClusterIdlePoller {
    /// Initialize with base controller URL and mTLS configuration.
    pub fn new(base_url: impl Into<String>, tls_config: &TlsConfig) -> Result<Self, LeaseError> {
        let client = tls_config
            .build_reqwest_client()
            .map_err(|e| LeaseError::Http(e.to_string()))?;

        let url = base_url.into();
        let trimmed_url = url.trim_end_matches('/').to_string();

        Ok(Self {
            base_url: trimmed_url,
            client,
        })
    }

    /// Initialize with an existing configured `reqwest::Client` (useful for mocks and custom transport).
    pub fn with_client(base_url: impl Into<String>, client: Client) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client,
        }
    }

    /// Base URL for the target controller.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Fetch all registered cluster node statuses from `GET /api/cluster/nodes`.
    pub async fn fetch_nodes(&self) -> Result<Vec<ClusterNodeStatus>, LeaseError> {
        let endpoint = format!("{}/api/cluster/nodes", self.base_url);
        let resp = self.client.get(&endpoint).send().await.map_err(|e| {
            LeaseError::Http(format!("Failed to query cluster nodes at {endpoint}: {e}"))
        })?;

        if !resp.status().is_success() {
            return Err(LeaseError::Http(format!(
                "GET {} returned unexpected HTTP status: {}",
                endpoint,
                resp.status()
            )));
        }

        let nodes: Vec<ClusterNodeStatus> = resp
            .json()
            .await
            .map_err(|e| LeaseError::Http(format!("Failed to parse cluster nodes JSON: {e}")))?;

        Ok(nodes)
    }

    /// Filter a slice of nodes, returning references to those eligible for deployment updates.
    pub fn filter_idle_nodes<'a>(
        &self,
        nodes: &'a [ClusterNodeStatus],
    ) -> Vec<&'a ClusterNodeStatus> {
        nodes
            .iter()
            .filter(|node| node.is_idle_for_deployment())
            .collect()
    }

    /// Query controller and return only nodes that are currently idle and eligible for updates.
    pub async fn fetch_idle_nodes(&self) -> Result<Vec<ClusterNodeStatus>, LeaseError> {
        let all_nodes = self.fetch_nodes().await?;
        Ok(all_nodes
            .into_iter()
            .filter(|n| n.is_idle_for_deployment())
            .collect())
    }

    /// Check if a specific named node is currently idle and eligible for deployment.
    pub async fn is_node_idle(&self, node_id: &str) -> Result<bool, LeaseError> {
        let nodes = self.fetch_nodes().await?;
        match nodes.iter().find(|n| n.node_id == node_id) {
            Some(n) => Ok(n.is_idle_for_deployment()),
            None => Err(LeaseError::NodeOffline(format!(
                "Node '{node_id}' not found in cluster"
            ))),
        }
    }
}

/// Internal tracking representation of an active deployment lease.
#[derive(Debug, Clone)]
struct ActiveLease {
    grant: DeploymentLeaseGrant,
    service_name: String,
    artifact_sha256: String,
    promoted: bool,
}

/// Manages and tracks active TTL-bounded deployment leases across cluster nodes.
#[derive(Debug, Clone, Default)]
pub struct LeaseCoordinator {
    leases: Arc<RwLock<HashMap<String, ActiveLease>>>,
}

impl LeaseCoordinator {
    /// Create a new empty `LeaseCoordinator`.
    pub fn new() -> Self {
        Self {
            leases: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Current timestamp in milliseconds since the Unix epoch.
    pub fn current_epoch_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// Request and acquire a TTL-bounded deployment lease on a target node for a service.
    ///
    /// Prevents overlapping active leases on the same `(node_id, service_name)`.
    pub async fn acquire_lease(&self, req: &DeploymentLeaseRequest) -> DeploymentLeaseGrant {
        let mut leases = self.leases.write().await;
        let now_ms = Self::current_epoch_ms();

        // Check for active overlapping leases on the same (node_id, service_name)
        for active in leases.values() {
            if active.grant.node_id == req.node_id
                && active.service_name == req.service_name
                && !active.promoted
                && active.grant.expires_at_epoch_ms > now_ms
            {
                return DeploymentLeaseGrant {
                    deployment_id: req.deployment_id.clone(),
                    lease_id: String::new(),
                    node_id: req.node_id.clone(),
                    active_slot: DeploymentSlot::SlotA,
                    candidate_slot: DeploymentSlot::SlotB,
                    expires_at_epoch_ms: 0,
                    granted: false,
                    denial_reason: Some(format!(
                        "Active unexpired lease '{}' already exists for service '{}' on node '{}'",
                        active.grant.lease_id, req.service_name, req.node_id
                    )),
                };
            }
        }

        let lease_id = format!("lease-{}", uuid::Uuid::new_v4());
        let ttl_ms = req.requested_ttl_secs.saturating_mul(1000);
        let expires_at_epoch_ms = now_ms.saturating_add(ttl_ms);

        let grant = DeploymentLeaseGrant {
            deployment_id: req.deployment_id.clone(),
            lease_id: lease_id.clone(),
            node_id: req.node_id.clone(),
            active_slot: DeploymentSlot::SlotA,
            candidate_slot: DeploymentSlot::SlotB,
            expires_at_epoch_ms,
            granted: true,
            denial_reason: None,
        };

        let active = ActiveLease {
            grant: grant.clone(),
            service_name: req.service_name.clone(),
            artifact_sha256: req.artifact_sha256.clone(),
            promoted: false,
        };

        leases.insert(lease_id, active);
        grant
    }

    /// Mark a deployment as successfully promoted.
    ///
    /// Once marked promoted, the lease will not trigger rollback when its TTL passes,
    /// and it can be released cleanly.
    pub async fn mark_promoted(&self, lease_id: &str) -> Result<(), LeaseError> {
        let mut leases = self.leases.write().await;
        if let Some(active) = leases.get_mut(lease_id) {
            active.promoted = true;
            Ok(())
        } else {
            Err(LeaseError::LeaseNotFound(lease_id.to_string()))
        }
    }

    /// Release and remove a completed lease from the tracking registry.
    pub async fn release_lease(&self, lease_id: &str) -> Result<(), LeaseError> {
        let mut leases = self.leases.write().await;
        if leases.remove(lease_id).is_some() {
            Ok(())
        } else {
            Err(LeaseError::LeaseNotFound(lease_id.to_string()))
        }
    }

    /// Retrieve a copy of a grant by lease ID if it exists.
    pub async fn get_lease(&self, lease_id: &str) -> Option<DeploymentLeaseGrant> {
        let leases = self.leases.read().await;
        leases.get(lease_id).map(|a| a.grant.clone())
    }

    /// Snapshot of every tracked lease for the read-only CD API.
    pub async fn list_leases(&self) -> Vec<crate::cd_state::LeaseView> {
        let now = Self::current_epoch_ms();
        let leases = self.leases.read().await;
        let mut out: Vec<crate::cd_state::LeaseView> = leases
            .values()
            .map(|a| crate::cd_state::LeaseView {
                lease_id: a.grant.lease_id.clone(),
                deployment_id: a.grant.deployment_id.clone(),
                target_node: a.grant.node_id.clone(),
                service: a.service_name.clone(),
                artifact_digest: a.artifact_sha256.clone(),
                active_slot: a.grant.active_slot.into(),
                candidate_slot: a.grant.candidate_slot.into(),
                expires_epoch_ms: a.grant.expires_at_epoch_ms,
                ttl_remaining_ms: a.grant.expires_at_epoch_ms.saturating_sub(now),
                promoted: a.promoted,
            })
            .collect();
        out.sort_by(|a, b| a.lease_id.cmp(&b.lease_id));
        out
    }

    /// Explicitly revoke an active lease, returning revocation and rollback commands.
    pub async fn revoke_lease(
        &self,
        lease_id: &str,
        reason: &str,
    ) -> Result<(DeploymentLeaseRevoke, RollbackCommand), LeaseError> {
        let mut leases = self.leases.write().await;
        let active = leases
            .remove(lease_id)
            .ok_or_else(|| LeaseError::LeaseNotFound(lease_id.to_string()))?;

        let revoke = DeploymentLeaseRevoke {
            deployment_id: active.grant.deployment_id.clone(),
            lease_id: active.grant.lease_id.clone(),
            reason: reason.to_string(),
        };

        let rollback = RollbackCommand {
            deployment_id: active.grant.deployment_id.clone(),
            lease_id: active.grant.lease_id.clone(),
            service_name: active.service_name.clone(),
            restore_slot: active.grant.active_slot,
            failed_artifact_sha256: active.artifact_sha256.clone(),
            reason: reason.to_string(),
        };

        Ok((revoke, rollback))
    }

    /// Sweep and evict any leases whose expiration epoch has passed and were not promoted.
    ///
    /// For every expired unpromoted lease, generates an auto-revoke event and an
    /// autonomous RollbackCommand to restore the baseline slot.
    pub async fn sweep_expired_leases(&self) -> Vec<(DeploymentLeaseRevoke, RollbackCommand)> {
        let mut leases = self.leases.write().await;
        let now_ms = Self::current_epoch_ms();

        let mut expired_ids = Vec::new();
        for (id, active) in leases.iter() {
            if !active.promoted && active.grant.expires_at_epoch_ms <= now_ms {
                expired_ids.push(id.clone());
            }
        }

        let mut revocations = Vec::new();
        for id in expired_ids {
            if let Some(active) = leases.remove(&id) {
                let reason = format!(
                    "Lease '{}' TTL expired before promotion (expired at {} ms, now is {} ms)",
                    active.grant.lease_id, active.grant.expires_at_epoch_ms, now_ms
                );

                let revoke = DeploymentLeaseRevoke {
                    deployment_id: active.grant.deployment_id.clone(),
                    lease_id: active.grant.lease_id.clone(),
                    reason: reason.clone(),
                };

                let rollback = RollbackCommand {
                    deployment_id: active.grant.deployment_id.clone(),
                    lease_id: active.grant.lease_id.clone(),
                    service_name: active.service_name.clone(),
                    restore_slot: active.grant.active_slot,
                    failed_artifact_sha256: active.artifact_sha256.clone(),
                    reason,
                };

                revocations.push((revoke, rollback));
            }
        }

        revocations
    }

    /// Spawns a background task that periodically sweeps expired leases and delivers
    /// the revocation/rollback pairs to an async channel.
    pub fn spawn_expiration_watcher(
        self: Arc<Self>,
        sweep_interval: Duration,
        sender: mpsc::Sender<(DeploymentLeaseRevoke, RollbackCommand)>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(sweep_interval);
            loop {
                ticker.tick().await;
                let swept = self.sweep_expired_leases().await;
                for item in swept {
                    if sender.send(item).await.is_err() {
                        tracing::warn!(
                            "Lease expiration watcher receiver dropped; stopping watcher"
                        );
                        return;
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cluster_node_status_idle_filtering() {
        let node_idle = ClusterNodeStatus {
            node_id: "node-a".to_string(),
            online: true,
            active_slots: 0,
            max_slots: 1,
            exclusive_locked: false,
        };
        assert!(node_idle.is_idle_for_deployment());

        let node_offline = ClusterNodeStatus {
            node_id: "node-b".to_string(),
            online: false,
            active_slots: 0,
            max_slots: 1,
            exclusive_locked: false,
        };
        assert!(!node_offline.is_idle_for_deployment());

        let node_busy = ClusterNodeStatus {
            node_id: "node-c".to_string(),
            online: true,
            active_slots: 1,
            max_slots: 1,
            exclusive_locked: false,
        };
        assert!(!node_busy.is_idle_for_deployment());

        let node_locked = ClusterNodeStatus {
            node_id: "node-d".to_string(),
            online: true,
            active_slots: 0,
            max_slots: 1,
            exclusive_locked: true,
        };
        assert!(!node_locked.is_idle_for_deployment());

        let poller =
            ClusterIdlePoller::with_client("http://127.0.0.1:8080", reqwest::Client::new());

        let nodes = vec![node_idle.clone(), node_offline, node_busy, node_locked];

        let filtered = poller.filter_idle_nodes(&nodes);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].node_id, "node-a");
    }

    #[test]
    fn test_deserialize_cluster_node_with_is_online_alias() {
        let json = r#"[
            {"node_id":"worker-riscv64","is_online":true,"active_slots":0,"max_slots":1,"exclusive_locked":false},
            {"node_id":"worker-x86","is_online":false,"active_slots":0,"max_slots":1,"exclusive_locked":false}
        ]"#;

        let statuses: Vec<ClusterNodeStatus> = serde_json::from_str(json).unwrap();
        assert_eq!(statuses.len(), 2);
        assert!(statuses[0].online);
        assert!(!statuses[1].online);
        assert!(statuses[0].is_idle_for_deployment());
        assert!(!statuses[1].is_idle_for_deployment());
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_lease_coordinator_acquire_and_prevent_overlap() {
        let coordinator = LeaseCoordinator::new();

        let req1 = DeploymentLeaseRequest {
            deployment_id: "dep-1".to_string(),
            node_id: "node-a".to_string(),
            service_name: "action-runner".to_string(),
            artifact_sha256: "sha-abc-123".to_string(),
            requested_ttl_secs: 10,
        };

        let grant1 = coordinator.acquire_lease(&req1).await;
        assert!(grant1.granted);
        assert!(!grant1.lease_id.is_empty());
        assert_eq!(grant1.active_slot, DeploymentSlot::SlotA);
        assert_eq!(grant1.candidate_slot, DeploymentSlot::SlotB);

        // Attempt second lease on identical (node_id, service_name) before first expires
        let req2 = DeploymentLeaseRequest {
            deployment_id: "dep-2".to_string(),
            node_id: "node-a".to_string(),
            service_name: "action-runner".to_string(),
            artifact_sha256: "sha-def-456".to_string(),
            requested_ttl_secs: 10,
        };

        let grant2 = coordinator.acquire_lease(&req2).await;
        assert!(!grant2.granted);
        assert!(grant2.denial_reason.is_some());
        assert!(grant2.denial_reason.unwrap().contains("already exists"));

        // Second lease on different node succeeds
        let req3 = DeploymentLeaseRequest {
            deployment_id: "dep-3".to_string(),
            node_id: "node-b".to_string(),
            service_name: "action-runner".to_string(),
            artifact_sha256: "sha-def-456".to_string(),
            requested_ttl_secs: 10,
        };
        let grant3 = coordinator.acquire_lease(&req3).await;
        assert!(grant3.granted);

        // Release first lease, now req2 succeeds
        coordinator.release_lease(&grant1.lease_id).await.unwrap();
        let grant4 = coordinator.acquire_lease(&req2).await;
        assert!(grant4.granted);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_lease_auto_expires_and_emits_revoke_and_rollback() {
        let coordinator = Arc::new(LeaseCoordinator::new());

        // Create lease with 0-second TTL (expires immediately)
        let req = DeploymentLeaseRequest {
            deployment_id: "dep-expire".to_string(),
            node_id: "node-a".to_string(),
            service_name: "action-runner".to_string(),
            artifact_sha256: "sha-fail-123".to_string(),
            requested_ttl_secs: 0,
        };

        let grant = coordinator.acquire_lease(&req).await;
        assert!(grant.granted);

        // Small sleep to ensure epoch_ms <= now_ms
        tokio::time::sleep(Duration::from_millis(10)).await;

        let swept = coordinator.sweep_expired_leases().await;
        assert_eq!(swept.len(), 1);

        let (revoke, rollback) = &swept[0];
        assert_eq!(revoke.deployment_id, "dep-expire");
        assert_eq!(revoke.lease_id, grant.lease_id);
        assert!(revoke.reason.contains("TTL expired"));

        assert_eq!(rollback.deployment_id, "dep-expire");
        assert_eq!(rollback.lease_id, grant.lease_id);
        assert_eq!(rollback.service_name, "action-runner");
        assert_eq!(rollback.restore_slot, DeploymentSlot::SlotA);
        assert_eq!(rollback.failed_artifact_sha256, "sha-fail-123");
        assert!(rollback.reason.contains("TTL expired"));

        // Sweeping again finds no remaining expired leases
        let swept2 = coordinator.sweep_expired_leases().await;
        assert!(swept2.is_empty());
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_promoted_lease_is_not_rolled_back_on_expiration() {
        let coordinator = Arc::new(LeaseCoordinator::new());

        let req = DeploymentLeaseRequest {
            deployment_id: "dep-promote".to_string(),
            node_id: "node-a".to_string(),
            service_name: "action-runner".to_string(),
            artifact_sha256: "sha-ok-123".to_string(),
            requested_ttl_secs: 0,
        };

        let grant = coordinator.acquire_lease(&req).await;
        assert!(grant.granted);

        // Mark as promoted
        coordinator.mark_promoted(&grant.lease_id).await.unwrap();

        tokio::time::sleep(Duration::from_millis(10)).await;

        let swept = coordinator.sweep_expired_leases().await;
        assert!(swept.is_empty());
    }
}
