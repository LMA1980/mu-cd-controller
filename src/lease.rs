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

/// Default maximum wall-clock duration awaiting an eligible idle target node (120 seconds).
pub const DEFAULT_IDLE_WAIT_TIMEOUT_SECS: u64 = 120;

/// Default initial backoff interval between target-node idle probes (500 ms).
pub const DEFAULT_IDLE_POLL_INITIAL_MS: u64 = 500;

/// Default upper bound on backoff interval between target-node idle probes (10 seconds).
pub const DEFAULT_IDLE_POLL_MAX_MS: u64 = 10_000;

/// Default jitter percentage `[0..=100]` applied to backoff probe intervals (20%).
pub const DEFAULT_IDLE_JITTER_PERCENT: u64 = 20;

/// Configuration for bounded contention-tolerant exponential backoff while waiting
/// for busy target nodes to drain active stages before granting a deployment lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdleBackoffConfig {
    /// Total deadline awaiting an eligible idle node before failing with [`LeaseError::NodeNotIdle`].
    pub wait_timeout: Duration,
    /// Initial delay after the first busy probe before retrying.
    pub initial_interval: Duration,
    /// Upper bound on delay between retries.
    pub max_interval: Duration,
    /// Jitter percentage `[0..=100]` around the exponential interval.
    pub jitter_percent: u64,
}

impl Default for IdleBackoffConfig {
    fn default() -> Self {
        Self {
            wait_timeout: Duration::from_secs(DEFAULT_IDLE_WAIT_TIMEOUT_SECS),
            initial_interval: Duration::from_millis(DEFAULT_IDLE_POLL_INITIAL_MS),
            max_interval: Duration::from_millis(DEFAULT_IDLE_POLL_MAX_MS),
            jitter_percent: DEFAULT_IDLE_JITTER_PERCENT,
        }
    }
}

impl IdleBackoffConfig {
    /// Builds [`IdleBackoffConfig`] from `MU_CD_CONTROLLER_IDLE_*` / `MU_CD_IDLE_*` environment
    /// variables with fallback to legacy `MUCONDE_IDLE_*` / `MUCD_IDLE_*` names and defaults.
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_env_lookup(&|key| std::env::var(key).ok())
    }

    /// Pure parser constructing [`IdleBackoffConfig`] via a caller-supplied environment lookup.
    #[must_use]
    pub fn from_env_lookup(lookup: &dyn Fn(&str) -> Option<String>) -> Self {
        let wait_secs = crate::first_non_empty_var(
            lookup,
            &[
                "MU_CD_CONTROLLER_IDLE_WAIT_TIMEOUT_SECS",
                "MU_CD_IDLE_WAIT_TIMEOUT_SECS",
                "MUCONDE_IDLE_WAIT_TIMEOUT_SECS",
                "MUCD_IDLE_WAIT_TIMEOUT_SECS",
            ],
        );
        let initial_ms = crate::first_non_empty_var(
            lookup,
            &[
                "MU_CD_CONTROLLER_IDLE_POLL_INITIAL_MS",
                "MU_CD_IDLE_POLL_INITIAL_MS",
                "MUCONDE_IDLE_POLL_INITIAL_MS",
                "MUCD_IDLE_POLL_INITIAL_MS",
            ],
        );
        let max_ms = crate::first_non_empty_var(
            lookup,
            &[
                "MU_CD_CONTROLLER_IDLE_POLL_MAX_MS",
                "MU_CD_IDLE_POLL_MAX_MS",
                "MUCONDE_IDLE_POLL_MAX_MS",
                "MUCD_IDLE_POLL_MAX_MS",
            ],
        );
        let jitter_pct = crate::first_non_empty_var(
            lookup,
            &[
                "MU_CD_CONTROLLER_IDLE_JITTER_PERCENT",
                "MU_CD_IDLE_JITTER_PERCENT",
                "MUCONDE_IDLE_JITTER_PERCENT",
                "MUCD_IDLE_JITTER_PERCENT",
            ],
        );
        Self::from_env_values(
            wait_secs.as_deref(),
            initial_ms.as_deref(),
            max_ms.as_deref(),
            jitter_pct.as_deref(),
        )
    }

    /// Pure parser constructing [`IdleBackoffConfig`] from optional string values.
    #[must_use]
    pub fn from_env_values(
        wait_timeout_secs: Option<&str>,
        initial_ms: Option<&str>,
        max_ms: Option<&str>,
        jitter_percent: Option<&str>,
    ) -> Self {
        let mut cfg = Self::default();
        if let Some(secs) = wait_timeout_secs.and_then(|s| s.trim().parse::<u64>().ok()) {
            cfg.wait_timeout = Duration::from_secs(secs);
        }
        if let Some(ms) = initial_ms.and_then(|s| s.trim().parse::<u64>().ok()) {
            cfg.initial_interval = Duration::from_millis(ms);
        }
        if let Some(ms) = max_ms.and_then(|s| s.trim().parse::<u64>().ok()) {
            cfg.max_interval = Duration::from_millis(ms);
        }
        if cfg.max_interval < cfg.initial_interval {
            cfg.max_interval = cfg.initial_interval;
        }
        if let Some(pct) = jitter_percent.and_then(|s| s.trim().parse::<u64>().ok()) {
            cfg.jitter_percent = pct.min(100);
        }
        cfg
    }

    /// Computes the unjittered exponential backoff delay for zero-based `attempt`
    /// (`initial_interval * 2^attempt`), clamped to `[initial_interval, max_interval]`.
    #[must_use]
    pub fn base_delay_for_attempt(&self, attempt: u32) -> Duration {
        let init_ms = self.initial_interval.as_millis().min(u64::MAX as u128) as u64;
        let max_ms = self
            .max_interval
            .as_millis()
            .max(init_ms as u128)
            .min(u64::MAX as u128) as u64;
        let multiplier = 1u64.checked_shl(attempt.min(30)).unwrap_or(u64::MAX);
        Duration::from_millis(init_ms.saturating_mul(multiplier).min(max_ms))
    }

    /// Computes a bounded jittered delay using caller-supplied entropy, clamped by `remaining`.
    #[must_use]
    pub fn delay_for_attempt(&self, attempt: u32, entropy: u64, remaining: Duration) -> Duration {
        let base_ms = self.base_delay_for_attempt(attempt).as_millis() as u64;
        let cap_ms = self
            .max_interval
            .as_millis()
            .max(base_ms as u128)
            .min(u64::MAX as u128) as u64;
        let jitter_pct = self.jitter_percent.min(100);
        let delay_ms = if base_ms == 0 || jitter_pct == 0 {
            base_ms
        } else {
            let span = base_ms.saturating_mul(jitter_pct) / 100;
            if span == 0 {
                base_ms
            } else {
                let min_ms = base_ms.saturating_sub(span);
                let max_ms = base_ms.saturating_add(span).min(cap_ms);
                let range = max_ms.saturating_sub(min_ms).saturating_add(1);
                min_ms.saturating_add(entropy % range)
            }
        };
        Duration::from_millis(delay_ms).min(remaining)
    }
}

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

/// Returns the opposite A/B slot (`SlotA <-> SlotB`) for symmetric rollouts.
#[must_use]
pub const fn opposite_slot(slot: DeploymentSlot) -> DeploymentSlot {
    match slot {
        DeploymentSlot::SlotA => DeploymentSlot::SlotB,
        DeploymentSlot::SlotB => DeploymentSlot::SlotA,
    }
}

/// Manages and tracks active TTL-bounded deployment leases across cluster nodes.
#[derive(Debug, Clone, Default)]
pub struct LeaseCoordinator {
    leases: Arc<RwLock<HashMap<String, ActiveLease>>>,
    /// Current active baseline slot per `(node_id, service_name)` pair.
    active_slots: Arc<RwLock<HashMap<(String, String), DeploymentSlot>>>,
}

impl LeaseCoordinator {
    /// Create a new empty `LeaseCoordinator`.
    pub fn new() -> Self {
        Self {
            leases: Arc::new(RwLock::new(HashMap::new())),
            active_slots: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Returns the currently tracked live slot for `(node_id, service_name)`,
    /// defaulting to `SlotA` before any promotion has occurred.
    pub async fn active_slot_for(&self, node_id: &str, service_name: &str) -> DeploymentSlot {
        let slots = self.active_slots.read().await;
        slots
            .get(&(node_id.to_string(), service_name.to_string()))
            .copied()
            .unwrap_or(DeploymentSlot::SlotA)
    }

    /// Explicitly updates the tracked live slot for `(node_id, service_name)`
    /// (e.g. after an emergency rollback restores the prior `@a`/`@b` slot).
    pub async fn set_active_slot(
        &self,
        node_id: impl Into<String>,
        service_name: impl Into<String>,
        slot: DeploymentSlot,
    ) {
        let mut slots = self.active_slots.write().await;
        slots.insert((node_id.into(), service_name.into()), slot);
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
        let active_slots = self.active_slots.read().await;
        let active_slot = active_slots
            .get(&(req.node_id.clone(), req.service_name.clone()))
            .copied()
            .unwrap_or(DeploymentSlot::SlotA);
        let candidate_slot = opposite_slot(active_slot);
        drop(active_slots);
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
                    active_slot,
                    candidate_slot,
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
            active_slot,
            candidate_slot,
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

    /// Reconciles an active lease's baseline (`active_slot`) and staged (`candidate_slot`)
    /// slots with the authoritative `StageDeploymentResponse::target_slot` reported by the agent.
    pub async fn reconcile_lease_slots(
        &self,
        lease_id: &str,
        active_slot: DeploymentSlot,
        candidate_slot: DeploymentSlot,
    ) -> Result<(), LeaseError> {
        let mut leases = self.leases.write().await;
        if let Some(active) = leases.get_mut(lease_id) {
            active.grant.active_slot = active_slot;
            active.grant.candidate_slot = candidate_slot;
            let mut active_slots = self.active_slots.write().await;
            active_slots.insert(
                (active.grant.node_id.clone(), active.service_name.clone()),
                active_slot,
            );
            Ok(())
        } else {
            Err(LeaseError::LeaseNotFound(lease_id.to_string()))
        }
    }

    /// Mark a deployment as successfully promoted and advance the active `@a`/`@b` slot.
    ///
    /// Once marked promoted, the lease will not trigger rollback when its TTL passes,
    /// and subsequent leases for `(node_id, service_name)` will target the opposite slot.
    pub async fn mark_promoted(&self, lease_id: &str) -> Result<(), LeaseError> {
        let mut leases = self.leases.write().await;
        if let Some(active) = leases.get_mut(lease_id) {
            active.promoted = true;
            let mut active_slots = self.active_slots.write().await;
            active_slots.insert(
                (active.grant.node_id.clone(), active.service_name.clone()),
                active.grant.candidate_slot,
            );
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
    async fn test_lease_coordinator_alternates_slots_symmetrically() {
        let coordinator = LeaseCoordinator::new();

        // Cycle 1: active @a -> stage @b -> promote -> active becomes @b
        let g1 = coordinator
            .acquire_lease(&DeploymentLeaseRequest {
                deployment_id: "dep-1".into(),
                node_id: "node-a".into(),
                service_name: "mu-cd-agent".into(),
                artifact_sha256: "sha-1".into(),
                requested_ttl_secs: 60,
            })
            .await;
        assert_eq!(g1.active_slot, DeploymentSlot::SlotA);
        assert_eq!(g1.candidate_slot, DeploymentSlot::SlotB);
        coordinator.mark_promoted(&g1.lease_id).await.unwrap();
        coordinator.release_lease(&g1.lease_id).await.unwrap();
        assert_eq!(
            coordinator.active_slot_for("node-a", "mu-cd-agent").await,
            DeploymentSlot::SlotB
        );

        // Cycle 2: active @b -> stage @a -> revoke/rollback -> restores @b
        let g2 = coordinator
            .acquire_lease(&DeploymentLeaseRequest {
                deployment_id: "dep-2".into(),
                node_id: "node-a".into(),
                service_name: "mu-cd-agent".into(),
                artifact_sha256: "sha-2".into(),
                requested_ttl_secs: 60,
            })
            .await;
        assert_eq!(g2.active_slot, DeploymentSlot::SlotB);
        assert_eq!(g2.candidate_slot, DeploymentSlot::SlotA);
        let (_rev, rb) = coordinator
            .revoke_lease(&g2.lease_id, "critical failure")
            .await
            .unwrap();
        assert_eq!(rb.restore_slot, DeploymentSlot::SlotB);
        assert_eq!(
            coordinator.active_slot_for("node-a", "mu-cd-agent").await,
            DeploymentSlot::SlotB
        );

        // Cycle 3: still active @b -> stage @a -> promote -> active becomes @a
        let g3 = coordinator
            .acquire_lease(&DeploymentLeaseRequest {
                deployment_id: "dep-3".into(),
                node_id: "node-a".into(),
                service_name: "mu-cd-agent".into(),
                artifact_sha256: "sha-3".into(),
                requested_ttl_secs: 60,
            })
            .await;
        assert_eq!(g3.active_slot, DeploymentSlot::SlotB);
        assert_eq!(g3.candidate_slot, DeploymentSlot::SlotA);
        coordinator.mark_promoted(&g3.lease_id).await.unwrap();
        coordinator.release_lease(&g3.lease_id).await.unwrap();
        assert_eq!(
            coordinator.active_slot_for("node-a", "mu-cd-agent").await,
            DeploymentSlot::SlotA
        );

        // Cycle 4: back to active @a -> stage @b
        let g4 = coordinator
            .acquire_lease(&DeploymentLeaseRequest {
                deployment_id: "dep-4".into(),
                node_id: "node-a".into(),
                service_name: "mu-cd-agent".into(),
                artifact_sha256: "sha-4".into(),
                requested_ttl_secs: 60,
            })
            .await;
        assert_eq!(g4.active_slot, DeploymentSlot::SlotA);
        assert_eq!(g4.candidate_slot, DeploymentSlot::SlotB);
        coordinator.release_lease(&g4.lease_id).await.unwrap();

        // Explicit emergency rollback slot reset
        coordinator
            .set_active_slot("node-a", "mu-cd-agent", DeploymentSlot::SlotB)
            .await;
        assert_eq!(
            coordinator.active_slot_for("node-a", "mu-cd-agent").await,
            DeploymentSlot::SlotB
        );
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

    #[test]
    fn test_idle_backoff_config_progression_jitter_and_env_parsing() {
        let cfg =
            IdleBackoffConfig::from_env_values(Some("45"), Some("100"), Some("350"), Some("20"));
        assert_eq!(cfg.wait_timeout, Duration::from_secs(45));
        assert_eq!(cfg.initial_interval, Duration::from_millis(100));
        assert_eq!(cfg.max_interval, Duration::from_millis(350));
        assert_eq!(cfg.jitter_percent, 20);

        assert_eq!(cfg.base_delay_for_attempt(0), Duration::from_millis(100));
        assert_eq!(cfg.base_delay_for_attempt(1), Duration::from_millis(200));
        assert_eq!(cfg.base_delay_for_attempt(2), Duration::from_millis(350));
        assert_eq!(cfg.base_delay_for_attempt(20), Duration::from_millis(350));

        // Jitter stays within +/- 20% and is bounded by remaining budget.
        for entropy in [0u64, 1, 17, 99, 10_000] {
            let d0 = cfg.delay_for_attempt(0, entropy, Duration::from_secs(10));
            assert!(
                d0 >= Duration::from_millis(80) && d0 <= Duration::from_millis(120),
                "unexpected attempt-0 jittered delay: {d0:?}"
            );
            let d_capped = cfg.delay_for_attempt(2, entropy, Duration::from_millis(50));
            assert_eq!(d_capped, Duration::from_millis(50));
        }

        // max_interval < initial_interval clamps cleanly, and jitter_percent clamps at 100.
        let clamped =
            IdleBackoffConfig::from_env_values(Some("0"), Some("500"), Some("100"), Some("250"));
        assert_eq!(clamped.wait_timeout, Duration::ZERO);
        assert_eq!(clamped.max_interval, Duration::from_millis(500));
        assert_eq!(clamped.jitter_percent, 100);
    }

    #[test]
    fn test_idle_backoff_config_env_precedence_and_legacy_fallback() {
        let canonical = HashMap::from([
            ("MU_CD_CONTROLLER_IDLE_WAIT_TIMEOUT_SECS", "90"),
            ("MUCONDE_IDLE_WAIT_TIMEOUT_SECS", "30"),
            ("MU_CD_IDLE_POLL_INITIAL_MS", "250"),
            ("MUCONDE_IDLE_POLL_INITIAL_MS", "500"),
            ("MU_CD_CONTROLLER_IDLE_POLL_MAX_MS", "4000"),
            ("MUCD_IDLE_POLL_MAX_MS", "9000"),
            ("MU_CD_IDLE_JITTER_PERCENT", "15"),
            ("MUCONDE_IDLE_JITTER_PERCENT", "25"),
        ]);
        let cfg = IdleBackoffConfig::from_env_lookup(&|k| canonical.get(k).map(|v| (*v).into()));
        assert_eq!(cfg.wait_timeout, Duration::from_secs(90));
        assert_eq!(cfg.initial_interval, Duration::from_millis(250));
        assert_eq!(cfg.max_interval, Duration::from_millis(4000));
        assert_eq!(cfg.jitter_percent, 15);

        let legacy = HashMap::from([
            ("MUCONDE_IDLE_WAIT_TIMEOUT_SECS", "60"),
            ("MUCD_IDLE_POLL_INITIAL_MS", "300"),
            ("MUCONDE_IDLE_POLL_MAX_MS", "2000"),
            ("MUCD_IDLE_JITTER_PERCENT", "10"),
        ]);
        let cfg_legacy =
            IdleBackoffConfig::from_env_lookup(&|k| legacy.get(k).map(|v| (*v).into()));
        assert_eq!(cfg_legacy.wait_timeout, Duration::from_secs(60));
        assert_eq!(cfg_legacy.initial_interval, Duration::from_millis(300));
        assert_eq!(cfg_legacy.max_interval, Duration::from_millis(2000));
        assert_eq!(cfg_legacy.jitter_percent, 10);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_reconcile_lease_slots_updates_grant_active_slot_and_rollback() {
        let coordinator = LeaseCoordinator::new();
        let req = DeploymentLeaseRequest {
            deployment_id: "dep-reconcile-1".into(),
            node_id: "node-a".into(),
            service_name: "svc-demo".into(),
            artifact_sha256: "sha256-1".into(),
            requested_ttl_secs: 60,
        };
        let grant = coordinator.acquire_lease(&req).await;
        assert_eq!(grant.active_slot, DeploymentSlot::SlotA);
        assert_eq!(grant.candidate_slot, DeploymentSlot::SlotB);

        // Agent reports live slot was actually SlotB and candidate was staged into SlotA.
        coordinator
            .reconcile_lease_slots(
                &grant.lease_id,
                DeploymentSlot::SlotB,
                DeploymentSlot::SlotA,
            )
            .await
            .expect("reconcile lease slots");

        let updated = coordinator.get_lease(&grant.lease_id).await.unwrap();
        assert_eq!(updated.active_slot, DeploymentSlot::SlotB);
        assert_eq!(updated.candidate_slot, DeploymentSlot::SlotA);
        assert_eq!(
            coordinator.active_slot_for("node-a", "svc-demo").await,
            DeploymentSlot::SlotB
        );

        let (_revoke, rb) = coordinator
            .revoke_lease(&grant.lease_id, "test rollback")
            .await
            .expect("revoke reconciled lease");
        assert_eq!(rb.restore_slot, DeploymentSlot::SlotB);

        // Next lease starts from reconciled SlotB -> SlotA and promotes cleanly to SlotA.
        let grant2 = coordinator.acquire_lease(&req).await;
        assert_eq!(grant2.active_slot, DeploymentSlot::SlotB);
        assert_eq!(grant2.candidate_slot, DeploymentSlot::SlotA);
        coordinator.mark_promoted(&grant2.lease_id).await.unwrap();
        assert_eq!(
            coordinator.active_slot_for("node-a", "svc-demo").await,
            DeploymentSlot::SlotA
        );
    }
}
