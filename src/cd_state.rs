//! Read-only continuous-delivery state published to the `/api/cd/*` HTTP API.
//!
//! Writers (the [`crate::orchestrator::DeploymentOrchestrator`], the lease coordinator mirror and
//! the agent IPC reader forwarding `IntegrationTestProgress`) mutate a private [`CdState`] and
//! publish an immutable [`CdSnapshot`] behind an `Arc`. HTTP handlers only ever clone that `Arc`,
//! so reads never block writers for longer than a pointer swap. Every change is also broadcast as
//! a [`CdEvent`] for the SSE stream.
//!
//! JSON field names mirror the MuConsole data-worker DTOs (`snake_case` fields and enums, Unix
//! epoch milliseconds).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, RwLock};

use mu_cd_ipc::{
    DeploymentLeaseGrant, DeploymentSlot, IntegrationTestProgress, IntegrationTestReport, TestState,
};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// Default number of deployments kept for the history strip.
pub const DEFAULT_HISTORY_LIMIT: usize = 256;

/// Default SSE broadcast buffer; a consumer lagging further behind is dropped.
pub const DEFAULT_EVENT_BUFFER: usize = 1024;

/// Receives per-test progress from the agent IPC reader.
pub trait ItProgressSink: Send + Sync {
    fn on_it_progress(&self, progress: &IntegrationTestProgress);
}

/// A/B slot in API form (`"a"` / `"b"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Slot {
    #[default]
    A,
    B,
}

impl From<DeploymentSlot> for Slot {
    fn from(s: DeploymentSlot) -> Self {
        match s {
            DeploymentSlot::SlotA => Self::A,
            DeploymentSlot::SlotB => Self::B,
        }
    }
}

/// Outcome of a deployment's integration gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateOutcome {
    /// Gate still running (or not started).
    #[default]
    Pending,
    Promoted,
    RolledBack,
    /// Refused or rolled back and the digest is tainted.
    Tainted,
}

/// Why a deployment was rolled back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackReason {
    /// A critical integration test, health probe, staging, swap or SLO verification failed.
    CriticalTestFailed,
    /// The deployment lease TTL expired before promotion.
    LeaseExpired,
    /// Operator- or coordinator-initiated revocation.
    Manual,
}

/// Live verdict of the gate state machine (computed per request).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateVerdict {
    /// Not decided yet.
    Pending,
    /// Every critical test passed: `PROMOTE` lights.
    Promote,
    /// A critical test failed or the lease expired: `ROLLBACK` lights.
    Rollback,
}

/// One integration test of a gate (`tests[]` of `GET /api/cd/deployments/{id}/gate`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateTestView {
    pub name: String,
    /// `[C]` flag: a failure rolls the deployment back.
    pub critical: bool,
    pub state: TestState,
    pub duration_ms: u64,
    pub crate_name: Option<String>,
    pub log_excerpt: Option<String>,
}

/// Internal record for one deployment. Derived fields are computed at response time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentRecord {
    pub deployment_id: String,
    pub owner: String,
    pub repo: String,
    pub service: String,
    pub artifact_digest: String,
    pub target_node: String,
    pub active_slot: Slot,
    pub staged_slot: Slot,
    pub restore_slot: Slot,
    pub lease_id: String,
    pub lease_expires_epoch_ms: u64,
    pub lease_expired: bool,
    pub outcome: GateOutcome,
    pub rollback_reason: Option<RollbackReason>,
    pub rollback_detail: Option<String>,
    pub tainted: bool,
    pub started_epoch_ms: u64,
    pub finished_epoch_ms: Option<u64>,
    pub tests: Vec<GateTestView>,
}

/// Inputs recorded when a deployment acquires its lease.
#[derive(Debug, Clone)]
pub struct DeploymentStart {
    pub deployment_id: String,
    /// `owner/repo` of the source repository, when known.
    pub repo: Option<String>,
    pub service: String,
    pub artifact_digest: String,
    pub target_node: String,
    pub active_slot: Slot,
    pub staged_slot: Slot,
    pub restore_slot: Slot,
    pub lease_id: String,
    pub lease_expires_epoch_ms: u64,
    /// Contract test list in order; empty for `"all"` (filled by the agent's `Pending` frames).
    pub tests: Vec<(String, bool)>,
}

impl DeploymentStart {
    /// Builds the start record from a lease grant.
    pub fn from_grant(
        grant: &DeploymentLeaseGrant,
        repo: Option<String>,
        service: &str,
        artifact_digest: &str,
        target_node: &str,
        tests: Vec<(String, bool)>,
    ) -> Self {
        Self {
            deployment_id: grant.deployment_id.clone(),
            repo,
            service: service.to_string(),
            artifact_digest: artifact_digest.to_string(),
            target_node: target_node.to_string(),
            active_slot: grant.active_slot.into(),
            staged_slot: grant.candidate_slot.into(),
            restore_slot: grant.active_slot.into(),
            lease_id: grant.lease_id.clone(),
            lease_expires_epoch_ms: grant.expires_at_epoch_ms,
            tests,
        }
    }
}

/// Snapshot of one active lease (`GET /api/cd/leases`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseView {
    pub lease_id: String,
    pub deployment_id: String,
    pub target_node: String,
    pub service: String,
    pub artifact_digest: String,
    pub active_slot: Slot,
    pub candidate_slot: Slot,
    pub expires_epoch_ms: u64,
    /// Remaining TTL at response time (0 once expired).
    pub ttl_remaining_ms: u64,
    pub promoted: bool,
}

/// Immutable published state.
#[derive(Debug, Clone, Default)]
pub struct CdSnapshot {
    /// Monotonic revision, bumped on every publish.
    pub rev: u64,
    /// Newest first, bounded by the history limit.
    pub deployments: Vec<DeploymentRecord>,
    pub leases: Vec<LeaseView>,
}

impl CdSnapshot {
    pub fn deployment(&self, deployment_id: &str) -> Option<&DeploymentRecord> {
        self.deployments
            .iter()
            .find(|d| d.deployment_id == deployment_id)
    }
}

/// SSE `event: it_progress`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItProgressEvent {
    pub deployment_id: String,
    pub test_name: String,
    pub critical: bool,
    pub state: TestState,
    pub duration_ms: u64,
    pub timestamp_epoch_ms: u64,
}

/// SSE `event: promoted`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotedEvent {
    pub deployment_id: String,
    /// Slot now serving traffic.
    pub slot: Slot,
}

/// SSE `event: rolled_back`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolledBackEvent {
    pub deployment_id: String,
    pub restore_slot: Slot,
    pub reason: RollbackReason,
    pub detail: String,
}

/// SSE `event: tainted`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintedEvent {
    pub deployment_id: String,
    pub artifact_digest: String,
    pub reason: String,
}

/// SSE `event: lease_expired`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseExpiredEvent {
    pub deployment_id: String,
    pub lease_id: String,
}

/// One change broadcast to `/api/cd/events` subscribers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CdEvent {
    ItProgress(ItProgressEvent),
    Promoted(PromotedEvent),
    RolledBack(RolledBackEvent),
    Tainted(TaintedEvent),
    LeaseExpired(LeaseExpiredEvent),
}

impl CdEvent {
    /// SSE `event:` name.
    pub fn event_name(&self) -> &'static str {
        match self {
            Self::ItProgress(_) => "it_progress",
            Self::Promoted(_) => "promoted",
            Self::RolledBack(_) => "rolled_back",
            Self::Tainted(_) => "tainted",
            Self::LeaseExpired(_) => "lease_expired",
        }
    }

    /// SSE `data:` JSON payload.
    pub fn to_json(&self) -> String {
        let r = match self {
            Self::ItProgress(e) => serde_json::to_string(e),
            Self::Promoted(e) => serde_json::to_string(e),
            Self::RolledBack(e) => serde_json::to_string(e),
            Self::Tainted(e) => serde_json::to_string(e),
            Self::LeaseExpired(e) => serde_json::to_string(e),
        };
        r.unwrap_or_else(|_| "{}".to_string())
    }
}

/// Gate state machine: promote when every critical test passed; roll back when any critical
/// test failed or the lease expired.
///
/// With no critical tests, the gate promotes once every test reached a terminal state. An empty
/// test list stays `Pending` (the agent has not announced its tests yet).
pub fn evaluate_gate(tests: &[GateTestView], lease_expired: bool) -> GateVerdict {
    if lease_expired
        || tests
            .iter()
            .any(|t| t.critical && t.state == TestState::Failed)
    {
        return GateVerdict::Rollback;
    }
    if tests.is_empty() {
        return GateVerdict::Pending;
    }
    let has_critical = tests.iter().any(|t| t.critical);
    let ready = if has_critical {
        tests
            .iter()
            .filter(|t| t.critical)
            .all(|t| t.state == TestState::Passed)
    } else {
        tests.iter().all(|t| t.state.is_terminal())
    };
    if ready {
        GateVerdict::Promote
    } else {
        GateVerdict::Pending
    }
}

/// Classifies an orchestrator rollback reason string.
pub fn classify_rollback_reason(reason: &str) -> RollbackReason {
    let lower = reason.to_ascii_lowercase();
    if lower.contains("lease") && (lower.contains("expired") || lower.contains("ttl")) {
        RollbackReason::LeaseExpired
    } else if lower.contains("revoke") || lower.contains("manual") {
        RollbackReason::Manual
    } else {
        RollbackReason::CriticalTestFailed
    }
}

fn split_repo(repo: Option<&str>) -> (String, String) {
    match repo {
        Some(r) => match r.split_once('/') {
            Some((o, n)) => (o.to_string(), n.to_string()),
            None => (String::new(), r.to_string()),
        },
        None => (String::new(), String::new()),
    }
}

/// Current Unix epoch milliseconds.
pub fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Default)]
struct CdState {
    rev: u64,
    deployments: VecDeque<DeploymentRecord>,
    leases: Vec<LeaseView>,
}

/// Mutable CD state with an `Arc` snapshot publisher and SSE broadcaster.
#[derive(Debug)]
pub struct CdStateStore {
    inner: Mutex<CdState>,
    snapshot: RwLock<Arc<CdSnapshot>>,
    events: broadcast::Sender<CdEvent>,
    history_limit: usize,
}

impl Default for CdStateStore {
    fn default() -> Self {
        Self::new(DEFAULT_HISTORY_LIMIT, DEFAULT_EVENT_BUFFER)
    }
}

impl CdStateStore {
    pub fn new(history_limit: usize, event_buffer: usize) -> Self {
        let (events, _) = broadcast::channel(event_buffer.max(1));
        Self {
            inner: Mutex::new(CdState::default()),
            snapshot: RwLock::new(Arc::new(CdSnapshot::default())),
            events,
            history_limit: history_limit.max(1),
        }
    }

    /// Cheap read-only view (an `Arc` clone).
    pub fn snapshot(&self) -> Arc<CdSnapshot> {
        self.snapshot
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Number of live SSE subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.events.receiver_count()
    }

    /// New SSE subscriber.
    pub fn subscribe(&self) -> broadcast::Receiver<CdEvent> {
        self.events.subscribe()
    }

    fn mutate<R>(&self, f: impl FnOnce(&mut CdState) -> R) -> R {
        let mut st = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let r = f(&mut st);
        st.rev += 1;
        let snap = Arc::new(CdSnapshot {
            rev: st.rev,
            deployments: st.deployments.iter().cloned().collect(),
            leases: st.leases.clone(),
        });
        *self.snapshot.write().unwrap_or_else(|e| e.into_inner()) = snap;
        r
    }

    fn emit(&self, ev: CdEvent) {
        // No subscribers is fine.
        let _ = self.events.send(ev);
    }

    fn find<'a>(st: &'a mut CdState, id: &str) -> Option<&'a mut DeploymentRecord> {
        st.deployments.iter_mut().find(|d| d.deployment_id == id)
    }

    /// Records a new deployment (after the lease grant).
    pub fn deployment_started(&self, start: DeploymentStart) {
        let (owner, repo) = split_repo(start.repo.as_deref());
        let record = DeploymentRecord {
            deployment_id: start.deployment_id,
            owner,
            repo,
            service: start.service,
            artifact_digest: start.artifact_digest,
            target_node: start.target_node,
            active_slot: start.active_slot,
            staged_slot: start.staged_slot,
            restore_slot: start.restore_slot,
            lease_id: start.lease_id,
            lease_expires_epoch_ms: start.lease_expires_epoch_ms,
            lease_expired: false,
            outcome: GateOutcome::Pending,
            rollback_reason: None,
            rollback_detail: None,
            tainted: false,
            started_epoch_ms: now_epoch_ms(),
            finished_epoch_ms: None,
            tests: start
                .tests
                .into_iter()
                .map(|(name, critical)| GateTestView {
                    name,
                    critical,
                    state: TestState::Pending,
                    duration_ms: 0,
                    crate_name: None,
                    log_excerpt: None,
                })
                .collect(),
        };
        let limit = self.history_limit;
        self.mutate(|st| {
            st.deployments
                .retain(|d| d.deployment_id != record.deployment_id);
            st.deployments.push_front(record);
            st.deployments.truncate(limit);
        });
    }

    /// Applies one `IntegrationTestProgress` update and broadcasts `it_progress`.
    pub fn apply_it_progress(&self, p: &IntegrationTestProgress) {
        let limit = self.history_limit;
        self.mutate(|st| {
            if Self::find(st, &p.deployment_id).is_none() {
                // Progress for a deployment this controller did not start (e.g. after a
                // restart): keep a minimal record so the gate is still visible.
                st.deployments.push_front(DeploymentRecord {
                    deployment_id: p.deployment_id.clone(),
                    owner: String::new(),
                    repo: String::new(),
                    service: String::new(),
                    artifact_digest: String::new(),
                    target_node: String::new(),
                    active_slot: Slot::A,
                    staged_slot: Slot::B,
                    restore_slot: Slot::A,
                    lease_id: String::new(),
                    lease_expires_epoch_ms: 0,
                    lease_expired: false,
                    outcome: GateOutcome::Pending,
                    rollback_reason: None,
                    rollback_detail: None,
                    tainted: false,
                    started_epoch_ms: p.timestamp_epoch_ms,
                    finished_epoch_ms: None,
                    tests: Vec::new(),
                });
                st.deployments.truncate(limit);
            }
            if let Some(d) = Self::find(st, &p.deployment_id) {
                match d.tests.iter_mut().find(|t| t.name == p.test_name) {
                    Some(t) => {
                        // Never regress a terminal state on a late/out-of-order frame.
                        if !(t.state.is_terminal() && !p.state.is_terminal()) {
                            t.state = p.state;
                            t.duration_ms = p.duration_ms;
                        }
                        t.critical = p.critical;
                    }
                    None => d.tests.push(GateTestView {
                        name: p.test_name.clone(),
                        critical: p.critical,
                        state: p.state,
                        duration_ms: p.duration_ms,
                        crate_name: None,
                        log_excerpt: None,
                    }),
                }
            }
        });
        self.emit(CdEvent::ItProgress(ItProgressEvent {
            deployment_id: p.deployment_id.clone(),
            test_name: p.test_name.clone(),
            critical: p.critical,
            state: p.state,
            duration_ms: p.duration_ms,
            timestamp_epoch_ms: p.timestamp_epoch_ms,
        }));
    }

    /// Reconciles the final aggregate `IntegrationTestReport` (also covers 0.1.x agents that
    /// send no progress frames).
    pub fn apply_it_report(&self, r: &IntegrationTestReport) {
        self.mutate(|st| {
            let Some(d) = Self::find(st, &r.deployment_id) else {
                return;
            };
            for name in &r.executed_tests {
                if name == "all" || d.tests.iter().any(|t| &t.name == name) {
                    continue;
                }
                d.tests.push(GateTestView {
                    name: name.clone(),
                    critical: true,
                    state: TestState::Pending,
                    duration_ms: 0,
                    crate_name: None,
                    log_excerpt: None,
                });
            }
            for t in d.tests.iter_mut() {
                let named_failure = r.failed_tests.iter().any(|f| f == &t.name);
                if named_failure {
                    t.state = TestState::Failed;
                } else if !t.state.is_terminal() {
                    t.state = if r.passed {
                        TestState::Passed
                    } else {
                        TestState::Failed
                    };
                }
                if t.state == TestState::Failed && t.log_excerpt.is_none() {
                    t.log_excerpt = r.log_excerpt.clone();
                }
            }
        });
    }

    /// Records a promotion and broadcasts `promoted`.
    pub fn deployment_promoted(&self, deployment_id: &str, slot: Slot) {
        self.mutate(|st| {
            if let Some(d) = Self::find(st, deployment_id) {
                d.outcome = GateOutcome::Promoted;
                d.active_slot = slot;
                d.finished_epoch_ms = Some(now_epoch_ms());
            }
        });
        self.emit(CdEvent::Promoted(PromotedEvent {
            deployment_id: deployment_id.to_string(),
            slot,
        }));
    }

    /// Records a rollback and broadcasts `rolled_back`.
    pub fn deployment_rolled_back(
        &self,
        deployment_id: &str,
        restore_slot: Slot,
        reason: RollbackReason,
        detail: &str,
    ) {
        self.mutate(|st| {
            if let Some(d) = Self::find(st, deployment_id) {
                if d.outcome != GateOutcome::Tainted {
                    d.outcome = GateOutcome::RolledBack;
                }
                d.active_slot = restore_slot;
                d.restore_slot = restore_slot;
                d.rollback_reason = Some(reason);
                d.rollback_detail = Some(detail.to_string());
                if reason == RollbackReason::LeaseExpired {
                    d.lease_expired = true;
                }
                d.finished_epoch_ms = Some(now_epoch_ms());
            }
        });
        self.emit(CdEvent::RolledBack(RolledBackEvent {
            deployment_id: deployment_id.to_string(),
            restore_slot,
            reason,
            detail: detail.to_string(),
        }));
    }

    /// Records a digest taint and broadcasts `tainted`.
    pub fn deployment_tainted(&self, deployment_id: &str, artifact_digest: &str, reason: &str) {
        self.mutate(|st| {
            if let Some(d) = Self::find(st, deployment_id) {
                d.tainted = true;
            }
        });
        self.emit(CdEvent::Tainted(TaintedEvent {
            deployment_id: deployment_id.to_string(),
            artifact_digest: artifact_digest.to_string(),
            reason: reason.to_string(),
        }));
    }

    /// Records a lease expiry from the coordinator sweep and broadcasts `lease_expired`.
    pub fn lease_expired(&self, deployment_id: &str, lease_id: &str) {
        self.mutate(|st| {
            if let Some(d) = Self::find(st, deployment_id) {
                d.lease_expired = true;
            }
            st.leases.retain(|l| l.lease_id != lease_id);
        });
        self.emit(CdEvent::LeaseExpired(LeaseExpiredEvent {
            deployment_id: deployment_id.to_string(),
            lease_id: lease_id.to_string(),
        }));
    }

    /// Replaces the lease table (fed from [`crate::lease::LeaseCoordinator::list_leases`]).
    ///
    /// Skips publishing when nothing but the TTL countdown changed (the API recomputes
    /// `ttl_remaining_ms` per request), so the periodic mirror does not churn snapshots.
    pub fn set_leases(&self, leases: Vec<LeaseView>) {
        let key = |l: &LeaseView| {
            (
                l.lease_id.clone(),
                l.deployment_id.clone(),
                l.expires_epoch_ms,
                l.promoted,
            )
        };
        {
            let snap = self.snapshot();
            if snap.leases.len() == leases.len()
                && snap
                    .leases
                    .iter()
                    .zip(leases.iter())
                    .all(|(a, b)| key(a) == key(b))
            {
                return;
            }
        }
        self.mutate(|st| st.leases = leases);
    }
}

impl ItProgressSink for CdStateStore {
    fn on_it_progress(&self, progress: &IntegrationTestProgress) {
        self.apply_it_progress(progress);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(name: &str, critical: bool, state: TestState) -> GateTestView {
        GateTestView {
            name: name.into(),
            critical,
            state,
            duration_ms: 0,
            crate_name: None,
            log_excerpt: None,
        }
    }

    fn start(id: &str, tests: Vec<(String, bool)>) -> DeploymentStart {
        DeploymentStart {
            deployment_id: id.into(),
            repo: Some("LMA1980/example".into()),
            service: "example".into(),
            artifact_digest: "sha256:abc".into(),
            target_node: "node-a".into(),
            active_slot: Slot::A,
            staged_slot: Slot::B,
            restore_slot: Slot::A,
            lease_id: "lease-1".into(),
            lease_expires_epoch_ms: now_epoch_ms() + 60_000,
            tests,
        }
    }

    fn progress(id: &str, name: &str, critical: bool, state: TestState) -> IntegrationTestProgress {
        IntegrationTestProgress {
            deployment_id: id.into(),
            test_name: name.into(),
            critical,
            state,
            duration_ms: 7,
            timestamp_epoch_ms: 1,
        }
    }

    #[test]
    fn test_evaluate_gate() {
        use TestState::*;
        assert_eq!(evaluate_gate(&[], false), GateVerdict::Pending);
        assert_eq!(evaluate_gate(&[], true), GateVerdict::Rollback);
        assert_eq!(
            evaluate_gate(&[t("a", true, Passed), t("b", false, Running)], false),
            GateVerdict::Promote
        );
        assert_eq!(
            evaluate_gate(&[t("a", true, Passed), t("b", true, Running)], false),
            GateVerdict::Pending
        );
        assert_eq!(
            evaluate_gate(&[t("a", true, Failed), t("b", true, Passed)], false),
            GateVerdict::Rollback
        );
        assert_eq!(
            evaluate_gate(&[t("a", false, Failed), t("b", true, Passed)], false),
            GateVerdict::Promote
        );
        assert_eq!(
            evaluate_gate(&[t("a", false, Failed), t("b", false, Running)], false),
            GateVerdict::Pending
        );
        assert_eq!(
            evaluate_gate(&[t("a", false, Failed), t("b", false, Passed)], false),
            GateVerdict::Promote
        );
        assert_eq!(
            evaluate_gate(&[t("a", true, Passed)], true),
            GateVerdict::Rollback
        );
    }

    #[test]
    fn test_classify_rollback_reason() {
        assert_eq!(
            classify_rollback_reason("Lease TTL expired before integration tests completed"),
            RollbackReason::LeaseExpired
        );
        assert_eq!(
            classify_rollback_reason("Integration tests failed: [\"x\"]"),
            RollbackReason::CriticalTestFailed
        );
        assert_eq!(
            classify_rollback_reason("Lease revoked by operator"),
            RollbackReason::Manual
        );
    }

    #[test]
    fn test_progress_updates_snapshot_and_broadcasts() {
        let store = CdStateStore::default();
        let mut rx = store.subscribe();
        store.deployment_started(start("dep-1", vec![("smoke".into(), true)]));
        let rev0 = store.snapshot().rev;

        store.apply_it_progress(&progress("dep-1", "smoke", true, TestState::Running));
        store.apply_it_progress(&progress("dep-1", "extra", false, TestState::Pending));
        store.apply_it_progress(&progress("dep-1", "smoke", true, TestState::Passed));
        // Late Running must not regress Passed.
        store.apply_it_progress(&progress("dep-1", "smoke", true, TestState::Running));

        let snap = store.snapshot();
        assert!(snap.rev > rev0);
        let d = snap.deployment("dep-1").unwrap();
        assert_eq!(d.owner, "LMA1980");
        assert_eq!(d.repo, "example");
        assert_eq!(d.tests.len(), 2);
        assert_eq!(d.tests[0].state, TestState::Passed);
        assert_eq!(d.tests[1].name, "extra");
        assert_eq!(evaluate_gate(&d.tests, false), GateVerdict::Promote);

        let ev = rx.try_recv().unwrap();
        assert_eq!(ev.event_name(), "it_progress");
        assert!(ev.to_json().contains("\"state\":\"running\""));
    }

    #[test]
    fn test_unknown_deployment_progress_creates_minimal_record() {
        let store = CdStateStore::default();
        store.on_it_progress(&progress("dep-x", "a", true, TestState::Pending));
        let snap = store.snapshot();
        assert_eq!(snap.deployment("dep-x").unwrap().tests.len(), 1);
    }

    #[test]
    fn test_report_reconciles_tests_for_legacy_agents() {
        let store = CdStateStore::default();
        store.deployment_started(start("dep-2", vec![]));
        store.apply_it_report(&IntegrationTestReport {
            deployment_id: "dep-2".into(),
            service_name: "example".into(),
            artifact_sha256: "sha256:abc".into(),
            executed_tests: vec!["all".into(), "a".into(), "b".into()],
            passed: false,
            failed_tests: vec!["b".into()],
            duration_ms: 10,
            log_excerpt: Some("boom".into()),
        });
        let snap = store.snapshot();
        let d = snap.deployment("dep-2").unwrap();
        assert_eq!(d.tests.len(), 2);
        assert_eq!(d.tests[1].state, TestState::Failed);
        assert_eq!(d.tests[1].log_excerpt.as_deref(), Some("boom"));
        // Unknown deployment is ignored.
        store.apply_it_report(&IntegrationTestReport {
            deployment_id: "nope".into(),
            service_name: String::new(),
            artifact_sha256: String::new(),
            executed_tests: vec![],
            passed: true,
            failed_tests: vec![],
            duration_ms: 0,
            log_excerpt: None,
        });
        assert!(store.snapshot().deployment("nope").is_none());
    }

    #[test]
    fn test_outcomes_leases_and_history_limit() {
        let store = CdStateStore::new(2, 16);
        let mut rx = store.subscribe();
        store.deployment_started(start("d1", vec![]));
        store.deployment_started(start("d2", vec![]));
        store.deployment_started(start("d3", vec![]));
        let snap = store.snapshot();
        assert_eq!(snap.deployments.len(), 2);
        assert_eq!(snap.deployments[0].deployment_id, "d3");

        store.deployment_promoted("d3", Slot::B);
        store.deployment_rolled_back("d2", Slot::A, RollbackReason::LeaseExpired, "ttl");
        store.deployment_tainted("d2", "sha256:abc", "ttl");
        store.lease_expired("d2", "lease-1");
        store.set_leases(vec![LeaseView {
            lease_id: "l".into(),
            deployment_id: "d3".into(),
            target_node: "node-a".into(),
            service: "example".into(),
            artifact_digest: "sha256:abc".into(),
            active_slot: Slot::A,
            candidate_slot: Slot::B,
            expires_epoch_ms: 1,
            ttl_remaining_ms: 0,
            promoted: false,
        }]);

        let snap = store.snapshot();
        let d3 = snap.deployment("d3").unwrap();
        assert_eq!(d3.outcome, GateOutcome::Promoted);
        assert_eq!(d3.active_slot, Slot::B);
        let d2 = snap.deployment("d2").unwrap();
        assert_eq!(d2.outcome, GateOutcome::RolledBack);
        assert!(d2.tainted && d2.lease_expired);
        assert_eq!(d2.rollback_reason, Some(RollbackReason::LeaseExpired));
        assert_eq!(snap.leases.len(), 1);

        let names: Vec<&str> = std::iter::from_fn(|| rx.try_recv().ok())
            .map(|e| e.event_name())
            .collect();
        assert_eq!(
            names,
            vec!["promoted", "rolled_back", "tainted", "lease_expired"]
        );
    }
}
