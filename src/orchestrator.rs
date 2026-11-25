//! Continuous delivery deployment state machine and orchestrator.
//!
//! Coordinates TTL-bounded leases, inactive slot staging, live health probes,
//! atomic slot promotion, automatic rollback, and digest tainting.

use std::collections::HashSet;
use std::io::IoSlice;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use reqwest::Client;
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio_rustls::client::TlsStream;

use mu_cd_ipc::{
    create_fory_runtime, read_frame, write_frame, ArtifactTaintNotification, DeploymentLeaseGrant,
    DeploymentLeaseRequest, DeploymentSlot, IntegrationTestProgress, IntegrationTestReport,
    IpcHeader, RollbackCommand, ScenarioExecutionPlan, ScenarioPlanAck, SlotSwapCommand,
    StageDeploymentRequest, StageDeploymentResponse, MSG_TYPE_IT_PROGRESS, MSG_TYPE_IT_REPORT,
    MSG_TYPE_ROLLBACK, MSG_TYPE_SCENARIO_PLAN, MSG_TYPE_SCENARIO_PLAN_ACK, MSG_TYPE_SLOT_SWAP,
    MSG_TYPE_STAGE_DEPLOY_REQ, MSG_TYPE_STAGE_DEPLOY_RESP,
};
use mu_observable_ipc::CanarySloAssertionRequest;

use crate::cd_state::{
    classify_rollback_reason, CdStateStore, DeploymentStart, ItProgressSink, Slot,
};
use crate::contract::MuConDeConfig;
use crate::error::{ContractError, LeaseError, OrchestratorError};
use crate::lease::{ClusterIdlePoller, ClusterNodeStatus, IdleBackoffConfig, LeaseCoordinator};
use crate::policy_repo::{
    ArchDigestMaps, PinnedDeploymentSnapshot, PolicyRepository, DEFAULT_POLICY_SANDBOX_MEMLOCK_KB,
    MAX_POLICY_SANDBOX_PIDS,
};
use crate::slo::CanarySloClient;
use crate::telemetry::{build_cd_log, build_cd_span, now_unix_nano, CdTelemetrySink};
use crate::tls::TlsConfig;
use mu_observable_ipc::{OtelLogEntry, TraceContext};

/// Default MuRegist server URL used across continuous delivery fabric.
pub const DEFAULT_REGISTRY_URL: &str = "https://registry.ci.ci.internal:8444";
/// Default writable state directory for controller self-upgrade handoff state.
pub const DEFAULT_CONTROLLER_STATE_DIR: &str = "/var/lib/muconde";
/// Filename persisted atomically (`0600`) immediately before swapping `mu-cd-controller`.
pub const PENDING_SELF_UPGRADE_FILENAME: &str = "pending_self_upgrade.json";
/// Maximum age for resuming a persisted controller self-upgrade handoff (10 minutes).
pub const PENDING_SELF_UPGRADE_MAX_AGE_MS: u64 = 10 * 60 * 1000;
/// Default backoff interval when reconnecting to `mu-cd-agent` across transient disconnects.
pub const DEFAULT_AGENT_RECONNECT_BACKOFF: Duration = Duration::from_millis(250);

/// Resolves the controller state directory from `MU_CD_CONTROLLER_STATE_DIR` ->
/// `MUCONDE_STATE_DIR` -> `/var/lib/muconde`.
#[must_use]
pub fn resolve_controller_state_dir(lookup: &dyn Fn(&str) -> Option<String>) -> PathBuf {
    crate::first_non_empty_var(lookup, &["MU_CD_CONTROLLER_STATE_DIR", "MUCONDE_STATE_DIR"])
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONTROLLER_STATE_DIR))
}

/// Returns the canonical path to the durable controller self-upgrade handoff file.
#[must_use]
pub fn pending_self_upgrade_path(state_dir: &Path) -> PathBuf {
    state_dir.join(PENDING_SELF_UPGRADE_FILENAME)
}

/// Returns `true` when `service` refers to the controller daemon itself.
#[must_use]
pub fn is_controller_self_upgrade_service(service: &str) -> bool {
    matches!(service.trim(), "mu-cd-controller" | "muconde-controller")
}

/// Durable on-disk handoff written atomically (`0600`) immediately before dispatching
/// `SlotSwapCommand` for `mu-cd-controller` so the restarted controller resumes gate and
/// `MuObserve` bake-window SLO finalization without losing deployment state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PendingControllerSelfUpgrade {
    pub deployment_id: String,
    pub lease_id: String,
    pub service: String,
    #[serde(default)]
    pub repo: Option<String>,
    pub target_node: String,
    pub artifact_sha256: String,
    pub active_slot: String,
    pub candidate_slot: String,
    pub systemd_unit: String,
    pub policy_commit_sha: String,
    pub trace_id: String,
    #[serde(default)]
    pub selected_tests: Vec<String>,
    pub bake_window_seconds: u64,
    pub max_error_logs: u32,
    pub max_p99_latency_ms: f64,
    pub warmup_timeout_seconds: u64,
    pub started_at_epoch_ms: u64,
}

fn slot_to_handoff_str(slot: DeploymentSlot) -> &'static str {
    match slot {
        DeploymentSlot::SlotA => "@a",
        DeploymentSlot::SlotB => "@b",
    }
}

fn parse_handoff_slot(raw: &str) -> Option<DeploymentSlot> {
    match raw.trim() {
        "@a" | "a" | "slot_a" | "SlotA" => Some(DeploymentSlot::SlotA),
        "@b" | "b" | "slot_b" | "SlotB" => Some(DeploymentSlot::SlotB),
        _ => None,
    }
}

/// Atomically writes `handoff` to `path` with owner-only `0600` permissions (write temp + rename).
pub fn write_pending_self_upgrade_atomic(
    path: &Path,
    handoff: &PendingControllerSelfUpgrade,
) -> Result<(), OrchestratorError> {
    let parent = path.parent().ok_or_else(|| {
        OrchestratorError::DeploymentFailed(format!(
            "Self-upgrade handoff path '{}' has no parent directory",
            path.display()
        ))
    })?;
    std::fs::create_dir_all(parent).map_err(|e| {
        OrchestratorError::DeploymentFailed(format!(
            "Failed to create state directory '{}': {e}",
            parent.display()
        ))
    })?;
    let json = serde_json::to_vec_pretty(handoff).map_err(|e| {
        OrchestratorError::DeploymentFailed(format!(
            "Failed to serialize pending_self_upgrade.json: {e}"
        ))
    })?;
    let tmp_path = parent.join(format!(
        ".{PENDING_SELF_UPGRADE_FILENAME}.tmp-{}",
        uuid::Uuid::new_v4()
    ));
    let write_res = (|| -> std::io::Result<()> {
        std::fs::write(&tmp_path, &json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    })();
    if let Err(err) = write_res {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(OrchestratorError::DeploymentFailed(format!(
            "Failed to persist '{}': {err}",
            path.display()
        )));
    }
    Ok(())
}

/// Atomically claims and removes `pending_self_upgrade.json` if present and fresher than 10 minutes.
pub fn claim_pending_self_upgrade(
    path: &Path,
) -> Result<Option<PendingControllerSelfUpgrade>, OrchestratorError> {
    let Some(parent) = path.parent() else {
        return Ok(None);
    };
    let claim_path = parent.join(format!(
        ".{PENDING_SELF_UPGRADE_FILENAME}.claiming-{}",
        uuid::Uuid::new_v4()
    ));
    match std::fs::rename(path, &claim_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(OrchestratorError::DeploymentFailed(format!(
                "Failed to claim '{}': {e}",
                path.display()
            )));
        }
    }
    let bytes = std::fs::read(&claim_path);
    let _ = std::fs::remove_file(&claim_path);
    let bytes = bytes.map_err(|e| {
        OrchestratorError::DeploymentFailed(format!(
            "Failed to read claimed self-upgrade handoff '{}': {e}",
            claim_path.display()
        ))
    })?;
    let pending: PendingControllerSelfUpgrade = serde_json::from_slice(&bytes).map_err(|e| {
        OrchestratorError::DeploymentFailed(format!(
            "Failed to deserialize pending_self_upgrade.json: {e}"
        ))
    })?;
    let now_ms = LeaseCoordinator::current_epoch_ms();
    let age_ms = now_ms.saturating_sub(pending.started_at_epoch_ms);
    if age_ms > PENDING_SELF_UPGRADE_MAX_AGE_MS {
        tracing::warn!(
            deployment_id = %pending.deployment_id,
            service = %pending.service,
            age_ms,
            "Ignoring expired pending_self_upgrade.json (>10 minutes old)"
        );
        return Ok(None);
    }
    Ok(Some(pending))
}

fn clear_pending_self_upgrade_if_matching(state_dir: &Path, deployment_id: &str) {
    let path = pending_self_upgrade_path(state_dir);
    let Ok(bytes) = std::fs::read(&path) else {
        return;
    };
    if let Ok(parsed) = serde_json::from_slice::<PendingControllerSelfUpgrade>(&bytes) {
        if parsed.deployment_id == deployment_id {
            let _ = std::fs::remove_file(&path);
        }
    }
}

fn is_retryable_ipc_io_kind(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionRefused
    )
}

/// Represents the terminal outcome of a continuous delivery deployment run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeploymentOutcome {
    /// Candidate passed all health probes and integration tests, and was promoted to Slot A.
    Promoted {
        deployment_id: String,
        service: String,
        target_node: String,
        artifact_sha256: String,
    },
    /// Deployment failed verification or timed out, and was atomically rolled back to Slot A.
    RolledBack {
        deployment_id: String,
        service: String,
        target_node: String,
        artifact_sha256: String,
        reason: String,
    },
}

impl DeploymentOutcome {
    /// Returns `true` if the candidate was successfully promoted to baseline Slot A.
    pub fn is_promoted(&self) -> bool {
        matches!(self, Self::Promoted { .. })
    }

    /// Returns `true` if the candidate was rolled back.
    pub fn is_rolled_back(&self) -> bool {
        matches!(self, Self::RolledBack { .. })
    }
}

/// Abstract IPC client contract for communicating with node-level `MuConDe-agent`.
#[async_trait]
pub trait AgentIpcClient: Send + Sync {
    /// Request the agent stage the candidate artifact into the designated slot subvolume.
    async fn stage_deployment(
        &self,
        node_id: &str,
        req: &StageDeploymentRequest,
    ) -> Result<StageDeploymentResponse, OrchestratorError>;

    /// Request the agent perform an atomic slot swap pointing to the candidate subvolume.
    async fn slot_swap(
        &self,
        node_id: &str,
        cmd: &SlotSwapCommand,
    ) -> Result<(), OrchestratorError>;

    /// Transmit an optional [`ScenarioExecutionPlan`] (`0x0D`) immediately followed by
    /// [`SlotSwapCommand`] (`0x06`) on the same stream without blocking for `0x0E`.
    async fn slot_swap_with_plan(
        &self,
        node_id: &str,
        cmd: &SlotSwapCommand,
        _plan: Option<&ScenarioExecutionPlan>,
    ) -> Result<(), OrchestratorError> {
        self.slot_swap(node_id, cmd).await
    }

    /// Await or trigger integration test execution on the candidate slot.
    async fn execute_integration_tests(
        &self,
        node_id: &str,
        deployment_id: &str,
        service: &str,
        artifact_sha256: &str,
        selected_tests: Option<&[String]>,
        timeout: Duration,
    ) -> Result<IntegrationTestReport, OrchestratorError>;

    /// Dispatch RollbackCommand to restore baseline Slot A.
    async fn rollback(&self, node_id: &str, cmd: &RollbackCommand)
        -> Result<(), OrchestratorError>;
}

/// Abstract client contract for communicating with `MuRegist` canary management API.
#[async_trait]
pub trait MuRegistClient: Send + Sync {
    /// Check whether an artifact digest has already been marked tainted in MuRegist.
    async fn is_digest_tainted(&self, digest: &str) -> Result<bool, OrchestratorError>;

    /// Mark canary release promoted and healthy in MuRegist (`POST /api/v1/canary/{digest}/promote`).
    async fn promote_canary(&self, digest: &str) -> Result<(), OrchestratorError>;

    /// Record tainted digest and rollback reason in MuRegist (`POST /api/v1/canary/{digest}/taint`).
    async fn taint_canary(
        &self,
        digest: &str,
        notification: &ArtifactTaintNotification,
    ) -> Result<(), OrchestratorError>;

    /// Record tainted digest, target node, and rollback reason in MuRegist
    /// (`POST /api/v1/canary/{digest}/taint`). Defaults to [`Self::taint_canary`] for
    /// backward-compatible mock implementations.
    async fn taint_canary_for_node(
        &self,
        digest: &str,
        _node_id: Option<&str>,
        notification: &ArtifactTaintNotification,
    ) -> Result<(), OrchestratorError> {
        self.taint_canary(digest, notification).await
    }
}

/// HTTP/mTLS client for MuRegist canary and bundle API.
#[derive(Debug, Clone)]
pub struct HttpMuRegistClient {
    base_url: String,
    client: Client,
    auth_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TaintPayload {
    pub service_name: Option<String>,
    pub node_id: Option<String>,
    pub reason: Option<String>,
}

impl HttpMuRegistClient {
    /// Initialize with base URL and mTLS configuration.
    pub fn new(
        base_url: impl Into<String>,
        tls_config: &TlsConfig,
        auth_token: Option<String>,
    ) -> Result<Self, OrchestratorError> {
        let client = tls_config
            .build_reqwest_client()
            .map_err(|e| OrchestratorError::Regist(e.to_string()))?;

        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client,
            auth_token,
        })
    }

    /// Initialize with an existing configured `reqwest::Client` (useful for mocks).
    pub fn with_client(
        base_url: impl Into<String>,
        client: Client,
        auth_token: Option<String>,
    ) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client,
            auth_token,
        }
    }
}

#[async_trait]
impl MuRegistClient for HttpMuRegistClient {
    async fn is_digest_tainted(&self, digest: &str) -> Result<bool, OrchestratorError> {
        // Query canary status summary
        let url = format!("{}/api/v1/canary/status", self.base_url);
        let mut req = self.client.get(&url);
        if let Some(ref token) = self.auth_token {
            req = req.bearer_auth(token);
        }

        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                // If registry status endpoint is unreachable, fail safe or return false if testing
                return Err(OrchestratorError::Regist(format!(
                    "Failed to query canary status from {url}: {e}"
                )));
            }
        };

        if resp.status().is_success() {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Some(status) = json.get("status").and_then(|s| s.as_str()) {
                    if status == "tainted" {
                        if let Some(active) =
                            json.get("active_canary_digest").and_then(|d| d.as_str())
                        {
                            if active == digest {
                                return Ok(true);
                            }
                        }
                    }
                }
            }
        }

        Ok(false)
    }

    async fn promote_canary(&self, digest: &str) -> Result<(), OrchestratorError> {
        let url = format!("{}/api/v1/canary/{digest}/promote", self.base_url);
        let mut req = self
            .client
            .post(&url)
            .header("x-client-cert-san", "mu-cd-controller");
        if let Some(ref token) = self.auth_token {
            req = req.bearer_auth(token);
        }

        let resp = req.send().await.map_err(|e| {
            OrchestratorError::Regist(format!("Failed to send promote request to {url}: {e}"))
        })?;

        if resp.status().as_u16() == 409 {
            return Err(OrchestratorError::ArtifactTainted(format!(
                "Registry rejected promotion: digest '{digest}' is tainted"
            )));
        }

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(OrchestratorError::Regist(format!(
                "Registry promotion for '{digest}' failed with status: {body}"
            )));
        }

        Ok(())
    }

    async fn taint_canary(
        &self,
        digest: &str,
        notification: &ArtifactTaintNotification,
    ) -> Result<(), OrchestratorError> {
        self.taint_canary_for_node(digest, None, notification).await
    }

    async fn taint_canary_for_node(
        &self,
        digest: &str,
        node_id: Option<&str>,
        notification: &ArtifactTaintNotification,
    ) -> Result<(), OrchestratorError> {
        let url = format!("{}/api/v1/canary/{digest}/taint", self.base_url);
        let payload = TaintPayload {
            service_name: Some(notification.service_name.clone()),
            node_id: node_id
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned),
            reason: Some(notification.reason.clone()),
        };

        let mut req = self
            .client
            .post(&url)
            .header("x-client-cert-san", "mu-cd-controller")
            .json(&payload);
        if let Some(ref token) = self.auth_token {
            req = req.bearer_auth(token);
        }

        let resp = req.send().await.map_err(|e| {
            OrchestratorError::Regist(format!("Failed to send taint request to {url}: {e}"))
        })?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(OrchestratorError::Regist(format!(
                "Registry taint for '{digest}' failed: {body}"
            )));
        }

        Ok(())
    }
}

/// Result of dispatching one agent frame while awaiting the integration-test verdict.
#[derive(Debug, Clone, PartialEq)]
pub enum AgentFrame {
    /// The final aggregate verdict.
    Report(IntegrationTestReport),
    /// A per-test progress update (already forwarded to the sink, if any).
    Progress(IntegrationTestProgress),
    /// Advisory acknowledgement for a transmitted [`ScenarioExecutionPlan`] (`0x0E`).
    ScenarioAck(ScenarioPlanAck),
    /// Any other or unknown message type; skipped without decoding the payload.
    Ignored(u16),
}

/// Dispatches one frame read from an agent while the integration gate runs.
///
/// Dispatch happens on `msg_type` before decoding, so unknown message IDs are skipped
/// safely. Progress (`0x0C`) and scenario plan acknowledgement (`0x0E`) frames are advisory;
/// a report (`0x08`) that fails to decode is an error.
pub fn dispatch_agent_frame(
    fory: &fory::Fory,
    msg_type: u16,
    payload: &[u8],
    sink: Option<&dyn ItProgressSink>,
) -> Result<AgentFrame, OrchestratorError> {
    match msg_type {
        MSG_TYPE_IT_REPORT => {
            let report: IntegrationTestReport = fory
                .deserialize(payload)
                .map_err(|e| OrchestratorError::Agent(e.to_string()))?;
            Ok(AgentFrame::Report(report))
        }
        MSG_TYPE_IT_PROGRESS => match fory.deserialize::<IntegrationTestProgress>(payload) {
            Ok(p) => {
                if let Some(sink) = sink {
                    sink.on_it_progress(&p);
                }
                Ok(AgentFrame::Progress(p))
            }
            Err(e) => {
                tracing::warn!(error = %e, "Ignoring undecodable IntegrationTestProgress frame");
                Ok(AgentFrame::Ignored(msg_type))
            }
        },
        MSG_TYPE_SCENARIO_PLAN_ACK => match fory.deserialize::<ScenarioPlanAck>(payload) {
            Ok(ack) => {
                if ack.accepted {
                    tracing::info!(
                        deployment_id = %ack.deployment_id,
                        lease_id = %ack.lease_id,
                        "Agent acknowledged ScenarioExecutionPlan"
                    );
                } else {
                    tracing::warn!(
                        deployment_id = %ack.deployment_id,
                        lease_id = %ack.lease_id,
                        reason = ?ack.rejection_reason,
                        "Agent rejected ScenarioExecutionPlan"
                    );
                }
                Ok(AgentFrame::ScenarioAck(ack))
            }
            Err(e) => {
                tracing::warn!(error = %e, "Ignoring undecodable ScenarioPlanAck frame");
                Ok(AgentFrame::Ignored(msg_type))
            }
        },
        other => Ok(AgentFrame::Ignored(other)),
    }
}

/// Trims and deduplicates a list of target node identifiers while preserving first-seen order
/// (capped at 64 targets).
#[must_use]
pub fn dedup_target_nodes(nodes: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for raw in nodes.iter().take(64) {
        let trimmed = raw.trim();
        if !trimmed.is_empty() && !out.iter().any(|existing: &String| existing == trimmed) {
            out.push(trimmed.to_string());
        }
    }
    out
}

/// Transport stream to `mu-cd-agent`, supporting plain TCP for unconfigured tests
/// and `rustls` mTLS when `TlsConfig` provides certificate material.
enum AgentStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for AgentStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for AgentStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Plain(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Plain(stream) => stream.is_write_vectored(),
            Self::Tls(stream) => stream.is_write_vectored(),
        }
    }
}

/// Network implementation of `AgentIpcClient` communicating over TCP/TLS framing.
#[derive(Clone)]
pub struct IpcAgentClient {
    port: u16,
    progress_sink: Option<Arc<dyn ItProgressSink>>,
    tls_config: Option<TlsConfig>,
    policy_repo: Option<Arc<PolicyRepository>>,
    reconnect_backoff: Duration,
    active_streams: Arc<tokio::sync::Mutex<std::collections::HashMap<String, AgentStream>>>,
}

impl std::fmt::Debug for IpcAgentClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpcAgentClient")
            .field("port", &self.port)
            .field("progress_sink", &self.progress_sink.is_some())
            .field("policy_repo", &self.policy_repo.is_some())
            .field("reconnect_backoff_ms", &self.reconnect_backoff.as_millis())
            .field(
                "tls_configured",
                &self
                    .tls_config
                    .as_ref()
                    .is_some_and(TlsConfig::has_tls_material),
            )
            .finish()
    }
}

impl IpcAgentClient {
    /// Create client targeting agents listening on standard CD port.
    pub fn new(port: u16) -> Self {
        Self {
            port,
            progress_sink: None,
            tls_config: None,
            policy_repo: None,
            reconnect_backoff: DEFAULT_AGENT_RECONNECT_BACKOFF,
            active_streams: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Overrides the reconnect retry interval used while waiting for an agent restart.
    #[must_use]
    pub fn with_reconnect_backoff(mut self, backoff: Duration) -> Self {
        self.reconnect_backoff = backoff.max(Duration::from_millis(1));
        self
    }

    /// Forward `IntegrationTestProgress` frames to `sink` (e.g. the CD API state store).
    #[must_use]
    pub fn with_progress_sink(mut self, sink: Arc<dyn ItProgressSink>) -> Self {
        self.progress_sink = Some(sink);
        self
    }

    /// Configure mutual TLS credentials for agent IPC connections (`:8446`).
    #[must_use]
    pub fn with_tls_config(mut self, tls_config: TlsConfig) -> Self {
        self.tls_config = Some(tls_config);
        self
    }

    /// Attach a verified [`PolicyRepository`] for authoritative node-ID-to-host resolution.
    #[must_use]
    pub fn with_policy_repo(mut self, policy_repo: Arc<PolicyRepository>) -> Self {
        self.policy_repo = Some(policy_repo);
        self
    }

    fn resolve_agent_host(&self, node_id: &str) -> String {
        if let Some(ref repo) = self.policy_repo {
            if let Some(host) = repo.resolve_node_host(node_id) {
                return host;
            }
        }
        node_id.trim().to_string()
    }

    async fn connect_stream_classified(
        &self,
        host: &str,
    ) -> Result<AgentStream, (Option<std::io::ErrorKind>, OrchestratorError)> {
        let connector = match self
            .tls_config
            .as_ref()
            .filter(|cfg| cfg.has_tls_material())
        {
            Some(tls_cfg) => Some((
                tls_cfg
                    .build_tls_connector()
                    .map_err(|e| (None, OrchestratorError::from(e)))?,
                ServerName::try_from(host.to_string()).map_err(|e| {
                    (
                        None,
                        OrchestratorError::Agent(format!("Invalid TLS server name '{host}': {e}")),
                    )
                })?,
            )),
            None => None,
        };

        let addr = format!("{}:{}", host, self.port);
        let tcp_stream = TcpStream::connect(&addr).await.map_err(|e| {
            (
                Some(e.kind()),
                OrchestratorError::Agent(format!("Connect to agent {addr} failed: {e}")),
            )
        })?;

        if let Some((connector, server_name)) = connector {
            let tls_stream = connector
                .connect(server_name, tcp_stream)
                .await
                .map_err(|e| {
                    (
                        Some(e.kind()),
                        OrchestratorError::Agent(format!(
                            "mTLS handshake with agent {addr} failed: {e}"
                        )),
                    )
                })?;
            Ok(AgentStream::Tls(Box::new(tls_stream)))
        } else {
            Ok(AgentStream::Plain(tcp_stream))
        }
    }

    async fn connect_stream(&self, host: &str) -> Result<AgentStream, OrchestratorError> {
        self.connect_stream_classified(host)
            .await
            .map_err(|(_, err)| err)
    }

    async fn connect_stream_with_retry(
        &self,
        host: &str,
        immediate_first_attempt: bool,
    ) -> Result<AgentStream, OrchestratorError> {
        let mut first = immediate_first_attempt;
        loop {
            if !first {
                tokio::time::sleep(self.reconnect_backoff).await;
            }
            first = false;
            match self.connect_stream_classified(host).await {
                Ok(stream) => return Ok(stream),
                Err((Some(kind), err)) if is_retryable_ipc_io_kind(kind) => {
                    tracing::debug!(
                        host = %host,
                        port = self.port,
                        error = %err,
                        backoff_ms = self.reconnect_backoff.as_millis() as u64,
                        "Retrying agent IPC connection after transient error"
                    );
                }
                Err((_, err)) => return Err(err),
            }
        }
    }
}

impl Default for IpcAgentClient {
    fn default() -> Self {
        Self::new(8446)
    }
}

#[async_trait]
impl AgentIpcClient for IpcAgentClient {
    async fn stage_deployment(
        &self,
        node_id: &str,
        req: &StageDeploymentRequest,
    ) -> Result<StageDeploymentResponse, OrchestratorError> {
        let fory = create_fory_runtime().map_err(|e| OrchestratorError::Agent(e.to_string()))?;
        let host = self.resolve_agent_host(node_id);
        let mut stream = self.connect_stream(&host).await?;

        let payload = fory
            .serialize(req)
            .map_err(|e| OrchestratorError::Agent(e.to_string()))?;
        let header = IpcHeader::new(MSG_TYPE_STAGE_DEPLOY_REQ, payload.len() as u32, 0, 1);

        write_frame(&mut stream, &header, &payload)
            .await
            .map_err(|e| OrchestratorError::Agent(e.to_string()))?;

        let (resp_header, resp_payload) = read_frame(&mut stream)
            .await
            .map_err(|e| OrchestratorError::Agent(e.to_string()))?;

        if resp_header.msg_type != MSG_TYPE_STAGE_DEPLOY_RESP {
            return Err(OrchestratorError::Agent(format!(
                "Unexpected IPC frame type: {}",
                resp_header.msg_type
            )));
        }

        let resp: StageDeploymentResponse = fory
            .deserialize(&resp_payload)
            .map_err(|e| OrchestratorError::Agent(e.to_string()))?;

        Ok(resp)
    }

    async fn slot_swap(
        &self,
        node_id: &str,
        cmd: &SlotSwapCommand,
    ) -> Result<(), OrchestratorError> {
        self.slot_swap_with_plan(node_id, cmd, None).await
    }

    async fn slot_swap_with_plan(
        &self,
        node_id: &str,
        cmd: &SlotSwapCommand,
        plan: Option<&ScenarioExecutionPlan>,
    ) -> Result<(), OrchestratorError> {
        let fory = create_fory_runtime().map_err(|e| OrchestratorError::Agent(e.to_string()))?;
        let host = self.resolve_agent_host(node_id);
        let mut stream = self.connect_stream(&host).await?;

        let mut next_seq = 1u64;
        if let Some(scenario_plan) = plan {
            let plan_payload = fory
                .serialize(scenario_plan)
                .map_err(|e| OrchestratorError::Agent(e.to_string()))?;
            let plan_header = IpcHeader::new(
                MSG_TYPE_SCENARIO_PLAN,
                plan_payload.len() as u32,
                0,
                next_seq,
            );
            write_frame(&mut stream, &plan_header, &plan_payload)
                .await
                .map_err(|e| OrchestratorError::Agent(e.to_string()))?;
            next_seq += 1;
        }

        let payload = fory
            .serialize(cmd)
            .map_err(|e| OrchestratorError::Agent(e.to_string()))?;
        let header = IpcHeader::new(MSG_TYPE_SLOT_SWAP, payload.len() as u32, 0, next_seq);

        write_frame(&mut stream, &header, &payload)
            .await
            .map_err(|e| OrchestratorError::Agent(e.to_string()))?;

        self.active_streams
            .lock()
            .await
            .insert(cmd.deployment_id.clone(), stream);

        Ok(())
    }

    async fn execute_integration_tests(
        &self,
        node_id: &str,
        deployment_id: &str,
        service: &str,
        artifact_sha256: &str,
        selected_tests: Option<&[String]>,
        timeout: Duration,
    ) -> Result<IntegrationTestReport, OrchestratorError> {
        let fory = create_fory_runtime().map_err(|e| OrchestratorError::Agent(e.to_string()))?;
        let host = self.resolve_agent_host(node_id);
        let initial_stream = self.active_streams.lock().await.remove(deployment_id);

        let executed = match selected_tests {
            Some(tests) => tests.to_vec(),
            None => vec!["all".to_string()],
        };

        // Await IntegrationTestReport frame or terminal IntegrationTestProgress frames within timeout,
        // retrying transient disconnects (`UnexpectedEof | ConnectionReset | BrokenPipe | ConnectionRefused`)
        // across agent or controller self-upgrades until the timeout deadline.
        let read_future = async {
            let mut stream = match initial_stream {
                Some(s) => s,
                None => self.connect_stream_with_retry(&host, true).await?,
            };
            let mut seen_states: std::collections::HashMap<String, mu_cd_ipc::TestState> =
                std::collections::HashMap::new();
            let mut seen_order: Vec<String> = Vec::new();
            let mut max_duration_ms: u64 = 0;
            let mut reconnected_once = false;

            loop {
                let frame_res = read_frame(&mut stream).await;
                let (header, payload) = match frame_res {
                    Ok(f) => f,
                    Err(mu_cd_ipc::IpcError::Io(ref e)) if is_retryable_ipc_io_kind(e.kind()) => {
                        tracing::info!(
                            deployment_id = %deployment_id,
                            host = %host,
                            error_kind = ?e.kind(),
                            "Agent IPC stream disconnected while awaiting integration report; reconnecting"
                        );
                        let immediate = !reconnected_once;
                        reconnected_once = true;
                        stream = self.connect_stream_with_retry(&host, immediate).await?;
                        continue;
                    }
                    Err(e) => return Err(OrchestratorError::Agent(e.to_string())),
                };

                match dispatch_agent_frame(
                    &fory,
                    header.msg_type,
                    &payload,
                    self.progress_sink.as_deref(),
                )? {
                    AgentFrame::Report(report) => return Ok(report),
                    AgentFrame::Progress(p) => {
                        if !seen_order.contains(&p.test_name) {
                            seen_order.push(p.test_name.clone());
                        }
                        max_duration_ms = max_duration_ms.max(p.duration_ms);
                        seen_states.insert(p.test_name, p.state);

                        let all_terminal = !seen_states.is_empty()
                            && seen_states.values().all(|st| {
                                matches!(
                                    st,
                                    mu_cd_ipc::TestState::Passed | mu_cd_ipc::TestState::Failed
                                )
                            });
                        let any_failed = seen_states
                            .values()
                            .any(|st| matches!(st, mu_cd_ipc::TestState::Failed));
                        if all_terminal && !any_failed {
                            // Peek briefly in case a fake/legacy agent also emits MSG_TYPE_IT_REPORT on success.
                            if let Ok(Ok((next_hdr, next_payload))) = tokio::time::timeout(
                                Duration::from_millis(50),
                                read_frame(&mut stream),
                            )
                            .await
                            {
                                if let AgentFrame::Report(report) = dispatch_agent_frame(
                                    &fory,
                                    next_hdr.msg_type,
                                    &next_payload,
                                    self.progress_sink.as_deref(),
                                )? {
                                    return Ok(report);
                                }
                            }
                            return Ok(IntegrationTestReport {
                                deployment_id: deployment_id.to_string(),
                                service_name: service.to_string(),
                                artifact_sha256: artifact_sha256.to_string(),
                                executed_tests: seen_order,
                                passed: true,
                                failed_tests: Vec::new(),
                                duration_ms: max_duration_ms,
                                log_excerpt: None,
                            });
                        }
                    }
                    AgentFrame::ScenarioAck(_) | AgentFrame::Ignored(_) => {}
                }
            }
        };

        match tokio::time::timeout(timeout, read_future).await {
            Ok(res) => res,
            Err(_) => Ok(IntegrationTestReport {
                deployment_id: deployment_id.to_string(),
                service_name: service.to_string(),
                artifact_sha256: artifact_sha256.to_string(),
                executed_tests: executed,
                passed: false,
                failed_tests: vec!["timeout".to_string()],
                duration_ms: timeout.as_millis() as u64,
                log_excerpt: Some("Integration test execution timed out".to_string()),
            }),
        }
    }

    async fn rollback(
        &self,
        node_id: &str,
        cmd: &RollbackCommand,
    ) -> Result<(), OrchestratorError> {
        let fory = create_fory_runtime().map_err(|e| OrchestratorError::Agent(e.to_string()))?;
        let host = self.resolve_agent_host(node_id);
        let mut stream = self.connect_stream(&host).await?;

        let payload = fory
            .serialize(cmd)
            .map_err(|e| OrchestratorError::Agent(e.to_string()))?;
        let header = IpcHeader::new(MSG_TYPE_ROLLBACK, payload.len() as u32, 0, 1);

        write_frame(&mut stream, &header, &payload)
            .await
            .map_err(|e| OrchestratorError::Agent(e.to_string()))?;

        Ok(())
    }
}

/// Orchestrator driving continuous delivery deployments across cluster nodes.
pub struct DeploymentOrchestrator {
    lease_coordinator: Arc<LeaseCoordinator>,
    poller: Option<ClusterIdlePoller>,
    idle_backoff: IdleBackoffConfig,
    agent_client: Arc<dyn AgentIpcClient>,
    regist_client: Arc<dyn MuRegistClient>,
    slo_client: Option<Arc<dyn CanarySloClient>>,
    tainted_digests: Arc<RwLock<HashSet<String>>>,
    cd_state: Option<Arc<CdStateStore>>,
    telemetry_sink: Option<Arc<dyn CdTelemetrySink>>,
    policy_repo: Option<Arc<PolicyRepository>>,
    state_dir: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct PromotedNodeRecord {
    outcome_index: usize,
    deployment_id: String,
    node: String,
    binary_digest: String,
    restore_slot: DeploymentSlot,
}

#[derive(Debug, Clone)]
struct ResolvedNodeTarget {
    node: String,
    binary_digest: String,
    it_archive_digest: Option<String>,
}

struct CompensationRequest<'a> {
    config: &'a MuConDeConfig,
    artifact_sha256: &'a str,
    failed_node: &'a str,
    failure_reason: &'a str,
    taint_in_state: bool,
    parent_trace: Option<TraceContext>,
}

impl DeploymentOrchestrator {
    /// Create a new `DeploymentOrchestrator` with specified dependencies.
    pub fn new(
        lease_coordinator: Arc<LeaseCoordinator>,
        poller: Option<ClusterIdlePoller>,
        agent_client: Arc<dyn AgentIpcClient>,
        regist_client: Arc<dyn MuRegistClient>,
    ) -> Self {
        Self {
            lease_coordinator,
            poller,
            idle_backoff: IdleBackoffConfig::default(),
            agent_client,
            regist_client,
            slo_client: None,
            tainted_digests: Arc::new(RwLock::new(HashSet::new())),
            cd_state: None,
            telemetry_sink: None,
            policy_repo: None,
            state_dir: None,
        }
    }

    /// Configures the writable state directory used for durable controller self-upgrade handoffs
    /// (`<state_dir>/pending_self_upgrade.json`).
    #[must_use]
    pub fn with_state_dir(mut self, state_dir: impl Into<PathBuf>) -> Self {
        self.state_dir = Some(state_dir.into());
        self
    }

    /// Returns the configured writable state directory, if set.
    #[must_use]
    pub fn state_dir(&self) -> Option<&Path> {
        self.state_dir.as_deref()
    }

    /// Configures bounded contention-tolerant exponential backoff parameters for idle node discovery.
    #[must_use]
    pub fn with_idle_backoff(mut self, idle_backoff: IdleBackoffConfig) -> Self {
        self.idle_backoff = idle_backoff;
        self
    }

    /// Attach a [`CdTelemetrySink`] (`MuObserveCdSink`) to stream W3C trace spans to `muObserve`.
    pub fn with_telemetry_sink(mut self, sink: Arc<dyn CdTelemetrySink>) -> Self {
        self.telemetry_sink = Some(sink);
        self
    }

    /// Returns the attached [`CdTelemetrySink`], if configured.
    #[must_use]
    pub fn telemetry_sink(&self) -> Option<&Arc<dyn CdTelemetrySink>> {
        self.telemetry_sink.as_ref()
    }

    /// Attach a verified [`PolicyRepository`] for immutable per-deployment policy snapshots.
    #[must_use]
    pub fn with_policy_repo(mut self, policy_repo: Arc<PolicyRepository>) -> Self {
        self.policy_repo = Some(policy_repo);
        self
    }

    /// Returns the attached [`PolicyRepository`], if configured.
    #[must_use]
    pub fn policy_repo(&self) -> Option<&Arc<PolicyRepository>> {
        self.policy_repo.as_ref()
    }

    /// Publish deployment, gate, lease and outcome changes to the read-only CD API state.
    pub fn with_cd_state(mut self, cd_state: Arc<CdStateStore>) -> Self {
        self.cd_state = Some(cd_state);
        self
    }

    async fn sync_leases(&self) {
        if let Some(ref store) = self.cd_state {
            store.set_leases(self.lease_coordinator.list_leases().await);
        }
    }

    /// Attach a `CanarySloClient` (`MuObserveSloClient`) to gate canary promotion on `MuObserve` SLO verification.
    pub fn with_slo_client(mut self, slo_client: Arc<dyn CanarySloClient>) -> Self {
        self.slo_client = Some(slo_client);
        self
    }

    /// Check whether an artifact digest is currently recorded as tainted
    /// either locally or in MuRegist.
    pub async fn is_digest_tainted(&self, digest: &str) -> Result<bool, OrchestratorError> {
        {
            let local_taints = self.tainted_digests.read().await;
            if local_taints.contains(digest) {
                return Ok(true);
            }
        }

        self.regist_client.is_digest_tainted(digest).await
    }

    /// Mark an artifact digest tainted locally.
    pub async fn mark_local_tainted(&self, digest: impl Into<String>) {
        let mut local_taints = self.tainted_digests.write().await;
        local_taints.insert(digest.into());
    }

    /// Discover and select the first eligible idle target node from the configured list,
    /// polling with bounded exponential backoff up to `self.idle_backoff.wait_timeout`.
    pub async fn select_idle_target_node(
        &self,
        target_nodes: &[String],
    ) -> Result<String, OrchestratorError> {
        self.select_idle_target_node_with_backoff(target_nodes, &self.idle_backoff)
            .await
    }

    /// Discover and select the first eligible idle target node using explicit backoff bounds.
    pub async fn select_idle_target_node_with_backoff(
        &self,
        target_nodes: &[String],
        backoff: &IdleBackoffConfig,
    ) -> Result<String, OrchestratorError> {
        let candidates = Self::resolve_node_candidates(target_nodes);
        if candidates.is_empty() {
            return Err(OrchestratorError::Lease(LeaseError::Internal(
                "No target nodes specified".into(),
            )));
        }

        let Some(ref poller) = self.poller else {
            // Standalone/mock path without cluster poller uses the first resolved node.
            return Ok(candidates[0].1.clone());
        };

        let deadline = tokio::time::Instant::now() + backoff.wait_timeout;
        let mut attempt: u32 = 0;

        loop {
            let nodes = poller
                .fetch_nodes()
                .await
                .map_err(OrchestratorError::Lease)?;
            if let Some(selected) = Self::find_first_eligible_idle_node(&candidates, &nodes) {
                return Ok(selected);
            }

            let now = tokio::time::Instant::now();
            if now >= deadline {
                let resolved_list: Vec<&str> = candidates.iter().map(|(_, r)| r.as_str()).collect();
                return Err(OrchestratorError::Lease(LeaseError::NodeNotIdle(format!(
                    "None of the target nodes {resolved_list:?} became idle within {}ms",
                    backoff.wait_timeout.as_millis()
                ))));
            }

            let remaining = deadline.saturating_duration_since(now);
            let entropy =
                (now_unix_nano().unsigned_abs()) ^ u64::from(attempt).wrapping_mul(0x9E37_79B9);
            let delay = backoff.delay_for_attempt(attempt, entropy, remaining);
            tracing::debug!(
                attempt,
                delay_ms = delay.as_millis() as u64,
                remaining_ms = remaining.as_millis() as u64,
                "Target nodes busy or ineligible; waiting before next idle poll"
            );
            if delay.is_zero() {
                tokio::task::yield_now().await;
            } else {
                tokio::time::sleep(delay).await;
            }
            attempt = attempt.saturating_add(1);
        }
    }

    fn resolve_node_candidates(target_nodes: &[String]) -> Vec<(String, String)> {
        dedup_target_nodes(target_nodes)
            .into_iter()
            .map(|node| (node.clone(), node))
            .collect()
    }

    fn find_first_eligible_idle_node(
        candidates: &[(String, String)],
        nodes: &[ClusterNodeStatus],
    ) -> Option<String> {
        for (raw, resolved) in candidates {
            if let Some(node) = nodes
                .iter()
                .find(|n| n.node_id == *resolved || n.node_id == *raw)
            {
                if node.is_idle_for_deployment() {
                    return Some(resolved.clone());
                }
            }
        }
        None
    }

    /// Orchestrates sequential A/B rollout across every distinct resolved target node
    /// in `config.effective_target_nodes()`.
    ///
    /// Stops on the first failed node, compensates any previously promoted nodes to restore
    /// cluster parity, and emits audit log records.
    pub async fn orchestrate_rollout_for_repo(
        &self,
        config: &MuConDeConfig,
        artifact_sha256: &str,
        repo: Option<&str>,
    ) -> Result<Vec<DeploymentOutcome>, OrchestratorError> {
        self.orchestrate_rollout_for_repo_with_trace(config, artifact_sha256, repo, None)
            .await
    }

    /// Orchestrates sequential A/B rollout across every distinct target node defined by an
    /// immutable verified [`PinnedDeploymentSnapshot`], propagating per-node
    /// [`ScenarioExecutionPlan`] frames (`0x0D`) over additive `mu-cd-ipc` `v0.3.0`.
    pub async fn orchestrate_rollout_with_snapshot(
        &self,
        snapshot: Arc<PinnedDeploymentSnapshot>,
        artifact_sha256: &str,
        repo: Option<&str>,
        parent_trace: Option<TraceContext>,
    ) -> Result<Vec<DeploymentOutcome>, OrchestratorError> {
        self.orchestrate_rollout_with_snapshot_and_arch_digests(
            snapshot,
            artifact_sha256,
            None,
            repo,
            parent_trace,
        )
        .await
    }

    /// Orchestrates sequential A/B rollout across every distinct target node defined by an
    /// immutable verified [`PinnedDeploymentSnapshot`], resolving optional per-architecture
    /// binary and IT archive digests against `snapshot.nodes_inventory` before touching node 1.
    pub async fn orchestrate_rollout_with_snapshot_and_arch_digests(
        &self,
        snapshot: Arc<PinnedDeploymentSnapshot>,
        default_artifact_sha256: &str,
        arch_digests: Option<&ArchDigestMaps>,
        repo: Option<&str>,
        parent_trace: Option<TraceContext>,
    ) -> Result<Vec<DeploymentOutcome>, OrchestratorError> {
        let config = snapshot.to_muconde_config();
        self.orchestrate_rollout_internal(
            &config,
            default_artifact_sha256,
            repo,
            parent_trace,
            Some(snapshot),
            arch_digests,
        )
        .await
    }

    /// Same as [`Self::orchestrate_rollout_for_repo`], propagating parent W3C [`TraceContext`].
    pub async fn orchestrate_rollout_for_repo_with_trace(
        &self,
        config: &MuConDeConfig,
        artifact_sha256: &str,
        repo: Option<&str>,
        parent_trace: Option<TraceContext>,
    ) -> Result<Vec<DeploymentOutcome>, OrchestratorError> {
        self.orchestrate_rollout_internal(config, artifact_sha256, repo, parent_trace, None, None)
            .await
    }

    fn resolve_rollout_node_targets(
        targets: &[String],
        default_artifact_sha256: &str,
        default_it_archive_digest: Option<&str>,
        snapshot: Option<&PinnedDeploymentSnapshot>,
        arch_digests: Option<&ArchDigestMaps>,
    ) -> Result<Vec<ResolvedNodeTarget>, OrchestratorError> {
        let has_arch_bin = arch_digests.is_some_and(|m| !m.binary_digests.is_empty());
        let has_arch_it = arch_digests.is_some_and(|m| !m.it_archive_digests.is_empty());

        let mut plan = Vec::with_capacity(targets.len());
        for node in targets {
            let node_arch = snapshot.and_then(|s| s.node_arch(node));
            let binary_digest = if has_arch_bin {
                let arch = node_arch.ok_or_else(|| {
                    OrchestratorError::DeploymentFailed(format!(
                        "Multi-arch rollout cannot resolve architecture for target node '{node}' from verified nodes inventory"
                    ))
                })?;
                arch_digests
                    .and_then(|m| m.binary_digests.get(&arch))
                    .cloned()
                    .ok_or_else(|| {
                        OrchestratorError::DeploymentFailed(format!(
                            "Missing binary_digests_by_arch entry for target node '{node}' architecture '{}'",
                            arch.as_canonical_str()
                        ))
                    })?
            } else {
                default_artifact_sha256.to_string()
            };

            let it_archive_digest = if has_arch_it {
                let arch = node_arch.ok_or_else(|| {
                    OrchestratorError::DeploymentFailed(format!(
                        "Multi-arch rollout cannot resolve architecture for target node '{node}' from verified nodes inventory"
                    ))
                })?;
                let digest = arch_digests
                    .and_then(|m| m.it_archive_digests.get(&arch))
                    .cloned()
                    .ok_or_else(|| {
                        OrchestratorError::DeploymentFailed(format!(
                            "Missing it_archive_digests_by_arch entry for target node '{node}' architecture '{}'",
                            arch.as_canonical_str()
                        ))
                    })?;
                Some(digest)
            } else {
                default_it_archive_digest.map(str::to_string)
            };

            plan.push(ResolvedNodeTarget {
                node: node.clone(),
                binary_digest,
                it_archive_digest,
            });
        }
        Ok(plan)
    }

    async fn taint_participating_digests(
        &self,
        service: &str,
        deployment_id: &str,
        failed_node: &str,
        already_tainted_digest: Option<&str>,
        participating_digests: &[String],
        reason: &str,
    ) {
        for digest in participating_digests {
            if already_tainted_digest == Some(digest.as_str()) {
                continue;
            }
            self.mark_local_tainted(digest.clone()).await;
            let notif = ArtifactTaintNotification {
                deployment_id: deployment_id.to_string(),
                service_name: service.to_string(),
                artifact_sha256: digest.clone(),
                tainted_at_epoch_ms: LeaseCoordinator::current_epoch_ms(),
                reason: reason.to_string(),
                rollback_completed: true,
            };
            if let Err(e) = self
                .regist_client
                .taint_canary_for_node(digest, Some(failed_node), &notif)
                .await
            {
                tracing::error!(
                    digest = %digest,
                    node = %failed_node,
                    error = %e,
                    "Failed to taint participating multi-arch digest in MuRegist"
                );
            }
        }
    }

    async fn orchestrate_rollout_internal(
        &self,
        config: &MuConDeConfig,
        artifact_sha256: &str,
        repo: Option<&str>,
        parent_trace: Option<TraceContext>,
        snapshot: Option<Arc<PinnedDeploymentSnapshot>>,
        arch_digests: Option<&ArchDigestMaps>,
    ) -> Result<Vec<DeploymentOutcome>, OrchestratorError> {
        config.validate()?;
        let targets = dedup_target_nodes(config.effective_target_nodes());
        if targets.is_empty() {
            return Err(OrchestratorError::Contract(ContractError::EmptyTargetNodes));
        }

        // Pre-node-1 multi-arch resolution (fail closed on missing arch before touching node 1)
        let resolved_targets = Self::resolve_rollout_node_targets(
            &targets,
            artifact_sha256,
            config.it_archive_digest.as_deref(),
            snapshot.as_deref(),
            arch_digests,
        )?;

        // Pre-node-1 taint check across ALL distinct participating binary digests
        let mut distinct_binary_digests = Vec::new();
        for target in &resolved_targets {
            if !distinct_binary_digests.contains(&target.binary_digest) {
                distinct_binary_digests.push(target.binary_digest.clone());
            }
        }
        for digest in &distinct_binary_digests {
            if self.is_digest_tainted(digest).await? {
                return Err(OrchestratorError::ArtifactTainted(digest.clone()));
            }
        }

        let reuse_snapshot_dep_id = resolved_targets.len() == 1
            && is_controller_self_upgrade_service(&config.service)
            && snapshot
                .as_ref()
                .is_some_and(|s| !s.deployment_id.trim().is_empty());

        let mut outcomes = Vec::new();
        let mut promoted: Vec<PromotedNodeRecord> = Vec::new();

        for target in resolved_targets {
            let node = target.node;
            let node_digest = target.binary_digest;
            let mut single_cfg = config.clone();
            single_cfg.target_nodes = vec![node.clone()];
            single_cfg.deployment.target_nodes = vec![node.clone()];
            if let Some(ref it_digest) = target.it_archive_digest {
                single_cfg.it_archive_digest = Some(it_digest.clone());
            }
            let node_dep_id = if reuse_snapshot_dep_id {
                snapshot
                    .as_ref()
                    .map(|s| s.deployment_id.clone())
                    .unwrap_or_else(|| format!("dep-{}", uuid::Uuid::new_v4()))
            } else {
                format!("dep-{}", uuid::Uuid::new_v4())
            };
            if let (Some(ref policy_repo), Some(ref snap)) = (&self.policy_repo, &snapshot) {
                policy_repo.register_snapshot_alias(node_dep_id.clone(), snap.clone());
            }

            match self
                .orchestrate_deployment_internal(
                    &single_cfg,
                    &node_digest,
                    Some(node_dep_id.clone()),
                    repo,
                    parent_trace,
                    snapshot.as_deref(),
                    target.it_archive_digest.as_deref(),
                )
                .await
            {
                Ok(outcome) => match &outcome {
                    DeploymentOutcome::Promoted {
                        deployment_id,
                        target_node,
                        ..
                    } => {
                        let promoted_slot = self
                            .lease_coordinator
                            .active_slot_for(target_node, &config.service)
                            .await;
                        let restore_slot = crate::lease::opposite_slot(promoted_slot);
                        let idx = outcomes.len();
                        promoted.push(PromotedNodeRecord {
                            outcome_index: idx,
                            deployment_id: deployment_id.clone(),
                            node: target_node.clone(),
                            binary_digest: node_digest.clone(),
                            restore_slot,
                        });
                        outcomes.push(outcome);
                    }
                    DeploymentOutcome::RolledBack {
                        deployment_id: failed_dep_id,
                        target_node: failed_node,
                        reason,
                        ..
                    } => {
                        let failed_dep_id = failed_dep_id.clone();
                        let failed_node = failed_node.clone();
                        let reason = reason.clone();
                        outcomes.push(outcome);
                        if !promoted.is_empty() {
                            self.compensate_promoted_nodes(
                                CompensationRequest {
                                    config,
                                    artifact_sha256: &node_digest,
                                    failed_node: &failed_node,
                                    failure_reason: &reason,
                                    taint_in_state: true,
                                    parent_trace,
                                },
                                &promoted,
                                Some(&mut outcomes),
                            )
                            .await?;
                        }
                        self.taint_participating_digests(
                            &config.service,
                            &failed_dep_id,
                            &failed_node,
                            Some(&node_digest),
                            &distinct_binary_digests,
                            &reason,
                        )
                        .await;
                        break;
                    }
                },
                Err(err) => {
                    let should_compensate = !promoted.is_empty()
                        && (!matches!(err, OrchestratorError::IntegrationTestFailed { .. })
                            || config.ab_rules.auto_rollback_on_critical);
                    let taint_digest =
                        matches!(err, OrchestratorError::IntegrationTestFailed { .. });
                    let err_msg = err.to_string();
                    if should_compensate {
                        self.compensate_promoted_nodes(
                            CompensationRequest {
                                config,
                                artifact_sha256: &node_digest,
                                failed_node: &node,
                                failure_reason: &err_msg,
                                taint_in_state: taint_digest,
                                parent_trace,
                            },
                            &promoted,
                            None,
                        )
                        .await?;
                    } else if !promoted.is_empty() {
                        self.emit_partial_rollout_audit(
                            parent_trace,
                            config,
                            &node_digest,
                            &node,
                            "WARN",
                            13,
                            format!(
                                "Multi-node rollout aborted at '{node}' with {} previously promoted node(s) retained per ab_rules",
                                promoted.len()
                            ),
                            Vec::new(),
                        )
                        .await;
                    }
                    if taint_digest {
                        self.taint_participating_digests(
                            &config.service,
                            &node_dep_id,
                            &node,
                            None,
                            &distinct_binary_digests,
                            &err_msg,
                        )
                        .await;
                    }
                    return Err(err);
                }
            }
        }
        Ok(outcomes)
    }

    /// Orchestrate complete deployment workflow for a candidate artifact.
    ///
    /// Steps:
    /// 1. Verifies candidate digest is NOT tainted; refuses deployment immediately if tainted.
    /// 2. Discovers idle target worker node.
    /// 3. Acquires TTL-bounded deployment lease from `LeaseCoordinator`.
    /// 4. Instructs `MuConDe-agent` to stage candidate into Slot B (`@b`).
    /// 5. Dispatches `SlotSwapCommand` to swap pointer to Slot B.
    /// 6. Awaits live integration test and health verification.
    /// 7. **Success Path**: Promotes candidate, calls `POST /api/v1/canary/{digest}/promote` on MuRegist,
    ///    releases deployment lease, and returns `DeploymentOutcome::Promoted`.
    /// 8. **Failure Path**: Immediately dispatches `RollbackCommand` to Slot A, records digest in taint set,
    ///    calls `POST /api/v1/canary/{digest}/taint` on MuRegist, releases lease, and returns `DeploymentOutcome::RolledBack`.
    pub async fn orchestrate_deployment(
        &self,
        config: &MuConDeConfig,
        artifact_sha256: &str,
        custom_deployment_id: Option<String>,
    ) -> Result<DeploymentOutcome, OrchestratorError> {
        self.orchestrate_deployment_for_repo(config, artifact_sha256, custom_deployment_id, None)
            .await
    }

    /// Same as [`Self::orchestrate_deployment`], recording `repo` (`owner/repo`) for the
    /// CD API's `?repo=` filter.
    pub async fn orchestrate_deployment_for_repo(
        &self,
        config: &MuConDeConfig,
        artifact_sha256: &str,
        custom_deployment_id: Option<String>,
        repo: Option<&str>,
    ) -> Result<DeploymentOutcome, OrchestratorError> {
        self.orchestrate_deployment_for_repo_with_trace(
            config,
            artifact_sha256,
            custom_deployment_id,
            repo,
            None,
        )
        .await
    }

    /// Same as [`Self::orchestrate_deployment_for_repo`], propagating parent W3C [`TraceContext`]
    /// and emitting OpenTelemetry spans for `cd.deployment.start`, `cd.slot.stage_b`, and `cd.gate.evaluate`.
    pub async fn orchestrate_deployment_for_repo_with_trace(
        &self,
        config: &MuConDeConfig,
        artifact_sha256: &str,
        custom_deployment_id: Option<String>,
        repo: Option<&str>,
        parent_trace: Option<TraceContext>,
    ) -> Result<DeploymentOutcome, OrchestratorError> {
        self.orchestrate_deployment_internal(
            config,
            artifact_sha256,
            custom_deployment_id,
            repo,
            parent_trace,
            None,
            None,
        )
        .await
    }

    /// Orchestrates a single-node deployment using an immutable [`PinnedDeploymentSnapshot`],
    /// transmitting the resolved [`ScenarioExecutionPlan`] (`0x0D`) ahead of `SlotSwapCommand` (`0x06`).
    pub async fn orchestrate_deployment_with_snapshot(
        &self,
        snapshot: &PinnedDeploymentSnapshot,
        artifact_sha256: &str,
        custom_deployment_id: Option<String>,
        repo: Option<&str>,
        parent_trace: Option<TraceContext>,
    ) -> Result<DeploymentOutcome, OrchestratorError> {
        let config = snapshot.to_muconde_config();
        self.orchestrate_deployment_internal(
            &config,
            artifact_sha256,
            custom_deployment_id,
            repo,
            parent_trace,
            Some(snapshot),
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn orchestrate_deployment_internal(
        &self,
        config: &MuConDeConfig,
        artifact_sha256: &str,
        custom_deployment_id: Option<String>,
        repo: Option<&str>,
        parent_trace: Option<TraceContext>,
        snapshot: Option<&PinnedDeploymentSnapshot>,
        it_archive_digest_override: Option<&str>,
    ) -> Result<DeploymentOutcome, OrchestratorError> {
        let dep_start_ns = now_unix_nano();
        let root_trace = parent_trace.unwrap_or_else(|| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            TraceContext::from_seed(now, 0x4d55_4344_0000_0001, 0x5350_414e_0000_0001, true)
        });
        let dep_span_ctx = root_trace.next_deterministic_child(1);
        let mut spans_to_emit = Vec::new();

        // Step 1: Enforce Digest Tainting Pre-check (#10)
        if self.is_digest_tainted(artifact_sha256).await? {
            return Err(OrchestratorError::ArtifactTainted(
                artifact_sha256.to_string(),
            ));
        }

        // Validate declarative contract
        config.validate()?;

        // Step 2: Select idle target worker node (#4, #77)
        let target_node = self
            .select_idle_target_node(config.effective_target_nodes())
            .await?;

        // Step 3: Acquire TTL deployment lease (#5)
        let deployment_id =
            custom_deployment_id.unwrap_or_else(|| format!("dep-{}", uuid::Uuid::new_v4()));

        let lease_req = DeploymentLeaseRequest {
            deployment_id: deployment_id.clone(),
            node_id: target_node.clone(),
            service_name: config.service.clone(),
            artifact_sha256: artifact_sha256.to_string(),
            requested_ttl_secs: config.lease_ttl_seconds,
        };

        let mut grant = self.lease_coordinator.acquire_lease(&lease_req).await;
        if !grant.granted {
            let reason = grant
                .denial_reason
                .unwrap_or_else(|| "Deployment lease denied".to_string());
            return Err(OrchestratorError::Lease(LeaseError::Internal(reason)));
        }

        if let Some(ref store) = self.cd_state {
            let tests = config
                .selected_tests()
                .map(|t| t.iter().map(|n| (n.clone(), true)).collect())
                .unwrap_or_default();
            store.deployment_started(DeploymentStart::from_grant(
                &grant,
                repo.map(str::to_string),
                &config.service,
                artifact_sha256,
                &target_node,
                tests,
            ));
        }
        self.sync_leases().await;

        // Step 4: Instruct agent to stage deployment bundle into candidate slot (@b)
        let stage_req = StageDeploymentRequest {
            deployment_id: deployment_id.clone(),
            lease_id: grant.lease_id.clone(),
            service_name: config.service.clone(),
            artifact_sha256: artifact_sha256.to_string(),
            target_slot: grant.candidate_slot,
        };

        let stage_start_ns = now_unix_nano();
        let stage_result = self
            .agent_client
            .stage_deployment(&target_node, &stage_req)
            .await;
        let stage_end_ns = now_unix_nano();
        let stage_span_ctx = root_trace.next_deterministic_child(2);

        let staged_slot = match stage_result {
            Ok(ref resp) if resp.staged_ok => resp.target_slot,
            Ok(ref resp) => {
                let err_msg = resp
                    .error_message
                    .clone()
                    .unwrap_or_else(|| "Staging refused by agent".to_string());
                spans_to_emit.push(build_cd_span(
                    stage_span_ctx.trace_id,
                    stage_span_ctx.span_id,
                    Some(dep_span_ctx.span_id),
                    &target_node,
                    Self::stage_span_name(grant.candidate_slot),
                    "INTERNAL",
                    stage_start_ns,
                    stage_end_ns,
                    "ERROR",
                    Some(err_msg.clone()),
                    serde_json::json!({
                        "deployment_id": &deployment_id,
                        "service": &config.service,
                        "slot": Self::slot_label(grant.candidate_slot),
                        "target_node": &target_node,
                    }),
                ));
                spans_to_emit.push(build_cd_span(
                    dep_span_ctx.trace_id,
                    dep_span_ctx.span_id,
                    if root_trace.span_id == dep_span_ctx.span_id {
                        None
                    } else {
                        Some(root_trace.span_id)
                    },
                    &target_node,
                    &format!("cd.deployment.start:{}", config.service),
                    "SERVER",
                    dep_start_ns,
                    now_unix_nano(),
                    "ERROR",
                    Some(format!("Staging failed: {err_msg}")),
                    serde_json::json!({
                        "deployment_id": &deployment_id,
                        "service": &config.service,
                        "target_node": &target_node,
                        "artifact_sha256": artifact_sha256,
                    }),
                ));
                self.emit_telemetry_spans(spans_to_emit).await;
                return self
                    .handle_failure_and_rollback(
                        &grant,
                        config,
                        &target_node,
                        artifact_sha256,
                        &format!("Staging failed: {err_msg}"),
                    )
                    .await;
            }
            Err(e) => {
                let err_msg = format!("Agent stage IPC error: {e}");
                spans_to_emit.push(build_cd_span(
                    stage_span_ctx.trace_id,
                    stage_span_ctx.span_id,
                    Some(dep_span_ctx.span_id),
                    &target_node,
                    Self::stage_span_name(grant.candidate_slot),
                    "INTERNAL",
                    stage_start_ns,
                    stage_end_ns,
                    "ERROR",
                    Some(err_msg.clone()),
                    serde_json::json!({
                        "deployment_id": &deployment_id,
                        "service": &config.service,
                        "slot": Self::slot_label(grant.candidate_slot),
                        "target_node": &target_node,
                    }),
                ));
                spans_to_emit.push(build_cd_span(
                    dep_span_ctx.trace_id,
                    dep_span_ctx.span_id,
                    if root_trace.span_id == dep_span_ctx.span_id {
                        None
                    } else {
                        Some(root_trace.span_id)
                    },
                    &target_node,
                    &format!("cd.deployment.start:{}", config.service),
                    "SERVER",
                    dep_start_ns,
                    now_unix_nano(),
                    "ERROR",
                    Some(err_msg.clone()),
                    serde_json::json!({
                        "deployment_id": &deployment_id,
                        "service": &config.service,
                        "target_node": &target_node,
                        "artifact_sha256": artifact_sha256,
                    }),
                ));
                self.emit_telemetry_spans(spans_to_emit).await;
                return self
                    .handle_failure_and_rollback(
                        &grant,
                        config,
                        &target_node,
                        artifact_sha256,
                        &err_msg,
                    )
                    .await;
            }
        };

        let baseline_slot = crate::lease::opposite_slot(staged_slot);
        if staged_slot != grant.candidate_slot || baseline_slot != grant.active_slot {
            tracing::warn!(
                deployment_id = %deployment_id,
                service = %config.service,
                target_node = %target_node,
                assumed_active = ?grant.active_slot,
                assumed_candidate = ?grant.candidate_slot,
                authoritative_active = ?baseline_slot,
                authoritative_staged = ?staged_slot,
                "Reconciling controller A/B slot state with authoritative StageDeploymentResponse target_slot"
            );
            grant.active_slot = baseline_slot;
            grant.candidate_slot = staged_slot;
            let _ = self
                .lease_coordinator
                .reconcile_lease_slots(&grant.lease_id, baseline_slot, staged_slot)
                .await;
            if let Some(ref store) = self.cd_state {
                store.deployment_slots_reconciled(
                    &deployment_id,
                    Slot::from(baseline_slot),
                    Slot::from(staged_slot),
                );
            }
            self.sync_leases().await;
        }

        spans_to_emit.push(build_cd_span(
            stage_span_ctx.trace_id,
            stage_span_ctx.span_id,
            Some(dep_span_ctx.span_id),
            &target_node,
            Self::stage_span_name(grant.candidate_slot),
            "INTERNAL",
            stage_start_ns,
            stage_end_ns,
            "OK",
            None,
            serde_json::json!({
                "deployment_id": &deployment_id,
                "service": &config.service,
                "slot": Self::slot_label(grant.candidate_slot),
                "target_node": &target_node,
            }),
        ));

        // Step 5: Transmit resolved ScenarioExecutionPlan (0x0D) and perform atomic slot swap (0x06)
        let scenario_plan: Option<ScenarioExecutionPlan> = if let Some(snap) = snapshot {
            snap.plan_for_node_with_it_digest(
                &target_node,
                &deployment_id,
                &grant.lease_id,
                it_archive_digest_override,
            )
            .or_else(|| {
                config.effective_target_nodes().first().and_then(|raw| {
                    snap.plan_for_node_with_it_digest(
                        raw,
                        &deployment_id,
                        &grant.lease_id,
                        it_archive_digest_override,
                    )
                })
            })
        } else {
            it_archive_digest_override
                .map(str::to_string)
                .or_else(|| config.it_archive_digest.clone())
                .map(|digest| ScenarioExecutionPlan {
                    deployment_id: deployment_id.clone(),
                    lease_id: grant.lease_id.clone(),
                    service_name: config.service.clone(),
                    node_id: target_node.clone(),
                    policy_commit_sha: String::new(),
                    it_archive_digest: Some(digest),
                    bundle_id: None,
                    selected_tests: config
                        .selected_tests()
                        .map(|tests| tests.to_vec())
                        .unwrap_or_default(),
                    scenarios: Vec::new(),
                    env: Vec::new(),
                    args: Vec::new(),
                    cidrs: Vec::new(),
                    ro_mounts: Vec::new(),
                    max_pids: MAX_POLICY_SANDBOX_PIDS,
                    max_memlock_kb: DEFAULT_POLICY_SANDBOX_MEMLOCK_KB,
                    auto_rollback_on_critical: config.ab_rules.auto_rollback_on_critical,
                })
        };

        let swap_cmd = SlotSwapCommand {
            deployment_id: deployment_id.clone(),
            lease_id: grant.lease_id.clone(),
            service_name: config.service.clone(),
            from_slot: grant.active_slot,
            to_slot: grant.candidate_slot,
            systemd_unit: config.effective_systemd_unit(),
            warmup_timeout_secs: config.warmup_timeout_seconds,
        };

        // Persist durable 0600 self-upgrade handoff BEFORE triggering controller restart via SlotSwapCommand
        if is_controller_self_upgrade_service(&config.service) {
            if let Some(ref state_dir) = self.state_dir {
                let handoff = PendingControllerSelfUpgrade {
                    deployment_id: deployment_id.clone(),
                    lease_id: grant.lease_id.clone(),
                    service: config.service.clone(),
                    repo: repo.map(str::to_string),
                    target_node: target_node.clone(),
                    artifact_sha256: artifact_sha256.to_string(),
                    active_slot: slot_to_handoff_str(grant.active_slot).to_string(),
                    candidate_slot: slot_to_handoff_str(grant.candidate_slot).to_string(),
                    systemd_unit: swap_cmd.systemd_unit.clone(),
                    policy_commit_sha: snapshot
                        .map(|s| s.policy_commit_sha.clone())
                        .unwrap_or_default(),
                    trace_id: dep_span_ctx.trace_id_hex(),
                    selected_tests: config
                        .selected_tests()
                        .map(|t| t.to_vec())
                        .unwrap_or_default(),
                    bake_window_seconds: config.bake_window_seconds,
                    max_error_logs: config.max_error_logs,
                    max_p99_latency_ms: config.max_p99_latency_ms,
                    warmup_timeout_seconds: config.warmup_timeout_seconds,
                    started_at_epoch_ms: LeaseCoordinator::current_epoch_ms(),
                };
                write_pending_self_upgrade_atomic(&pending_self_upgrade_path(state_dir), &handoff)?;
                tracing::info!(
                    deployment_id = %deployment_id,
                    service = %config.service,
                    target_node = %target_node,
                    state_dir = %state_dir.display(),
                    "Persisted atomic 0600 pending_self_upgrade.json prior to controller SlotSwapCommand"
                );
            }
        }

        if let Err(e) = self
            .agent_client
            .slot_swap_with_plan(&target_node, &swap_cmd, scenario_plan.as_ref())
            .await
        {
            let err_msg = format!("Atomic slot swap failed: {e}");
            spans_to_emit.push(build_cd_span(
                dep_span_ctx.trace_id,
                dep_span_ctx.span_id,
                if root_trace.span_id == dep_span_ctx.span_id {
                    None
                } else {
                    Some(root_trace.span_id)
                },
                &target_node,
                &format!("cd.deployment.start:{}", config.service),
                "SERVER",
                dep_start_ns,
                now_unix_nano(),
                "ERROR",
                Some(err_msg.clone()),
                serde_json::json!({
                    "deployment_id": &deployment_id,
                    "service": &config.service,
                    "target_node": &target_node,
                    "artifact_sha256": artifact_sha256,
                }),
            ));
            self.emit_telemetry_spans(spans_to_emit).await;
            return self
                .handle_failure_and_rollback(
                    &grant,
                    config,
                    &target_node,
                    artifact_sha256,
                    &err_msg,
                )
                .await;
        }

        // Step 6: Await integration test execution and health watchdog
        let it_start_ns = now_unix_nano();
        let it_timeout = Duration::from_secs(config.warmup_timeout_seconds);
        let it_result = self
            .agent_client
            .execute_integration_tests(
                &target_node,
                &deployment_id,
                &config.service,
                artifact_sha256,
                config.selected_tests(),
                it_timeout,
            )
            .await;

        let report = match it_result {
            Ok(r) => {
                if let Some(ref store) = self.cd_state {
                    store.apply_it_report(&r);
                }
                r
            }
            Err(e) => {
                let err_msg = format!("Integration test communication failure: {e}");
                let gate_span_ctx = root_trace.next_deterministic_child(3);
                spans_to_emit.push(build_cd_span(
                    gate_span_ctx.trace_id,
                    gate_span_ctx.span_id,
                    Some(dep_span_ctx.span_id),
                    &target_node,
                    "cd.gate.evaluate",
                    "INTERNAL",
                    it_start_ns,
                    now_unix_nano(),
                    "ERROR",
                    Some(err_msg.clone()),
                    serde_json::json!({
                        "deployment_id": &deployment_id,
                        "service": &config.service,
                        "target_node": &target_node,
                    }),
                ));
                spans_to_emit.push(build_cd_span(
                    dep_span_ctx.trace_id,
                    dep_span_ctx.span_id,
                    if root_trace.span_id == dep_span_ctx.span_id {
                        None
                    } else {
                        Some(root_trace.span_id)
                    },
                    &target_node,
                    &format!("cd.deployment.start:{}", config.service),
                    "SERVER",
                    dep_start_ns,
                    now_unix_nano(),
                    "ERROR",
                    Some(err_msg.clone()),
                    serde_json::json!({
                        "deployment_id": &deployment_id,
                        "service": &config.service,
                        "target_node": &target_node,
                        "artifact_sha256": artifact_sha256,
                    }),
                ));
                self.emit_telemetry_spans(spans_to_emit).await;
                return self
                    .handle_failure_and_rollback(
                        &grant,
                        config,
                        &target_node,
                        artifact_sha256,
                        &err_msg,
                    )
                    .await;
            }
        };

        // Check verification outcome
        let now_ms = LeaseCoordinator::current_epoch_ms();
        let lease_expired = now_ms >= grant.expires_at_epoch_ms;

        if lease_expired {
            let reason = "Lease TTL expired before integration tests completed".to_string();
            let gate_span_ctx = root_trace.next_deterministic_child(3);
            spans_to_emit.push(build_cd_span(
                gate_span_ctx.trace_id,
                gate_span_ctx.span_id,
                Some(dep_span_ctx.span_id),
                &target_node,
                "cd.gate.evaluate",
                "INTERNAL",
                it_start_ns,
                now_unix_nano(),
                "ERROR",
                Some(reason.clone()),
                serde_json::json!({
                    "deployment_id": &deployment_id,
                    "service": &config.service,
                    "target_node": &target_node,
                }),
            ));
            spans_to_emit.push(build_cd_span(
                dep_span_ctx.trace_id,
                dep_span_ctx.span_id,
                if root_trace.span_id == dep_span_ctx.span_id {
                    None
                } else {
                    Some(root_trace.span_id)
                },
                &target_node,
                &format!("cd.deployment.start:{}", config.service),
                "SERVER",
                dep_start_ns,
                now_unix_nano(),
                "ERROR",
                Some(reason.clone()),
                serde_json::json!({
                    "deployment_id": &deployment_id,
                    "service": &config.service,
                    "target_node": &target_node,
                    "artifact_sha256": artifact_sha256,
                }),
            ));
            self.emit_telemetry_spans(spans_to_emit).await;
            if config.ab_rules.auto_rollback_on_critical {
                return self
                    .handle_failure_and_rollback(
                        &grant,
                        config,
                        &target_node,
                        artifact_sha256,
                        &reason,
                    )
                    .await;
            }
            let _ = self.lease_coordinator.release_lease(&grant.lease_id).await;
            self.sync_leases().await;
            return Err(OrchestratorError::IntegrationTestFailed {
                failed_tests: report.failed_tests,
                log: report.log_excerpt,
            });
        }

        if !report.passed || !report.failed_tests.is_empty() {
            let reason = format!("Integration tests failed: {:?}", report.failed_tests);
            let gate_span_ctx = root_trace.next_deterministic_child(3);
            spans_to_emit.push(build_cd_span(
                gate_span_ctx.trace_id,
                gate_span_ctx.span_id,
                Some(dep_span_ctx.span_id),
                &target_node,
                "cd.gate.evaluate",
                "INTERNAL",
                it_start_ns,
                now_unix_nano(),
                "ERROR",
                Some(reason.clone()),
                serde_json::json!({
                    "deployment_id": &deployment_id,
                    "service": &config.service,
                    "target_node": &target_node,
                }),
            ));
            spans_to_emit.push(build_cd_span(
                dep_span_ctx.trace_id,
                dep_span_ctx.span_id,
                if root_trace.span_id == dep_span_ctx.span_id {
                    None
                } else {
                    Some(root_trace.span_id)
                },
                &target_node,
                &format!("cd.deployment.start:{}", config.service),
                "SERVER",
                dep_start_ns,
                now_unix_nano(),
                "ERROR",
                Some(reason.clone()),
                serde_json::json!({
                    "deployment_id": &deployment_id,
                    "service": &config.service,
                    "target_node": &target_node,
                    "artifact_sha256": artifact_sha256,
                }),
            ));
            self.emit_telemetry_spans(spans_to_emit).await;
            if config.ab_rules.auto_rollback_on_critical {
                return self
                    .handle_failure_and_rollback(
                        &grant,
                        config,
                        &target_node,
                        artifact_sha256,
                        &reason,
                    )
                    .await;
            }
            let _ = self.lease_coordinator.release_lease(&grant.lease_id).await;
            self.sync_leases().await;
            return Err(OrchestratorError::IntegrationTestFailed {
                failed_tests: report.failed_tests,
                log: report.log_excerpt,
            });
        }

        // Step 6b: Canary Bake SLO Verification via MuObserve (#12-#15)
        if let Some(ref slo_client) = self.slo_client {
            let slo_req = CanarySloAssertionRequest {
                request_id: format!("slo-{deployment_id}"),
                service_name: config.service.clone(),
                candidate_digest: artifact_sha256.to_string(),
                node_id: target_node.clone(),
                bake_window_secs: config.bake_window_seconds,
                max_error_logs: config.max_error_logs,
                max_p99_latency_ms: config.max_p99_latency_ms,
            };

            match slo_client.verify_canary_slo(&slo_req).await {
                Ok(slo_resp) => {
                    if !slo_resp.healthy || slo_resp.taint_recommended {
                        let reason = format!(
                            "MuObserve canary SLO breach (healthy={}, taint_recommended={}, error_logs={}, p99_latency_ms={:.2}): {}",
                            slo_resp.healthy,
                            slo_resp.taint_recommended,
                            slo_resp.error_log_count,
                            slo_resp.p99_latency_ms,
                            slo_resp.reason
                        );
                        let gate_span_ctx = root_trace.next_deterministic_child(3);
                        spans_to_emit.push(build_cd_span(
                            gate_span_ctx.trace_id,
                            gate_span_ctx.span_id,
                            Some(dep_span_ctx.span_id),
                            &target_node,
                            "cd.gate.evaluate",
                            "INTERNAL",
                            it_start_ns,
                            now_unix_nano(),
                            "ERROR",
                            Some(reason.clone()),
                            serde_json::json!({
                                "deployment_id": &deployment_id,
                                "service": &config.service,
                                "target_node": &target_node,
                            }),
                        ));
                        spans_to_emit.push(build_cd_span(
                            dep_span_ctx.trace_id,
                            dep_span_ctx.span_id,
                            if root_trace.span_id == dep_span_ctx.span_id {
                                None
                            } else {
                                Some(root_trace.span_id)
                            },
                            &target_node,
                            &format!("cd.deployment.start:{}", config.service),
                            "SERVER",
                            dep_start_ns,
                            now_unix_nano(),
                            "ERROR",
                            Some(reason.clone()),
                            serde_json::json!({
                                "deployment_id": &deployment_id,
                                "service": &config.service,
                                "target_node": &target_node,
                                "artifact_sha256": artifact_sha256,
                            }),
                        ));
                        self.emit_telemetry_spans(spans_to_emit).await;
                        return self
                            .handle_failure_and_rollback(
                                &grant,
                                config,
                                &target_node,
                                artifact_sha256,
                                &reason,
                            )
                            .await;
                    }
                }
                Err(e) => {
                    let reason = format!("MuObserve canary SLO verification error: {e}");
                    let gate_span_ctx = root_trace.next_deterministic_child(3);
                    spans_to_emit.push(build_cd_span(
                        gate_span_ctx.trace_id,
                        gate_span_ctx.span_id,
                        Some(dep_span_ctx.span_id),
                        &target_node,
                        "cd.gate.evaluate",
                        "INTERNAL",
                        it_start_ns,
                        now_unix_nano(),
                        "ERROR",
                        Some(reason.clone()),
                        serde_json::json!({
                            "deployment_id": &deployment_id,
                            "service": &config.service,
                            "target_node": &target_node,
                        }),
                    ));
                    spans_to_emit.push(build_cd_span(
                        dep_span_ctx.trace_id,
                        dep_span_ctx.span_id,
                        if root_trace.span_id == dep_span_ctx.span_id {
                            None
                        } else {
                            Some(root_trace.span_id)
                        },
                        &target_node,
                        &format!("cd.deployment.start:{}", config.service),
                        "SERVER",
                        dep_start_ns,
                        now_unix_nano(),
                        "ERROR",
                        Some(reason.clone()),
                        serde_json::json!({
                            "deployment_id": &deployment_id,
                            "service": &config.service,
                            "target_node": &target_node,
                            "artifact_sha256": artifact_sha256,
                        }),
                    ));
                    self.emit_telemetry_spans(spans_to_emit).await;
                    return self
                        .handle_failure_and_rollback(
                            &grant,
                            config,
                            &target_node,
                            artifact_sha256,
                            &reason,
                        )
                        .await;
                }
            }
        }

        // Gate evaluated successfully
        let gate_span_ctx = root_trace.next_deterministic_child(3);
        spans_to_emit.push(build_cd_span(
            gate_span_ctx.trace_id,
            gate_span_ctx.span_id,
            Some(dep_span_ctx.span_id),
            &target_node,
            "cd.gate.evaluate",
            "INTERNAL",
            it_start_ns,
            now_unix_nano(),
            "OK",
            None,
            serde_json::json!({
                "deployment_id": &deployment_id,
                "service": &config.service,
                "target_node": &target_node,
            }),
        ));

        // Step 7: Success Path - Promotion to Slot A (#9)
        // Mark lease as promoted so background expiration sweeps do not trigger rollback
        let _ = self.lease_coordinator.mark_promoted(&grant.lease_id).await;

        // Notify MuRegist of canary promotion
        if let Err(e) = self.regist_client.promote_canary(artifact_sha256).await {
            tracing::error!(
                digest = %artifact_sha256,
                error = %e,
                "MuRegist promotion failed"
            );
        }

        // Release deployment lease
        let _ = self.lease_coordinator.release_lease(&grant.lease_id).await;

        if let Some(ref store) = self.cd_state {
            store.deployment_promoted(&deployment_id, Slot::from(grant.candidate_slot));
        }
        self.sync_leases().await;

        // Emit successful root CD deployment span
        spans_to_emit.push(build_cd_span(
            dep_span_ctx.trace_id,
            dep_span_ctx.span_id,
            if root_trace.span_id == dep_span_ctx.span_id {
                None
            } else {
                Some(root_trace.span_id)
            },
            &target_node,
            &format!("cd.deployment.start:{}", config.service),
            "SERVER",
            dep_start_ns,
            now_unix_nano(),
            "OK",
            None,
            serde_json::json!({
                "deployment_id": &deployment_id,
                "service": &config.service,
                "target_node": &target_node,
                "artifact_sha256": artifact_sha256,
            }),
        ));
        self.emit_telemetry_spans(spans_to_emit).await;

        if is_controller_self_upgrade_service(&config.service) {
            if let Some(ref state_dir) = self.state_dir {
                clear_pending_self_upgrade_if_matching(state_dir, &deployment_id);
            }
        }

        Ok(DeploymentOutcome::Promoted {
            deployment_id,
            service: config.service.clone(),
            target_node,
            artifact_sha256: artifact_sha256.to_string(),
        })
    }

    /// Resumes an interrupted controller self-upgrade from `<state_dir>/pending_self_upgrade.json`
    /// (written atomically prior to `SlotSwapCommand`) when fresh (`<= 10 minutes`).
    ///
    /// Atomically claims and removes the handoff file, hydrates [`CdStateStore`] under the original
    /// `deployment_id`, reconnects to `mu-cd-agent` via [`AgentIpcClient::execute_integration_tests`]
    /// to collect the cached [`IntegrationTestReport`], runs the configured `MuObserve` bake-window
    /// SLO assertion, and finalizes either promotion (`Promoted` + `mu-registry /promote`) or
    /// rollback (`RolledBack` + agent rollback + `mu-registry /taint` with actual `target_node`).
    pub async fn resume_pending_self_upgrade_if_present(
        &self,
    ) -> Result<Option<DeploymentOutcome>, OrchestratorError> {
        let Some(ref state_dir) = self.state_dir else {
            return Ok(None);
        };
        let path = pending_self_upgrade_path(state_dir);
        let Some(pending) = claim_pending_self_upgrade(&path)? else {
            return Ok(None);
        };

        let active_slot = parse_handoff_slot(&pending.active_slot).ok_or_else(|| {
            OrchestratorError::DeploymentFailed(format!(
                "Invalid active_slot '{}' in pending_self_upgrade.json",
                pending.active_slot
            ))
        })?;
        let candidate_slot = parse_handoff_slot(&pending.candidate_slot).ok_or_else(|| {
            OrchestratorError::DeploymentFailed(format!(
                "Invalid candidate_slot '{}' in pending_self_upgrade.json",
                pending.candidate_slot
            ))
        })?;

        tracing::info!(
            deployment_id = %pending.deployment_id,
            service = %pending.service,
            target_node = %pending.target_node,
            active_slot = ?active_slot,
            candidate_slot = ?candidate_slot,
            "Resuming pending controller self-upgrade gate after daemon restart"
        );

        let resume_start_ns = now_unix_nano();
        let warmup_secs = pending.warmup_timeout_seconds.max(1);
        let lease_expires_ms = pending
            .started_at_epoch_ms
            .saturating_add(warmup_secs.max(60).saturating_mul(1000));

        if let Some(ref store) = self.cd_state {
            let tests = pending
                .selected_tests
                .iter()
                .map(|t| (t.clone(), true))
                .collect();
            store.deployment_started(DeploymentStart {
                deployment_id: pending.deployment_id.clone(),
                repo: pending.repo.clone(),
                service: pending.service.clone(),
                artifact_digest: pending.artifact_sha256.clone(),
                target_node: pending.target_node.clone(),
                active_slot: Slot::from(active_slot),
                staged_slot: Slot::from(candidate_slot),
                restore_slot: Slot::from(active_slot),
                lease_id: pending.lease_id.clone(),
                lease_expires_epoch_ms: lease_expires_ms,
                tests,
            });
        }

        let selected_tests = if pending.selected_tests.is_empty() {
            None
        } else {
            Some(pending.selected_tests.as_slice())
        };
        let it_result = self
            .agent_client
            .execute_integration_tests(
                &pending.target_node,
                &pending.deployment_id,
                &pending.service,
                &pending.artifact_sha256,
                selected_tests,
                Duration::from_secs(warmup_secs),
            )
            .await;

        let mut failure_reason: Option<String> = match it_result {
            Ok(report) => {
                if let Some(ref store) = self.cd_state {
                    store.apply_it_report(&report);
                }
                if !report.passed || !report.failed_tests.is_empty() {
                    Some(format!(
                        "Integration tests failed: {:?}",
                        report.failed_tests
                    ))
                } else {
                    None
                }
            }
            Err(e) => Some(format!(
                "Integration test communication failure after controller restart: {e}"
            )),
        };

        if failure_reason.is_none() {
            if let Some(ref slo_client) = self.slo_client {
                let slo_req = CanarySloAssertionRequest {
                    request_id: format!("slo-{}", pending.deployment_id),
                    service_name: pending.service.clone(),
                    candidate_digest: pending.artifact_sha256.clone(),
                    node_id: pending.target_node.clone(),
                    bake_window_secs: pending.bake_window_seconds,
                    max_error_logs: pending.max_error_logs,
                    max_p99_latency_ms: pending.max_p99_latency_ms,
                };
                match slo_client.verify_canary_slo(&slo_req).await {
                    Ok(slo_resp) => {
                        if !slo_resp.healthy || slo_resp.taint_recommended {
                            failure_reason = Some(format!(
                                "MuObserve canary SLO breach (healthy={}, taint_recommended={}, error_logs={}, p99_latency_ms={:.2}): {}",
                                slo_resp.healthy,
                                slo_resp.taint_recommended,
                                slo_resp.error_log_count,
                                slo_resp.p99_latency_ms,
                                slo_resp.reason
                            ));
                        }
                    }
                    Err(e) => {
                        failure_reason =
                            Some(format!("MuObserve canary SLO verification error: {e}"));
                    }
                }
            }
        }

        let trace = Self::resolve_audit_trace(None, resume_start_ns);
        let span_ctx = trace.next_deterministic_child(1);

        if let Some(reason) = failure_reason {
            let rollback_cmd = RollbackCommand {
                deployment_id: pending.deployment_id.clone(),
                lease_id: pending.lease_id.clone(),
                service_name: pending.service.clone(),
                restore_slot: active_slot,
                failed_artifact_sha256: pending.artifact_sha256.clone(),
                reason: reason.clone(),
            };
            if let Err(e) = self
                .agent_client
                .rollback(&pending.target_node, &rollback_cmd)
                .await
            {
                tracing::error!(
                    deployment_id = %pending.deployment_id,
                    node = %pending.target_node,
                    error = %e,
                    "Failed to dispatch rollback command during resumed controller self-upgrade"
                );
            }
            self.mark_local_tainted(pending.artifact_sha256.clone())
                .await;
            let taint_notif = ArtifactTaintNotification {
                deployment_id: pending.deployment_id.clone(),
                service_name: pending.service.clone(),
                artifact_sha256: pending.artifact_sha256.clone(),
                tainted_at_epoch_ms: LeaseCoordinator::current_epoch_ms(),
                reason: reason.clone(),
                rollback_completed: true,
            };
            if let Err(e) = self
                .regist_client
                .taint_canary_for_node(
                    &pending.artifact_sha256,
                    Some(&pending.target_node),
                    &taint_notif,
                )
                .await
            {
                tracing::error!(
                    digest = %pending.artifact_sha256,
                    node = %pending.target_node,
                    error = %e,
                    "Failed to taint digest during resumed controller self-upgrade rollback"
                );
            }
            self.lease_coordinator
                .set_active_slot(&pending.target_node, &pending.service, active_slot)
                .await;
            if let Some(ref store) = self.cd_state {
                store.deployment_rolled_back(
                    &pending.deployment_id,
                    Slot::from(active_slot),
                    classify_rollback_reason(&reason),
                    &reason,
                );
                store.deployment_tainted(&pending.deployment_id, &pending.artifact_sha256, &reason);
            }
            self.sync_leases().await;
            self.emit_telemetry_spans(vec![build_cd_span(
                trace.trace_id,
                span_ctx.span_id,
                None,
                &pending.target_node,
                "cd.deployment.self_upgrade_resume",
                "SERVER",
                resume_start_ns,
                now_unix_nano(),
                "ERROR",
                Some(reason.clone()),
                serde_json::json!({
                    "deployment_id": &pending.deployment_id,
                    "service": &pending.service,
                    "target_node": &pending.target_node,
                    "artifact_sha256": &pending.artifact_sha256,
                    "original_trace_id": &pending.trace_id,
                }),
            )])
            .await;
            return Ok(Some(DeploymentOutcome::RolledBack {
                deployment_id: pending.deployment_id,
                service: pending.service,
                target_node: pending.target_node,
                artifact_sha256: pending.artifact_sha256,
                reason,
            }));
        }

        if let Err(e) = self
            .regist_client
            .promote_canary(&pending.artifact_sha256)
            .await
        {
            tracing::error!(
                digest = %pending.artifact_sha256,
                error = %e,
                "MuRegist promotion failed during resumed controller self-upgrade"
            );
        }
        self.lease_coordinator
            .set_active_slot(&pending.target_node, &pending.service, candidate_slot)
            .await;
        if let Some(ref store) = self.cd_state {
            store.deployment_promoted(&pending.deployment_id, Slot::from(candidate_slot));
        }
        self.sync_leases().await;
        self.emit_telemetry_spans(vec![build_cd_span(
            trace.trace_id,
            span_ctx.span_id,
            None,
            &pending.target_node,
            "cd.deployment.self_upgrade_resume",
            "SERVER",
            resume_start_ns,
            now_unix_nano(),
            "OK",
            None,
            serde_json::json!({
                "deployment_id": &pending.deployment_id,
                "service": &pending.service,
                "target_node": &pending.target_node,
                "artifact_sha256": &pending.artifact_sha256,
                "original_trace_id": &pending.trace_id,
            }),
        )])
        .await;

        Ok(Some(DeploymentOutcome::Promoted {
            deployment_id: pending.deployment_id,
            service: pending.service,
            target_node: pending.target_node,
            artifact_sha256: pending.artifact_sha256,
        }))
    }

    /// Canonical stage span name reflecting the candidate A/B slot.
    const fn stage_span_name(slot: mu_cd_ipc::DeploymentSlot) -> &'static str {
        match slot {
            mu_cd_ipc::DeploymentSlot::SlotA => "cd.slot.stage_a",
            mu_cd_ipc::DeploymentSlot::SlotB => "cd.slot.stage_b",
        }
    }

    /// Canonical lowercase slot label (`"a"` / `"b"`).
    const fn slot_label(slot: mu_cd_ipc::DeploymentSlot) -> &'static str {
        match slot {
            mu_cd_ipc::DeploymentSlot::SlotA => "a",
            mu_cd_ipc::DeploymentSlot::SlotB => "b",
        }
    }

    async fn emit_telemetry_spans(&self, spans: Vec<mu_observable_ipc::OtelSpanEntry>) {
        if let Some(ref sink) = self.telemetry_sink {
            sink.emit_spans(spans).await;
        }
    }

    async fn emit_telemetry_logs(&self, logs: Vec<OtelLogEntry>) {
        if let Some(ref sink) = self.telemetry_sink {
            sink.emit_logs(logs).await;
        }
    }

    fn resolve_audit_trace(parent_trace: Option<TraceContext>, now_ns: i64) -> TraceContext {
        parent_trace.unwrap_or_else(|| {
            TraceContext::from_seed(
                now_ns as u64,
                (now_ns as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1,
                1,
                true,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn emit_partial_rollout_audit(
        &self,
        parent_trace: Option<TraceContext>,
        config: &MuConDeConfig,
        artifact_sha256: &str,
        node_id: &str,
        severity_text: &str,
        severity_number: i32,
        body: String,
        compensated_nodes: Vec<String>,
    ) {
        let now_ns = now_unix_nano();
        let trace = Self::resolve_audit_trace(parent_trace, now_ns);
        let child = trace.next_deterministic_child(10);
        let entry = build_cd_log(
            trace.trace_id,
            child.span_id,
            now_ns,
            severity_number,
            severity_text,
            node_id,
            body,
            serde_json::json!({
                "event": "cd.rollout.partial_rollback",
                "service": &config.service,
                "failed_node": node_id,
                "compensated_nodes": compensated_nodes,
                "artifact_sha256": artifact_sha256,
            }),
        );
        self.emit_telemetry_logs(vec![entry]).await;
    }

    async fn compensate_promoted_nodes(
        &self,
        req: CompensationRequest<'_>,
        promoted: &[PromotedNodeRecord],
        mut outcomes: Option<&mut Vec<DeploymentOutcome>>,
    ) -> Result<(), OrchestratorError> {
        let mut compensated_nodes = Vec::new();
        let mut comp_failures = Vec::new();
        let mut spans = Vec::new();

        for (step, track) in promoted.iter().rev().enumerate() {
            let comp_reason = format!(
                "Compensating multi-node rollback after failure on '{}': {}",
                req.failed_node, req.failure_reason
            );
            let cmd = RollbackCommand {
                deployment_id: track.deployment_id.clone(),
                lease_id: format!("compensate-{}", track.deployment_id),
                service_name: req.config.service.clone(),
                restore_slot: track.restore_slot,
                failed_artifact_sha256: track.binary_digest.clone(),
                reason: comp_reason.clone(),
            };
            let span_start = now_unix_nano();
            let trace = Self::resolve_audit_trace(req.parent_trace, span_start);
            let span_ctx = trace.next_deterministic_child((100 + step) as u64);

            match self.agent_client.rollback(&track.node, &cmd).await {
                Ok(()) => {
                    self.lease_coordinator
                        .set_active_slot(&track.node, &req.config.service, track.restore_slot)
                        .await;
                    if let Some(ref store) = self.cd_state {
                        if req.taint_in_state {
                            store.deployment_tainted(
                                &track.deployment_id,
                                &track.binary_digest,
                                &comp_reason,
                            );
                        }
                        store.deployment_rolled_back(
                            &track.deployment_id,
                            Slot::from(track.restore_slot),
                            classify_rollback_reason(req.failure_reason),
                            &comp_reason,
                        );
                    }
                    spans.push(build_cd_span(
                        trace.trace_id,
                        span_ctx.span_id,
                        req.parent_trace.map(|p| p.span_id),
                        &track.node,
                        "cd.ab.rollback",
                        "SERVER",
                        span_start,
                        now_unix_nano(),
                        "OK",
                        Some(comp_reason.clone()),
                        serde_json::json!({
                            "deployment_id": &track.deployment_id,
                            "service": &req.config.service,
                            "target_node": &track.node,
                            "restore_slot": Self::slot_label(track.restore_slot),
                            "compensating": true,
                            "failed_node": req.failed_node,
                        }),
                    ));
                    compensated_nodes.push(track.node.clone());
                    if let Some(ref mut out) = outcomes {
                        if let Some(slot) = out.get_mut(track.outcome_index) {
                            *slot = DeploymentOutcome::RolledBack {
                                deployment_id: track.deployment_id.clone(),
                                service: req.config.service.clone(),
                                target_node: track.node.clone(),
                                artifact_sha256: track.binary_digest.clone(),
                                reason: comp_reason,
                            };
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(
                        deployment_id = %track.deployment_id,
                        node = %track.node,
                        error = %e,
                        "Failed compensating rollback on previously promoted node"
                    );
                    comp_failures.push(format!("{}: {e}", track.node));
                    spans.push(build_cd_span(
                        trace.trace_id,
                        span_ctx.span_id,
                        req.parent_trace.map(|p| p.span_id),
                        &track.node,
                        "cd.ab.rollback",
                        "SERVER",
                        span_start,
                        now_unix_nano(),
                        "ERROR",
                        Some(e.to_string()),
                        serde_json::json!({
                            "deployment_id": &track.deployment_id,
                            "service": &req.config.service,
                            "target_node": &track.node,
                            "compensating": true,
                            "failed_node": req.failed_node,
                        }),
                    ));
                }
            }
        }

        self.sync_leases().await;
        if !spans.is_empty() {
            self.emit_telemetry_spans(spans).await;
        }
        let (severity_text, severity_num, summary) = if comp_failures.is_empty() {
            (
                "WARN",
                13,
                format!(
                    "Multi-node partial rollback completed for '{}' after failure on '{}': rolled back {:?}",
                    req.config.service, req.failed_node, compensated_nodes
                ),
            )
        } else {
            (
                "ERROR",
                17,
                format!(
                    "Multi-node partial rollback incomplete for '{}' after failure on '{}': rolled back {:?}, failed {:?}",
                    req.config.service, req.failed_node, compensated_nodes, comp_failures
                ),
            )
        };
        self.emit_partial_rollout_audit(
            req.parent_trace,
            req.config,
            req.artifact_sha256,
            req.failed_node,
            severity_text,
            severity_num,
            summary,
            compensated_nodes,
        )
        .await;

        if !comp_failures.is_empty() {
            return Err(OrchestratorError::RollbackFailed(comp_failures.join("; ")));
        }
        Ok(())
    }

    /// Handles failure, lease expiration, or IT regression by triggering atomic rollback
    /// and digest tainting (#9, #10).
    async fn handle_failure_and_rollback(
        &self,
        grant: &DeploymentLeaseGrant,
        config: &MuConDeConfig,
        target_node: &str,
        artifact_sha256: &str,
        reason: &str,
    ) -> Result<DeploymentOutcome, OrchestratorError> {
        tracing::warn!(
            deployment_id = %grant.deployment_id,
            service = %config.service,
            node = %target_node,
            digest = %artifact_sha256,
            reason = %reason,
            "Deployment failed verification; initiating rollback and digest taint"
        );

        // 1. Dispatch immediate RollbackCommand to restore Slot A
        let rollback_cmd = RollbackCommand {
            deployment_id: grant.deployment_id.clone(),
            lease_id: grant.lease_id.clone(),
            service_name: config.service.clone(),
            restore_slot: grant.active_slot,
            failed_artifact_sha256: artifact_sha256.to_string(),
            reason: reason.to_string(),
        };

        if let Err(e) = self.agent_client.rollback(target_node, &rollback_cmd).await {
            tracing::error!(
                node = %target_node,
                error = %e,
                "Failed to dispatch rollback command to agent"
            );
        }

        // 2. Record digest locally in taint set (#10)
        self.mark_local_tainted(artifact_sha256).await;

        // 3. Notify MuRegist of tainted digest (#10)
        let taint_notification = ArtifactTaintNotification {
            deployment_id: grant.deployment_id.clone(),
            service_name: config.service.clone(),
            artifact_sha256: artifact_sha256.to_string(),
            tainted_at_epoch_ms: LeaseCoordinator::current_epoch_ms(),
            reason: reason.to_string(),
            rollback_completed: true,
        };

        if let Err(e) = self
            .regist_client
            .taint_canary_for_node(artifact_sha256, Some(target_node), &taint_notification)
            .await
        {
            tracing::error!(
                digest = %artifact_sha256,
                node = %target_node,
                error = %e,
                "Failed to send taint notification to MuRegist"
            );
        }

        // 4. Clean up lease in LeaseCoordinator and pin tracked live slot to restored baseline
        let _ = self.lease_coordinator.release_lease(&grant.lease_id).await;
        self.lease_coordinator
            .set_active_slot(target_node, &config.service, grant.active_slot)
            .await;

        if let Some(ref store) = self.cd_state {
            store.deployment_rolled_back(
                &grant.deployment_id,
                Slot::from(grant.active_slot),
                classify_rollback_reason(reason),
                reason,
            );
            store.deployment_tainted(&grant.deployment_id, artifact_sha256, reason);
        }
        self.sync_leases().await;

        let now_ns = now_unix_nano();
        let audit_trace = Self::resolve_audit_trace(None, now_ns);
        let audit_span = audit_trace.next_deterministic_child(9);
        self.emit_telemetry_logs(vec![build_cd_log(
            audit_trace.trace_id,
            audit_span.span_id,
            now_ns,
            13,
            "WARN",
            target_node,
            format!(
                "Automatic A/B rollback executed for '{}' on '{}': {reason}",
                config.service, target_node
            ),
            serde_json::json!({
                "event": "cd.ab.rollback",
                "deployment_id": &grant.deployment_id,
                "service": &config.service,
                "target_node": target_node,
                "restore_slot": Self::slot_label(grant.active_slot),
                "tainted_digest": artifact_sha256,
            }),
        )])
        .await;

        if is_controller_self_upgrade_service(&config.service) {
            if let Some(ref state_dir) = self.state_dir {
                clear_pending_self_upgrade_if_matching(state_dir, &grant.deployment_id);
            }
        }

        Ok(DeploymentOutcome::RolledBack {
            deployment_id: grant.deployment_id.clone(),
            service: config.service.clone(),
            target_node: target_node.to_string(),
            artifact_sha256: artifact_sha256.to_string(),
            reason: reason.to_string(),
        })
    }

    /// Executes an operator-triggered emergency A|B rollback (`POST /api/cd/deployments/{id}/rollback`):
    /// dispatches an immediate [`RollbackCommand`] to restore the prior `@a`/`@b` slot, updates
    /// [`LeaseCoordinator`], taints the artifact digest locally and in `mu-registry`, updates
    /// [`CdStateStore`], and emits a `cd.ab.rollback` telemetry span.
    pub async fn emergency_rollback(
        &self,
        deployment_id: &str,
        note: Option<&str>,
    ) -> Result<crate::cd_state::AbRollbackResponseDto, OrchestratorError> {
        let store = self
            .cd_state
            .as_ref()
            .ok_or_else(|| OrchestratorError::DeploymentNotFound(deployment_id.to_string()))?;
        let snap = store.snapshot();
        let record = snap
            .deployment(deployment_id)
            .ok_or_else(|| OrchestratorError::DeploymentNotFound(deployment_id.to_string()))?
            .clone();

        let reason = match note.map(str::trim).filter(|s| !s.is_empty()) {
            Some(n) => format!("Manual emergency rollback: {n}"),
            None => "Manual emergency rollback requested by operator".to_string(),
        };

        let restore_slot_ipc = match record.restore_slot {
            Slot::A => mu_cd_ipc::DeploymentSlot::SlotA,
            Slot::B => mu_cd_ipc::DeploymentSlot::SlotB,
        };
        let rollback_cmd = RollbackCommand {
            deployment_id: record.deployment_id.clone(),
            lease_id: record.lease_id.clone(),
            service_name: record.service.clone(),
            restore_slot: restore_slot_ipc,
            failed_artifact_sha256: record.artifact_digest.clone(),
            reason: reason.clone(),
        };

        self.agent_client
            .rollback(&record.target_node, &rollback_cmd)
            .await?;

        if !record.lease_id.is_empty() {
            let _ = self.lease_coordinator.release_lease(&record.lease_id).await;
        }
        if !record.target_node.is_empty() && !record.service.is_empty() {
            self.lease_coordinator
                .set_active_slot(&record.target_node, &record.service, restore_slot_ipc)
                .await;
        }

        let tainted_digest = if !record.artifact_digest.is_empty() {
            self.mark_local_tainted(&record.artifact_digest).await;
            let taint_notification = ArtifactTaintNotification {
                deployment_id: record.deployment_id.clone(),
                service_name: record.service.clone(),
                artifact_sha256: record.artifact_digest.clone(),
                tainted_at_epoch_ms: LeaseCoordinator::current_epoch_ms(),
                reason: reason.clone(),
                rollback_completed: true,
            };
            let taint_node =
                (!record.target_node.trim().is_empty()).then_some(record.target_node.as_str());
            self.regist_client
                .taint_canary_for_node(&record.artifact_digest, taint_node, &taint_notification)
                .await?;
            store.deployment_tainted(&record.deployment_id, &record.artifact_digest, &reason);
            Some(record.artifact_digest.clone())
        } else {
            None
        };

        store.deployment_rolled_back(
            &record.deployment_id,
            record.restore_slot,
            crate::cd_state::RollbackReason::Manual,
            &reason,
        );
        self.sync_leases().await;

        let now_ns = now_unix_nano();
        let span_ctx = TraceContext::from_seed(
            now_ns as u64,
            (now_ns as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1,
            1,
            true,
        );
        self.emit_telemetry_spans(vec![build_cd_span(
            span_ctx.trace_id,
            span_ctx.span_id,
            None,
            &record.target_node,
            "cd.ab.rollback",
            "SERVER",
            now_ns,
            now_ns,
            "OK",
            Some(reason.clone()),
            serde_json::json!({
                "deployment_id": &record.deployment_id,
                "service": &record.service,
                "target_node": &record.target_node,
                "restore_slot": Self::slot_label(restore_slot_ipc),
                "tainted_digest": &tainted_digest,
            }),
        )])
        .await;
        self.emit_telemetry_logs(vec![build_cd_log(
            span_ctx.trace_id,
            span_ctx.span_id,
            now_ns,
            13,
            "WARN",
            &record.target_node,
            format!(
                "Emergency A/B rollback executed for '{}' on '{}': {reason}",
                record.service, record.target_node
            ),
            serde_json::json!({
                "event": "cd.ab.rollback",
                "deployment_id": &record.deployment_id,
                "service": &record.service,
                "target_node": &record.target_node,
                "restore_slot": Self::slot_label(restore_slot_ipc),
                "tainted_digest": &tainted_digest,
            }),
        )])
        .await;

        Ok(crate::cd_state::AbRollbackResponseDto {
            deployment_id: record.deployment_id,
            restored_slot: record.restore_slot,
            tainted_digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mu_cd_ipc::DeploymentSlot;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use tokio::sync::Mutex;

    // Mock implementation of AgentIpcClient
    #[derive(Default)]
    struct MockAgentClient {
        pub stage_ok: AtomicBool,
        pub stage_calls: AtomicU32,
        pub stage_override_slots: Mutex<std::collections::HashMap<String, DeploymentSlot>>,
        pub swap_ok: AtomicBool,
        pub swap_calls: AtomicU32,
        pub swap_commands: Mutex<Vec<(String, SlotSwapCommand)>>,
        pub it_passed: AtomicBool,
        pub it_failed_tests: Mutex<Vec<String>>,
        pub fail_it_node: Mutex<Option<String>>,
        pub rollback_calls: AtomicU32,
        pub last_rollback_cmd: Mutex<Option<RollbackCommand>>,
        pub rollback_nodes: Mutex<Vec<(String, DeploymentSlot)>>,
    }

    #[async_trait]
    impl AgentIpcClient for MockAgentClient {
        async fn stage_deployment(
            &self,
            node_id: &str,
            req: &StageDeploymentRequest,
        ) -> Result<StageDeploymentResponse, OrchestratorError> {
            self.stage_calls.fetch_add(1, Ordering::SeqCst);
            let ok = self.stage_ok.load(Ordering::SeqCst);
            let target_slot = self
                .stage_override_slots
                .lock()
                .await
                .get(node_id)
                .copied()
                .unwrap_or(req.target_slot);
            Ok(StageDeploymentResponse {
                deployment_id: req.deployment_id.clone(),
                target_slot,
                btrfs_subvolume_path: match target_slot {
                    DeploymentSlot::SlotA => "/srv/muconde/slots/slot-a".into(),
                    DeploymentSlot::SlotB => "/srv/muconde/slots/slot-b".into(),
                },
                staged_ok: ok,
                error_message: if ok {
                    None
                } else {
                    Some("Staging simulated failure".into())
                },
            })
        }

        async fn slot_swap(
            &self,
            node_id: &str,
            cmd: &SlotSwapCommand,
        ) -> Result<(), OrchestratorError> {
            self.swap_calls.fetch_add(1, Ordering::SeqCst);
            self.swap_commands
                .lock()
                .await
                .push((node_id.to_string(), cmd.clone()));
            if self.swap_ok.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(OrchestratorError::Agent("Swap simulated failure".into()))
            }
        }

        async fn execute_integration_tests(
            &self,
            node_id: &str,
            deployment_id: &str,
            service: &str,
            artifact_sha256: &str,
            _selected_tests: Option<&[String]>,
            _timeout: Duration,
        ) -> Result<IntegrationTestReport, OrchestratorError> {
            let force_fail = self
                .fail_it_node
                .lock()
                .await
                .as_deref()
                .is_some_and(|n| n == node_id);
            let passed = !force_fail && self.it_passed.load(Ordering::SeqCst);
            let failed = if force_fail {
                vec!["it_smoke".to_string()]
            } else {
                self.it_failed_tests.lock().await.clone()
            };
            Ok(IntegrationTestReport {
                deployment_id: deployment_id.to_string(),
                service_name: service.to_string(),
                artifact_sha256: artifact_sha256.to_string(),
                executed_tests: vec!["it_smoke".into()],
                passed,
                failed_tests: failed,
                duration_ms: 100,
                log_excerpt: None,
            })
        }

        async fn rollback(
            &self,
            node_id: &str,
            cmd: &RollbackCommand,
        ) -> Result<(), OrchestratorError> {
            self.rollback_calls.fetch_add(1, Ordering::SeqCst);
            self.rollback_nodes
                .lock()
                .await
                .push((node_id.to_string(), cmd.restore_slot));
            let mut last = self.last_rollback_cmd.lock().await;
            *last = Some(cmd.clone());
            Ok(())
        }
    }

    // Mock implementation of MuRegistClient
    #[derive(Default)]
    struct MockMuRegistClient {
        pub tainted_digests: Mutex<HashSet<String>>,
        pub promote_calls: AtomicU32,
        pub taint_calls: AtomicU32,
        pub last_taint: Mutex<Option<(String, ArtifactTaintNotification)>>,
        pub last_taint_node: Mutex<Option<String>>,
    }

    #[async_trait]
    impl MuRegistClient for MockMuRegistClient {
        async fn is_digest_tainted(&self, digest: &str) -> Result<bool, OrchestratorError> {
            let taints = self.tainted_digests.lock().await;
            Ok(taints.contains(digest))
        }

        async fn promote_canary(&self, digest: &str) -> Result<(), OrchestratorError> {
            let taints = self.tainted_digests.lock().await;
            if taints.contains(digest) {
                return Err(OrchestratorError::ArtifactTainted(digest.to_string()));
            }
            self.promote_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn taint_canary(
            &self,
            digest: &str,
            notification: &ArtifactTaintNotification,
        ) -> Result<(), OrchestratorError> {
            self.taint_canary_for_node(digest, None, notification).await
        }

        async fn taint_canary_for_node(
            &self,
            digest: &str,
            node_id: Option<&str>,
            notification: &ArtifactTaintNotification,
        ) -> Result<(), OrchestratorError> {
            self.taint_calls.fetch_add(1, Ordering::SeqCst);
            let mut taints = self.tainted_digests.lock().await;
            taints.insert(digest.to_string());
            let mut last = self.last_taint.lock().await;
            *last = Some((digest.to_string(), notification.clone()));
            let mut last_node = self.last_taint_node.lock().await;
            *last_node = node_id.map(ToOwned::to_owned);
            Ok(())
        }
    }

    fn sample_config() -> MuConDeConfig {
        MuConDeConfig {
            version: "1".into(),
            service: "action-runner".into(),
            target_nodes: vec!["worker-riscv64".into()],
            lease_ttl_seconds: 300,
            warmup_timeout_seconds: 30,
            bake_window_seconds: 60,
            max_error_logs: 0,
            max_p99_latency_ms: 250.0,
            integration_tests: crate::contract::IntegrationTestSelector::All("all".into()),
            it_archive_digest: None,
            ab_rules: crate::contract::AbRulesConfig::default(),
            deployment: crate::contract::DeploymentConfig::default(),
        }
    }

    struct MockSloClient {
        pub healthy: AtomicBool,
        pub taint_recommended: AtomicBool,
        pub error_log_count: AtomicU32,
        pub p99_latency_ms: Mutex<f64>,
        pub reason: Mutex<String>,
        pub slo_calls: AtomicU32,
    }

    impl Default for MockSloClient {
        fn default() -> Self {
            Self {
                healthy: AtomicBool::new(true),
                taint_recommended: AtomicBool::new(false),
                error_log_count: AtomicU32::new(0),
                p99_latency_ms: Mutex::new(35.0),
                reason: Mutex::new("SLO within bounds".into()),
                slo_calls: AtomicU32::new(0),
            }
        }
    }

    #[async_trait]
    impl CanarySloClient for MockSloClient {
        async fn verify_canary_slo(
            &self,
            req: &CanarySloAssertionRequest,
        ) -> Result<mu_observable_ipc::CanarySloAssertionResponse, OrchestratorError> {
            self.slo_calls.fetch_add(1, Ordering::SeqCst);
            Ok(mu_observable_ipc::CanarySloAssertionResponse {
                request_id: req.request_id.clone(),
                healthy: self.healthy.load(Ordering::SeqCst),
                error_log_count: self.error_log_count.load(Ordering::SeqCst),
                p99_latency_ms: *self.p99_latency_ms.lock().await,
                taint_recommended: self.taint_recommended.load(Ordering::SeqCst),
                reason: self.reason.lock().await.clone(),
            })
        }
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_orchestrator_full_success_path() {
        let coordinator = Arc::new(LeaseCoordinator::new());
        let agent = Arc::new(MockAgentClient {
            stage_ok: AtomicBool::new(true),
            swap_ok: AtomicBool::new(true),
            it_passed: AtomicBool::new(true),
            ..Default::default()
        });
        let regist = Arc::new(MockMuRegistClient::default());

        let orchestrator =
            DeploymentOrchestrator::new(coordinator.clone(), None, agent.clone(), regist.clone());

        let config = sample_config();
        let digest = "sha256-success-123";

        let outcome = orchestrator
            .orchestrate_deployment(&config, digest, Some("dep-success".into()))
            .await
            .expect("deployment should succeed");

        assert!(outcome.is_promoted());
        assert_eq!(agent.stage_calls.load(Ordering::SeqCst), 1);
        assert_eq!(agent.swap_calls.load(Ordering::SeqCst), 1);
        assert_eq!(agent.rollback_calls.load(Ordering::SeqCst), 0);
        assert_eq!(regist.promote_calls.load(Ordering::SeqCst), 1);
        assert_eq!(regist.taint_calls.load(Ordering::SeqCst), 0);

        // Verify lease was released
        let active_leases = coordinator.sweep_expired_leases().await;
        assert!(active_leases.is_empty());
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_orchestrator_it_failure_triggers_rollback_and_taint() {
        let coordinator = Arc::new(LeaseCoordinator::new());
        let agent = Arc::new(MockAgentClient {
            stage_ok: AtomicBool::new(true),
            swap_ok: AtomicBool::new(true),
            it_passed: AtomicBool::new(false),
            it_failed_tests: Mutex::new(vec!["it_smoke".into()]),
            ..Default::default()
        });
        let regist = Arc::new(MockMuRegistClient::default());

        let orchestrator =
            DeploymentOrchestrator::new(coordinator.clone(), None, agent.clone(), regist.clone());

        let config = sample_config();
        let digest = "sha256-it-fail-123";

        let outcome = orchestrator
            .orchestrate_deployment(&config, digest, Some("dep-it-fail".into()))
            .await
            .expect("orchestrator should return outcome");

        assert!(outcome.is_rolled_back());
        assert_eq!(agent.stage_calls.load(Ordering::SeqCst), 1);
        assert_eq!(agent.swap_calls.load(Ordering::SeqCst), 1);
        assert_eq!(agent.rollback_calls.load(Ordering::SeqCst), 1);
        assert_eq!(regist.promote_calls.load(Ordering::SeqCst), 0);
        assert_eq!(regist.taint_calls.load(Ordering::SeqCst), 1);

        // Verify rollback command details
        let last_rb = agent.last_rollback_cmd.lock().await;
        let rb = last_rb.as_ref().expect("rollback command was dispatched");
        assert_eq!(rb.restore_slot, DeploymentSlot::SlotA);
        assert_eq!(rb.failed_artifact_sha256, digest);

        // Subsequent deployment attempt of the tainted digest MUST be refused pre-lease
        let retry_outcome = orchestrator
            .orchestrate_deployment(&config, digest, Some("dep-retry".into()))
            .await;

        match retry_outcome {
            Err(OrchestratorError::ArtifactTainted(d)) => assert_eq!(d, digest),
            other => panic!("Expected ArtifactTainted error, got: {:?}", other),
        }

        // Staging count should not have increased on the refused retry
        assert_eq!(agent.stage_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_orchestrator_slo_healthy_promotes_canary() {
        let coordinator = Arc::new(LeaseCoordinator::new());
        let agent = Arc::new(MockAgentClient {
            stage_ok: AtomicBool::new(true),
            swap_ok: AtomicBool::new(true),
            it_passed: AtomicBool::new(true),
            ..Default::default()
        });
        let regist = Arc::new(MockMuRegistClient::default());
        let slo = Arc::new(MockSloClient::default());

        let orchestrator =
            DeploymentOrchestrator::new(coordinator.clone(), None, agent.clone(), regist.clone())
                .with_slo_client(slo.clone());

        let config = sample_config();
        let digest = "sha256-slo-healthy-123";

        let outcome = orchestrator
            .orchestrate_deployment(&config, digest, Some("dep-slo-ok".into()))
            .await
            .expect("deployment should succeed");

        assert!(outcome.is_promoted());
        assert_eq!(slo.slo_calls.load(Ordering::SeqCst), 1);
        assert_eq!(regist.promote_calls.load(Ordering::SeqCst), 1);
        assert_eq!(regist.taint_calls.load(Ordering::SeqCst), 0);
        assert_eq!(agent.rollback_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_orchestrator_slo_breach_triggers_rollback_and_taint() {
        let coordinator = Arc::new(LeaseCoordinator::new());
        let agent = Arc::new(MockAgentClient {
            stage_ok: AtomicBool::new(true),
            swap_ok: AtomicBool::new(true),
            it_passed: AtomicBool::new(true),
            ..Default::default()
        });
        let regist = Arc::new(MockMuRegistClient::default());
        let slo = Arc::new(MockSloClient {
            healthy: AtomicBool::new(false),
            taint_recommended: AtomicBool::new(true),
            error_log_count: AtomicU32::new(4),
            p99_latency_ms: Mutex::new(420.5),
            reason: Mutex::new("error_log_count (4 > 0) and p99_latency_ms (420.5 > 250.0)".into()),
            slo_calls: AtomicU32::new(0),
        });

        let orchestrator =
            DeploymentOrchestrator::new(coordinator.clone(), None, agent.clone(), regist.clone())
                .with_slo_client(slo.clone());

        let config = sample_config();
        let digest = "sha256-slo-breach-999";

        let outcome = orchestrator
            .orchestrate_deployment(&config, digest, Some("dep-slo-breach".into()))
            .await
            .expect("orchestrator should return RolledBack outcome");

        assert!(outcome.is_rolled_back());
        assert_eq!(slo.slo_calls.load(Ordering::SeqCst), 1);
        assert_eq!(agent.rollback_calls.load(Ordering::SeqCst), 1);
        assert_eq!(regist.promote_calls.load(Ordering::SeqCst), 0);
        assert_eq!(regist.taint_calls.load(Ordering::SeqCst), 1);

        let last_rb = agent.last_rollback_cmd.lock().await;
        let rb = last_rb.as_ref().expect("rollback command dispatched");
        assert_eq!(rb.restore_slot, DeploymentSlot::SlotA);
        assert_eq!(rb.failed_artifact_sha256, digest);
        assert!(rb.reason.contains("MuObserve canary SLO breach"));
    }

    #[test]
    fn test_dedup_target_nodes_preserves_order_and_deduplicates_simple() {
        let input = vec![
            " node-a ".into(),
            "node-b".into(),
            "worker-riscv64".into(),
            "node-a".into(),
        ];
        assert_eq!(
            dedup_target_nodes(&input),
            vec!["node-a", "node-b", "worker-riscv64"]
        );
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_orchestrate_rollout_for_repo_multi_node() {
        let coordinator = Arc::new(LeaseCoordinator::new());
        let agent = Arc::new(MockAgentClient {
            stage_ok: AtomicBool::new(true),
            swap_ok: AtomicBool::new(true),
            it_passed: AtomicBool::new(true),
            ..Default::default()
        });
        let regist = Arc::new(MockMuRegistClient::default());
        let orchestrator =
            DeploymentOrchestrator::new(coordinator, None, agent.clone(), regist.clone());

        let mut config = sample_config();
        config.target_nodes = vec!["node-a".into(), "node-b".into()];
        let outcomes = orchestrator
            .orchestrate_rollout_for_repo(&config, "sha256-multi-1", Some("LMA1980/mu-console"))
            .await
            .expect("multi-node rollout should succeed");

        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(DeploymentOutcome::is_promoted));
        assert_eq!(agent.stage_calls.load(Ordering::SeqCst), 2);
        assert_eq!(agent.swap_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_orchestrate_deployment_emits_w3c_trace_spans() {
        use crate::telemetry::RecordingCdTelemetrySink;

        let coordinator = Arc::new(LeaseCoordinator::new());
        let agent = Arc::new(MockAgentClient {
            stage_ok: AtomicBool::new(true),
            swap_ok: AtomicBool::new(true),
            it_passed: AtomicBool::new(true),
            ..Default::default()
        });
        let regist = Arc::new(MockMuRegistClient::default());
        let recording_sink = Arc::new(RecordingCdTelemetrySink::new());

        let orchestrator = DeploymentOrchestrator::new(coordinator, None, agent, regist)
            .with_telemetry_sink(recording_sink.clone());

        let mut config = sample_config();
        config.target_nodes = vec!["node-a".into()];

        let root_trace = TraceContext::from_seed(
            0x1111_2222_3333_4444,
            0x5555_6666_7777_8888,
            0x9999_aaaa_bbbb_cccc,
            true,
        );

        let outcome = orchestrator
            .orchestrate_deployment_for_repo_with_trace(
                &config,
                "sha256-trace-test",
                Some("dep-trace-1".into()),
                Some("LMA1980/test-repo"),
                Some(root_trace),
            )
            .await
            .expect("deployment should succeed");

        assert!(outcome.is_promoted());

        let spans = recording_sink.recorded_spans().await;
        assert_eq!(
            spans.len(),
            3,
            "expected 3 spans: stage_b, gate.evaluate, deployment.start"
        );

        let stage_span = spans
            .iter()
            .find(|s| s.span_name == "cd.slot.stage_b")
            .expect("cd.slot.stage_b");
        let gate_span = spans
            .iter()
            .find(|s| s.span_name == "cd.gate.evaluate")
            .expect("cd.gate.evaluate");
        let dep_span = spans
            .iter()
            .find(|s| s.span_name.starts_with("cd.deployment.start:"))
            .expect("cd.deployment.start");

        let expected_trace_id = mu_observable_ipc::encode_hex(&root_trace.trace_id);
        assert_eq!(stage_span.trace_id, expected_trace_id);
        assert_eq!(gate_span.trace_id, expected_trace_id);
        assert_eq!(dep_span.trace_id, expected_trace_id);

        assert_eq!(
            stage_span.parent_span_id.as_deref(),
            Some(dep_span.span_id.as_str())
        );
        assert_eq!(
            gate_span.parent_span_id.as_deref(),
            Some(dep_span.span_id.as_str())
        );
        assert_eq!(
            dep_span.parent_span_id.as_deref(),
            Some(mu_observable_ipc::encode_hex(&root_trace.span_id).as_str())
        );

        assert_eq!(stage_span.status_code, "OK");
        assert_eq!(gate_span.status_code, "OK");
        assert_eq!(dep_span.status_code, "OK");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_symmetric_slot_alternation_and_emergency_rollback() {
        let store = Arc::new(CdStateStore::default());
        let coordinator = Arc::new(LeaseCoordinator::new());
        let agent = Arc::new(MockAgentClient {
            stage_ok: AtomicBool::new(true),
            swap_ok: AtomicBool::new(true),
            it_passed: AtomicBool::new(true),
            ..Default::default()
        });
        let regist = Arc::new(MockMuRegistClient::default());
        let sink = Arc::new(crate::telemetry::RecordingCdTelemetrySink::default());

        let orchestrator =
            DeploymentOrchestrator::new(coordinator.clone(), None, agent.clone(), regist.clone())
                .with_cd_state(store.clone())
                .with_telemetry_sink(sink.clone());

        let config = sample_config();

        // Deploy 1: active @a -> candidate @b -> promote -> active becomes @b
        let d1 = orchestrator
            .orchestrate_deployment(&config, "sha-sym-1", Some("dep-sym-1".into()))
            .await
            .unwrap();
        assert!(d1.is_promoted());
        assert_eq!(
            store
                .snapshot()
                .deployment("dep-sym-1")
                .unwrap()
                .active_slot,
            Slot::B
        );
        assert_eq!(
            store
                .snapshot()
                .deployment("dep-sym-1")
                .unwrap()
                .restore_slot,
            Slot::A
        );

        // Deploy 2: active @b -> candidate @a -> promote -> active becomes @a + stage_a span
        let d2 = orchestrator
            .orchestrate_deployment(&config, "sha-sym-2", Some("dep-sym-2".into()))
            .await
            .unwrap();
        assert!(d2.is_promoted());
        let rec2 = store.snapshot().deployment("dep-sym-2").unwrap().clone();
        assert_eq!(rec2.staged_slot, Slot::A);
        assert_eq!(rec2.restore_slot, Slot::B);
        assert_eq!(rec2.active_slot, Slot::A);
        assert_eq!(
            coordinator
                .active_slot_for("worker-riscv64", "action-runner")
                .await,
            DeploymentSlot::SlotA
        );
        let spans = sink.recorded_spans().await;
        assert!(
            spans.iter().any(|s| s.span_name == "cd.slot.stage_a"),
            "second rollout must emit symmetric cd.slot.stage_a span"
        );

        // Emergency rollback on dep-sym-2 restores @b and taints sha-sym-2 in mu-registry
        let rb = orchestrator
            .emergency_rollback("dep-sym-2", Some("regression in production"))
            .await
            .unwrap();
        assert_eq!(rb.deployment_id, "dep-sym-2");
        assert_eq!(rb.restored_slot, Slot::B);
        assert_eq!(rb.tainted_digest.as_deref(), Some("sha-sym-2"));
        assert_eq!(agent.rollback_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            agent
                .last_rollback_cmd
                .lock()
                .await
                .as_ref()
                .unwrap()
                .restore_slot,
            DeploymentSlot::SlotB
        );
        assert!(orchestrator
            .is_digest_tainted("sha-sym-2")
            .await
            .expect("taint check"));
        assert!(regist.tainted_digests.lock().await.contains("sha-sym-2"));
        assert_eq!(
            coordinator
                .active_slot_for("worker-riscv64", "action-runner")
                .await,
            DeploymentSlot::SlotB
        );
    }

    #[test]
    fn test_dedup_target_nodes_trims_and_ignores_blank_entries() {
        let input = vec![
            " node-a ".into(),
            "node-b".into(),
            "standby".into(),
            "worker-riscv64".into(),
            "  ".into(),
            "node-b".into(),
            "worker-aarch64".into(),
        ];
        let resolved = dedup_target_nodes(&input);
        assert_eq!(
            resolved,
            vec![
                "node-a",
                "node-b",
                "standby",
                "worker-riscv64",
                "worker-aarch64",
            ]
        );
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_select_idle_target_node_contention_retries_then_succeeds() {
        use axum::{routing::get, Json, Router};

        let calls = Arc::new(AtomicU32::new(0));
        let calls_handler = calls.clone();
        let app = Router::new().route(
            "/api/cluster/nodes",
            get(move || {
                let calls_handler = calls_handler.clone();
                async move {
                    let probe = calls_handler.fetch_add(1, Ordering::SeqCst);
                    let active_slots = if probe < 2 { 1 } else { 0 };
                    Json(vec![ClusterNodeStatus {
                        node_id: "node-a".into(),
                        online: true,
                        active_slots,
                        max_slots: 1,
                        exclusive_locked: false,
                    }])
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let poller =
            ClusterIdlePoller::with_client(format!("http://{addr}"), reqwest::Client::new());
        let orchestrator = DeploymentOrchestrator::new(
            Arc::new(LeaseCoordinator::new()),
            Some(poller),
            Arc::new(MockAgentClient::default()),
            Arc::new(MockMuRegistClient::default()),
        )
        .with_idle_backoff(IdleBackoffConfig {
            wait_timeout: Duration::from_secs(2),
            initial_interval: Duration::from_millis(5),
            max_interval: Duration::from_millis(15),
            jitter_percent: 20,
        });

        let selected = orchestrator
            .select_idle_target_node(&["node-a".into()])
            .await
            .expect("busy node drains and succeeds within backoff deadline");
        assert_eq!(selected, "node-a");
        assert_eq!(calls.load(Ordering::SeqCst), 3);

        // Immediate idle takes a single probe
        let immediate = orchestrator
            .select_idle_target_node(&["node-a".into()])
            .await
            .expect("immediate idle");
        assert_eq!(immediate, "node-a");
        assert_eq!(calls.load(Ordering::SeqCst), 4);

        server.abort();
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_select_idle_target_node_preserves_cross_arch_filter_and_times_out() {
        use axum::{routing::get, Json, Router};

        let calls = Arc::new(AtomicU32::new(0));
        let calls_handler = calls.clone();
        let app = Router::new().route(
            "/api/cluster/nodes",
            get(move || {
                let calls_handler = calls_handler.clone();
                async move {
                    calls_handler.fetch_add(1, Ordering::SeqCst);
                    // Unrequested x86_64/aarch64 nodes are idle, requested worker-riscv64 is busy.
                    Json(vec![
                        ClusterNodeStatus {
                            node_id: "node-a".into(),
                            online: true,
                            active_slots: 0,
                            max_slots: 1,
                            exclusive_locked: false,
                        },
                        ClusterNodeStatus {
                            node_id: "worker-aarch64".into(),
                            online: true,
                            active_slots: 0,
                            max_slots: 1,
                            exclusive_locked: false,
                        },
                        ClusterNodeStatus {
                            node_id: "worker-riscv64".into(),
                            online: true,
                            active_slots: 1,
                            max_slots: 1,
                            exclusive_locked: false,
                        },
                    ])
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let poller =
            ClusterIdlePoller::with_client(format!("http://{addr}"), reqwest::Client::new());
        let orchestrator = DeploymentOrchestrator::new(
            Arc::new(LeaseCoordinator::new()),
            Some(poller),
            Arc::new(MockAgentClient::default()),
            Arc::new(MockMuRegistClient::default()),
        )
        .with_idle_backoff(IdleBackoffConfig {
            wait_timeout: Duration::from_millis(35),
            initial_interval: Duration::from_millis(5),
            max_interval: Duration::from_millis(10),
            jitter_percent: 0,
        });

        let err = orchestrator
            .select_idle_target_node(&["worker-riscv64".into()])
            .await
            .expect_err("must not fall back to idle nodes of other architectures");
        assert!(
            matches!(err, OrchestratorError::Lease(LeaseError::NodeNotIdle(_))),
            "expected NodeNotIdle, got {err:?}"
        );
        assert!(
            calls.load(Ordering::SeqCst) >= 2,
            "expected retry probes before deadline expiry"
        );

        server.abort();
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_slot_swap_command_propagates_deployment_systemd_unit() {
        let coordinator = Arc::new(LeaseCoordinator::new());
        let agent = Arc::new(MockAgentClient {
            stage_ok: AtomicBool::new(true),
            swap_ok: AtomicBool::new(true),
            it_passed: AtomicBool::new(true),
            ..Default::default()
        });
        let regist = Arc::new(MockMuRegistClient::default());
        let orchestrator = DeploymentOrchestrator::new(coordinator, None, agent.clone(), regist);

        let mut cfg = sample_config();
        cfg.service = "mu-observable-collector.service".into();
        cfg.deployment.systemd_unit = Some("custom-collector".into());

        let outcome = orchestrator
            .orchestrate_deployment(&cfg, "sha256-unit-prop", Some("dep-unit-1".into()))
            .await
            .expect("deployment should succeed");
        assert!(outcome.is_promoted());

        let swaps = agent.swap_commands.lock().await;
        assert_eq!(swaps.len(), 1);
        assert_eq!(swaps[0].1.systemd_unit, "custom-collector.service");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_orchestrate_rollout_partial_failure_compensates_and_emits_audit() {
        let store = Arc::new(CdStateStore::default());
        let coordinator = Arc::new(LeaseCoordinator::new());
        let agent = Arc::new(MockAgentClient {
            stage_ok: AtomicBool::new(true),
            swap_ok: AtomicBool::new(true),
            it_passed: AtomicBool::new(true),
            fail_it_node: Mutex::new(Some("node-b".into())),
            ..Default::default()
        });
        let regist = Arc::new(MockMuRegistClient::default());
        let sink = Arc::new(crate::telemetry::RecordingCdTelemetrySink::default());

        let orchestrator =
            DeploymentOrchestrator::new(coordinator.clone(), None, agent.clone(), regist.clone())
                .with_cd_state(store.clone())
                .with_telemetry_sink(sink.clone());

        let mut config = sample_config();
        config.target_nodes = vec!["node-a".into(), "node-b".into(), "node-c".into()];

        let outcomes = orchestrator
            .orchestrate_rollout_for_repo(
                &config,
                "sha256-partial-rb",
                Some("LMA1980/mu-cd-controller"),
            )
            .await
            .expect("rollout stops gracefully with compensated rollback outcomes");

        // Stopped before node-c; both node-a (compensated) and node-b ended RolledBack.
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(DeploymentOutcome::is_rolled_back));
        assert_eq!(agent.stage_calls.load(Ordering::SeqCst), 2);
        assert_eq!(agent.rollback_calls.load(Ordering::SeqCst), 2);

        let rb_nodes = agent.rollback_nodes.lock().await.clone();
        assert_eq!(
            rb_nodes,
            vec![
                ("node-b".to_string(), DeploymentSlot::SlotA),
                ("node-a".to_string(), DeploymentSlot::SlotA),
            ]
        );
        assert_eq!(
            coordinator.active_slot_for("node-a", "action-runner").await,
            DeploymentSlot::SlotA
        );
        assert_eq!(
            coordinator.active_slot_for("node-b", "action-runner").await,
            DeploymentSlot::SlotA
        );

        let snap = store.snapshot();
        assert_eq!(snap.deployments.len(), 2);
        assert!(snap
            .deployments
            .iter()
            .all(|d| d.outcome == crate::cd_state::GateOutcome::RolledBack && d.tainted));

        let logs = sink.recorded_logs().await;
        assert!(
            logs.iter()
                .any(|l| l.attributes_json.contains("cd.rollout.partial_rollback")),
            "expected partial rollback audit log entry, got {logs:?}"
        );
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_orchestrate_rollout_second_node_error_compensates_without_taint() {
        use axum::{routing::get, Json, Router};

        let app = Router::new().route(
            "/api/cluster/nodes",
            get(|| async {
                Json(vec![
                    ClusterNodeStatus {
                        node_id: "node-a".into(),
                        online: true,
                        active_slots: 0,
                        max_slots: 1,
                        exclusive_locked: false,
                    },
                    ClusterNodeStatus {
                        node_id: "node-b".into(),
                        online: true,
                        active_slots: 1,
                        max_slots: 1,
                        exclusive_locked: false,
                    },
                ])
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let coordinator = Arc::new(LeaseCoordinator::new());
        let agent = Arc::new(MockAgentClient {
            stage_ok: AtomicBool::new(true),
            swap_ok: AtomicBool::new(true),
            it_passed: AtomicBool::new(true),
            ..Default::default()
        });
        let regist = Arc::new(MockMuRegistClient::default());
        let sink = Arc::new(crate::telemetry::RecordingCdTelemetrySink::default());
        let poller =
            ClusterIdlePoller::with_client(format!("http://{addr}"), reqwest::Client::new());

        let orchestrator = DeploymentOrchestrator::new(
            coordinator.clone(),
            Some(poller),
            agent.clone(),
            regist.clone(),
        )
        .with_idle_backoff(IdleBackoffConfig {
            wait_timeout: Duration::from_millis(15),
            initial_interval: Duration::from_millis(5),
            max_interval: Duration::from_millis(10),
            jitter_percent: 0,
        })
        .with_telemetry_sink(sink.clone());

        let mut config = sample_config();
        config.target_nodes = vec!["node-a".into(), "node-b".into()];

        let err = orchestrator
            .orchestrate_rollout_for_repo(&config, "sha256-healthy-busy-2nd", None)
            .await
            .expect_err("second node timeout should abort rollout");
        assert!(matches!(
            err,
            OrchestratorError::Lease(LeaseError::NodeNotIdle(_))
        ));

        // Compensating rollback restored node-a without tainting the healthy digest.
        assert_eq!(
            agent.rollback_nodes.lock().await.as_slice(),
            &[("node-a".to_string(), DeploymentSlot::SlotA)]
        );
        assert_eq!(
            coordinator.active_slot_for("node-a", "action-runner").await,
            DeploymentSlot::SlotA
        );
        assert!(!orchestrator
            .is_digest_tainted("sha256-healthy-busy-2nd")
            .await
            .unwrap());
        assert_eq!(regist.taint_calls.load(Ordering::SeqCst), 0);

        let logs = sink.recorded_logs().await;
        assert!(logs
            .iter()
            .any(|l| l.attributes_json.contains("cd.rollout.partial_rollback")));

        server.abort();
    }

    struct AgentMtlsFixtures {
        _temp_dir: tempfile::TempDir,
        client_tls_paths: TlsConfig,
        ca_only_tls: TlsConfig,
        untrusted_client_tls: TlsConfig,
        server_config: Arc<rustls::ServerConfig>,
        untrusted_server_config: Arc<rustls::ServerConfig>,
    }

    fn build_ca_issuer(cn: &str) -> (rcgen::Certificate, rcgen::Issuer<'static, rcgen::KeyPair>) {
        let mut ca_params = rcgen::CertificateParams::new(vec![cn.into()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_issuer = rcgen::Issuer::new(ca_params, ca_key);
        (ca_cert, ca_issuer)
    }

    fn build_server_mtls_config(
        ca_cert: &rcgen::Certificate,
        server_issuer: &rcgen::Issuer<'static, rcgen::KeyPair>,
    ) -> Arc<rustls::ServerConfig> {
        let server_params =
            rcgen::CertificateParams::new(vec!["127.0.0.1".into(), "localhost".into()]).unwrap();
        let server_key = rcgen::KeyPair::generate().unwrap();
        let server_cert = server_params.signed_by(&server_key, server_issuer).unwrap();

        let mut client_roots = rustls::RootCertStore::empty();
        client_roots.add(ca_cert.der().clone()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .unwrap();

        let server_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![server_cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()),
                ),
            )
            .unwrap();
        Arc::new(server_config)
    }

    fn generate_agent_mtls_fixtures() -> AgentMtlsFixtures {
        TlsConfig::ensure_crypto_provider();
        let (ca_cert, ca_issuer) = build_ca_issuer("Test Agent Root CA");
        let (other_ca_cert, other_ca_issuer) = build_ca_issuer("Untrusted Agent Root CA");

        let client_params = rcgen::CertificateParams::new(vec!["mu-cd-controller".into()]).unwrap();
        let client_key = rcgen::KeyPair::generate().unwrap();
        let client_cert = client_params.signed_by(&client_key, &ca_issuer).unwrap();

        let bad_client_params =
            rcgen::CertificateParams::new(vec!["untrusted-client".into()]).unwrap();
        let bad_client_key = rcgen::KeyPair::generate().unwrap();
        let bad_client_cert = bad_client_params
            .signed_by(&bad_client_key, &other_ca_issuer)
            .unwrap();

        let temp_dir = tempfile::tempdir().unwrap();
        let ca_path = temp_dir.path().join("ca.pem");
        let client_cert_path = temp_dir.path().join("client.pem");
        let client_key_path = temp_dir.path().join("client.key");
        std::fs::write(&ca_path, ca_cert.pem()).unwrap();
        std::fs::write(&client_cert_path, client_cert.pem()).unwrap();
        std::fs::write(&client_key_path, client_key.serialize_pem()).unwrap();

        let client_tls_paths = TlsConfig::from_paths(&ca_path, &client_cert_path, &client_key_path);
        let ca_only_tls = TlsConfig {
            ca_cert_path: Some(ca_path),
            ..Default::default()
        };
        let untrusted_client_tls = TlsConfig::from_pem_strings(
            ca_cert.pem(),
            bad_client_cert.pem(),
            bad_client_key.serialize_pem(),
        );

        let server_config = build_server_mtls_config(&ca_cert, &ca_issuer);
        let untrusted_server_config = build_server_mtls_config(&other_ca_cert, &other_ca_issuer);

        AgentMtlsFixtures {
            _temp_dir: temp_dir,
            client_tls_paths,
            ca_only_tls,
            untrusted_client_tls,
            server_config,
            untrusted_server_config,
        }
    }

    async fn spawn_mtls_agent_server(
        server_config: Arc<rustls::ServerConfig>,
        close_after_swap: bool,
        rollback_seen: Arc<AtomicBool>,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);

        let handle = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let rollback_seen = rollback_seen.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let fory = create_fory_runtime().unwrap();
                    let read_res =
                        tokio::time::timeout(Duration::from_millis(300), read_frame(&mut tls))
                            .await;
                    match read_res {
                        Ok(Ok((hdr, payload))) if hdr.msg_type == MSG_TYPE_STAGE_DEPLOY_REQ => {
                            let req: StageDeploymentRequest = fory.deserialize(&payload).unwrap();
                            let resp = StageDeploymentResponse {
                                deployment_id: req.deployment_id,
                                target_slot: req.target_slot,
                                btrfs_subvolume_path: "/srv/muconde/example/@b".into(),
                                staged_ok: true,
                                error_message: None,
                            };
                            let bytes = fory.serialize(&resp).unwrap();
                            let rh = IpcHeader::new(
                                MSG_TYPE_STAGE_DEPLOY_RESP,
                                bytes.len() as u32,
                                0,
                                hdr.sequence,
                            );
                            let _ = write_frame(&mut tls, &rh, &bytes).await;
                            let _ = tls.shutdown().await;
                        }
                        Ok(Ok((hdr, payload))) if hdr.msg_type == MSG_TYPE_SLOT_SWAP => {
                            let cmd: SlotSwapCommand = fory.deserialize(&payload).unwrap();
                            if close_after_swap {
                                let _ = tls.shutdown().await;
                                return;
                            }
                            let prog = IntegrationTestProgress {
                                deployment_id: cmd.deployment_id.clone(),
                                test_name: "mtls_smoke".into(),
                                critical: true,
                                state: mu_cd_ipc::TestState::Passed,
                                duration_ms: 12,
                                timestamp_epoch_ms: 1_700_000_000_000,
                            };
                            let pb = fory.serialize(&prog).unwrap();
                            let ph = IpcHeader::new(MSG_TYPE_IT_PROGRESS, pb.len() as u32, 0, 2);
                            let _ = write_frame(&mut tls, &ph, &pb).await;
                            let report = IntegrationTestReport {
                                deployment_id: cmd.deployment_id,
                                service_name: cmd.service_name,
                                artifact_sha256: "sha256-mtls".into(),
                                executed_tests: vec!["mtls_smoke".into()],
                                passed: true,
                                failed_tests: vec![],
                                duration_ms: 12,
                                log_excerpt: None,
                            };
                            let rb = fory.serialize(&report).unwrap();
                            let rh = IpcHeader::new(MSG_TYPE_IT_REPORT, rb.len() as u32, 0, 3);
                            let _ = write_frame(&mut tls, &rh, &rb).await;
                            let _ = tls.shutdown().await;
                        }
                        Ok(Ok((hdr, _))) if hdr.msg_type == MSG_TYPE_ROLLBACK => {
                            rollback_seen.store(true, Ordering::SeqCst);
                            let _ = tls.shutdown().await;
                        }
                        Err(_) if close_after_swap => {
                            let report = IntegrationTestReport {
                                deployment_id: "dep-mtls-reconn".into(),
                                service_name: "svc-mtls".into(),
                                artifact_sha256: "sha256-mtls".into(),
                                executed_tests: vec!["mtls_reconnect".into()],
                                passed: true,
                                failed_tests: vec![],
                                duration_ms: 15,
                                log_excerpt: None,
                            };
                            let rb = fory.serialize(&report).unwrap();
                            let rh = IpcHeader::new(MSG_TYPE_IT_REPORT, rb.len() as u32, 0, 1);
                            let _ = write_frame(&mut tls, &rh, &rb).await;
                            let _ = tls.shutdown().await;
                        }
                        _ => {}
                    }
                });
            }
        });
        (port, handle)
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_ipc_agent_client_mtls_stage_swap_it_stream_and_rollback() {
        let fixtures = generate_agent_mtls_fixtures();
        let rollback_seen = Arc::new(AtomicBool::new(false));
        let (port, server) =
            spawn_mtls_agent_server(fixtures.server_config.clone(), false, rollback_seen.clone())
                .await;

        let store = Arc::new(CdStateStore::default());
        store.deployment_started(crate::cd_state::DeploymentStart {
            deployment_id: "dep-mtls-1".into(),
            repo: Some("LMA1980/example".into()),
            service: "svc-mtls".into(),
            target_node: "127.0.0.1".into(),
            artifact_digest: "sha256-mtls".into(),
            active_slot: crate::cd_state::Slot::A,
            staged_slot: crate::cd_state::Slot::B,
            restore_slot: crate::cd_state::Slot::A,
            lease_id: "lease-mtls-1".into(),
            lease_expires_epoch_ms: u64::MAX / 2,
            tests: vec![("mtls_smoke".into(), true)],
        });

        let client = IpcAgentClient::new(port)
            .with_progress_sink(store.clone())
            .with_tls_config(fixtures.client_tls_paths.clone());

        let stage_req = StageDeploymentRequest {
            deployment_id: "dep-mtls-1".into(),
            lease_id: "lease-mtls-1".into(),
            service_name: "svc-mtls".into(),
            artifact_sha256: "sha256-mtls".into(),
            target_slot: DeploymentSlot::SlotB,
        };
        let stage_resp = client
            .stage_deployment("127.0.0.1", &stage_req)
            .await
            .expect("mTLS stage_deployment succeeds");
        assert!(stage_resp.staged_ok);

        let swap_cmd = SlotSwapCommand {
            deployment_id: "dep-mtls-1".into(),
            lease_id: "lease-mtls-1".into(),
            service_name: "svc-mtls".into(),
            from_slot: DeploymentSlot::SlotA,
            to_slot: DeploymentSlot::SlotB,
            systemd_unit: "svc-mtls.service".into(),
            warmup_timeout_secs: 5,
        };
        client
            .slot_swap("127.0.0.1", &swap_cmd)
            .await
            .expect("mTLS slot_swap succeeds");

        let report = client
            .execute_integration_tests(
                "127.0.0.1",
                "dep-mtls-1",
                "svc-mtls",
                "sha256-mtls",
                None,
                Duration::from_secs(5),
            )
            .await
            .expect("mTLS execute_integration_tests succeeds");
        assert!(report.passed);
        assert_eq!(report.executed_tests, vec!["mtls_smoke"]);
        assert_eq!(
            store
                .snapshot()
                .deployment("dep-mtls-1")
                .unwrap()
                .tests
                .len(),
            1
        );

        let rb_cmd = RollbackCommand {
            deployment_id: "dep-mtls-1".into(),
            lease_id: "lease-mtls-1".into(),
            service_name: "svc-mtls".into(),
            restore_slot: DeploymentSlot::SlotA,
            failed_artifact_sha256: "sha256-mtls".into(),
            reason: "test rollback".into(),
        };
        client
            .rollback("127.0.0.1", &rb_cmd)
            .await
            .expect("mTLS rollback succeeds");
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(rollback_seen.load(Ordering::SeqCst));

        server.abort();
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_ipc_agent_client_mtls_reconnects_after_swap_eof() {
        let fixtures = generate_agent_mtls_fixtures();
        let (port, server) = spawn_mtls_agent_server(
            fixtures.server_config.clone(),
            true,
            Arc::new(AtomicBool::new(false)),
        )
        .await;

        let client = IpcAgentClient::new(port).with_tls_config(fixtures.client_tls_paths.clone());
        let swap_cmd = SlotSwapCommand {
            deployment_id: "dep-mtls-reconn".into(),
            lease_id: "lease-mtls-reconn".into(),
            service_name: "svc-mtls".into(),
            from_slot: DeploymentSlot::SlotA,
            to_slot: DeploymentSlot::SlotB,
            systemd_unit: "svc-mtls.service".into(),
            warmup_timeout_secs: 5,
        };
        client
            .slot_swap("127.0.0.1", &swap_cmd)
            .await
            .expect("mTLS slot_swap");

        let report = client
            .execute_integration_tests(
                "127.0.0.1",
                "dep-mtls-reconn",
                "svc-mtls",
                "sha256-mtls",
                None,
                Duration::from_secs(5),
            )
            .await
            .expect("mTLS post-swap EOF reconnect succeeds");
        assert!(report.passed);
        assert_eq!(report.executed_tests, vec!["mtls_reconnect"]);

        server.abort();
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_ipc_agent_client_mtls_rejects_untrusted_certs_and_falls_back_when_unset() {
        let fixtures = generate_agent_mtls_fixtures();
        let stage_req = StageDeploymentRequest {
            deployment_id: "dep-untrusted".into(),
            lease_id: "lease-untrusted".into(),
            service_name: "svc-mtls".into(),
            artifact_sha256: "sha256-untrusted".into(),
            target_slot: DeploymentSlot::SlotB,
        };
        let swap_cmd = SlotSwapCommand {
            deployment_id: "dep-untrusted".into(),
            lease_id: "lease-untrusted".into(),
            service_name: "svc-mtls".into(),
            from_slot: DeploymentSlot::SlotA,
            to_slot: DeploymentSlot::SlotB,
            systemd_unit: "svc-mtls.service".into(),
            warmup_timeout_secs: 5,
        };

        // 1. Untrusted server certificate rejected by client CA trust store.
        let (bad_srv_port, bad_srv) = spawn_mtls_agent_server(
            fixtures.untrusted_server_config.clone(),
            false,
            Arc::new(AtomicBool::new(false)),
        )
        .await;
        let good_client =
            IpcAgentClient::new(bad_srv_port).with_tls_config(fixtures.client_tls_paths.clone());
        assert!(good_client
            .stage_deployment("127.0.0.1", &stage_req)
            .await
            .is_err());
        assert!(good_client.slot_swap("127.0.0.1", &swap_cmd).await.is_err());
        bad_srv.abort();

        // 2. Untrusted client certificate and CA-only config rejected by mTLS server.
        let (srv_port, srv) = spawn_mtls_agent_server(
            fixtures.server_config.clone(),
            false,
            Arc::new(AtomicBool::new(false)),
        )
        .await;
        let bad_client =
            IpcAgentClient::new(srv_port).with_tls_config(fixtures.untrusted_client_tls.clone());
        assert!(bad_client
            .stage_deployment("127.0.0.1", &stage_req)
            .await
            .is_err());
        let ca_only_client =
            IpcAgentClient::new(srv_port).with_tls_config(fixtures.ca_only_tls.clone());
        assert!(ca_only_client
            .stage_deployment("127.0.0.1", &stage_req)
            .await
            .is_err());
        srv.abort();

        // 3. Empty TlsConfig::default() keeps plain TCP compatibility.
        let plain_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let plain_port = plain_listener.local_addr().unwrap().port();
        let plain_srv = tokio::spawn(async move {
            let (mut stream, _) = plain_listener.accept().await.unwrap();
            let fory = create_fory_runtime().unwrap();
            let (hdr, payload) = read_frame(&mut stream).await.unwrap();
            let req: StageDeploymentRequest = fory.deserialize(&payload).unwrap();
            let resp = StageDeploymentResponse {
                deployment_id: req.deployment_id,
                target_slot: req.target_slot,
                btrfs_subvolume_path: "/srv/muconde/example/@b".into(),
                staged_ok: true,
                error_message: None,
            };
            let bytes = fory.serialize(&resp).unwrap();
            let rh = IpcHeader::new(
                MSG_TYPE_STAGE_DEPLOY_RESP,
                bytes.len() as u32,
                0,
                hdr.sequence,
            );
            write_frame(&mut stream, &rh, &bytes).await.unwrap();
        });
        let plain_client = IpcAgentClient::new(plain_port).with_tls_config(TlsConfig::default());
        let plain_resp = plain_client
            .stage_deployment("127.0.0.1", &stage_req)
            .await
            .expect("default TlsConfig falls back to plain TCP");
        assert!(plain_resp.staged_ok);
        plain_srv.await.unwrap();
    }

    #[test]
    fn test_ipc_agent_client_resolves_raw_host_without_env_node_map() {
        let client = IpcAgentClient::new(8446);
        assert_eq!(client.resolve_agent_host(" node-a "), "node-a");
        assert_eq!(
            client.resolve_agent_host("worker-riscv64.cluster.internal"),
            "worker-riscv64.cluster.internal"
        );
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_adopt_authoritative_staged_slot_symmetric_promotions_and_rollbacks() {
        use crate::cd_state::{CdStateStore, Slot};
        use std::collections::HashMap;

        let coordinator = Arc::new(LeaseCoordinator::new());
        let store = Arc::new(CdStateStore::default());
        let regist = Arc::new(MockMuRegistClient::default());
        let agent = Arc::new(MockAgentClient {
            stage_ok: AtomicBool::new(true),
            swap_ok: AtomicBool::new(true),
            it_passed: AtomicBool::new(true),
            stage_override_slots: Mutex::new(HashMap::from([(
                "node-a".to_string(),
                DeploymentSlot::SlotA,
            )])),
            ..Default::default()
        });

        let orchestrator =
            DeploymentOrchestrator::new(coordinator.clone(), None, agent.clone(), regist.clone())
                .with_cd_state(store.clone());

        let mut cfg = sample_config();
        cfg.target_nodes = vec!["node-a".to_string()];

        // 1. Controller assumes SlotA -> SlotB, but node-a's live symlink is @b so agent stages SlotA.
        let out1 = orchestrator
            .orchestrate_deployment(&cfg, "sha256-slot-a-1", Some("dep-reconcile-a".into()))
            .await
            .expect("promotion to reconciled SlotA succeeds");
        assert!(out1.is_promoted());
        {
            let swaps = agent.swap_commands.lock().await;
            assert_eq!(swaps.len(), 1);
            assert_eq!(swaps[0].1.from_slot, DeploymentSlot::SlotB);
            assert_eq!(swaps[0].1.to_slot, DeploymentSlot::SlotA);
        }
        assert_eq!(
            coordinator.active_slot_for("node-a", "action-runner").await,
            DeploymentSlot::SlotA
        );
        let rec1 = store
            .snapshot()
            .deployment("dep-reconcile-a")
            .unwrap()
            .clone();
        assert_eq!(rec1.active_slot, Slot::A);
        assert_eq!(rec1.staged_slot, Slot::A);
        assert_eq!(rec1.restore_slot, Slot::B);

        // Emergency rollback restores authoritative SlotB and taints with actual target_node.
        let em = orchestrator
            .emergency_rollback("dep-reconcile-a", Some("operator check"))
            .await
            .expect("emergency rollback succeeds");
        assert_eq!(em.restored_slot, Slot::B);
        assert_eq!(
            agent
                .last_rollback_cmd
                .lock()
                .await
                .as_ref()
                .unwrap()
                .restore_slot,
            DeploymentSlot::SlotB
        );
        assert_eq!(
            regist.last_taint_node.lock().await.as_deref(),
            Some("node-a")
        );
        assert_eq!(
            coordinator.active_slot_for("node-a", "action-runner").await,
            DeploymentSlot::SlotB
        );

        // 2. Reverse divergence: controller thinks active=SlotB (expects SlotA), agent stages SlotB.
        agent
            .stage_override_slots
            .lock()
            .await
            .insert("node-a".to_string(), DeploymentSlot::SlotB);
        let out2 = orchestrator
            .orchestrate_deployment(&cfg, "sha256-slot-b-2", Some("dep-reconcile-b".into()))
            .await
            .expect("promotion to reconciled SlotB succeeds");
        assert!(out2.is_promoted());
        {
            let swaps = agent.swap_commands.lock().await;
            assert_eq!(swaps.len(), 2);
            assert_eq!(swaps[1].1.from_slot, DeploymentSlot::SlotA);
            assert_eq!(swaps[1].1.to_slot, DeploymentSlot::SlotB);
        }
        assert_eq!(
            coordinator.active_slot_for("node-a", "action-runner").await,
            DeploymentSlot::SlotB
        );
        let rec2 = store
            .snapshot()
            .deployment("dep-reconcile-b")
            .unwrap()
            .clone();
        assert_eq!(rec2.active_slot, Slot::B);
        assert_eq!(rec2.staged_slot, Slot::B);
        assert_eq!(rec2.restore_slot, Slot::A);

        // 3. Diverged rollback on IT failure: reset controller to assume SlotA -> SlotB,
        //    agent stages SlotA (live was @b), IT fails -> must restore SlotB and taint with node-a.
        coordinator
            .set_active_slot("node-a", "action-runner", DeploymentSlot::SlotA)
            .await;
        agent
            .stage_override_slots
            .lock()
            .await
            .insert("node-a".to_string(), DeploymentSlot::SlotA);
        agent.it_passed.store(false, Ordering::SeqCst);
        *agent.it_failed_tests.lock().await = vec!["smoke_demo".to_string()];

        let out3 = orchestrator
            .orchestrate_deployment(&cfg, "sha256-it-fail-3", Some("dep-reconcile-fail".into()))
            .await
            .expect("IT failure returns RolledBack");
        assert!(out3.is_rolled_back());
        {
            let swaps = agent.swap_commands.lock().await;
            assert_eq!(swaps.len(), 3);
            assert_eq!(swaps[2].1.from_slot, DeploymentSlot::SlotB);
            assert_eq!(swaps[2].1.to_slot, DeploymentSlot::SlotA);
        }
        assert_eq!(
            agent
                .last_rollback_cmd
                .lock()
                .await
                .as_ref()
                .unwrap()
                .restore_slot,
            DeploymentSlot::SlotB
        );
        assert_eq!(
            coordinator.active_slot_for("node-a", "action-runner").await,
            DeploymentSlot::SlotB
        );
        let rec3 = store
            .snapshot()
            .deployment("dep-reconcile-fail")
            .unwrap()
            .clone();
        assert_eq!(rec3.active_slot, Slot::B);
        assert_eq!(rec3.restore_slot, Slot::B);
        assert_eq!(
            regist.last_taint_node.lock().await.as_deref(),
            Some("node-a")
        );
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_multi_node_compensation_uses_reconciled_restore_slot_and_actual_taint_node() {
        use crate::cd_state::CdStateStore;
        use std::collections::HashMap;

        let coordinator = Arc::new(LeaseCoordinator::new());
        let store = Arc::new(CdStateStore::default());
        let regist = Arc::new(MockMuRegistClient::default());
        let agent = Arc::new(MockAgentClient {
            stage_ok: AtomicBool::new(true),
            swap_ok: AtomicBool::new(true),
            it_passed: AtomicBool::new(true),
            fail_it_node: Mutex::new(Some("node-2".to_string())),
            // Controller assumes both nodes are on SlotA, but node-1 is live on SlotB (stages SlotA).
            stage_override_slots: Mutex::new(HashMap::from([
                ("node-1".to_string(), DeploymentSlot::SlotA),
                ("node-2".to_string(), DeploymentSlot::SlotB),
            ])),
            ..Default::default()
        });

        let orchestrator =
            DeploymentOrchestrator::new(coordinator.clone(), None, agent.clone(), regist.clone())
                .with_cd_state(store);

        let mut cfg = sample_config();
        cfg.target_nodes = vec!["node-1".to_string(), "node-2".to_string()];

        let outcomes = orchestrator
            .orchestrate_rollout_for_repo(&cfg, "sha256-multi-slot-fix", Some("LMA1980/demo"))
            .await
            .expect("multi-node partial rollback returns outcomes");
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes.iter().all(DeploymentOutcome::is_rolled_back));

        // Verify node-1 swapped SlotB -> SlotA, node-2 swapped SlotA -> SlotB.
        let swaps = agent.swap_commands.lock().await;
        assert_eq!(swaps.len(), 2);
        assert_eq!(swaps[0].0, "node-1");
        assert_eq!(swaps[0].1.from_slot, DeploymentSlot::SlotB);
        assert_eq!(swaps[0].1.to_slot, DeploymentSlot::SlotA);
        assert_eq!(swaps[1].0, "node-2");
        assert_eq!(swaps[1].1.from_slot, DeploymentSlot::SlotA);
        assert_eq!(swaps[1].1.to_slot, DeploymentSlot::SlotB);
        drop(swaps);

        // Verify node-2 rolled back to SlotA, tainted with node-2, and node-1 compensated back to SlotB!
        let rollbacks = agent.rollback_nodes.lock().await;
        assert_eq!(
            rollbacks.as_slice(),
            &[
                ("node-2".to_string(), DeploymentSlot::SlotA),
                ("node-1".to_string(), DeploymentSlot::SlotB),
            ]
        );
        assert_eq!(
            regist.last_taint_node.lock().await.as_deref(),
            Some("node-2")
        );
        assert_eq!(
            coordinator.active_slot_for("node-1", "action-runner").await,
            DeploymentSlot::SlotB
        );
        assert_eq!(
            coordinator.active_slot_for("node-2", "action-runner").await,
            DeploymentSlot::SlotA
        );
    }

    #[test]
    fn test_resolve_controller_state_dir_env_precedence() {
        assert_eq!(
            resolve_controller_state_dir(&|_| None),
            PathBuf::from(DEFAULT_CONTROLLER_STATE_DIR)
        );
        assert_eq!(
            resolve_controller_state_dir(
                &|k| (k == "MUCONDE_STATE_DIR").then(|| "/var/lib/legacy-state".to_string())
            ),
            PathBuf::from("/var/lib/legacy-state")
        );
        assert_eq!(
            resolve_controller_state_dir(&|k| match k {
                "MU_CD_CONTROLLER_STATE_DIR" => Some("/var/lib/preferred-state".to_string()),
                "MUCONDE_STATE_DIR" => Some("/var/lib/legacy-state".to_string()),
                _ => None,
            }),
            PathBuf::from("/var/lib/preferred-state")
        );
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_ipc_agent_client_retries_connection_refused_and_eof_until_report() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let addr = listener.local_addr().unwrap();

        // Phase 1: Accept slot_swap stream, drop immediately (simulating agent restart)
        // AND drop the listener so subsequent connects hit ECONNREFUSED for ~180ms.
        let server_task = tokio::spawn(async move {
            let (mut s1, _) = listener.accept().await.unwrap();
            let (hdr, _payload) = read_frame(&mut s1).await.unwrap();
            assert_eq!(hdr.msg_type, MSG_TYPE_SLOT_SWAP);
            drop(s1);
            drop(listener);

            // Agent is offline for 180ms (controller retries with 40ms backoff)
            tokio::time::sleep(Duration::from_millis(180)).await;

            // Agent restarts on the same port and delivers cached IntegrationTestReport
            let listener2 = TcpListener::bind(addr).await.unwrap();
            let (mut s2, _) = listener2.accept().await.unwrap();
            let fory = create_fory_runtime().unwrap();
            let report = IntegrationTestReport {
                deployment_id: "dep-reconn-retry".into(),
                service_name: "mu-cd-agent".into(),
                artifact_sha256: "a".repeat(64),
                executed_tests: vec!["smoke_mu_cd_agent".into()],
                passed: true,
                failed_tests: Vec::new(),
                duration_ms: 35,
                log_excerpt: Some("reconnected after restart".into()),
            };
            let bytes = fory.serialize(&report).unwrap();
            write_frame(
                &mut s2,
                &IpcHeader::new(MSG_TYPE_IT_REPORT, bytes.len() as u32, 0, 1),
                &bytes,
            )
            .await
            .unwrap();
        });

        let client = IpcAgentClient::new(port).with_reconnect_backoff(Duration::from_millis(40));
        let swap_cmd = SlotSwapCommand {
            deployment_id: "dep-reconn-retry".into(),
            lease_id: "lease-reconn-retry".into(),
            service_name: "mu-cd-agent".into(),
            from_slot: DeploymentSlot::SlotA,
            to_slot: DeploymentSlot::SlotB,
            systemd_unit: "muconde-agent.service".into(),
            warmup_timeout_secs: 5,
        };
        client.slot_swap("127.0.0.1", &swap_cmd).await.unwrap();

        let report = client
            .execute_integration_tests(
                "127.0.0.1",
                "dep-reconn-retry",
                "mu-cd-agent",
                &"a".repeat(64),
                None,
                Duration::from_secs(5),
            )
            .await
            .expect("client must retry ConnectionRefused and receive report");
        assert!(report.passed);
        assert_eq!(report.deployment_id, "dep-reconn-retry");
        assert_eq!(report.executed_tests, vec!["smoke_mu_cd_agent"]);
        server_task.await.unwrap();
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_controller_self_upgrade_persists_0600_and_resumes_promote_with_slo() {
        use crate::cd_state::{CdStateStore, GateOutcome};
        use mu_observable_ipc::{CanarySloAssertionRequest, CanarySloAssertionResponse};

        struct RecordingSloClient {
            healthy: bool,
            requests: Mutex<Vec<CanarySloAssertionRequest>>,
        }
        #[async_trait]
        impl CanarySloClient for RecordingSloClient {
            async fn verify_canary_slo(
                &self,
                request: &CanarySloAssertionRequest,
            ) -> Result<CanarySloAssertionResponse, OrchestratorError> {
                self.requests.lock().await.push(request.clone());
                Ok(CanarySloAssertionResponse {
                    request_id: request.request_id.clone(),
                    healthy: self.healthy,
                    error_log_count: if self.healthy { 0 } else { 5 },
                    p99_latency_ms: if self.healthy { 12.5 } else { 999.0 },
                    taint_recommended: !self.healthy,
                    reason: if self.healthy {
                        "SLO healthy".into()
                    } else {
                        "Error budget exceeded".into()
                    },
                })
            }
        }

        // Agent that verifies pending_self_upgrade.json exists (0600) at slot_swap time and
        // simulates the old controller dying mid-gate before returning.
        struct HandoffCheckingAgent {
            state_dir: PathBuf,
            saw_0600_file_before_swap: AtomicBool,
            hold_notify: Arc<tokio::sync::Notify>,
        }
        #[async_trait]
        impl AgentIpcClient for HandoffCheckingAgent {
            async fn stage_deployment(
                &self,
                _node_id: &str,
                req: &StageDeploymentRequest,
            ) -> Result<StageDeploymentResponse, OrchestratorError> {
                Ok(StageDeploymentResponse {
                    deployment_id: req.deployment_id.clone(),
                    target_slot: req.target_slot,
                    btrfs_subvolume_path: "/srv/mucd/mu-cd-controller/@b".into(),
                    staged_ok: true,
                    error_message: None,
                })
            }
            async fn slot_swap(
                &self,
                _node_id: &str,
                _cmd: &SlotSwapCommand,
            ) -> Result<(), OrchestratorError> {
                let path = pending_self_upgrade_path(&self.state_dir);
                if path.is_file() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
                        assert_eq!(mode, 0o600, "pending_self_upgrade.json must be 0600");
                    }
                    self.saw_0600_file_before_swap.store(true, Ordering::SeqCst);
                }
                self.hold_notify.notify_one();
                // Simulate daemon SIGTERM killing the old controller while swap is in-flight.
                futures_util::future::pending::<()>().await;
                Ok(())
            }
            async fn execute_integration_tests(
                &self,
                _node_id: &str,
                _deployment_id: &str,
                _service: &str,
                _artifact_sha256: &str,
                _selected_tests: Option<&[String]>,
                _timeout: Duration,
            ) -> Result<IntegrationTestReport, OrchestratorError> {
                unreachable!("old controller died on restart")
            }
            async fn rollback(
                &self,
                _node_id: &str,
                _cmd: &RollbackCommand,
            ) -> Result<(), OrchestratorError> {
                Ok(())
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path().to_path_buf();
        let hold_notify = Arc::new(tokio::sync::Notify::new());
        let old_agent = Arc::new(HandoffCheckingAgent {
            state_dir: state_dir.clone(),
            saw_0600_file_before_swap: AtomicBool::new(false),
            hold_notify: hold_notify.clone(),
        });

        let old_orch = Arc::new(
            DeploymentOrchestrator::new(
                Arc::new(LeaseCoordinator::new()),
                None,
                old_agent.clone(),
                Arc::new(MockMuRegistClient::default()),
            )
            .with_state_dir(&state_dir),
        );

        let mut cfg = sample_config();
        cfg.service = "mu-cd-controller".into();
        cfg.target_nodes = vec!["node-a".into()];
        cfg.bake_window_seconds = 30;
        cfg.max_error_logs = 2;
        cfg.max_p99_latency_ms = 250.0;
        let digest = "1".repeat(64);

        let old_orch_clone = old_orch.clone();
        let digest_clone = digest.clone();
        let old_task = tokio::spawn(async move {
            let _ = old_orch_clone
                .orchestrate_deployment(&cfg, &digest_clone, Some("dep-ctrl-self-ok".into()))
                .await;
        });

        hold_notify.notified().await;
        assert!(old_agent.saw_0600_file_before_swap.load(Ordering::SeqCst));
        // Terminate old controller task to simulate systemd restart SIGTERM
        old_task.abort();
        let _ = old_task.await;
        assert!(pending_self_upgrade_path(&state_dir).is_file());

        // Phase 2: Restarted controller boots with fresh CdStateStore & LeaseCoordinator
        let new_coordinator = Arc::new(LeaseCoordinator::new());
        let new_store = Arc::new(CdStateStore::default());
        let new_regist = Arc::new(MockMuRegistClient::default());
        let new_slo = Arc::new(RecordingSloClient {
            healthy: true,
            requests: Mutex::new(Vec::new()),
        });
        let new_agent = Arc::new(MockAgentClient {
            stage_ok: AtomicBool::new(true),
            swap_ok: AtomicBool::new(true),
            it_passed: AtomicBool::new(true),
            ..Default::default()
        });
        let new_orch = DeploymentOrchestrator::new(
            new_coordinator.clone(),
            None,
            new_agent,
            new_regist.clone(),
        )
        .with_cd_state(new_store.clone())
        .with_slo_client(new_slo.clone())
        .with_state_dir(&state_dir);

        let resumed = new_orch
            .resume_pending_self_upgrade_if_present()
            .await
            .expect("resume succeeds")
            .expect("pending handoff was claimed");
        assert!(matches!(
            resumed,
            DeploymentOutcome::Promoted {
                ref deployment_id,
                ref service,
                ref target_node,
                ref artifact_sha256,
            } if deployment_id == "dep-ctrl-self-ok"
                && service == "mu-cd-controller"
                && target_node == "node-a"
                && artifact_sha256 == &digest
        ));
        assert!(!pending_self_upgrade_path(&state_dir).exists());

        // Verify MuObserve SLO assertion was invoked with persisted contract bounds
        let slo_reqs = new_slo.requests.lock().await;
        assert_eq!(slo_reqs.len(), 1);
        assert_eq!(slo_reqs[0].bake_window_secs, 30);
        assert_eq!(slo_reqs[0].max_error_logs, 2);
        assert_eq!(slo_reqs[0].service_name, "mu-cd-controller");
        drop(slo_reqs);

        // Verify CdStateStore hydrated and finalized as Promoted + LeaseCoordinator updated
        let rec = new_store
            .snapshot()
            .deployment("dep-ctrl-self-ok")
            .expect("hydrated deployment record present")
            .clone();
        assert_eq!(rec.outcome, GateOutcome::Promoted);
        assert_eq!(rec.active_slot, Slot::B);
        assert_eq!(new_regist.promote_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            new_coordinator
                .active_slot_for("node-a", "mu-cd-controller")
                .await,
            DeploymentSlot::SlotB
        );
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_controller_self_upgrade_resume_rollback_on_slo_breach_and_stale_expiry() {
        use crate::cd_state::{CdStateStore, GateOutcome};
        use mu_observable_ipc::{CanarySloAssertionRequest, CanarySloAssertionResponse};

        struct BreachingSloClient;
        #[async_trait]
        impl CanarySloClient for BreachingSloClient {
            async fn verify_canary_slo(
                &self,
                request: &CanarySloAssertionRequest,
            ) -> Result<CanarySloAssertionResponse, OrchestratorError> {
                Ok(CanarySloAssertionResponse {
                    request_id: request.request_id.clone(),
                    healthy: false,
                    error_log_count: 12,
                    p99_latency_ms: 850.0,
                    taint_recommended: true,
                    reason: "p99 latency SLO breach".into(),
                })
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path().to_path_buf();
        let bad_digest = "2".repeat(64);
        let handoff = PendingControllerSelfUpgrade {
            deployment_id: "dep-ctrl-self-slo-fail".into(),
            lease_id: "lease-ctrl-self-slo-fail".into(),
            service: "mu-cd-controller".into(),
            repo: Some("LMA1980/mu-cd-controller".into()),
            target_node: "node-a".into(),
            artifact_sha256: bad_digest.clone(),
            active_slot: "@a".into(),
            candidate_slot: "@b".into(),
            systemd_unit: "muconde-controller.service".into(),
            policy_commit_sha: "a".repeat(40),
            trace_id: "0123456789abcdef0123456789abcdef".into(),
            selected_tests: vec!["smoke_mu_cd_controller".into()],
            bake_window_seconds: 30,
            max_error_logs: 0,
            max_p99_latency_ms: 200.0,
            warmup_timeout_seconds: 15,
            started_at_epoch_ms: LeaseCoordinator::current_epoch_ms(),
        };
        write_pending_self_upgrade_atomic(&pending_self_upgrade_path(&state_dir), &handoff)
            .unwrap();

        let coordinator = Arc::new(LeaseCoordinator::new());
        let store = Arc::new(CdStateStore::default());
        let regist = Arc::new(MockMuRegistClient::default());
        let agent = Arc::new(MockAgentClient {
            stage_ok: AtomicBool::new(true),
            swap_ok: AtomicBool::new(true),
            it_passed: AtomicBool::new(true),
            ..Default::default()
        });
        let orch =
            DeploymentOrchestrator::new(coordinator.clone(), None, agent.clone(), regist.clone())
                .with_cd_state(store.clone())
                .with_slo_client(Arc::new(BreachingSloClient))
                .with_state_dir(&state_dir);

        let outcome = orch
            .resume_pending_self_upgrade_if_present()
            .await
            .expect("resume executes rollback cleanly")
            .expect("handoff claimed");
        assert!(
            matches!(
                outcome,
                DeploymentOutcome::RolledBack { ref reason, .. }
                    if reason.contains("MuObserve canary SLO breach")
            ),
            "expected SLO-breach rollback, got: {outcome:?}"
        );
        assert_eq!(agent.rollback_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            agent.rollback_nodes.lock().await.as_slice(),
            &[("node-a".to_string(), DeploymentSlot::SlotA)]
        );
        assert_eq!(regist.taint_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            regist.last_taint_node.lock().await.as_deref(),
            Some("node-a")
        );
        assert!(orch.is_digest_tainted(&bad_digest).await.unwrap());
        let rec = store
            .snapshot()
            .deployment("dep-ctrl-self-slo-fail")
            .unwrap()
            .clone();
        assert_eq!(rec.outcome, GateOutcome::RolledBack);
        assert!(rec.tainted);
        assert_eq!(rec.active_slot, Slot::A);

        // Stale handoff (>10 minutes old) must be ignored cleanly and deleted
        let mut stale = handoff;
        stale.deployment_id = "dep-ctrl-self-stale".into();
        stale.started_at_epoch_ms = LeaseCoordinator::current_epoch_ms()
            .saturating_sub(PENDING_SELF_UPGRADE_MAX_AGE_MS + 60_000);
        write_pending_self_upgrade_atomic(&pending_self_upgrade_path(&state_dir), &stale).unwrap();
        assert!(orch
            .resume_pending_self_upgrade_if_present()
            .await
            .unwrap()
            .is_none());
        assert!(!pending_self_upgrade_path(&state_dir).exists());
    }
}
