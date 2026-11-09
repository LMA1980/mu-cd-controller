//! Continuous delivery deployment state machine and orchestrator.
//!
//! Coordinates TTL-bounded leases, inactive slot staging, live health probes,
//! atomic slot promotion, automatic rollback, and digest tainting.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use mu_cd_ipc::{
    create_fory_runtime, read_frame, write_frame, ArtifactTaintNotification, DeploymentLeaseGrant,
    DeploymentLeaseRequest, IntegrationTestProgress, IntegrationTestReport, IpcHeader,
    RollbackCommand, SlotSwapCommand, StageDeploymentRequest, StageDeploymentResponse,
    MSG_TYPE_IT_PROGRESS, MSG_TYPE_IT_REPORT, MSG_TYPE_ROLLBACK, MSG_TYPE_SLOT_SWAP,
    MSG_TYPE_STAGE_DEPLOY_REQ, MSG_TYPE_STAGE_DEPLOY_RESP,
};
use mu_observable_ipc::CanarySloAssertionRequest;

use crate::cd_state::{
    classify_rollback_reason, CdStateStore, DeploymentStart, ItProgressSink, Slot,
};
use crate::contract::MuConDeConfig;
use crate::error::{LeaseError, OrchestratorError};
use crate::lease::{ClusterIdlePoller, LeaseCoordinator};
use crate::slo::CanarySloClient;
use crate::tls::TlsConfig;

/// Default MuRegist server URL used across continuous delivery fabric.
pub const DEFAULT_REGISTRY_URL: &str = "https://registry.ci.ci.internal:8444";

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
        let url = format!("{}/api/v1/canary/{digest}/taint", self.base_url);
        let payload = TaintPayload {
            service_name: Some(notification.service_name.clone()),
            node_id: None,
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
    /// Any other or unknown message type; skipped without decoding the payload.
    Ignored(u16),
}

/// Dispatches one frame read from an agent while the integration gate runs.
///
/// Dispatch happens on `msg_type` before decoding, so unknown message IDs are skipped
/// safely. A progress payload that fails to decode is logged and ignored (progress is
/// advisory); a report that fails to decode is an error.
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
        other => Ok(AgentFrame::Ignored(other)),
    }
}

/// Resolves a logical target node identifier (e.g. `node-a`, `node-b`, `worker-riscv64`)
/// using `MUCONDE_NODE_MAP` (`"node-a=host1,node-b=host2"`).
pub fn resolve_target_node(logical: &str) -> String {
    if let Ok(map_str) = std::env::var("MUCONDE_NODE_MAP") {
        resolve_target_node_from_map(logical, &map_str)
    } else {
        logical.trim().to_string()
    }
}

/// Pure helper resolving `logical` against a comma-separated `key=value` map string.
pub fn resolve_target_node_from_map(logical: &str, map_str: &str) -> String {
    let trimmed = logical.trim();
    for pair in map_str.split(',') {
        if let Some((k, v)) = pair.split_once('=') {
            if k.trim().eq_ignore_ascii_case(trimmed) && !v.trim().is_empty() {
                return v.trim().to_string();
            }
        }
    }
    trimmed.to_string()
}

/// Resolves and deduplicates a list of logical target node names while preserving order.
pub fn resolve_target_nodes(nodes: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for n in nodes.iter().take(64) {
        let resolved = resolve_target_node(n);
        if !resolved.is_empty() && !out.contains(&resolved) {
            out.push(resolved);
        }
    }
    out
}

/// Network implementation of `AgentIpcClient` communicating over TCP/TLS framing.
#[derive(Clone)]
pub struct IpcAgentClient {
    port: u16,
    progress_sink: Option<Arc<dyn ItProgressSink>>,
    active_streams:
        Arc<tokio::sync::Mutex<std::collections::HashMap<String, tokio::net::TcpStream>>>,
}

impl std::fmt::Debug for IpcAgentClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpcAgentClient")
            .field("port", &self.port)
            .field("progress_sink", &self.progress_sink.is_some())
            .finish()
    }
}

impl IpcAgentClient {
    /// Create client targeting agents listening on standard CD port.
    pub fn new(port: u16) -> Self {
        Self {
            port,
            progress_sink: None,
            active_streams: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Forward `IntegrationTestProgress` frames to `sink` (e.g. the CD API state store).
    #[must_use]
    pub fn with_progress_sink(mut self, sink: Arc<dyn ItProgressSink>) -> Self {
        self.progress_sink = Some(sink);
        self
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
        let host = resolve_target_node(node_id);
        let addr = format!("{}:{}", host, self.port);
        let mut stream = tokio::net::TcpStream::connect(&addr).await.map_err(|e| {
            OrchestratorError::Agent(format!("Connect to agent {addr} failed: {e}"))
        })?;

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
        let fory = create_fory_runtime().map_err(|e| OrchestratorError::Agent(e.to_string()))?;
        let host = resolve_target_node(node_id);
        let addr = format!("{}:{}", host, self.port);
        let mut stream = tokio::net::TcpStream::connect(&addr).await.map_err(|e| {
            OrchestratorError::Agent(format!("Connect to agent {addr} failed: {e}"))
        })?;

        let payload = fory
            .serialize(cmd)
            .map_err(|e| OrchestratorError::Agent(e.to_string()))?;
        let header = IpcHeader::new(MSG_TYPE_SLOT_SWAP, payload.len() as u32, 0, 1);

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
        let host = resolve_target_node(node_id);
        let addr = format!("{}:{}", host, self.port);
        let mut stream = if let Some(s) = self.active_streams.lock().await.remove(deployment_id) {
            s
        } else {
            tokio::net::TcpStream::connect(&addr).await.map_err(|e| {
                OrchestratorError::Agent(format!("Connect to agent {addr} failed: {e}"))
            })?
        };

        let executed = match selected_tests {
            Some(tests) => tests.to_vec(),
            None => vec!["all".to_string()],
        };

        // Await IntegrationTestReport frame or terminal IntegrationTestProgress frames within timeout
        let read_future = async {
            let mut seen_states: std::collections::HashMap<String, mu_cd_ipc::TestState> =
                std::collections::HashMap::new();
            let mut seen_order: Vec<String> = Vec::new();
            let mut max_duration_ms: u64 = 0;
            let mut reconnected_after_swap_eof = false;

            loop {
                let frame_res = read_frame(&mut stream).await;
                let (header, payload) = match frame_res {
                    Ok(f) => f,
                    Err(mu_cd_ipc::IpcError::Io(ref e))
                        if e.kind() == std::io::ErrorKind::UnexpectedEof
                            && seen_states.is_empty()
                            && !reconnected_after_swap_eof =>
                    {
                        reconnected_after_swap_eof = true;
                        stream = tokio::net::TcpStream::connect(&addr).await.map_err(|ce| {
                            OrchestratorError::Agent(format!(
                                "Connect to agent {addr} failed: {ce}"
                            ))
                        })?;
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
                    AgentFrame::Ignored(_) => {}
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
        let host = resolve_target_node(node_id);
        let addr = format!("{}:{}", host, self.port);
        let mut stream = tokio::net::TcpStream::connect(&addr).await.map_err(|e| {
            OrchestratorError::Agent(format!("Connect to agent {addr} failed: {e}"))
        })?;

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
    agent_client: Arc<dyn AgentIpcClient>,
    regist_client: Arc<dyn MuRegistClient>,
    slo_client: Option<Arc<dyn CanarySloClient>>,
    tainted_digests: Arc<RwLock<HashSet<String>>>,
    cd_state: Option<Arc<CdStateStore>>,
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
            agent_client,
            regist_client,
            slo_client: None,
            tainted_digests: Arc::new(RwLock::new(HashSet::new())),
            cd_state: None,
        }
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

    /// Discover and select the first eligible idle target node from the configured list.
    pub async fn select_idle_target_node(
        &self,
        target_nodes: &[String],
    ) -> Result<String, OrchestratorError> {
        if let Some(ref poller) = self.poller {
            let nodes = poller
                .fetch_nodes()
                .await
                .map_err(OrchestratorError::Lease)?;

            for target in target_nodes {
                let resolved = resolve_target_node(target);
                if let Some(node) = nodes
                    .iter()
                    .find(|n| n.node_id == resolved || &n.node_id == target)
                {
                    if node.is_idle_for_deployment() {
                        return Ok(target.clone());
                    }
                }
            }

            Err(OrchestratorError::Lease(LeaseError::NodeNotIdle(format!(
                "None of the target nodes {:?} are currently idle and eligible",
                target_nodes
            ))))
        } else if let Some(first) = target_nodes.first() {
            // When poller is not provided (standalone/test), use first target node
            Ok(first.clone())
        } else {
            Err(OrchestratorError::Lease(LeaseError::Internal(
                "No target nodes specified".into(),
            )))
        }
    }

    /// Orchestrates sequential A/B rollout across every target node in `config.target_nodes`
    /// (resolved through `MUCONDE_NODE_MAP` when connecting to node agents).
    ///
    /// Stops immediately and returns the outcomes collected so far if any node rolls back.
    pub async fn orchestrate_rollout_for_repo(
        &self,
        config: &MuConDeConfig,
        artifact_sha256: &str,
        repo: Option<&str>,
    ) -> Result<Vec<DeploymentOutcome>, OrchestratorError> {
        config.validate()?;
        let mut targets = Vec::new();
        for n in config.target_nodes.iter().take(64) {
            let trimmed = n.trim().to_string();
            if !trimmed.is_empty() && !targets.contains(&trimmed) {
                targets.push(trimmed);
            }
        }
        let mut outcomes = Vec::new();
        for node in targets {
            let mut single_cfg = config.clone();
            single_cfg.target_nodes = vec![node];
            let outcome = self
                .orchestrate_deployment_for_repo(&single_cfg, artifact_sha256, None, repo)
                .await?;
            let rolled_back = outcome.is_rolled_back();
            outcomes.push(outcome);
            if rolled_back {
                break;
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
        // Step 1: Enforce Digest Tainting Pre-check (#10)
        if self.is_digest_tainted(artifact_sha256).await? {
            return Err(OrchestratorError::ArtifactTainted(
                artifact_sha256.to_string(),
            ));
        }

        // Validate declarative contract
        config.validate()?;

        // Step 2: Select idle target worker node (#4)
        let target_node = self.select_idle_target_node(&config.target_nodes).await?;

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

        let grant = self.lease_coordinator.acquire_lease(&lease_req).await;
        if !grant.granted {
            let reason = grant
                .denial_reason
                .unwrap_or_else(|| "Deployment lease denied".to_string());
            return Err(OrchestratorError::Lease(LeaseError::Internal(reason)));
        }

        if let Some(ref store) = self.cd_state {
            // Contract test list in order; "all" is expanded by the agent's Pending frames.
            // The contract has no per-test criticality, so every contract test is critical.
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

        let stage_result = self
            .agent_client
            .stage_deployment(&target_node, &stage_req)
            .await;

        let stage_ok = match stage_result {
            Ok(ref resp) if resp.staged_ok => true,
            Ok(ref resp) => {
                let err_msg = resp
                    .error_message
                    .clone()
                    .unwrap_or_else(|| "Staging refused by agent".to_string());
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
                return self
                    .handle_failure_and_rollback(
                        &grant,
                        config,
                        &target_node,
                        artifact_sha256,
                        &format!("Agent stage IPC error: {e}"),
                    )
                    .await;
            }
        };

        if !stage_ok {
            return self
                .handle_failure_and_rollback(
                    &grant,
                    config,
                    &target_node,
                    artifact_sha256,
                    "Staging verification failed",
                )
                .await;
        }

        // Step 5: Instruct agent to perform atomic slot swap to Slot B
        let swap_cmd = SlotSwapCommand {
            deployment_id: deployment_id.clone(),
            lease_id: grant.lease_id.clone(),
            service_name: config.service.clone(),
            from_slot: grant.active_slot,
            to_slot: grant.candidate_slot,
            systemd_unit: format!("{}.service", config.service),
            warmup_timeout_secs: config.warmup_timeout_seconds,
        };

        if let Err(e) = self.agent_client.slot_swap(&target_node, &swap_cmd).await {
            return self
                .handle_failure_and_rollback(
                    &grant,
                    config,
                    &target_node,
                    artifact_sha256,
                    &format!("Atomic slot swap failed: {e}"),
                )
                .await;
        }

        // Step 6: Await integration test execution and health watchdog
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
                return self
                    .handle_failure_and_rollback(
                        &grant,
                        config,
                        &target_node,
                        artifact_sha256,
                        &format!("Integration test communication failure: {e}"),
                    )
                    .await;
            }
        };

        // Check verification outcome
        let now_ms = LeaseCoordinator::current_epoch_ms();
        let lease_expired = now_ms >= grant.expires_at_epoch_ms;

        if lease_expired {
            return self
                .handle_failure_and_rollback(
                    &grant,
                    config,
                    &target_node,
                    artifact_sha256,
                    "Lease TTL expired before integration tests completed",
                )
                .await;
        }

        if !report.passed || !report.failed_tests.is_empty() {
            let reason = format!("Integration tests failed: {:?}", report.failed_tests);
            return self
                .handle_failure_and_rollback(&grant, config, &target_node, artifact_sha256, &reason)
                .await;
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

        Ok(DeploymentOutcome::Promoted {
            deployment_id,
            service: config.service.clone(),
            target_node,
            artifact_sha256: artifact_sha256.to_string(),
        })
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
            .taint_canary(artifact_sha256, &taint_notification)
            .await
        {
            tracing::error!(
                digest = %artifact_sha256,
                error = %e,
                "Failed to send taint notification to MuRegist"
            );
        }

        // 4. Clean up lease in LeaseCoordinator
        let _ = self.lease_coordinator.release_lease(&grant.lease_id).await;

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

        Ok(DeploymentOutcome::RolledBack {
            deployment_id: grant.deployment_id.clone(),
            service: config.service.clone(),
            target_node: target_node.to_string(),
            artifact_sha256: artifact_sha256.to_string(),
            reason: reason.to_string(),
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
        pub swap_ok: AtomicBool,
        pub swap_calls: AtomicU32,
        pub it_passed: AtomicBool,
        pub it_failed_tests: Mutex<Vec<String>>,
        pub rollback_calls: AtomicU32,
        pub last_rollback_cmd: Mutex<Option<RollbackCommand>>,
    }

    #[async_trait]
    impl AgentIpcClient for MockAgentClient {
        async fn stage_deployment(
            &self,
            _node_id: &str,
            req: &StageDeploymentRequest,
        ) -> Result<StageDeploymentResponse, OrchestratorError> {
            self.stage_calls.fetch_add(1, Ordering::SeqCst);
            let ok = self.stage_ok.load(Ordering::SeqCst);
            Ok(StageDeploymentResponse {
                deployment_id: req.deployment_id.clone(),
                target_slot: req.target_slot,
                btrfs_subvolume_path: "/srv/muconde/slots/slot-b".into(),
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
            _node_id: &str,
            _cmd: &SlotSwapCommand,
        ) -> Result<(), OrchestratorError> {
            self.swap_calls.fetch_add(1, Ordering::SeqCst);
            if self.swap_ok.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(OrchestratorError::Agent("Swap simulated failure".into()))
            }
        }

        async fn execute_integration_tests(
            &self,
            _node_id: &str,
            deployment_id: &str,
            service: &str,
            artifact_sha256: &str,
            _selected_tests: Option<&[String]>,
            _timeout: Duration,
        ) -> Result<IntegrationTestReport, OrchestratorError> {
            let passed = self.it_passed.load(Ordering::SeqCst);
            let failed = self.it_failed_tests.lock().await.clone();
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
            _node_id: &str,
            cmd: &RollbackCommand,
        ) -> Result<(), OrchestratorError> {
            self.rollback_calls.fetch_add(1, Ordering::SeqCst);
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
            self.taint_calls.fetch_add(1, Ordering::SeqCst);
            let mut taints = self.tainted_digests.lock().await;
            taints.insert(digest.to_string());
            let mut last = self.last_taint.lock().await;
            *last = Some((digest.to_string(), notification.clone()));
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
    fn test_resolve_target_node_from_map() {
        let map = "node-a=host-primary,node-b=host-secondary,worker-riscv64=host-riscv";
        assert_eq!(resolve_target_node_from_map("node-a", map), "host-primary");
        assert_eq!(
            resolve_target_node_from_map("node-b", map),
            "host-secondary"
        );
        assert_eq!(
            resolve_target_node_from_map("worker-riscv64", map),
            "host-riscv"
        );
        assert_eq!(
            resolve_target_node_from_map("custom-node", map),
            "custom-node"
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
}
