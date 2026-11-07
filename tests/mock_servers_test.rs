//! End-to-end integration tests using local Axum mock servers for ActionRunner-controller and MuRegist.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use mu_cd_controller::contract::{IntegrationTestSelector, MuConDeConfig};
use mu_cd_controller::error::OrchestratorError;
use mu_cd_controller::lease::{ClusterIdlePoller, ClusterNodeStatus, LeaseCoordinator};
use mu_cd_controller::orchestrator::{
    AgentIpcClient, DeploymentOrchestrator, DeploymentOutcome, HttpMuRegistClient,
};
use mu_cd_ipc::{
    DeploymentSlot, IntegrationTestReport, RollbackCommand, SlotSwapCommand,
    StageDeploymentRequest, StageDeploymentResponse,
};

// ============================================================================
// Mock ActionRunner-controller Server
// ============================================================================

async fn handle_get_cluster_nodes() -> impl IntoResponse {
    let nodes = vec![
        ClusterNodeStatus {
            node_id: "node-idle-1".to_string(),
            online: true,
            active_slots: 0,
            max_slots: 1,
            exclusive_locked: false,
        },
        ClusterNodeStatus {
            node_id: "node-offline".to_string(),
            online: false,
            active_slots: 0,
            max_slots: 1,
            exclusive_locked: false,
        },
        ClusterNodeStatus {
            node_id: "node-busy".to_string(),
            online: true,
            active_slots: 1,
            max_slots: 1,
            exclusive_locked: false,
        },
        ClusterNodeStatus {
            node_id: "node-locked".to_string(),
            online: true,
            active_slots: 0,
            max_slots: 1,
            exclusive_locked: true,
        },
    ];

    Json(nodes)
}

async fn start_mock_controller_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let app = Router::new().route("/api/cluster/nodes", get(handle_get_cluster_nodes));

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, handle)
}

// ============================================================================
// Mock MuRegist Server
// ============================================================================

#[derive(Default, Clone)]
struct MockRegistryState {
    pub promote_invocations: Arc<AtomicU32>,
    pub taint_invocations: Arc<AtomicU32>,
    pub tainted_digests: Arc<Mutex<HashSet<String>>>,
    pub promoted_digests: Arc<Mutex<HashSet<String>>>,
}

#[derive(Debug, Deserialize)]
struct MockTaintRequest {
    #[allow(dead_code)]
    pub service_name: Option<String>,
    #[allow(dead_code)]
    pub node_id: Option<String>,
    #[allow(dead_code)]
    pub reason: Option<String>,
}

async fn handle_promote(
    State(state): State<MockRegistryState>,
    Path(digest): Path<String>,
) -> impl IntoResponse {
    let taints = state.tainted_digests.lock().await;
    if taints.contains(&digest) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "cannot_promote_tainted",
                "message": format!("Digest {digest} is tainted and cannot be promoted")
            })),
        );
    }
    drop(taints);

    state.promote_invocations.fetch_add(1, Ordering::SeqCst);
    let mut promoted = state.promoted_digests.lock().await;
    promoted.insert(digest.clone());

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "healthy",
            "digest": digest
        })),
    )
}

async fn handle_taint(
    State(state): State<MockRegistryState>,
    Path(digest): Path<String>,
    Json(_payload): Json<MockTaintRequest>,
) -> impl IntoResponse {
    state.taint_invocations.fetch_add(1, Ordering::SeqCst);
    let mut taints = state.tainted_digests.lock().await;
    taints.insert(digest.clone());

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "tainted",
            "digest": digest
        })),
    )
}

#[derive(Serialize)]
struct CanaryStatusResponse {
    pub status: String,
    pub active_canary_digest: Option<String>,
}

async fn handle_canary_status(State(state): State<MockRegistryState>) -> impl IntoResponse {
    let taints = state.tainted_digests.lock().await;
    let (status, active) = if let Some(first_tainted) = taints.iter().next() {
        ("tainted", Some(first_tainted.clone()))
    } else {
        ("healthy", None)
    };

    Json(CanaryStatusResponse {
        status: status.to_string(),
        active_canary_digest: active,
    })
}

async fn start_mock_regist_server(
    state: MockRegistryState,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/api/v1/canary/{digest}/promote", post(handle_promote))
        .route("/api/v1/canary/{digest}/taint", post(handle_taint))
        .route("/api/v1/canary/status", get(handle_canary_status))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, handle)
}

// ============================================================================
// Test Mock Agent IPC Client
// ============================================================================

#[derive(Default)]
struct TestAgentClient {
    pub stage_ok: AtomicBool,
    pub stage_calls: AtomicU32,
    pub swap_calls: AtomicU32,
    pub it_passed: AtomicBool,
    pub it_failed_tests: Mutex<Vec<String>>,
    pub rollback_calls: AtomicU32,
    pub last_rollback_cmd: Mutex<Option<RollbackCommand>>,
}

#[async_trait::async_trait]
impl AgentIpcClient for TestAgentClient {
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
        Ok(())
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
            duration_ms: 50,
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

// ============================================================================
// Integration Tests
// ============================================================================

#[tokio::test]
async fn test_actionrunner_cluster_idle_poller_live_mock() {
    let (addr, server_handle) = start_mock_controller_server().await;
    let base_url = format!("http://{}", addr);

    let poller = ClusterIdlePoller::with_client(&base_url, reqwest::Client::new());

    let all_nodes = poller
        .fetch_nodes()
        .await
        .expect("fetch_nodes from mock controller");
    assert_eq!(all_nodes.len(), 4);

    let idle_nodes = poller.fetch_idle_nodes().await.expect("fetch_idle_nodes");
    assert_eq!(idle_nodes.len(), 1);
    assert_eq!(idle_nodes[0].node_id, "node-idle-1");
    assert!(idle_nodes[0].is_idle_for_deployment());

    server_handle.abort();
}

#[tokio::test]
async fn test_end_to_end_full_success_promotes_on_mock_muregist() {
    let reg_state = MockRegistryState::default();
    let (reg_addr, reg_handle) = start_mock_regist_server(reg_state.clone()).await;
    let reg_url = format!("http://{}", reg_addr);

    let coordinator = Arc::new(LeaseCoordinator::new());
    let agent = Arc::new(TestAgentClient {
        stage_ok: AtomicBool::new(true),
        it_passed: AtomicBool::new(true),
        ..Default::default()
    });

    let regist_client = Arc::new(HttpMuRegistClient::with_client(
        &reg_url,
        reqwest::Client::new(),
        Some("test-bearer-token".into()),
    ));

    let orchestrator =
        DeploymentOrchestrator::new(coordinator.clone(), None, agent.clone(), regist_client);

    let config = MuConDeConfig {
        version: "1".into(),
        service: "action-runner".into(),
        target_nodes: vec!["worker-riscv64".into()],
        lease_ttl_seconds: 300,
        warmup_timeout_seconds: 30,
        bake_window_seconds: 60,
        max_error_logs: 0,
        max_p99_latency_ms: 250.0,
        integration_tests: IntegrationTestSelector::All("all".into()),
    };

    let digest = "sha256-canary-pass-999";

    let outcome = orchestrator
        .orchestrate_deployment(&config, digest, Some("dep-success-test".into()))
        .await
        .expect("deployment succeeded");

    assert!(outcome.is_promoted());
    assert_eq!(agent.stage_calls.load(Ordering::SeqCst), 1);
    assert_eq!(agent.swap_calls.load(Ordering::SeqCst), 1);
    assert_eq!(agent.rollback_calls.load(Ordering::SeqCst), 0);

    // Verify MuRegist POST /api/v1/canary/{digest}/promote was called
    assert_eq!(reg_state.promote_invocations.load(Ordering::SeqCst), 1);
    assert_eq!(reg_state.taint_invocations.load(Ordering::SeqCst), 0);
    let promoted = reg_state.promoted_digests.lock().await;
    assert!(promoted.contains(digest));

    reg_handle.abort();
}

#[tokio::test]
async fn test_end_to_end_it_failure_triggers_rollback_and_taints_mock_muregist() {
    let reg_state = MockRegistryState::default();
    let (reg_addr, reg_handle) = start_mock_regist_server(reg_state.clone()).await;
    let reg_url = format!("http://{}", reg_addr);

    let coordinator = Arc::new(LeaseCoordinator::new());
    let agent = Arc::new(TestAgentClient {
        stage_ok: AtomicBool::new(true),
        it_passed: AtomicBool::new(false),
        it_failed_tests: Mutex::new(vec!["it_smoke".into(), "it_mtls".into()]),
        ..Default::default()
    });

    let regist_client = Arc::new(HttpMuRegistClient::with_client(
        &reg_url,
        reqwest::Client::new(),
        Some("test-bearer-token".into()),
    ));

    let orchestrator =
        DeploymentOrchestrator::new(coordinator.clone(), None, agent.clone(), regist_client);

    let config = MuConDeConfig {
        version: "1".into(),
        service: "action-runner".into(),
        target_nodes: vec!["worker-riscv64".into()],
        lease_ttl_seconds: 300,
        warmup_timeout_seconds: 30,
        bake_window_seconds: 60,
        max_error_logs: 0,
        max_p99_latency_ms: 250.0,
        integration_tests: IntegrationTestSelector::Selected(vec![
            "it_smoke".into(),
            "it_mtls".into(),
        ]),
    };

    let digest = "sha256-canary-fail-000";

    let outcome = orchestrator
        .orchestrate_deployment(&config, digest, Some("dep-fail-test".into()))
        .await
        .expect("deployment returns outcome");

    match outcome {
        DeploymentOutcome::RolledBack {
            service,
            artifact_sha256,
            reason,
            ..
        } => {
            assert_eq!(service, "action-runner");
            assert_eq!(artifact_sha256, digest);
            assert!(reason.contains("it_smoke"));
        }
        other => panic!("Expected RolledBack, got: {:?}", other),
    }

    // 1. Verify RollbackCommand was dispatched to agent
    assert_eq!(agent.rollback_calls.load(Ordering::SeqCst), 1);
    let last_rb = agent.last_rollback_cmd.lock().await;
    let rb = last_rb.as_ref().expect("RollbackCommand captured");
    assert_eq!(rb.restore_slot, DeploymentSlot::SlotA);
    assert_eq!(rb.failed_artifact_sha256, digest);

    // 2. Verify MuRegist POST /api/v1/canary/{digest}/taint was called
    assert_eq!(reg_state.promote_invocations.load(Ordering::SeqCst), 0);
    assert_eq!(reg_state.taint_invocations.load(Ordering::SeqCst), 1);
    let taints = reg_state.tainted_digests.lock().await;
    assert!(taints.contains(digest));

    // 3. Verify subsequent deployment attempt of the tainted digest is rejected BEFORE lease/staging
    let retry_res = orchestrator
        .orchestrate_deployment(&config, digest, Some("dep-retry-test".into()))
        .await;

    match retry_res {
        Err(OrchestratorError::ArtifactTainted(d)) => assert_eq!(d, digest),
        other => panic!("Expected ArtifactTainted error, got: {:?}", other),
    }

    // Agent staging must still be 1 (never touched on retry)
    assert_eq!(agent.stage_calls.load(Ordering::SeqCst), 1);

    reg_handle.abort();
}

#[tokio::test]
async fn test_end_to_end_muobserve_slo_gate_promote_and_breach_rollback_taint() {
    use mu_cd_controller::slo::MuObserveSloClient;
    use mu_observable_ipc::{
        decode_control_envelope, encode_control_envelope, read_frame, write_frame,
        CanarySloAssertionResponse, ControlRpcEnvelope, IpcHeader, MSG_TYPE_FORY_CONTROL,
    };

    let reg_state = MockRegistryState::default();
    let (reg_addr, reg_handle) = start_mock_regist_server(reg_state.clone()).await;
    let reg_url = format!("http://{}", reg_addr);

    // Start a live MUOB Fory RPC mock MuObserve server that approves "sha256-canary-slo-ok"
    // and rejects "sha256-canary-slo-breach" with taint_recommended = true.
    let observe_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind observe");
    let observe_addr = observe_listener.local_addr().expect("observe local_addr");
    let observe_handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = observe_listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (hdr, payload) = read_frame(&mut stream).await.expect("read slo req");
                assert_eq!(hdr.msg_type, MSG_TYPE_FORY_CONTROL);
                let env = decode_control_envelope(&payload).expect("decode slo req");
                if let ControlRpcEnvelope::CanarySloReq(req) = env {
                    let is_ok = req.candidate_digest == "sha256-canary-slo-ok";
                    let resp = if is_ok {
                        CanarySloAssertionResponse {
                            request_id: req.request_id,
                            healthy: true,
                            error_log_count: 0,
                            p99_latency_ms: 19.5,
                            taint_recommended: false,
                            reason: "SLO healthy".to_string(),
                        }
                    } else {
                        CanarySloAssertionResponse {
                            request_id: req.request_id,
                            healthy: false,
                            error_log_count: 7,
                            p99_latency_ms: 615.0,
                            taint_recommended: true,
                            reason: "p99 latency 615.0ms > 250.0ms and 7 error logs".to_string(),
                        }
                    };
                    let bytes = encode_control_envelope(&ControlRpcEnvelope::CanarySloResp(resp))
                        .expect("encode slo resp");
                    let resp_hdr =
                        IpcHeader::new(MSG_TYPE_FORY_CONTROL, bytes.len() as u32, 0, hdr.sequence);
                    write_frame(&mut stream, &resp_hdr, &bytes)
                        .await
                        .expect("write slo resp");
                }
            });
        }
    });

    let coordinator = Arc::new(LeaseCoordinator::new());
    let agent = Arc::new(TestAgentClient {
        stage_ok: AtomicBool::new(true),
        it_passed: AtomicBool::new(true),
        ..Default::default()
    });
    let regist_client = Arc::new(HttpMuRegistClient::with_client(
        &reg_url,
        reqwest::Client::new(),
        Some("test-bearer-token".into()),
    ));
    let slo_client = Arc::new(MuObserveSloClient::new_plaintext(observe_addr.to_string()));

    let orchestrator =
        DeploymentOrchestrator::new(coordinator.clone(), None, agent.clone(), regist_client)
            .with_slo_client(slo_client);

    let config = MuConDeConfig {
        version: "1".into(),
        service: "action-runner".into(),
        target_nodes: vec!["worker-riscv64".into()],
        lease_ttl_seconds: 300,
        warmup_timeout_seconds: 30,
        bake_window_seconds: 60,
        max_error_logs: 0,
        max_p99_latency_ms: 250.0,
        integration_tests: IntegrationTestSelector::All("all".into()),
    };

    // Case 1: Healthy SLO -> Promoted
    let ok_digest = "sha256-canary-slo-ok";
    let ok_outcome = orchestrator
        .orchestrate_deployment(&config, ok_digest, Some("dep-slo-ok".into()))
        .await
        .expect("ok deployment");
    assert!(ok_outcome.is_promoted());
    assert_eq!(reg_state.promote_invocations.load(Ordering::SeqCst), 1);
    assert_eq!(reg_state.taint_invocations.load(Ordering::SeqCst), 0);
    assert_eq!(agent.rollback_calls.load(Ordering::SeqCst), 0);

    // Case 2: Breached SLO -> Automatic Rollback + MuRegist Taint
    let bad_digest = "sha256-canary-slo-breach";
    let bad_outcome = orchestrator
        .orchestrate_deployment(&config, bad_digest, Some("dep-slo-breach".into()))
        .await
        .expect("breach deployment returns outcome");
    assert!(bad_outcome.is_rolled_back());
    assert_eq!(agent.rollback_calls.load(Ordering::SeqCst), 1);
    assert_eq!(reg_state.promote_invocations.load(Ordering::SeqCst), 1);
    assert_eq!(reg_state.taint_invocations.load(Ordering::SeqCst), 1);

    let taints = reg_state.tainted_digests.lock().await;
    assert!(taints.contains(bad_digest));
    drop(taints);

    reg_handle.abort();
    observe_handle.abort();
}
