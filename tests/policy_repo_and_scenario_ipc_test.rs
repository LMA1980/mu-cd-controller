//! Integration tests for Phase 2 zero-trust deployment policy inversion (`#102`, `#103`)
//! and additive `mu-cd-ipc` `v0.3.0` `ScenarioExecutionPlan` (`0x0D` / `0x0E`) propagation (`#104`).

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use mu_cd_controller::api::{router, CdApiState, DeployTriggerResponse};
use mu_cd_controller::cd_state::CdStateStore;
use mu_cd_controller::error::OrchestratorError;
use mu_cd_controller::lease::LeaseCoordinator;
use mu_cd_controller::orchestrator::{
    dispatch_agent_frame, AgentFrame, AgentIpcClient, DeploymentOrchestrator, IpcAgentClient,
    MuRegistClient,
};
use mu_cd_controller::policy_repo::{
    PolicyRepoConfig, PolicyRepository, METRIC_POLICY_VERIFY_FAILED,
};
use mu_cd_controller::telemetry::RecordingCdTelemetrySink;
use mu_cd_ipc::{
    create_fory_runtime, read_frame, write_frame, ArtifactTaintNotification, DeploymentSlot,
    IntegrationTestProgress, IntegrationTestReport, IpcHeader, RollbackCommand,
    ScenarioExecutionPlan, ScenarioPlanAck, SlotSwapCommand, StageDeploymentRequest,
    StageDeploymentResponse, TestState, MSG_TYPE_IT_PROGRESS, MSG_TYPE_IT_REPORT,
    MSG_TYPE_ROLLBACK, MSG_TYPE_SCENARIO_PLAN, MSG_TYPE_SCENARIO_PLAN_ACK, MSG_TYPE_SLOT_SWAP,
    MSG_TYPE_STAGE_DEPLOY_REQ, MSG_TYPE_STAGE_DEPLOY_RESP,
};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tower::ServiceExt;

const API_TOKEN: &str = "phase2-cd-service-token";

fn bearer() -> String {
    format!("Bearer {API_TOKEN}")
}

fn run_cmd_ok(cmd: &mut std::process::Command) {
    let out = cmd.output().expect("spawn command");
    assert!(
        out.status.success(),
        "command {:?} failed: stdout={}, stderr={}",
        cmd,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn sample_nodes_yaml(host_a: &str, host_b: &str) -> String {
    format!(
        r#"
nodes:
  - node_id: "node-a"
    arch: "x86_64"
    host: "{host_a}"
    max_memlock_kb: 2097152
    max_slots: 1
    thread_budget: 2
    mucd_root: "/srv/mucd"
  - node_id: "worker-riscv64"
    arch: "riscv64gc"
    host: "{host_b}"
    max_memlock_kb: 29360128
    max_slots: 1
    thread_budget: 6
    mucd_root: "/srv/mucd"
"#
    )
}

fn sample_service_yaml() -> &'static str {
    r#"
version: "2"
service: "example-service"
target_nodes:
  - "node-a"
  - "worker-riscv64"
lease_ttl_seconds: 300
warmup_timeout_seconds: 10
bake_window_seconds: 60
max_error_logs: 0
max_p99_latency_ms: 250.0
ab_rules:
  btrfs_snapshots: true
  keep_snapshots: 5
  auto_rollback_on_critical: true
deployment:
  binary: "example-service"
  install_path: "/usr/local/bin/example-service"
  systemd_unit: "example-service.service"
  rollout_strategy: "sequential"
sandbox_ceiling:
  max_pids: 256
  max_memlock_kb: 65536
integration_tests:
  - "systemd_unit_active"
  - "smoke_example_service"
scenarios:
  - name: "smoke_example_service_node_a"
    test_binary: "smoke_example_service"
    args: ["--nocapture"]
    target_url: "https://node-a.cluster.internal:8445"
    tls_ca_file: "/etc/mu-cd-canary/tls/ca.crt"
    tls_cert_file: "/etc/mu-cd-canary/tls/canary-probe.crt"
    tls_key_file: "/etc/mu-cd-canary/tls/canary-probe.key"
    bearer_token_file: "/etc/mu-cd-canary/tokens/cd-readonly.token"
    read_only: true
    timeout_secs: 10
    restricted_cidrs:
      - "192.0.2.10/32"
      - "127.0.0.1/32"
  - name: "smoke_example_service_worker_riscv64"
    test_binary: "smoke_example_service"
    args: ["--nocapture"]
    target_addr: "worker-riscv64.cluster.internal:8446"
    tls_ca_file: "/etc/mu-cd-canary/tls/ca.crt"
    tls_cert_file: "/etc/mu-cd-canary/tls/canary-probe.crt"
    tls_key_file: "/etc/mu-cd-canary/tls/canary-probe.key"
    read_only: true
    timeout_secs: 12
    restricted_cidrs:
      - "192.0.2.20/32"
      - "127.0.0.1/32"
"#
}

struct TestPolicyFixture {
    _tmp: tempfile::TempDir,
    repo_dir: std::path::PathBuf,
    signing_key: std::path::PathBuf,
    signers_file: std::path::PathBuf,
}

impl TestPolicyFixture {
    fn create(host_a: &str, host_b: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let signing_key = tmp.path().join("signer_ed25519");
        run_cmd_ok(std::process::Command::new("ssh-keygen").args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-f",
            signing_key.to_str().unwrap(),
        ]));
        let pub_key = std::fs::read_to_string(tmp.path().join("signer_ed25519.pub")).unwrap();
        let signers_file = tmp.path().join("allowed_signers");
        std::fs::write(&signers_file, format!("cd-test@example.invalid {pub_key}")).unwrap();
        std::fs::set_permissions(&signers_file, std::fs::Permissions::from_mode(0o644)).unwrap();

        let repo_dir = tmp.path().join("policy-repo");
        let fixture = Self {
            _tmp: tmp,
            repo_dir,
            signing_key,
            signers_file,
        };
        fixture.commit_files(
            &sample_nodes_yaml(host_a, host_b),
            sample_service_yaml(),
            true,
            "initial signed policy",
        );
        fixture
    }

    fn commit_files(&self, nodes_yaml: &str, service_yaml: &str, signed: bool, msg: &str) {
        std::fs::create_dir_all(self.repo_dir.join("policy")).unwrap();
        std::fs::create_dir_all(self.repo_dir.join("contracts/services")).unwrap();
        std::fs::write(
            self.repo_dir.join("policy/commit-verification.yml"),
            format!(
                "branch: \"main\"\nrequire_signed_commits: true\nallowed_signers_path: \"{}\"\nfail_closed_on_unverified: true\n",
                self.signers_file.display()
            ),
        )
        .unwrap();
        std::fs::write(self.repo_dir.join("contracts/nodes.yml"), nodes_yaml).unwrap();
        std::fs::write(
            self.repo_dir.join("contracts/services/example-service.yml"),
            service_yaml,
        )
        .unwrap();

        if !self.repo_dir.join(".git").exists() {
            run_cmd_ok(
                std::process::Command::new("git")
                    .env("GIT_CONFIG_GLOBAL", "/dev/null")
                    .env("GIT_CONFIG_SYSTEM", "/dev/null")
                    .args(["-C", self.repo_dir.to_str().unwrap(), "init", "-b", "main"]),
            );
            run_cmd_ok(
                std::process::Command::new("git")
                    .env("GIT_CONFIG_GLOBAL", "/dev/null")
                    .env("GIT_CONFIG_SYSTEM", "/dev/null")
                    .args([
                        "-C",
                        self.repo_dir.to_str().unwrap(),
                        "config",
                        "user.name",
                        "CD Test",
                    ]),
            );
            run_cmd_ok(
                std::process::Command::new("git")
                    .env("GIT_CONFIG_GLOBAL", "/dev/null")
                    .env("GIT_CONFIG_SYSTEM", "/dev/null")
                    .args([
                        "-C",
                        self.repo_dir.to_str().unwrap(),
                        "config",
                        "user.email",
                        "cd-test@example.invalid",
                    ]),
            );
        }

        run_cmd_ok(
            std::process::Command::new("git")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .args(["-C", self.repo_dir.to_str().unwrap(), "add", "."]),
        );

        let mut commit = std::process::Command::new("git");
        commit
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .args(["-C", self.repo_dir.to_str().unwrap()]);
        if signed {
            commit.args([
                "-c",
                "gpg.format=ssh",
                "-c",
                &format!("user.signingkey={}", self.signing_key.display()),
                "commit",
                "-S",
                "-m",
                msg,
            ]);
        } else {
            commit.args(["commit", "-m", msg]);
        }
        run_cmd_ok(&mut commit);
    }

    fn policy_repo(&self, sink: Arc<RecordingCdTelemetrySink>) -> Arc<PolicyRepository> {
        Arc::new(
            PolicyRepository::new(PolicyRepoConfig {
                repo_dir: Some(self.repo_dir.clone()),
                refresh_on_deploy: true,
                ..Default::default()
            })
            .with_telemetry_sink(sink, "node-a"),
        )
    }
}

#[derive(Default)]
struct RecordingAgent {
    plans: Mutex<Vec<(String, Option<ScenarioExecutionPlan>)>>,
    rollbacks: Mutex<Vec<(String, DeploymentSlot)>>,
    fail_node: Option<String>,
}

#[async_trait]
impl AgentIpcClient for RecordingAgent {
    async fn stage_deployment(
        &self,
        _node_id: &str,
        req: &StageDeploymentRequest,
    ) -> Result<StageDeploymentResponse, OrchestratorError> {
        Ok(StageDeploymentResponse {
            deployment_id: req.deployment_id.clone(),
            target_slot: req.target_slot,
            btrfs_subvolume_path: "/srv/mucd/example-service/@b".into(),
            staged_ok: true,
            error_message: None,
        })
    }

    async fn slot_swap(
        &self,
        _node_id: &str,
        _cmd: &SlotSwapCommand,
    ) -> Result<(), OrchestratorError> {
        Ok(())
    }

    async fn slot_swap_with_plan(
        &self,
        node_id: &str,
        _cmd: &SlotSwapCommand,
        plan: Option<&ScenarioExecutionPlan>,
    ) -> Result<(), OrchestratorError> {
        self.plans
            .lock()
            .await
            .push((node_id.to_string(), plan.cloned()));
        Ok(())
    }

    async fn execute_integration_tests(
        &self,
        node_id: &str,
        deployment_id: &str,
        service: &str,
        artifact_sha256: &str,
        selected_tests: Option<&[String]>,
        _timeout: Duration,
    ) -> Result<IntegrationTestReport, OrchestratorError> {
        let should_fail = self.fail_node.as_deref() == Some(node_id);
        let tests = selected_tests
            .map(|s| s.to_vec())
            .unwrap_or_else(|| vec!["smoke_example_service".into()]);
        Ok(IntegrationTestReport {
            deployment_id: deployment_id.into(),
            service_name: service.into(),
            artifact_sha256: artifact_sha256.into(),
            executed_tests: tests,
            passed: !should_fail,
            failed_tests: if should_fail {
                vec!["smoke_example_service".into()]
            } else {
                vec![]
            },
            duration_ms: 42,
            log_excerpt: should_fail.then(|| "missing test in archive".into()),
        })
    }

    async fn rollback(
        &self,
        node_id: &str,
        cmd: &RollbackCommand,
    ) -> Result<(), OrchestratorError> {
        self.rollbacks
            .lock()
            .await
            .push((node_id.to_string(), cmd.restore_slot));
        Ok(())
    }
}

#[derive(Default)]
struct RecordingRegist {
    taints: Mutex<Vec<String>>,
    promoted: Mutex<Vec<String>>,
}

#[async_trait]
impl MuRegistClient for RecordingRegist {
    async fn is_digest_tainted(&self, digest: &str) -> Result<bool, OrchestratorError> {
        Ok(self.taints.lock().await.iter().any(|d| d == digest))
    }

    async fn promote_canary(&self, digest: &str) -> Result<(), OrchestratorError> {
        self.promoted.lock().await.push(digest.to_string());
        Ok(())
    }

    async fn taint_canary(
        &self,
        digest: &str,
        _notification: &ArtifactTaintNotification,
    ) -> Result<(), OrchestratorError> {
        self.taints.lock().await.push(digest.to_string());
        Ok(())
    }
}

async fn post_api(app: axum::Router, uri: &str, body: &str) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::AUTHORIZATION, bearer())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn test_zero_trust_deploy_ignores_caller_overrides_and_emits_deprecation_warning() {
    let fixture =
        TestPolicyFixture::create("node-a.cluster.internal", "worker-riscv64.cluster.internal");
    let sink = Arc::new(RecordingCdTelemetrySink::new());
    let policy_repo = fixture.policy_repo(sink.clone());
    let store = Arc::new(CdStateStore::default());
    let coordinator = Arc::new(LeaseCoordinator::new());
    let agent = Arc::new(RecordingAgent::default());
    let regist = Arc::new(RecordingRegist::default());

    let orchestrator = Arc::new(
        DeploymentOrchestrator::new(coordinator, None, agent.clone(), regist.clone())
            .with_cd_state(store.clone())
            .with_telemetry_sink(sink.clone())
            .with_policy_repo(policy_repo.clone()),
    );
    let app = router(
        CdApiState::new(store, Some(API_TOKEN.into()))
            .with_orchestrator(orchestrator)
            .with_policy_repo(policy_repo),
    );

    let bin_sha = "1".repeat(64);
    let it_sha = "2".repeat(64);
    let commit_sha = "a".repeat(40);

    // 1. Canonical digest-only request succeeds with zero deprecation warnings.
    let digest_only = serde_json::json!({
        "repo": "LMA1980/example-service",
        "service": "example-service",
        "git_commit": commit_sha,
        "binary_digest": bin_sha,
        "it_archive_digest": it_sha,
        "bundle_id": "bundle-clean-1",
        "wait": true
    });
    let (status, body) = post_api(app.clone(), "/api/cd/deploy", &digest_only.to_string()).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let resp: DeployTriggerResponse = serde_json::from_value(body).unwrap();
    assert!(resp.accepted);
    assert_eq!(resp.service, "example-service");
    assert_eq!(resp.target_nodes, vec!["node-a", "worker-riscv64"]);
    assert_eq!(resp.promoted_nodes, vec!["node-a", "worker-riscv64"]);

    let plans = agent.plans.lock().await.clone();
    assert_eq!(plans.len(), 2);
    let plan_a = plans[0].1.as_ref().expect("node-a plan");
    assert_eq!(plan_a.node_id, "node-a");
    assert_eq!(plan_a.it_archive_digest.as_deref(), Some(it_sha.as_str()));
    assert_eq!(plan_a.bundle_id.as_deref(), Some("bundle-clean-1"));
    assert_eq!(plan_a.scenarios.len(), 1);
    assert_eq!(plan_a.scenarios[0].name, "smoke_example_service_node_a");

    let plan_rv = plans[1].1.as_ref().expect("worker-riscv64 plan");
    assert_eq!(plan_rv.node_id, "worker-riscv64");
    assert_eq!(plan_rv.scenarios.len(), 1);
    assert_eq!(
        plan_rv.scenarios[0].name,
        "smoke_example_service_worker_riscv64"
    );
    assert!(
        sink.recorded_logs()
            .await
            .iter()
            .all(|l| !l.body.contains("legacy_manifest_fallback")),
        "digest-only request must not emit legacy_manifest_fallback"
    );

    // 2. Caller attempts to override target_nodes and integration_tests via manifest_yaml.
    agent.plans.lock().await.clear();
    let bin_sha_2 = "3".repeat(64);
    let override_attempt = serde_json::json!({
        "repo": "LMA1980/example-service",
        "service": "example-service",
        "git_commit": commit_sha,
        "binary_digest": bin_sha_2,
        "it_archive_digest": it_sha,
        "manifest_yaml": "version: \"1\"\nservice: \"example-service\"\ntarget_nodes: [\"untrusted-override-node\"]\nintegration_tests: [\"fake_noop\"]\n",
        "wait": true
    });
    let (status, body) = post_api(app, "/api/cd/deploy", &override_attempt.to_string()).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let resp2: DeployTriggerResponse = serde_json::from_value(body).unwrap();
    assert_eq!(
        resp2.target_nodes,
        vec!["node-a", "worker-riscv64"],
        "caller-supplied target_nodes must never override verified policy repo"
    );
    let plans2 = agent.plans.lock().await.clone();
    assert_eq!(
        plans2[0].1.as_ref().unwrap().selected_tests,
        vec!["systemd_unit_active", "smoke_example_service"],
        "caller-supplied integration_tests must never override verified policy repo"
    );

    let logs = sink.recorded_logs().await;
    assert!(
        logs.iter().any(|l| {
            l.severity_text == "WARN"
                && l.body.contains("legacy_manifest_fallback")
                && l.attributes_json.contains("\"legacy_manifest_fallback\"")
                && l.attributes_json.contains("\"manifest_yaml\"")
        }),
        "expected legacy_manifest_fallback warning log, got {logs:?}"
    );
}

#[tokio::test]
async fn test_preflight_validation_status_codes_and_unsigned_policy_fail_closed() {
    let fixture =
        TestPolicyFixture::create("node-a.cluster.internal", "worker-riscv64.cluster.internal");
    let sink = Arc::new(RecordingCdTelemetrySink::new());
    let policy_repo = fixture.policy_repo(sink.clone());
    let store = Arc::new(CdStateStore::default());
    let coordinator = Arc::new(LeaseCoordinator::new());
    let agent = Arc::new(RecordingAgent::default());
    let regist = Arc::new(RecordingRegist::default());

    let tainted_sha = "9".repeat(64);
    regist.taints.lock().await.push(tainted_sha.clone());

    let orchestrator = Arc::new(
        DeploymentOrchestrator::new(coordinator.clone(), None, agent, regist)
            .with_cd_state(store.clone())
            .with_telemetry_sink(sink.clone())
            .with_policy_repo(policy_repo.clone()),
    );
    let app = router(
        CdApiState::new(store, Some(API_TOKEN.into()))
            .with_orchestrator(orchestrator)
            .with_policy_repo(policy_repo),
    );

    let good_bin = "4".repeat(64);
    let good_it = "5".repeat(64);
    let good_commit = "b".repeat(40);

    // 400 digest_mismatch
    let (s, j) = post_api(
        app.clone(),
        "/api/cd/deploy",
        &serde_json::json!({
            "service": "example-service",
            "git_commit": good_commit,
            "binary_digest": good_bin,
            "artifact_sha256": "6".repeat(64),
            "it_archive_digest": good_it
        })
        .to_string(),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(j["error"], "digest_mismatch");

    // 400 invalid_digest
    let (s, j) = post_api(
        app.clone(),
        "/api/cd/deploy",
        &serde_json::json!({
            "service": "example-service",
            "git_commit": good_commit,
            "binary_digest": "short-not-sha256",
            "it_archive_digest": good_it
        })
        .to_string(),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(j["error"], "invalid_digest");

    // 400 invalid_service (path traversal)
    let (s, j) = post_api(
        app.clone(),
        "/api/cd/deploy",
        &serde_json::json!({
            "service": "../etc/passwd",
            "git_commit": good_commit,
            "binary_digest": good_bin,
            "it_archive_digest": good_it
        })
        .to_string(),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(j["error"], "invalid_service");

    // 400 invalid_git_commit
    let (s, j) = post_api(
        app.clone(),
        "/api/cd/deploy",
        &serde_json::json!({
            "service": "example-service",
            "git_commit": "xyz",
            "binary_digest": good_bin,
            "it_archive_digest": good_it
        })
        .to_string(),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(j["error"], "invalid_git_commit");

    // 400 invalid_it_archive_digest (missing when required by scenarios[])
    let (s, j) = post_api(
        app.clone(),
        "/api/cd/deploy",
        &serde_json::json!({
            "service": "example-service",
            "git_commit": good_commit,
            "binary_digest": good_bin
        })
        .to_string(),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(j["error"], "invalid_it_archive_digest");

    // 404 service_contract_not_found
    let (s, j) = post_api(
        app.clone(),
        "/api/cd/deploy",
        &serde_json::json!({
            "service": "unknown-service",
            "git_commit": good_commit,
            "binary_digest": good_bin,
            "it_archive_digest": good_it
        })
        .to_string(),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(j["error"], "service_contract_not_found");

    // 409 artifact_tainted
    let (s, j) = post_api(
        app.clone(),
        "/api/cd/deploy",
        &serde_json::json!({
            "service": "example-service",
            "git_commit": good_commit,
            "binary_digest": tainted_sha,
            "it_archive_digest": good_it
        })
        .to_string(),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(j["error"], "artifact_tainted");

    // POST /api/cd/policy/refresh succeeds while signed.
    let (s, j) = post_api(app.clone(), "/api/cd/policy/refresh", "{}").await;
    assert_eq!(s, StatusCode::OK, "body: {j}");
    assert_eq!(j["refreshed"], true);

    // Introduce an unsigned commit -> both deploy and refresh fail closed with 503.
    let modified =
        sample_service_yaml().replace("bake_window_seconds: 60", "bake_window_seconds: 90");
    fixture.commit_files(
        &sample_nodes_yaml("node-a.cluster.internal", "worker-riscv64.cluster.internal"),
        &modified,
        false,
        "unsigned tampered tip",
    );

    let (s, j) = post_api(
        app.clone(),
        "/api/cd/deploy",
        &serde_json::json!({
            "service": "example-service",
            "git_commit": good_commit,
            "binary_digest": good_bin,
            "it_archive_digest": good_it
        })
        .to_string(),
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(j["error"], "deploy_repo_unverified");

    let (s, j) = post_api(app, "/api/cd/policy/refresh", "{}").await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(j["error"], "deploy_repo_unverified");

    assert!(
        coordinator.list_leases().await.is_empty(),
        "zero leases may be acquired on pre-flight failures"
    );
    assert!(sink
        .recorded_metrics()
        .await
        .iter()
        .any(|m| m.metric_name == METRIC_POLICY_VERIFY_FAILED));
}

/// Spawns a real TCP mock agent simulating either a `0.3.0` agent (stores `0x0D`, emits `0x0E`)
/// or a `0.2.x` legacy agent (skips unknown `0x0D` without blocking, executes `0x06`).
async fn spawn_wire_mock_agent(
    is_v0_3: bool,
    it_passes: bool,
) -> (
    u16,
    Arc<Mutex<Vec<u16>>>,
    Arc<Mutex<Vec<ScenarioExecutionPlan>>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen_msg_types = Arc::new(Mutex::new(Vec::new()));
    let received_plans = Arc::new(Mutex::new(Vec::new()));

    let seen_clone = seen_msg_types.clone();
    let plans_clone = received_plans.clone();

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let seen = seen_clone.clone();
            let plans = plans_clone.clone();
            tokio::spawn(async move {
                let fory = create_fory_runtime().unwrap();
                let mut stored_plan: Option<ScenarioExecutionPlan> = None;
                loop {
                    let (hdr, payload) = match read_frame(&mut stream).await {
                        Ok(f) => f,
                        Err(_) => return,
                    };
                    seen.lock().await.push(hdr.msg_type);
                    match hdr.msg_type {
                        MSG_TYPE_STAGE_DEPLOY_REQ => {
                            let req: StageDeploymentRequest = fory.deserialize(&payload).unwrap();
                            let resp = StageDeploymentResponse {
                                deployment_id: req.deployment_id,
                                target_slot: req.target_slot,
                                btrfs_subvolume_path: "/srv/mucd/example-service/@b".into(),
                                staged_ok: true,
                                error_message: None,
                            };
                            let bytes = fory.serialize(&resp).unwrap();
                            let resp_hdr = IpcHeader::new(
                                MSG_TYPE_STAGE_DEPLOY_RESP,
                                bytes.len() as u32,
                                0,
                                hdr.sequence,
                            );
                            let _ = write_frame(&mut stream, &resp_hdr, &bytes).await;
                            return;
                        }
                        MSG_TYPE_SCENARIO_PLAN => {
                            if is_v0_3 {
                                let plan: ScenarioExecutionPlan =
                                    fory.deserialize(&payload).unwrap();
                                let ack = ScenarioPlanAck {
                                    deployment_id: plan.deployment_id.clone(),
                                    lease_id: plan.lease_id.clone(),
                                    accepted: true,
                                    rejection_reason: None,
                                };
                                plans.lock().await.push(plan.clone());
                                stored_plan = Some(plan);
                                let ack_bytes = fory.serialize(&ack).unwrap();
                                let ack_hdr = IpcHeader::new(
                                    MSG_TYPE_SCENARIO_PLAN_ACK,
                                    ack_bytes.len() as u32,
                                    0,
                                    hdr.sequence,
                                );
                                let _ = write_frame(&mut stream, &ack_hdr, &ack_bytes).await;
                            }
                            // 0.2.x skips unknown 0x0D cleanly and reads the next frame (0x06).
                        }
                        MSG_TYPE_SLOT_SWAP => {
                            let cmd: SlotSwapCommand = fory.deserialize(&payload).unwrap();
                            let executed = stored_plan
                                .as_ref()
                                .map(|p| p.selected_tests.clone())
                                .unwrap_or_else(|| vec!["systemd_unit_active".into()]);
                            let prog = IntegrationTestProgress {
                                deployment_id: cmd.deployment_id.clone(),
                                test_name: executed[0].clone(),
                                critical: true,
                                state: if it_passes {
                                    TestState::Passed
                                } else {
                                    TestState::Failed
                                },
                                duration_ms: 25,
                                timestamp_epoch_ms: 1_700_000_000_000,
                            };
                            let prog_bytes = fory.serialize(&prog).unwrap();
                            let _ = write_frame(
                                &mut stream,
                                &IpcHeader::new(
                                    MSG_TYPE_IT_PROGRESS,
                                    prog_bytes.len() as u32,
                                    0,
                                    10,
                                ),
                                &prog_bytes,
                            )
                            .await;

                            let report = IntegrationTestReport {
                                deployment_id: cmd.deployment_id,
                                service_name: cmd.service_name,
                                artifact_sha256: "a".repeat(64),
                                executed_tests: executed.clone(),
                                passed: it_passes,
                                failed_tests: if it_passes {
                                    Vec::new()
                                } else {
                                    vec!["smoke_example_service".into()]
                                },
                                duration_ms: 40,
                                log_excerpt: (!it_passes).then(|| {
                                    "UnknownIntegrationTests: smoke_example_service".into()
                                }),
                            };
                            let rep_bytes = fory.serialize(&report).unwrap();
                            let _ = write_frame(
                                &mut stream,
                                &IpcHeader::new(MSG_TYPE_IT_REPORT, rep_bytes.len() as u32, 0, 11),
                                &rep_bytes,
                            )
                            .await;
                            return;
                        }
                        MSG_TYPE_ROLLBACK => {
                            return;
                        }
                        _ => {}
                    }
                }
            });
        }
    });

    (port, seen_msg_types, received_plans)
}

#[tokio::test]
async fn test_wire_scenario_plan_transmission_v0_3_and_v0_2_compat_and_fail_closed_rollback() {
    let fixture = TestPolicyFixture::create("127.0.0.1", "127.0.0.1");
    let sink = Arc::new(RecordingCdTelemetrySink::new());
    let policy_repo = fixture.policy_repo(sink);
    let it_sha = "c".repeat(64);
    let bin_sha = "d".repeat(64);

    // 1. 0.3.0 agent receives 0x0D immediately before 0x06, sends advisory 0x0E, promotes cleanly.
    let (port_v3, seen_v3, plans_v3) = spawn_wire_mock_agent(true, true).await;
    let store_v3 = Arc::new(CdStateStore::default());
    let agent_v3 = Arc::new(
        IpcAgentClient::new(port_v3)
            .with_progress_sink(store_v3.clone())
            .with_policy_repo(policy_repo.clone()),
    );
    let regist_v3 = Arc::new(RecordingRegist::default());
    let orch_v3 = DeploymentOrchestrator::new(
        Arc::new(LeaseCoordinator::new()),
        None,
        agent_v3,
        regist_v3.clone(),
    )
    .with_cd_state(store_v3)
    .with_policy_repo(policy_repo.clone());

    let snap = policy_repo
        .pin_deployment_snapshot("rollout-v3", "example-service", Some(&it_sha), Some("b-3"))
        .await
        .unwrap();
    let outcomes = orch_v3
        .orchestrate_rollout_with_snapshot(
            snap.clone(),
            &bin_sha,
            Some("LMA1980/example-service"),
            None,
        )
        .await
        .unwrap();
    assert_eq!(outcomes.len(), 2);
    assert!(outcomes.iter().all(|o| o.is_promoted()));

    let frames = seen_v3.lock().await.clone();
    assert!(
        frames
            .windows(2)
            .any(|w| w == [MSG_TYPE_SCENARIO_PLAN, MSG_TYPE_SLOT_SWAP]),
        "expected 0x0D immediately followed by 0x06 on swap stream, saw {frames:x?}"
    );
    let recv_plans = plans_v3.lock().await.clone();
    assert_eq!(recv_plans.len(), 2);
    assert_eq!(
        recv_plans[0].it_archive_digest.as_deref(),
        Some(it_sha.as_str())
    );
    assert_eq!(recv_plans[0].policy_commit_sha, snap.policy_commit_sha);
    assert!(!recv_plans[0].lease_id.is_empty());

    // 2. 0.2.x agent ignores 0x0D without deadlock and completes 0x06 + 0x0C + 0x08.
    let (port_v2, seen_v2, plans_v2) = spawn_wire_mock_agent(false, true).await;
    let agent_v2 = Arc::new(IpcAgentClient::new(port_v2).with_policy_repo(policy_repo.clone()));
    let orch_v2 = DeploymentOrchestrator::new(
        Arc::new(LeaseCoordinator::new()),
        None,
        agent_v2,
        Arc::new(RecordingRegist::default()),
    )
    .with_policy_repo(policy_repo.clone());
    let outcomes_v2 = orch_v2
        .orchestrate_rollout_with_snapshot(
            snap.clone(),
            &bin_sha,
            Some("LMA1980/example-service"),
            None,
        )
        .await
        .unwrap();
    assert_eq!(outcomes_v2.len(), 2);
    assert!(outcomes_v2.iter().all(|o| o.is_promoted()));
    assert!(plans_v2.lock().await.is_empty());
    assert!(seen_v2
        .lock()
        .await
        .windows(2)
        .any(|w| w == [MSG_TYPE_SCENARIO_PLAN, MSG_TYPE_SLOT_SWAP]));

    // 3. Fail-closed missing test report rolls back and taints artifact digest.
    let (port_fail, seen_fail, _) = spawn_wire_mock_agent(true, false).await;
    let regist_fail = Arc::new(RecordingRegist::default());
    let agent_fail = Arc::new(IpcAgentClient::new(port_fail).with_policy_repo(policy_repo.clone()));
    let orch_fail = DeploymentOrchestrator::new(
        Arc::new(LeaseCoordinator::new()),
        None,
        agent_fail,
        regist_fail.clone(),
    )
    .with_policy_repo(policy_repo);
    let fail_sha = "e".repeat(64);
    let outcomes_fail = orch_fail
        .orchestrate_rollout_with_snapshot(snap, &fail_sha, Some("LMA1980/example-service"), None)
        .await
        .unwrap();
    assert_eq!(outcomes_fail.len(), 1);
    assert!(outcomes_fail[0].is_rolled_back());
    assert_eq!(regist_fail.taints.lock().await.as_slice(), &[fail_sha]);
    // Mock server reads the rollback frame asynchronously after IpcAgentClient::rollback flushes.
    let mut saw_rollback = false;
    for _ in 0..40 {
        if seen_fail.lock().await.contains(&MSG_TYPE_ROLLBACK) {
            saw_rollback = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        saw_rollback,
        "expected mock agent to receive MSG_TYPE_ROLLBACK"
    );

    // 4. Verify dispatch_agent_frame handles 0x0E cleanly (valid & malformed advisory).
    let fory = create_fory_runtime().unwrap();
    let ack = ScenarioPlanAck {
        deployment_id: "dep-1".into(),
        lease_id: "lease-1".into(),
        accepted: true,
        rejection_reason: None,
    };
    let ack_bytes = fory.serialize(&ack).unwrap();
    assert_eq!(
        dispatch_agent_frame(&fory, MSG_TYPE_SCENARIO_PLAN_ACK, &ack_bytes, None).unwrap(),
        AgentFrame::ScenarioAck(ack)
    );
    assert_eq!(
        dispatch_agent_frame(&fory, MSG_TYPE_SCENARIO_PLAN_ACK, b"corrupt", None).unwrap(),
        AgentFrame::Ignored(MSG_TYPE_SCENARIO_PLAN_ACK)
    );
}

#[test]
fn test_privacy_fixture_helper_clean_path_check() {
    assert!(!Path::new("/etc/mu-cd-canary/tls/ca.crt")
        .as_os_str()
        .is_empty());
}
