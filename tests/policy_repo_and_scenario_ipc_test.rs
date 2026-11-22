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
    staged: Mutex<Vec<(String, String)>>,
    plans: Mutex<Vec<(String, Option<ScenarioExecutionPlan>)>>,
    rollbacks: Mutex<Vec<(String, DeploymentSlot, String)>>,
    fail_node: Option<String>,
}

#[async_trait]
impl AgentIpcClient for RecordingAgent {
    async fn stage_deployment(
        &self,
        node_id: &str,
        req: &StageDeploymentRequest,
    ) -> Result<StageDeploymentResponse, OrchestratorError> {
        self.staged
            .lock()
            .await
            .push((node_id.to_string(), req.artifact_sha256.clone()));
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
        self.rollbacks.lock().await.push((
            node_id.to_string(),
            cmd.restore_slot,
            cmd.failed_artifact_sha256.clone(),
        ));
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

fn run_git_isolated(repo_dir: &Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .args(["-C", repo_dir.to_str().unwrap()])
        .args(args)
        .output()
        .expect("spawn isolated git");
    assert!(
        out.status.success(),
        "git {args:?} failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[tokio::test]
async fn test_two_parent_merge_ssh_verification_and_fail_closed_cases() {
    use mu_cd_controller::error::PolicyRepoError;

    // Case 1: Clean 2-parent PR merge (gh pr merge --merge style) where P1 is ancestor of
    // SSH-signed P2 and HEAD^{tree} == P2^{tree} -> PASS (even if P1 itself was unsigned).
    let fixture_clean =
        TestPolicyFixture::create("node-a.cluster.internal", "worker-riscv64.cluster.internal");
    let nodes_yaml =
        sample_nodes_yaml("node-a.cluster.internal", "worker-riscv64.cluster.internal");
    // Simulate a prior unsigned base commit on main (e.g. a legacy squash commit) as P1.
    let p1_yaml =
        sample_service_yaml().replace("bake_window_seconds: 60", "bake_window_seconds: 65");
    fixture_clean.commit_files(&nodes_yaml, &p1_yaml, false, "prior base commit P1");
    let sink_clean = Arc::new(RecordingCdTelemetrySink::new());
    let repo_clean = fixture_clean.policy_repo(sink_clean);
    assert!(
        matches!(
            repo_clean.refresh_and_verify().await,
            Err(PolicyRepoError::Unverified(_))
        ),
        "single-parent unsigned P1 must fail closed before clean merge"
    );

    // Branch from P1, add SSH-signed P2, merge into main with --no-ff (unsigned 2-parent merge).
    run_git_isolated(
        &fixture_clean.repo_dir,
        &["checkout", "-b", "feat/pr-merge"],
    );
    let p2_yaml =
        sample_service_yaml().replace("bake_window_seconds: 60", "bake_window_seconds: 75");
    fixture_clean.commit_files(&nodes_yaml, &p2_yaml, true, "signed PR commit P2");
    run_git_isolated(&fixture_clean.repo_dir, &["checkout", "main"]);
    run_git_isolated(
        &fixture_clean.repo_dir,
        &[
            "merge",
            "--no-ff",
            "-m",
            "Merge pull request #12",
            "feat/pr-merge",
        ],
    );

    let verified_summary = repo_clean
        .refresh_and_verify()
        .await
        .expect("clean 2-parent tree-equivalent merge of SSH-signed P2 must PASS");
    let snap = repo_clean
        .pin_deployment_snapshot(
            "dep-merge-ok",
            "example-service",
            Some(&"a".repeat(64)),
            None,
        )
        .await
        .expect("pin verified snapshot");
    assert_eq!(snap.policy_commit_sha, verified_summary.policy_commit_sha);
    assert_eq!(snap.service_contract.bake_window_seconds, 75);

    // Case 1b: GitHub `gh pr merge --merge` style 2-parent merge commit carrying a PGP signature
    // header (`web-flow`) with P1 ancestor of SSH-signed P2 and HEAD^{tree} == P2^{tree} ->
    // direct SSH check rejects the PGP header, then step-2 fallback verifies P2's SSH signature.
    let p1_sha = run_git_isolated(&fixture_clean.repo_dir, &["rev-parse", "HEAD^1"]);
    let p2_sha = run_git_isolated(&fixture_clean.repo_dir, &["rev-parse", "HEAD^2"]);
    let p2_tree = run_git_isolated(&fixture_clean.repo_dir, &["rev-parse", "HEAD^2^{tree}"]);
    let gh_merge_raw = format!(
        "tree {p2_tree}\nparent {p1_sha}\nparent {p2_sha}\nauthor GitHub <noreply@github.com> 1795330000 +0000\ncommitter GitHub <noreply@github.com> 1795330000 +0000\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n iQIzBAABCAAdFiEEsyntheticGitHubWebFlowMergeSig==\n -----END PGP SIGNATURE-----\n\nMerge pull request #12 from org/feat/pr-merge\n"
    );
    let mut gh_merge_child = std::process::Command::new("git")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .args([
            "-C",
            fixture_clean.repo_dir.to_str().unwrap(),
            "hash-object",
            "-t",
            "commit",
            "-w",
            "--stdin",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn git hash-object");
    {
        use std::io::Write;
        gh_merge_child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(gh_merge_raw.as_bytes())
            .unwrap();
    }
    let gh_merge_out = gh_merge_child.wait_with_output().unwrap();
    assert!(gh_merge_out.status.success());
    let gh_merge_sha = String::from_utf8_lossy(&gh_merge_out.stdout)
        .trim()
        .to_string();
    run_git_isolated(
        &fixture_clean.repo_dir,
        &["update-ref", "refs/heads/main", &gh_merge_sha],
    );
    let gh_verified = repo_clean
        .refresh_and_verify()
        .await
        .expect("PGP-armored 2-parent merge commit with tree-equivalent SSH-signed P2 must PASS");
    assert_eq!(gh_verified.policy_commit_sha, gh_merge_sha);

    // Case 2: Tampered 2-parent merge (HEAD^{tree} != P2^{tree}) -> FAIL CLOSED (503).
    let fixture_tamper =
        TestPolicyFixture::create("node-a.cluster.internal", "worker-riscv64.cluster.internal");
    run_git_isolated(&fixture_tamper.repo_dir, &["checkout", "-b", "feat/tamper"]);
    let signed_yaml =
        sample_service_yaml().replace("bake_window_seconds: 60", "bake_window_seconds: 80");
    fixture_tamper.commit_files(&nodes_yaml, &signed_yaml, true, "signed P2 before tamper");
    run_git_isolated(&fixture_tamper.repo_dir, &["checkout", "main"]);
    run_git_isolated(
        &fixture_tamper.repo_dir,
        &["merge", "--no-ff", "--no-commit", "feat/tamper"],
    );
    let tampered_yaml =
        sample_service_yaml().replace("bake_window_seconds: 60", "bake_window_seconds: 999");
    std::fs::write(
        fixture_tamper
            .repo_dir
            .join("contracts/services/example-service.yml"),
        &tampered_yaml,
    )
    .unwrap();
    run_git_isolated(&fixture_tamper.repo_dir, &["add", "."]);
    run_git_isolated(
        &fixture_tamper.repo_dir,
        &["commit", "-m", "tampered 2-parent merge"],
    );
    let repo_tamper = fixture_tamper.policy_repo(Arc::new(RecordingCdTelemetrySink::new()));
    let tamper_err = repo_tamper.refresh_and_verify().await.unwrap_err();
    assert!(
        matches!(tamper_err, PolicyRepoError::Unverified(ref msg) if msg.contains("tree")),
        "tampered 2-parent merge must fail closed on tree mismatch, got: {tamper_err}"
    );

    // Case 3a: Clean 2-parent merge whose P2 is unsigned -> FAIL CLOSED.
    let fixture_unsigned_p2 =
        TestPolicyFixture::create("node-a.cluster.internal", "worker-riscv64.cluster.internal");
    run_git_isolated(
        &fixture_unsigned_p2.repo_dir,
        &["checkout", "-b", "feat/unsigned-p2"],
    );
    let unsigned_p2_yaml =
        sample_service_yaml().replace("bake_window_seconds: 60", "bake_window_seconds: 85");
    fixture_unsigned_p2.commit_files(&nodes_yaml, &unsigned_p2_yaml, false, "unsigned P2");
    run_git_isolated(&fixture_unsigned_p2.repo_dir, &["checkout", "main"]);
    run_git_isolated(
        &fixture_unsigned_p2.repo_dir,
        &[
            "merge",
            "--no-ff",
            "-m",
            "merge unsigned P2",
            "feat/unsigned-p2",
        ],
    );
    let repo_unsigned_p2 =
        fixture_unsigned_p2.policy_repo(Arc::new(RecordingCdTelemetrySink::new()));
    assert!(
        matches!(
            repo_unsigned_p2.refresh_and_verify().await,
            Err(PolicyRepoError::Unverified(_))
        ),
        "2-parent merge with unsigned P2 must fail closed"
    );

    // Case 3b: Non-ancestor P2 (main diverged with another commit P1' before merge) -> FAIL CLOSED.
    let fixture_diverged =
        TestPolicyFixture::create("node-a.cluster.internal", "worker-riscv64.cluster.internal");
    run_git_isolated(
        &fixture_diverged.repo_dir,
        &["checkout", "-b", "feat/diverged-p2"],
    );
    let diverged_p2_yaml =
        sample_service_yaml().replace("bake_window_seconds: 60", "bake_window_seconds: 90");
    fixture_diverged.commit_files(&nodes_yaml, &diverged_p2_yaml, true, "signed diverged P2");
    run_git_isolated(&fixture_diverged.repo_dir, &["checkout", "main"]);
    let main_diverge_yaml =
        sample_service_yaml().replace("bake_window_seconds: 60", "bake_window_seconds: 95");
    fixture_diverged.commit_files(&nodes_yaml, &main_diverge_yaml, true, "main advanced P1'");
    // Force merge commit to match P2's tree via -X theirs so only ancestry distinguishes it.
    run_git_isolated(
        &fixture_diverged.repo_dir,
        &[
            "merge",
            "--no-ff",
            "-X",
            "theirs",
            "-m",
            "merge non-ancestor P2",
            "feat/diverged-p2",
        ],
    );
    let repo_diverged = fixture_diverged.policy_repo(Arc::new(RecordingCdTelemetrySink::new()));
    let diverged_err = repo_diverged.refresh_and_verify().await.unwrap_err();
    assert!(
        matches!(diverged_err, PolicyRepoError::Unverified(ref msg) if msg.contains("ancestor")),
        "2-parent merge where P1 is not ancestor of P2 must fail closed, got: {diverged_err}"
    );

    // Case 3c: 3-parent octopus merge -> FAIL CLOSED (>2 parents).
    let fixture_octopus =
        TestPolicyFixture::create("node-a.cluster.internal", "worker-riscv64.cluster.internal");
    run_git_isolated(&fixture_octopus.repo_dir, &["checkout", "-b", "feat/oct-1"]);
    std::fs::write(fixture_octopus.repo_dir.join("NOTE_A.txt"), "branch a\n").unwrap();
    run_git_isolated(&fixture_octopus.repo_dir, &["add", "NOTE_A.txt"]);
    run_git_isolated(
        &fixture_octopus.repo_dir,
        &[
            "-c",
            "gpg.format=ssh",
            "-c",
            &format!("user.signingkey={}", fixture_octopus.signing_key.display()),
            "commit",
            "-S",
            "-m",
            "signed oct branch 1",
        ],
    );
    run_git_isolated(&fixture_octopus.repo_dir, &["checkout", "main"]);
    run_git_isolated(&fixture_octopus.repo_dir, &["checkout", "-b", "feat/oct-2"]);
    std::fs::write(fixture_octopus.repo_dir.join("NOTE_B.txt"), "branch b\n").unwrap();
    run_git_isolated(&fixture_octopus.repo_dir, &["add", "NOTE_B.txt"]);
    run_git_isolated(
        &fixture_octopus.repo_dir,
        &[
            "-c",
            "gpg.format=ssh",
            "-c",
            &format!("user.signingkey={}", fixture_octopus.signing_key.display()),
            "commit",
            "-S",
            "-m",
            "signed oct branch 2",
        ],
    );
    run_git_isolated(&fixture_octopus.repo_dir, &["checkout", "main"]);
    run_git_isolated(
        &fixture_octopus.repo_dir,
        &[
            "merge",
            "--no-ff",
            "-m",
            "octopus 3-parent merge",
            "feat/oct-1",
            "feat/oct-2",
        ],
    );
    let repo_octopus = fixture_octopus.policy_repo(Arc::new(RecordingCdTelemetrySink::new()));
    let oct_err = repo_octopus.refresh_and_verify().await.unwrap_err();
    assert!(
        matches!(oct_err, PolicyRepoError::Unverified(ref msg) if msg.contains("3 parent")),
        "3-parent octopus merge must fail closed, got: {oct_err}"
    );

    // Case 4: Single-parent PGP-only commit (simulating GitHub web-flow squash signature)
    // fails closed with HTTP 503 deploy_repo_unverified.
    let fixture_pgp =
        TestPolicyFixture::create("node-a.cluster.internal", "worker-riscv64.cluster.internal");
    let tree_sha = run_git_isolated(&fixture_pgp.repo_dir, &["rev-parse", "HEAD^{tree}"]);
    let parent_sha = run_git_isolated(&fixture_pgp.repo_dir, &["rev-parse", "HEAD"]);
    let pgp_commit_raw = format!(
        "tree {tree_sha}\nparent {parent_sha}\nauthor GitHub <noreply@github.com> 1795330000 +0000\ncommitter GitHub <noreply@github.com> 1795330000 +0000\ngpgsig -----BEGIN PGP SIGNATURE-----\n \n iQIzBAABCAAdFiEEsyntheticPGPsignaturePayloadOnly==\n -----END PGP SIGNATURE-----\n\nsynthetic pgp-only squash commit\n"
    );
    let mut hash_child = std::process::Command::new("git")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .args([
            "-C",
            fixture_pgp.repo_dir.to_str().unwrap(),
            "hash-object",
            "-t",
            "commit",
            "-w",
            "--stdin",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn git hash-object");
    {
        use std::io::Write;
        hash_child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(pgp_commit_raw.as_bytes())
            .unwrap();
    }
    let hash_out = hash_child.wait_with_output().unwrap();
    assert!(hash_out.status.success());
    let pgp_sha = String::from_utf8_lossy(&hash_out.stdout).trim().to_string();
    run_git_isolated(
        &fixture_pgp.repo_dir,
        &["update-ref", "refs/heads/main", &pgp_sha],
    );

    let sink_pgp = Arc::new(RecordingCdTelemetrySink::new());
    let repo_pgp = fixture_pgp.policy_repo(sink_pgp);
    let store = Arc::new(CdStateStore::default());
    let orch = Arc::new(
        DeploymentOrchestrator::new(
            Arc::new(LeaseCoordinator::new()),
            None,
            Arc::new(RecordingAgent::default()),
            Arc::new(RecordingRegist::default()),
        )
        .with_cd_state(store.clone())
        .with_policy_repo(repo_pgp.clone()),
    );
    let app = router(
        CdApiState::new(store, Some(API_TOKEN.into()))
            .with_orchestrator(orch)
            .with_policy_repo(repo_pgp),
    );
    let (status, json) = post_api(
        app,
        "/api/cd/deploy",
        &serde_json::json!({
            "service": "example-service",
            "git_commit": "a".repeat(40),
            "binary_digest": "1".repeat(64),
            "it_archive_digest": "2".repeat(64)
        })
        .to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json["error"], "deploy_repo_unverified");
}

#[test]
fn test_privacy_fixture_helper_clean_path_check() {
    assert!(!Path::new("/etc/mu-cd-canary/tls/ca.crt")
        .as_os_str()
        .is_empty());
}

fn create_three_arch_policy_fixture() -> TestPolicyFixture {
    let fixture =
        TestPolicyFixture::create("node-x86.cluster.internal", "node-rv.cluster.internal");
    let nodes_yaml = r#"nodes:
  - node_id: "node-x86"
    arch: "x86_64"
    host: "node-x86.cluster.internal"
    max_memlock_kb: 2097152
    max_slots: 1
  - node_id: "node-arm"
    arch: "aarch64"
    host: "node-arm.cluster.internal"
    max_memlock_kb: 2097152
    max_slots: 1
  - node_id: "node-rv"
    arch: "riscv64gc"
    host: "node-rv.cluster.internal"
    max_memlock_kb: 2097152
    max_slots: 1
"#;
    let multi_arch_service_yaml = r#"version: "2"
service: "example-service"
target_nodes:
  - "node-x86"
  - "node-arm"
  - "node-rv"
lease_ttl_seconds: 180
warmup_timeout_seconds: 15
bake_window_seconds: 60
max_error_logs: 0
max_p99_latency_ms: 250.0
ab_rules:
  auto_rollback_on_critical: true
  snapshot_retention: 3
deployment:
  binary: "example-service"
  install_path: "/usr/local/bin/example-service"
  systemd_unit: "example-service.service"
sandbox_ceiling:
  max_pids: 256
  max_memlock_kb: 65536
integration_tests:
  - "systemd_unit_active"
  - "health_endpoint_ready"
  - "smoke_example_service"
scenarios:
  - name: "smoke_example_service"
    test_binary: "smoke_example_service"
    target_url: "https://127.0.0.1:8446/health"
    restricted_cidrs:
      - "127.0.0.1/32"
    read_only: true
    timeout_secs: 15
"#;
    let controller_service_yaml = r#"version: "2"
service: "mu-cd-controller"
target_nodes:
  - "node-x86"
lease_ttl_seconds: 180
warmup_timeout_seconds: 15
bake_window_seconds: 60
max_error_logs: 0
max_p99_latency_ms: 250.0
ab_rules:
  auto_rollback_on_critical: true
  snapshot_retention: 3
deployment:
  binary: "mu-cd-controller"
  install_path: "/usr/local/bin/mu-cd-controller"
  systemd_unit: "muconde-controller.service"
  self_upgrade_guard: true
sandbox_ceiling:
  max_pids: 256
  max_memlock_kb: 65536
integration_tests:
  - "systemd_unit_active"
  - "health_endpoint_ready"
  - "smoke_mu_cd_controller"
scenarios:
  - name: "smoke_mu_cd_controller"
    test_binary: "smoke_mu_cd_controller"
    target_url: "https://127.0.0.1:8445/health"
    restricted_cidrs:
      - "127.0.0.1/32"
    read_only: true
    timeout_secs: 15
"#;
    std::fs::write(
        fixture
            .repo_dir
            .join("contracts/services/mu-cd-controller.yml"),
        controller_service_yaml,
    )
    .unwrap();
    fixture.commit_files(
        nodes_yaml,
        multi_arch_service_yaml,
        true,
        "add 3-arch cluster inventory and mu-cd-controller contract",
    );
    fixture
}

#[tokio::test]
async fn test_multi_arch_rollout_3_arch_success_and_per_node_digests_and_fail_closed_checks() {
    let fixture = create_three_arch_policy_fixture();
    let policy_repo = fixture.policy_repo(Arc::new(RecordingCdTelemetrySink::new()));

    let bin_x86 = "a".repeat(64);
    let bin_arm = "b".repeat(64);
    let bin_rv = "c".repeat(64);
    let it_x86 = "1".repeat(64);
    let it_arm = "2".repeat(64);
    let it_rv = "3".repeat(64);

    // 1. 3-arch rollout success using aliases (`arm64` -> `aarch64`, `riscv64` -> `riscv64gc`)
    let store = Arc::new(CdStateStore::default());
    let agent = Arc::new(RecordingAgent::default());
    let regist = Arc::new(RecordingRegist::default());
    let orch = Arc::new(
        DeploymentOrchestrator::new(
            Arc::new(LeaseCoordinator::new()),
            None,
            agent.clone(),
            regist.clone(),
        )
        .with_cd_state(store.clone())
        .with_policy_repo(policy_repo.clone()),
    );
    let app = router(
        CdApiState::new(store, Some(API_TOKEN.into()))
            .with_orchestrator(orch.clone())
            .with_policy_repo(policy_repo.clone()),
    );

    let (status, json) = post_api(
        app.clone(),
        "/api/cd/deploy",
        &serde_json::json!({
            "repo": "LMA1980/example-service",
            "service": "example-service",
            "git_commit": "0123456789abcdef0123456789abcdef01234567",
            "binary_digests_by_arch": {
                "x86_64": bin_x86,
                "arm64": bin_arm,
                "riscv64": bin_rv
            },
            "it_archive_digests_by_arch": {
                "x86_64": it_x86,
                "aarch64": it_arm,
                "riscv64gc": it_rv
            },
            "wait": true
        })
        .to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "response: {json}");
    assert_eq!(json["accepted"], true);
    assert_eq!(
        json["promoted_nodes"],
        serde_json::json!(["node-x86", "node-arm", "node-rv"])
    );

    assert_eq!(
        agent.staged.lock().await.as_slice(),
        &[
            ("node-x86".to_string(), bin_x86.clone()),
            ("node-arm".to_string(), bin_arm.clone()),
            ("node-rv".to_string(), bin_rv.clone()),
        ]
    );
    let plans = agent.plans.lock().await;
    assert_eq!(plans.len(), 3);
    assert_eq!(
        plans[0].1.as_ref().unwrap().it_archive_digest.as_deref(),
        Some(it_x86.as_str())
    );
    assert_eq!(
        plans[1].1.as_ref().unwrap().it_archive_digest.as_deref(),
        Some(it_arm.as_str())
    );
    assert_eq!(
        plans[2].1.as_ref().unwrap().it_archive_digest.as_deref(),
        Some(it_rv.as_str())
    );
    drop(plans);
    assert_eq!(
        regist.promoted.lock().await.as_slice(),
        &[bin_x86.clone(), bin_arm.clone(), bin_rv.clone()]
    );

    // 2. Missing target node arch fails closed (400) before touching node 1
    let agent_missing = Arc::new(RecordingAgent::default());
    let orch_missing = Arc::new(
        DeploymentOrchestrator::new(
            Arc::new(LeaseCoordinator::new()),
            None,
            agent_missing.clone(),
            Arc::new(RecordingRegist::default()),
        )
        .with_policy_repo(policy_repo.clone()),
    );
    let app_missing = router(
        CdApiState::new(Arc::new(CdStateStore::default()), Some(API_TOKEN.into()))
            .with_orchestrator(orch_missing)
            .with_policy_repo(policy_repo.clone()),
    );
    let (status_m, json_m) = post_api(
        app_missing.clone(),
        "/api/cd/deploy",
        &serde_json::json!({
            "service": "example-service",
            "git_commit": "0123456789abcdef0123456789abcdef01234567",
            "binary_digests_by_arch": {
                "x86_64": bin_x86,
                "aarch64": bin_arm
            },
            "it_archive_digests_by_arch": {
                "x86_64": it_x86,
                "aarch64": it_arm,
                "riscv64gc": it_rv
            },
            "wait": true
        })
        .to_string(),
    )
    .await;
    assert_eq!(status_m, StatusCode::BAD_REQUEST);
    assert_eq!(json_m["error"], "missing_arch_binary_digest");
    assert_eq!(json_m["arch"], "riscv64gc");
    assert!(agent_missing.staged.lock().await.is_empty());

    // Malformed non-64-hex digest in map -> 400
    let (status_bad, json_bad) = post_api(
        app_missing,
        "/api/cd/deploy",
        &serde_json::json!({
            "service": "example-service",
            "git_commit": "0123456789abcdef0123456789abcdef01234567",
            "binary_digests_by_arch": {
                "x86_64": "short",
                "aarch64": bin_arm,
                "riscv64": bin_rv
            },
            "it_archive_digest": it_x86,
            "wait": true
        })
        .to_string(),
    )
    .await;
    assert_eq!(status_bad, StatusCode::BAD_REQUEST);
    assert_eq!(json_bad["error"], "invalid_binary_digests_by_arch");

    // 3. Pre-tainted arch digest refuses rollout (409 Conflict) before touching node 1
    let agent_taint = Arc::new(RecordingAgent::default());
    let regist_taint = Arc::new(RecordingRegist::default());
    regist_taint.taints.lock().await.push(bin_rv.clone());
    let orch_taint = Arc::new(
        DeploymentOrchestrator::new(
            Arc::new(LeaseCoordinator::new()),
            None,
            agent_taint.clone(),
            regist_taint,
        )
        .with_policy_repo(policy_repo.clone()),
    );
    let app_taint = router(
        CdApiState::new(Arc::new(CdStateStore::default()), Some(API_TOKEN.into()))
            .with_orchestrator(orch_taint)
            .with_policy_repo(policy_repo.clone()),
    );
    let (status_t, json_t) = post_api(
        app_taint,
        "/api/cd/deploy",
        &serde_json::json!({
            "service": "example-service",
            "git_commit": "0123456789abcdef0123456789abcdef01234567",
            "binary_digests_by_arch": {
                "x86_64": bin_x86,
                "aarch64": bin_arm,
                "riscv64": bin_rv
            },
            "it_archive_digests_by_arch": {
                "x86_64": it_x86,
                "aarch64": it_arm,
                "riscv64gc": it_rv
            },
            "wait": true
        })
        .to_string(),
    )
    .await;
    assert_eq!(status_t, StatusCode::CONFLICT);
    assert_eq!(json_t["error"], "artifact_tainted");
    assert_eq!(json_t["digest"], bin_rv);
    assert!(
        agent_taint.staged.lock().await.is_empty(),
        "pre-tainted riscv64gc digest must abort rollout before touching node-x86"
    );

    // 4. Mid-rollout failure on node-rv compensates node-arm & node-x86 AND taints ALL 3 digests
    let fail_bin_x86 = "d".repeat(64);
    let fail_bin_arm = "e".repeat(64);
    let fail_bin_rv = "f".repeat(64);
    let agent_mid = Arc::new(RecordingAgent {
        fail_node: Some("node-rv".to_string()),
        ..Default::default()
    });
    let regist_mid = Arc::new(RecordingRegist::default());
    let orch_mid = Arc::new(
        DeploymentOrchestrator::new(
            Arc::new(LeaseCoordinator::new()),
            None,
            agent_mid.clone(),
            regist_mid.clone(),
        )
        .with_policy_repo(policy_repo.clone()),
    );
    let app_mid = router(
        CdApiState::new(Arc::new(CdStateStore::default()), Some(API_TOKEN.into()))
            .with_orchestrator(orch_mid.clone())
            .with_policy_repo(policy_repo),
    );
    let (status_mid, json_mid) = post_api(
        app_mid,
        "/api/cd/deploy",
        &serde_json::json!({
            "service": "example-service",
            "git_commit": "0123456789abcdef0123456789abcdef01234567",
            "binary_digests_by_arch": {
                "x86_64": fail_bin_x86,
                "arm64": fail_bin_arm,
                "riscv64": fail_bin_rv
            },
            "it_archive_digests_by_arch": {
                "x86_64": it_x86,
                "aarch64": it_arm,
                "riscv64gc": it_rv
            },
            "wait": true
        })
        .to_string(),
    )
    .await;
    assert_eq!(status_mid, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json_mid["accepted"], false);
    assert_eq!(
        json_mid["rolled_back_nodes"],
        serde_json::json!(["node-x86", "node-arm", "node-rv"])
    );
    let rbs = agent_mid.rollbacks.lock().await;
    assert_eq!(
        rbs.as_slice(),
        &[
            (
                "node-rv".to_string(),
                DeploymentSlot::SlotA,
                fail_bin_rv.clone()
            ),
            (
                "node-arm".to_string(),
                DeploymentSlot::SlotA,
                fail_bin_arm.clone()
            ),
            (
                "node-x86".to_string(),
                DeploymentSlot::SlotA,
                fail_bin_x86.clone()
            ),
        ]
    );
    drop(rbs);
    let tainted = regist_mid.taints.lock().await;
    for d in [&fail_bin_x86, &fail_bin_arm, &fail_bin_rv] {
        assert!(
            tainted.contains(d),
            "expected multi-arch digest {d} to be tainted in registry, got {tainted:?}"
        );
        assert!(orch_mid.is_digest_tainted(d).await.unwrap());
    }
}

#[tokio::test]
async fn test_controller_self_upgrade_async_202_persists_handoff_before_swap() {
    use mu_cd_controller::orchestrator::{pending_self_upgrade_path, PendingControllerSelfUpgrade};

    struct SlowSwapAgent {
        state_dir: std::path::PathBuf,
        captured: Mutex<Option<PendingControllerSelfUpgrade>>,
        swapped_notify: Arc<tokio::sync::Notify>,
    }
    #[async_trait]
    impl AgentIpcClient for SlowSwapAgent {
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
            let bytes = std::fs::read(pending_self_upgrade_path(&self.state_dir)).unwrap();
            let parsed: PendingControllerSelfUpgrade = serde_json::from_slice(&bytes).unwrap();
            *self.captured.lock().await = Some(parsed);
            self.swapped_notify.notify_one();
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
            Ok(IntegrationTestReport {
                deployment_id: deployment_id.into(),
                service_name: service.into(),
                artifact_sha256: artifact_sha256.into(),
                executed_tests: vec!["smoke_mu_cd_controller".into()],
                passed: true,
                failed_tests: Vec::new(),
                duration_ms: 10,
                log_excerpt: None,
            })
        }
        async fn rollback(
            &self,
            _node_id: &str,
            _cmd: &RollbackCommand,
        ) -> Result<(), OrchestratorError> {
            Ok(())
        }
    }

    let fixture = create_three_arch_policy_fixture();
    let policy_repo = fixture.policy_repo(Arc::new(RecordingCdTelemetrySink::new()));
    let state_tmp = tempfile::tempdir().unwrap();
    let swapped_notify = Arc::new(tokio::sync::Notify::new());
    let agent = Arc::new(SlowSwapAgent {
        state_dir: state_tmp.path().to_path_buf(),
        captured: Mutex::new(None),
        swapped_notify: swapped_notify.clone(),
    });
    let orch = Arc::new(
        DeploymentOrchestrator::new(
            Arc::new(LeaseCoordinator::new()),
            None,
            agent.clone(),
            Arc::new(RecordingRegist::default()),
        )
        .with_policy_repo(policy_repo.clone())
        .with_state_dir(state_tmp.path()),
    );
    let app = router(
        CdApiState::new(Arc::new(CdStateStore::default()), Some(API_TOKEN.into()))
            .with_orchestrator(orch)
            .with_policy_repo(policy_repo),
    );

    let bin_sha = "7".repeat(64);
    let it_sha = "8".repeat(64);
    let (status, json) = post_api(
        app,
        "/api/cd/deploy",
        &serde_json::json!({
            "service": "mu-cd-controller",
            "git_commit": "0123456789abcdef0123456789abcdef01234567",
            "binary_digest": bin_sha,
            "it_archive_digest": it_sha,
            "wait": false
        })
        .to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(json["accepted"], true);
    let dep_id = json["deployment_id"]
        .as_str()
        .expect("202 Accepted must return deployment_id")
        .to_string();
    assert!(dep_id.starts_with("dep-"));

    tokio::time::timeout(Duration::from_secs(5), swapped_notify.notified())
        .await
        .expect("background controller self-upgrade reached slot_swap");
    let captured = agent
        .captured
        .lock()
        .await
        .clone()
        .expect("pending_self_upgrade.json captured before slot_swap");
    assert_eq!(captured.deployment_id, dep_id);
    assert_eq!(captured.service, "mu-cd-controller");
    assert_eq!(captured.target_node, "node-x86");
    assert_eq!(captured.artifact_sha256, bin_sha);
}
