//! Integration tests for the read-only `/api/cd/*` API: authentication, deployments/history,
//! gate and lease endpoints, the SSE stream, and an agent → controller → SSE replay.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tower::ServiceExt;

use mu_cd_controller::api::{
    load_token_file, router, serve, CdApiState, DeploymentGate, DeploymentSummary,
};
use mu_cd_controller::cd_state::{
    CdStateStore, DeploymentStart, GateOutcome, GateVerdict, LeaseView, RollbackReason, Slot,
};
use mu_cd_controller::contract::{IntegrationTestSelector, MuConDeConfig};
use mu_cd_controller::error::OrchestratorError;
use mu_cd_controller::lease::LeaseCoordinator;
use mu_cd_controller::orchestrator::{
    dispatch_agent_frame, AgentFrame, DeploymentOrchestrator, IpcAgentClient, MuRegistClient,
};
use mu_cd_ipc::{
    create_fory_runtime, read_frame, write_frame, ArtifactTaintNotification,
    IntegrationTestProgress, IntegrationTestReport, IpcHeader, StageDeploymentRequest,
    StageDeploymentResponse, TestState, MSG_TYPE_HEARTBEAT, MSG_TYPE_IT_PROGRESS,
    MSG_TYPE_IT_REPORT, MSG_TYPE_STAGE_DEPLOY_REQ, MSG_TYPE_STAGE_DEPLOY_RESP,
};

const TOKEN: &str = "test-token-0123456789";

fn start(id: &str, repo: &str, tests: Vec<(&str, bool)>) -> DeploymentStart {
    DeploymentStart {
        deployment_id: id.into(),
        repo: Some(repo.into()),
        service: "example-svc".into(),
        artifact_digest: format!("sha256:{id}"),
        target_node: "node-a".into(),
        active_slot: Slot::A,
        staged_slot: Slot::B,
        restore_slot: Slot::A,
        lease_id: format!("lease-{id}"),
        lease_expires_epoch_ms: LeaseCoordinator::current_epoch_ms() + 120_000,
        tests: tests.into_iter().map(|(n, c)| (n.to_string(), c)).collect(),
    }
}

fn progress(id: &str, name: &str, critical: bool, state: TestState) -> IntegrationTestProgress {
    IntegrationTestProgress {
        deployment_id: id.into(),
        test_name: name.into(),
        critical,
        state,
        duration_ms: if state.is_terminal() { 42 } else { 0 },
        timestamp_epoch_ms: LeaseCoordinator::current_epoch_ms(),
    }
}

fn seeded_store() -> Arc<CdStateStore> {
    let store = Arc::new(CdStateStore::default());
    store.deployment_started(start(
        "dep-old",
        "LMA1980/example",
        vec![("smoke", true), ("perf", false)],
    ));
    store.apply_it_progress(&progress("dep-old", "smoke", true, TestState::Failed));
    store.apply_it_report(&IntegrationTestReport {
        deployment_id: "dep-old".into(),
        service_name: "example-svc".into(),
        artifact_sha256: "sha256:dep-old".into(),
        executed_tests: vec!["smoke".into(), "perf".into()],
        passed: false,
        failed_tests: vec!["smoke".into()],
        duration_ms: 42,
        log_excerpt: Some("assertion failed: smoke probe returned 503".into()),
    });
    store.deployment_rolled_back(
        "dep-old",
        Slot::A,
        RollbackReason::CriticalTestFailed,
        "Integration tests failed: [\"smoke\"]",
    );
    store.deployment_tainted("dep-old", "sha256:dep-old", "smoke failed");

    store.deployment_started(start("dep-other", "LMA1980/other", vec![("smoke", true)]));

    store.deployment_started(start(
        "dep-new",
        "LMA1980/example",
        vec![("smoke", true), ("perf", false)],
    ));
    store.apply_it_progress(&progress("dep-new", "smoke", true, TestState::Passed));
    store.apply_it_progress(&progress("dep-new", "perf", false, TestState::Running));
    store.set_leases(vec![LeaseView {
        lease_id: "lease-dep-new".into(),
        deployment_id: "dep-new".into(),
        target_node: "node-a".into(),
        service: "example-svc".into(),
        artifact_digest: "sha256:dep-new".into(),
        active_slot: Slot::A,
        candidate_slot: Slot::B,
        expires_epoch_ms: LeaseCoordinator::current_epoch_ms() + 60_000,
        ttl_remaining_ms: 0,
        promoted: false,
    }]);
    store
}

async fn get(
    app: axum::Router,
    uri: &str,
    auth: Option<&str>,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    get_with_headers(app, uri, auth, &[]).await
}

async fn get_with_headers(
    app: axum::Router,
    uri: &str,
    auth: Option<&str>,
    extra_headers: &[(&str, &str)],
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut req = Request::builder().uri(uri);
    if let Some(a) = auth {
        req = req.header(header::AUTHORIZATION, a);
    }
    for (k, v) in extra_headers {
        req = req.header(*k, *v);
    }
    let resp = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, headers, body)
}

fn bearer() -> String {
    format!("Bearer {TOKEN}")
}

// ---------------------------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn test_every_cd_route_rejects_missing_or_wrong_token() {
    let app = router(CdApiState::new(seeded_store(), Some(TOKEN.into())));
    for uri in [
        "/api/cd/deployments",
        "/api/cd/deployments?repo=LMA1980/example&limit=5",
        "/api/cd/deployments/dep-new/gate",
        "/api/cd/leases",
        "/api/cd/events",
    ] {
        let (s, h, body) = get(app.clone(), uri, None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{uri} without token");
        assert!(h.get(header::WWW_AUTHENTICATE).is_some());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["error"],
            "unauthorized"
        );

        let (s, _, _) = get(app.clone(), uri, Some("Bearer wrong-token")).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{uri} with wrong token");

        let (s, _, _) = get(app.clone(), uri, Some(TOKEN)).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{uri} without Bearer scheme");
    }
}

#[tokio::test]
async fn test_fails_closed_when_token_unconfigured_or_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist");
    let token = load_token_file(&missing);
    assert!(token.is_none());

    let app = router(CdApiState::new(seeded_store(), token));
    // Even the path string itself must not work as a token.
    let path_as_token = format!("Bearer {}", missing.display());
    for auth in [None, Some(path_as_token.as_str()), Some("Bearer ")] {
        let (s, _, _) = get(app.clone(), "/api/cd/deployments", auth).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn test_token_file_is_trimmed_and_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("cd-api.token");
    std::fs::write(&p, format!("\n  {TOKEN}  \n")).unwrap();
    let app = router(CdApiState::new(seeded_store(), load_token_file(&p)));
    let (s, _, _) = get(app, "/api/cd/leases", Some(&bearer())).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn test_unknown_routes_are_not_served() {
    let app = router(CdApiState::new(seeded_store(), Some(TOKEN.into())));
    let (s, _, _) = get(app.clone(), "/api/cd/admin", Some(&bearer())).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _, _) = get(app, "/", Some(&bearer())).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------------------------
// Deployments, history, gate, leases
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn test_deployments_filter_history_and_summary() {
    let app = router(CdApiState::new(seeded_store(), Some(TOKEN.into())));

    let (s, _, body) = get(app.clone(), "/api/cd/deployments", Some(&bearer())).await;
    assert_eq!(s, StatusCode::OK);
    let all: Vec<DeploymentSummary> = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        all.iter()
            .map(|d| d.deployment_id.as_str())
            .collect::<Vec<_>>(),
        vec!["dep-new", "dep-other", "dep-old"],
        "newest first"
    );

    let (_, _, body) = get(
        app.clone(),
        "/api/cd/deployments?repo=LMA1980/example",
        Some(&bearer()),
    )
    .await;
    let example: Vec<DeploymentSummary> = serde_json::from_slice(&body).unwrap();
    assert_eq!(example.len(), 2);
    let new = &example[0];
    assert_eq!(new.owner, "LMA1980");
    assert_eq!(new.repo, "example");
    assert_eq!(new.active_slot, Slot::A);
    assert_eq!(new.staged_slot, Slot::B);
    assert_eq!(new.outcome, GateOutcome::Pending);
    assert_eq!(
        new.verdict,
        GateVerdict::Promote,
        "only critical test passed"
    );
    assert_eq!((new.it_passed, new.it_total), (1, 2));
    let old = &example[1];
    assert_eq!(old.outcome, GateOutcome::RolledBack);
    assert_eq!(old.verdict, GateVerdict::Rollback);
    assert_eq!(
        old.rollback_reason,
        Some(RollbackReason::CriticalTestFailed)
    );
    assert!(old.tainted);
    assert_eq!(old.critical_failed, 1);
    assert!(old.finished_epoch_ms.is_some());

    // History strip: limit=N.
    let (_, _, body) = get(
        app.clone(),
        "/api/cd/deployments?repo=LMA1980/example&limit=1",
        Some(&bearer()),
    )
    .await;
    let one: Vec<DeploymentSummary> = serde_json::from_slice(&body).unwrap();
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].deployment_id, "dep-new");

    // Bare repo name and service name also match.
    let (_, _, body) = get(
        app.clone(),
        "/api/cd/deployments?repo=other",
        Some(&bearer()),
    )
    .await;
    let other: Vec<DeploymentSummary> = serde_json::from_slice(&body).unwrap();
    assert_eq!(other.len(), 1);
    let (_, _, body) = get(app, "/api/cd/deployments?repo=nope/nope", Some(&bearer())).await;
    let none: Vec<DeploymentSummary> = serde_json::from_slice(&body).unwrap();
    assert!(none.is_empty());
}

#[tokio::test]
async fn test_gate_endpoint_shape() {
    let app = router(CdApiState::new(seeded_store(), Some(TOKEN.into())));
    let (s, _, body) = get(
        app.clone(),
        "/api/cd/deployments/dep-new/gate",
        Some(&bearer()),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let raw: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // Snake-case JSON contract consumed by MuConsole.
    for key in [
        "deployment_id",
        "owner",
        "repo",
        "service",
        "artifact_digest",
        "target_node",
        "staged_slot",
        "restore_slot",
        "lease_expires_epoch_ms",
        "lease_ttl_remaining_ms",
        "outcome",
        "verdict",
        "rollback_reason",
        "tainted",
        "tests",
    ] {
        assert!(raw.get(key).is_some(), "missing {key}");
    }
    assert_eq!(raw["staged_slot"], "b");
    assert_eq!(raw["restore_slot"], "a");
    assert_eq!(raw["outcome"], "pending");
    assert_eq!(raw["tests"][0]["name"], "smoke");
    assert_eq!(raw["tests"][0]["critical"], true);
    assert_eq!(raw["tests"][0]["state"], "passed");
    assert_eq!(raw["tests"][0]["duration_ms"], 42);
    assert_eq!(raw["tests"][1]["state"], "running");

    let gate: DeploymentGate = serde_json::from_value(raw).unwrap();
    assert!(gate.lease_ttl_remaining_ms > 0 && gate.lease_ttl_remaining_ms <= 120_000);

    let (s, _, body) = get(app, "/api/cd/deployments/missing/gate", Some(&bearer())).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["error"],
        "deployment_not_found"
    );
}

#[tokio::test]
async fn test_gate_redacts_log_excerpt_unless_operator_authenticated() {
    let app = router(CdApiState::new(seeded_store(), Some(TOKEN.into())));

    // 1. Public read-only dashboard request (valid bearer token, no operator header):
    // checkpoint states and durations are intact, but log_excerpt is redacted to None.
    let (s, _, body) = get(
        app.clone(),
        "/api/cd/deployments/dep-old/gate",
        Some(&bearer()),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let anon_gate: DeploymentGate = serde_json::from_slice(&body).unwrap();
    assert_eq!(anon_gate.outcome, GateOutcome::RolledBack);
    assert_eq!(anon_gate.tests.len(), 2);
    assert_eq!(anon_gate.tests[0].name, "smoke");
    assert_eq!(anon_gate.tests[0].state, TestState::Failed);
    assert_eq!(anon_gate.tests[0].duration_ms, 42);
    assert!(
        anon_gate.tests.iter().all(|t| t.log_excerpt.is_none()),
        "anonymous public requests must redact log_excerpt"
    );

    // 2. Operator-authenticated request via X-Forwarded-User preserves log_excerpt.
    let (s, _, body) = get_with_headers(
        app.clone(),
        "/api/cd/deployments/dep-old/gate",
        Some(&bearer()),
        &[("x-forwarded-user", "octocat")],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let op_gate: DeploymentGate = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        op_gate.tests[0].log_excerpt.as_deref(),
        Some("assertion failed: smoke probe returned 503")
    );

    // 3. Operator-authenticated request via X-Operator-Authenticated: true preserves log_excerpt.
    let (s, _, body) = get_with_headers(
        app.clone(),
        "/api/cd/deployments/dep-old/gate",
        Some(&bearer()),
        &[("x-operator-authenticated", "true")],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let op_gate_flag: DeploymentGate = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        op_gate_flag.tests[0].log_excerpt.as_deref(),
        Some("assertion failed: smoke probe returned 503")
    );

    // 4. Missing or invalid bearer token still fails closed with 401 even when X-Forwarded-User is sent.
    let (s, _, _) = get_with_headers(
        app.clone(),
        "/api/cd/deployments/dep-old/gate",
        None,
        &[("x-forwarded-user", "octocat")],
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let (s, _, _) = get_with_headers(
        app,
        "/api/cd/deployments/dep-old/gate",
        Some("Bearer invalid-token"),
        &[("x-forwarded-user", "octocat")],
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_leases_endpoint() {
    let app = router(CdApiState::new(seeded_store(), Some(TOKEN.into())));
    let (s, _, body) = get(app, "/api/cd/leases", Some(&bearer())).await;
    assert_eq!(s, StatusCode::OK);
    let leases: Vec<LeaseView> = serde_json::from_slice(&body).unwrap();
    assert_eq!(leases.len(), 1);
    assert_eq!(leases[0].deployment_id, "dep-new");
    assert!(leases[0].ttl_remaining_ms > 0, "TTL recomputed per request");
}

#[tokio::test]
async fn test_lease_coordinator_feeds_lease_view() {
    use mu_cd_ipc::DeploymentLeaseRequest;
    let coordinator = LeaseCoordinator::new();
    let grant = coordinator
        .acquire_lease(&DeploymentLeaseRequest {
            deployment_id: "dep-l".into(),
            node_id: "node-a".into(),
            service_name: "example-svc".into(),
            artifact_sha256: "sha256:l".into(),
            requested_ttl_secs: 30,
        })
        .await;
    assert!(grant.granted);
    let leases = coordinator.list_leases().await;
    assert_eq!(leases.len(), 1);
    assert_eq!(leases[0].lease_id, grant.lease_id);
    assert_eq!(leases[0].target_node, "node-a");
    assert!(leases[0].ttl_remaining_ms > 0);
}

// ---------------------------------------------------------------------------------------------
// SSE
// ---------------------------------------------------------------------------------------------

async fn spawn_server(state: CdApiState) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(listener, state).await;
    });
    addr
}

/// Reads the SSE body until every `needle` was seen or `timeout` elapsed.
async fn read_sse_until(
    mut resp: reqwest::Response,
    needles: &[&str],
    timeout: Duration,
) -> String {
    let mut buf = String::new();
    let deadline = tokio::time::Instant::now() + timeout;
    while !needles.iter().all(|n| buf.contains(n)) {
        match tokio::time::timeout_at(deadline, resp.chunk()).await {
            Ok(Ok(Some(chunk))) => buf.push_str(&String::from_utf8_lossy(&chunk)),
            _ => break,
        }
    }
    buf
}

async fn wait_for_subscriber(store: &CdStateStore) {
    // The SSE handler subscribes when the response starts.
    for _ in 0..250 {
        if store.subscriber_count() > 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("SSE subscriber never attached");
}

#[tokio::test]
async fn test_sse_requires_auth_and_streams_events_with_heartbeat() {
    let store = Arc::new(CdStateStore::default());
    let state = CdApiState::new(store.clone(), Some(TOKEN.into()))
        .with_keep_alive(Duration::from_millis(100));
    let addr = spawn_server(state).await;
    let client = reqwest::Client::new();
    let url = format!("http://{addr}/api/cd/events");

    let denied = client.get(&url).send().await.unwrap();
    assert_eq!(denied.status().as_u16(), 401);

    let resp = client.get(&url).bearer_auth(TOKEN).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert!(resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/event-stream"));

    wait_for_subscriber(&store).await;
    store.deployment_started(start("dep-sse", "LMA1980/example", vec![("smoke", true)]));
    store.apply_it_progress(&progress("dep-sse", "smoke", true, TestState::Running));
    store.apply_it_progress(&progress("dep-sse", "smoke", true, TestState::Passed));
    store.deployment_promoted("dep-sse", Slot::B);
    store.lease_expired("dep-sse", "lease-dep-sse");
    store.deployment_tainted("dep-sse", "sha256:dep-sse", "manual taint");
    store.deployment_rolled_back("dep-sse", Slot::A, RollbackReason::Manual, "operator");

    let body = read_sse_until(
        resp,
        &[
            "event: it_progress",
            "\"state\":\"passed\"",
            "event: promoted",
            "event: lease_expired",
            "event: tainted",
            "event: rolled_back",
            "heartbeat",
        ],
        Duration::from_secs(5),
    )
    .await;
    assert!(body.contains("event: it_progress"), "{body}");
    assert!(body.contains("\"test_name\":\"smoke\""), "{body}");
    assert!(body.contains("\"state\":\"running\""), "{body}");
    assert!(body.contains("\"state\":\"passed\""), "{body}");
    assert!(
        body.contains("event: promoted\ndata: {\"deployment_id\":\"dep-sse\",\"slot\":\"b\"}"),
        "{body}"
    );
    assert!(body.contains("event: lease_expired"), "{body}");
    assert!(body.contains("event: tainted"), "{body}");
    assert!(body.contains("\"reason\":\"manual\""), "{body}");
    assert!(body.contains("heartbeat"), "{body}");
    // Order: progress before promotion.
    assert!(body.find("event: it_progress").unwrap() < body.find("event: promoted").unwrap());
}

#[tokio::test]
async fn test_sse_drops_slow_consumer() {
    use futures_util::StreamExt;
    let store = CdStateStore::new(16, 2);
    let rx = store.subscribe();
    for i in 0..10 {
        store.lease_expired(&format!("d{i}"), "l");
    }
    let mut stream = Box::pin(mu_cd_controller::api::cd_event_stream(rx));
    // Lagged receiver: the stream terminates instead of silently skipping events.
    assert!(stream.next().await.is_none());
}

// ---------------------------------------------------------------------------------------------
// IPC ingestion
// ---------------------------------------------------------------------------------------------

#[test]
fn test_dispatch_ignores_unknown_ids_and_forwards_progress() {
    let fory = create_fory_runtime().unwrap();
    let store = CdStateStore::default();
    store.deployment_started(start("dep-d", "LMA1980/example", vec![]));

    // Unknown / unrelated message types are skipped without decoding.
    assert_eq!(
        dispatch_agent_frame(&fory, 0x7F, b"garbage", Some(&store)).unwrap(),
        AgentFrame::Ignored(0x7F)
    );
    assert_eq!(
        dispatch_agent_frame(&fory, MSG_TYPE_HEARTBEAT, b"garbage", Some(&store)).unwrap(),
        AgentFrame::Ignored(MSG_TYPE_HEARTBEAT)
    );
    // Undecodable progress is advisory: ignored, not an error.
    assert_eq!(
        dispatch_agent_frame(&fory, MSG_TYPE_IT_PROGRESS, b"garbage", Some(&store)).unwrap(),
        AgentFrame::Ignored(MSG_TYPE_IT_PROGRESS)
    );
    // Undecodable report is an error.
    assert!(dispatch_agent_frame(&fory, MSG_TYPE_IT_REPORT, b"garbage", None).is_err());

    let p = progress("dep-d", "smoke", true, TestState::Running);
    let bytes = fory.serialize(&p).unwrap();
    assert_eq!(
        dispatch_agent_frame(&fory, MSG_TYPE_IT_PROGRESS, &bytes, Some(&store)).unwrap(),
        AgentFrame::Progress(p)
    );
    assert_eq!(
        store.snapshot().deployment("dep-d").unwrap().tests[0].state,
        TestState::Running
    );
}

// ---------------------------------------------------------------------------------------------
// Agent -> controller -> SSE replay
// ---------------------------------------------------------------------------------------------

#[derive(Default)]
struct NoopRegist;

#[async_trait]
impl MuRegistClient for NoopRegist {
    async fn is_digest_tainted(&self, _digest: &str) -> Result<bool, OrchestratorError> {
        Ok(false)
    }
    async fn promote_canary(&self, _digest: &str) -> Result<(), OrchestratorError> {
        Ok(())
    }
    async fn taint_canary(
        &self,
        _digest: &str,
        _n: &ArtifactTaintNotification,
    ) -> Result<(), OrchestratorError> {
        Ok(())
    }
}

/// Minimal fake agent: answers staging, accepts swap/rollback, and on the integration-test
/// connection (where the controller sends nothing) streams the scripted gate.
async fn spawn_fake_agent(health_passes: bool) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let fory = create_fory_runtime().unwrap();
                match tokio::time::timeout(Duration::from_millis(300), read_frame(&mut stream))
                    .await
                {
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
                        let h = IpcHeader::new(
                            MSG_TYPE_STAGE_DEPLOY_RESP,
                            bytes.len() as u32,
                            0,
                            hdr.sequence,
                        );
                        let _ = write_frame(&mut stream, &h, &bytes).await;
                    }
                    Ok(_) => {} // swap / rollback: nothing to answer
                    Err(_) => {
                        // Integration-test connection.
                        let dep = "dep-replay";
                        let tests = [
                            ("systemd_unit_active", true),
                            ("health_endpoint_ready", true),
                        ];
                        let mut frames: Vec<(u16, Vec<u8>)> = Vec::new();
                        // Unknown future message type first: must be skipped.
                        frames.push((0x7E, b"future".to_vec()));
                        for state in [TestState::Pending, TestState::Running] {
                            for (n, c) in tests {
                                frames.push((
                                    MSG_TYPE_IT_PROGRESS,
                                    fory.serialize(&progress(dep, n, c, state)).unwrap(),
                                ));
                            }
                        }
                        frames.push((
                            MSG_TYPE_IT_PROGRESS,
                            fory.serialize(&progress(dep, tests[0].0, true, TestState::Passed))
                                .unwrap(),
                        ));
                        let last = if health_passes {
                            TestState::Passed
                        } else {
                            TestState::Failed
                        };
                        frames.push((
                            MSG_TYPE_IT_PROGRESS,
                            fory.serialize(&progress(dep, tests[1].0, true, last))
                                .unwrap(),
                        ));
                        let report = IntegrationTestReport {
                            deployment_id: dep.into(),
                            service_name: "example-svc".into(),
                            artifact_sha256: "sha256:replay".into(),
                            executed_tests: tests.iter().map(|(n, _)| n.to_string()).collect(),
                            passed: health_passes,
                            failed_tests: if health_passes {
                                vec![]
                            } else {
                                vec![tests[1].0.to_string()]
                            },
                            duration_ms: 500,
                            log_excerpt: (!health_passes).then(|| "connection refused".to_string()),
                        };
                        frames.push((MSG_TYPE_IT_REPORT, fory.serialize(&report).unwrap()));
                        for (seq, (t, p)) in frames.into_iter().enumerate() {
                            let h = IpcHeader::new(t, p.len() as u32, 0, seq as u64);
                            if write_frame(&mut stream, &h, &p).await.is_err() {
                                return;
                            }
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                        let _ = stream.shutdown().await;
                    }
                }
            });
        }
    });
    port
}

async fn replay(health_passes: bool) -> (String, Arc<CdStateStore>, bool) {
    let store = Arc::new(CdStateStore::default());
    let addr = spawn_server(CdApiState::new(store.clone(), Some(TOKEN.into()))).await;
    let sse = reqwest::Client::new()
        .get(format!("http://{addr}/api/cd/events"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(sse.status().as_u16(), 200);
    wait_for_subscriber(&store).await;

    let port = spawn_fake_agent(health_passes).await;
    let agent = Arc::new(IpcAgentClient::new(port).with_progress_sink(store.clone()));
    let orchestrator = DeploymentOrchestrator::new(
        Arc::new(LeaseCoordinator::new()),
        None,
        agent,
        Arc::new(NoopRegist),
    )
    .with_cd_state(store.clone());

    let config = MuConDeConfig {
        version: "1".into(),
        service: "example-svc".into(),
        target_nodes: vec!["127.0.0.1".into()],
        lease_ttl_seconds: 60,
        warmup_timeout_seconds: 5,
        bake_window_seconds: 60,
        max_error_logs: 0,
        max_p99_latency_ms: 250.0,
        integration_tests: IntegrationTestSelector::All("all".into()),
    };
    let outcome = orchestrator
        .orchestrate_deployment_for_repo(
            &config,
            "sha256:replay",
            Some("dep-replay".into()),
            Some("LMA1980/example"),
        )
        .await
        .unwrap();

    let terminal = if health_passes {
        "event: promoted"
    } else {
        "event: tainted"
    };
    let body = read_sse_until(sse, &[terminal], Duration::from_secs(5)).await;
    (body, store, outcome.is_promoted())
}

#[tokio::test]
async fn test_replay_agent_progress_to_sse_promotes_when_all_critical_pass() {
    let (body, store, promoted) = replay(true).await;
    assert!(promoted);
    assert_eq!(body.matches("event: it_progress").count(), 6, "{body}");
    assert!(body.find("event: it_progress").unwrap() < body.find("event: promoted").unwrap());
    assert!(!body.contains("event: rolled_back"));

    let snap = store.snapshot();
    let d = snap.deployment("dep-replay").unwrap();
    assert_eq!(d.owner, "LMA1980");
    assert_eq!(d.outcome, GateOutcome::Promoted);
    assert_eq!(d.active_slot, Slot::B);
    assert_eq!(d.tests.len(), 2);
    assert!(d
        .tests
        .iter()
        .all(|t| t.state == TestState::Passed && t.critical));
    let gate = DeploymentGate::from_record(d, LeaseCoordinator::current_epoch_ms());
    assert_eq!(gate.verdict, GateVerdict::Promote);
    assert_eq!(gate.lease_ttl_remaining_ms, 0);
    assert!(snap.leases.is_empty(), "lease released after promotion");
}

#[tokio::test]
async fn test_replay_critical_failure_rolls_back_and_taints() {
    let (body, store, promoted) = replay(false).await;
    assert!(!promoted);
    assert_eq!(body.matches("event: it_progress").count(), 6, "{body}");
    assert!(body.contains("\"state\":\"failed\""), "{body}");
    assert!(body.contains("event: rolled_back"), "{body}");
    assert!(
        body.contains("\"reason\":\"critical_test_failed\""),
        "{body}"
    );
    assert!(body.contains("\"restore_slot\":\"a\""), "{body}");
    assert!(body.contains("event: tainted"), "{body}");
    assert!(!body.contains("event: promoted"));
    let i_fail = body.find("\"state\":\"failed\"").unwrap();
    let i_rb = body.find("event: rolled_back").unwrap();
    let i_taint = body.find("event: tainted").unwrap();
    assert!(i_fail < i_rb && i_rb < i_taint);

    let snap = store.snapshot();
    let d = snap.deployment("dep-replay").unwrap();
    assert_eq!(d.outcome, GateOutcome::RolledBack);
    assert!(d.tainted);
    assert_eq!(d.active_slot, Slot::A);
    assert_eq!(d.rollback_reason, Some(RollbackReason::CriticalTestFailed));
    let health = d
        .tests
        .iter()
        .find(|t| t.name == "health_endpoint_ready")
        .unwrap();
    assert_eq!(health.state, TestState::Failed);
    assert_eq!(health.log_excerpt.as_deref(), Some("connection refused"));
}
