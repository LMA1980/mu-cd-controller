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
    load_token_file, router, serve, CdApiState, DeployTriggerResponse, DeploymentGate,
    DeploymentSummary,
};
use mu_cd_controller::auth::{
    ROLE_AB_EMERGENCY, ROLE_GATE_INSPECTOR, ROLE_MEMBER, ROLE_PLATFORM_ADMIN,
};
use mu_cd_controller::cd_state::{
    AbRollbackResponseDto, CdEcosystem, CdRepoId, CdRunDto, CdRunFailurePinpointDto, CdRunState,
    CdStateStore, CdStepDto, DeploymentStart, GateOutcome, GateVerdict, LeaseView, RollbackReason,
    SkipReasonDto, Slot,
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

async fn post_json(
    app: axum::Router,
    uri: &str,
    auth: Option<&str>,
    extra_headers: &[(&str, &str)],
    json_body: &str,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(a) = auth {
        req = req.header(header::AUTHORIZATION, a);
    }
    for (k, v) in extra_headers {
        req = req.header(*k, *v);
    }
    let resp = app
        .oneshot(req.body(Body::from(json_body.to_string())).unwrap())
        .await
        .unwrap();
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
        "/api/cd/runs",
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

    let (s, h, _) = post_json(
        app.clone(),
        "/api/cd/deployments/dep-new/rollback",
        None,
        &[],
        "{}",
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(h.get(header::WWW_AUTHENTICATE).is_some());
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
async fn test_gate_redacts_log_excerpt_without_ab_gate_logs_read_folio() {
    let state = CdApiState::new(seeded_store(), Some(TOKEN.into()))
        .with_proxy_secret(Some("edge-secret-42".into()));
    let now = mu_cd_controller::cd_state::now_epoch_ms();
    state
        .authorizer
        .bind_operator("alice", 1, &[ROLE_MEMBER], &[], false, now)
        .unwrap();
    state
        .authorizer
        .bind_operator(
            "bob",
            1,
            &[ROLE_GATE_INSPECTOR],
            &[ROLE_GATE_INSPECTOR],
            false,
            now,
        )
        .unwrap();
    state
        .authorizer
        .bind_operator("nopass", 0, &[ROLE_GATE_INSPECTOR], &[], false, now)
        .unwrap();
    let app = router(state);

    // 1. Service-to-service dashboard request (valid bearer token, no user session):
    // checkpoint states and durations stay visible, but log_excerpt is redacted to None.
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
        "service-only dashboard requests must redact log_excerpt"
    );

    // 2. Spoofed X-Operator-Authenticated header MUST NOT bypass folio redaction.
    let (s, _, body) = get_with_headers(
        app.clone(),
        "/api/cd/deployments/dep-old/gate",
        Some(&bearer()),
        &[("x-operator-authenticated", "true")],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let spoofed_flag: DeploymentGate = serde_json::from_slice(&body).unwrap();
    assert!(spoofed_flag.tests.iter().all(|t| t.log_excerpt.is_none()));

    // 3. Authenticated baseline member (folio:cd:read + folio:ab:read, NO folio:ab:gate-logs)
    // still receives redacted log_excerpt.
    let (s, _, body) = get_with_headers(
        app.clone(),
        "/api/cd/deployments/dep-old/gate",
        None,
        &[
            ("x-proxy-secret", "edge-secret-42"),
            ("x-forwarded-user", "alice"),
        ],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let member_gate: DeploymentGate = serde_json::from_slice(&body).unwrap();
    assert!(member_gate.tests.iter().all(|t| t.log_excerpt.is_none()));

    // 4. Operator holding elective gate-inspector folio (ab:gate.logs.read) sees full log_excerpt.
    let (s, _, body) = get_with_headers(
        app.clone(),
        "/api/cd/deployments/dep-old/gate",
        Some(&bearer()),
        &[
            ("x-proxy-secret", "edge-secret-42"),
            ("x-forwarded-user", "bob"),
        ],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let op_gate: DeploymentGate = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        op_gate.tests[0].log_excerpt.as_deref(),
        Some("assertion failed: smoke probe returned 503")
    );

    // 5. Spoofed X-Forwarded-User without X-Proxy-Secret fails closed with 401.
    let (s, _, _) = get_with_headers(
        app.clone(),
        "/api/cd/deployments/dep-old/gate",
        Some(&bearer()),
        &[("x-forwarded-user", "bob")],
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // 6. Bound user with 0 enrolled Passkeys fails closed with 403 Forbidden.
    let (s, _, _) = get_with_headers(
        app.clone(),
        "/api/cd/deployments/dep-old/gate",
        None,
        &[
            ("x-proxy-secret", "edge-secret-42"),
            ("x-forwarded-user", "nopass"),
        ],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // 7. Invalid bearer token fails closed with 401 even when valid X-Proxy-Secret + user are sent.
    let (s, _, _) = get_with_headers(
        app,
        "/api/cd/deployments/dep-old/gate",
        Some("Bearer invalid-token"),
        &[
            ("x-proxy-secret", "edge-secret-42"),
            ("x-forwarded-user", "bob"),
        ],
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
        it_archive_digest: None,
        ab_rules: Default::default(),
        deployment: Default::default(),
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

// ---------------------------------------------------------------------------------------------
// Ecosystem-agnostic GET /api/cd/runs & emergency POST /api/cd/deployments/{id}/rollback (#72)
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn test_cd_runs_endpoint_multi_ecosystem_and_auth() {
    let store = seeded_store();
    store.record_cd_run(CdRunDto {
        run_id: "cd-cargo-1".into(),
        ecosystem: CdEcosystem::Cargo,
        repo: CdRepoId::new("LMA1980", "mu-cd-controller"),
        ref_name: "refs/heads/main".into(),
        commit_sha: "111aaaa".into(),
        state: CdRunState::Succeeded,
        started_epoch_ms: 100,
        finished_epoch_ms: Some(150),
        steps: vec![CdStepDto {
            step_id: "cargo-publish".into(),
            label: "Publish crate".into(),
            state: CdRunState::Succeeded,
            duration_ms: 50,
            ..Default::default()
        }],
        failure: None,
        registry_package: Some("mu-cd-controller".into()),
        registry_version: Some("0.1.1".into()),
        ab_deployment_id: Some("dep-new".into()),
        artifact_digest: Some("sha256:dep-new".into()),
    });
    store.record_cd_run(CdRunDto {
        run_id: "cd-dotnet-2".into(),
        ecosystem: CdEcosystem::from_label(".NET"),
        repo: CdRepoId::new("LMA1980", "k3-sdk-dotnet"),
        ref_name: "refs/tags/v2.0.0".into(),
        commit_sha: "222bbbb".into(),
        state: CdRunState::Failed,
        started_epoch_ms: 200,
        finished_epoch_ms: Some(260),
        steps: vec![
            CdStepDto {
                step_id: "dotnet-pack".into(),
                label: "Pack NuGet".into(),
                state: CdRunState::Succeeded,
                duration_ms: 30,
                ..Default::default()
            },
            CdStepDto {
                step_id: "nuget-push".into(),
                label: "Push NuGet".into(),
                state: CdRunState::Failed,
                duration_ms: 30,
                skip_reason: Some(SkipReasonDto::Other("upstream_registry_conflict".into())),
                error_summary: Some("409 Conflict".into()),
                failed_package: Some("K3.Runtime".into()),
                exit_code: Some(1),
            },
        ],
        failure: Some(CdRunFailurePinpointDto {
            step_id: "nuget-push".into(),
            package_name: Some("K3.Runtime".into()),
            package_version: Some("2.0.0".into()),
            reason: "NuGet feed rejected duplicate package".into(),
            log_excerpt: Some("Response status code: 409".into()),
        }),
        registry_package: Some("K3.Runtime".into()),
        registry_version: Some("2.0.0".into()),
        ab_deployment_id: None,
        artifact_digest: None,
    });
    store.record_cd_run(CdRunDto {
        run_id: "cd-maven-3".into(),
        ecosystem: CdEcosystem::Maven,
        repo: CdRepoId::new("LMA1980", "k3-java"),
        ref_name: "refs/heads/main".into(),
        commit_sha: "333cccc".into(),
        state: CdRunState::Blocked,
        started_epoch_ms: 300,
        finished_epoch_ms: None,
        steps: vec![],
        failure: None,
        registry_package: Some("org.lma1980:k3-java".into()),
        registry_version: Some("1.0.0".into()),
        ab_deployment_id: None,
        artifact_digest: None,
    });

    let state =
        CdApiState::new(store, Some(TOKEN.into())).with_proxy_secret(Some("proxy-secret".into()));
    state
        .authorizer
        .bind_operator(
            "reader",
            1,
            &[ROLE_MEMBER],
            &[],
            false,
            mu_cd_controller::cd_state::now_epoch_ms(),
        )
        .unwrap();
    let app = router(state);

    // Uninvited user rejected with 403 Forbidden
    let (s, _, _) = get_with_headers(
        app.clone(),
        "/api/cd/runs",
        None,
        &[
            ("x-proxy-secret", "proxy-secret"),
            ("x-forwarded-user", "stranger"),
        ],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Authenticated member sees all 3 ecosystems + pinpoint failure shape
    let (s, _, body) = get_with_headers(
        app.clone(),
        "/api/cd/runs",
        None,
        &[
            ("x-proxy-secret", "proxy-secret"),
            ("x-forwarded-user", "reader"),
        ],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let runs: Vec<CdRunDto> = serde_json::from_slice(&body).unwrap();
    assert_eq!(runs.len(), 3);
    assert_eq!(runs[0].ecosystem, CdEcosystem::Maven);
    assert_eq!(runs[1].ecosystem, CdEcosystem::DotNet);
    assert_eq!(runs[2].ecosystem, CdEcosystem::Cargo);
    assert_eq!(
        runs[1].failure.as_ref().unwrap().package_name.as_deref(),
        Some("K3.Runtime")
    );

    // Filter by ecosystem slug aliases
    let (s, _, body) = get(app, "/api/cd/runs?ecosystem=nuget&limit=5", Some(&bearer())).await;
    assert_eq!(s, StatusCode::OK);
    let filtered: Vec<CdRunDto> = serde_json::from_slice(&body).unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].run_id, "cd-dotnet-2");
    assert_eq!(
        serde_json::to_value(&filtered[0]).unwrap()["ecosystem"],
        "dotnet"
    );
}

struct MockApiAgent {
    rollback_slots: tokio::sync::Mutex<Vec<(String, mu_cd_ipc::DeploymentSlot, String)>>,
    swap_units: tokio::sync::Mutex<Vec<(String, String)>>,
    fail_it_node: Option<String>,
}

impl Default for MockApiAgent {
    fn default() -> Self {
        Self {
            rollback_slots: tokio::sync::Mutex::new(Vec::new()),
            swap_units: tokio::sync::Mutex::new(Vec::new()),
            fail_it_node: None,
        }
    }
}

#[async_trait]
impl mu_cd_controller::orchestrator::AgentIpcClient for MockApiAgent {
    async fn stage_deployment(
        &self,
        _node_id: &str,
        req: &StageDeploymentRequest,
    ) -> Result<StageDeploymentResponse, OrchestratorError> {
        Ok(StageDeploymentResponse {
            deployment_id: req.deployment_id.clone(),
            target_slot: req.target_slot,
            btrfs_subvolume_path: "/srv/muconde/slots".into(),
            staged_ok: true,
            error_message: None,
        })
    }

    async fn slot_swap(
        &self,
        node_id: &str,
        cmd: &mu_cd_ipc::SlotSwapCommand,
    ) -> Result<(), OrchestratorError> {
        self.swap_units
            .lock()
            .await
            .push((node_id.to_string(), cmd.systemd_unit.clone()));
        Ok(())
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
        let should_fail = self.fail_it_node.as_deref().is_some_and(|n| n == node_id);
        Ok(IntegrationTestReport {
            deployment_id: deployment_id.into(),
            service_name: service.into(),
            artifact_sha256: artifact_sha256.into(),
            executed_tests: vec!["smoke".into()],
            passed: !should_fail,
            failed_tests: if should_fail {
                vec!["smoke".into()]
            } else {
                vec![]
            },
            duration_ms: 10,
            log_excerpt: None,
        })
    }

    async fn rollback(
        &self,
        _node_id: &str,
        cmd: &mu_cd_ipc::RollbackCommand,
    ) -> Result<(), OrchestratorError> {
        self.rollback_slots.lock().await.push((
            cmd.deployment_id.clone(),
            cmd.restore_slot,
            cmd.failed_artifact_sha256.clone(),
        ));
        Ok(())
    }
}

#[derive(Default)]
struct RecordingRegist {
    taints: tokio::sync::Mutex<Vec<String>>,
}

#[async_trait]
impl MuRegistClient for RecordingRegist {
    async fn is_digest_tainted(&self, digest: &str) -> Result<bool, OrchestratorError> {
        Ok(self.taints.lock().await.iter().any(|d| d == digest))
    }
    async fn promote_canary(&self, _digest: &str) -> Result<(), OrchestratorError> {
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

#[tokio::test]
async fn test_emergency_rollback_enforces_ab_rollback_folio_restores_slot_and_taints_registry() {
    let store = Arc::new(CdStateStore::default());
    let coordinator = Arc::new(LeaseCoordinator::new());
    let agent = Arc::new(MockApiAgent::default());
    let regist = Arc::new(RecordingRegist::default());
    let orchestrator = Arc::new(
        DeploymentOrchestrator::new(coordinator.clone(), None, agent.clone(), regist.clone())
            .with_cd_state(store.clone()),
    );

    let cfg = MuConDeConfig {
        version: "1".into(),
        service: "example-svc".into(),
        target_nodes: vec!["node-a".into()],
        lease_ttl_seconds: 60,
        warmup_timeout_seconds: 5,
        bake_window_seconds: 60,
        max_error_logs: 0,
        max_p99_latency_ms: 250.0,
        integration_tests: IntegrationTestSelector::All("all".into()),
        it_archive_digest: None,
        ab_rules: Default::default(),
        deployment: Default::default(),
    };

    // Deploy 1 promotes @a -> @b; Deploy 2 promotes @b -> @a.
    orchestrator
        .orchestrate_deployment(&cfg, "sha256:d1", Some("dep-emg-1".into()))
        .await
        .unwrap();
    orchestrator
        .orchestrate_deployment(&cfg, "sha256:d2", Some("dep-emg-2".into()))
        .await
        .unwrap();
    assert_eq!(
        store
            .snapshot()
            .deployment("dep-emg-2")
            .unwrap()
            .active_slot,
        Slot::A
    );
    assert_eq!(
        store
            .snapshot()
            .deployment("dep-emg-2")
            .unwrap()
            .restore_slot,
        Slot::B
    );

    let state = CdApiState::new(store.clone(), Some(TOKEN.into()))
        .with_orchestrator(orchestrator.clone())
        .with_proxy_secret(Some("edge-secret".into()));
    let now = mu_cd_controller::cd_state::now_epoch_ms();
    state
        .authorizer
        .bind_operator("alice", 1, &[ROLE_MEMBER], &[], false, now)
        .unwrap();
    state
        .authorizer
        .bind_operator(
            "bob",
            1,
            &[ROLE_GATE_INSPECTOR],
            &[ROLE_GATE_INSPECTOR],
            false,
            now,
        )
        .unwrap();
    state
        .authorizer
        .bind_operator(
            "carol",
            1,
            &[ROLE_AB_EMERGENCY],
            &[ROLE_AB_EMERGENCY],
            true,
            now,
        )
        .unwrap();
    state
        .authorizer
        .bind_operator(
            "admin",
            1,
            &[ROLE_PLATFORM_ADMIN],
            &[ROLE_PLATFORM_ADMIN],
            true,
            now,
        )
        .unwrap();
    let app = router(state);

    // 1. Service token alone, member, and gate-inspector cannot invoke ab:rollback -> 403
    let (s, _, _) = post_json(
        app.clone(),
        "/api/cd/deployments/dep-emg-2/rollback",
        Some(&bearer()),
        &[],
        r#"{"note":"service-should-fail"}"#,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    for login in ["alice", "bob", "stranger"] {
        let (s, _, _) = post_json(
            app.clone(),
            "/api/cd/deployments/dep-emg-2/rollback",
            None,
            &[
                ("x-proxy-secret", "edge-secret"),
                ("x-forwarded-user", login),
            ],
            r#"{"note":"should-fail"}"#,
        )
        .await;
        assert_eq!(
            s,
            StatusCode::FORBIDDEN,
            "{login} must not trigger rollback"
        );
    }
    assert!(agent.rollback_slots.lock().await.is_empty());

    // 2. Zero manual ab:promote endpoint exists anywhere, even for platform-admin.
    let (s, _, _) = post_json(
        app.clone(),
        "/api/cd/deployments/dep-emg-2/promote",
        None,
        &[
            ("x-proxy-secret", "edge-secret"),
            ("x-forwarded-user", "admin"),
        ],
        "{}",
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // 3. Unknown deployment returns 404 for authorized operator.
    let (s, _, _) = post_json(
        app.clone(),
        "/api/cd/deployments/does-not-exist/rollback",
        None,
        &[
            ("x-proxy-secret", "edge-secret"),
            ("x-forwarded-user", "carol"),
        ],
        "{}",
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // 4. Emergency operator with active Passkey-step-up folio triggers immediate rollback to @b + taint.
    let (s, _, body) = post_json(
        app,
        "/api/cd/deployments/dep-emg-2/rollback",
        Some(&bearer()),
        &[
            ("x-proxy-secret", "edge-secret"),
            ("x-forwarded-user", "carol"),
        ],
        r#"{"note":"late production regression"}"#,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let rb: AbRollbackResponseDto = serde_json::from_slice(&body).unwrap();
    assert_eq!(rb.deployment_id, "dep-emg-2");
    assert_eq!(rb.restored_slot, Slot::B);
    assert_eq!(rb.tainted_digest.as_deref(), Some("sha256:d2"));

    assert_eq!(
        agent.rollback_slots.lock().await.as_slice(),
        &[(
            "dep-emg-2".to_string(),
            mu_cd_ipc::DeploymentSlot::SlotB,
            "sha256:d2".to_string()
        )]
    );
    assert_eq!(
        regist.taints.lock().await.as_slice(),
        &["sha256:d2".to_string()]
    );

    // Restoring @b causes the next deploy to target @a rather than overwriting @b
    orchestrator
        .orchestrate_deployment(&cfg, "sha256:d3", Some("dep-emg-3".into()))
        .await
        .unwrap();
    let d3 = store.snapshot().deployment("dep-emg-3").unwrap().clone();
    assert_eq!(d3.staged_slot, Slot::A);
    assert_eq!(d3.restore_slot, Slot::B);
    assert_eq!(d3.active_slot, Slot::A);
}

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn test_post_deploy_deduplicates_targets_and_promotes_all_nodes() {
    let store = Arc::new(CdStateStore::default());
    let coordinator = Arc::new(LeaseCoordinator::new());
    let agent = Arc::new(MockApiAgent::default());
    let regist = Arc::new(RecordingRegist::default());
    let orchestrator = Arc::new(
        DeploymentOrchestrator::new(coordinator, None, agent.clone(), regist)
            .with_cd_state(store.clone()),
    );
    let app = router(CdApiState::new(store, Some(TOKEN.into())).with_orchestrator(orchestrator));

    let payload = serde_json::json!({
        "repo": "LMA1980/mu-cd-controller",
        "artifact_sha256": "deadbeef1234",
        "git_commit": "0123456789abcdef",
        "binary_digest": "deadbeef1234",
        "it_archive_digest": "cafebabe5678",
        "manifest_yaml": r#"
version: "1"
service: "mu-cd-controller"
integration_tests: "all"
deployment:
  target_nodes:
    - " node-a "
    - "node-b"
    - "node-a"
  binary: "mu-cd-controller"
  install_path: "/usr/local/bin/mu-cd-controller"
  systemd_unit: "custom-cd-ctrl"
"#,
        "wait": true
    });

    let (status, _, body) = post_json(
        app,
        "/api/cd/deploy",
        Some(&bearer()),
        &[],
        &payload.to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let resp: DeployTriggerResponse = serde_json::from_slice(&body).unwrap();
    assert!(resp.accepted);
    assert_eq!(resp.service, "mu-cd-controller");
    assert_eq!(resp.target_nodes, vec!["node-a", "node-b"]);
    assert_eq!(resp.promoted_nodes, vec!["node-a", "node-b"]);
    assert!(resp.rolled_back_nodes.is_empty());

    assert_eq!(
        agent.swap_units.lock().await.as_slice(),
        &[
            ("node-a".to_string(), "custom-cd-ctrl.service".to_string()),
            ("node-b".to_string(), "custom-cd-ctrl.service".to_string()),
        ]
    );
}

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn test_post_deploy_multi_node_partial_rollback_returns_422_and_compensates() {
    let store = Arc::new(CdStateStore::default());
    let coordinator = Arc::new(LeaseCoordinator::new());
    let agent = Arc::new(MockApiAgent {
        fail_it_node: Some("node-b".into()),
        ..Default::default()
    });
    let regist = Arc::new(RecordingRegist::default());
    let orchestrator = Arc::new(
        DeploymentOrchestrator::new(coordinator.clone(), None, agent.clone(), regist.clone())
            .with_cd_state(store.clone()),
    );
    let app = router(CdApiState::new(store, Some(TOKEN.into())).with_orchestrator(orchestrator));

    let payload = serde_json::json!({
        "repo": "LMA1980/mu-cd-controller",
        "artifact_sha256": "deadbeef5678",
        "manifest_yaml": r#"
version: "1"
service: "mu-cd-controller"
target_nodes:
  - "node-a"
  - "node-b"
  - "worker-riscv64"
integration_tests: "all"
"#,
        "wait": true
    });

    let (status, _, body) = post_json(
        app,
        "/api/cd/deploy",
        Some(&bearer()),
        &[],
        &payload.to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let resp: DeployTriggerResponse = serde_json::from_slice(&body).unwrap();
    assert!(!resp.accepted);
    assert_eq!(
        resp.target_nodes,
        vec!["node-a", "node-b", "worker-riscv64"]
    );
    assert!(resp.promoted_nodes.is_empty());
    assert_eq!(resp.rolled_back_nodes, vec!["node-a", "node-b"]);
    assert_eq!(
        coordinator
            .active_slot_for("node-a", "mu-cd-controller")
            .await,
        mu_cd_ipc::DeploymentSlot::SlotA
    );
    assert_eq!(
        coordinator
            .active_slot_for("node-b", "mu-cd-controller")
            .await,
        mu_cd_ipc::DeploymentSlot::SlotA
    );
    assert_eq!(agent.rollback_slots.lock().await.len(), 2);
}

#[tokio::test]
async fn test_operator_users_bootstrap_allows_combined_bearer_and_proxy_reads() {
    let store = seeded_store();
    let state = CdApiState::new(store, Some(TOKEN.into()))
        .with_proxy_secret(Some("proxy-sec".into()))
        .with_operator_users(["alice-op"]);
    let app = router(state);
    let bearer_hdr = bearer();
    let op_headers = [
        ("x-proxy-secret", "proxy-sec"),
        ("x-forwarded-user", "alice-op"),
    ];

    for path in ["/api/cd/deployments", "/api/cd/runs", "/api/cd/leases"] {
        let (status, _, body) =
            get_with_headers(app.clone(), path, Some(&bearer_hdr), &op_headers).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "expected 200 OK on {path}, got {status}: {}",
            String::from_utf8_lossy(&body)
        );
    }

    let sse_req = Request::builder()
        .uri("/api/cd/events")
        .header(header::AUTHORIZATION, &bearer_hdr)
        .header("x-proxy-secret", "proxy-sec")
        .header("x-forwarded-user", "alice-op")
        .body(Body::empty())
        .unwrap();
    let sse_resp = app.oneshot(sse_req).await.unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);
}
