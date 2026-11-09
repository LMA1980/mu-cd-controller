//! Read-only, authenticated CD status and integration-gate HTTP API (`/api/cd/*`).
//!
//! Served by axum on a **separate listener**, disabled unless `MUCONDE_CD_API_ADDR` is set.
//! Browsers reach it only through the reverse proxy, which authenticates the session and
//! forwards a bearer token. Service-to-service traffic (agents, MuRegist, MuObserve) keeps
//! using mTLS and is not affected.
//!
//! Every `/api/cd/*` route requires `Authorization: Bearer <token>`. The token is read from a
//! token file, trimmed, and the API **fails closed** (every request is rejected with `401`) when
//! no file is configured, the file cannot be read, or it is empty. The file path itself is never
//! used as a token.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path as AxPath, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::stream::Stream;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::sync::broadcast;

use crate::cd_state::{
    evaluate_gate, now_epoch_ms, CdEvent, CdStateStore, DeploymentRecord, GateOutcome,
    GateTestView, GateVerdict, LeaseView, RollbackReason, Slot,
};
use crate::contract::MuConDeConfig;
use crate::orchestrator::DeploymentOrchestrator;

/// Default `limit` for `GET /api/cd/deployments`.
pub const DEFAULT_DEPLOYMENTS_LIMIT: usize = 20;
/// Maximum accepted `limit`.
pub const MAX_DEPLOYMENTS_LIMIT: usize = 256;
/// Default SSE heartbeat interval.
pub const DEFAULT_SSE_KEEP_ALIVE: Duration = Duration::from_secs(15);

/// Listener configuration for the CD API.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CdApiConfig {
    /// Bind address; `None` disables the API (the default).
    pub bind_addr: Option<String>,
    /// File containing the bearer token.
    pub token_file: Option<PathBuf>,
}

impl CdApiConfig {
    /// Reads `MUCONDE_CD_API_ADDR` and `MUCONDE_CD_API_TOKEN_FILE`.
    pub fn from_env() -> Self {
        Self {
            bind_addr: std::env::var("MUCONDE_CD_API_ADDR")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            token_file: std::env::var("MUCONDE_CD_API_TOKEN_FILE")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from),
        }
    }
}

/// Reads and trims the bearer token from `path`.
///
/// Returns `None` (fail closed) if the file is missing, unreadable, not UTF-8 or empty after
/// trimming. Never falls back to the path string.
pub fn load_token_file(path: &Path) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(s) => {
            let t = s.trim();
            if t.is_empty() {
                tracing::error!(path = %path.display(), "CD API token file is empty; /api/cd/* will reject all requests");
                None
            } else {
                Some(t.to_string())
            }
        }
        Err(e) => {
            tracing::error!(path = %path.display(), error = %e, "CD API token file unreadable; /api/cd/* will reject all requests");
            None
        }
    }
}

/// Shared handler state.
#[derive(Clone)]
pub struct CdApiState {
    pub store: Arc<CdStateStore>,
    pub orchestrator: Option<Arc<DeploymentOrchestrator>>,
    token: Option<Arc<str>>,
    keep_alive: Duration,
}

impl CdApiState {
    /// `token = None` makes every request fail with `401`.
    pub fn new(store: Arc<CdStateStore>, token: Option<String>) -> Self {
        Self {
            store,
            orchestrator: None,
            token: token.map(Arc::from),
            keep_alive: DEFAULT_SSE_KEEP_ALIVE,
        }
    }

    /// Attaches a [`DeploymentOrchestrator`] so `POST /api/cd/deploy` can dispatch rollouts.
    #[must_use]
    pub fn with_orchestrator(mut self, orchestrator: Arc<DeploymentOrchestrator>) -> Self {
        self.orchestrator = Some(orchestrator);
        self
    }

    /// Overrides the SSE heartbeat interval.
    #[must_use]
    pub fn with_keep_alive(mut self, keep_alive: Duration) -> Self {
        self.keep_alive = keep_alive;
        self
    }
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
}

fn unauthorized() -> Response {
    let mut resp = (
        StatusCode::UNAUTHORIZED,
        Json(ErrorBody {
            error: "unauthorized",
        }),
    )
        .into_response();
    resp.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"muconde-cd\""),
    );
    resp
}

async fn require_bearer(State(state): State<CdApiState>, req: Request, next: Next) -> Response {
    let Some(expected) = state.token.as_deref() else {
        return unauthorized();
    };
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .map(str::trim);
    match presented {
        Some(p) if bool::from(p.as_bytes().ct_eq(expected.as_bytes())) => next.run(req).await,
        _ => unauthorized(),
    }
}

/// Returns `true` when the reverse proxy has verified an invited GitHub operator session.
///
/// Public read-only dashboard requests carry the reverse-proxy CD bearer token without an
/// operator header; those requests receive full gate checkpoint state (`tests[].name`,
/// `critical`, `state`, `duration_ms`) with `tests[].log_excerpt` redacted to `None`.
pub fn is_operator_authenticated(headers: &HeaderMap) -> bool {
    let op_auth = headers
        .get("x-operator-authenticated")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .is_some_and(|v| v.eq_ignore_ascii_case("true") || v == "1");
    if op_auth {
        return true;
    }
    headers
        .get("x-forwarded-user")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .is_some_and(|v| !v.is_empty())
}

/// `GET /api/cd/deployments` entry (newest first).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentSummary {
    pub deployment_id: String,
    pub owner: String,
    pub repo: String,
    pub service: String,
    pub artifact_digest: String,
    pub target_node: String,
    /// Slot currently serving traffic on the target.
    pub active_slot: Slot,
    /// Slot the candidate was staged into.
    pub staged_slot: Slot,
    pub outcome: GateOutcome,
    pub verdict: GateVerdict,
    pub it_passed: u32,
    pub it_failed: u32,
    pub it_total: u32,
    pub critical_failed: u32,
    pub rollback_reason: Option<RollbackReason>,
    pub tainted: bool,
    pub started_epoch_ms: u64,
    pub finished_epoch_ms: Option<u64>,
}

/// `GET /api/cd/deployments/{id}/gate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentGate {
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
    /// Remaining lease TTL at response time (0 once expired or finished).
    pub lease_ttl_remaining_ms: u64,
    pub outcome: GateOutcome,
    pub verdict: GateVerdict,
    pub rollback_reason: Option<RollbackReason>,
    pub rollback_detail: Option<String>,
    pub tainted: bool,
    pub started_epoch_ms: u64,
    pub finished_epoch_ms: Option<u64>,
    /// Contract order (`.muconde/MuConDe.yml` -> `integration_tests`, `"all"` expanded by the agent).
    pub tests: Vec<GateTestView>,
}

fn count(tests: &[GateTestView], f: impl Fn(&GateTestView) -> bool) -> u32 {
    u32::try_from(tests.iter().filter(|t| f(t)).count()).unwrap_or(u32::MAX)
}

fn lease_expired_now(d: &DeploymentRecord, now: u64) -> bool {
    d.lease_expired
        || (d.outcome == GateOutcome::Pending
            && d.lease_expires_epoch_ms != 0
            && d.lease_expires_epoch_ms <= now)
}

fn verdict_of(d: &DeploymentRecord, now: u64) -> GateVerdict {
    match d.outcome {
        GateOutcome::Promoted => GateVerdict::Promote,
        GateOutcome::RolledBack | GateOutcome::Tainted => GateVerdict::Rollback,
        GateOutcome::Pending => evaluate_gate(&d.tests, lease_expired_now(d, now)),
    }
}

impl DeploymentSummary {
    pub fn from_record(d: &DeploymentRecord, now: u64) -> Self {
        use mu_cd_ipc::TestState;
        Self {
            deployment_id: d.deployment_id.clone(),
            owner: d.owner.clone(),
            repo: d.repo.clone(),
            service: d.service.clone(),
            artifact_digest: d.artifact_digest.clone(),
            target_node: d.target_node.clone(),
            active_slot: d.active_slot,
            staged_slot: d.staged_slot,
            outcome: d.outcome,
            verdict: verdict_of(d, now),
            it_passed: count(&d.tests, |t| t.state == TestState::Passed),
            it_failed: count(&d.tests, |t| t.state == TestState::Failed),
            it_total: count(&d.tests, |_| true),
            critical_failed: count(&d.tests, |t| t.critical && t.state == TestState::Failed),
            rollback_reason: d.rollback_reason,
            tainted: d.tainted,
            started_epoch_ms: d.started_epoch_ms,
            finished_epoch_ms: d.finished_epoch_ms,
        }
    }
}

impl DeploymentGate {
    pub fn from_record(d: &DeploymentRecord, now: u64) -> Self {
        let ttl = if d.outcome == GateOutcome::Pending {
            d.lease_expires_epoch_ms.saturating_sub(now)
        } else {
            0
        };
        Self {
            deployment_id: d.deployment_id.clone(),
            owner: d.owner.clone(),
            repo: d.repo.clone(),
            service: d.service.clone(),
            artifact_digest: d.artifact_digest.clone(),
            target_node: d.target_node.clone(),
            active_slot: d.active_slot,
            staged_slot: d.staged_slot,
            restore_slot: d.restore_slot,
            lease_id: d.lease_id.clone(),
            lease_expires_epoch_ms: d.lease_expires_epoch_ms,
            lease_ttl_remaining_ms: ttl,
            outcome: d.outcome,
            verdict: verdict_of(d, now),
            rollback_reason: d.rollback_reason,
            rollback_detail: d.rollback_detail.clone(),
            tainted: d.tainted,
            started_epoch_ms: d.started_epoch_ms,
            finished_epoch_ms: d.finished_epoch_ms,
            tests: d.tests.clone(),
        }
    }
}

/// Query of `GET /api/cd/deployments`.
#[derive(Debug, Default, Deserialize)]
pub struct DeploymentsQuery {
    /// `owner/repo`, bare repo name, or service name.
    pub repo: Option<String>,
    pub limit: Option<usize>,
}

fn matches_repo(d: &DeploymentRecord, q: &str) -> bool {
    let full = format!("{}/{}", d.owner, d.repo);
    full.eq_ignore_ascii_case(q)
        || (!d.repo.is_empty() && d.repo.eq_ignore_ascii_case(q))
        || d.service.eq_ignore_ascii_case(q)
}

async fn get_deployments(
    State(state): State<CdApiState>,
    Query(q): Query<DeploymentsQuery>,
) -> Json<Vec<DeploymentSummary>> {
    let snap = state.store.snapshot();
    let now = now_epoch_ms();
    let limit = q
        .limit
        .unwrap_or(DEFAULT_DEPLOYMENTS_LIMIT)
        .clamp(1, MAX_DEPLOYMENTS_LIMIT);
    let repo = q.repo.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let out = snap
        .deployments
        .iter()
        .filter(|d| repo.is_none_or(|r| matches_repo(d, r)))
        .take(limit)
        .map(|d| DeploymentSummary::from_record(d, now))
        .collect();
    Json(out)
}

async fn get_gate(
    State(state): State<CdApiState>,
    headers: HeaderMap,
    AxPath(id): AxPath<String>,
) -> Response {
    let snap = state.store.snapshot();
    match snap.deployment(&id) {
        Some(d) => {
            let mut gate = DeploymentGate::from_record(d, now_epoch_ms());
            if !is_operator_authenticated(&headers) {
                for test in &mut gate.tests {
                    test.log_excerpt = None;
                }
            }
            Json(gate).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: "deployment_not_found",
            }),
        )
            .into_response(),
    }
}

async fn get_leases(State(state): State<CdApiState>) -> Json<Vec<LeaseView>> {
    let snap = state.store.snapshot();
    let now = now_epoch_ms();
    Json(
        snap.leases
            .iter()
            .cloned()
            .map(|mut l| {
                l.ttl_remaining_ms = l.expires_epoch_ms.saturating_sub(now);
                l
            })
            .collect(),
    )
}

/// Converts a broadcast receiver into an SSE stream. A consumer that lags behind the buffer is
/// dropped (the stream ends) so it reconnects and re-fetches a fresh snapshot.
pub fn cd_event_stream(
    rx: broadcast::Receiver<CdEvent>,
) -> impl Stream<Item = Result<Event, Infallible>> + Send + 'static {
    futures_util::stream::unfold(rx, |mut rx| async move {
        match rx.recv().await {
            Ok(ev) => {
                let sse = Event::default().event(ev.event_name()).data(ev.to_json());
                Some((Ok(sse), rx))
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!(
                    skipped = n,
                    "Dropping slow /api/cd/events consumer (lagged)"
                );
                None
            }
            Err(broadcast::error::RecvError::Closed) => None,
        }
    })
}

async fn get_events(State(state): State<CdApiState>) -> impl IntoResponse {
    let stream = cd_event_stream(state.store.subscribe());
    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(state.keep_alive)
            .text("heartbeat"),
    )
}

/// Request payload for `POST /api/cd/deploy`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployTriggerRequest {
    pub repo: Option<String>,
    pub artifact_sha256: String,
    pub config: Option<MuConDeConfig>,
    pub manifest_yaml: Option<String>,
    pub repo_path: Option<String>,
    #[serde(default)]
    pub wait: bool,
}

/// Response payload for `POST /api/cd/deploy`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployTriggerResponse {
    pub accepted: bool,
    pub service: String,
    pub target_nodes: Vec<String>,
    pub artifact_sha256: String,
    pub promoted_nodes: Vec<String>,
    pub rolled_back_nodes: Vec<String>,
}

async fn post_deploy(
    State(state): State<CdApiState>,
    Json(req): Json<DeployTriggerRequest>,
) -> Response {
    let Some(orchestrator) = state.orchestrator.clone() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "orchestrator_unavailable" })),
        )
            .into_response();
    };

    let config = if let Some(cfg) = req.config {
        if let Err(e) = cfg.validate() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("invalid_contract: {e}") })),
            )
                .into_response();
        }
        cfg
    } else if let Some(ref yaml) = req.manifest_yaml {
        match MuConDeConfig::from_yaml_str(yaml) {
            Ok(cfg) => cfg,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": format!("invalid_manifest_yaml: {e}") })),
                )
                    .into_response();
            }
        }
    } else if let Some(ref path) = req.repo_path {
        match MuConDeConfig::from_file(path) {
            Ok(cfg) => cfg,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": format!("invalid_repo_path: {e}") })),
                )
                    .into_response();
            }
        }
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "missing_contract" })),
        )
            .into_response();
    };

    let resolved_nodes = config.target_nodes.clone();
    let service = config.service.clone();
    let digest = req.artifact_sha256.trim().to_string();
    if digest.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "empty_artifact_sha256" })),
        )
            .into_response();
    }

    if req.wait {
        match orchestrator
            .orchestrate_rollout_for_repo(&config, &digest, req.repo.as_deref())
            .await
        {
            Ok(outcomes) => {
                let mut promoted_nodes = Vec::new();
                let mut rolled_back_nodes = Vec::new();
                for o in &outcomes {
                    match o {
                        crate::orchestrator::DeploymentOutcome::Promoted {
                            target_node, ..
                        } => {
                            promoted_nodes.push(target_node.clone());
                        }
                        crate::orchestrator::DeploymentOutcome::RolledBack {
                            target_node, ..
                        } => {
                            rolled_back_nodes.push(target_node.clone());
                        }
                    }
                }
                let status = if rolled_back_nodes.is_empty() {
                    StatusCode::OK
                } else {
                    StatusCode::UNPROCESSABLE_ENTITY
                };
                (
                    status,
                    Json(DeployTriggerResponse {
                        accepted: rolled_back_nodes.is_empty(),
                        service,
                        target_nodes: resolved_nodes,
                        artifact_sha256: digest,
                        promoted_nodes,
                        rolled_back_nodes,
                    }),
                )
                    .into_response()
            }
            Err(e) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response(),
        }
    } else {
        let digest_bg = digest.clone();
        let repo_bg = req.repo.clone();
        let cfg_bg = config.clone();
        tokio::spawn(async move {
            if let Err(e) = orchestrator
                .orchestrate_rollout_for_repo(&cfg_bg, &digest_bg, repo_bg.as_deref())
                .await
            {
                tracing::error!(
                    service = %cfg_bg.service,
                    digest = %digest_bg,
                    error = %e,
                    "Asynchronous CD rollout failed"
                );
            }
        });
        (
            StatusCode::ACCEPTED,
            Json(DeployTriggerResponse {
                accepted: true,
                service,
                target_nodes: resolved_nodes,
                artifact_sha256: digest,
                promoted_nodes: Vec::new(),
                rolled_back_nodes: Vec::new(),
            }),
        )
            .into_response()
    }
}

/// Builds the `/api/cd/*` router; every route sits behind the bearer-token gate.
pub fn router(state: CdApiState) -> Router {
    Router::new()
        .route("/api/cd/deployments", get(get_deployments))
        .route("/api/cd/deployments/{id}/gate", get(get_gate))
        .route("/api/cd/leases", get(get_leases))
        .route("/api/cd/events", get(get_events))
        .route("/api/cd/deploy", post(post_deploy))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_bearer,
        ))
        .with_state(state)
}

/// Serves the router on an already-bound listener until the task is dropped.
pub async fn serve(listener: TcpListener, state: CdApiState) -> std::io::Result<()> {
    axum::serve(listener, router(state)).await
}

/// Binds and spawns the CD API when `config.bind_addr` is set. Returns the bound address.
pub async fn spawn_cd_api(
    config: &CdApiConfig,
    store: Arc<CdStateStore>,
) -> std::io::Result<Option<(SocketAddr, tokio::task::JoinHandle<()>)>> {
    spawn_cd_api_with_orchestrator(config, store, None).await
}

/// Binds and spawns the CD API with an attached [`DeploymentOrchestrator`] for `POST /api/cd/deploy`.
pub async fn spawn_cd_api_with_orchestrator(
    config: &CdApiConfig,
    store: Arc<CdStateStore>,
    orchestrator: Option<Arc<DeploymentOrchestrator>>,
) -> std::io::Result<Option<(SocketAddr, tokio::task::JoinHandle<()>)>> {
    let Some(addr) = config.bind_addr.as_deref() else {
        return Ok(None);
    };
    let token = match config.token_file.as_deref() {
        Some(p) => load_token_file(p),
        None => {
            tracing::error!(
                "MUCONDE_CD_API_TOKEN_FILE not set; /api/cd/* will reject all requests"
            );
            None
        }
    };
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    let mut state = CdApiState::new(store, token);
    if let Some(orch) = orchestrator {
        state = state.with_orchestrator(orch);
    }
    let handle = tokio::spawn(async move {
        if let Err(e) = serve(listener, state).await {
            tracing::error!(error = %e, "CD API listener stopped");
        }
    });
    tracing::info!(addr = %local, "MuConDe CD status API listening (bearer auth)");
    Ok(Some((local, handle)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_load_token_file_trims_and_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("token");
        std::fs::File::create(&p)
            .unwrap()
            .write_all(b"  s3cret-token\n")
            .unwrap();
        assert_eq!(load_token_file(&p).as_deref(), Some("s3cret-token"));

        let empty = dir.path().join("empty");
        std::fs::write(&empty, "  \n").unwrap();
        assert_eq!(load_token_file(&empty), None);

        let missing = dir.path().join("missing");
        assert_eq!(load_token_file(&missing), None);
    }

    #[test]
    fn test_config_disabled_by_default() {
        let c = CdApiConfig::default();
        assert!(c.bind_addr.is_none());
        assert!(c.token_file.is_none());
    }

    #[test]
    fn test_is_operator_authenticated_headers() {
        let mut h = HeaderMap::new();
        assert!(!is_operator_authenticated(&h));

        h.insert(
            "x-operator-authenticated",
            HeaderValue::from_static("false"),
        );
        assert!(!is_operator_authenticated(&h));

        h.insert("x-operator-authenticated", HeaderValue::from_static("TRUE"));
        assert!(is_operator_authenticated(&h));

        h.insert("x-operator-authenticated", HeaderValue::from_static("1"));
        assert!(is_operator_authenticated(&h));

        h.remove("x-operator-authenticated");
        h.insert("x-forwarded-user", HeaderValue::from_static("   "));
        assert!(!is_operator_authenticated(&h));

        h.insert("x-forwarded-user", HeaderValue::from_static("octocat"));
        assert!(is_operator_authenticated(&h));
    }
}
