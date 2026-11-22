//! Continuous Delivery and A/B Gate HTTP API (`/api/cd/*`) guarded by `mu-auth` policy folios.
//!
//! Served by axum on a **separate listener**, disabled unless `MU_CD_CONTROLLER_API_ADDR` (or
//! `MUCONDE_CD_API_ADDR`) is set.
//! Interactive operator sessions authenticate through the edge reverse proxy (`X-Proxy-Secret` and
//! `X-Forwarded-User`) and are evaluated against `mu-auth` policy folios (`cd:runs.read`,
//! `cd:steps.read`, `ab:slots.read`, `ab:gate.logs.read`, and `ab:rollback`, with zero manual
//! `ab:promote` endpoint). Service-to-service callers use `MU_CD_CONTROLLER_API_TOKEN_FILE` (or
//! `MUCONDE_CD_API_TOKEN_FILE`) strictly for service-scoped reads and CI-to-CD triggers, failing
//! closed (`401`/`403`) whenever credentials or required policy folios are missing.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path as AxPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::stream::Stream;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

use crate::auth::{
    load_secret_file, AuthRejection, AuthorizedCaller, CdAuthorizer, POLICY_AB_ROLLBACK,
    POLICY_AB_SLOTS_READ, POLICY_CD_RUNS_READ, POLICY_CD_SERVICE_DEPLOY,
};
use crate::cd_state::{
    evaluate_gate, now_epoch_ms, AbRollbackRequestDto, CdEvent, CdStateStore, DeploymentRecord,
    GateOutcome, GateTestView, GateVerdict, LeaseView, RollbackReason, Slot,
};
use crate::contract::MuConDeConfig;
use crate::error::{OrchestratorError, PolicyRepoError};
use crate::orchestrator::DeploymentOrchestrator;
use crate::policy_repo::{
    validate_git_commit_sha, validate_service_identifier, validate_sha256_hex, PolicyRepository,
};
use crate::telemetry::{build_cd_log, now_unix_nano};
use mu_observable_ipc::TraceContext;

/// Default `limit` for `GET /api/cd/deployments` and `GET /api/cd/runs`.
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
    /// File containing the service-to-service bearer token.
    pub token_file: Option<PathBuf>,
    /// File containing the shared edge proxy secret (`X-Proxy-Secret`).
    pub proxy_secret_file: Option<PathBuf>,
    /// GitHub logins bootstrapped with baseline CD/A|B read + gate-inspector folios
    /// (`MU_CD_CONTROLLER_OPERATOR_USERS` / `MUCONDE_OPERATOR_USERS`, comma-separated).
    pub operator_users: Vec<String>,
}

impl CdApiConfig {
    /// Reads `MU_CD_CONTROLLER_*` / `MU_CD_*` environment variables with fallback to legacy
    /// `MUCONDE_*` names.
    pub fn from_env() -> Self {
        Self::from_env_lookup(&|key| std::env::var(key).ok())
    }

    /// Pure parser reading CD API configuration via a caller-supplied environment lookup.
    pub fn from_env_lookup(lookup: &dyn Fn(&str) -> Option<String>) -> Self {
        let operator_users = crate::first_non_empty_var(
            lookup,
            &[
                "MU_CD_CONTROLLER_OPERATOR_USERS",
                "MU_CD_OPERATOR_USERS",
                "MUCONDE_OPERATOR_USERS",
            ],
        )
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
        Self {
            bind_addr: crate::first_non_empty_var(
                lookup,
                &[
                    "MU_CD_CONTROLLER_API_ADDR",
                    "MU_CD_API_ADDR",
                    "MUCONDE_CD_API_ADDR",
                ],
            ),
            token_file: crate::first_non_empty_var(
                lookup,
                &[
                    "MU_CD_CONTROLLER_API_TOKEN_FILE",
                    "MU_CD_API_TOKEN_FILE",
                    "MUCONDE_CD_API_TOKEN_FILE",
                ],
            )
            .map(PathBuf::from),
            proxy_secret_file: crate::first_non_empty_var(
                lookup,
                &[
                    "MU_CD_CONTROLLER_PROXY_SECRET_FILE",
                    "MU_CD_PROXY_SECRET_FILE",
                    "MUCONDE_PROXY_SECRET_FILE",
                ],
            )
            .map(PathBuf::from),
            operator_users,
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
    pub policy_repo: Option<Arc<PolicyRepository>>,
    pub authorizer: CdAuthorizer,
    keep_alive: Duration,
}

impl CdApiState {
    /// `token = None` (with no configured edge proxy secret) fails closed with `401`.
    pub fn new(store: Arc<CdStateStore>, token: Option<String>) -> Self {
        Self {
            store,
            orchestrator: None,
            policy_repo: None,
            authorizer: CdAuthorizer::new(token),
            keep_alive: DEFAULT_SSE_KEEP_ALIVE,
        }
    }

    /// Attaches a [`DeploymentOrchestrator`] for `POST /api/cd/deploy` and emergency rollback.
    #[must_use]
    pub fn with_orchestrator(mut self, orchestrator: Arc<DeploymentOrchestrator>) -> Self {
        if self.policy_repo.is_none() {
            self.policy_repo = orchestrator.policy_repo().cloned();
        }
        self.orchestrator = Some(orchestrator);
        self
    }

    /// Attaches an authoritative signature-verified [`PolicyRepository`] for zero-trust
    /// `POST /api/cd/deploy` resolution and `POST /api/cd/policy/refresh`.
    #[must_use]
    pub fn with_policy_repo(mut self, policy_repo: Arc<PolicyRepository>) -> Self {
        self.policy_repo = Some(policy_repo);
        self
    }

    /// Replaces the `mu-auth` policy-folio [`CdAuthorizer`].
    #[must_use]
    pub fn with_authorizer(mut self, authorizer: CdAuthorizer) -> Self {
        self.authorizer = authorizer;
        self
    }

    /// Configures the expected `X-Proxy-Secret` header for authenticated `X-Forwarded-User` calls.
    #[must_use]
    pub fn with_proxy_secret(mut self, secret: Option<String>) -> Self {
        self.authorizer = self.authorizer.with_proxy_secret(secret);
        self
    }

    /// Bootstraps configured operator logins (e.g. from `MU_CD_CONTROLLER_OPERATOR_USERS` or
    /// `MUCONDE_OPERATOR_USERS`) on the underlying [`CdAuthorizer`].
    #[must_use]
    pub fn with_operator_users<I, S>(mut self, logins: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.authorizer = self.authorizer.with_operator_users(logins, now_epoch_ms());
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

fn authorize(
    state: &CdApiState,
    headers: &HeaderMap,
    required_policy: &str,
) -> Result<AuthorizedCaller, AuthRejection> {
    state
        .authorizer
        .authorize_at(headers, required_policy, now_epoch_ms())
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
    /// Contract order (`.mucd/mu-cd.yml` / legacy `.muconde/MuConDe.yml` -> `integration_tests`, `"all"` expanded by the agent).
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

/// Query of `GET /api/cd/runs`.
#[derive(Debug, Default, Deserialize)]
pub struct CdRunsQuery {
    /// Ecosystem filter (`cargo`, `dotnet`/`.net`, `maven`, or custom).
    pub ecosystem: Option<String>,
    /// `owner/repo` or bare repo name filter.
    pub repo: Option<String>,
    pub limit: Option<usize>,
}

async fn get_cd_runs(
    State(state): State<CdApiState>,
    headers: HeaderMap,
    Query(q): Query<CdRunsQuery>,
) -> Response {
    let caller = match authorize(&state, &headers, POLICY_CD_RUNS_READ) {
        Ok(c) => c,
        Err(rej) => return rej.into_response(),
    };
    let limit = q
        .limit
        .unwrap_or(DEFAULT_DEPLOYMENTS_LIMIT)
        .clamp(1, MAX_DEPLOYMENTS_LIMIT);
    let mut runs = state
        .store
        .list_cd_runs(q.ecosystem.as_deref(), q.repo.as_deref(), Some(limit));
    if !caller.can_read_steps {
        for run in &mut runs {
            run.steps.clear();
        }
    }
    Json(runs).into_response()
}

async fn get_deployments(
    State(state): State<CdApiState>,
    headers: HeaderMap,
    Query(q): Query<DeploymentsQuery>,
) -> Response {
    if let Err(rej) = authorize(&state, &headers, POLICY_AB_SLOTS_READ) {
        return rej.into_response();
    }
    let snap = state.store.snapshot();
    let now = now_epoch_ms();
    let limit = q
        .limit
        .unwrap_or(DEFAULT_DEPLOYMENTS_LIMIT)
        .clamp(1, MAX_DEPLOYMENTS_LIMIT);
    let repo = q.repo.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let out: Vec<DeploymentSummary> = snap
        .deployments
        .iter()
        .filter(|d| repo.is_none_or(|r| matches_repo(d, r)))
        .take(limit)
        .map(|d| DeploymentSummary::from_record(d, now))
        .collect();
    Json(out).into_response()
}

async fn get_gate(
    State(state): State<CdApiState>,
    headers: HeaderMap,
    AxPath(id): AxPath<String>,
) -> Response {
    let caller = match authorize(&state, &headers, POLICY_AB_SLOTS_READ) {
        Ok(c) => c,
        Err(rej) => return rej.into_response(),
    };
    let snap = state.store.snapshot();
    match snap.deployment(&id) {
        Some(d) => {
            let mut gate = DeploymentGate::from_record(d, now_epoch_ms());
            if !caller.can_read_gate_logs {
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

async fn post_rollback(
    State(state): State<CdApiState>,
    headers: HeaderMap,
    AxPath(id): AxPath<String>,
    body: Bytes,
) -> Response {
    if let Err(rej) = authorize(&state, &headers, POLICY_AB_ROLLBACK) {
        return rej.into_response();
    }
    let req: AbRollbackRequestDto = if body.iter().all(|b| b.is_ascii_whitespace()) {
        AbRollbackRequestDto::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(parsed) => parsed,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": format!("invalid_rollback_payload: {e}") })),
                )
                    .into_response();
            }
        }
    };
    let Some(orchestrator) = state.orchestrator.clone() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorBody {
                error: "orchestrator_unavailable",
            }),
        )
            .into_response();
    };
    match orchestrator
        .emergency_rollback(&id, req.note.as_deref())
        .await
    {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(OrchestratorError::DeploymentNotFound(_)) => (
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: "deployment_not_found",
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({
                "error": "rollback_failed",
                "detail": e.to_string(),
            })),
        )
            .into_response(),
    }
}

async fn get_leases(State(state): State<CdApiState>, headers: HeaderMap) -> Response {
    if let Err(rej) = authorize(&state, &headers, POLICY_AB_SLOTS_READ) {
        return rej.into_response();
    }
    let snap = state.store.snapshot();
    let now = now_epoch_ms();
    let out: Vec<LeaseView> = snap
        .leases
        .iter()
        .cloned()
        .map(|mut l| {
            l.ttl_remaining_ms = l.expires_epoch_ms.saturating_sub(now);
            l
        })
        .collect();
    Json(out).into_response()
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

async fn get_events(State(state): State<CdApiState>, headers: HeaderMap) -> Response {
    if let Err(rej) = authorize(&state, &headers, POLICY_AB_SLOTS_READ) {
        return rej.into_response();
    }
    let stream = cd_event_stream(state.store.subscribe());
    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(state.keep_alive)
                .text("heartbeat"),
        )
        .into_response()
}

/// Request payload for `POST /api/cd/deploy`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployTriggerRequest {
    pub repo: Option<String>,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub artifact_sha256: Option<String>,
    pub config: Option<MuConDeConfig>,
    pub manifest_yaml: Option<String>,
    pub repo_path: Option<String>,
    #[serde(default)]
    pub wait: bool,
    #[serde(default)]
    pub git_commit: Option<String>,
    #[serde(default)]
    pub binary_digest: Option<String>,
    #[serde(default)]
    pub it_archive_digest: Option<String>,
    #[serde(default)]
    pub bundle_id: Option<String>,
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

fn collect_legacy_fields(req: &DeployTriggerRequest) -> Vec<&'static str> {
    let mut present = Vec::new();
    if req.config.is_some() {
        present.push("config");
    }
    if req.manifest_yaml.is_some() {
        present.push("manifest_yaml");
    }
    if req.repo_path.is_some() {
        present.push("repo_path");
    }
    present
}

fn resolve_requested_service(req: &DeployTriggerRequest) -> Option<String> {
    if let Some(svc) = req
        .service
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Some(svc.to_string());
    }
    req.repo
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|repo| repo.rsplit('/').next())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

fn resolve_effective_digest(req: &DeployTriggerRequest) -> Result<Option<String>, &'static str> {
    let bin = req
        .binary_digest
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let legacy = req
        .artifact_sha256
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if let (Some(b), Some(a)) = (bin, legacy) {
        if !b.eq_ignore_ascii_case(a) {
            return Err("digest_mismatch");
        }
    }
    Ok(bin.or(legacy).map(ToOwned::to_owned))
}

async fn emit_legacy_manifest_deprecation(
    orchestrator: &DeploymentOrchestrator,
    incoming_trace: Option<TraceContext>,
    service: &str,
    repo: &str,
    legacy_fields: &[&'static str],
    ignored_in_favor_of_policy_repo: bool,
) {
    let detail = if ignored_in_favor_of_policy_repo {
        "legacy_manifest_fallback: ignoring caller-supplied legacy contract fields in favor of verified deployment policy repository"
    } else {
        "legacy_manifest_fallback: serving caller-supplied legacy contract because deployment policy repository is unconfigured"
    };
    tracing::warn!(
        deprecation = "legacy_manifest_fallback",
        service = %service,
        repo = %repo,
        legacy_fields = ?legacy_fields,
        ignored_by_policy_repo = ignored_in_favor_of_policy_repo,
        "{detail}"
    );
    if let Some(sink) = orchestrator.telemetry_sink() {
        let now_ns = now_unix_nano();
        let trace = incoming_trace.unwrap_or_else(|| {
            TraceContext::from_seed(
                now_ns as u64,
                (now_ns as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1,
                1,
                true,
            )
        });
        let entry = build_cd_log(
            trace.trace_id,
            trace.span_id,
            now_ns,
            13,
            "WARN",
            "controller",
            detail,
            serde_json::json!({
                "deprecation": "legacy_manifest_fallback",
                "service": service,
                "repo": repo,
                "legacy_fields": legacy_fields,
                "ignored_by_policy_repo": ignored_in_favor_of_policy_repo,
            }),
        );
        sink.emit_logs(vec![entry]).await;
    }
}

fn rollout_outcomes_response(
    outcomes_res: Result<Vec<crate::orchestrator::DeploymentOutcome>, OrchestratorError>,
    service: String,
    target_nodes: Vec<String>,
    digest: String,
) -> Response {
    match outcomes_res {
        Ok(outcomes) => {
            let mut promoted_nodes = Vec::new();
            let mut rolled_back_nodes = Vec::new();
            for o in &outcomes {
                match o {
                    crate::orchestrator::DeploymentOutcome::Promoted { target_node, .. } => {
                        promoted_nodes.push(target_node.clone());
                    }
                    crate::orchestrator::DeploymentOutcome::RolledBack { target_node, .. } => {
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
                    target_nodes,
                    artifact_sha256: digest,
                    promoted_nodes,
                    rolled_back_nodes,
                }),
            )
                .into_response()
        }
        Err(OrchestratorError::ArtifactTainted(d)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "artifact_tainted", "digest": d })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn post_deploy_with_policy_repo(
    orchestrator: Arc<DeploymentOrchestrator>,
    policy_repo: Arc<PolicyRepository>,
    req: DeployTriggerRequest,
    incoming_trace: Option<TraceContext>,
    legacy_fields: Vec<&'static str>,
    raw_digest: Option<String>,
) -> Response {
    let Some(raw_service) = resolve_requested_service(&req) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid_service" })),
        )
            .into_response();
    };
    let service = match validate_service_identifier(&raw_service) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid_service" })),
            )
                .into_response();
        }
    };

    let digest = match raw_digest.as_deref().map(validate_sha256_hex) {
        Some(Ok(hex)) => hex,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid_digest" })),
            )
                .into_response();
        }
    };

    let git_commit_trimmed = req
        .git_commit
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if legacy_fields.is_empty() {
        match git_commit_trimmed.map(validate_git_commit_sha) {
            Some(Ok(_)) => {}
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "invalid_git_commit" })),
                )
                    .into_response();
            }
        }
    } else if let Some(commit) = git_commit_trimmed {
        if validate_git_commit_sha(commit).is_err() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid_git_commit" })),
            )
                .into_response();
        }
    }

    let repo_label = req.repo.as_deref().unwrap_or(&service);
    if !legacy_fields.is_empty() {
        emit_legacy_manifest_deprecation(
            &orchestrator,
            incoming_trace,
            &service,
            repo_label,
            &legacy_fields,
            true,
        )
        .await;
    }

    let verified = match policy_repo.ensure_verified().await {
        Ok(bundle) => bundle,
        Err(err) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "deploy_repo_unverified",
                    "detail": err.to_string(),
                })),
            )
                .into_response();
        }
    };

    let Some(contract) = verified.service_contracts.get(&service) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "service_contract_not_found",
                "service": service,
            })),
        )
            .into_response();
    };

    let it_archive_digest = match req
        .it_archive_digest
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw) => match validate_sha256_hex(raw) {
            Ok(hex) => Some(hex),
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "invalid_it_archive_digest" })),
                )
                    .into_response();
            }
        },
        None if contract.requires_it_archive() => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid_it_archive_digest" })),
            )
                .into_response();
        }
        None => None,
    };

    match orchestrator.is_digest_tainted(&digest).await {
        Ok(true) => {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "artifact_tainted",
                    "digest": digest,
                })),
            )
                .into_response();
        }
        Ok(false) => {}
        Err(err) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "registry_unavailable",
                    "detail": err.to_string(),
                })),
            )
                .into_response();
        }
    }

    let rollout_id = format!("rollout-{}", uuid::Uuid::new_v4());
    let bundle_id = req
        .bundle_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let snapshot = match policy_repo.pin_deployment_snapshot_from_verified(
        &verified,
        &rollout_id,
        &service,
        it_archive_digest.as_deref(),
        bundle_id,
    ) {
        Ok(snap) => snap,
        Err(PolicyRepoError::ServiceContractNotFound(svc)) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": "service_contract_not_found",
                    "service": svc,
                })),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "deploy_repo_unverified",
                    "detail": err.to_string(),
                })),
            )
                .into_response();
        }
    };

    let target_nodes = snapshot.service_contract.effective_target_nodes().to_vec();
    if req.wait {
        let res = orchestrator
            .orchestrate_rollout_with_snapshot(
                snapshot,
                &digest,
                req.repo.as_deref(),
                incoming_trace,
            )
            .await;
        rollout_outcomes_response(res, service, target_nodes, digest)
    } else {
        let digest_bg = digest.clone();
        let repo_bg = req.repo.clone();
        let svc_bg = service.clone();
        tokio::spawn(async move {
            if let Err(e) = orchestrator
                .orchestrate_rollout_with_snapshot(
                    snapshot,
                    &digest_bg,
                    repo_bg.as_deref(),
                    incoming_trace,
                )
                .await
            {
                tracing::error!(
                    service = %svc_bg,
                    digest = %digest_bg,
                    error = %e,
                    "Asynchronous verified-policy CD rollout failed"
                );
            }
        });
        (
            StatusCode::ACCEPTED,
            Json(DeployTriggerResponse {
                accepted: true,
                service,
                target_nodes,
                artifact_sha256: digest,
                promoted_nodes: Vec::new(),
                rolled_back_nodes: Vec::new(),
            }),
        )
            .into_response()
    }
}

async fn post_deploy(
    State(state): State<CdApiState>,
    headers: HeaderMap,
    Json(req): Json<DeployTriggerRequest>,
) -> Response {
    if let Err(rej) = authorize(&state, &headers, POLICY_CD_SERVICE_DEPLOY) {
        return rej.into_response();
    }
    let Some(orchestrator) = state.orchestrator.clone() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "orchestrator_unavailable" })),
        )
            .into_response();
    };

    let incoming_trace = headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| mu_observable_ipc::TraceContext::parse_traceparent(s).ok());

    let legacy_fields = collect_legacy_fields(&req);
    let raw_digest = match resolve_effective_digest(&req) {
        Ok(d) => d,
        Err(code) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": code })),
            )
                .into_response();
        }
    };

    if let Some(policy_repo) = state
        .policy_repo
        .clone()
        .or_else(|| orchestrator.policy_repo().cloned())
    {
        return post_deploy_with_policy_repo(
            orchestrator,
            policy_repo,
            req,
            incoming_trace,
            legacy_fields,
            raw_digest,
        )
        .await;
    }

    if legacy_fields.is_empty() {
        if let Some(raw_service) = resolve_requested_service(&req) {
            if validate_service_identifier(&raw_service).is_err() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "invalid_service" })),
                )
                    .into_response();
            }
        }
        if raw_digest
            .as_deref()
            .is_none_or(|d| validate_sha256_hex(d).is_err())
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid_digest" })),
            )
                .into_response();
        }
        if req
            .git_commit
            .as_deref()
            .is_none_or(|c| validate_git_commit_sha(c).is_err())
        {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid_git_commit" })),
            )
                .into_response();
        }
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "deploy_repo_unverified",
                "detail": "deployment policy repository is not configured",
            })),
        )
            .into_response();
    }

    let mut config = if let Some(cfg) = req.config {
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

    if config.it_archive_digest.is_none() {
        if let Some(ref it_digest) = req.it_archive_digest {
            let trimmed = it_digest.trim();
            if !trimmed.is_empty() {
                config.it_archive_digest = Some(trimmed.to_string());
            }
        }
    }

    let resolved_nodes = crate::orchestrator::resolve_target_nodes(config.effective_target_nodes());
    let service = config.service.clone();
    let Some(digest) = raw_digest else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "empty_artifact_sha256" })),
        )
            .into_response();
    };

    let repo_label = req.repo.as_deref().unwrap_or(&service);
    emit_legacy_manifest_deprecation(
        &orchestrator,
        incoming_trace,
        &service,
        repo_label,
        &legacy_fields,
        false,
    )
    .await;

    if req.wait {
        let res = orchestrator
            .orchestrate_rollout_for_repo_with_trace(
                &config,
                &digest,
                req.repo.as_deref(),
                incoming_trace,
            )
            .await;
        rollout_outcomes_response(res, service, resolved_nodes, digest)
    } else {
        let digest_bg = digest.clone();
        let repo_bg = req.repo.clone();
        let cfg_bg = config.clone();
        let trace_bg = incoming_trace;
        tokio::spawn(async move {
            if let Err(e) = orchestrator
                .orchestrate_rollout_for_repo_with_trace(
                    &cfg_bg,
                    &digest_bg,
                    repo_bg.as_deref(),
                    trace_bg,
                )
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

async fn post_policy_refresh(State(state): State<CdApiState>, headers: HeaderMap) -> Response {
    if let Err(rej) = authorize(&state, &headers, POLICY_CD_SERVICE_DEPLOY) {
        return rej.into_response();
    }
    let Some(policy_repo) = state.policy_repo.clone().or_else(|| {
        state
            .orchestrator
            .as_ref()
            .and_then(|o| o.policy_repo().cloned())
    }) else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "policy_repo_unconfigured" })),
        )
            .into_response();
    };
    match policy_repo.refresh_and_verify().await {
        Ok(summary) => (StatusCode::OK, Json(summary)).into_response(),
        Err(err) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "deploy_repo_unverified",
                "detail": err.to_string(),
            })),
        )
            .into_response(),
    }
}

async fn get_health() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({
            "status": "ok",
            "service": "mu-cd-controller",
        })),
    )
}

/// Builds the `/api/cd/*` router; every `/api/cd/*` route sits behind the bearer-token gate.
pub fn router(state: CdApiState) -> Router {
    Router::new()
        .route("/health", get(get_health))
        .route("/api/cd/runs", get(get_cd_runs))
        .route("/api/cd/deployments", get(get_deployments))
        .route("/api/cd/deployments/{id}/gate", get(get_gate))
        .route("/api/cd/deployments/{id}/rollback", post(post_rollback))
        .route("/api/cd/leases", get(get_leases))
        .route("/api/cd/events", get(get_events))
        .route("/api/cd/deploy", post(post_deploy))
        .route("/api/cd/policy/refresh", post(post_policy_refresh))
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
                "MU_CD_CONTROLLER_API_TOKEN_FILE / MUCONDE_CD_API_TOKEN_FILE not set; /api/cd/* will reject all requests"
            );
            None
        }
    };
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    let proxy_secret = config
        .proxy_secret_file
        .as_deref()
        .and_then(load_secret_file);
    let mut state = CdApiState::new(store, token)
        .with_proxy_secret(proxy_secret)
        .with_operator_users(&config.operator_users);
    if let Some(orch) = orchestrator {
        state = state.with_orchestrator(orch);
    }
    let handle = tokio::spawn(async move {
        if let Err(e) = serve(listener, state).await {
            tracing::error!(error = %e, "CD API listener stopped");
        }
    });
    tracing::info!(addr = %local, "mu-cd-controller CD API listening (mu-auth folio + bearer auth)");
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
        assert!(c.proxy_secret_file.is_none());
        assert!(c.operator_users.is_empty());
    }

    #[test]
    fn test_cd_api_config_env_precedence_and_legacy_fallback() {
        use std::collections::HashMap;

        let canonical = HashMap::from([
            ("MU_CD_CONTROLLER_API_ADDR", "127.0.0.1:9447"),
            ("MU_CD_API_ADDR", "127.0.0.1:8448"),
            ("MUCONDE_CD_API_ADDR", "127.0.0.1:8447"),
            (
                "MU_CD_CONTROLLER_API_TOKEN_FILE",
                "/etc/mu-cd-controller/api.token",
            ),
            ("MUCONDE_CD_API_TOKEN_FILE", "/etc/muconde/api.token"),
            ("MU_CD_PROXY_SECRET_FILE", "/etc/mu-cd/proxy.secret"),
            ("MUCONDE_PROXY_SECRET_FILE", "/etc/muconde/proxy.secret"),
            ("MU_CD_CONTROLLER_OPERATOR_USERS", "alice, bob"),
            ("MUCONDE_OPERATOR_USERS", "legacy"),
        ]);
        let cfg = CdApiConfig::from_env_lookup(&|k| canonical.get(k).map(|v| (*v).to_string()));
        assert_eq!(cfg.bind_addr.as_deref(), Some("127.0.0.1:9447"));
        assert_eq!(
            cfg.token_file,
            Some(PathBuf::from("/etc/mu-cd-controller/api.token"))
        );
        assert_eq!(
            cfg.proxy_secret_file,
            Some(PathBuf::from("/etc/mu-cd/proxy.secret"))
        );
        assert_eq!(cfg.operator_users, vec!["alice", "bob"]);

        let legacy = HashMap::from([
            ("MUCONDE_CD_API_ADDR", "127.0.0.1:8447"),
            ("MUCONDE_CD_API_TOKEN_FILE", "/etc/muconde/api.token"),
            ("MUCONDE_PROXY_SECRET_FILE", "/etc/muconde/proxy.secret"),
            ("MUCONDE_OPERATOR_USERS", "carol"),
        ]);
        let cfg_legacy = CdApiConfig::from_env_lookup(&|k| legacy.get(k).map(|v| (*v).to_string()));
        assert_eq!(cfg_legacy.bind_addr.as_deref(), Some("127.0.0.1:8447"));
        assert_eq!(
            cfg_legacy.token_file,
            Some(PathBuf::from("/etc/muconde/api.token"))
        );
        assert_eq!(
            cfg_legacy.proxy_secret_file,
            Some(PathBuf::from("/etc/muconde/proxy.secret"))
        );
        assert_eq!(cfg_legacy.operator_users, vec!["carol"]);
    }
}
