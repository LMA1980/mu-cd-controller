//! Authorization adapter bridging edge proxy / service tokens with `mu-auth` policy folios.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::{Arc, RwLock};

use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use mu_auth::{
    canonical_super_operator_folios, AuthAuthority, FolioCatalog, FolioError, FolioId, Principal,
    RoleActivation, RoleCatalog, RoleFolioIndex, RoleId, RoleLease, RoleLeases, RoleSpec,
    StepUpRequirement, SubsystemId, SUPER_OPERATOR_ROLE_ID,
};
use serde_json::json;
use subtle::ConstantTimeEq;

/// Canonical policy identifier required to read ecosystem-agnostic CD runs (`GET /api/cd/runs`).
pub const POLICY_CD_RUNS_READ: &str = "cd:runs.read";
/// Canonical policy identifier controlling step-level CD trace visibility (`GET /api/cd/runs`).
pub const POLICY_CD_STEPS_READ: &str = "cd:steps.read";
/// Canonical policy identifier required to read A/B slots, gates, leases, and SSE events.
pub const POLICY_AB_SLOTS_READ: &str = "ab:slots.read";
/// Canonical policy identifier required to view unredacted integration-test `log_excerpt` fields.
pub const POLICY_AB_GATE_LOGS_READ: &str = "ab:gate.logs.read";
/// Canonical policy identifier required to invoke emergency `POST /api/cd/deployments/{id}/rollback`.
pub const POLICY_AB_ROLLBACK: &str = "ab:rollback";

/// Service-only capability gating automated `POST /api/cd/deploy` triggers from `mu-ci-controller`.
pub const POLICY_CD_SERVICE_DEPLOY: &str = "cd:service.deploy";

/// Canonical pinned baseline role (`cd:runs.read`, `cd:steps.read`, `ab:slots.read` — redacted logs, no rollback).
pub const ROLE_MEMBER: &str = "member";
/// Elective role unlocking unredacted `ab:gate.logs.read` diagnostic excerpts.
pub const ROLE_GATE_INSPECTOR: &str = "gate-inspector";
/// Time-bounded emergency role unlocking `ab:rollback` (`folio:ab:operate`) + gate logs.
pub const ROLE_AB_EMERGENCY: &str = "ab-emergency";
/// Time-bounded platform admin role with full CD/A|B read + emergency rollback visibility.
pub const ROLE_PLATFORM_ADMIN: &str = "platform-admin";
/// Passkey-gated renewable all-access role (2m idle, 15m hard, single +15m last-2m renewal).
pub const ROLE_SUPER_OPERATOR: &str = SUPER_OPERATOR_ROLE_ID;

const HEADER_PROXY_SECRET: &str = "x-proxy-secret";
const HEADER_FORWARDED_USER: &str = "x-forwarded-user";

/// Reads and trims a secret file (e.g. `MU_CD_CONTROLLER_API_TOKEN_FILE` /
/// `MUCONDE_CD_API_TOKEN_FILE` or `MU_CD_CONTROLLER_PROXY_SECRET_FILE` / `MUCONDE_PROXY_SECRET_FILE`),
/// failing closed (`None`) if the path does not exist, cannot be read, or trims to empty.
#[must_use]
pub fn load_secret_file(path: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(path).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Constant-time string equality check avoiding early exits when comparing tokens/secrets.
#[must_use]
pub fn constant_time_str_eq(lhs: &str, rhs: &str) -> bool {
    let a = lhs.as_bytes();
    let b = rhs.as_bytes();
    let max_len = a.len().max(b.len());
    let mut diff = 0u8;
    for i in 0..max_len {
        let ba = if i < a.len() { a[i] } else { 0 };
        let bb = if i < b.len() { b[i] } else { 0 };
        diff |= ba ^ bb;
    }
    diff == 0 && bool::from((a.len() as u64).ct_eq(&(b.len() as u64)))
}

fn validate_github_login(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 39 {
        return None;
    }
    if trimmed.starts_with('-') || trimmed.ends_with('-') {
        return None;
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return None;
    }
    Some(trimmed.to_string())
}

fn role_id(raw: &str) -> RoleId {
    RoleId::new(raw).expect("static canonical role id must be valid")
}

fn folio_id(raw: &str) -> FolioId {
    FolioId::new(raw).expect("static canonical folio id must be valid")
}

/// Constructs the default `mu-auth` [`AuthAuthority`] for `mu-cd-controller` using
/// canonical CD and A|B deployment manifests (`zero ab:promote`).
#[must_use]
pub fn default_authority() -> AuthAuthority {
    let folio_catalog = FolioCatalog::with_canonical_manifests();
    let role_catalog = RoleCatalog::from_roles([
        RoleSpec::pinned_baseline(
            role_id(ROLE_MEMBER),
            Some("Member"),
            "Baseline authenticated read-only CD and A/B slot visibility (redacted logs)",
        )
        .expect("valid baseline role"),
        RoleSpec::elective(
            role_id(ROLE_GATE_INSPECTOR),
            Some("Gate Inspector"),
            "Unlocks unredacted A/B integration gate log excerpts",
            StepUpRequirement::None,
        )
        .expect("valid elective role"),
        RoleSpec::timed(
            role_id(ROLE_AB_EMERGENCY),
            Some("AB Emergency Operator"),
            "Time-bounded Passkey-gated permission to execute emergency A/B rollback",
            900,
            300,
        )
        .expect("valid timed ab-emergency role"),
        RoleSpec::timed(
            role_id(ROLE_PLATFORM_ADMIN),
            Some("Platform Admin"),
            "Time-bounded Passkey-gated platform emergency operator role",
            1800,
            300,
        )
        .expect("valid timed platform-admin role"),
        RoleSpec::super_operator(),
    ])
    .expect("canonical controller roles must validate");

    let mut index = RoleFolioIndex::new();
    index
        .set_role_folios(
            role_id(ROLE_MEMBER),
            BTreeSet::from([folio_id("folio:cd:read"), folio_id("folio:ab:read")]),
            &folio_catalog,
            &role_catalog,
        )
        .expect("member folios must validate");
    index
        .set_role_folios(
            role_id(ROLE_GATE_INSPECTOR),
            BTreeSet::from([
                folio_id("folio:cd:read"),
                folio_id("folio:ab:read"),
                folio_id("folio:ab:gate-logs"),
            ]),
            &folio_catalog,
            &role_catalog,
        )
        .expect("gate-inspector folios must validate");
    index
        .set_role_folios(
            role_id(ROLE_AB_EMERGENCY),
            BTreeSet::from([
                folio_id("folio:cd:read"),
                folio_id("folio:ab:read"),
                folio_id("folio:ab:gate-logs"),
                folio_id("folio:ab:operate"),
            ]),
            &folio_catalog,
            &role_catalog,
        )
        .expect("ab-emergency folios must validate");
    index
        .set_role_folios(
            role_id(ROLE_PLATFORM_ADMIN),
            BTreeSet::from([
                folio_id("folio:cd:read"),
                folio_id("folio:ab:read"),
                folio_id("folio:ab:gate-logs"),
                folio_id("folio:ab:operate"),
            ]),
            &folio_catalog,
            &role_catalog,
        )
        .expect("platform-admin folios must validate");
    index
        .set_role_folios(
            role_id(ROLE_SUPER_OPERATOR),
            BTreeSet::from(canonical_super_operator_folios()),
            &folio_catalog,
            &role_catalog,
        )
        .expect("super-operator folios must validate");

    AuthAuthority::new(folio_catalog, role_catalog, index)
        .expect("default canonical AuthAuthority must validate")
}

/// Registered operator principal and active `RoleLeases` evaluated by `mu-auth`.
#[derive(Debug, Clone)]
pub struct BoundOperatorSession {
    pub principal: Principal,
    pub leases: RoleLeases,
}

/// Evaluated authorization context returned to HTTP handlers after policy checks succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedCaller {
    /// Authenticated GitHub login when verified through edge proxy headers.
    pub principal_login: Option<String>,
    /// `true` when authenticated exclusively by service-to-service bearer token.
    pub service_only: bool,
    /// `true` when the caller holds `"cd:steps.read"`.
    pub can_read_steps: bool,
    /// `true` when the caller holds `"ab:gate.logs.read"`.
    pub can_read_gate_logs: bool,
    /// `true` when the caller holds `"ab:rollback"`.
    pub can_rollback: bool,
}

/// Fail-closed authorization denial converted into `401 Unauthorized` or `403 Forbidden`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRejection {
    pub status: StatusCode,
    pub error: &'static str,
    pub detail: String,
    pub www_authenticate: bool,
}

impl AuthRejection {
    fn unauthorized(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            error: "unauthorized",
            detail: detail.into(),
            www_authenticate: true,
        }
    }

    fn forbidden(error: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            error,
            detail: detail.into(),
            www_authenticate: false,
        }
    }
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        let mut resp = (
            self.status,
            Json(json!({
                "error": self.error,
                "detail": self.detail,
            })),
        )
            .into_response();
        if self.www_authenticate {
            resp.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                header::HeaderValue::from_static("Bearer realm=\"mu-cd-controller\""),
            );
        }
        resp
    }
}

/// Combined service-token + `mu-auth` policy-folio authorizer used by [`crate::api::CdApiState`].
#[derive(Debug, Clone)]
pub struct CdAuthorizer {
    service_bearer: Option<String>,
    proxy_secret: Option<String>,
    authority: Arc<RwLock<AuthAuthority>>,
    operators: Arc<RwLock<HashMap<String, BoundOperatorSession>>>,
}

impl CdAuthorizer {
    /// Creates an authorizer backed by the canonical CD + A|B `mu-auth` policy folios.
    #[must_use]
    pub fn new(service_bearer: Option<String>) -> Self {
        Self {
            service_bearer: service_bearer
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty()),
            proxy_secret: None,
            authority: Arc::new(RwLock::new(default_authority())),
            operators: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Replaces the backing `mu-auth` [`AuthAuthority`] (folios, roles, and index).
    #[must_use]
    pub fn with_authority(mut self, authority: AuthAuthority) -> Self {
        self.authority = Arc::new(RwLock::new(authority));
        self
    }

    /// Configures the expected `X-Proxy-Secret` shared between an authenticating edge proxy
    /// (such as `mu-console` or `oauth2-proxy`) and `mu-cd-controller`.
    #[must_use]
    pub fn with_proxy_secret(mut self, secret: Option<String>) -> Self {
        self.proxy_secret = secret
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        self
    }

    /// Returns whether a service bearer token is configured.
    #[must_use]
    pub fn has_service_bearer(&self) -> bool {
        self.service_bearer.is_some()
    }

    /// Suppresses all grants belonging to `subsystem` (maintenance mode / fail-closed).
    pub fn disable_subsystem(&self, subsystem: SubsystemId) {
        self.authority
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .disable_subsystem(subsystem);
    }

    /// Re-enables grants belonging to `subsystem`.
    pub fn enable_subsystem(&self, subsystem: SubsystemId) -> bool {
        self.authority
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .enable_subsystem(subsystem)
    }

    /// Registers a principal and explicit [`RoleLeases`] directly for a GitHub `login`.
    pub fn bind_principal(&self, login: &str, principal: Principal, leases: RoleLeases) {
        let key = login.trim().to_ascii_lowercase();
        self.operators
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, BoundOperatorSession { principal, leases });
    }

    /// Binds a GitHub operator with Passkey enrollment count, bound roles, and initially active
    /// roles, validating activations through `mu-auth` (`RoleLeases`).
    pub fn bind_operator(
        &self,
        login: &str,
        passkey_count: usize,
        bound_roles: &[&str],
        active_roles: &[&str],
        step_up_verified: bool,
        now_ms: u64,
    ) -> Result<(), FolioError> {
        let authority = self.authority.read().unwrap_or_else(|e| e.into_inner());
        let mut parsed_bound = BTreeSet::new();
        for role in bound_roles {
            parsed_bound.insert(RoleId::new(*role)?);
        }
        let principal = Principal::Authenticated {
            login: login.trim().to_string(),
            passkey_count,
            bound_roles: parsed_bound,
        };
        let mut leases = RoleLeases::for_login(&authority.role_catalog, &principal);
        for active in active_roles {
            let rid = RoleId::new(*active)?;
            if rid == authority.role_catalog.pinned_baseline().id {
                continue;
            }
            let Some(spec) = authority.role_catalog.get(&rid) else {
                return Err(FolioError::UnknownRole(active.to_string()));
            };
            match spec.activation {
                RoleActivation::PinnedBaseline => {}
                RoleActivation::Elective => {
                    leases.enable_elective(
                        &authority.role_catalog,
                        &principal,
                        &rid,
                        step_up_verified,
                    )?;
                }
                RoleActivation::Timed { .. } => {
                    leases.activate_timed(
                        &authority.role_catalog,
                        &principal,
                        &rid,
                        now_ms,
                        step_up_verified,
                    )?;
                }
            }
        }
        drop(authority);
        self.bind_principal(login, principal, leases);
        Ok(())
    }

    /// Renews a bound operator's active renewable `Timed` role lease (e.g. `super-operator`)
    /// during its final renewal window after fresh Passkey step-up confirmation.
    pub fn renew_operator_role(
        &self,
        login: &str,
        role: &str,
        step_up_verified: bool,
        now_ms: u64,
    ) -> Result<RoleLease, FolioError> {
        let authority = self.authority.read().unwrap_or_else(|e| e.into_inner());
        let rid = RoleId::new(role)?;
        let key = login.trim().to_ascii_lowercase();
        let mut ops = self.operators.write().unwrap_or_else(|e| e.into_inner());
        let session = ops
            .get_mut(&key)
            .ok_or_else(|| FolioError::UnauthorizedActivation {
                role: role.to_string(),
            })?;
        let lease = session.leases.renew_timed(
            &authority.role_catalog,
            &session.principal,
            &rid,
            now_ms,
            step_up_verified,
        )?;
        Ok(lease.clone())
    }

    /// Records explicit user activity to extend active `Timed` idle timers up to hard limits.
    pub fn touch_operator_activity(&self, login: &str, now_ms: u64) {
        let key = login.trim().to_ascii_lowercase();
        if let Some(session) = self
            .operators
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&key)
        {
            let _ = session.leases.record_activity(now_ms);
        }
    }

    /// Removes a previously registered operator session binding.
    pub fn revoke_operator(&self, login: &str) {
        self.operators
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&login.trim().to_ascii_lowercase());
    }

    /// Bootstraps configured operator GitHub logins (from `MU_CD_CONTROLLER_OPERATOR_USERS` /
    /// `MUCONDE_OPERATOR_USERS`) with baseline and elective gate-inspector read/step/gate-log folios
    /// while keeping `ab:rollback` gated behind explicit timed elevation.
    #[must_use]
    pub fn with_operator_users<I, S>(self, logins: I, now_ms: u64) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for raw in logins {
            let trimmed = raw.as_ref().trim();
            if trimmed.is_empty() {
                continue;
            }
            let Some(valid_login) = validate_github_login(trimmed) else {
                tracing::warn!(
                    login = trimmed,
                    "Ignoring invalid GitHub login in MU_CD_CONTROLLER_OPERATOR_USERS / MUCONDE_OPERATOR_USERS"
                );
                continue;
            };
            if let Err(err) = self.bind_operator(
                &valid_login,
                1,
                &[
                    ROLE_MEMBER,
                    ROLE_GATE_INSPECTOR,
                    ROLE_AB_EMERGENCY,
                    ROLE_PLATFORM_ADMIN,
                    ROLE_SUPER_OPERATOR,
                ],
                &[ROLE_GATE_INSPECTOR],
                false,
                now_ms,
            ) {
                tracing::warn!(
                    login = %valid_login,
                    error = %err,
                    "Failed to bootstrap MU_CD_CONTROLLER_OPERATOR_USERS / MUCONDE_OPERATOR_USERS operator binding"
                );
            }
        }
        self
    }

    /// Authenticates transport credentials (`Authorization: Bearer` / `X-Proxy-Secret` +
    /// `X-Forwarded-User`) and evaluates the required `mu-auth` policy at `now_ms`.
    pub fn authorize_at(
        &self,
        headers: &HeaderMap,
        required_policy: &str,
        now_ms: u64,
    ) -> Result<AuthorizedCaller, AuthRejection> {
        let auth_values: Vec<&str> = headers
            .get_all(header::AUTHORIZATION)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        if auth_values.len() > 1 {
            return Err(AuthRejection::unauthorized(
                "duplicate Authorization header",
            ));
        }

        let service_verified = if let Some(raw_auth) = auth_values.first() {
            let Some(presented) = raw_auth
                .strip_prefix("Bearer ")
                .or_else(|| raw_auth.strip_prefix("bearer "))
            else {
                return Err(AuthRejection::unauthorized("missing Bearer scheme"));
            };
            let trimmed = presented.trim();
            let Some(expected) = self.service_bearer.as_deref() else {
                return Err(AuthRejection::unauthorized("bearer token not accepted"));
            };
            if !constant_time_str_eq(trimmed, expected) {
                return Err(AuthRejection::unauthorized("invalid bearer token"));
            }
            true
        } else {
            false
        };

        let proxy_secrets: Vec<&str> = headers
            .get_all(HEADER_PROXY_SECRET)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        if proxy_secrets.len() > 1 {
            return Err(AuthRejection::unauthorized(
                "duplicate X-Proxy-Secret header",
            ));
        }

        let forwarded_users: Vec<&str> = headers
            .get_all(HEADER_FORWARDED_USER)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        if forwarded_users.len() > 1 {
            return Err(AuthRejection::unauthorized(
                "duplicate X-Forwarded-User header",
            ));
        }

        let proxy_verified = if let Some(presented_secret) = proxy_secrets.first() {
            let Some(expected) = self.proxy_secret.as_deref() else {
                return Err(AuthRejection::unauthorized("unconfigured X-Proxy-Secret"));
            };
            if !constant_time_str_eq(presented_secret.trim(), expected) {
                return Err(AuthRejection::unauthorized("invalid X-Proxy-Secret"));
            }
            true
        } else {
            false
        };

        if let Some(raw_user) = forwarded_users.first() {
            if !proxy_verified {
                return Err(AuthRejection::unauthorized(
                    "X-Forwarded-User without verified X-Proxy-Secret",
                ));
            }
            let Some(login) = validate_github_login(raw_user) else {
                return Err(AuthRejection::unauthorized(
                    "invalid X-Forwarded-User login",
                ));
            };

            let bound = self
                .operators
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .get(&login.to_ascii_lowercase())
                .cloned();

            let Some(session) = bound else {
                return Err(AuthRejection::forbidden(
                    "authorization_denied",
                    format!("operator '{login}' has no bound role folio"),
                ));
            };

            let eval = self
                .authority
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .evaluate_session(&session.principal, &session.leases, now_ms)
                .map_err(|e| AuthRejection::forbidden("authorization_denied", e.to_string()))?;

            if eval.passkey_enrollment_required {
                return Err(AuthRejection::forbidden(
                    "passkey_enrollment_required",
                    "enroll at least one Passkey before accessing protected resources",
                ));
            }

            if !eval.has_policy_str(required_policy) {
                return Err(AuthRejection::forbidden(
                    "insufficient_policy_folio",
                    format!("missing required policy '{required_policy}'"),
                ));
            }

            return Ok(AuthorizedCaller {
                principal_login: eval.principal_login.clone(),
                service_only: false,
                can_read_steps: eval.has_policy_str(POLICY_CD_STEPS_READ),
                can_read_gate_logs: eval.has_policy_str(POLICY_AB_GATE_LOGS_READ),
                can_rollback: eval.has_policy_str(POLICY_AB_ROLLBACK),
            });
        }

        // Pure service-to-service caller (MU_CD_CONTROLLER_API_TOKEN_FILE / MUCONDE_CD_API_TOKEN_FILE)
        // with no proxied user: permits read-only CD/A|B slots + automated CI->CD trigger, never gate logs or ab:rollback.
        if service_verified {
            let service_allowed = matches!(
                required_policy,
                POLICY_CD_RUNS_READ
                    | POLICY_CD_STEPS_READ
                    | POLICY_AB_SLOTS_READ
                    | POLICY_CD_SERVICE_DEPLOY
            );
            if !service_allowed {
                return Err(AuthRejection::forbidden(
                    "insufficient_policy_folio",
                    format!("service token lacks user folio permission for '{required_policy}'"),
                ));
            }
            return Ok(AuthorizedCaller {
                principal_login: None,
                service_only: true,
                can_read_steps: true,
                can_read_gate_logs: false,
                can_rollback: false,
            });
        }

        // Edge proxy request with verified secret and no X-Forwarded-User evaluates Anonymous.
        if proxy_verified {
            let eval = self
                .authority
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .evaluate_session(&Principal::Anonymous, &RoleLeases::new(), now_ms)
                .map_err(|e| AuthRejection::forbidden("authorization_denied", e.to_string()))?;
            if eval.has_policy_str(required_policy) {
                return Ok(AuthorizedCaller {
                    principal_login: None,
                    service_only: false,
                    can_read_steps: eval.has_policy_str(POLICY_CD_STEPS_READ),
                    can_read_gate_logs: eval.has_policy_str(POLICY_AB_GATE_LOGS_READ),
                    can_rollback: eval.has_policy_str(POLICY_AB_ROLLBACK),
                });
            }
            return Err(AuthRejection::forbidden(
                "insufficient_policy_folio",
                format!("anonymous principal lacks policy '{required_policy}'"),
            ));
        }

        Err(AuthRejection::unauthorized(
            "missing or invalid credentials",
        ))
    }
}

/// Returns whether a string looks like a non-empty subsystem token helper check if needed.
#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                axum::http::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn test_constant_time_str_eq() {
        assert!(constant_time_str_eq("alpha", "alpha"));
        assert!(!constant_time_str_eq("alpha", "alphb"));
        assert!(!constant_time_str_eq("alpha", "alpha-longer"));
    }

    #[test]
    fn test_canonical_authority_grants_without_ab_promote() {
        let auth =
            CdAuthorizer::new(Some("svc-tok".into())).with_proxy_secret(Some("proxy-sec".into()));
        let now = 1_700_000_000_000;
        auth.bind_operator("alice", 1, &[ROLE_MEMBER], &[], false, now)
            .unwrap();
        auth.bind_operator(
            "bob",
            1,
            &[ROLE_GATE_INSPECTOR],
            &[ROLE_GATE_INSPECTOR],
            false,
            now,
        )
        .unwrap();
        auth.bind_operator(
            "carol",
            1,
            &[ROLE_AB_EMERGENCY],
            &[ROLE_AB_EMERGENCY],
            true,
            now,
        )
        .unwrap();
        auth.bind_operator("nopass", 0, &[ROLE_AB_EMERGENCY], &[], false, now)
            .unwrap();

        // Unauthenticated fails with 401
        let err = auth
            .authorize_at(&HeaderMap::new(), POLICY_CD_RUNS_READ, now)
            .unwrap_err();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);

        // Spoofed X-Forwarded-User without proxy secret fails with 401
        let spoof = headers_with(&[
            ("authorization", "Bearer svc-tok"),
            ("x-forwarded-user", "carol"),
        ]);
        assert_eq!(
            auth.authorize_at(&spoof, POLICY_AB_ROLLBACK, now)
                .unwrap_err()
                .status,
            StatusCode::UNAUTHORIZED
        );

        // Service token only: reads allowed, gate logs redacted, rollback forbidden (403)
        let svc = headers_with(&[("authorization", "Bearer svc-tok")]);
        let svc_read = auth.authorize_at(&svc, POLICY_AB_SLOTS_READ, now).unwrap();
        assert!(svc_read.service_only);
        assert!(!svc_read.can_read_gate_logs);
        assert_eq!(
            auth.authorize_at(&svc, POLICY_AB_ROLLBACK, now)
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );

        // Member baseline: runs & slots allowed, gate logs redacted, rollback forbidden (403)
        let alice = headers_with(&[
            ("x-proxy-secret", "proxy-sec"),
            ("x-forwarded-user", "alice"),
        ]);
        assert!(auth.authorize_at(&alice, POLICY_CD_RUNS_READ, now).is_ok());
        let alice_slots = auth
            .authorize_at(&alice, POLICY_AB_SLOTS_READ, now)
            .unwrap();
        assert!(!alice_slots.can_read_gate_logs);
        assert_eq!(
            auth.authorize_at(&alice, POLICY_AB_ROLLBACK, now)
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );

        // Gate inspector: unredacted logs allowed, rollback still forbidden (403)
        let bob = headers_with(&[("x-proxy-secret", "proxy-sec"), ("x-forwarded-user", "bob")]);
        let bob_slots = auth.authorize_at(&bob, POLICY_AB_SLOTS_READ, now).unwrap();
        assert!(bob_slots.can_read_gate_logs);
        assert_eq!(
            auth.authorize_at(&bob, POLICY_AB_ROLLBACK, now)
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );

        // AB emergency with active timed lease: rollback allowed, then denied after expiry
        let carol = headers_with(&[
            ("x-proxy-secret", "proxy-sec"),
            ("x-forwarded-user", "carol"),
        ]);
        let ok = auth.authorize_at(&carol, POLICY_AB_ROLLBACK, now + 10_000);
        assert!(ok.unwrap().can_rollback);
        assert_eq!(
            auth.authorize_at(&carol, POLICY_AB_ROLLBACK, now + 301_000)
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );

        // Zero passkeys held back with 403
        let nopass = headers_with(&[
            ("x-proxy-secret", "proxy-sec"),
            ("x-forwarded-user", "nopass"),
        ]);
        assert_eq!(
            auth.authorize_at(&nopass, POLICY_CD_RUNS_READ, now)
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );

        // MUCONDE_OPERATOR_USERS bootstrap binds valid logins (case-insensitively) and ignores invalid ones,
        // allowing combined Authorization: Bearer + X-Proxy-Secret/X-Forwarded-User reads while keeping
        // ab:rollback gated behind timed elevation.
        let bootstrapped = CdAuthorizer::new(Some("svc-tok".into()))
            .with_proxy_secret(Some("proxy-sec".into()))
            .with_operator_users(["Operator-One", " invalid user ", "-bad"], now);
        let op_hdrs = headers_with(&[
            ("authorization", "Bearer svc-tok"),
            ("x-proxy-secret", "proxy-sec"),
            ("x-forwarded-user", "operator-one"),
        ]);
        let op_caller = bootstrapped
            .authorize_at(&op_hdrs, POLICY_AB_SLOTS_READ, now)
            .unwrap();
        assert_eq!(op_caller.principal_login.as_deref(), Some("Operator-One"));
        assert!(!op_caller.service_only);
        assert!(op_caller.can_read_steps);
        assert!(op_caller.can_read_gate_logs);
        assert!(!op_caller.can_rollback);
        assert!(bootstrapped
            .authorize_at(&op_hdrs, POLICY_CD_RUNS_READ, now)
            .is_ok());
        assert_eq!(
            bootstrapped
                .authorize_at(&op_hdrs, POLICY_AB_ROLLBACK, now)
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );

        // Super-operator: Passkey required, 2m idle, 15m hard, single +15m last-2m Passkey renewal.
        bootstrapped
            .bind_operator(
                "alice",
                1,
                &[ROLE_MEMBER, ROLE_SUPER_OPERATOR],
                &[ROLE_SUPER_OPERATOR],
                true,
                0,
            )
            .unwrap();
        let alice_hdrs = headers_with(&[
            ("x-proxy-secret", "proxy-sec"),
            ("x-forwarded-user", "alice"),
        ]);
        let caller = bootstrapped
            .authorize_at(&alice_hdrs, POLICY_AB_ROLLBACK, 1_000)
            .unwrap();
        assert!(caller.can_read_steps);
        assert!(caller.can_read_gate_logs);
        assert!(caller.can_rollback);

        for t in [
            90_000, 180_000, 270_000, 360_000, 450_000, 540_000, 630_000, 720_000, 779_000,
        ] {
            bootstrapped.touch_operator_activity("alice", t);
        }
        assert!(matches!(
            bootstrapped.renew_operator_role("alice", ROLE_SUPER_OPERATOR, true, 779_000),
            Err(FolioError::RenewalWindowNotReached { .. })
        ));
        assert!(matches!(
            bootstrapped.renew_operator_role("alice", ROLE_SUPER_OPERATOR, false, 780_000),
            Err(FolioError::StepUpRequired { .. })
        ));
        let renewed = bootstrapped
            .renew_operator_role("alice", ROLE_SUPER_OPERATOR, true, 780_000)
            .unwrap();
        assert_eq!(renewed.hard_expires_at_ms, 1_800_000);
        bootstrapped.touch_operator_activity("alice", 880_000);
        bootstrapped.touch_operator_activity("alice", 920_000);
        assert!(
            bootstrapped
                .authorize_at(&alice_hdrs, POLICY_AB_ROLLBACK, 920_000)
                .unwrap()
                .can_rollback
        );
        assert!(matches!(
            bootstrapped.renew_operator_role("alice", ROLE_SUPER_OPERATOR, true, 920_000),
            Err(FolioError::RenewalLimitReached { .. })
        ));
        // Leaving idle >= 120s after last activity (at 1_040_000ms) expires super-operator cleanly.
        assert_eq!(
            bootstrapped
                .authorize_at(&alice_hdrs, POLICY_AB_ROLLBACK, 1_040_000)
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );
    }
}
