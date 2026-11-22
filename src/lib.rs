//! Continuous delivery control plane orchestrator for the MuConDe distributed deployment fabric.
//!
//! Provides zero-downtime A/B rollouts, cluster idle worker discovery, TTL-bounded deployment leases,
//! declarative failure contracts, atomic slot promotion, automatic rollback, and registry digest tainting.

#![deny(unsafe_code)]

pub mod api;
pub mod auth;
pub mod cd_state;
pub mod contract;
pub mod error;
pub mod lease;
pub mod orchestrator;
pub mod policy_repo;
pub mod slo;
pub mod telemetry;
pub mod tls;

// Re-exports of common primary types for ergonomic library use
pub use api::{CdApiConfig, CdApiState, DeploymentGate, DeploymentSummary};
pub use auth::{
    constant_time_str_eq, default_authority, load_secret_file, AuthRejection, AuthorizedCaller,
    BoundOperatorSession, CdAuthorizer, POLICY_AB_GATE_LOGS_READ, POLICY_AB_ROLLBACK,
    POLICY_AB_SLOTS_READ, POLICY_CD_RUNS_READ, POLICY_CD_SERVICE_DEPLOY, POLICY_CD_STEPS_READ,
    ROLE_AB_EMERGENCY, ROLE_GATE_INSPECTOR, ROLE_MEMBER, ROLE_PLATFORM_ADMIN,
};
pub use cd_state::{
    AbRollbackRequestDto, AbRollbackResponseDto, CdEcosystem, CdEvent, CdRepoId, CdRunDto,
    CdRunFailurePinpointDto, CdRunState, CdSnapshot, CdStateStore, CdStepDto, GateVerdict,
    ItProgressSink, SkipReasonDto, Slot,
};
pub use contract::{
    resolve_manifest_path, AbRulesConfig, DeploymentConfig, IntegrationTestSelector, MuCdConfig,
    MuConDeConfig, DEFAULT_BAKE_WINDOW_SECONDS, DEFAULT_KEEP_SNAPSHOTS, DEFAULT_LEASE_TTL_SECONDS,
    DEFAULT_MAX_ERROR_LOGS, DEFAULT_MAX_P99_LATENCY_MS, DEFAULT_WARMUP_TIMEOUT_SECONDS,
};
pub use error::{
    ContractError, ControllerError, LeaseError, OrchestratorError, PolicyRepoError, TlsError,
};
pub use lease::{
    ClusterIdlePoller, ClusterNodeStatus, IdleBackoffConfig, LeaseCoordinator,
    DEFAULT_CONTROLLER_URL, DEFAULT_IDLE_JITTER_PERCENT, DEFAULT_IDLE_POLL_INITIAL_MS,
    DEFAULT_IDLE_POLL_MAX_MS, DEFAULT_IDLE_WAIT_TIMEOUT_SECS,
};
pub use orchestrator::{
    dispatch_agent_frame, resolve_node_map, resolve_target_node, resolve_target_node_from_map,
    resolve_target_nodes, resolve_target_nodes_from_map, AgentFrame, AgentIpcClient,
    DeploymentOrchestrator, DeploymentOutcome, HttpMuRegistClient, IpcAgentClient, MuRegistClient,
    DEFAULT_REGISTRY_URL,
};
pub use policy_repo::{
    build_scenario_execution_plan, parse_cidr, resolve_scenarios_for_node,
    validate_allowed_signers_file, validate_clean_absolute_path, validate_git_commit_sha,
    validate_service_identifier, validate_sha256_hex, CommitVerificationPolicy, NodeArch,
    NodeRolloutOverride, NodeSpec, NodesInventory, PinnedDeploymentSnapshot, PolicyDeploymentSpec,
    PolicyRepoConfig, PolicyRepository, PolicyServiceContract, RolloutStrategy, SandboxCeiling,
    ScenarioBinding, UnitMapping, VerifiedPolicyBundle, VerifiedPolicySummary,
    DEFAULT_POLICY_SANDBOX_MEMLOCK_KB, DEFAULT_REFRESH_INTERVAL_SECS,
    DEFAULT_SNAPSHOT_CACHE_CAPACITY, MAX_POLICY_MEMLOCK_KB, MAX_POLICY_SANDBOX_PIDS,
    METRIC_POLICY_VERIFY_FAILED,
};
pub use slo::{
    CanarySloClient, MuObserveSloClient, DEFAULT_MUOBSERVE_ADDR, DEFAULT_MUOBSERVE_SERVER_NAME,
};
pub use telemetry::{
    build_cd_log, build_cd_span, CdTelemetrySink, MuObserveCdSink, RecordingCdTelemetrySink,
    CD_SERVICE_NAME,
};
pub use tls::TlsConfig;

/// Returns the first non-empty trimmed value across `keys` using `lookup`.
pub fn first_non_empty_var(
    lookup: &dyn Fn(&str) -> Option<String>,
    keys: &[&str],
) -> Option<String> {
    for key in keys {
        if let Some(val) = lookup(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// Returns the first non-empty trimmed environment variable value across `keys`.
pub fn first_non_empty_env(keys: &[&str]) -> Option<String> {
    first_non_empty_var(&|key| std::env::var(key).ok(), keys)
}

/// Daemon version string.
pub const CONTROLLER_VERSION: &str = env!("CARGO_PKG_VERSION");
