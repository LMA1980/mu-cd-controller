//! Signature-verified deployment policy repository loader, immutable per-deployment snapshot
//! cache, and per-node [`ScenarioExecutionPlan`] resolver.
//!
//! Enforces zero-trust continuous delivery policy inversion: deployment targets, SLO thresholds,
//! A/B rollback rules, sandbox ceilings, integration test selections, and read-only canary
//! scenario bindings resolve exclusively from a Git-verified deployment policy repository.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use mu_cd_ipc::{ScenarioEnvVar, ScenarioExecutionPlan, ScenarioTestSpec};
use mu_observable_ipc::{OtelMetricEntry, TraceContext};
use serde::{Deserialize, Serialize};
use tokio::process::Command;

use crate::cd_state::now_epoch_ms;
use crate::contract::{
    AbRulesConfig, DeploymentConfig, IntegrationTestSelector, MuConDeConfig,
    DEFAULT_BAKE_WINDOW_SECONDS, DEFAULT_LEASE_TTL_SECONDS, DEFAULT_MAX_P99_LATENCY_MS,
    DEFAULT_WARMUP_TIMEOUT_SECONDS,
};
use crate::error::PolicyRepoError;
use crate::telemetry::{build_cd_log, now_unix_nano, CdTelemetrySink, CD_SERVICE_NAME};

/// Maximum permitted `RLIMIT_MEMLOCK` ceiling in KiB (`28 GiB`).
pub const MAX_POLICY_MEMLOCK_KB: u64 = 29_360_128;
/// Maximum permitted PIDs inside a post-swap integration test sandbox (`256`).
pub const MAX_POLICY_SANDBOX_PIDS: u32 = 256;
/// Default bounded `RLIMIT_MEMLOCK` ceiling in KiB for isolated test sandboxes (`64 MiB`).
pub const DEFAULT_POLICY_SANDBOX_MEMLOCK_KB: u64 = 65_536;
/// Default periodic remote fetch cadence in seconds (`30`).
pub const DEFAULT_REFRESH_INTERVAL_SECS: u64 = 30;
/// Minimum allowed periodic remote fetch cadence in seconds (`5`).
pub const MIN_REFRESH_INTERVAL_SECS: u64 = 5;
/// Maximum allowed periodic remote fetch cadence in seconds (`300`).
pub const MAX_REFRESH_INTERVAL_SECS: u64 = 300;
/// Maximum timeout for a single `git fetch` refresh attempt (`10s`).
pub const GIT_FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum number of immutable per-`deployment_id` snapshots retained in memory (`256`).
pub const DEFAULT_SNAPSHOT_CACHE_CAPACITY: usize = 256;
/// Metric name emitted when deployment policy verification fails closed.
pub const METRIC_POLICY_VERIFY_FAILED: &str = "muconde.controller.policy_verify_failed";

/// Built-in agent health checks that do not require an external integration test archive binary.
const BUILTIN_INTEGRATION_TESTS: &[&str] = &["systemd_unit_active", "health_endpoint_ready"];

const fn default_lease_ttl() -> u64 {
    DEFAULT_LEASE_TTL_SECONDS
}

const fn default_warmup_timeout() -> u64 {
    DEFAULT_WARMUP_TIMEOUT_SECONDS
}

const fn default_bake_window() -> u64 {
    DEFAULT_BAKE_WINDOW_SECONDS
}

const fn default_max_p99_latency_ms() -> f64 {
    DEFAULT_MAX_P99_LATENCY_MS
}

const fn default_true() -> bool {
    true
}

const fn default_max_pids() -> u32 {
    MAX_POLICY_SANDBOX_PIDS
}

const fn default_max_memlock_kb() -> u64 {
    DEFAULT_POLICY_SANDBOX_MEMLOCK_KB
}

const fn default_max_slots() -> u32 {
    1
}

/// Configuration for [`PolicyRepository`] loaded from `MU_CD_CONTROLLER_DEPLOY_*` / `MU_CD_DEPLOY_*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRepoConfig {
    /// Local path to the cloned deployment policy Git repository.
    pub repo_dir: Option<PathBuf>,
    /// Optional SSH remote URL used when fetching updates (`git fetch --prune origin <branch>`).
    pub repo_url: Option<String>,
    /// Optional branch override (defaults to `branch` inside `policy/commit-verification.yml`).
    pub branch: Option<String>,
    /// Optional override for the SSH `allowed_signers` file path.
    pub allowed_signers_path: Option<PathBuf>,
    /// Optional SSH private deploy key path (`IdentitiesOnly=yes`).
    pub deploy_key_path: Option<PathBuf>,
    /// Optional pinned SSH `known_hosts` file path (`StrictHostKeyChecking=yes`).
    pub known_hosts_path: Option<PathBuf>,
    /// Periodic SSH fetch interval in seconds (clamped to `5..=300`, default `30`).
    pub refresh_interval_secs: u64,
    /// When `true` (default), run a single-flight fetch before resolving each deployment.
    pub refresh_on_deploy: bool,
}

impl Default for PolicyRepoConfig {
    fn default() -> Self {
        Self {
            repo_dir: None,
            repo_url: None,
            branch: None,
            allowed_signers_path: None,
            deploy_key_path: None,
            known_hosts_path: None,
            refresh_interval_secs: DEFAULT_REFRESH_INTERVAL_SECS,
            refresh_on_deploy: true,
        }
    }
}

impl PolicyRepoConfig {
    /// Reads deployment policy repository configuration from process environment variables.
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_env_lookup(&|key| std::env::var(key).ok())
    }

    /// Pure parser constructing [`PolicyRepoConfig`] via a caller-supplied environment lookup.
    #[must_use]
    pub fn from_env_lookup(lookup: &dyn Fn(&str) -> Option<String>) -> Self {
        let repo_dir = crate::first_non_empty_var(
            lookup,
            &["MU_CD_CONTROLLER_DEPLOY_REPO_DIR", "MU_CD_DEPLOY_REPO_DIR"],
        )
        .map(PathBuf::from);
        let repo_url = crate::first_non_empty_var(
            lookup,
            &["MU_CD_CONTROLLER_DEPLOY_REPO_URL", "MU_CD_DEPLOY_REPO_URL"],
        );
        let branch = crate::first_non_empty_var(
            lookup,
            &[
                "MU_CD_CONTROLLER_DEPLOY_REPO_BRANCH",
                "MU_CD_DEPLOY_REPO_BRANCH",
            ],
        );
        let allowed_signers_path = crate::first_non_empty_var(
            lookup,
            &[
                "MU_CD_CONTROLLER_DEPLOY_ALLOWED_SIGNERS",
                "MU_CD_DEPLOY_ALLOWED_SIGNERS",
            ],
        )
        .map(PathBuf::from);
        let deploy_key_path = crate::first_non_empty_var(
            lookup,
            &["MU_CD_CONTROLLER_DEPLOY_SSH_KEY", "MU_CD_DEPLOY_SSH_KEY"],
        )
        .map(PathBuf::from);
        let known_hosts_path = crate::first_non_empty_var(
            lookup,
            &[
                "MU_CD_CONTROLLER_DEPLOY_KNOWN_HOSTS",
                "MU_CD_DEPLOY_KNOWN_HOSTS",
            ],
        )
        .map(PathBuf::from);
        let refresh_interval_secs = crate::first_non_empty_var(
            lookup,
            &[
                "MU_CD_CONTROLLER_DEPLOY_REFRESH_INTERVAL_SECS",
                "MU_CD_DEPLOY_REFRESH_INTERVAL_SECS",
            ],
        )
        .and_then(|raw| raw.parse::<u64>().ok())
        .unwrap_or(DEFAULT_REFRESH_INTERVAL_SECS)
        .clamp(MIN_REFRESH_INTERVAL_SECS, MAX_REFRESH_INTERVAL_SECS);
        let refresh_on_deploy = crate::first_non_empty_var(
            lookup,
            &[
                "MU_CD_CONTROLLER_DEPLOY_REFRESH_ON_DEPLOY",
                "MU_CD_DEPLOY_REFRESH_ON_DEPLOY",
            ],
        )
        .map(|raw| {
            !matches!(
                raw.to_ascii_lowercase().as_str(),
                "false" | "0" | "no" | "off"
            )
        })
        .unwrap_or(true);

        Self {
            repo_dir,
            repo_url,
            branch,
            allowed_signers_path,
            deploy_key_path,
            known_hosts_path,
            refresh_interval_secs,
            refresh_on_deploy,
        }
    }

    /// Returns `true` when a local deployment policy repository directory is configured.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.repo_dir.is_some()
    }
}

/// Validates a canonical service identifier (`^[a-z0-9-]+$`, zero path separators or `..`).
pub fn validate_service_identifier(raw: &str) -> Result<String, PolicyRepoError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed != raw
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains("..")
        || !trimmed
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(PolicyRepoError::InvalidServiceName(raw.to_string()));
    }
    Ok(trimmed.to_string())
}

/// Validates a 64-character ASCII hexadecimal SHA-256 digest string, returning lowercase hex.
pub fn validate_sha256_hex(raw: &str) -> Result<String, PolicyRepoError> {
    let trimmed = raw.trim();
    if trimmed.len() != 64 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(PolicyRepoError::Schema(format!(
            "expected 64-character ASCII hex SHA-256 digest, got length {}",
            trimmed.len()
        )));
    }
    Ok(trimmed.to_ascii_lowercase())
}

/// Validates a 7..=40-character ASCII hexadecimal Git commit SHA.
pub fn validate_git_commit_sha(raw: &str) -> Result<String, PolicyRepoError> {
    let trimmed = raw.trim();
    if !(7..=40).contains(&trimmed.len()) || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(PolicyRepoError::Schema(format!(
            "expected 7..=40-character ASCII hex git_commit, got '{trimmed}'"
        )));
    }
    Ok(trimmed.to_ascii_lowercase())
}

/// Validates that `raw` is a clean absolute filesystem path with zero `..`/`.` segments,
/// duplicate slashes, backslashes, or NUL bytes.
pub fn validate_clean_absolute_path(field: &'static str, raw: &str) -> Result<(), PolicyRepoError> {
    if raw.trim().is_empty() {
        return Err(PolicyRepoError::Schema(format!(
            "field '{field}' cannot be empty"
        )));
    }
    if raw != raw.trim() || raw.contains('\0') || raw.contains('\\') || !raw.starts_with('/') {
        return Err(PolicyRepoError::Schema(format!(
            "field '{field}' must be a clean absolute path: '{raw}'"
        )));
    }
    let tail = &raw[1..];
    if tail.is_empty() {
        return Err(PolicyRepoError::Schema(format!(
            "field '{field}' cannot be bare root '/'"
        )));
    }
    for segment in tail.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(PolicyRepoError::Schema(format!(
                "field '{field}' contains unsafe path segment in '{raw}'"
            )));
        }
    }
    let mut components = Path::new(raw).components();
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(PolicyRepoError::Schema(format!(
            "field '{field}' must begin with root directory: '{raw}'"
        )));
    }
    for comp in components {
        if !matches!(comp, Component::Normal(_)) {
            return Err(PolicyRepoError::Schema(format!(
                "field '{field}' contains non-normal path component: '{raw}'"
            )));
        }
    }
    Ok(())
}

/// Parses and validates an IPv4 or IPv6 CIDR string (`<ip>/<prefix>`).
pub fn parse_cidr(scenario: &str, raw: &str) -> Result<(IpAddr, u8), PolicyRepoError> {
    if raw.is_empty() || raw != raw.trim() {
        return Err(PolicyRepoError::Schema(format!(
            "scenario '{scenario}' contains empty or padded CIDR '{raw}'"
        )));
    }
    let Some((ip_part, prefix_part)) = raw.split_once('/') else {
        return Err(PolicyRepoError::Schema(format!(
            "scenario '{scenario}' CIDR '{raw}' is missing '/<prefix>'"
        )));
    };
    if prefix_part.contains('/')
        || prefix_part.is_empty()
        || !prefix_part.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(PolicyRepoError::Schema(format!(
            "scenario '{scenario}' CIDR '{raw}' has invalid prefix length"
        )));
    }
    let ip: IpAddr = ip_part.parse().map_err(|_| {
        PolicyRepoError::Schema(format!(
            "scenario '{scenario}' CIDR '{raw}' has invalid IP address"
        ))
    })?;
    let prefix: u8 = prefix_part.parse().map_err(|_| {
        PolicyRepoError::Schema(format!(
            "scenario '{scenario}' CIDR '{raw}' prefix exceeds u8 range"
        ))
    })?;
    let max_prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max_prefix {
        return Err(PolicyRepoError::Schema(format!(
            "scenario '{scenario}' CIDR '{raw}' prefix {prefix} exceeds /{max_prefix}"
        )));
    }
    Ok((ip, prefix))
}

fn validate_non_blank(field: &'static str, raw: &str) -> Result<(), PolicyRepoError> {
    if raw.trim().is_empty() {
        return Err(PolicyRepoError::Schema(format!(
            "field '{field}' cannot be empty"
        )));
    }
    Ok(())
}

/// Signed-commit verification policy loaded from `policy/commit-verification.yml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitVerificationPolicy {
    pub branch: String,
    pub require_signed_commits: bool,
    pub allowed_signers_path: String,
    pub fail_closed_on_unverified: bool,
}

impl CommitVerificationPolicy {
    pub fn from_yaml_str(yaml: &str) -> Result<Self, PolicyRepoError> {
        let parsed: Self = serde_yaml::from_str(yaml)
            .map_err(|e| PolicyRepoError::Schema(format!("commit-verification.yml: {e}")))?;
        parsed.validate()?;
        Ok(parsed)
    }

    pub fn validate(&self) -> Result<(), PolicyRepoError> {
        validate_non_blank("branch", &self.branch)?;
        if self.branch.chars().any(char::is_whitespace) || self.branch.contains("..") {
            return Err(PolicyRepoError::Schema(format!(
                "invalid branch name '{}'",
                self.branch
            )));
        }
        validate_clean_absolute_path("allowed_signers_path", &self.allowed_signers_path)?;
        Ok(())
    }
}

/// Canonical CPU architecture supported in a cluster node inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeArch {
    X86_64,
    Riscv64gc,
    Aarch64,
}

/// Hardware and resource ceiling entry for one cluster node in `contracts/nodes.yml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeSpec {
    pub node_id: String,
    pub arch: NodeArch,
    pub host: String,
    pub max_memlock_kb: u64,
    #[serde(default = "default_max_slots")]
    pub max_slots: u32,
    #[serde(default)]
    pub thread_budget: Option<u32>,
    #[serde(default)]
    pub storage_mode: Option<String>,
    #[serde(default)]
    pub cross_compile_only: bool,
    #[serde(default)]
    pub disabled_tools: Vec<String>,
    #[serde(default)]
    pub mucd_root: Option<String>,
}

impl NodeSpec {
    pub fn validate(&self) -> Result<(), PolicyRepoError> {
        validate_non_blank("nodes[].node_id", &self.node_id)?;
        validate_non_blank("nodes[].host", &self.host)?;
        if self.max_memlock_kb == 0 || self.max_memlock_kb > MAX_POLICY_MEMLOCK_KB {
            return Err(PolicyRepoError::Schema(format!(
                "node '{}' max_memlock_kb {} out of bounds (1..={})",
                self.node_id, self.max_memlock_kb, MAX_POLICY_MEMLOCK_KB
            )));
        }
        if self.max_slots == 0 {
            return Err(PolicyRepoError::Schema(format!(
                "node '{}' max_slots must be > 0",
                self.node_id
            )));
        }
        if let Some(threads) = self.thread_budget {
            if threads == 0 {
                return Err(PolicyRepoError::Schema(format!(
                    "node '{}' thread_budget must be > 0",
                    self.node_id
                )));
            }
        }
        for tool in &self.disabled_tools {
            validate_non_blank("nodes[].disabled_tools[]", tool)?;
        }
        if let Some(root) = &self.mucd_root {
            validate_clean_absolute_path("nodes[].mucd_root", root)?;
        }
        Ok(())
    }
}

/// Authoritative cluster node inventory loaded from `contracts/nodes.yml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodesInventory {
    pub nodes: Vec<NodeSpec>,
}

impl NodesInventory {
    pub fn from_yaml_str(yaml: &str) -> Result<Self, PolicyRepoError> {
        let parsed: Self = serde_yaml::from_str(yaml)
            .map_err(|e| PolicyRepoError::Schema(format!("contracts/nodes.yml: {e}")))?;
        parsed.validate()?;
        Ok(parsed)
    }

    pub fn validate(&self) -> Result<(), PolicyRepoError> {
        if self.nodes.is_empty() {
            return Err(PolicyRepoError::Schema(
                "contracts/nodes.yml nodes list cannot be empty".into(),
            ));
        }
        let mut seen = HashSet::with_capacity(self.nodes.len());
        for node in &self.nodes {
            node.validate()?;
            let normalized = node.node_id.trim().to_string();
            if !seen.insert(normalized.clone()) {
                return Err(PolicyRepoError::Schema(format!(
                    "duplicate node_id '{normalized}' in contracts/nodes.yml"
                )));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn find_node(&self, node_id: &str) -> Option<&NodeSpec> {
        let needle = node_id.trim();
        self.nodes.iter().find(|n| n.node_id.trim() == needle)
    }
}

/// Rollout ordering strategy across target nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutStrategy {
    LeaderFirstHa,
    Sequential,
    SingleNode,
}

/// Additional unit or Phase 1 compatibility alias mapping under `deployment`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitMapping {
    pub binary: String,
    pub install_path: String,
    pub systemd_unit: String,
}

impl UnitMapping {
    fn validate(&self, field: &'static str) -> Result<(), PolicyRepoError> {
        validate_non_blank(field, &self.binary)?;
        validate_non_blank(field, &self.systemd_unit)?;
        validate_clean_absolute_path(field, &self.install_path)?;
        Ok(())
    }
}

/// Node-specific rollout policy constraints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRolloutOverride {
    pub node_id: String,
    #[serde(default)]
    pub cross_compile_only: bool,
    #[serde(default)]
    pub disabled_tools: Vec<String>,
    #[serde(default)]
    pub allowed_tags: Vec<String>,
}

impl NodeRolloutOverride {
    fn validate(&self) -> Result<(), PolicyRepoError> {
        validate_non_blank("deployment.node_overrides[].node_id", &self.node_id)?;
        for tool in &self.disabled_tools {
            validate_non_blank("deployment.node_overrides[].disabled_tools[]", tool)?;
        }
        for tag in &self.allowed_tags {
            validate_non_blank("deployment.node_overrides[].allowed_tags[]", tag)?;
        }
        Ok(())
    }
}

/// Deployment target metadata inside a policy service contract.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyDeploymentSpec {
    pub target_nodes: Vec<String>,
    pub binary: Option<String>,
    pub install_path: Option<String>,
    pub systemd_unit: Option<String>,
    pub web_root: Option<String>,
    pub artifact: Option<String>,
    pub reload_unit: Option<String>,
    pub rollout_strategy: Option<RolloutStrategy>,
    pub drain_condition: Option<String>,
    pub self_upgrade_guard: bool,
    pub preserve_wal_buffer: bool,
    pub additional_units: Vec<UnitMapping>,
    pub phase1_aliases: Vec<UnitMapping>,
    pub node_overrides: Vec<NodeRolloutOverride>,
}

impl PolicyDeploymentSpec {
    pub fn validate(&self) -> Result<(), PolicyRepoError> {
        for node in &self.target_nodes {
            validate_non_blank("deployment.target_nodes[]", node)?;
        }
        if let Some(binary) = &self.binary {
            validate_non_blank("deployment.binary", binary)?;
        }
        if let Some(path) = &self.install_path {
            validate_clean_absolute_path("deployment.install_path", path)?;
        }
        if let Some(unit) = &self.systemd_unit {
            validate_non_blank("deployment.systemd_unit", unit)?;
        }
        if let Some(root) = &self.web_root {
            validate_clean_absolute_path("deployment.web_root", root)?;
        }
        if let Some(artifact) = &self.artifact {
            validate_non_blank("deployment.artifact", artifact)?;
        }
        if let Some(reload) = &self.reload_unit {
            validate_non_blank("deployment.reload_unit", reload)?;
        }
        if let Some(drain) = &self.drain_condition {
            validate_non_blank("deployment.drain_condition", drain)?;
        }
        for unit in &self.additional_units {
            unit.validate("deployment.additional_units[]")?;
        }
        for alias in &self.phase1_aliases {
            alias.validate("deployment.phase1_aliases[]")?;
        }
        for ov in &self.node_overrides {
            ov.validate()?;
        }
        Ok(())
    }

    #[must_use]
    pub fn to_contract_deployment(&self) -> DeploymentConfig {
        DeploymentConfig {
            target_nodes: self.target_nodes.clone(),
            binary: self.binary.clone(),
            install_path: self.install_path.clone(),
            systemd_unit: self.systemd_unit.clone(),
            web_root: self.web_root.clone(),
            artifact: self.artifact.clone(),
        }
    }
}

/// Bounded `MuIsolation` resource ceiling for post-swap test execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SandboxCeiling {
    #[serde(default = "default_max_pids")]
    pub max_pids: u32,
    #[serde(default = "default_max_memlock_kb")]
    pub max_memlock_kb: u64,
}

impl Default for SandboxCeiling {
    fn default() -> Self {
        Self {
            max_pids: MAX_POLICY_SANDBOX_PIDS,
            max_memlock_kb: DEFAULT_POLICY_SANDBOX_MEMLOCK_KB,
        }
    }
}

impl SandboxCeiling {
    pub fn validate(&self) -> Result<(), PolicyRepoError> {
        if self.max_pids == 0 || self.max_pids > MAX_POLICY_SANDBOX_PIDS {
            return Err(PolicyRepoError::Schema(format!(
                "sandbox_ceiling.max_pids {} out of bounds (1..={})",
                self.max_pids, MAX_POLICY_SANDBOX_PIDS
            )));
        }
        if self.max_memlock_kb == 0 || self.max_memlock_kb > MAX_POLICY_MEMLOCK_KB {
            return Err(PolicyRepoError::Schema(format!(
                "sandbox_ceiling.max_memlock_kb {} out of bounds (1..={})",
                self.max_memlock_kb, MAX_POLICY_MEMLOCK_KB
            )));
        }
        Ok(())
    }
}

/// Per-scenario read-only live probe configuration bound to target endpoints and credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioBinding {
    pub name: String,
    pub test_binary: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub target_url: Option<String>,
    #[serde(default)]
    pub target_addr: Option<String>,
    #[serde(default)]
    pub tls_ca_file: Option<String>,
    #[serde(default)]
    pub tls_cert_file: Option<String>,
    #[serde(default)]
    pub tls_key_file: Option<String>,
    #[serde(default)]
    pub bearer_token_file: Option<String>,
    #[serde(default = "default_true")]
    pub read_only: bool,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    #[serde(default)]
    pub restricted_cidrs: Vec<String>,
}

impl ScenarioBinding {
    pub fn validate(&self) -> Result<(), PolicyRepoError> {
        let label = if self.name.trim().is_empty() {
            "<unnamed>"
        } else {
            self.name.trim()
        };
        validate_non_blank("scenarios[].name", &self.name)?;
        if self.test_binary.trim().is_empty()
            || self.test_binary != self.test_binary.trim()
            || self.test_binary.contains('/')
            || self.test_binary.contains('\\')
            || self.test_binary.contains("..")
            || self.test_binary.contains('\0')
        {
            return Err(PolicyRepoError::Schema(format!(
                "scenario '{label}' has invalid test_binary '{}'",
                self.test_binary
            )));
        }
        let has_url = self
            .target_url
            .as_deref()
            .map(str::trim)
            .is_some_and(|s| !s.is_empty());
        let has_addr = self
            .target_addr
            .as_deref()
            .map(str::trim)
            .is_some_and(|s| !s.is_empty());
        if !has_url && !has_addr {
            return Err(PolicyRepoError::Schema(format!(
                "scenario '{label}' must define target_url or target_addr"
            )));
        }
        if let Some(url) = &self.target_url {
            validate_target_url(label, url)?;
        }
        if let Some(addr) = &self.target_addr {
            validate_target_addr(label, addr)?;
        }
        if let Some(ca) = &self.tls_ca_file {
            validate_clean_absolute_path("scenarios[].tls_ca_file", ca)?;
        }
        if let Some(cert) = &self.tls_cert_file {
            validate_clean_absolute_path("scenarios[].tls_cert_file", cert)?;
        }
        if let Some(key) = &self.tls_key_file {
            validate_clean_absolute_path("scenarios[].tls_key_file", key)?;
        }
        if self.tls_cert_file.is_some() != self.tls_key_file.is_some() {
            return Err(PolicyRepoError::Schema(format!(
                "scenario '{label}' must pair tls_cert_file and tls_key_file together"
            )));
        }
        if let Some(tok) = &self.bearer_token_file {
            validate_clean_absolute_path("scenarios[].bearer_token_file", tok)?;
        }
        if !self.read_only {
            return Err(PolicyRepoError::Schema(format!(
                "scenario '{label}' must remain read_only: true"
            )));
        }
        if let Some(timeout) = self.timeout_secs {
            if timeout == 0 {
                return Err(PolicyRepoError::Schema(format!(
                    "scenario '{label}' timeout_secs must be > 0"
                )));
            }
        }
        for cidr in &self.restricted_cidrs {
            let _ = parse_cidr(label, cidr)?;
        }
        Ok(())
    }

    /// Converts this validated scenario binding into a wire [`ScenarioTestSpec`].
    #[must_use]
    pub fn to_scenario_test_spec(&self, default_timeout_secs: u64) -> ScenarioTestSpec {
        let mut env = Vec::new();
        let mut ro_mounts = Vec::new();

        if let Some(ref url) = self.target_url {
            env.push(ScenarioEnvVar {
                key: "MU_SMOKE_TARGET_URL".to_string(),
                value: url.clone(),
            });
        }
        if let Some(ref addr) = self.target_addr {
            env.push(ScenarioEnvVar {
                key: "MU_SMOKE_TARGET_ADDR".to_string(),
                value: addr.clone(),
            });
        }
        for (env_key, path_opt) in [
            ("MU_SMOKE_TLS_CA_FILE", &self.tls_ca_file),
            ("MU_SMOKE_TLS_CERT_FILE", &self.tls_cert_file),
            ("MU_SMOKE_TLS_KEY_FILE", &self.tls_key_file),
            ("MU_SMOKE_BEARER_TOKEN_FILE", &self.bearer_token_file),
        ] {
            if let Some(path) = path_opt {
                env.push(ScenarioEnvVar {
                    key: env_key.to_string(),
                    value: path.clone(),
                });
                if !ro_mounts.contains(path) {
                    ro_mounts.push(path.clone());
                }
            }
        }
        let timeout_secs = self.timeout_secs.unwrap_or(default_timeout_secs);
        env.push(ScenarioEnvVar {
            key: "MU_SMOKE_TIMEOUT_SECS".to_string(),
            value: timeout_secs.to_string(),
        });

        ScenarioTestSpec {
            name: self.name.clone(),
            test_binary: self.test_binary.clone(),
            args: self.args.clone(),
            env,
            cidrs: self.restricted_cidrs.clone(),
            ro_mounts,
            critical: true,
            timeout_secs,
        }
    }
}

fn validate_target_url(scenario: &str, raw: &str) -> Result<(), PolicyRepoError> {
    let trimmed = raw.trim();
    if trimmed != raw || trimmed.chars().any(char::is_whitespace) {
        return Err(PolicyRepoError::Schema(format!(
            "scenario '{scenario}' target_url must not contain whitespace"
        )));
    }
    let rest = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .ok_or_else(|| {
            PolicyRepoError::Schema(format!(
                "scenario '{scenario}' target_url must use http:// or https://"
            ))
        })?;
    let host_port = rest.split('/').next().unwrap_or("");
    if host_port.is_empty() {
        return Err(PolicyRepoError::Schema(format!(
            "scenario '{scenario}' target_url must contain a non-empty host"
        )));
    }
    Ok(())
}

fn validate_target_addr(scenario: &str, raw: &str) -> Result<(), PolicyRepoError> {
    let trimmed = raw.trim();
    if trimmed != raw || trimmed.chars().any(char::is_whitespace) {
        return Err(PolicyRepoError::Schema(format!(
            "scenario '{scenario}' target_addr must not contain whitespace"
        )));
    }
    let Some((host, port_str)) = trimmed.rsplit_once(':') else {
        return Err(PolicyRepoError::Schema(format!(
            "scenario '{scenario}' target_addr must use host:port syntax"
        )));
    };
    if host.is_empty() {
        return Err(PolicyRepoError::Schema(format!(
            "scenario '{scenario}' target_addr host cannot be empty"
        )));
    }
    let port: u16 = port_str.parse().map_err(|_| {
        PolicyRepoError::Schema(format!(
            "scenario '{scenario}' target_addr port must be a valid u16"
        ))
    })?;
    if port == 0 {
        return Err(PolicyRepoError::Schema(format!(
            "scenario '{scenario}' target_addr port must be > 0"
        )));
    }
    Ok(())
}

/// Authoritative per-service deployment and scenario binding contract loaded from
/// `contracts/services/<service>.yml`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyServiceContract {
    pub version: String,
    pub service: String,
    #[serde(default)]
    pub target_nodes: Vec<String>,
    #[serde(default = "default_lease_ttl")]
    pub lease_ttl_seconds: u64,
    #[serde(default = "default_warmup_timeout")]
    pub warmup_timeout_seconds: u64,
    #[serde(default = "default_bake_window")]
    pub bake_window_seconds: u64,
    #[serde(default)]
    pub max_error_logs: u32,
    #[serde(default = "default_max_p99_latency_ms")]
    pub max_p99_latency_ms: f64,
    #[serde(default)]
    pub ab_rules: AbRulesConfig,
    #[serde(default)]
    pub deployment: PolicyDeploymentSpec,
    #[serde(default)]
    pub sandbox_ceiling: SandboxCeiling,
    pub integration_tests: IntegrationTestSelector,
    #[serde(default)]
    pub scenarios: Vec<ScenarioBinding>,
}

impl PolicyServiceContract {
    pub fn from_yaml_str(yaml: &str) -> Result<Self, PolicyRepoError> {
        let parsed: Self = serde_yaml::from_str(yaml)
            .map_err(|e| PolicyRepoError::Schema(format!("service contract YAML error: {e}")))?;
        parsed.validate()?;
        Ok(parsed)
    }

    /// Returns effective ordered target nodes (top-level or `deployment.target_nodes` for v1 compat).
    #[must_use]
    pub fn effective_target_nodes(&self) -> &[String] {
        if !self.target_nodes.is_empty() {
            &self.target_nodes
        } else {
            &self.deployment.target_nodes
        }
    }

    /// Returns `true` when this service contract requires a verified integration test archive
    /// (any non-built-in selected test or any configured `scenarios[]` entry).
    #[must_use]
    pub fn requires_it_archive(&self) -> bool {
        if !self.scenarios.is_empty() {
            return true;
        }
        match &self.integration_tests {
            IntegrationTestSelector::All(_) => false,
            IntegrationTestSelector::Selected(tests) => tests
                .iter()
                .any(|t| !BUILTIN_INTEGRATION_TESTS.contains(&t.trim())),
        }
    }

    pub fn validate(&self) -> Result<(), PolicyRepoError> {
        let version = self.version.trim();
        if version != "1" && version != "2" {
            return Err(PolicyRepoError::Schema(format!(
                "unsupported service contract version '{}', expected '1' or '2'",
                self.version
            )));
        }
        validate_service_identifier(&self.service)?;

        let targets = self.effective_target_nodes();
        if targets.is_empty() {
            return Err(PolicyRepoError::Schema(format!(
                "service '{}' target_nodes cannot be empty",
                self.service
            )));
        }
        let mut seen_nodes = HashSet::with_capacity(targets.len());
        for node in targets {
            validate_non_blank("target_nodes[]", node)?;
            let trimmed = node.trim().to_string();
            if !seen_nodes.insert(trimmed.clone()) {
                return Err(PolicyRepoError::Schema(format!(
                    "service '{}' has duplicate target_node '{trimmed}'",
                    self.service
                )));
            }
        }
        if self.lease_ttl_seconds == 0 {
            return Err(PolicyRepoError::Schema(
                "lease_ttl_seconds must be > 0".into(),
            ));
        }
        if self.warmup_timeout_seconds == 0 {
            return Err(PolicyRepoError::Schema(
                "warmup_timeout_seconds must be > 0".into(),
            ));
        }
        if self.bake_window_seconds == 0 {
            return Err(PolicyRepoError::Schema(
                "bake_window_seconds must be > 0".into(),
            ));
        }
        if !self.max_p99_latency_ms.is_finite() || self.max_p99_latency_ms <= 0.0 {
            return Err(PolicyRepoError::Schema(format!(
                "max_p99_latency_ms must be finite and > 0, got {}",
                self.max_p99_latency_ms
            )));
        }

        self.deployment.validate()?;
        self.sandbox_ceiling.validate()?;

        match &self.integration_tests {
            IntegrationTestSelector::All(raw) => {
                if version != "1" || !raw.trim().eq_ignore_ascii_case("all") {
                    return Err(PolicyRepoError::Schema(format!(
                        "service '{}' version '{version}' requires an explicit non-empty integration_tests list",
                        self.service
                    )));
                }
            }
            IntegrationTestSelector::Selected(tests) => {
                if tests.is_empty() {
                    return Err(PolicyRepoError::Schema(format!(
                        "service '{}' integration_tests list cannot be empty",
                        self.service
                    )));
                }
                let mut seen = HashSet::with_capacity(tests.len());
                for t in tests {
                    let trimmed = t.trim();
                    if trimmed.is_empty() {
                        return Err(PolicyRepoError::Schema(format!(
                            "service '{}' integration_tests contains blank entry",
                            self.service
                        )));
                    }
                    if !seen.insert(trimmed.to_string()) {
                        return Err(PolicyRepoError::Schema(format!(
                            "service '{}' has duplicate integration test '{trimmed}'",
                            self.service
                        )));
                    }
                }
            }
        }

        if version == "2" && self.scenarios.is_empty() {
            return Err(PolicyRepoError::Schema(format!(
                "service '{}' version '2' contract requires non-empty scenarios[]",
                self.service
            )));
        }
        let mut seen_scenarios = HashSet::with_capacity(self.scenarios.len());
        for scenario in &self.scenarios {
            scenario.validate()?;
            let trimmed = scenario.name.trim().to_string();
            if !seen_scenarios.insert(trimmed.clone()) {
                return Err(PolicyRepoError::Schema(format!(
                    "service '{}' has duplicate scenario '{trimmed}'",
                    self.service
                )));
            }
        }

        Ok(())
    }

    /// Cross-checks target nodes and `sandbox_ceiling.max_memlock_kb` against `contracts/nodes.yml`.
    pub fn validate_against_nodes(
        &self,
        inventory: &NodesInventory,
    ) -> Result<(), PolicyRepoError> {
        for node_id in self.effective_target_nodes() {
            let Some(node) = inventory.find_node(node_id) else {
                return Err(PolicyRepoError::Schema(format!(
                    "service '{}' references unknown target_node '{node_id}'",
                    self.service
                )));
            };
            if self.sandbox_ceiling.max_memlock_kb > node.max_memlock_kb {
                return Err(PolicyRepoError::Schema(format!(
                    "service '{}' sandbox_ceiling.max_memlock_kb ({}) exceeds node '{}' limit ({})",
                    self.service,
                    self.sandbox_ceiling.max_memlock_kb,
                    node.node_id,
                    node.max_memlock_kb
                )));
            }
        }
        for ov in &self.deployment.node_overrides {
            if inventory.find_node(&ov.node_id).is_none() {
                return Err(PolicyRepoError::Schema(format!(
                    "service '{}' node_override references unknown node '{}'",
                    self.service, ov.node_id
                )));
            }
        }
        Ok(())
    }

    /// Converts this authoritative service contract into a [`MuConDeConfig`] consumed by the
    /// orchestrator's rollout loop (normalizing `version` to `"1"` for internal compatibility).
    #[must_use]
    pub fn to_muconde_config(&self, it_archive_digest: Option<String>) -> MuConDeConfig {
        MuConDeConfig {
            version: "1".to_string(),
            service: self.service.clone(),
            target_nodes: self.effective_target_nodes().to_vec(),
            lease_ttl_seconds: self.lease_ttl_seconds,
            warmup_timeout_seconds: self.warmup_timeout_seconds,
            bake_window_seconds: self.bake_window_seconds,
            max_error_logs: self.max_error_logs,
            max_p99_latency_ms: self.max_p99_latency_ms,
            integration_tests: self.integration_tests.clone(),
            it_archive_digest,
            ab_rules: self.ab_rules.clone(),
            deployment: self.deployment.to_contract_deployment(),
        }
    }
}

fn node_id_to_snake(node_id: &str) -> String {
    node_id.trim().to_ascii_lowercase().replace('-', "_")
}

/// Resolves the [`ScenarioTestSpec`] list applicable to `node_id` from `contract.scenarios`.
///
/// Selection rules:
/// 1. If any scenario name in `contract.scenarios` carries a node suffix `_<node_id_snake>`
///    matching one of the contract's target nodes (or known inventory nodes), select only
///    scenarios whose name ends with `_<node_id_snake>` for `node_id`.
/// 2. Otherwise, all scenarios are treated as shared and apply to every target node.
///
/// Fails closed with [`PolicyRepoError::UnresolvedScenario`] if a `version: "2"` contract
/// yields zero scenarios for `node_id` or if any non-built-in test in `integration_tests`
/// has no matching scenario binding (`test_binary` or `name`).
pub fn resolve_scenarios_for_node(
    contract: &PolicyServiceContract,
    inventory: &NodesInventory,
    node_id: &str,
) -> Result<Vec<ScenarioTestSpec>, PolicyRepoError> {
    let mut known_suffixes: Vec<String> = contract
        .effective_target_nodes()
        .iter()
        .map(|n| format!("_{}", node_id_to_snake(n)))
        .collect();
    for inv_node in &inventory.nodes {
        let suffix = format!("_{}", node_id_to_snake(&inv_node.node_id));
        if !known_suffixes.contains(&suffix) {
            known_suffixes.push(suffix);
        }
    }

    let has_node_specific = contract.scenarios.iter().any(|scenario| {
        let lower = scenario.name.trim().to_ascii_lowercase();
        known_suffixes.iter().any(|s| lower.ends_with(s))
    });

    let target_suffix = format!("_{}", node_id_to_snake(node_id));
    let filtered: Vec<&ScenarioBinding> = if has_node_specific {
        contract
            .scenarios
            .iter()
            .filter(|s| s.name.trim().to_ascii_lowercase().ends_with(&target_suffix))
            .collect()
    } else {
        contract.scenarios.iter().collect()
    };

    if contract.version.trim() == "2" && filtered.is_empty() {
        return Err(PolicyRepoError::UnresolvedScenario {
            service: contract.service.clone(),
            node: node_id.to_string(),
            reason: "no matching scenario binding found for target node".to_string(),
        });
    }

    let specs: Vec<ScenarioTestSpec> = filtered
        .into_iter()
        .map(|b| b.to_scenario_test_spec(contract.warmup_timeout_seconds))
        .collect();

    if contract.version.trim() == "2" {
        if let IntegrationTestSelector::Selected(ref tests) = contract.integration_tests {
            for required in tests {
                let trimmed = required.trim();
                if BUILTIN_INTEGRATION_TESTS.contains(&trimmed) {
                    continue;
                }
                let matched = specs
                    .iter()
                    .any(|s| s.test_binary == trimmed || s.name == trimmed);
                if !matched {
                    return Err(PolicyRepoError::UnresolvedScenario {
                        service: contract.service.clone(),
                        node: node_id.to_string(),
                        reason: format!(
                            "required integration test '{trimmed}' has no resolved scenario binding"
                        ),
                    });
                }
            }
        }
    }

    Ok(specs)
}

/// Builds a per-node [`ScenarioExecutionPlan`] from a verified contract, node inventory, and
/// candidate IT bundle metadata.
#[allow(clippy::too_many_arguments)]
pub fn build_scenario_execution_plan(
    deployment_id: &str,
    lease_id: &str,
    policy_commit_sha: &str,
    contract: &PolicyServiceContract,
    inventory: &NodesInventory,
    node_id: &str,
    it_archive_digest: Option<&str>,
    bundle_id: Option<&str>,
) -> Result<ScenarioExecutionPlan, PolicyRepoError> {
    let node_spec =
        inventory
            .find_node(node_id)
            .ok_or_else(|| PolicyRepoError::UnresolvedScenario {
                service: contract.service.clone(),
                node: node_id.to_string(),
                reason: "target node missing from verified nodes inventory".to_string(),
            })?;

    let scenarios = resolve_scenarios_for_node(contract, inventory, node_id)?;

    let selected_tests = match &contract.integration_tests {
        IntegrationTestSelector::All(_) => Vec::new(),
        IntegrationTestSelector::Selected(list) => list.clone(),
    };

    let mut env: Vec<ScenarioEnvVar> = Vec::new();
    let mut args: Vec<String> = Vec::new();
    let mut cidrs: Vec<String> = Vec::new();
    let mut ro_mounts: Vec<String> = Vec::new();

    for sc in &scenarios {
        for ev in &sc.env {
            if !env.contains(ev) {
                env.push(ev.clone());
            }
        }
        for arg in &sc.args {
            if !args.contains(arg) {
                args.push(arg.clone());
            }
        }
        for cidr in &sc.cidrs {
            if !cidrs.contains(cidr) {
                cidrs.push(cidr.clone());
            }
        }
        for mount in &sc.ro_mounts {
            if !ro_mounts.contains(mount) {
                ro_mounts.push(mount.clone());
            }
        }
    }

    Ok(ScenarioExecutionPlan {
        deployment_id: deployment_id.to_string(),
        lease_id: lease_id.to_string(),
        service_name: contract.service.clone(),
        node_id: node_id.to_string(),
        policy_commit_sha: policy_commit_sha.to_string(),
        it_archive_digest: it_archive_digest.map(str::to_string),
        bundle_id: bundle_id.map(str::to_string),
        selected_tests,
        scenarios,
        env,
        args,
        cidrs,
        ro_mounts,
        max_pids: contract.sandbox_ceiling.max_pids,
        max_memlock_kb: contract
            .sandbox_ceiling
            .max_memlock_kb
            .min(node_spec.max_memlock_kb),
        auto_rollback_on_critical: contract.ab_rules.auto_rollback_on_critical,
    })
}

/// Verified policy repository state pinned to a specific Git commit SHA.
#[derive(Debug, Clone)]
pub struct VerifiedPolicyBundle {
    pub policy_commit_sha: String,
    pub verified_at_epoch_ms: u64,
    pub commit_policy: CommitVerificationPolicy,
    pub nodes_inventory: NodesInventory,
    pub service_contracts: BTreeMap<String, PolicyServiceContract>,
}

/// Summary returned by authenticated policy refresh operations (`POST /api/cd/policy/refresh`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedPolicySummary {
    pub refreshed: bool,
    pub policy_commit_sha: String,
    pub verified_at_epoch_ms: u64,
    pub services: Vec<String>,
}

/// Immutable per-`deployment_id` snapshot pinned before lease acquisition so an entire
/// multi-node rollout evaluates against one consistent verified policy commit.
#[derive(Debug, Clone)]
pub struct PinnedDeploymentSnapshot {
    pub deployment_id: String,
    pub policy_commit_sha: String,
    pub verified_at_epoch_ms: u64,
    pub service_contract: PolicyServiceContract,
    pub nodes_inventory: NodesInventory,
    pub resolved_node_plans: BTreeMap<String, ScenarioExecutionPlan>,
    pub it_archive_digest: Option<String>,
    pub bundle_id: Option<String>,
}

impl PinnedDeploymentSnapshot {
    /// Returns a cloned [`ScenarioExecutionPlan`] for `node_id` stamped with the node-level
    /// `deployment_id` and active `lease_id`.
    #[must_use]
    pub fn plan_for_node(
        &self,
        node_id: &str,
        deployment_id: &str,
        lease_id: &str,
    ) -> Option<ScenarioExecutionPlan> {
        let mut plan = self
            .resolved_node_plans
            .get(node_id)
            .or_else(|| {
                // Also match resolved hostname back to canonical node_id in inventory.
                let canonical = self
                    .nodes_inventory
                    .nodes
                    .iter()
                    .find(|n| n.host == node_id)
                    .map(|n| n.node_id.as_str())?;
                self.resolved_node_plans.get(canonical)
            })?
            .clone();
        plan.deployment_id = deployment_id.to_string();
        plan.lease_id = lease_id.to_string();
        Some(plan)
    }

    /// Builds a [`MuConDeConfig`] derived exclusively from this immutable pinned snapshot.
    #[must_use]
    pub fn to_muconde_config(&self) -> MuConDeConfig {
        self.service_contract
            .to_muconde_config(self.it_archive_digest.clone())
    }
}

#[derive(Debug)]
struct SnapshotCache {
    capacity: usize,
    order: VecDeque<String>,
    entries: HashMap<String, Arc<PinnedDeploymentSnapshot>>,
}

impl SnapshotCache {
    fn new(capacity: usize) -> Self {
        let bounded = capacity.max(1);
        Self {
            capacity: bounded,
            order: VecDeque::with_capacity(bounded),
            entries: HashMap::with_capacity(bounded),
        }
    }

    fn insert(&mut self, key: String, snapshot: Arc<PinnedDeploymentSnapshot>) {
        if let Some(slot) = self.entries.get_mut(&key) {
            *slot = snapshot;
            return;
        }
        while self.entries.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            } else {
                break;
            }
        }
        self.order.push_back(key.clone());
        self.entries.insert(key, snapshot);
    }

    fn get(&self, key: &str) -> Option<Arc<PinnedDeploymentSnapshot>> {
        self.entries.get(key).cloned()
    }
}

#[derive(Debug, Default)]
struct RepoVerificationState {
    verified: Option<VerifiedPolicyBundle>,
    unverified_error: Option<String>,
}

/// Fail-closed Git deployment policy repository loader with SSH signature verification,
/// single-flight refresh locking, and an immutable bounded snapshot cache.
pub struct PolicyRepository {
    config: PolicyRepoConfig,
    fetch_lock: tokio::sync::Mutex<()>,
    state: RwLock<RepoVerificationState>,
    snapshots: RwLock<SnapshotCache>,
    telemetry_sink: Option<Arc<dyn CdTelemetrySink>>,
    controller_node_id: String,
    verify_failure_count: AtomicU64,
}

impl std::fmt::Debug for PolicyRepository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyRepository")
            .field("repo_dir", &self.config.repo_dir)
            .field("refresh_on_deploy", &self.config.refresh_on_deploy)
            .field("refresh_interval_secs", &self.config.refresh_interval_secs)
            .field(
                "verify_failure_count",
                &self.verify_failure_count.load(Ordering::Relaxed),
            )
            .finish()
    }
}

impl PolicyRepository {
    /// Creates a new [`PolicyRepository`] backed by `config`.
    #[must_use]
    pub fn new(config: PolicyRepoConfig) -> Self {
        Self {
            config,
            fetch_lock: tokio::sync::Mutex::new(()),
            state: RwLock::new(RepoVerificationState::default()),
            snapshots: RwLock::new(SnapshotCache::new(DEFAULT_SNAPSHOT_CACHE_CAPACITY)),
            telemetry_sink: None,
            controller_node_id: "node-a".to_string(),
            verify_failure_count: AtomicU64::new(0),
        }
    }

    /// Overrides the bounded snapshot cache capacity (useful for deterministic eviction tests).
    #[must_use]
    pub fn with_snapshot_cache_capacity(mut self, capacity: usize) -> Self {
        self.snapshots = RwLock::new(SnapshotCache::new(capacity));
        self
    }

    /// Attaches a [`CdTelemetrySink`] to emit `ERROR` logs and `muconde.controller.policy_verify_failed` metrics.
    #[must_use]
    pub fn with_telemetry_sink(
        mut self,
        sink: Arc<dyn CdTelemetrySink>,
        controller_node_id: impl Into<String>,
    ) -> Self {
        self.telemetry_sink = Some(sink);
        self.controller_node_id = controller_node_id.into();
        self
    }

    /// Returns the configuration for this policy repository.
    #[must_use]
    pub fn config(&self) -> &PolicyRepoConfig {
        &self.config
    }

    /// Returns total failed verification attempts recorded by this repository instance.
    #[must_use]
    pub fn verify_failure_count(&self) -> u64 {
        self.verify_failure_count.load(Ordering::Relaxed)
    }

    /// Resolves the canonical hostname for `node_id` from the latest verified node inventory, if pinned.
    #[must_use]
    pub fn resolve_node_host(&self, node_id: &str) -> Option<String> {
        self.state.read().ok().and_then(|st| {
            st.verified
                .as_ref()
                .and_then(|b| b.nodes_inventory.find_node(node_id))
                .map(|n| n.host.clone())
        })
    }

    /// Returns the currently cached immutable snapshot for `deployment_id`, if present.
    #[must_use]
    pub fn get_snapshot(&self, deployment_id: &str) -> Option<Arc<PinnedDeploymentSnapshot>> {
        self.snapshots
            .read()
            .ok()
            .and_then(|cache| cache.get(deployment_id))
    }

    /// Associates an additional `deployment_id` alias (e.g. a per-node deployment ID in a
    /// multi-node rollout) with the same immutable [`PinnedDeploymentSnapshot`].
    pub fn register_snapshot_alias(
        &self,
        deployment_id: impl Into<String>,
        snapshot: Arc<PinnedDeploymentSnapshot>,
    ) {
        if let Ok(mut cache) = self.snapshots.write() {
            cache.insert(deployment_id.into(), snapshot);
        }
    }

    /// Spawns a periodic background refresh loop running every `refresh_interval_secs`.
    pub fn spawn_background_refresh(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let interval = Duration::from_secs(self.config.refresh_interval_secs);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                if let Err(err) = self.refresh_and_verify().await {
                    tracing::error!(
                        error = %err,
                        "Periodic deployment policy repository refresh failed closed"
                    );
                }
            }
        })
    }

    /// Performs a single-flight Git fetch (when a remote is configured) and full fail-closed
    /// signature + schema verification of the candidate commit tip.
    pub async fn refresh_and_verify(&self) -> Result<VerifiedPolicySummary, PolicyRepoError> {
        let _guard = self.fetch_lock.lock().await;
        let Some(ref repo_dir) = self.config.repo_dir else {
            return Err(self
                .record_verify_failure("deployment policy repo directory not configured", true)
                .await);
        };
        if !repo_dir.is_dir() {
            return Err(self
                .record_verify_failure(
                    format!(
                        "deployment policy repo directory '{}' does not exist",
                        repo_dir.display()
                    ),
                    true,
                )
                .await);
        }

        let target_branch = self.config.branch.as_deref().unwrap_or("main");
        let has_origin = self.has_origin_remote(repo_dir).await;
        if self.config.repo_url.is_some() || has_origin {
            if let Err(fetch_err) = self.git_fetch_origin(repo_dir, target_branch).await {
                let already_pinned = self
                    .state
                    .read()
                    .map(|st| st.verified.is_some() && st.unverified_error.is_none())
                    .unwrap_or(false);
                if !already_pinned {
                    return Err(self
                        .record_verify_failure(
                            format!("git fetch failed while unpinned: {fetch_err}"),
                            true,
                        )
                        .await);
                }
                tracing::error!(
                    error = %fetch_err,
                    "git fetch failed; retaining previously verified pinned commit"
                );
                let _ = self
                    .record_verify_failure(
                        format!("git fetch failed while retaining pinned tip: {fetch_err}"),
                        false,
                    )
                    .await;
            }
        }

        match self.verify_candidate_tip(repo_dir).await {
            Ok(bundle) => {
                let summary = VerifiedPolicySummary {
                    refreshed: true,
                    policy_commit_sha: bundle.policy_commit_sha.clone(),
                    verified_at_epoch_ms: bundle.verified_at_epoch_ms,
                    services: bundle.service_contracts.keys().cloned().collect(),
                };
                if let Ok(mut st) = self.state.write() {
                    st.verified = Some(bundle);
                    st.unverified_error = None;
                }
                Ok(summary)
            }
            Err(err) => Err(self.record_verify_failure(err.to_string(), true).await),
        }
    }

    /// Ensures a verified policy bundle is available (refreshing on deploy when enabled) and
    /// fails closed if verification has failed.
    pub async fn ensure_verified(&self) -> Result<VerifiedPolicyBundle, PolicyRepoError> {
        let needs_refresh = self.config.refresh_on_deploy
            || self
                .state
                .read()
                .map(|st| st.verified.is_none() || st.unverified_error.is_some())
                .unwrap_or(true);
        if needs_refresh {
            self.refresh_and_verify().await?;
        }
        let guard = self
            .state
            .read()
            .map_err(|_| PolicyRepoError::Unverified("policy repository lock poisoned".into()))?;
        if let Some(ref err) = guard.unverified_error {
            return Err(PolicyRepoError::Unverified(err.clone()));
        }
        guard
            .verified
            .clone()
            .ok_or_else(|| PolicyRepoError::Unverified("no verified policy commit pinned".into()))
    }

    /// Pins an immutable [`PinnedDeploymentSnapshot`] for `deployment_id` and `service_name`
    /// from the verified policy repository and caches it keyed by `deployment_id`.
    pub async fn pin_deployment_snapshot(
        &self,
        deployment_id: &str,
        service_name: &str,
        it_archive_digest: Option<&str>,
        bundle_id: Option<&str>,
    ) -> Result<Arc<PinnedDeploymentSnapshot>, PolicyRepoError> {
        let verified = self.ensure_verified().await?;
        self.pin_deployment_snapshot_from_verified(
            &verified,
            deployment_id,
            service_name,
            it_archive_digest,
            bundle_id,
        )
    }

    /// Pins an immutable [`PinnedDeploymentSnapshot`] from an already-verified policy bundle
    /// without re-running `git fetch`, caching it keyed by `deployment_id`.
    pub fn pin_deployment_snapshot_from_verified(
        &self,
        verified: &VerifiedPolicyBundle,
        deployment_id: &str,
        service_name: &str,
        it_archive_digest: Option<&str>,
        bundle_id: Option<&str>,
    ) -> Result<Arc<PinnedDeploymentSnapshot>, PolicyRepoError> {
        let canonical_service = validate_service_identifier(service_name)?;
        let contract = verified
            .service_contracts
            .get(&canonical_service)
            .cloned()
            .ok_or_else(|| PolicyRepoError::ServiceContractNotFound(canonical_service.clone()))?;

        let mut resolved_node_plans = BTreeMap::new();
        for node_id in contract.effective_target_nodes() {
            let plan = build_scenario_execution_plan(
                deployment_id,
                "",
                &verified.policy_commit_sha,
                &contract,
                &verified.nodes_inventory,
                node_id,
                it_archive_digest,
                bundle_id,
            )?;
            resolved_node_plans.insert(node_id.clone(), plan);
        }

        let snapshot = Arc::new(PinnedDeploymentSnapshot {
            deployment_id: deployment_id.to_string(),
            policy_commit_sha: verified.policy_commit_sha.clone(),
            verified_at_epoch_ms: verified.verified_at_epoch_ms,
            service_contract: contract,
            nodes_inventory: verified.nodes_inventory.clone(),
            resolved_node_plans,
            it_archive_digest: it_archive_digest.map(str::to_string),
            bundle_id: bundle_id.map(str::to_string),
        });

        if let Ok(mut cache) = self.snapshots.write() {
            cache.insert(deployment_id.to_string(), snapshot.clone());
        }

        Ok(snapshot)
    }

    async fn record_verify_failure(
        &self,
        reason: impl Into<String>,
        mark_unverified: bool,
    ) -> PolicyRepoError {
        let reason = reason.into();
        let count = self.verify_failure_count.fetch_add(1, Ordering::Relaxed) + 1;
        if mark_unverified {
            if let Ok(mut st) = self.state.write() {
                st.unverified_error = Some(reason.clone());
            }
        }
        tracing::error!(
            error = %reason,
            metric = METRIC_POLICY_VERIFY_FAILED,
            failure_count = count,
            "Deployment policy repository verification failed closed"
        );
        if let Some(ref sink) = self.telemetry_sink {
            let now_ns = now_unix_nano();
            let trace = TraceContext::from_seed(
                now_ns as u64,
                count.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1,
                1,
                true,
            );
            let log = build_cd_log(
                trace.trace_id,
                trace.span_id,
                now_ns,
                17,
                "ERROR",
                &self.controller_node_id,
                format!("Deployment policy repository verification failed: {reason}"),
                serde_json::json!({
                    "event": "cd.policy.verify_failed",
                    "reason": reason,
                    "failure_count": count,
                }),
            );
            let metric = OtelMetricEntry {
                timestamp_unix_nano: now_ns,
                service_name: CD_SERVICE_NAME.to_string(),
                node_id: self.controller_node_id.clone(),
                metric_name: METRIC_POLICY_VERIFY_FAILED.to_string(),
                metric_unit: "count".to_string(),
                value_f64: 1.0,
                arch: std::env::consts::ARCH.to_string(),
                cpu_cluster: None,
                vlen_bits: None,
                memlock_used_bytes: None,
                memlock_limit_bytes: None,
                trace_id: Some(trace.trace_id_hex()),
                span_id: Some(trace.span_id_hex()),
                attributes_json: serde_json::json!({
                    "reason": reason,
                })
                .to_string(),
            };
            sink.emit_logs(vec![log]).await;
            sink.emit_metrics(vec![metric]).await;
        }
        PolicyRepoError::Unverified(reason)
    }

    async fn has_origin_remote(&self, repo_dir: &Path) -> bool {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo_dir)
            .args(["remote", "get-url", "origin"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .await;
        matches!(output, Ok(out) if out.status.success())
    }

    async fn git_fetch_origin(&self, repo_dir: &Path, branch: &str) -> Result<(), String> {
        let mut cmd = Command::new("git");
        cmd.arg("-C")
            .arg(repo_dir)
            .args(["fetch", "--prune", "origin", branch])
            .env("GIT_TERMINAL_PROMPT", "0");

        if let Some(ssh_cmd) = self.build_git_ssh_command() {
            cmd.env("GIT_SSH_COMMAND", ssh_cmd);
        }

        let output = tokio::time::timeout(GIT_FETCH_TIMEOUT, cmd.output())
            .await
            .map_err(|_| format!("git fetch timed out after {}s", GIT_FETCH_TIMEOUT.as_secs()))?
            .map_err(|e| format!("failed to spawn git fetch: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "git fetch exited with {}: {}",
                output.status,
                stderr.trim()
            ));
        }
        Ok(())
    }

    fn build_git_ssh_command(&self) -> Option<String> {
        if self.config.deploy_key_path.is_none() && self.config.known_hosts_path.is_none() {
            return None;
        }
        let mut parts = vec![
            "ssh".to_string(),
            "-o".to_string(),
            "BatchMode=yes".to_string(),
            "-o".to_string(),
            "IdentitiesOnly=yes".to_string(),
        ];
        if let Some(ref key) = self.config.deploy_key_path {
            parts.push("-i".to_string());
            parts.push(shell_single_quote(&key.to_string_lossy()));
        }
        if let Some(ref kh) = self.config.known_hosts_path {
            parts.push("-o".to_string());
            parts.push("StrictHostKeyChecking=yes".to_string());
            parts.push("-o".to_string());
            parts.push(format!(
                "UserKnownHostsFile={}",
                shell_single_quote(&kh.to_string_lossy())
            ));
        }
        Some(parts.join(" "))
    }

    async fn verify_candidate_tip(
        &self,
        repo_dir: &Path,
    ) -> Result<VerifiedPolicyBundle, PolicyRepoError> {
        let initial_branch = self.config.branch.as_deref().unwrap_or("main");
        let mut commit_sha = self
            .resolve_candidate_commit(repo_dir, initial_branch)
            .await?;

        let commit_policy_yaml = self
            .git_show_file(repo_dir, &commit_sha, "policy/commit-verification.yml")
            .await?;
        let mut commit_policy = CommitVerificationPolicy::from_yaml_str(&commit_policy_yaml)?;

        // If config did not explicitly override branch and commit-verification.yml tracks a
        // different branch name, re-resolve against the declared policy branch.
        if self.config.branch.is_none() && commit_policy.branch != initial_branch {
            commit_sha = self
                .resolve_candidate_commit(repo_dir, &commit_policy.branch)
                .await?;
            let refreshed_policy_yaml = self
                .git_show_file(repo_dir, &commit_sha, "policy/commit-verification.yml")
                .await?;
            commit_policy = CommitVerificationPolicy::from_yaml_str(&refreshed_policy_yaml)?;
        }

        let effective_signers = self
            .config
            .allowed_signers_path
            .clone()
            .unwrap_or_else(|| PathBuf::from(&commit_policy.allowed_signers_path));
        validate_allowed_signers_file(&effective_signers)?;

        if commit_policy.require_signed_commits {
            verify_git_ssh_commit_signature(repo_dir, &commit_sha, &effective_signers).await?;
        }

        let nodes_yaml = self
            .git_show_file(repo_dir, &commit_sha, "contracts/nodes.yml")
            .await?;
        let nodes_inventory = NodesInventory::from_yaml_str(&nodes_yaml)?;

        let service_files = self
            .git_list_service_contract_files(repo_dir, &commit_sha)
            .await?;
        if service_files.is_empty() {
            return Err(PolicyRepoError::Schema(
                "no contracts/services/*.yml files found in policy repository".into(),
            ));
        }

        let mut service_contracts = BTreeMap::new();
        for rel_path in service_files {
            let yaml = self.git_show_file(repo_dir, &commit_sha, &rel_path).await?;
            let contract = PolicyServiceContract::from_yaml_str(&yaml)?;
            contract.validate_against_nodes(&nodes_inventory)?;

            // Ensure every target node resolves its scenario plan cleanly before accepting tip.
            for node_id in contract.effective_target_nodes() {
                let _ = resolve_scenarios_for_node(&contract, &nodes_inventory, node_id)?;
            }

            let file_stem = Path::new(&rel_path)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            if file_stem != contract.service {
                return Err(PolicyRepoError::Schema(format!(
                    "contract file '{rel_path}' stem '{file_stem}' does not match service '{}'",
                    contract.service
                )));
            }
            if service_contracts
                .insert(contract.service.clone(), contract)
                .is_some()
            {
                return Err(PolicyRepoError::Schema(format!(
                    "duplicate service contract '{file_stem}'"
                )));
            }
        }

        Ok(VerifiedPolicyBundle {
            policy_commit_sha: commit_sha,
            verified_at_epoch_ms: now_epoch_ms(),
            commit_policy,
            nodes_inventory,
            service_contracts,
        })
    }

    async fn resolve_candidate_commit(
        &self,
        repo_dir: &Path,
        branch: &str,
    ) -> Result<String, PolicyRepoError> {
        let remote_ref = format!("refs/remotes/origin/{branch}");
        if let Ok(sha) = git_rev_parse(repo_dir, &remote_ref).await {
            return Ok(sha);
        }
        let local_branch = format!("refs/heads/{branch}");
        if let Ok(sha) = git_rev_parse(repo_dir, &local_branch).await {
            return Ok(sha);
        }
        git_rev_parse(repo_dir, "HEAD").await.map_err(|e| {
            PolicyRepoError::Unverified(format!(
                "failed to resolve candidate commit for branch '{branch}': {e}"
            ))
        })
    }

    async fn git_show_file(
        &self,
        repo_dir: &Path,
        commit_sha: &str,
        rel_path: &str,
    ) -> Result<String, PolicyRepoError> {
        let spec = format!("{commit_sha}:{rel_path}");
        let output = Command::new("git")
            .arg("-C")
            .arg(repo_dir)
            .args(["show", &spec])
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .await
            .map_err(|e| PolicyRepoError::Unverified(format!("failed to run git show: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PolicyRepoError::Unverified(format!(
                "git show '{spec}' failed: {}",
                stderr.trim()
            )));
        }

        String::from_utf8(output.stdout).map_err(|e| {
            PolicyRepoError::Schema(format!("file '{rel_path}' is not valid UTF-8: {e}"))
        })
    }

    async fn git_list_service_contract_files(
        &self,
        repo_dir: &Path,
        commit_sha: &str,
    ) -> Result<Vec<String>, PolicyRepoError> {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo_dir)
            .args([
                "ls-tree",
                "-r",
                "--name-only",
                commit_sha,
                "contracts/services",
            ])
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .await
            .map_err(|e| PolicyRepoError::Unverified(format!("failed to run git ls-tree: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PolicyRepoError::Unverified(format!(
                "git ls-tree contracts/services failed: {}",
                stderr.trim()
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let files = stdout
            .lines()
            .map(str::trim)
            .filter(|line| line.ends_with(".yml") || line.ends_with(".yaml"))
            .map(ToOwned::to_owned)
            .collect();
        Ok(files)
    }
}

fn shell_single_quote(raw: &str) -> String {
    format!("'{}'", raw.replace('\'', "'\\''"))
}

async fn git_rev_parse(repo_dir: &Path, git_ref: &str) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_dir)
        .args(["rev-parse", "--verify", "--quiet", git_ref])
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .await
        .map_err(|e| format!("failed to run git rev-parse: {e}"))?;
    if !output.status.success() {
        return Err(format!("ref '{git_ref}' not found"));
    }
    let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if sha.len() < 7 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("unexpected rev-parse output '{sha}'"));
    }
    Ok(sha)
}

/// Validates that `allowed_signers` exists, is a regular non-empty file, and is neither
/// group-writable nor world-writable (`mode & 0o022 == 0` on Unix).
pub fn validate_allowed_signers_file(path: &Path) -> Result<(), PolicyRepoError> {
    let sym_meta = std::fs::symlink_metadata(path).map_err(|e| {
        PolicyRepoError::Unverified(format!(
            "allowed_signers file '{}' is unreadable: {e}",
            path.display()
        ))
    })?;
    if sym_meta.file_type().is_symlink() {
        return Err(PolicyRepoError::Unverified(format!(
            "allowed_signers file '{}' must not be a symlink",
            path.display()
        )));
    }
    if !sym_meta.is_file() {
        return Err(PolicyRepoError::Unverified(format!(
            "allowed_signers path '{}' is not a regular file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = sym_meta.permissions().mode();
        if (mode & 0o022) != 0 {
            return Err(PolicyRepoError::Unverified(format!(
                "allowed_signers file '{}' has unsafe permissions {:04o} (must not be group/world writable)",
                path.display(),
                mode & 0o7777
            )));
        }
    }
    let content = std::fs::read_to_string(path).map_err(|e| {
        PolicyRepoError::Unverified(format!(
            "failed reading allowed_signers '{}': {e}",
            path.display()
        ))
    })?;
    if content.trim().is_empty() {
        return Err(PolicyRepoError::Unverified(format!(
            "allowed_signers file '{}' is empty",
            path.display()
        )));
    }
    Ok(())
}

async fn verify_git_ssh_commit_signature(
    repo_dir: &Path,
    commit_sha: &str,
    allowed_signers: &Path,
) -> Result<(), PolicyRepoError> {
    let signers_opt = format!("gpg.ssh.allowedSignersFile={}", allowed_signers.display());

    let verify_out = Command::new("git")
        .arg("-C")
        .arg(repo_dir)
        .args([
            "-c",
            "gpg.format=ssh",
            "-c",
            &signers_opt,
            "verify-commit",
            commit_sha,
        ])
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .await
        .map_err(|e| {
            PolicyRepoError::Unverified(format!("failed spawning git verify-commit: {e}"))
        })?;

    if !verify_out.status.success() {
        let stderr = String::from_utf8_lossy(&verify_out.stderr);
        return Err(PolicyRepoError::Unverified(format!(
            "git verify-commit failed for {commit_sha}: {}",
            stderr.trim()
        )));
    }

    let status_out = Command::new("git")
        .arg("-C")
        .arg(repo_dir)
        .args([
            "-c",
            "gpg.format=ssh",
            "-c",
            &signers_opt,
            "log",
            "-1",
            "--format=%G?",
            commit_sha,
        ])
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .await
        .map_err(|e| {
            PolicyRepoError::Unverified(format!("failed spawning git log signature status: {e}"))
        })?;

    if !status_out.status.success() {
        return Err(PolicyRepoError::Unverified(format!(
            "git log --format=%G? exited non-zero for {commit_sha}"
        )));
    }

    let status_code = String::from_utf8_lossy(&status_out.stdout)
        .trim()
        .to_string();
    if status_code != "G" {
        return Err(PolicyRepoError::Unverified(format!(
            "commit {commit_sha} signature status is '{status_code}', expected 'G'"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::RecordingCdTelemetrySink;

    fn sample_nodes_yaml() -> &'static str {
        r#"
nodes:
  - node_id: "node-a"
    arch: "x86_64"
    host: "node-a.cluster.internal"
    max_memlock_kb: 2097152
    max_slots: 1
    thread_budget: 2
    mucd_root: "/srv/mucd"
  - node_id: "worker-riscv64"
    arch: "riscv64gc"
    host: "worker-riscv64.cluster.internal"
    max_memlock_kb: 29360128
    max_slots: 1
    thread_budget: 6
    mucd_root: "/srv/mucd"
"#
    }

    fn sample_multi_node_service_yaml() -> &'static str {
        r#"
version: "2"
service: "example-service"
target_nodes:
  - "node-a"
  - "worker-riscv64"
lease_ttl_seconds: 300
warmup_timeout_seconds: 30
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
    timeout_secs: 15
    restricted_cidrs:
      - "192.0.2.20/32"
      - "127.0.0.1/32"
"#
    }

    #[test]
    fn test_policy_repo_config_env_precedence_and_bounds() {
        let vars = HashMap::from([
            (
                "MU_CD_CONTROLLER_DEPLOY_REPO_DIR",
                "/var/lib/cd/policy-primary",
            ),
            ("MU_CD_DEPLOY_REPO_DIR", "/var/lib/cd/policy-fallback"),
            (
                "MU_CD_DEPLOY_REPO_URL",
                "git@example.invalid:org/policy.git",
            ),
            ("MU_CD_CONTROLLER_DEPLOY_REPO_BRANCH", "release"),
            ("MU_CD_DEPLOY_ALLOWED_SIGNERS", "/etc/mu-cd/allowed_signers"),
            ("MU_CD_DEPLOY_SSH_KEY", "/etc/mu-cd/deploy_key"),
            ("MU_CD_DEPLOY_KNOWN_HOSTS", "/etc/mu-cd/known_hosts"),
            ("MU_CD_DEPLOY_REFRESH_INTERVAL_SECS", "999"),
            ("MU_CD_DEPLOY_REFRESH_ON_DEPLOY", "false"),
        ]);
        let cfg = PolicyRepoConfig::from_env_lookup(&|k| vars.get(k).map(|v| (*v).to_string()));
        assert!(cfg.is_enabled());
        assert_eq!(
            cfg.repo_dir,
            Some(PathBuf::from("/var/lib/cd/policy-primary"))
        );
        assert_eq!(
            cfg.repo_url.as_deref(),
            Some("git@example.invalid:org/policy.git")
        );
        assert_eq!(cfg.branch.as_deref(), Some("release"));
        assert_eq!(
            cfg.allowed_signers_path,
            Some(PathBuf::from("/etc/mu-cd/allowed_signers"))
        );
        assert_eq!(cfg.refresh_interval_secs, MAX_REFRESH_INTERVAL_SECS);
        assert!(!cfg.refresh_on_deploy);

        let low = HashMap::from([("MU_CD_DEPLOY_REFRESH_INTERVAL_SECS", "1")]);
        let cfg_low = PolicyRepoConfig::from_env_lookup(&|k| low.get(k).map(|v| (*v).to_string()));
        assert_eq!(cfg_low.refresh_interval_secs, MIN_REFRESH_INTERVAL_SECS);
        assert!(cfg_low.refresh_on_deploy);
    }

    #[test]
    fn test_service_identifier_digest_and_commit_validators() {
        assert_eq!(
            validate_service_identifier("mu-cd-controller").unwrap(),
            "mu-cd-controller"
        );
        for bad in [
            "",
            "../escape",
            "a/b",
            "a\\b",
            "UpperCase",
            "under_score",
            " a ",
        ] {
            assert!(
                validate_service_identifier(bad).is_err(),
                "expected err for '{bad}'"
            );
        }
        let good_sha = "a".repeat(64);
        assert_eq!(validate_sha256_hex(&good_sha).unwrap(), good_sha);
        assert!(validate_sha256_hex("deadbeef").is_err());
        assert!(validate_sha256_hex(&"z".repeat(64)).is_err());

        assert_eq!(validate_git_commit_sha("0123456").unwrap(), "0123456");
        assert_eq!(
            validate_git_commit_sha(&"A".repeat(40)).unwrap(),
            "a".repeat(40)
        );
        assert!(validate_git_commit_sha("abc").is_err());
        assert!(validate_git_commit_sha(&"a".repeat(41)).is_err());
    }

    #[test]
    fn test_per_node_scenario_filtering_and_shared_fallback() {
        let inventory = NodesInventory::from_yaml_str(sample_nodes_yaml()).unwrap();
        let contract =
            PolicyServiceContract::from_yaml_str(sample_multi_node_service_yaml()).unwrap();
        contract.validate_against_nodes(&inventory).unwrap();

        let plan_a = build_scenario_execution_plan(
            "dep-1",
            "lease-1",
            "0123456789abcdef0123456789abcdef01234567",
            &contract,
            &inventory,
            "node-a",
            Some(&"b".repeat(64)),
            Some("bundle-1"),
        )
        .unwrap();
        assert_eq!(plan_a.scenarios.len(), 1);
        assert_eq!(plan_a.scenarios[0].name, "smoke_example_service_node_a");
        assert!(plan_a.scenarios[0].env.contains(&ScenarioEnvVar {
            key: "MU_SMOKE_TARGET_URL".into(),
            value: "https://node-a.cluster.internal:8445".into(),
        }));
        assert!(plan_a.scenarios[0].env.contains(&ScenarioEnvVar {
            key: "MU_SMOKE_BEARER_TOKEN_FILE".into(),
            value: "/etc/mu-cd-canary/tokens/cd-readonly.token".into(),
        }));
        assert_eq!(plan_a.ro_mounts.len(), 4);
        assert_eq!(plan_a.cidrs, vec!["192.0.2.10/32", "127.0.0.1/32"]);

        let plan_rv = build_scenario_execution_plan(
            "dep-1",
            "lease-1",
            "0123456789abcdef0123456789abcdef01234567",
            &contract,
            &inventory,
            "worker-riscv64",
            Some(&"b".repeat(64)),
            None,
        )
        .unwrap();
        assert_eq!(plan_rv.scenarios.len(), 1);
        assert_eq!(
            plan_rv.scenarios[0].name,
            "smoke_example_service_worker_riscv64"
        );
        assert!(plan_rv.scenarios[0].env.contains(&ScenarioEnvVar {
            key: "MU_SMOKE_TARGET_ADDR".into(),
            value: "worker-riscv64.cluster.internal:8446".into(),
        }));
        assert_eq!(plan_rv.ro_mounts.len(), 3);

        // Shared scenario (no node suffix) applies to all target nodes.
        let shared_yaml = r#"
version: "2"
service: "shared-svc"
target_nodes:
  - "node-a"
  - "worker-riscv64"
integration_tests:
  - "systemd_unit_active"
  - "smoke_shared"
scenarios:
  - name: "smoke_shared_control"
    test_binary: "smoke_shared"
    target_url: "https://shared.cluster.internal:8443/health"
    restricted_cidrs: ["192.0.2.10/32"]
  - name: "smoke_shared_ingest"
    test_binary: "smoke_shared"
    target_addr: "shared.cluster.internal:4319"
    restricted_cidrs: ["192.0.2.10/32"]
"#;
        let shared = PolicyServiceContract::from_yaml_str(shared_yaml).unwrap();
        let shared_a = resolve_scenarios_for_node(&shared, &inventory, "node-a").unwrap();
        let shared_rv = resolve_scenarios_for_node(&shared, &inventory, "worker-riscv64").unwrap();
        assert_eq!(shared_a.len(), 2);
        assert_eq!(shared_rv.len(), 2);
    }

    #[test]
    fn test_unresolved_required_scenario_fails_closed() {
        let inventory = NodesInventory::from_yaml_str(sample_nodes_yaml()).unwrap();
        let missing_node_scenario_yaml = r#"
version: "2"
service: "partial-svc"
target_nodes:
  - "node-a"
  - "worker-riscv64"
integration_tests:
  - "smoke_partial"
scenarios:
  - name: "smoke_partial_node_a"
    test_binary: "smoke_partial"
    target_url: "https://node-a.cluster.internal:8445"
    restricted_cidrs: ["127.0.0.1/32"]
"#;
        let contract = PolicyServiceContract::from_yaml_str(missing_node_scenario_yaml).unwrap();
        assert!(resolve_scenarios_for_node(&contract, &inventory, "node-a").is_ok());
        assert!(matches!(
            resolve_scenarios_for_node(&contract, &inventory, "worker-riscv64"),
            Err(PolicyRepoError::UnresolvedScenario { .. })
        ));

        let missing_test_binding_yaml = r#"
version: "2"
service: "missing-binding"
target_nodes:
  - "node-a"
integration_tests:
  - "smoke_expected"
scenarios:
  - name: "smoke_other"
    test_binary: "smoke_other"
    target_url: "https://node-a.cluster.internal:8445"
    restricted_cidrs: ["127.0.0.1/32"]
"#;
        let contract2 = PolicyServiceContract::from_yaml_str(missing_test_binding_yaml).unwrap();
        assert!(matches!(
            resolve_scenarios_for_node(&contract2, &inventory, "node-a"),
            Err(PolicyRepoError::UnresolvedScenario { .. })
        ));
    }

    #[test]
    fn test_snapshot_cache_bounded_fifo_eviction() {
        let inventory = NodesInventory::from_yaml_str(sample_nodes_yaml()).unwrap();
        let contract =
            PolicyServiceContract::from_yaml_str(sample_multi_node_service_yaml()).unwrap();
        let mut cache = SnapshotCache::new(2);
        for id in ["dep-1", "dep-2", "dep-3"] {
            cache.insert(
                id.to_string(),
                Arc::new(PinnedDeploymentSnapshot {
                    deployment_id: id.to_string(),
                    policy_commit_sha: "0123456789abcdef0123456789abcdef01234567".into(),
                    verified_at_epoch_ms: 1,
                    service_contract: contract.clone(),
                    nodes_inventory: inventory.clone(),
                    resolved_node_plans: BTreeMap::new(),
                    it_archive_digest: None,
                    bundle_id: None,
                }),
            );
        }
        assert!(
            cache.get("dep-1").is_none(),
            "oldest snapshot must be evicted"
        );
        assert!(cache.get("dep-2").is_some());
        assert!(cache.get("dep-3").is_some());
    }

    #[cfg(unix)]
    fn run_cmd_ok(cmd: &mut std::process::Command) {
        let out = cmd.output().expect("spawn test command");
        assert!(
            out.status.success(),
            "command {:?} failed: stdout={}, stderr={}",
            cmd,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[cfg(unix)]
    fn init_signed_policy_repo(
        dir: &Path,
        signing_key: &Path,
        signers_file: &Path,
        service_yaml: &str,
        sign_commit: bool,
    ) {
        std::fs::create_dir_all(dir.join("policy")).unwrap();
        std::fs::create_dir_all(dir.join("contracts/services")).unwrap();
        std::fs::write(
            dir.join("policy/commit-verification.yml"),
            format!(
                "branch: \"main\"\nrequire_signed_commits: true\nallowed_signers_path: \"{}\"\nfail_closed_on_unverified: true\n",
                signers_file.display()
            ),
        )
        .unwrap();
        std::fs::write(dir.join("contracts/nodes.yml"), sample_nodes_yaml()).unwrap();
        std::fs::write(
            dir.join("contracts/services/example-service.yml"),
            service_yaml,
        )
        .unwrap();

        if !dir.join(".git").exists() {
            run_cmd_ok(std::process::Command::new("git").args([
                "-C",
                dir.to_str().unwrap(),
                "init",
                "-b",
                "main",
            ]));
            run_cmd_ok(std::process::Command::new("git").args([
                "-C",
                dir.to_str().unwrap(),
                "config",
                "user.name",
                "Policy Test",
            ]));
            run_cmd_ok(std::process::Command::new("git").args([
                "-C",
                dir.to_str().unwrap(),
                "config",
                "user.email",
                "policy-test@example.invalid",
            ]));
        }

        run_cmd_ok(std::process::Command::new("git").args([
            "-C",
            dir.to_str().unwrap(),
            "add",
            ".",
        ]));

        let mut commit = std::process::Command::new("git");
        commit
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .args(["-C", dir.to_str().unwrap()]);
        if sign_commit {
            commit.args([
                "-c",
                "gpg.format=ssh",
                "-c",
                &format!("user.signingkey={}", signing_key.display()),
                "commit",
                "-S",
                "-m",
                "signed policy commit",
            ]);
        } else {
            commit.args(["commit", "-m", "unsigned policy commit"]);
        }
        run_cmd_ok(&mut commit);
    }

    #[cfg(unix)]
    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_git_ssh_signature_verification_fail_closed_and_immutable_snapshots() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let trusted_key = tmp.path().join("trusted_ed25519");
        let untrusted_key = tmp.path().join("untrusted_ed25519");
        run_cmd_ok(std::process::Command::new("ssh-keygen").args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-f",
            trusted_key.to_str().unwrap(),
        ]));
        run_cmd_ok(std::process::Command::new("ssh-keygen").args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-f",
            untrusted_key.to_str().unwrap(),
        ]));

        let pub_key = std::fs::read_to_string(tmp.path().join("trusted_ed25519.pub")).unwrap();
        let signers_file = tmp.path().join("allowed_signers");
        std::fs::write(
            &signers_file,
            format!("policy-test@example.invalid {pub_key}"),
        )
        .unwrap();
        std::fs::set_permissions(&signers_file, std::fs::Permissions::from_mode(0o644)).unwrap();

        let repo_dir = tmp.path().join("policy-repo");
        init_signed_policy_repo(
            &repo_dir,
            &trusted_key,
            &signers_file,
            sample_multi_node_service_yaml(),
            true,
        );

        let sink = Arc::new(RecordingCdTelemetrySink::new());
        let repo = PolicyRepository::new(PolicyRepoConfig {
            repo_dir: Some(repo_dir.clone()),
            refresh_on_deploy: true,
            ..Default::default()
        })
        .with_telemetry_sink(sink.clone(), "node-a");

        // 1. Valid SSH-signed commit verifies and pins immutable snapshot for dep-v1.
        let summary = repo.refresh_and_verify().await.expect("valid signed tip");
        assert_eq!(summary.services, vec!["example-service"]);
        let snap_v1 = repo
            .pin_deployment_snapshot(
                "dep-v1",
                "example-service",
                Some(&"a".repeat(64)),
                Some("bundle-v1"),
            )
            .await
            .expect("pin snapshot v1");
        assert_eq!(snap_v1.policy_commit_sha, summary.policy_commit_sha);
        assert_eq!(snap_v1.service_contract.bake_window_seconds, 60);

        // 2. New signed commit changes bake_window_seconds to 120; existing dep-v1 stays immutable.
        let updated_yaml = sample_multi_node_service_yaml()
            .replace("bake_window_seconds: 60", "bake_window_seconds: 120");
        init_signed_policy_repo(&repo_dir, &trusted_key, &signers_file, &updated_yaml, true);

        let snap_v2 = repo
            .pin_deployment_snapshot(
                "dep-v2",
                "example-service",
                Some(&"b".repeat(64)),
                Some("bundle-v2"),
            )
            .await
            .expect("pin snapshot v2");
        assert_ne!(snap_v2.policy_commit_sha, snap_v1.policy_commit_sha);
        assert_eq!(snap_v2.service_contract.bake_window_seconds, 120);
        assert_eq!(
            repo.get_snapshot("dep-v1")
                .unwrap()
                .service_contract
                .bake_window_seconds,
            60,
            "in-flight deployment snapshot must remain immutable across refreshes"
        );

        // 3. Group-writable allowed_signers fails closed.
        std::fs::set_permissions(&signers_file, std::fs::Permissions::from_mode(0o664)).unwrap();
        let perm_err = repo.refresh_and_verify().await.unwrap_err();
        assert!(matches!(perm_err, PolicyRepoError::Unverified(_)));
        std::fs::set_permissions(&signers_file, std::fs::Permissions::from_mode(0o644)).unwrap();

        // 4. Commit signed by untrusted key fails closed and emits metric.
        let untrusted_yaml = sample_multi_node_service_yaml()
            .replace("bake_window_seconds: 60", "bake_window_seconds: 180");
        init_signed_policy_repo(
            &repo_dir,
            &untrusted_key,
            &signers_file,
            &untrusted_yaml,
            true,
        );
        let untrusted_err = repo.refresh_and_verify().await.unwrap_err();
        assert!(matches!(untrusted_err, PolicyRepoError::Unverified(_)));
        assert!(repo.verify_failure_count() >= 2);
        assert!(sink
            .recorded_metrics()
            .await
            .iter()
            .any(|m| m.metric_name == METRIC_POLICY_VERIFY_FAILED));

        // 5. Unsigned commit fails closed.
        let unsigned_yaml = sample_multi_node_service_yaml()
            .replace("bake_window_seconds: 60", "bake_window_seconds: 240");
        init_signed_policy_repo(
            &repo_dir,
            &trusted_key,
            &signers_file,
            &unsigned_yaml,
            false,
        );
        let unsigned_err = repo.refresh_and_verify().await.unwrap_err();
        assert!(matches!(unsigned_err, PolicyRepoError::Unverified(_)));
    }
}
