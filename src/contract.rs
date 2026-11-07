//! Declarative continuous delivery deployment contract (`.mucd/mu-cd.yml` with `.muconde/MuConDe.yml` fallback).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::ContractError;

/// Canonical candidate manifest filenames under `.mucd/` checked in precedence order.
const MUCD_CANDIDATES: &[&str] = &[
    ".mucd/mu-cd.yml",
    ".mucd/mu-cd.yaml",
    ".mucd/MuConDe.yml",
    ".mucd/MuConDe.yaml",
];

/// Legacy candidate manifest filenames under `.muconde/` checked in fallback order.
const LEGACY_MUCONDE_CANDIDATES: &[&str] = &[".muconde/MuConDe.yml", ".muconde/MuConDe.yaml"];

/// Resolve the path to the continuous delivery manifest in `repo_root`.
///
/// In Phase 1 dual-stack resolution:
/// 1. Checks `.mucd/mu-cd.yml`, `.mucd/mu-cd.yaml`, `.mucd/MuConDe.yml`, and `.mucd/MuConDe.yaml`.
/// 2. If none exist under `.mucd/`, falls back to `.muconde/MuConDe.yml` and `.muconde/MuConDe.yaml`,
///    emitting a structured `tracing::warn!` advising migration.
/// 3. Returns `ContractError::NotFound` if neither manifest is present.
pub fn resolve_manifest_path(repo_root: impl AsRef<Path>) -> Result<PathBuf, ContractError> {
    MuConDeConfig::resolve_manifest_path(repo_root)
}

/// Type alias for [`MuConDeConfig`] conforming to the `mu-cd` naming scheme.
pub type MuCdConfig = MuConDeConfig;

/// Default lease time-to-live in seconds (300 seconds / 5 minutes).
pub const DEFAULT_LEASE_TTL_SECONDS: u64 = 300;

/// Default post-swap warmup and health probe timeout in seconds (30 seconds).
pub const DEFAULT_WARMUP_TIMEOUT_SECONDS: u64 = 30;

/// Default canary bake SLO evaluation window in seconds (60 seconds).
pub const DEFAULT_BAKE_WINDOW_SECONDS: u64 = 60;

/// Default maximum error log count permitted during a canary bake window (0).
pub const DEFAULT_MAX_ERROR_LOGS: u32 = 0;

/// Default maximum p99 latency in milliseconds permitted during a canary bake window (250.0 ms).
pub const DEFAULT_MAX_P99_LATENCY_MS: f64 = 250.0;

fn default_lease_ttl() -> u64 {
    DEFAULT_LEASE_TTL_SECONDS
}

fn default_warmup_timeout() -> u64 {
    DEFAULT_WARMUP_TIMEOUT_SECONDS
}

fn default_bake_window() -> u64 {
    DEFAULT_BAKE_WINDOW_SECONDS
}

fn default_max_error_logs() -> u32 {
    DEFAULT_MAX_ERROR_LOGS
}

fn default_max_p99_latency_ms() -> f64 {
    DEFAULT_MAX_P99_LATENCY_MS
}

/// Declarative continuous delivery configuration loaded from `.muconde/MuConDe.yml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MuConDeConfig {
    pub version: String,
    pub service: String,
    pub target_nodes: Vec<String>,
    #[serde(default = "default_lease_ttl")]
    pub lease_ttl_seconds: u64,
    #[serde(default = "default_warmup_timeout")]
    pub warmup_timeout_seconds: u64,
    #[serde(default = "default_bake_window")]
    pub bake_window_seconds: u64,
    #[serde(default = "default_max_error_logs")]
    pub max_error_logs: u32,
    #[serde(default = "default_max_p99_latency_ms")]
    pub max_p99_latency_ms: f64,
    pub integration_tests: IntegrationTestSelector,
}

/// Selector specifying which integration test suites are required before promotion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum IntegrationTestSelector {
    /// Target all integration test suites (`"all"`).
    All(String),
    /// Target an explicit list of integration test identifiers.
    Selected(Vec<String>),
}

impl MuConDeConfig {
    /// Parse and validate configuration from a YAML string.
    pub fn from_yaml_str(yaml_str: &str) -> Result<Self, ContractError> {
        let config: Self = serde_yaml::from_str(yaml_str)?;
        config.validate()?;
        Ok(config)
    }

    /// Resolve the path to the continuous delivery manifest in `repo_root`.
    pub fn resolve_manifest_path(repo_root: impl AsRef<Path>) -> Result<PathBuf, ContractError> {
        let root = repo_root.as_ref();
        for candidate in MUCD_CANDIDATES {
            let path = root.join(candidate);
            if path.is_file() {
                return Ok(path);
            }
        }
        for candidate in LEGACY_MUCONDE_CANDIDATES {
            let path = root.join(candidate);
            if path.is_file() {
                tracing::warn!(
                    path = %path.display(),
                    "Loaded deployment contract from legacy .muconde directory; consider migrating to .mucd/mu-cd.yml"
                );
                return Ok(path);
            }
        }
        Err(ContractError::NotFound(root.to_path_buf()))
    }

    /// Load and validate configuration from a repository root directory by resolving
    /// either `.mucd/mu-cd.yml` or the legacy `.muconde/MuConDe.yml` fallback.
    pub fn from_repo_root(repo_root: impl AsRef<Path>) -> Result<Self, ContractError> {
        let manifest_path = Self::resolve_manifest_path(repo_root)?;
        let content = std::fs::read_to_string(&manifest_path)
            .map_err(|e| ContractError::Yaml(e.to_string()))?;
        Self::from_yaml_str(&content)
    }

    /// Load and validate configuration from a file or repository root on disk.
    ///
    /// If `path` is a directory, it resolves the manifest via [`Self::from_repo_root`].
    /// If `path` is a file, it loads it directly (emitting a migration warning if under `.muconde/`).
    /// If `path` does not exist as specified (e.g. default `.mucd/mu-cd.yml`), it attempts fallback
    /// to legacy manifests or returns [`ContractError::NotFound`].
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ContractError> {
        let p = path.as_ref();
        if p.is_dir() {
            return Self::from_repo_root(p);
        }
        if p.is_file() {
            if p.starts_with(".muconde") || p.to_string_lossy().contains("/.muconde/") {
                tracing::warn!(
                    path = %p.display(),
                    "Loaded deployment contract from legacy .muconde directory; consider migrating to .mucd/mu-cd.yml"
                );
            }
            let content =
                std::fs::read_to_string(p).map_err(|e| ContractError::Yaml(e.to_string()))?;
            return Self::from_yaml_str(&content);
        }

        // If path does not exist directly, check whether it is a candidate relative path
        if let Some(parent) = p.parent() {
            let parent_dir = if parent.as_os_str().is_empty() {
                Path::new(".")
            } else {
                parent
            };
            if parent_dir
                .file_name()
                .map(|n| n == ".mucd" || n == ".muconde")
                .unwrap_or(false)
            {
                let repo_root = parent_dir.parent().unwrap_or_else(|| Path::new("."));
                let repo_root = if repo_root.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    repo_root
                };
                if let Ok(resolved) = Self::resolve_manifest_path(repo_root) {
                    let content = std::fs::read_to_string(&resolved)
                        .map_err(|e| ContractError::Yaml(e.to_string()))?;
                    return Self::from_yaml_str(&content);
                }
            }
        }

        Err(ContractError::NotFound(p.to_path_buf()))
    }

    /// Validate all contract fields against CD architectural invariants.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.version != "1" {
            return Err(ContractError::UnsupportedVersion(self.version.clone()));
        }

        if self.service.trim().is_empty() {
            return Err(ContractError::EmptyService);
        }

        if self.target_nodes.is_empty() {
            return Err(ContractError::EmptyTargetNodes);
        }

        for node in &self.target_nodes {
            if node.trim().is_empty() {
                return Err(ContractError::EmptyTargetNode);
            }
        }

        if self.lease_ttl_seconds == 0 {
            return Err(ContractError::InvalidLeaseTtl);
        }

        if self.warmup_timeout_seconds == 0 {
            return Err(ContractError::InvalidWarmupTimeout);
        }

        match &self.integration_tests {
            IntegrationTestSelector::All(s) => {
                if !s.trim().eq_ignore_ascii_case("all") {
                    return Err(ContractError::InvalidSelector(s.clone()));
                }
            }
            IntegrationTestSelector::Selected(list) => {
                if list.is_empty() {
                    return Err(ContractError::EmptyTestList);
                }
                for test in list {
                    if test.trim().is_empty() {
                        return Err(ContractError::EmptyTestName);
                    }
                }
            }
        }

        Ok(())
    }

    /// Returns `true` if all integration tests should be executed.
    pub fn should_run_all(&self) -> bool {
        matches!(&self.integration_tests, IntegrationTestSelector::All(_))
    }

    /// Returns a slice of explicitly selected test names, or `None` if `"all"` was selected.
    pub fn selected_tests(&self) -> Option<&[String]> {
        match &self.integration_tests {
            IntegrationTestSelector::All(_) => None,
            IntegrationTestSelector::Selected(tests) => Some(tests.as_slice()),
        }
    }

    /// Checks if a given test name should be executed according to this configuration.
    pub fn matches_test(&self, test_name: &str) -> bool {
        match &self.integration_tests {
            IntegrationTestSelector::All(_) => true,
            IntegrationTestSelector::Selected(tests) => tests.iter().any(|t| t == test_name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_all_selector() {
        let yaml = r#"
version: "1"
service: "action-runner"
target_nodes:
  - "node-a"
  - "worker-riscv64"
lease_ttl_seconds: 180
warmup_timeout_seconds: 25
integration_tests: "all"
"#;
        let config = MuConDeConfig::from_yaml_str(yaml).expect("valid config with all tests");
        assert_eq!(config.version, "1");
        assert_eq!(config.service, "action-runner");
        assert_eq!(config.target_nodes, vec!["node-a", "worker-riscv64"]);
        assert_eq!(config.lease_ttl_seconds, 180);
        assert_eq!(config.warmup_timeout_seconds, 25);
        assert_eq!(
            config.integration_tests,
            IntegrationTestSelector::All("all".to_string())
        );
        assert!(config.should_run_all());
        assert!(config.matches_test("any_test"));
        assert_eq!(config.selected_tests(), None);
    }

    #[test]
    fn test_parse_valid_selected_selector_with_defaults() {
        let yaml = r#"
version: "1"
service: "muconde-agent"
target_nodes:
  - "node-a"
integration_tests:
  - "it_smoke"
  - "it_mtls_handshake"
"#;
        let config = MuConDeConfig::from_yaml_str(yaml).expect("valid config with selected tests");
        assert_eq!(config.version, "1");
        assert_eq!(config.service, "muconde-agent");
        assert_eq!(config.lease_ttl_seconds, DEFAULT_LEASE_TTL_SECONDS);
        assert_eq!(
            config.warmup_timeout_seconds,
            DEFAULT_WARMUP_TIMEOUT_SECONDS
        );
        assert_eq!(
            config.integration_tests,
            IntegrationTestSelector::Selected(vec![
                "it_smoke".to_string(),
                "it_mtls_handshake".to_string(),
            ])
        );
        assert!(!config.should_run_all());
        assert!(config.matches_test("it_smoke"));
        assert!(config.matches_test("it_mtls_handshake"));
        assert!(!config.matches_test("it_unknown"));
        assert_eq!(
            config.selected_tests(),
            Some(&["it_smoke".to_string(), "it_mtls_handshake".to_string()][..])
        );
    }

    #[test]
    fn test_reject_unsupported_version() {
        let yaml = r#"
version: "2"
service: "action-runner"
target_nodes: ["node-a"]
integration_tests: "all"
"#;
        let err = MuConDeConfig::from_yaml_str(yaml).unwrap_err();
        assert_eq!(err, ContractError::UnsupportedVersion("2".to_string()));
    }

    #[test]
    fn test_reject_empty_service() {
        let yaml = r#"
version: "1"
service: "   "
target_nodes: ["node-a"]
integration_tests: "all"
"#;
        let err = MuConDeConfig::from_yaml_str(yaml).unwrap_err();
        assert_eq!(err, ContractError::EmptyService);
    }

    #[test]
    fn test_reject_empty_target_nodes() {
        let yaml = r#"
version: "1"
service: "action-runner"
target_nodes: []
integration_tests: "all"
"#;
        let err = MuConDeConfig::from_yaml_str(yaml).unwrap_err();
        assert_eq!(err, ContractError::EmptyTargetNodes);
    }

    #[test]
    fn test_reject_empty_target_node_name() {
        let yaml = r#"
version: "1"
service: "action-runner"
target_nodes: ["node-a", "  "]
integration_tests: "all"
"#;
        let err = MuConDeConfig::from_yaml_str(yaml).unwrap_err();
        assert_eq!(err, ContractError::EmptyTargetNode);
    }

    #[test]
    fn test_reject_zero_lease_ttl() {
        let yaml = r#"
version: "1"
service: "action-runner"
target_nodes: ["node-a"]
lease_ttl_seconds: 0
integration_tests: "all"
"#;
        let err = MuConDeConfig::from_yaml_str(yaml).unwrap_err();
        assert_eq!(err, ContractError::InvalidLeaseTtl);
    }

    #[test]
    fn test_reject_zero_warmup_timeout() {
        let yaml = r#"
version: "1"
service: "action-runner"
target_nodes: ["node-a"]
warmup_timeout_seconds: 0
integration_tests: "all"
"#;
        let err = MuConDeConfig::from_yaml_str(yaml).unwrap_err();
        assert_eq!(err, ContractError::InvalidWarmupTimeout);
    }

    #[test]
    fn test_reject_invalid_string_selector() {
        let yaml = r#"
version: "1"
service: "action-runner"
target_nodes: ["node-a"]
integration_tests: "none"
"#;
        let err = MuConDeConfig::from_yaml_str(yaml).unwrap_err();
        assert_eq!(err, ContractError::InvalidSelector("none".to_string()));
    }

    #[test]
    fn test_reject_empty_selected_test_list() {
        let yaml = r#"
version: "1"
service: "action-runner"
target_nodes: ["node-a"]
integration_tests: []
"#;
        let err = MuConDeConfig::from_yaml_str(yaml).unwrap_err();
        assert_eq!(err, ContractError::EmptyTestList);
    }

    #[test]
    fn test_reject_empty_test_name_in_selected_list() {
        let yaml = r#"
version: "1"
service: "action-runner"
target_nodes: ["node-a"]
integration_tests:
  - "it_smoke"
  - "   "
"#;
        let err = MuConDeConfig::from_yaml_str(yaml).unwrap_err();
        assert_eq!(err, ContractError::EmptyTestName);
    }

    #[test]
    fn test_phase1_mucd_loaded_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let mucd_dir = dir.path().join(".mucd");
        std::fs::create_dir_all(&mucd_dir).unwrap();
        let manifest_path = mucd_dir.join("mu-cd.yml");
        std::fs::write(
            &manifest_path,
            r#"
version: "1"
service: "mu-service-primary"
target_nodes: ["worker-node-1"]
integration_tests: "all"
"#,
        )
        .unwrap();

        let resolved = resolve_manifest_path(dir.path()).unwrap();
        assert_eq!(resolved, manifest_path);

        let config = MuConDeConfig::from_repo_root(dir.path()).unwrap();
        assert_eq!(config.service, "mu-service-primary");
        assert_eq!(config.target_nodes, vec!["worker-node-1"]);

        // Verify MuCdConfig type alias works equivalently
        let alias_config = MuCdConfig::from_repo_root(dir.path()).unwrap();
        assert_eq!(alias_config, config);

        // Verify from_file works when given the repo root directory
        let from_file_dir = MuConDeConfig::from_file(dir.path()).unwrap();
        assert_eq!(from_file_dir, config);
    }

    #[test]
    fn test_phase1_mucd_precedence_over_legacy_muconde() {
        let dir = tempfile::tempdir().unwrap();
        let mucd_dir = dir.path().join(".mucd");
        let muconde_dir = dir.path().join(".muconde");
        std::fs::create_dir_all(&mucd_dir).unwrap();
        std::fs::create_dir_all(&muconde_dir).unwrap();

        std::fs::write(
            mucd_dir.join("mu-cd.yml"),
            r#"
version: "1"
service: "mu-service-mucd-priority"
target_nodes: ["worker-node-mucd"]
integration_tests: "all"
"#,
        )
        .unwrap();

        std::fs::write(
            muconde_dir.join("MuConDe.yml"),
            r#"
version: "1"
service: "mu-service-legacy"
target_nodes: ["worker-node-legacy"]
integration_tests: "all"
"#,
        )
        .unwrap();

        let resolved = resolve_manifest_path(dir.path()).unwrap();
        assert_eq!(resolved, mucd_dir.join("mu-cd.yml"));

        let config = MuConDeConfig::from_repo_root(dir.path()).unwrap();
        assert_eq!(config.service, "mu-service-mucd-priority");
        assert_eq!(config.target_nodes, vec!["worker-node-mucd"]);
    }

    #[test]
    fn test_phase1_legacy_muconde_fallback_when_mucd_absent() {
        let dir = tempfile::tempdir().unwrap();
        let muconde_dir = dir.path().join(".muconde");
        std::fs::create_dir_all(&muconde_dir).unwrap();

        let legacy_manifest = muconde_dir.join("MuConDe.yml");
        std::fs::write(
            &legacy_manifest,
            r#"
version: "1"
service: "mu-service-legacy-fallback"
target_nodes: ["worker-node-legacy"]
integration_tests: "all"
"#,
        )
        .unwrap();

        let resolved = resolve_manifest_path(dir.path()).unwrap();
        assert_eq!(resolved, legacy_manifest);

        let config = MuConDeConfig::from_repo_root(dir.path()).unwrap();
        assert_eq!(config.service, "mu-service-legacy-fallback");

        // Verify from_file with a path under .mucd falls back to .muconde
        let config_fallback = MuConDeConfig::from_file(dir.path().join(".mucd/mu-cd.yml")).unwrap();
        assert_eq!(config_fallback.service, "mu-service-legacy-fallback");
    }

    #[test]
    fn test_phase1_missing_both_returns_contract_error() {
        let dir = tempfile::tempdir().unwrap();

        let err = resolve_manifest_path(dir.path()).unwrap_err();
        assert_eq!(err, ContractError::NotFound(dir.path().to_path_buf()));

        let err_repo = MuConDeConfig::from_repo_root(dir.path()).unwrap_err();
        assert_eq!(err_repo, ContractError::NotFound(dir.path().to_path_buf()));

        let nonexistent_file = dir.path().join("missing.yml");
        let err_file = MuConDeConfig::from_file(&nonexistent_file).unwrap_err();
        assert_eq!(err_file, ContractError::NotFound(nonexistent_file));
    }

    #[test]
    fn test_phase1_alternate_manifest_extensions_and_names() {
        let dir = tempfile::tempdir().unwrap();
        let mucd_dir = dir.path().join(".mucd");
        std::fs::create_dir_all(&mucd_dir).unwrap();

        // Test .mucd/mu-cd.yaml
        let manifest_yaml = mucd_dir.join("mu-cd.yaml");
        std::fs::write(
            &manifest_yaml,
            r#"
version: "1"
service: "mu-yaml-ext"
target_nodes: ["worker-1"]
integration_tests: "all"
"#,
        )
        .unwrap();

        let resolved = resolve_manifest_path(dir.path()).unwrap();
        assert_eq!(resolved, manifest_yaml);
        let config = MuConDeConfig::from_repo_root(dir.path()).unwrap();
        assert_eq!(config.service, "mu-yaml-ext");
    }
}
