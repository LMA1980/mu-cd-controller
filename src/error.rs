//! Error types for MuConDe continuous delivery controller.

use thiserror::Error;

/// Top-level error enum encompassing all MuConDe-controller operations.
#[derive(Debug, Error)]
pub enum ControllerError {
    #[error("Contract error: {0}")]
    Contract(#[from] ContractError),

    #[error("Lease coordinator error: {0}")]
    Lease(#[from] LeaseError),

    #[error("Orchestrator error: {0}")]
    Orchestrator(#[from] OrchestratorError),

    #[error("TLS configuration error: {0}")]
    Tls(#[from] TlsError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Errors occurring while parsing and validating `.mucd/mu-cd.yml` or legacy `.muconde/MuConDe.yml`.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ContractError {
    #[error("Configuration manifest not found in '{0}': expected .mucd/mu-cd.ya?ml or .muconde/MuConDe.ya?ml")]
    NotFound(std::path::PathBuf),

    #[error("Unsupported contract version '{0}', expected '1'")]
    UnsupportedVersion(String),

    #[error("Service name cannot be empty")]
    EmptyService,

    #[error("Target nodes list cannot be empty")]
    EmptyTargetNodes,

    #[error("Target node name cannot be empty")]
    EmptyTargetNode,

    #[error("Lease TTL must be greater than zero seconds")]
    InvalidLeaseTtl,

    #[error("Warmup timeout must be greater than zero seconds")]
    InvalidWarmupTimeout,

    #[error("Invalid integration test selector '{0}', string selector must be 'all'")]
    InvalidSelector(String),

    #[error("Integration test list cannot be empty when using selected tests")]
    EmptyTestList,

    #[error("Integration test name cannot be empty")]
    EmptyTestName,

    #[error("YAML deserialization failed: {0}")]
    Yaml(String),
}

impl From<serde_yaml::Error> for ContractError {
    fn from(err: serde_yaml::Error) -> Self {
        ContractError::Yaml(err.to_string())
    }
}

/// Errors related to cluster polling and lease coordination.
#[derive(Debug, Error)]
pub enum LeaseError {
    #[error("HTTP request error: {0}")]
    Http(String),

    #[error("JSON serialization/deserialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Active lease already exists for service '{service_name}' on node '{node_id}'")]
    LeaseConflict {
        node_id: String,
        service_name: String,
    },

    #[error("Lease '{0}' not found or already released")]
    LeaseNotFound(String),

    #[error("Target node '{0}' is not eligible (busy or exclusive locked)")]
    NodeNotIdle(String),

    #[error("Target node '{0}' is offline")]
    NodeOffline(String),

    #[error("Target node '{0}' is exclusively locked by another stage")]
    NodeLocked(String),

    #[error("Lease coordinator internal error: {0}")]
    Internal(String),
}

/// Errors related to TLS certificate loading and mTLS configuration.
#[derive(Debug, Error)]
pub enum TlsError {
    #[error("I/O error reading TLS material: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid certificate format or empty certificate chain")]
    InvalidCertificate(String),

    #[error("Invalid private key format")]
    InvalidPrivateKey(String),

    #[error("Rustls error: {0}")]
    Rustls(#[from] rustls::Error),
}

/// Errors encountered during end-to-end continuous delivery deployment orchestration.
#[derive(Debug, Error)]
pub enum OrchestratorError {
    #[error("Deployment refused: artifact digest '{0}' is tainted")]
    ArtifactTainted(String),

    #[error("Contract validation error: {0}")]
    Contract(#[from] ContractError),

    #[error("Lease coordination error: {0}")]
    Lease(#[from] LeaseError),

    #[error("TLS error: {0}")]
    Tls(#[from] TlsError),

    #[error("MuConDe-agent IPC communication error: {0}")]
    Agent(String),

    #[error("MuRegist communication error: {0}")]
    Regist(String),

    #[error("MuObserve SLO client error: {0}")]
    Slo(String),

    #[error("Deployment timed out: {0}")]
    Timeout(String),

    #[error("Integration tests failed: {failed_tests:?}, log: {log:?}")]
    IntegrationTestFailed {
        failed_tests: Vec<String>,
        log: Option<String>,
    },

    #[error("Health probe verification failed: {0}")]
    HealthProbeFailed(String),

    #[error("Deployment failed: {0}")]
    DeploymentFailed(String),

    #[error("Rollback failed: {0}")]
    RollbackFailed(String),
}
