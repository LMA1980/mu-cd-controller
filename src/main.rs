//! `mu-cd-controller` daemon and CLI entry point.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use mu_cd_controller::api::{spawn_cd_api_with_orchestrator, CdApiConfig};
use mu_cd_controller::auth::load_secret_file;
use mu_cd_controller::cd_state::CdStateStore;
use mu_cd_controller::contract::MuConDeConfig;
use mu_cd_controller::first_non_empty_var;
use mu_cd_controller::lease::{
    ClusterIdlePoller, IdleBackoffConfig, LeaseCoordinator, DEFAULT_CONTROLLER_URL,
};
use mu_cd_controller::orchestrator::{
    DeploymentOrchestrator, DeploymentOutcome, HttpMuRegistClient, IpcAgentClient,
    DEFAULT_REGISTRY_URL,
};
use mu_cd_controller::policy_repo::{PolicyRepoConfig, PolicyRepository};
use mu_cd_controller::slo::MuObserveSloClient;
use mu_cd_controller::telemetry::{CdTelemetrySink, MuObserveCdSink};
use mu_cd_controller::tls::TlsConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ControllerEnvConfig {
    controller_url: String,
    regist_url: String,
    agent_port: u16,
    auth_token: Option<String>,
    ca_path: Option<PathBuf>,
    client_cert_path: Option<PathBuf>,
    client_key_path: Option<PathBuf>,
    muobserve_addr: Option<String>,
    repo: Option<String>,
}

impl ControllerEnvConfig {
    fn from_env_lookup(lookup: &dyn Fn(&str) -> Option<String>) -> Self {
        let controller_url = first_non_empty_var(
            lookup,
            &[
                "MU_CD_CONTROLLER_CI_URL",
                "MU_CD_CONTROLLER_URL",
                "MU_CD_CI_CONTROLLER_URL",
                "MU_CI_CONTROLLER_URL",
                "MUCONDE_CONTROLLER_URL",
            ],
        )
        .unwrap_or_else(|| DEFAULT_CONTROLLER_URL.to_string());

        let regist_url = first_non_empty_var(
            lookup,
            &[
                "MU_CD_CONTROLLER_REGISTRY_URL",
                "MU_CD_REGISTRY_URL",
                "MU_REGISTRY_URL",
                "MUCONDE_REGISTRY_URL",
                "MUREGIST_URL",
            ],
        )
        .unwrap_or_else(|| DEFAULT_REGISTRY_URL.to_string());

        let agent_port = first_non_empty_var(
            lookup,
            &[
                "MU_CD_CONTROLLER_AGENT_PORT",
                "MU_CD_AGENT_PORT",
                "MUCONDE_AGENT_PORT",
            ],
        )
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8446);

        let auth_token = resolve_registry_token(lookup);

        let ca_path = first_non_empty_var(
            lookup,
            &[
                "MU_CD_CONTROLLER_TLS_CA_CERT",
                "MU_CD_TLS_CA_CERT",
                "MUCONDE_TLS_CA_CERT",
                "TLS_CA_CERT",
            ],
        )
        .map(PathBuf::from);
        let client_cert_path = first_non_empty_var(
            lookup,
            &[
                "MU_CD_CONTROLLER_TLS_CLIENT_CERT",
                "MU_CD_TLS_CLIENT_CERT",
                "MUCONDE_TLS_CLIENT_CERT",
                "TLS_CLIENT_CERT",
            ],
        )
        .map(PathBuf::from);
        let client_key_path = first_non_empty_var(
            lookup,
            &[
                "MU_CD_CONTROLLER_TLS_CLIENT_KEY",
                "MU_CD_TLS_CLIENT_KEY",
                "MUCONDE_TLS_CLIENT_KEY",
                "TLS_CLIENT_KEY",
            ],
        )
        .map(PathBuf::from);

        let muobserve_addr = first_non_empty_var(
            lookup,
            &[
                "MU_CD_CONTROLLER_OBSERVABLE_ADDR",
                "MU_OBSERVABLE_HUB_ADDR",
                "MU_OBSERVABLE_ADDR",
                "MUOBSERVE_ADDR",
            ],
        );

        let repo = first_non_empty_var(
            lookup,
            &["MU_CD_CONTROLLER_REPO", "MU_CD_REPO", "MUCONDE_REPO"],
        );

        Self {
            controller_url,
            regist_url,
            agent_port,
            auth_token,
            ca_path,
            client_cert_path,
            client_key_path,
            muobserve_addr,
            repo,
        }
    }
}

fn resolve_registry_token(lookup: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    if let Some(path) = first_non_empty_var(
        lookup,
        &[
            "MU_CD_CONTROLLER_REGISTRY_TOKEN_FILE",
            "MU_CD_REGISTRY_TOKEN_FILE",
            "MU_REGISTRY_TOKEN_FILE",
            "MUCONDE_REGISTRY_TOKEN_FILE",
            "MUREGIST_TOKEN_FILE",
        ],
    ) {
        return load_secret_file(Path::new(&path));
    }
    if let Some(raw) = first_non_empty_var(
        lookup,
        &[
            "MU_CD_CONTROLLER_REGISTRY_TOKEN",
            "MU_CD_REGISTRY_TOKEN",
            "MU_REGISTRY_TOKEN",
            "MUCONDE_REGISTRY_TOKEN",
            "MUREGIST_TOKEN",
        ],
    ) {
        if raw.starts_with('/') {
            return load_secret_file(Path::new(&raw));
        }
        return Some(raw);
    }
    None
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    info!(
        version = mu_cd_controller::CONTROLLER_VERSION,
        "Starting mu-cd-controller CD control plane"
    );

    let env_cfg = ControllerEnvConfig::from_env_lookup(&|key| std::env::var(key).ok());

    let tls_config = TlsConfig {
        ca_cert_path: env_cfg.ca_path,
        client_cert_path: env_cfg.client_cert_path,
        client_key_path: env_cfg.client_key_path,
        ..Default::default()
    };

    let coordinator = Arc::new(LeaseCoordinator::new());
    let poller = match ClusterIdlePoller::new(&env_cfg.controller_url, &tls_config) {
        Ok(p) => Some(p),
        Err(e) => {
            error!(error = %e, "Failed to initialize cluster poller; proceeding with poller disabled");
            None
        }
    };

    let regist_client = Arc::new(HttpMuRegistClient::new(
        &env_cfg.regist_url,
        &tls_config,
        env_cfg.auth_token,
    )?);
    // Read-only CD state shared by the orchestrator, lease watcher, agent IPC reader and the
    // optional `/api/cd/*` listener.
    let cd_state = Arc::new(CdStateStore::default());
    let cd_sink_concrete = MuObserveCdSink::from_env();
    let controller_node_id = cd_sink_concrete.node_id().to_string();
    let cd_sink: Arc<dyn CdTelemetrySink> = Arc::new(cd_sink_concrete);

    let policy_repo_cfg = PolicyRepoConfig::from_env();
    let policy_repo = if policy_repo_cfg.is_enabled() {
        let repo = Arc::new(
            PolicyRepository::new(policy_repo_cfg)
                .with_telemetry_sink(cd_sink.clone(), controller_node_id),
        );
        if let Err(err) = repo.refresh_and_verify().await {
            error!(
                error = %err,
                "Initial deployment policy repository verification failed closed; incoming deployments will return 503 until verified"
            );
        }
        let _bg_refresh = repo.clone().spawn_background_refresh();
        Some(repo)
    } else {
        None
    };

    let mut agent_client_builder = IpcAgentClient::new(env_cfg.agent_port)
        .with_progress_sink(cd_state.clone())
        .with_tls_config(tls_config.clone());
    if let Some(ref repo) = policy_repo {
        agent_client_builder = agent_client_builder.with_policy_repo(repo.clone());
    }
    let agent_client = Arc::new(agent_client_builder);

    let mut orchestrator =
        DeploymentOrchestrator::new(coordinator.clone(), poller, agent_client, regist_client)
            .with_idle_backoff(IdleBackoffConfig::from_env())
            .with_cd_state(cd_state.clone())
            .with_telemetry_sink(cd_sink);
    if let Some(ref repo) = policy_repo {
        orchestrator = orchestrator.with_policy_repo(repo.clone());
    }

    if let Some(muobserve_addr) = env_cfg.muobserve_addr {
        let slo_client = Arc::new(MuObserveSloClient::new(muobserve_addr, tls_config.clone()));
        orchestrator = orchestrator.with_slo_client(slo_client);
    }

    let orchestrator = Arc::new(orchestrator);

    // Spawn background lease expiration watcher (sweeping every 1s)
    let (revoke_tx, mut revoke_rx) = tokio::sync::mpsc::channel(64);
    let _watcher_handle = coordinator
        .clone()
        .spawn_expiration_watcher(Duration::from_secs(1), revoke_tx);

    let sweep_state = cd_state.clone();
    tokio::spawn(async move {
        while let Some((revoke, rollback)) = revoke_rx.recv().await {
            sweep_state.lease_expired(&revoke.deployment_id, &revoke.lease_id);
            info!(
                deployment_id = %revoke.deployment_id,
                lease_id = %revoke.lease_id,
                service = %rollback.service_name,
                reason = %rollback.reason,
                "Background sweep evicted expired deployment lease"
            );
        }
    });

    // Mirror the lease table into the CD API snapshot (TTL countdowns, expiries).
    {
        let mirror_state = cd_state.clone();
        let mirror_coordinator = coordinator.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            loop {
                ticker.tick().await;
                mirror_state.set_leases(mirror_coordinator.list_leases().await);
            }
        });
    }

    // Optional CD status & deploy API on a separate listener (disabled unless
    // MU_CD_CONTROLLER_API_ADDR / MUCONDE_CD_API_ADDR is set; bearer token from
    // MU_CD_CONTROLLER_API_TOKEN_FILE / MUCONDE_CD_API_TOKEN_FILE).
    let cd_api_config = CdApiConfig::from_env();
    let _cd_api = spawn_cd_api_with_orchestrator(
        &cd_api_config,
        cd_state.clone(),
        Some(orchestrator.clone()),
    )
    .await?;

    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 3 && args[1] == "deploy" {
        let config_path = &args[2];
        let artifact_sha256 = args
            .get(3)
            .map(|s| s.as_str())
            .unwrap_or("unspecified-digest");

        info!(
            config = %config_path,
            digest = %artifact_sha256,
            "Executing standalone deployment dispatch"
        );

        let config = MuConDeConfig::from_file(config_path)?;
        let outcomes = orchestrator
            .orchestrate_rollout_for_repo(&config, artifact_sha256, env_cfg.repo.as_deref())
            .await?;

        let mut any_rolled_back = false;
        for outcome in outcomes {
            match outcome {
                DeploymentOutcome::Promoted {
                    service,
                    target_node,
                    artifact_sha256,
                    ..
                } => {
                    info!(
                        service = %service,
                        node = %target_node,
                        digest = %artifact_sha256,
                        "Deployment successfully completed and promoted"
                    );
                }
                DeploymentOutcome::RolledBack {
                    service,
                    target_node,
                    artifact_sha256,
                    reason,
                    ..
                } => {
                    any_rolled_back = true;
                    error!(
                        service = %service,
                        node = %target_node,
                        digest = %artifact_sha256,
                        reason = %reason,
                        "Deployment failed and was rolled back"
                    );
                }
            }
        }

        if any_rolled_back {
            std::process::exit(1);
        }

        return Ok(());
    }

    info!("mu-cd-controller daemon running; waiting for shutdown signal");
    tokio::signal::ctrl_c().await?;
    info!("Received termination signal; shutting down");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_controller_env_config_precedence_and_legacy_fallback() {
        let canonical = HashMap::from([
            (
                "MU_CD_CONTROLLER_CI_URL",
                "https://ci.cluster.internal:8443",
            ),
            ("MUCONDE_CONTROLLER_URL", "https://legacy-ci.example:8443"),
            (
                "MU_CD_CONTROLLER_REGISTRY_URL",
                "https://reg.cluster.internal:8444",
            ),
            ("MU_REGISTRY_URL", "https://mid-reg.example:8444"),
            ("MUREGIST_URL", "https://legacy-reg.example:8444"),
            ("MU_CD_CONTROLLER_AGENT_PORT", "9446"),
            ("MUCONDE_AGENT_PORT", "8446"),
            ("MU_REGISTRY_TOKEN", "reg-token-primary"),
            ("MUREGIST_TOKEN", "reg-token-legacy"),
            ("MU_CD_CONTROLLER_TLS_CA_CERT", "/etc/mu-cd/ca.crt"),
            ("TLS_CA_CERT", "/etc/legacy/ca.crt"),
            ("MU_CD_TLS_CLIENT_CERT", "/etc/mu-cd/client.crt"),
            ("TLS_CLIENT_CERT", "/etc/legacy/client.crt"),
            ("MU_CD_TLS_CLIENT_KEY", "/etc/mu-cd/client.key"),
            ("TLS_CLIENT_KEY", "/etc/legacy/client.key"),
            ("MU_OBSERVABLE_ADDR", "observe.cluster.internal:9445"),
            ("MUOBSERVE_ADDR", "legacy-observe.example:9445"),
            ("MU_CD_CONTROLLER_REPO", "LMA1980/mu-cd-controller"),
            ("MUCONDE_REPO", "LMA1980/legacy"),
        ]);
        let cfg = ControllerEnvConfig::from_env_lookup(&|k| canonical.get(k).map(|v| (*v).into()));
        assert_eq!(cfg.controller_url, "https://ci.cluster.internal:8443");
        assert_eq!(cfg.regist_url, "https://reg.cluster.internal:8444");
        assert_eq!(cfg.agent_port, 9446);
        assert_eq!(cfg.auth_token.as_deref(), Some("reg-token-primary"));
        assert_eq!(cfg.ca_path, Some(PathBuf::from("/etc/mu-cd/ca.crt")));
        assert_eq!(
            cfg.client_cert_path,
            Some(PathBuf::from("/etc/mu-cd/client.crt"))
        );
        assert_eq!(
            cfg.client_key_path,
            Some(PathBuf::from("/etc/mu-cd/client.key"))
        );
        assert_eq!(
            cfg.muobserve_addr.as_deref(),
            Some("observe.cluster.internal:9445")
        );
        assert_eq!(cfg.repo.as_deref(), Some("LMA1980/mu-cd-controller"));

        let legacy = HashMap::from([
            ("MUCONDE_CONTROLLER_URL", "https://legacy-ci.example:8443"),
            ("MUREGIST_URL", "https://legacy-reg.example:8444"),
            ("MUCONDE_AGENT_PORT", "7446"),
            ("MUREGIST_TOKEN", "legacy-tok"),
            ("TLS_CA_CERT", "/etc/legacy/ca.crt"),
            ("TLS_CLIENT_CERT", "/etc/legacy/client.crt"),
            ("TLS_CLIENT_KEY", "/etc/legacy/client.key"),
            ("MUOBSERVE_ADDR", "legacy-observe.example:9445"),
            ("MUCONDE_REPO", "LMA1980/legacy"),
        ]);
        let cfg_legacy =
            ControllerEnvConfig::from_env_lookup(&|k| legacy.get(k).map(|v| (*v).into()));
        assert_eq!(cfg_legacy.controller_url, "https://legacy-ci.example:8443");
        assert_eq!(cfg_legacy.regist_url, "https://legacy-reg.example:8444");
        assert_eq!(cfg_legacy.agent_port, 7446);
        assert_eq!(cfg_legacy.auth_token.as_deref(), Some("legacy-tok"));
        assert_eq!(
            cfg_legacy.ca_path,
            Some(PathBuf::from("/etc/legacy/ca.crt"))
        );
        assert_eq!(
            cfg_legacy.client_cert_path,
            Some(PathBuf::from("/etc/legacy/client.crt"))
        );
        assert_eq!(
            cfg_legacy.client_key_path,
            Some(PathBuf::from("/etc/legacy/client.key"))
        );
        assert_eq!(
            cfg_legacy.muobserve_addr.as_deref(),
            Some("legacy-observe.example:9445")
        );
        assert_eq!(cfg_legacy.repo.as_deref(), Some("LMA1980/legacy"));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_controller_registry_token_file_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let tok = dir.path().join("reg_token");
        std::fs::write(&tok, "  tok-from-file\n").unwrap();

        let good = HashMap::from([(
            "MU_CD_CONTROLLER_REGISTRY_TOKEN_FILE",
            tok.to_str().unwrap().to_string(),
        )]);
        assert_eq!(
            resolve_registry_token(&|k| good.get(k).cloned()).as_deref(),
            Some("tok-from-file")
        );

        let missing = HashMap::from([(
            "MU_REGISTRY_TOKEN_FILE",
            "/nonexistent/mu-registry/token".to_string(),
        )]);
        assert_eq!(resolve_registry_token(&|k| missing.get(k).cloned()), None);

        let missing_path_raw =
            HashMap::from([("MUREGIST_TOKEN", "/nonexistent/muregist/token".to_string())]);
        assert_eq!(
            resolve_registry_token(&|k| missing_path_raw.get(k).cloned()),
            None
        );
    }
}
