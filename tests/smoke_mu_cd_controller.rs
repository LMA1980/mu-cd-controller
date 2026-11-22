#![deny(unsafe_code)]

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use mu_cd_controller::api::{load_token_file, spawn_cd_api, CdApiConfig, CdApiState};
use mu_cd_controller::cd_state::{CdStateStore, DeploymentStart, LeaseView, Slot};
use mu_cd_controller::{DeploymentSummary, TlsConfig};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const DEFAULT_SMOKE_TIMEOUT_SECS: u64 = 10;
const HEALTH_RETRY_BACKOFF: Duration = Duration::from_millis(200);

fn is_transient_health_status(status: u16) -> bool {
    matches!(status, 502..=504)
}

async fn probe_health_with_retry(
    base_url: &str,
    client: &reqwest::Client,
    timeout: Duration,
    retry_backoff: Duration,
) -> Result<serde_json::Value, String> {
    let url = format!("{base_url}/health");
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last_transient_err: Option<String> = None;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(format!(
                "GET {url} timed out after {:?}: {}",
                timeout,
                last_transient_err.unwrap_or_else(|| "deadline exceeded".to_string())
            ));
        }

        match client.get(&url).timeout(remaining).send().await {
            Ok(resp) => {
                let code = resp.status().as_u16();
                if code == 200 {
                    let json: serde_json::Value = resp
                        .json()
                        .await
                        .map_err(|e| format!("GET {url} must return valid JSON: {e}"))?;
                    if json["status"] != "ok" {
                        return Err(format!("GET {url} expected status='ok', got {json}"));
                    }
                    return Ok(json);
                }
                if is_transient_health_status(code) {
                    last_transient_err = Some(format!("transient HTTP {code}"));
                } else {
                    return Err(format!("GET {url} returned non-transient HTTP {code}"));
                }
            }
            Err(err) => {
                last_transient_err = Some(format!("transport error: {err}"));
            }
        }

        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(format!(
                "GET {url} failed after {:?}: {}",
                timeout,
                last_transient_err.unwrap_or_else(|| "deadline exceeded".to_string())
            ));
        }
        let sleep_for = retry_backoff.min(deadline.saturating_duration_since(now));
        tokio::time::sleep(sleep_for).await;
    }
}

#[derive(Debug, Clone)]
struct SmokeConfig {
    target_url: Option<String>,
    tls_ca_file: Option<PathBuf>,
    tls_cert_file: Option<PathBuf>,
    tls_key_file: Option<PathBuf>,
    bearer_token: Option<String>,
    timeout: Duration,
}

impl SmokeConfig {
    fn from_env() -> Result<Self, String> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    fn from_lookup<F>(lookup: F) -> Result<Self, String>
    where
        F: Fn(&str) -> Option<String>,
    {
        let tls_ca_file = non_empty_path(&lookup, "MU_SMOKE_TLS_CA_FILE")?;
        let tls_cert_file = non_empty_path(&lookup, "MU_SMOKE_TLS_CERT_FILE")?;
        let tls_key_file = non_empty_path(&lookup, "MU_SMOKE_TLS_KEY_FILE")?;

        if tls_cert_file.is_some() != tls_key_file.is_some() {
            return Err(
                "MU_SMOKE_TLS_CERT_FILE and MU_SMOKE_TLS_KEY_FILE must both be set when configuring client mTLS"
                    .to_string(),
            );
        }

        if let Some(ref ca_path) = tls_ca_file {
            validate_pem_certs_file(ca_path, "MU_SMOKE_TLS_CA_FILE")?;
        }
        if let (Some(ref cert_path), Some(ref key_path)) = (&tls_cert_file, &tls_key_file) {
            validate_pem_certs_file(cert_path, "MU_SMOKE_TLS_CERT_FILE")?;
            validate_pem_key_file(key_path, "MU_SMOKE_TLS_KEY_FILE")?;
        }

        let bearer_token = match non_empty_path(&lookup, "MU_SMOKE_BEARER_TOKEN_FILE")? {
            Some(path) => Some(read_trimmed_secret(&path, "MU_SMOKE_BEARER_TOKEN_FILE")?),
            None => None,
        };

        let timeout_secs = match non_empty_var(&lookup, "MU_SMOKE_TIMEOUT_SECS") {
            Some(raw) => {
                let parsed = raw
                    .parse::<u64>()
                    .map_err(|e| format!("Invalid MU_SMOKE_TIMEOUT_SECS '{raw}': {e}"))?;
                if parsed == 0 {
                    return Err("MU_SMOKE_TIMEOUT_SECS must be greater than 0".to_string());
                }
                parsed
            }
            None => DEFAULT_SMOKE_TIMEOUT_SECS,
        };

        let has_tls = tls_ca_file.is_some() || tls_cert_file.is_some();
        let target_url = match non_empty_var(&lookup, "MU_SMOKE_TARGET_URL") {
            Some(url) => Some(url.trim_end_matches('/').to_string()),
            None => non_empty_var(&lookup, "MU_SMOKE_TARGET_ADDR").map(|addr| {
                let trimmed = addr.trim_end_matches('/');
                if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
                    trimmed.to_string()
                } else if has_tls {
                    format!("https://{trimmed}")
                } else {
                    format!("http://{trimmed}")
                }
            }),
        };

        Ok(Self {
            target_url,
            tls_ca_file,
            tls_cert_file,
            tls_key_file,
            bearer_token,
            timeout: Duration::from_secs(timeout_secs),
        })
    }

    fn build_client(&self, include_client_identity: bool) -> Result<reqwest::Client, String> {
        let tls = TlsConfig {
            ca_cert_path: self.tls_ca_file.clone(),
            client_cert_path: if include_client_identity {
                self.tls_cert_file.clone()
            } else {
                None
            },
            client_key_path: if include_client_identity {
                self.tls_key_file.clone()
            } else {
                None
            },
            ..Default::default()
        };
        if self.tls_ca_file.is_some() || (include_client_identity && self.tls_cert_file.is_some()) {
            tls.build_reqwest_client()
                .map_err(|e| format!("Failed building TLS reqwest client: {e}"))
        } else {
            reqwest::Client::builder()
                .timeout(self.timeout)
                .build()
                .map_err(|e| format!("Failed building HTTP reqwest client: {e}"))
        }
    }
}

fn non_empty_var<F>(lookup: &F, key: &str) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    lookup(key)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn non_empty_path<F>(lookup: &F, key: &str) -> Result<Option<PathBuf>, String>
where
    F: Fn(&str) -> Option<String>,
{
    match lookup(key) {
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                Err(format!("{key} was set but empty"))
            } else {
                Ok(Some(PathBuf::from(trimmed)))
            }
        }
        None => Ok(None),
    }
}

fn read_trimmed_secret(path: &Path, var_name: &str) -> Result<String, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        format!(
            "Failed to read {var_name} at '{}': {e} (fail closed)",
            path.display()
        )
    })?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!(
            "{var_name} at '{}' is empty after trimming (fail closed)",
            path.display()
        ));
    }
    Ok(trimmed.to_string())
}

fn validate_pem_certs_file(path: &Path, var_name: &str) -> Result<(), String> {
    let file = File::open(path).map_err(|e| {
        format!(
            "Failed to open {var_name} at '{}': {e} (fail closed)",
            path.display()
        )
    })?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            format!(
                "Invalid PEM certificate in {var_name} at '{}': {e}",
                path.display()
            )
        })?;
    if certs.is_empty() {
        return Err(format!(
            "{var_name} at '{}' contains zero certificates",
            path.display()
        ));
    }
    Ok(())
}

fn validate_pem_key_file(path: &Path, var_name: &str) -> Result<(), String> {
    let file = File::open(path).map_err(|e| {
        format!(
            "Failed to open {var_name} at '{}': {e} (fail closed)",
            path.display()
        )
    })?;
    let mut reader = BufReader::new(file);
    PrivateKeyDer::from_pem_reader(&mut reader).map_err(|e| {
        format!(
            "Invalid PEM private key in {var_name} at '{}': {e}",
            path.display()
        )
    })?;
    Ok(())
}

fn generate_ephemeral_pki(dir: &Path) -> (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
    let mut ca_params = CertificateParams::new(vec!["mu-cd-smoke-ca".to_string()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "mu-cd-smoke-ca");
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_issuer = Issuer::from_params(&ca_params, &ca_key);

    let srv_params =
        CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
    let srv_key = KeyPair::generate().unwrap();
    let srv_cert = srv_params.signed_by(&srv_key, &ca_issuer).unwrap();

    let cli_params = CertificateParams::new(vec!["smoke-probe-client".to_string()]).unwrap();
    let cli_key = KeyPair::generate().unwrap();
    let cli_cert = cli_params.signed_by(&cli_key, &ca_issuer).unwrap();

    let ca_path = dir.join("ca.crt");
    let srv_cert_path = dir.join("server.crt");
    let srv_key_path = dir.join("server.key");
    let cli_cert_path = dir.join("client.crt");
    let cli_key_path = dir.join("client.key");

    std::fs::write(&ca_path, ca_cert.pem()).unwrap();
    std::fs::write(&srv_cert_path, srv_cert.pem()).unwrap();
    std::fs::write(&srv_key_path, srv_key.serialize_pem()).unwrap();
    std::fs::write(&cli_cert_path, cli_cert.pem()).unwrap();
    std::fs::write(&cli_key_path, cli_key.serialize_pem()).unwrap();

    (
        ca_path,
        srv_cert_path,
        srv_key_path,
        cli_cert_path,
        cli_key_path,
    )
}

async fn spawn_ephemeral_mtls_health_proxy(
    ca_path: &Path,
    srv_cert_path: &Path,
    srv_key_path: &Path,
    backend_addr: std::net::SocketAddr,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    TlsConfig::ensure_crypto_provider();
    let mut ca_reader = BufReader::new(File::open(ca_path).unwrap());
    let ca_certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(&mut ca_reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut root_store = rustls::RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(cert).unwrap();
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .unwrap();

    let mut srv_reader = BufReader::new(File::open(srv_cert_path).unwrap());
    let srv_certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(&mut srv_reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut key_reader = BufReader::new(File::open(srv_key_path).unwrap());
    let srv_key = PrivateKeyDer::from_pem_reader(&mut key_reader).unwrap();

    let server_cfg = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(srv_certs, srv_key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls_stream) = acceptor.accept(tcp).await else {
                    return;
                };
                if let Ok(mut backend) = tokio::net::TcpStream::connect(backend_addr).await {
                    let _ = tokio::io::copy_bidirectional(&mut tls_stream, &mut backend).await;
                }
                let _ = tls_stream.shutdown().await;
            });
        }
    });

    (addr, handle)
}

async fn run_http_cd_smoke(
    base_url: &str,
    client: &reqwest::Client,
    bearer_token: Option<&str>,
    timeout: Duration,
) {
    // 1. Read-only /health check with bounded retry on transient startup/proxy errors
    let health_json = probe_health_with_retry(base_url, client, timeout, HEALTH_RETRY_BACKOFF)
        .await
        .expect("GET /health must succeed within timeout");
    assert_eq!(health_json["status"], "ok");

    // 2. Unauthenticated requests to protected CD endpoints MUST fail closed (401/403)
    for path in ["/api/cd/deployments", "/api/cd/leases", "/api/cd/events"] {
        let unauth = client
            .get(format!("{base_url}{path}"))
            .timeout(timeout)
            .send()
            .await
            .expect("unauthenticated probe request should complete");
        assert!(
            matches!(unauth.status().as_u16(), 401 | 403),
            "{path} without credentials must fail closed with 401/403, got {}",
            unauth.status()
        );
    }

    // Wrong bearer token must also fail closed (401/403)
    let bad_auth = client
        .get(format!("{base_url}/api/cd/deployments"))
        .bearer_auth("invalid-smoke-credential")
        .timeout(timeout)
        .send()
        .await
        .expect("bad bearer probe request should complete");
    assert!(
        matches!(bad_auth.status().as_u16(), 401 | 403),
        "wrong bearer token must fail closed with 401/403, got {}",
        bad_auth.status()
    );

    // 3. Authenticated strictly read-only checks when bearer credential is available
    if let Some(token) = bearer_token {
        let dep_resp_1 = client
            .get(format!("{base_url}/api/cd/deployments?limit=5"))
            .bearer_auth(token)
            .timeout(timeout)
            .send()
            .await
            .expect("authenticated GET /api/cd/deployments");
        assert_eq!(dep_resp_1.status().as_u16(), 200);
        let deployments_1: Vec<DeploymentSummary> = dep_resp_1
            .json()
            .await
            .expect("deserialize DeploymentSummary list");

        let leases_resp_1 = client
            .get(format!("{base_url}/api/cd/leases"))
            .bearer_auth(token)
            .timeout(timeout)
            .send()
            .await
            .expect("authenticated GET /api/cd/leases");
        assert_eq!(leases_resp_1.status().as_u16(), 200);
        let leases_1: Vec<LeaseView> = leases_resp_1
            .json()
            .await
            .expect("deserialize LeaseView list");

        let sse_resp = client
            .get(format!("{base_url}/api/cd/events"))
            .bearer_auth(token)
            .timeout(timeout)
            .send()
            .await
            .expect("authenticated GET /api/cd/events SSE");
        assert_eq!(sse_resp.status().as_u16(), 200);
        let content_type = sse_resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            content_type.starts_with("text/event-stream"),
            "SSE endpoint must return text/event-stream, got '{content_type}'"
        );
        drop(sse_resp);

        // Re-read deployments and leases to confirm zero mutation occurred
        let dep_resp_2 = client
            .get(format!("{base_url}/api/cd/deployments?limit=5"))
            .bearer_auth(token)
            .timeout(timeout)
            .send()
            .await
            .expect("second GET /api/cd/deployments");
        assert_eq!(dep_resp_2.status().as_u16(), 200);
        let deployments_2: Vec<DeploymentSummary> = dep_resp_2.json().await.unwrap();
        assert_eq!(
            deployments_1
                .iter()
                .map(|d| (&d.deployment_id, d.outcome, d.active_slot, d.tainted))
                .collect::<Vec<_>>(),
            deployments_2
                .iter()
                .map(|d| (&d.deployment_id, d.outcome, d.active_slot, d.tainted))
                .collect::<Vec<_>>(),
            "read-only smoke probes must not mutate deployment state"
        );

        let leases_resp_2 = client
            .get(format!("{base_url}/api/cd/leases"))
            .bearer_auth(token)
            .timeout(timeout)
            .send()
            .await
            .expect("second GET /api/cd/leases");
        assert_eq!(leases_resp_2.status().as_u16(), 200);
        let leases_2: Vec<LeaseView> = leases_resp_2.json().await.unwrap();
        assert_eq!(
            leases_1
                .iter()
                .map(|l| (&l.lease_id, &l.deployment_id, l.promoted))
                .collect::<Vec<_>>(),
            leases_2
                .iter()
                .map(|l| (&l.lease_id, &l.deployment_id, l.promoted))
                .collect::<Vec<_>>(),
            "read-only smoke probes must not mutate active leases"
        );
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn smoke_config_enforces_fail_closed_credentials_and_defaults() {
    let temp = tempfile::tempdir().unwrap();
    let token_path = temp.path().join("bearer.token");
    std::fs::write(&token_path, "  smoke-bearer-secret-42 \n").unwrap();

    let (ca_path, _, _, cli_cert_path, cli_key_path) = generate_ephemeral_pki(temp.path());

    // Valid token + mTLS paths trim cleanly and default timeout to 10s
    let ok_env = HashMap::from([
        ("MU_SMOKE_TARGET_URL", "https://127.0.0.1:8445/".to_string()),
        (
            "MU_SMOKE_BEARER_TOKEN_FILE",
            token_path.to_string_lossy().into_owned(),
        ),
        (
            "MU_SMOKE_TLS_CA_FILE",
            ca_path.to_string_lossy().into_owned(),
        ),
        (
            "MU_SMOKE_TLS_CERT_FILE",
            cli_cert_path.to_string_lossy().into_owned(),
        ),
        (
            "MU_SMOKE_TLS_KEY_FILE",
            cli_key_path.to_string_lossy().into_owned(),
        ),
    ]);
    let cfg = SmokeConfig::from_lookup(|k| ok_env.get(k).cloned()).unwrap();
    assert_eq!(cfg.target_url.as_deref(), Some("https://127.0.0.1:8445"));
    assert_eq!(cfg.bearer_token.as_deref(), Some("smoke-bearer-secret-42"));
    assert_eq!(cfg.timeout, Duration::from_secs(10));
    assert!(cfg.build_client(true).is_ok());

    // Unreadable bearer token file fails closed
    let missing_token_env = HashMap::from([(
        "MU_SMOKE_BEARER_TOKEN_FILE",
        temp.path()
            .join("missing.token")
            .to_string_lossy()
            .into_owned(),
    )]);
    assert!(SmokeConfig::from_lookup(|k| missing_token_env.get(k).cloned()).is_err());

    // Empty bearer token file fails closed
    let empty_token = temp.path().join("empty.token");
    std::fs::write(&empty_token, "   \n").unwrap();
    let empty_token_env = HashMap::from([(
        "MU_SMOKE_BEARER_TOKEN_FILE",
        empty_token.to_string_lossy().into_owned(),
    )]);
    assert!(SmokeConfig::from_lookup(|k| empty_token_env.get(k).cloned()).is_err());

    // Unreadable TLS CA file fails closed
    let bad_ca_env = HashMap::from([(
        "MU_SMOKE_TLS_CA_FILE",
        temp.path()
            .join("missing-ca.pem")
            .to_string_lossy()
            .into_owned(),
    )]);
    assert!(SmokeConfig::from_lookup(|k| bad_ca_env.get(k).cloned()).is_err());

    // Half-configured client mTLS (cert without key) fails closed
    let partial_tls_env = HashMap::from([(
        "MU_SMOKE_TLS_CERT_FILE",
        cli_cert_path.to_string_lossy().into_owned(),
    )]);
    assert!(SmokeConfig::from_lookup(|k| partial_tls_env.get(k).cloned()).is_err());
}

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn smoke_cd_controller_health_deployments_and_sse() {
    let cfg = SmokeConfig::from_env().expect("valid MU_SMOKE_* environment configuration");

    if let Some(ref target_url) = cfg.target_url {
        let auth_client = cfg
            .build_client(true)
            .expect("build live probe HTTP/mTLS client");

        run_http_cd_smoke(
            target_url,
            &auth_client,
            cfg.bearer_token.as_deref(),
            cfg.timeout,
        )
        .await;

        // If client mTLS credentials were supplied, verify missing client cert fails closed
        if cfg.tls_cert_file.is_some() && target_url.starts_with("https://") {
            let no_cert_client = cfg
                .build_client(false)
                .expect("build CA-only client without client identity");
            let unauth_tls = no_cert_client
                .get(format!("{target_url}/api/cd/deployments"))
                .timeout(cfg.timeout)
                .send()
                .await;
            if let Ok(resp) = unauth_tls {
                assert!(
                    matches!(resp.status().as_u16(), 401 | 403),
                    "expected TLS rejection or 401/403 without client cert, got {}",
                    resp.status()
                );
            }
        }
        return;
    }

    // Ephemeral mode: spin up local 127.0.0.1:0 CD API + mTLS proxy with ephemeral creds
    let temp = tempfile::tempdir().unwrap();
    let token_path = temp.path().join("cd-api.token");
    std::fs::write(&token_path, "  ephemeral-cd-smoke-token\n").unwrap();
    let loaded_token = load_token_file(&token_path).expect("load ephemeral token");

    let store = Arc::new(CdStateStore::default());
    store.deployment_started(DeploymentStart {
        deployment_id: "dep-smoke-seed".into(),
        repo: Some("LMA1980/example-svc".into()),
        service: "example-svc".into(),
        artifact_digest: "sha256:0123456789abcdef".into(),
        target_node: "node-a".into(),
        active_slot: Slot::A,
        staged_slot: Slot::B,
        restore_slot: Slot::A,
        lease_id: "lease-smoke-seed".into(),
        lease_expires_epoch_ms: mu_cd_controller::lease::LeaseCoordinator::current_epoch_ms()
            + 60_000,
        tests: vec![("smoke_health".into(), true)],
    });
    store.set_leases(vec![LeaseView {
        lease_id: "lease-smoke-seed".into(),
        deployment_id: "dep-smoke-seed".into(),
        target_node: "node-a".into(),
        service: "example-svc".into(),
        artifact_digest: "sha256:0123456789abcdef".into(),
        active_slot: Slot::A,
        candidate_slot: Slot::B,
        expires_epoch_ms: mu_cd_controller::lease::LeaseCoordinator::current_epoch_ms() + 60_000,
        ttl_remaining_ms: 60_000,
        promoted: false,
    }]);

    let before = store.snapshot();

    let api_cfg = CdApiConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        token_file: Some(token_path.clone()),
        proxy_secret_file: None,
        operator_users: Vec::new(),
    };
    let (addr, server_handle) = spawn_cd_api(&api_cfg, store.clone())
        .await
        .expect("spawn ephemeral CD API")
        .expect("bound addr");

    let http_client = cfg.build_client(false).unwrap();
    let http_base = format!("http://{addr}");
    run_http_cd_smoke(&http_base, &http_client, Some(&loaded_token), cfg.timeout).await;

    // Also exercise SSE heartbeat chunk on an ephemeral listener with short keep-alive
    let sse_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sse_addr = sse_listener.local_addr().unwrap();
    let sse_state = CdApiState::new(store.clone(), Some(loaded_token.clone()))
        .with_keep_alive(Duration::from_millis(50));
    let sse_handle = tokio::spawn(async move {
        let _ = mu_cd_controller::api::serve(sse_listener, sse_state).await;
    });
    let mut sse_resp = http_client
        .get(format!("http://{sse_addr}/api/cd/events"))
        .bearer_auth(&loaded_token)
        .timeout(cfg.timeout)
        .send()
        .await
        .unwrap();
    assert_eq!(sse_resp.status().as_u16(), 200);
    let chunk = tokio::time::timeout(Duration::from_secs(2), sse_resp.chunk())
        .await
        .expect("SSE heartbeat chunk arrived")
        .expect("SSE chunk read ok")
        .expect("SSE chunk non-empty");
    let text = String::from_utf8_lossy(&chunk);
    assert!(
        text.contains("heartbeat"),
        "expected keep-alive heartbeat comment on SSE stream, got '{text}'"
    );
    drop(sse_resp);
    sse_handle.abort();

    // Exercise ephemeral mTLS transport using TlsConfig against mTLS-enforcing listener
    let (ca_path, srv_cert, srv_key, cli_cert, cli_key) = generate_ephemeral_pki(temp.path());
    let (mtls_addr, mtls_handle) =
        spawn_ephemeral_mtls_health_proxy(&ca_path, &srv_cert, &srv_key, addr).await;
    let mtls_url = format!("https://{mtls_addr}");

    let missing_cert_client = TlsConfig {
        ca_cert_path: Some(ca_path.clone()),
        ..Default::default()
    }
    .build_reqwest_client()
    .unwrap();
    let no_cert_res = missing_cert_client
        .get(format!("{mtls_url}/health"))
        .timeout(cfg.timeout)
        .send()
        .await;
    assert!(
        no_cert_res.is_err(),
        "mTLS listener must reject connections missing a client certificate"
    );

    let mtls_client = TlsConfig::from_paths(&ca_path, &cli_cert, &cli_key)
        .build_reqwest_client()
        .unwrap();
    run_http_cd_smoke(&mtls_url, &mtls_client, Some(&loaded_token), cfg.timeout).await;

    let after = store.snapshot();
    assert_eq!(before.rev, after.rev);
    assert_eq!(before.deployments.len(), after.deployments.len());
    assert_eq!(before.leases, after.leases);
    assert_eq!(before.cd_runs.len(), after.cd_runs.len());

    mtls_handle.abort();
    server_handle.abort();
}

async fn spawn_scripted_health_server(
    statuses: Vec<(u16, &'static str)>,
) -> (
    std::net::SocketAddr,
    Arc<std::sync::atomic::AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::AsyncReadExt;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_srv = attempts.clone();

    let handle = tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let idx = attempts_srv.fetch_add(1, Ordering::SeqCst);
            let (code, body) = statuses
                .get(idx)
                .copied()
                .unwrap_or_else(|| *statuses.last().unwrap());
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = tcp.read(&mut buf).await;
                let reason = match code {
                    200 => "OK",
                    500 => "Internal Server Error",
                    502 => "Bad Gateway",
                    503 => "Service Unavailable",
                    504 => "Gateway Timeout",
                    _ => "Error",
                };
                let resp = format!(
                    "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = tcp.write_all(resp.as_bytes()).await;
                let _ = tcp.shutdown().await;
            });
        }
    });

    (addr, attempts, handle)
}

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn smoke_health_probe_retries_transient_502_until_200_and_fails_closed() {
    use std::sync::atomic::Ordering;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    // 1. Transient proxy startup sequence `502 -> 502 -> 200` recovers within budget
    let (ok_addr, ok_attempts, ok_srv) = spawn_scripted_health_server(vec![
        (502, r#"{"error":"bad_gateway"}"#),
        (502, r#"{"error":"bad_gateway"}"#),
        (200, r#"{"status":"ok"}"#),
    ])
    .await;
    let health = probe_health_with_retry(
        &format!("http://{ok_addr}"),
        &client,
        Duration::from_secs(2),
        Duration::from_millis(50),
    )
    .await
    .expect("502 -> 502 -> 200 must recover within budget");
    assert_eq!(health["status"], "ok");
    assert_eq!(ok_attempts.load(Ordering::SeqCst), 3);
    ok_srv.abort();

    // 2. Non-transient HTTP 500 fails immediately without retrying
    let (err_addr, err_attempts, err_srv) =
        spawn_scripted_health_server(vec![(500, r#"{"error":"internal"}"#)]).await;
    let started = std::time::Instant::now();
    let err = probe_health_with_retry(
        &format!("http://{err_addr}"),
        &client,
        Duration::from_secs(3),
        Duration::from_millis(100),
    )
    .await
    .expect_err("non-transient HTTP 500 must fail immediately");
    assert!(
        err.contains("non-transient HTTP 500"),
        "unexpected error message: {err}"
    );
    assert_eq!(err_attempts.load(Ordering::SeqCst), 1);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "non-transient error must fail immediately, took {:?}",
        started.elapsed()
    );
    err_srv.abort();

    // 3. Persistent HTTP 502 fails closed once timeout expires
    let (fail_addr, fail_attempts, fail_srv) =
        spawn_scripted_health_server(vec![(502, r#"{"error":"bad_gateway"}"#)]).await;
    let err_timeout = probe_health_with_retry(
        &format!("http://{fail_addr}"),
        &client,
        Duration::from_millis(350),
        Duration::from_millis(80),
    )
    .await
    .expect_err("persistent 502 must fail closed after timeout");
    assert!(
        err_timeout.contains("transient HTTP 502"),
        "expected transient HTTP 502 detail, got: {err_timeout}"
    );
    assert!(
        fail_attempts.load(Ordering::SeqCst) >= 2,
        "expected multiple retry attempts before timeout, got {}",
        fail_attempts.load(Ordering::SeqCst)
    );
    fail_srv.abort();
}
