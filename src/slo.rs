//! Canary Bake SLO verification client communicating with `MuObserve` over `step-ca` mTLS
//! and `MUOB`-framed Apache Fory RPC envelopes.

use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use mu_observable_ipc::{
    decode_control_envelope, encode_control_envelope, read_frame, write_frame,
    CanarySloAssertionRequest, CanarySloAssertionResponse, ControlRpcEnvelope, IpcHeader,
    MSG_TYPE_FORY_CONTROL,
};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::error::OrchestratorError;
use crate::tls::TlsConfig;

/// Default `MuObserve` control-plane RPC endpoint.
pub const DEFAULT_MUOBSERVE_ADDR: &str = "observe.ci.internal:9445";

/// Default `MuObserve` TLS SNI server name.
pub const DEFAULT_MUOBSERVE_SERVER_NAME: &str = "observe.ci.internal";

/// Abstract client interface for evaluating canary bake window SLOs via `MuObserve`.
#[async_trait]
pub trait CanarySloClient: Send + Sync {
    /// Query `MuObserve` to assert whether a candidate deployment satisfies error-log,
    /// `p99` latency, and regression SLO bounds over its bake window.
    async fn verify_canary_slo(
        &self,
        req: &CanarySloAssertionRequest,
    ) -> Result<CanarySloAssertionResponse, OrchestratorError>;
}

/// Network client querying `MuObserve` (`CanarySloAssertionRequest` -> `CanarySloAssertionResponse`)
/// over `step-ca` mTLS and `MUOB` Fory control-plane RPC framing.
#[derive(Debug)]
pub struct MuObserveSloClient {
    endpoint: String,
    server_name: String,
    tls_config: Option<TlsConfig>,
    sequence: AtomicU64,
}

impl MuObserveSloClient {
    /// Creates a new `MuObserveSloClient` configured with `step-ca` mTLS credentials.
    pub fn new(endpoint: impl Into<String>, tls_config: TlsConfig) -> Self {
        let endpoint_str = endpoint.into();
        let host = endpoint_str
            .split(':')
            .next()
            .filter(|h| !h.is_empty())
            .unwrap_or(DEFAULT_MUOBSERVE_SERVER_NAME)
            .to_string();

        Self {
            endpoint: endpoint_str,
            server_name: host,
            tls_config: Some(tls_config),
            sequence: AtomicU64::new(1),
        }
    }

    /// Creates a plaintext `MUOB` Fory RPC client for isolated local testing.
    pub fn new_plaintext(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            server_name: DEFAULT_MUOBSERVE_SERVER_NAME.to_string(),
            tls_config: None,
            sequence: AtomicU64::new(1),
        }
    }

    /// Overrides the TLS SNI server name used during the mTLS handshake.
    pub fn with_server_name(mut self, server_name: impl Into<String>) -> Self {
        self.server_name = server_name.into();
        self
    }

    /// Exchanges a `CanarySloReq` / `CanarySloResp` frame pair over an established stream.
    async fn exchange_over_stream<S>(
        &self,
        stream: &mut S,
        req: &CanarySloAssertionRequest,
    ) -> Result<CanarySloAssertionResponse, OrchestratorError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let envelope = ControlRpcEnvelope::CanarySloReq(req.clone());
        let payload = encode_control_envelope(&envelope)
            .map_err(|e| OrchestratorError::Slo(format!("Failed to encode CanarySloReq: {e}")))?;

        let seq = self.sequence.fetch_add(1, Ordering::Relaxed);
        let header = IpcHeader::new(MSG_TYPE_FORY_CONTROL, payload.len() as u32, 0, seq);

        write_frame(stream, &header, &payload)
            .await
            .map_err(|e| OrchestratorError::Slo(format!("Failed to write MUOB SLO frame: {e}")))?;

        let (resp_hdr, resp_payload) = read_frame(stream)
            .await
            .map_err(|e| OrchestratorError::Slo(format!("Failed to read MUOB SLO frame: {e}")))?;

        if resp_hdr.msg_type != MSG_TYPE_FORY_CONTROL {
            return Err(OrchestratorError::Slo(format!(
                "Unexpected MUOB frame msg_type: 0x{:04x} (expected 0x{:04x})",
                resp_hdr.msg_type, MSG_TYPE_FORY_CONTROL
            )));
        }

        let decoded = decode_control_envelope(&resp_payload)
            .map_err(|e| OrchestratorError::Slo(format!("Failed to decode CanarySloResp: {e}")))?;

        match decoded {
            ControlRpcEnvelope::CanarySloResp(resp) => Ok(resp),
            other => Err(OrchestratorError::Slo(format!(
                "Unexpected ControlRpcEnvelope variant in CanarySlo response: {other:?}"
            ))),
        }
    }
}

#[async_trait]
impl CanarySloClient for MuObserveSloClient {
    async fn verify_canary_slo(
        &self,
        req: &CanarySloAssertionRequest,
    ) -> Result<CanarySloAssertionResponse, OrchestratorError> {
        let mut tcp_stream = TcpStream::connect(&self.endpoint).await.map_err(|e| {
            OrchestratorError::Slo(format!(
                "Failed to connect to MuObserve at {}: {e}",
                self.endpoint
            ))
        })?;

        if let Some(ref tls_cfg) = self.tls_config {
            let connector = tls_cfg.build_tls_connector()?;
            let server_name = ServerName::try_from(self.server_name.clone()).map_err(|e| {
                OrchestratorError::Slo(format!(
                    "Invalid TLS server name '{}': {e}",
                    self.server_name
                ))
            })?;
            let mut tls_stream = connector
                .connect(server_name, tcp_stream)
                .await
                .map_err(|e| {
                    OrchestratorError::Slo(format!(
                        "mTLS handshake with MuObserve at {} failed: {e}",
                        self.endpoint
                    ))
                })?;
            self.exchange_over_stream(&mut tls_stream, req).await
        } else {
            self.exchange_over_stream(&mut tcp_stream, req).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    fn generate_mtls_materials() -> (TlsConfig, Arc<rustls::ServerConfig>) {
        TlsConfig::ensure_crypto_provider();

        let mut ca_params = rcgen::CertificateParams::new(vec!["Test Root CA".into()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_issuer = rcgen::Issuer::new(ca_params, ca_key);

        let server_params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let server_key = rcgen::KeyPair::generate().unwrap();
        let server_cert = server_params.signed_by(&server_key, &ca_issuer).unwrap();

        let client_params =
            rcgen::CertificateParams::new(vec!["muconde-controller".into()]).unwrap();
        let client_key = rcgen::KeyPair::generate().unwrap();
        let client_cert = client_params.signed_by(&client_key, &ca_issuer).unwrap();

        let tls_config = TlsConfig::from_pem_strings(
            ca_cert.pem(),
            client_cert.pem(),
            client_key.serialize_pem(),
        );

        let mut client_root_store = rustls::RootCertStore::empty();
        client_root_store.add(ca_cert.der().clone()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_root_store))
            .build()
            .unwrap();

        let server_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![server_cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()),
                ),
            )
            .unwrap();

        (tls_config, Arc::new(server_config))
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_muobserve_slo_client_mtls_roundtrip() {
        let (client_tls, server_tls) = generate_mtls_materials();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let acceptor = TlsAcceptor::from(server_tls);

        let server_handle = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let mut tls_stream = acceptor.accept(tcp).await.expect("tls accept");
            let (hdr, payload) = read_frame(&mut tls_stream).await.expect("read req");
            assert_eq!(hdr.msg_type, MSG_TYPE_FORY_CONTROL);

            let env = decode_control_envelope(&payload).expect("decode req");
            match env {
                ControlRpcEnvelope::CanarySloReq(req) => {
                    let resp = CanarySloAssertionResponse {
                        request_id: req.request_id,
                        healthy: true,
                        error_log_count: 0,
                        p99_latency_ms: 42.0,
                        taint_recommended: false,
                        reason: "all SLO metrics within bounds".to_string(),
                    };
                    let resp_bytes =
                        encode_control_envelope(&ControlRpcEnvelope::CanarySloResp(resp))
                            .expect("encode resp");
                    let resp_hdr = IpcHeader::new(
                        MSG_TYPE_FORY_CONTROL,
                        resp_bytes.len() as u32,
                        0,
                        hdr.sequence,
                    );
                    write_frame(&mut tls_stream, &resp_hdr, &resp_bytes)
                        .await
                        .expect("write resp");
                }
                other => panic!("Expected CanarySloReq, got {other:?}"),
            }
        });

        let client =
            MuObserveSloClient::new(addr.to_string(), client_tls).with_server_name("localhost");
        let req = CanarySloAssertionRequest {
            request_id: "slo-test-1".to_string(),
            service_name: "action-runner".to_string(),
            candidate_digest: "sha256-candidate-001".to_string(),
            node_id: "worker-riscv64".to_string(),
            bake_window_secs: 60,
            max_error_logs: 0,
            max_p99_latency_ms: 250.0,
        };

        let resp = client
            .verify_canary_slo(&req)
            .await
            .expect("verify_canary_slo");
        assert!(resp.healthy);
        assert!(!resp.taint_recommended);
        assert_eq!(resp.error_log_count, 0);
        assert!((resp.p99_latency_ms - 42.0).abs() < f64::EPSILON);

        server_handle.await.expect("server task");
    }
}
