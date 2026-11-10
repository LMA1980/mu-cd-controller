//! Mutual TLS (mTLS) configuration and client builder supporting step-ca PKI.

use std::fs::File;
use std::io::{BufReader, Cursor};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsConnector;

use crate::error::TlsError;

/// Configuration for mTLS client connections to ActionRunner-controller, MuRegist, and MuConDe-agent.
#[derive(Debug, Clone, Default)]
pub struct TlsConfig {
    pub ca_cert_path: Option<PathBuf>,
    pub client_cert_path: Option<PathBuf>,
    pub client_key_path: Option<PathBuf>,
    pub ca_cert_pem: Option<String>,
    pub client_cert_pem: Option<String>,
    pub client_key_pem: Option<String>,
}

impl TlsConfig {
    /// Initialize with filesystem paths to PEM certificate material.
    pub fn from_paths(
        ca_cert_path: impl AsRef<Path>,
        client_cert_path: impl AsRef<Path>,
        client_key_path: impl AsRef<Path>,
    ) -> Self {
        Self {
            ca_cert_path: Some(ca_cert_path.as_ref().to_path_buf()),
            client_cert_path: Some(client_cert_path.as_ref().to_path_buf()),
            client_key_path: Some(client_key_path.as_ref().to_path_buf()),
            ca_cert_pem: None,
            client_cert_pem: None,
            client_key_pem: None,
        }
    }

    /// Initialize with in-memory PEM string contents (convenient for testing and dynamic config).
    pub fn from_pem_strings(
        ca_cert_pem: impl Into<String>,
        client_cert_pem: impl Into<String>,
        client_key_pem: impl Into<String>,
    ) -> Self {
        Self {
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
            ca_cert_pem: Some(ca_cert_pem.into()),
            client_cert_pem: Some(client_cert_pem.into()),
            client_key_pem: Some(client_key_pem.into()),
        }
    }

    /// Ensures the default crypto provider is installed.
    pub fn ensure_crypto_provider() {
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
    }

    /// Load root CA certificates from configured path or memory.
    pub fn load_ca_certificates(&self) -> Result<Vec<CertificateDer<'static>>, TlsError> {
        if let Some(ref pem) = self.ca_cert_pem {
            let mut cursor = Cursor::new(pem.as_bytes());
            let certs = CertificateDer::pem_reader_iter(&mut cursor)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    TlsError::InvalidCertificate(format!("Failed to parse CA PEM: {e}"))
                })?;
            if certs.is_empty() {
                return Err(TlsError::InvalidCertificate(
                    "CA PEM contains no certificates".into(),
                ));
            }
            Ok(certs)
        } else if let Some(ref path) = self.ca_cert_path {
            let file = File::open(path)?;
            let mut reader = BufReader::new(file);
            let certs = CertificateDer::pem_reader_iter(&mut reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    TlsError::InvalidCertificate(format!("Failed to parse CA file: {e}"))
                })?;
            if certs.is_empty() {
                return Err(TlsError::InvalidCertificate(format!(
                    "File {} contains no certificates",
                    path.display()
                )));
            }
            Ok(certs)
        } else {
            Ok(Vec::new())
        }
    }

    /// Load client certificates from configured path or memory.
    pub fn load_client_certificates(&self) -> Result<Vec<CertificateDer<'static>>, TlsError> {
        if let Some(ref pem) = self.client_cert_pem {
            let mut cursor = Cursor::new(pem.as_bytes());
            let certs = CertificateDer::pem_reader_iter(&mut cursor)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    TlsError::InvalidCertificate(format!("Failed to parse client cert PEM: {e}"))
                })?;
            if certs.is_empty() {
                return Err(TlsError::InvalidCertificate(
                    "Client cert PEM contains no certificates".into(),
                ));
            }
            Ok(certs)
        } else if let Some(ref path) = self.client_cert_path {
            let file = File::open(path)?;
            let mut reader = BufReader::new(file);
            let certs = CertificateDer::pem_reader_iter(&mut reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    TlsError::InvalidCertificate(format!("Failed to parse client cert file: {e}"))
                })?;
            if certs.is_empty() {
                return Err(TlsError::InvalidCertificate(format!(
                    "File {} contains no certificates",
                    path.display()
                )));
            }
            Ok(certs)
        } else {
            Ok(Vec::new())
        }
    }

    /// Load client private key from configured path or memory.
    pub fn load_client_key(&self) -> Result<Option<PrivateKeyDer<'static>>, TlsError> {
        if let Some(ref pem) = self.client_key_pem {
            let mut cursor = Cursor::new(pem.as_bytes());
            let key = PrivateKeyDer::from_pem_reader(&mut cursor).map_err(|e| {
                TlsError::InvalidPrivateKey(format!("Failed to parse private key PEM: {e}"))
            })?;
            Ok(Some(key))
        } else if let Some(ref path) = self.client_key_path {
            let file = File::open(path)?;
            let mut reader = BufReader::new(file);
            let key = PrivateKeyDer::from_pem_reader(&mut reader).map_err(|e| {
                TlsError::InvalidPrivateKey(format!("Failed to parse private key file: {e}"))
            })?;
            Ok(Some(key))
        } else {
            Ok(None)
        }
    }

    /// Builds a rustls `ClientConfig` configured with mTLS credentials.
    pub fn build_rustls_client_config(&self) -> Result<rustls::ClientConfig, TlsError> {
        Self::ensure_crypto_provider();

        let mut root_store = rustls::RootCertStore::empty();
        let ca_certs = self.load_ca_certificates()?;
        for cert in ca_certs {
            root_store.add(cert).map_err(|e| {
                TlsError::InvalidCertificate(format!("Failed to add cert to root store: {e}"))
            })?;
        }

        let client_certs = self.load_client_certificates()?;
        let client_key = self.load_client_key()?;

        let builder = rustls::ClientConfig::builder().with_root_certificates(root_store);

        let config = match (client_certs, client_key) {
            (certs, Some(key)) if !certs.is_empty() => builder.with_client_auth_cert(certs, key)?,
            _ => builder.with_no_client_auth(),
        };

        Ok(config)
    }

    /// Builds a `tokio_rustls::TlsConnector`.
    pub fn build_tls_connector(&self) -> Result<TlsConnector, TlsError> {
        let config = self.build_rustls_client_config()?;
        Ok(TlsConnector::from(Arc::new(config)))
    }

    /// Builds a configured `reqwest::Client` with mTLS and custom CA support.
    pub fn build_reqwest_client(&self) -> Result<reqwest::Client, TlsError> {
        let mut builder = reqwest::Client::builder();

        // Add root CA certificates if provided
        if let Some(ref pem) = self.ca_cert_pem {
            let cert = reqwest::Certificate::from_pem(pem.as_bytes())
                .map_err(|e| TlsError::InvalidCertificate(format!("Reqwest CA PEM error: {e}")))?;
            builder = builder.add_root_certificate(cert);
        } else if let Some(ref path) = self.ca_cert_path {
            let bytes = std::fs::read(path)?;
            let cert = reqwest::Certificate::from_pem(&bytes)
                .map_err(|e| TlsError::InvalidCertificate(format!("Reqwest CA file error: {e}")))?;
            builder = builder.add_root_certificate(cert);
        }

        // Add client identity (cert + key) if provided
        let client_pem = match (&self.client_cert_pem, &self.client_key_pem) {
            (Some(cert), Some(key)) => Some(format!("{cert}\n{key}")),
            _ => match (&self.client_cert_path, &self.client_key_path) {
                (Some(cert_path), Some(key_path)) => {
                    let cert = std::fs::read_to_string(cert_path)?;
                    let key = std::fs::read_to_string(key_path)?;
                    Some(format!("{cert}\n{key}"))
                }
                _ => None,
            },
        };

        if let Some(combined_pem) = client_pem {
            let identity = reqwest::Identity::from_pem(combined_pem.as_bytes()).map_err(|e| {
                TlsError::InvalidCertificate(format!("Reqwest identity error: {e}"))
            })?;
            builder = builder.identity(identity);
        }

        builder.build().map_err(|e| {
            TlsError::InvalidCertificate(format!("Failed to build reqwest client: {e}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_config_builds_client() {
        let cfg = TlsConfig::default();
        let client = cfg.build_reqwest_client();
        assert!(client.is_ok());
    }

    #[test]
    fn test_invalid_pem_fails_cleanly() {
        let cfg =
            TlsConfig::from_pem_strings("not-a-valid-cert", "not-a-valid-cert", "not-a-valid-key");
        assert!(cfg.load_ca_certificates().is_err());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_custom_ca_cert_pem_builds_client_with_root_certificate() {
        let mut ca_params = rcgen::CertificateParams::new(vec!["Test Custom CA".into()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let cfg = TlsConfig {
            ca_cert_pem: Some(ca_cert.pem()),
            ..Default::default()
        };
        let client = cfg.build_reqwest_client();
        assert!(
            client.is_ok(),
            "Client should successfully build with custom root CA certificate PEM"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_custom_ca_cert_path_builds_client_with_root_certificate() {
        let mut ca_params = rcgen::CertificateParams::new(vec!["Test File CA".into()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let temp_dir = tempfile::tempdir().unwrap();
        let ca_path = temp_dir.path().join("ca.pem");
        std::fs::write(&ca_path, ca_cert.pem()).unwrap();

        let cfg = TlsConfig {
            ca_cert_path: Some(ca_path),
            ..Default::default()
        };
        let client = cfg.build_reqwest_client();
        assert!(
            client.is_ok(),
            "Client should successfully build with custom root CA certificate file path"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_client_mtls_identity_builds_client() {
        let mut ca_params = rcgen::CertificateParams::new(vec!["Test CA".into()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_issuer = rcgen::Issuer::new(ca_params, ca_key);

        let client_params = rcgen::CertificateParams::new(vec!["client-identity".into()]).unwrap();
        let client_key = rcgen::KeyPair::generate().unwrap();
        let client_cert = client_params.signed_by(&client_key, &ca_issuer).unwrap();

        let cfg = TlsConfig {
            client_cert_pem: Some(client_cert.pem()),
            client_key_pem: Some(client_key.serialize_pem()),
            ..Default::default()
        };
        let client = cfg.build_reqwest_client();
        assert!(
            client.is_ok(),
            "Client should successfully build with client mTLS certificate and key PEM"
        );
    }
}
