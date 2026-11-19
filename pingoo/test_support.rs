#![cfg(test)]

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::{
    DigitallySignedStruct, Error as RustlsError, ServerConfig, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

use crate::tls::{TlsManager, certificate::parse_certificate_and_private_key};

/// RAII temporary directory removed on drop.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(prefix: &str) -> Self {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("pingoo-test-{prefix}-{pid}-{unique}"));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A generated certificate chain: PEM files plus the DER material needed by rustls clients.
pub struct GeneratedCert {
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_der: CertificateDer<'static>,
}

pub fn generate_cert(hostnames: &[&str]) -> GeneratedCert {
    let now = rcgen::date_time_ymd(2026, 1, 1);
    let san_names: Vec<String> = hostnames.iter().map(|hostname| hostname.to_string()).collect();
    let mut params = CertificateParams::new(san_names).expect("certificate params");
    params.not_before = now;
    params.not_after = rcgen::date_time_ymd(2035, 1, 1);
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, hostnames.first().copied().unwrap_or("pingoo-test"));

    let key_pair = KeyPair::generate().expect("key pair");
    let cert = params.self_signed(&key_pair).expect("self signed cert");

    let cert_der = cert.der().clone();

    GeneratedCert {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
        cert_der,
    }
}

/// Writes a certificate/key pair into a TLS folder using pingoo's `<name>.pem` / `<name>.key` layout.
pub fn write_cert(tls_dir: &Path, name: &str, cert: &GeneratedCert) {
    std::fs::write(tls_dir.join(format!("{name}.pem")), cert.cert_pem.as_bytes()).expect("write cert pem");
    std::fs::write(tls_dir.join(format!("{name}.key")), cert.key_pem.as_bytes()).expect("write key pem");
}

/// Builds a TlsManager backed by an isolated on-disk TLS folder (no ACME).
pub async fn tls_manager_from_dir(tls_dir: &Path) -> Arc<TlsManager> {
    let manager = TlsManager::load_from_dir(tls_dir, &crate::config::TlsConfig::default())
        .await
        .expect("load tls manager from temp dir");
    Arc::new(manager)
}

/// Builds a TlsManager from parsed certificates, exercising the production PEM parser without
/// requiring any filesystem layout.
pub fn tls_manager_from_certs(certs: &[&GeneratedCert]) -> Arc<TlsManager> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let exact = dashmap::DashMap::new();
    let mut wildcards = Vec::new();

    for cert in certs {
        let parsed = parse_certificate_and_private_key(cert.cert_pem.as_bytes(), cert.key_pem.as_bytes(), &provider)
            .expect("parse generated certificate");
        let shared = Arc::new(parsed);

        for hostname in &shared.metadata.hostnames {
            exact.insert(hostname.to_ascii_lowercase(), shared.clone());
        }
        if !shared.metadata.wildcard_matchers.is_empty() {
            wildcards.push(shared);
        }
    }

    Arc::new(TlsManager::with_certificates(exact, wildcards))
}

/// Starts a TLS server on an ephemeral localhost port using the given manager/server config.
/// Returns the bound port and a handle that stops the accept loop when dropped.
pub async fn spawn_tls_server(
    tls_manager: Arc<TlsManager>,
    alpn_protocols: Vec<Vec<u8>>,
) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind tcp listener");
    let port = listener.local_addr().expect("local addr").port();
    let server_config: Arc<ServerConfig> = tls_manager.get_tls_server_config(alpn_protocols);

    let handle = tokio::spawn(async move {
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        loop {
            let Ok((tcp_stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                // The outcome (handshake failure vs success) is asserted on the client side.
                if let Ok(mut tls_stream) = acceptor.accept(tcp_stream).await {
                    // echo a single byte so successful handshakes produce readable evidence
                    let mut buffer = [0u8; 1];
                    if tls_stream.read(&mut buffer).await.is_ok() {
                        let _ = tls_stream.write_all(&buffer).await;
                    }
                }
            });
        }
    });

    return (port, handle);
}

/// rustls client config that trusts exactly the provided certificates.
/// Hostname verification still runs, which lets compatibility tests assert the served identity.
pub fn trusting_client_config(trusted_anchors: Vec<CertificateDer<'static>>) -> rustls::ClientConfig {
    let mut root_store = rustls::RootCertStore::empty();
    for anchor in trusted_anchors {
        root_store.add(anchor).expect("add trusted anchor");
    }

    rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

/// Verifier that ignores the certificate chain and hostname so tests can observe whether the
/// *server* fails closed on an unknown SNI, independently of the client's trust decisions.
#[derive(Debug)]
pub struct InsecureAcceptAllVerifier;

impl ServerCertVerifier for InsecureAcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}

/// Client config that performs no certificate validation. For attack tests only.
pub fn insecure_client_config() -> rustls::ClientConfig {
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureAcceptAllVerifier))
        .with_no_client_auth()
}
