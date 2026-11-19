use std::{fmt::Debug, path::Path, sync::Arc};

use dashmap::DashMap;
use rustls::{
    ServerConfig,
    crypto::CryptoProvider,
    server::{ClientHello, ResolvesServerCert},
};
use tokio::fs;
use tracing::{debug, warn};

use crate::{
    Error,
    config::{DEFAULT_TLS_FOLDER, TlsConfig},
    security_identity::HostIdentity,
    tls::{
        acme::{AcmeChallenge, load_or_create_acme_account},
        certificate::{Certificate, parse_certificate_and_private_key},
    },
};

/// The ALPN protocol identifier for the ACME tls-alpn-01 challenge
pub const TLS_ALPN_ACME: &[u8] = b"acme-tls/1";
/// The ALPN protocol identifier for HTTP/2
pub const TLS_ALPN_HTTP2: &[u8] = b"h2";
/// The ALPN protocol identifier for HTTP/1.1
pub const TLS_ALPN_HTTP11: &[u8] = b"http/1.1";

#[derive(Debug)]
pub struct TlsManager {
    /// certificates indexed by their Subject Alternative Names that don't contain a wildcard
    pub(super) certificates: DashMap<String, Arc<Certificate>>,
    /// certificates that have at least 1 Subject Alternative Name containing a wildcard
    pub(super) wildcard_certificates: Vec<Arc<Certificate>>,

    pub(super) acme: Option<Arc<AcmeConfig>>,
}

pub(super) struct AcmeConfig {
    pub account: instant_acme::Account,
    pub domains: Vec<String>,
    pub challenges: DashMap<String, AcmeChallenge>,
}

impl Debug for AcmeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeConfig")
            .field("account", &"[REDACTED]")
            .field("domains", &self.domains)
            .field("challenges", &"[REDACTED]")
            .finish()
    }
}

impl TlsManager {
    pub async fn new(tls_config: &TlsConfig) -> Result<Self, Error> {
        Self::load_from_dir(Path::new(DEFAULT_TLS_FOLDER), tls_config).await
    }

    /// Test-only constructor with an explicit certificate set and no disk/ACME dependency.
    #[cfg(test)]
    pub(crate) fn with_certificates(
        certificates: DashMap<String, Arc<Certificate>>,
        wildcard_certificates: Vec<Arc<Certificate>>,
    ) -> Self {
        TlsManager {
            certificates,
            wildcard_certificates,
            acme: None,
        }
    }

    pub(crate) async fn load_from_dir(tls_dir: &Path, tls_config: &TlsConfig) -> Result<Self, Error> {
        fs::create_dir_all(tls_dir)
            .await
            .map_err(|err| Error::Config(format!("error creating TLS folder ({}): {err}", tls_dir.display())))?;

        let (certificates, wildcard_certificates) = load_certificates(tls_dir).await?;

        let acme = match &tls_config.acme {
            Some(acme_config) => {
                let acme_account =
                    load_or_create_acme_account(&tls_dir.to_string_lossy(), acme_config.directory_url.clone()).await?;
                Some(Arc::new(AcmeConfig {
                    account: acme_account,
                    domains: acme_config.domains.clone(),
                    challenges: DashMap::new(),
                }))
            }
            None => None,
        };

        Ok(Self {
            certificates,
            wildcard_certificates,

            acme,
        })
    }

    /// Resolves the certificate for a normalized hostname identity.
    ///
    /// Exact SAN matches take precedence over wildcard matches. A hostname with no matching
    /// certificate yields `None`: the TLS handshake then fails closed with a fatal alert instead
    /// of presenting an unrelated (e.g. self-signed default) certificate.
    pub(crate) fn certificate_for_identity(
        &self,
        host_identity: &HostIdentity,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        if let Some(certificate) = self.certificates.get(host_identity.as_str()) {
            return Some(certificate.key.clone());
        }

        // Strict RFC 6125 semantics: the wildcard only replaces the left-most, single label.
        // We iterate the SAN wildcard patterns directly instead of relying on loose glob matching.
        let wildcard_certificate = self.wildcard_certificates.iter().find(|certificate| {
            certificate.metadata.wildcard_matchers.iter().any(|matcher| {
                let pattern = core::str::from_utf8(matcher.pattern()).unwrap_or("");
                host_identity.matches_wildcard(pattern)
            })
        })?;

        return Some(wildcard_certificate.key.clone());
    }

    pub fn get_tls_server_config(
        self: &Arc<Self>,
        alpn_protocols: impl IntoIterator<Item = Vec<u8>>,
    ) -> Arc<ServerConfig> {
        // we only support TLS 1.3
        // TLS 1.3 was introduced in 2018 and is supported by virtually all browsers
        // and client libraries: https://caniuse.com/tls1-3
        // Only unmaintained bots don't support TLS 1.3
        let mut tls_server_config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_cert_resolver(self.clone());

        tls_server_config.alpn_protocols = alpn_protocols.into_iter().collect();

        return Arc::new(tls_server_config);
    }
}

impl ResolvesServerCert for TlsManager {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let raw_sni = client_hello.server_name();

        // Fail closed: an absent or unparseable SNI must never be mapped to another identity.
        let Some(raw_sni) = raw_sni else {
            debug!("tls: rejecting connection without an SNI extension");
            return None;
        };

        let host_identity = match HostIdentity::parse(raw_sni) {
            Ok(host_identity) => host_identity,
            Err(err) => {
                debug!("tls: rejecting connection with invalid SNI {raw_sni:?}: {err}");
                return None;
            }
        };

        let Some(certified_key) = self.certificate_for_identity(&host_identity) else {
            debug!("tls: no certificate matches SNI {}; failing closed", host_identity);
            return None;
        };

        return Some(certified_key);
    }
}

async fn load_certificates(
    directory_path: &Path,
) -> Result<(DashMap<String, Arc<Certificate>>, Vec<Arc<Certificate>>), Error> {
    let mut directory = fs::read_dir(directory_path).await.map_err(|err| {
        Error::Config(format!(
            "error reading certificates folder ({}): {err}",
            directory_path.display()
        ))
    })?;

    // list certs
    let mut certificate_paths = Vec::new();
    while let Ok(Some(entry)) = directory.next_entry().await {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .await
            .map_err(|err| Error::Config(format!("error getting file type for {path:?}: {err}")))?;
        if !file_type.is_file() {
            continue;
        }

        let file_extension = path.extension().unwrap_or_default().to_str().unwrap_or_default();
        // we expect that all .pem files are certificates.
        // `default.pem` is the legacy self-signed fallback certificate (SAN `*`) generated by
        // older pingoo versions. Fail-closed identity enforcement removed that fallback, so the
        // file is ignored rather than rejecting the whole certificate store on upgrade.
        let file_name = path.file_name().unwrap_or_default().to_str().unwrap_or_default();
        if file_extension == "pem" && file_name != "default.pem" {
            certificate_paths.push(path);
        }
    }

    let certificates = DashMap::with_capacity(certificate_paths.len());
    let mut wildcard_certificates = Vec::new();
    for cert_file_path in certificate_paths {
        let certificate = Arc::new(load_certificate(&cert_file_path).await?);

        for hostname in &certificate.metadata.hostnames {
            // SANs are normalized to lower case so the certificate index shares the same
            // identity representation as the normalized SNI.
            let hostname = hostname.to_ascii_lowercase();
            if certificates.contains_key(&hostname) {
                warn!("duplicate TLS certificate found for {hostname}");
            }
            certificates.insert(hostname.clone(), certificate.clone());
        }
        if certificate.metadata.wildcard_matchers.len() != 0 {
            wildcard_certificates.push(certificate.clone());
        }
    }

    return Ok((certificates, wildcard_certificates));
}

async fn load_certificate(cert_file_path: &std::path::PathBuf) -> Result<Certificate, Error> {
    let cert_file_content = fs::read(cert_file_path)
        .await
        .map_err(|err| Error::Config(format!("error reading certificate {cert_file_path:?}: {err}")))?;

    let mut private_key_path = cert_file_path.clone();
    private_key_path.set_extension("key");
    let private_key_file_content = fs::read(&private_key_path)
        .await
        .map_err(|err| Error::Config(format!("error reading private key {private_key_path:?}: {err}")))?;

    return parse_certificate_and_private_key(
        &cert_file_content,
        &private_key_file_content,
        CryptoProvider::get_default().unwrap(),
    );
}

// pub async fn write_sensitive_file(path: impl AsRef<Path> + Debug, contents: impl AsRef<[u8]>) -> Result<(), Error> {
//     let mut file = fs::OpenOptions::new()
//         .create(true)
//         .write(true)
//         .mode(0o600)
//         .truncate(true)
//         .open(&path)
//         .map_err(|err| Error::Unspecified(err.to_string()))
//         .await?;

//     file.write_all(contents.as_ref())
//         .await
//         .map_err(|err| Error::Unspecified(format!("error when writing data to file: {err}")))?;

//     file.flush()
//         .await
//         .map_err(|err| Error::Unspecified(format!("error when flushing data to file: {err}")))?;

//     return Ok(());
// }
