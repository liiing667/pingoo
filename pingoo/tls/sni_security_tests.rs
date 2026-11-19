#![cfg(test)]

use std::sync::Arc;

use rustls::pki_types::ServerName;
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_rustls::TlsConnector;

use crate::{
    security_identity::HostIdentity,
    test_support::{
        GeneratedCert, TempDir, generate_cert, insecure_client_config, spawn_tls_server, tls_manager_from_certs,
        tls_manager_from_dir, trusting_client_config, write_cert,
    },
    tls::TlsManager,
};

async fn tls_handshake_outcome(
    port: u16,
    sni: Option<&str>,
    client_config: Arc<rustls::ClientConfig>,
) -> Result<(), String> {
    let tcp_stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|err| err.to_string())?;
    let connector = TlsConnector::from(client_config);

    let server_name: ServerName<'static> = match sni {
        Some(name) => ServerName::DnsName(
            name.to_string()
                .try_into()
                .map_err(|err: rustls::pki_types::InvalidDnsNameError| err.to_string())?,
        ),
        None => ServerName::IpAddress(rustls::pki_types::IpAddr::from(std::net::Ipv4Addr::LOCALHOST)),
    };

    let mut tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|err| format!("{err:?}"))?;
    tls_stream.write_all(b"x").await.map_err(|err| err.to_string())?;
    return Ok(());
}

/// Attack tests: an unknown or spoofed SNI must never complete a handshake with a certificate
/// selected for another identity. Every variant must fail closed.
#[tokio::test]
async fn unknown_sni_fails_closed_instead_of_using_another_certificate() {
    rustls::crypto::aws_lc_rs::default_provider().install_default().ok();

    let tls_dir = TempDir::new("sni-unknown");
    let api_cert = generate_cert(&["api.example.com"]);
    write_cert(tls_dir.path(), "api", &api_cert);

    let manager = tls_manager_from_dir(tls_dir.path()).await;
    let (port, server_handle) = spawn_tls_server(manager, Vec::new()).await;

    // permissive verification isolates the server's own fail-closed decision
    let client_config = Arc::new(insecure_client_config());

    // attacker presents an SNI for which no certificate exists
    let outcome = tls_handshake_outcome(port, Some("evil.example.org"), client_config).await;
    assert!(outcome.is_err(), "unknown SNI must fail the TLS handshake, got {outcome:?}");

    server_handle.abort();
}

#[tokio::test]
async fn connection_without_sni_fails_closed() {
    rustls::crypto::aws_lc_rs::default_provider().install_default().ok();

    let tls_dir = TempDir::new("sni-missing");
    let api_cert = generate_cert(&["api.example.com"]);
    write_cert(tls_dir.path(), "api", &api_cert);

    let manager = tls_manager_from_dir(tls_dir.path()).await;
    let (port, server_handle) = spawn_tls_server(manager, Vec::new()).await;

    // a permissive client: the server must still reject before any certificate is presented
    let client_config = Arc::new(insecure_client_config());

    let outcome = tls_handshake_outcome(port, None, client_config).await;
    assert!(outcome.is_err(), "missing SNI must fail the TLS handshake, got {outcome:?}");

    server_handle.abort();
}

#[tokio::test]
async fn case_and_trailing_dot_variants_resolve_the_same_identity() {
    rustls::crypto::aws_lc_rs::default_provider().install_default().ok();

    let tls_dir = TempDir::new("sni-normalize");
    let api_cert = generate_cert(&["api.example.com"]);
    write_cert(tls_dir.path(), "api", &api_cert);

    let manager = tls_manager_from_dir(tls_dir.path()).await;

    // the certificate is indexed under the lower-cased identity and matches all equivalent forms
    let identity = HostIdentity::parse("API.Example.COM.").expect("normalized identity");
    assert!(manager.certificate_for_identity(&identity).is_some());

    // an SNI differing by case still selects the same certificate (same identity)
    let upper = HostIdentity::parse("API.EXAMPLE.COM").expect("identity");
    assert!(manager.certificate_for_identity(&upper).is_some());
}

#[tokio::test]
async fn wildcard_certificate_only_matches_a_single_label() {
    rustls::crypto::aws_lc_rs::default_provider().install_default().ok();

    let tls_dir = TempDir::new("sni-wildcard");
    let wildcard_cert = generate_cert(&["*.example.com"]);
    write_cert(tls_dir.path(), "wildcard", &wildcard_cert);

    let manager = tls_manager_from_dir(tls_dir.path()).await;

    let single_label = HostIdentity::parse("api.example.com").expect("identity");
    assert!(manager.certificate_for_identity(&single_label).is_some());

    // the wildcard must not span labels nor match the apex domain
    let nested = HostIdentity::parse("a.b.example.com").expect("identity");
    assert!(manager.certificate_for_identity(&nested).is_none());

    let apex = HostIdentity::parse("example.com").expect("identity");
    assert!(manager.certificate_for_identity(&apex).is_none());
}

/// Attack at the wire level: a nested-label SNI must not be accepted against a single-label
/// wildcard certificate, even when the client skips certificate validation.
#[tokio::test]
async fn nested_label_sni_fails_closed_against_wildcard_certificate() {
    rustls::crypto::aws_lc_rs::default_provider().install_default().ok();

    let tls_dir = TempDir::new("sni-wildcard-attack");
    let wildcard_cert = generate_cert(&["*.example.com"]);
    write_cert(tls_dir.path(), "wildcard", &wildcard_cert);

    let manager = tls_manager_from_dir(tls_dir.path()).await;
    let (port, server_handle) = spawn_tls_server(manager, Vec::new()).await;

    let client_config = Arc::new(insecure_client_config());

    let nested_outcome = tls_handshake_outcome(port, Some("a.b.example.com"), client_config.clone()).await;
    assert!(nested_outcome.is_err(), "nested-label SNI must fail: {nested_outcome:?}");

    let apex_outcome = tls_handshake_outcome(port, Some("example.com"), client_config).await;
    assert!(
        apex_outcome.is_err(),
        "apex SNI against a wildcard cert must fail: {apex_outcome:?}"
    );

    server_handle.abort();
}

/// Compatibility tests: legitimate SNIs keep selecting the correct certificate and complete the
/// full handshake with end-to-end certificate validation.
#[tokio::test]
async fn legitimate_sni_completes_handshake_with_the_matching_certificate() {
    rustls::crypto::aws_lc_rs::default_provider().install_default().ok();

    let tls_dir = TempDir::new("sni-legit");
    let api_cert = generate_cert(&["api.example.com"]);
    let web_cert = generate_cert(&["web.example.com"]);
    write_cert(tls_dir.path(), "api", &api_cert);
    write_cert(tls_dir.path(), "web", &web_cert);

    let manager = tls_manager_from_dir(tls_dir.path()).await;
    let (port, server_handle) = spawn_tls_server(manager, Vec::new()).await;

    // trusting both anchors: full PKIX validation, including the SNI/certificate hostname match
    let client_config = Arc::new(trusting_client_config(vec![
        api_cert.cert_der.clone(),
        web_cert.cert_der.clone(),
    ]));

    let api_outcome = tls_handshake_outcome(port, Some("api.example.com"), client_config.clone()).await;
    assert!(api_outcome.is_ok(), "legitimate api SNI must connect: {api_outcome:?}");

    let web_outcome = tls_handshake_outcome(port, Some("web.example.com"), client_config).await;
    assert!(web_outcome.is_ok(), "legitimate web SNI must connect: {web_outcome:?}");

    server_handle.abort();
}

#[tokio::test]
async fn wildcard_sni_completes_handshake_for_a_matching_single_label() {
    rustls::crypto::aws_lc_rs::default_provider().install_default().ok();

    let tls_dir = TempDir::new("sni-wildcard-ok");
    let wildcard_cert: GeneratedCert = generate_cert(&["*.example.com"]);
    write_cert(tls_dir.path(), "wildcard", &wildcard_cert);

    let manager: Arc<TlsManager> = tls_manager_from_dir(tls_dir.path()).await;
    let (port, server_handle) = spawn_tls_server(manager, Vec::new()).await;

    let client_config = Arc::new(trusting_client_config(vec![wildcard_cert.cert_der.clone()]));
    let outcome = tls_handshake_outcome(port, Some("api.example.com"), client_config).await;
    assert!(outcome.is_ok(), "wildcard-compatible SNI must connect: {outcome:?}");

    server_handle.abort();
}

/// Compatibility: an upgraded deployment that still contains the legacy self-signed
/// `default.pem` (SAN `*`) must keep starting; the legacy file is ignored and cannot be
/// used as a fail-open fallback.
#[tokio::test]
async fn legacy_default_certificate_is_ignored_and_never_served() {
    rustls::crypto::aws_lc_rs::default_provider().install_default().ok();

    let tls_dir = TempDir::new("sni-legacy-default");
    let api_cert = generate_cert(&["api.example.com"]);
    write_cert(tls_dir.path(), "api", &api_cert);

    // simulate the file layout produced by old pingoo releases
    let legacy_default = generate_cert(&["*"]);
    std::fs::write(tls_dir.path().join("default.pem"), legacy_default.cert_pem.as_bytes()).expect("write legacy pem");
    std::fs::write(tls_dir.path().join("default.key"), legacy_default.key_pem.as_bytes()).expect("write legacy key");

    let manager = tls_manager_from_dir(tls_dir.path()).await;

    // the legitimate certificate still loads and serves its identity
    let api_identity = HostIdentity::parse("api.example.com").expect("identity");
    assert!(manager.certificate_for_identity(&api_identity).is_some());

    // the legacy wildcard-all certificate must not make unknown SNIs succeed
    let unknown_identity = HostIdentity::parse("anything.example.net").expect("identity");
    assert!(manager.certificate_for_identity(&unknown_identity).is_none());
}

/// The production PEM parser feeds the same normalized identity store used at handshake time,
/// proving certificate selection and SNI resolution share one identity representation.
#[test]
fn parsed_certificates_share_the_normalized_identity_store() {
    rustls::crypto::aws_lc_rs::default_provider().install_default().ok();

    let api_cert = generate_cert(&["api.example.com"]);
    let wildcard_cert = generate_cert(&["*.example.com"]);
    let manager = tls_manager_from_certs(&[&api_cert, &wildcard_cert]);

    assert!(
        manager
            .certificate_for_identity(&HostIdentity::parse("API.Example.COM").expect("identity"))
            .is_some()
    );
    assert!(
        manager
            .certificate_for_identity(&HostIdentity::parse("shop.example.com").expect("identity"))
            .is_some()
    );
    assert!(
        manager
            .certificate_for_identity(&HostIdentity::parse("a.b.example.com").expect("identity"))
            .is_none()
    );
    assert!(
        manager
            .certificate_for_identity(&HostIdentity::parse("unknown.example.net").expect("identity"))
            .is_none()
    );
}
