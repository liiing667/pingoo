#![cfg(test)]

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper_util::{rt::TokioIo, server::graceful::GracefulShutdown};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::TlsConnector;

use crate::{
    geoip::GeoipDB,
    listeners::http_listener::serve_http_requests,
    security_identity::HostIdentity,
    services::HttpService,
    test_support::{TempDir, generate_cert, tls_manager_from_dir, trusting_client_config, write_cert},
};

/// Test service that records how many requests actually reached a backend and replies 200.
#[derive(Default)]
struct CountingService {
    handled: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl HttpService for CountingService {
    fn match_request(&self, _ctx: &rules::Context) -> bool {
        true
    }

    async fn handle_http_request(&self, _req: Request<Incoming>) -> Response<BoxBody<Bytes, hyper::Error>> {
        self.handled.fetch_add(1, Ordering::SeqCst);
        let body = Full::new(Bytes::from_static(b"ok"))
            .map_err(|never| match never {})
            .boxed();
        Response::builder().status(StatusCode::OK).body(body).expect("response")
    }
}

struct HttpsTestServer {
    port: u16,
    handled: Arc<AtomicUsize>,
    shutdown: tokio::sync::watch::Sender<()>,
    server_task: tokio::task::JoinHandle<()>,
}

impl HttpsTestServer {
    async fn start(tls_dir: &std::path::Path, sni_identity: Option<HostIdentity>, use_tls: bool) -> Self {
        let manager = tls_manager_from_dir(tls_dir).await;
        let tls_config = manager.get_tls_server_config(Vec::new());

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let port = listener.local_addr().expect("addr").port();

        let handled = Arc::new(AtomicUsize::new(0));
        let service = Arc::new(CountingService {
            handled: handled.clone(),
        });
        let services: Arc<Vec<Arc<dyn HttpService>>> = Arc::new(vec![service]);
        let graceful = GracefulShutdown::new();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());

        let server_task = tokio::spawn(async move {
            let mut shutdown_rx = shutdown_rx;
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (tcp_stream, client_addr) = accepted.expect("accept");
                        let services = services.clone();
                        let watcher = graceful.watcher();
                        let sni_identity = sni_identity.clone();
                        let tls_config = tls_config.clone();

                        tokio::spawn(async move {
                            if use_tls {
                                let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
                                let tls_stream = match acceptor.accept(tcp_stream).await {
                                    Ok(tls_stream) => tls_stream,
                                    Err(_) => return,
                                };
                                serve_http_requests(
                                    TokioIo::new(tls_stream),
                                    services,
                                    client_addr,
                                    SocketAddr::from(([127, 0, 0, 1], port)),
                                    Arc::new("test".to_string()),
                                    Arc::new(Vec::new()),
                                    Arc::new(bel::Value::Null),
                                    None::<Arc<GeoipDB>>,
                                    Arc::new(crate::captcha::CaptchaManager::for_tests()),
                                    true,
                                    sni_identity,
                                    watcher,
                                )
                                .await;
                            } else {
                                serve_http_requests(
                                    TokioIo::new(tcp_stream),
                                    services,
                                    client_addr,
                                    SocketAddr::from(([127, 0, 0, 1], port)),
                                    Arc::new("test".to_string()),
                                    Arc::new(Vec::new()),
                                    Arc::new(bel::Value::Null),
                                    None::<Arc<GeoipDB>>,
                                    Arc::new(crate::captcha::CaptchaManager::for_tests()),
                                    false,
                                    sni_identity,
                                    watcher,
                                )
                                .await;
                            }
                        });
                    }
                    _ = shutdown_rx.changed() => break,
                }
            }
        });

        HttpsTestServer {
            port,
            handled,
            shutdown: shutdown_tx,
            server_task,
        }
    }

    fn stop(self) {
        let _ = self.shutdown.send(());
        self.server_task.abort();
    }
}

/// Performs a raw TLS + HTTP/1.1 request with independent control over SNI and the Host header.
async fn http_request(
    port: u16,
    sni: &str,
    host_header: &str,
    trusted: Vec<CertificateDer<'static>>,
) -> Result<u16, String> {
    let client_config = Arc::new(trusting_client_config(trusted));
    let connector = TlsConnector::from(client_config);
    let server_name: ServerName<'static> = ServerName::DnsName(
        sni.to_string()
            .try_into()
            .map_err(|err: rustls::pki_types::InvalidDnsNameError| err.to_string())?,
    );

    let tcp_stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|err| err.to_string())?;
    let mut tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|err| format!("{err:?}"))?;

    let request = format!("GET / HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: test\r\nConnection: close\r\n\r\n");
    tls_stream
        .write_all(request.as_bytes())
        .await
        .map_err(|err| err.to_string())?;

    let mut response = Vec::new();
    tls_stream
        .read_to_end(&mut response)
        .await
        .map_err(|err| err.to_string())?;
    let response_text = String::from_utf8_lossy(&response);
    let status_line = response_text.lines().next().ok_or("empty response")?;
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or("missing status code")?
        .parse::<u16>()
        .map_err(|err| err.to_string())?;
    return Ok(status_code);
}

/// Attack: a valid SNI for one identity combined with a Host header for another identity is a
/// classic domain-fronting attempt. It must fail closed and never reach a backend service.
#[tokio::test]
async fn sni_host_mismatch_fails_closed_and_never_reaches_backend() {
    rustls::crypto::aws_lc_rs::default_provider().install_default().ok();

    let tls_dir = TempDir::new("http-fronting");
    let api_cert = generate_cert(&["api.example.com"]);
    write_cert(tls_dir.path(), "api", &api_cert);

    let sni_identity = HostIdentity::parse("api.example.com").expect("identity");
    let server = HttpsTestServer::start(tls_dir.path(), Some(sni_identity), true).await;

    let status = http_request(
        server.port,
        "api.example.com",
        "evil.example.org",
        vec![api_cert.cert_der.clone()],
    )
    .await
    .expect("tls handshake and http response");

    assert_eq!(status, 421, "domain fronting must produce a 421 Misdirected Request");
    assert_eq!(
        server.handled.load(Ordering::SeqCst),
        0,
        "no backend must handle the spoofed request"
    );

    server.stop();
}

/// Attack: the Host header cannot smuggle a port, userinfo or path to escape the SNI identity.
#[tokio::test]
async fn malformed_host_header_fails_closed_on_tls() {
    rustls::crypto::aws_lc_rs::default_provider().install_default().ok();

    let tls_dir = TempDir::new("http-bad-host");
    let api_cert = generate_cert(&["api.example.com"]);
    write_cert(tls_dir.path(), "api", &api_cert);

    let sni_identity = HostIdentity::parse("api.example.com").expect("identity");
    let server = HttpsTestServer::start(tls_dir.path(), Some(sni_identity), true).await;

    for malformed_host in ["user@api.example.com", "api.example.com/steal", "api.example.com:bad"] {
        let status = http_request(server.port, "api.example.com", malformed_host, vec![api_cert.cert_der.clone()])
            .await
            .expect("response");
        assert_eq!(status, 421, "host {malformed_host:?} must fail closed");
    }
    assert_eq!(server.handled.load(Ordering::SeqCst), 0);

    server.stop();
}

/// Compatibility: when SNI and Host share the same identity (including case and port variants),
/// the request reaches the backend with a 200 response.
#[tokio::test]
async fn matching_sni_and_host_reaches_backend() {
    rustls::crypto::aws_lc_rs::default_provider().install_default().ok();

    let tls_dir = TempDir::new("http-compat");
    let api_cert = generate_cert(&["api.example.com"]);
    write_cert(tls_dir.path(), "api", &api_cert);

    let sni_identity = HostIdentity::parse("api.example.com").expect("identity");
    let server = HttpsTestServer::start(tls_dir.path(), Some(sni_identity), true).await;

    for host_header in ["api.example.com", "API.Example.COM", "api.example.com:8443"] {
        let status = http_request(server.port, "api.example.com", host_header, vec![api_cert.cert_der.clone()])
            .await
            .expect("response");
        assert_eq!(status, 200, "legitimate host {host_header:?} must reach the backend");
    }
    assert_eq!(server.handled.load(Ordering::SeqCst), 3);

    server.stop();
}

/// Compatibility: plain HTTP listeners have no SNI and must keep accepting Host headers with ports.
#[tokio::test]
async fn plain_http_listener_keeps_accepting_host_with_port() {
    rustls::crypto::aws_lc_rs::default_provider().install_default().ok();

    let tls_dir = TempDir::new("http-plain");
    let api_cert = generate_cert(&["api.example.com"]);
    write_cert(tls_dir.path(), "api", &api_cert);

    let server = HttpsTestServer::start(tls_dir.path(), None, false).await;

    let mut tcp_stream = tokio::net::TcpStream::connect(("127.0.0.1", server.port))
        .await
        .expect("connect");
    let request = "GET / HTTP/1.1\r\nHost: api.example.com:8080\r\nUser-Agent: test\r\nConnection: close\r\n\r\n";
    tcp_stream.write_all(request.as_bytes()).await.expect("write");
    let mut response = Vec::new();
    tcp_stream.read_to_end(&mut response).await.expect("read");

    let status_line = String::from_utf8_lossy(&response)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string();
    assert!(
        status_line.contains("200"),
        "plain HTTP must stay compatible, got {status_line}"
    );
    assert_eq!(server.handled.load(Ordering::SeqCst), 1);

    server.stop();
}
