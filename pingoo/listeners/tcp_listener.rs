use std::{net::SocketAddr, sync::Arc};

use tokio::{sync::watch, task::JoinSet};
use tracing::debug;

use crate::{
    Error,
    client_addr::{self, TrustedProxies},
    config::ListenerConfig,
    listeners::{GRACEFUL_SHUTDOWN_TIMEOUT, Listener, accept_tcp_connection, bind_tcp_socket},
    services::TcpService,
};

pub struct TcpListener {
    name: String,
    address: SocketAddr,
    socket: Option<tokio::net::TcpListener>,
    service: Arc<dyn TcpService>,
    trusted_proxies: Arc<TrustedProxies>,
}

impl TcpListener {
    pub fn new(config: ListenerConfig, service: Arc<dyn TcpService>) -> Self {
        return TcpListener {
            name: config.name,
            address: config.address,
            socket: None,
            service,
            trusted_proxies: Arc::new(TrustedProxies::new(config.trusted_proxies)),
        };
    }
}

#[async_trait::async_trait]
impl Listener for TcpListener {
    fn bind(&mut self) -> Result<(), Error> {
        let socket = bind_tcp_socket(self.address, &self.name)?;
        self.socket = Some(socket);
        return Ok(());
    }

    async fn listen(self: Box<Self>, mut shutdown_signal: watch::Receiver<()>) {
        let tcp_socket = self
            .socket
            .expect("You need to bind the listener before calling listen()");

        let mut connections: JoinSet<_> = JoinSet::new();

        loop {
            tokio::select! {
                accept_tcp_res = accept_tcp_connection(&tcp_socket, &self.name) => {
                    let (tcp_stream, client_socket_addr) = match accept_tcp_res {
                        Ok(connection) => connection,
                        Err(_) => continue,
                    };

                    let service = self.service.clone();
                    // TCP connections carry no proxy headers, so the shared determination
                    // always resolves to the direct peer address.
                    let client_addr =
                        client_addr::resolve_client_addr(client_socket_addr, &[], &self.trusted_proxies);
                    connections.spawn(service.serve_connection(Box::new(tcp_stream), client_addr.client_addr));
                },
                 _ = shutdown_signal.changed() => {
                    break;
                }
            }
        }

        // TODO: should we use connections.shutdown()?
        tokio::select! {
            _ = connections.join_all() => {
                debug!("listener {} has gracefully shut down", self.name);
            },
            _ = tokio::time::sleep(GRACEFUL_SHUTDOWN_TIMEOUT) => {}
        }
    }
}
