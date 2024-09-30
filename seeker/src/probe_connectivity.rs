use async_std::io::{Read, Write};
use async_std::task::spawn;
use config::rule::Action;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_std::net::TcpStream;
use async_std::prelude::*;
use config::Address;
use tracing::instrument;

use crate::server_chooser::ServerChooser;

#[derive(Clone)]
pub(crate) struct ProbeConnectivity {
    map: Arc<Mutex<HashMap<Address, bool>>>,
    server_chooser: ServerChooser,
    timeout: Duration,
}

impl ProbeConnectivity {
    pub(crate) fn new(server_chooser: ServerChooser, timeout: Duration) -> Self {
        ProbeConnectivity {
            server_chooser,
            map: Arc::new(Mutex::new(HashMap::new())),
            timeout,
        }
    }

    #[instrument(skip(sock_addr, timeout, server_chooser))]
    pub(crate) async fn force_probe_connectivity(
        server_chooser: ServerChooser,
        sock_addr: SocketAddr,
        addr: &Address,
        timeout: Duration,
    ) -> bool {
        let proxy_connectivity_fut = async {
            let Ok(tcp_stream) = server_chooser.proxy_connect(addr).await else {
                // If the proxy connection fails, we return the direct connection.
                return Action::Direct;
            };

            if addr.port() == 443 {
                if Self::probe_https_connectivity(addr, tcp_stream).await {
                    // If the proxy connection succeeds, we return the proxy connection.
                    return Action::Proxy;
                } else {
                    // If the proxy connection fails, we return the direct connection.
                    return Action::Direct;
                }
            } else if addr.port() == 80 {
                if Self::probe_http_connectivity(addr, tcp_stream).await {
                    // If the proxy connection succeeds, we return the proxy connection.
                    return Action::Proxy;
                } else {
                    // If the proxy connection fails, we return the direct connection.
                    return Action::Direct;
                }
            }

            // If the port is not 443 or 80, we return the proxy connection.
            Action::Proxy
        };

        let direct_connectivity_fut = async {
            let Ok(tcp_stream) = TcpStream::connect(sock_addr).await else {
                // If the direct connection fails, we return the proxy connection.
                return Action::Proxy;
            };

            if addr.port() == 443 {
                if Self::probe_https_connectivity(addr, tcp_stream).await {
                    // If the direct connection succeeds, we return the direct connection.
                    return Action::Direct;
                } else {
                    // If the direct connection fails, we return the proxy connection.
                    return Action::Proxy;
                }
            } else if addr.port() == 80 {
                if Self::probe_http_connectivity(addr, tcp_stream).await {
                    // If the direct connection succeeds, we return the direct connection.
                    return Action::Direct;
                } else {
                    // If the direct connection fails, we return the proxy connection.
                    return Action::Proxy;
                }
            }

            // If the port is not 443 or 80, we return the direct connection.
            Action::Direct
        };

        let result = proxy_connectivity_fut
            .race(direct_connectivity_fut)
            .timeout(timeout)
            .await
            .unwrap_or(Action::Proxy);
        result == Action::Direct
    }

    async fn probe_https_connectivity<IO: Read + Write + Unpin>(
        addr: &Address,
        tcp_stream: IO,
    ) -> bool {
        let Some(hostname) = addr.hostname() else {
            // If the address is an IP address, we assume it is a direct connection.
            return true;
        };
        let connector = async_tls::TlsConnector::default();
        let encrypted_stream = connector.connect(hostname, tcp_stream).await;
        let Ok(mut tls_stream) = encrypted_stream else {
            return false;
        };
        // Send a HTTP HEAD request to the server to check if the server is alive.
        if tls_stream
            .write_all("HEAD / HTTP/1.0\r\n\r\n".as_bytes())
            .await
            .is_err()
        {
            return false;
        }

        // Read the response from the server.
        let mut buf = vec![0u8; 1024];
        tls_stream.read(&mut buf).await.is_ok()
    }

    async fn probe_http_connectivity<IO: Read + Write + Unpin>(
        addr: &Address,
        mut tcp_stream: IO,
    ) -> bool {
        let Some(_hostname) = addr.hostname() else {
            // If the address is an IP address, we assume it is a direct connection.
            return true;
        };
        // Send a HTTP HEAD request to the server to check if the server is alive.
        if tcp_stream
            .write_all("HEAD / HTTP/1.0\r\n\r\n".as_bytes())
            .await
            .is_err()
        {
            return false;
        }

        // Read the response from the server.
        let mut buf = vec![0u8; 1024];
        tcp_stream.read(&mut buf).await.is_ok()
    }

    pub(crate) async fn probe_connectivity(&self, sock_addr: SocketAddr, addr: &Address) -> bool {
        let prev_connectivity = self.map.lock().get(addr).copied();
        let server_chooser = self.server_chooser.clone();
        if let Some(result) = prev_connectivity {
            let map = self.map.clone();
            let timeout = self.timeout;
            let addr = addr.clone();

            spawn(async move {
                let is_direct =
                    Self::force_probe_connectivity(server_chooser, sock_addr, &addr, timeout).await;
                map.lock().insert(addr, is_direct);
            });
            result
        } else {
            let is_direct =
                Self::force_probe_connectivity(server_chooser, sock_addr, addr, self.timeout).await;
            self.map.lock().insert(addr.clone(), is_direct);
            is_direct
        }
    }
}
