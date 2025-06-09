use async_std::io::{Read, Write};
use async_std::task::spawn;
use config::rule::Action;
use futures_util::FutureExt;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_std::net::TcpStream;
use async_std::prelude::{FutureExt as _, *};
use config::Address;
use tracing::instrument;

use crate::server_chooser::{CandidateTcpStream, ServerChooser};

#[derive(Clone)]
pub(crate) struct ProbeConnectivity {
    map: Arc<Mutex<HashMap<Address, Action>>>,
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
        proxy_group_name: String,
    ) -> Action {
        let proxy_connectivity_fut = async {
            let proxy_group_name = proxy_group_name.clone();
            let Ok(CandidateTcpStream { stream: tcp_stream, .. }) = server_chooser.proxy_connect(addr, &proxy_group_name).await else {
                // If the proxy connection fails, we return the direct connection.
                return Action::Direct;
            };

            if addr.port() == 443 {
                if Self::probe_https_connectivity(addr, tcp_stream).await {
                    // If the proxy connection succeeds, we return the proxy connection.
                    return Action::Proxy(proxy_group_name);
                } else {
                    // If the proxy connection fails, we return the direct connection.
                    return Action::Direct;
                }
            } else if addr.port() == 80 {
                if Self::probe_http_connectivity(addr, tcp_stream).await {
                    // If the proxy connection succeeds, we return the proxy connection.
                    return Action::Proxy(proxy_group_name);
                } else {
                    // If the proxy connection fails, we return the direct connection.
                    return Action::Direct;
                }
            } else if addr.port() == 22 {
                if Self::probe_ssh_connectivity(tcp_stream).await {
                    return Action::Proxy(proxy_group_name);
                } else {
                    return Action::Direct;
                }
            }

            // If the port is not 443 or 80, we return the proxy connection.
            Action::Proxy(proxy_group_name)
        };

        let direct_connectivity_fut = async {
            let proxy_group_name = proxy_group_name.clone();
            let Ok(tcp_stream) = TcpStream::connect(sock_addr).await else {
                // If the direct connection fails, we return the proxy connection.
                return Action::Proxy(proxy_group_name);
            };

            if addr.port() == 443 {
                if Self::probe_https_connectivity(addr, tcp_stream).await {
                    // If the direct connection succeeds, we return the direct connection.
                    return Action::Direct;
                } else {
                    // If the direct connection fails, we return the proxy connection.
                    return Action::Proxy(proxy_group_name);
                }
            } else if addr.port() == 80 {
                if Self::probe_http_connectivity(addr, tcp_stream).await {
                    // If the direct connection succeeds, we return the direct connection.
                    return Action::Direct;
                } else {
                    // If the direct connection fails, we return the proxy connection.
                    return Action::Proxy(proxy_group_name);
                }
            } else if addr.port() == 22 {
                if Self::probe_ssh_connectivity(tcp_stream).await {
                    return Action::Direct;
                } else {
                    return Action::Proxy(proxy_group_name);
                }
            }

            // If the port is not 443 or 80, we return the direct connection.
            Action::Direct
        };

        proxy_connectivity_fut
            .inspect(|ret| {
                tracing::info!("Probe proxy connectivity result: {:?}", ret);
            })
            .race(direct_connectivity_fut.inspect(|ret| {
                tracing::info!("Probe direct connectivity result: {:?}", ret);
            }))
            .timeout(timeout)
            .await
            .unwrap_or_else(|_| {
                tracing::info!("Probe connectivity timeout");
                Action::Proxy(proxy_group_name)
            })
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
        let Ok(len) = tls_stream.read(&mut buf).await else {
            return false;
        };
        Self::is_valid_http_head_response(&buf[0..len])
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
        let Ok(len) = tcp_stream.read(&mut buf).await else {
            return false;
        };
        Self::is_valid_http_head_response(&buf[0..len])
    }

    fn is_valid_http_head_response(buf: &[u8]) -> bool {
        let Ok(response) = std::str::from_utf8(buf) else {
            return false;
        };
        response.starts_with("HTTP")
    }

    async fn probe_ssh_connectivity<IO: Read + Write + Unpin>(mut tcp_stream: IO) -> bool {
        let Ok(_) = tcp_stream.write_all(b"SSH-2.0-seeker\r\n").await else {
            return false;
        };
        let mut buf = vec![0u8; 1024];
        let Ok(len) = tcp_stream.read(&mut buf).await else {
            return false;
        };
        Self::is_valid_ssh_response(&buf[0..len])
    }

    fn is_valid_ssh_response(buf: &[u8]) -> bool {
        buf.starts_with(b"SSH")
    }

    pub(crate) async fn probe_connectivity(
        &self,
        sock_addr: SocketAddr,
        addr: &Address,
        proxy_group_name: String,
    ) -> Action {
        let prev_connectivity = self.map.lock().get(addr).cloned();
        let server_chooser = self.server_chooser.clone();
        if let Some(result) = prev_connectivity {
            let map = self.map.clone();
            let timeout = self.timeout;
            let addr = addr.clone();

            spawn(async move {
                let action = Self::force_probe_connectivity(
                    server_chooser,
                    sock_addr,
                    &addr,
                    timeout,
                    proxy_group_name,
                )
                .await;
                map.lock().insert(addr, action);
            });
            result
        } else {
            let action = Self::force_probe_connectivity(
                server_chooser,
                sock_addr,
                addr,
                self.timeout,
                proxy_group_name,
            )
            .await;
            self.map.lock().insert(addr.clone(), action.clone());
            action
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_http_head_response() {
        assert!(ProbeConnectivity::is_valid_http_head_response(
            b"HTTP/1.1 200 OK\r\n"
        ));
    }

    #[test]
    fn test_is_valid_ssh_response() {
        assert!(ProbeConnectivity::is_valid_ssh_response(b"SSH-2.0-seeker"));
    }

    #[async_std::test]
    async fn test_probe_ssh_connectivity() {
        // 205.166.94.16:22 is sdf.org, a free ssh server
        let tcp_stream = TcpStream::connect("205.166.94.16:22").await.unwrap();
        assert!(ProbeConnectivity::probe_ssh_connectivity(tcp_stream).await);
    }
}
