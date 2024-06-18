use async_std::task::spawn;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_std::net::TcpStream;
use async_std::prelude::*;
use config::Address;
use tracing::instrument;

#[derive(Clone)]
pub(crate) struct ProbeConnectivity {
    map: Arc<Mutex<HashMap<Address, bool>>>,
    timeout: Duration,
}

impl ProbeConnectivity {
    pub(crate) fn new(timeout: Duration) -> Self {
        ProbeConnectivity {
            map: Arc::new(Mutex::new(HashMap::new())),
            timeout,
        }
    }

    #[instrument(skip(sock_addr, timeout))]
    pub(crate) async fn force_probe_connectivity(
        sock_addr: SocketAddr,
        addr: &Address,
        timeout: Duration,
    ) -> bool {
        let ret = async {
            let Ok(tcp_stream) = TcpStream::connect(sock_addr).await else {
                return false;
            };

            if addr.port() == 443 {
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
                if tls_stream.read(&mut buf).await.is_err() {
                    return false;
                }
                return true;
            }

            // If the port is not 443, we assume it is a direct connection.
            true
        }
        .timeout(timeout)
        .await;

        ret.unwrap_or(false)
    }

    pub(crate) async fn probe_connectivity(&self, sock_addr: SocketAddr, addr: &Address) -> bool {
        let prev_connectivity = self.map.lock().get(addr).copied();
        if let Some(result) = prev_connectivity {
            let map = self.map.clone();
            let timeout = self.timeout;
            let addr = addr.clone();
            spawn(async move {
                let is_direct = Self::force_probe_connectivity(sock_addr, &addr, timeout).await;
                map.lock().insert(addr, is_direct);
            });
            result
        } else {
            let is_direct = Self::force_probe_connectivity(sock_addr, addr, self.timeout).await;
            self.map.lock().insert(addr.clone(), is_direct);
            is_direct
        }
    }
}
