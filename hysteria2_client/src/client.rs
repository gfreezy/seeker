use crate::salamander::SalamanderSocket;
use parking_lot::Mutex;
use quinn::{Connection, Endpoint};
use std::io::{self, Error, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// Configuration for a Hysteria 2 client
#[derive(Clone, Debug)]
pub struct Hy2Config {
    pub server_addr: SocketAddr,
    pub sni: String,
    pub password: String,
    pub obfs_password: Option<String>,
    pub insecure: bool,
    pub recv_window: Option<u64>,
    pub mimic: Option<config::MimicConfig>,
}

/// Shared Hysteria 2 client that manages QUIC connections.
/// One client per server — connections are reused across streams.
pub struct Hy2Client {
    config: Hy2Config,
    connection: Mutex<Option<Connection>>,
    udp_enabled: Mutex<bool>,
    endpoint: Mutex<Option<Endpoint>>,
    h3_driver: Mutex<Option<tokio::task::JoinHandle<()>>>,
    connecting: tokio::sync::Mutex<()>,
    mimic_transport: Mutex<Option<Arc<crate::mimic::MimicSocket>>>,
}

impl Hy2Client {
    pub fn new(config: Hy2Config) -> Arc<Self> {
        Arc::new(Self {
            config,
            connection: Mutex::new(None),
            udp_enabled: Mutex::new(false),
            endpoint: Mutex::new(None),
            h3_driver: Mutex::new(None),
            connecting: tokio::sync::Mutex::new(()),
            mimic_transport: Mutex::new(None),
        })
    }

    /// Get or create a QUIC connection with HTTP/3 authentication
    pub async fn get_connection(self: &Arc<Self>) -> io::Result<Connection> {
        // Only one handshake/transport per client, including concurrent TCP
        // and UDP requests and reconnects after a failed connection.
        let _connecting = self.connecting.lock().await;
        // Check if we have an existing valid connection
        {
            let conn = self.connection.lock();
            if let Some(ref c) = *conn {
                if c.close_reason().is_none() {
                    return Ok(c.clone());
                }
                debug!("existing connection closed, reconnecting");
            }
        }

        // Establish new connection
        let conn = match Box::pin(self.connect()).await {
            Ok(conn) => conn,
            Err(error) => {
                self.shutdown().await;
                return Err(error);
            }
        };

        // Authenticate via HTTP/3
        if let Err(error) = self.authenticate(&conn).await {
            self.shutdown().await;
            return Err(error);
        }

        // Store the connection
        {
            let mut guard = self.connection.lock();
            *guard = Some(conn.clone());
        }

        Ok(conn)
    }

    /// Check if UDP is enabled (set after authentication)
    pub fn udp_enabled(&self) -> bool {
        *self.udp_enabled.lock()
    }

    /// Stop the transport and release its TUN/NAT resources before the async
    /// runtime exits (the global client pool otherwise lives until exit).
    pub async fn shutdown(&self) {
        if let Some(endpoint) = self.endpoint.lock().take() {
            endpoint.close(0u32.into(), b"shutdown");
        }
        self.connection.lock().take();
        *self.udp_enabled.lock() = false;
        let driver = self.h3_driver.lock().take();
        if let Some(driver) = driver {
            driver.abort();
            let _ = driver.await;
        }
        let transport = self.mimic_transport.lock().take();
        if let Some(transport) = transport {
            transport.close().await;
        }
    }

    async fn connect(&self) -> io::Result<Connection> {
        self.shutdown().await;
        let tls_config = tcp_connection::tls::get_tls_config(self.config.insecure, &[b"h3"]);

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(std::time::Duration::from_secs(300))
                .map_err(|e| Error::new(ErrorKind::InvalidInput, e.to_string()))?,
        ));
        transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(15)));

        let mimic_socket = if let Some(config) = self.config.mimic.as_ref().filter(|c| c.enabled) {
            let socket = crate::mimic::MimicSocket::connect(
                config.clone(),
                self.config.server_addr,
                self.config.obfs_password.as_deref(),
            )
            .await?;
            let mut mtu = quinn::MtuDiscoveryConfig::default();
            mtu.upper_bound(socket.max_payload() as u16);
            transport_config.mtu_discovery_config(Some(mtu));
            Some(Arc::new(socket))
        } else {
            None
        };

        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
                .map_err(|e| Error::new(ErrorKind::InvalidData, e))?,
        ));
        client_config.transport_config(Arc::new(transport_config));

        let endpoint = if let Some(socket) = mimic_socket {
            let runtime =
                quinn::default_runtime().ok_or_else(|| Error::other("no async runtime found"))?;
            *self.mimic_transport.lock() = Some(socket.clone());
            let mut endpoint =
                Endpoint::new_with_abstract_socket(Default::default(), None, socket, runtime)?;
            endpoint.set_default_client_config(client_config);
            endpoint
        } else if let Some(obfs_password) = &self.config.obfs_password {
            // Use Salamander obfuscated socket
            let std_socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(Error::other)?;

            let salamander = SalamanderSocket::new(std_socket, obfs_password)?;
            let runtime =
                quinn::default_runtime().ok_or_else(|| Error::other("no async runtime found"))?;
            let mut endpoint = Endpoint::new_with_abstract_socket(
                Default::default(),
                None,
                Arc::new(salamander),
                runtime,
            )
            .map_err(Error::other)?;
            endpoint.set_default_client_config(client_config);
            endpoint
        } else {
            let mut endpoint =
                Endpoint::client("0.0.0.0:0".parse().unwrap()).map_err(Error::other)?;
            endpoint.set_default_client_config(client_config);
            endpoint
        };

        // Store endpoint for later cleanup
        {
            let mut ep = self.endpoint.lock();
            *ep = Some(endpoint.clone());
        }

        info!(
            server = %self.config.server_addr,
            sni = %self.config.sni,
            "connecting to Hysteria 2 server"
        );

        let conn = endpoint
            .connect(self.config.server_addr, &self.config.sni)
            .map_err(|e| {
                error!("QUIC connect error: {e}");
                Error::new(ErrorKind::ConnectionRefused, e.to_string())
            })?
            .await
            .map_err(|e| {
                error!("QUIC connection error: {e}");
                Error::new(ErrorKind::ConnectionRefused, e.to_string())
            })?;

        info!("QUIC connection established");
        Ok(conn)
    }

    async fn authenticate(&self, conn: &Connection) -> io::Result<()> {
        let quinn_conn = h3_quinn::Connection::new(conn.clone());
        let (mut driver, mut send_request) = h3::client::new(quinn_conn)
            .await
            .map_err(|e| Error::new(ErrorKind::ConnectionRefused, e.to_string()))?;

        // Keep the HTTP/3 critical streams open for the lifetime of Hy2's
        // shared QUIC connection. Dropping the last request sender also tells
        // the driver to close QUIC, so retain one sender inside the task.
        let keepalive = send_request.clone();
        let driver_handle = tokio::spawn(async move {
            let _keepalive = keepalive;
            let e = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
            warn!("h3 driver closed: {e}");
        });
        *self.h3_driver.lock() = Some(driver_handle);

        let mut headers = http::Request::builder()
            .method("POST")
            .uri("https://hysteria/auth")
            .header("Hysteria-Auth", &self.config.password);

        if let Some(rx) = self.config.recv_window {
            headers = headers.header("Hysteria-CC-RX", rx.to_string());
        }

        let request = headers
            .body(())
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

        debug!("sending auth request");
        let mut stream = send_request
            .send_request(request)
            .await
            .map_err(|e| Error::new(ErrorKind::ConnectionRefused, e.to_string()))?;

        stream
            .finish()
            .await
            .map_err(|e| Error::new(ErrorKind::ConnectionRefused, e.to_string()))?;

        let response = stream
            .recv_response()
            .await
            .map_err(|e| Error::new(ErrorKind::ConnectionRefused, e.to_string()))?;

        let status = response.status().as_u16();
        if status != 233 {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                format!("auth failed with status {status}"),
            ));
        }

        // Check if UDP is enabled
        let udp_enabled = response
            .headers()
            .get("Hysteria-UDP")
            .and_then(|v| v.to_str().ok())
            .map(|v| v == "true")
            .unwrap_or(false);

        {
            let mut udp = self.udp_enabled.lock();
            *udp = udp_enabled;
        }

        info!(udp_enabled, "Hysteria 2 authentication successful");

        Ok(())
    }
}

impl Drop for Hy2Client {
    fn drop(&mut self) {
        if let Some(driver) = self.h3_driver.get_mut().take() {
            driver.abort();
        }
    }
}
