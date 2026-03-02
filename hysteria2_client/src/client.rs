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
}

/// Shared Hysteria 2 client that manages QUIC connections.
/// One client per server — connections are reused across streams.
pub struct Hy2Client {
    config: Hy2Config,
    connection: Mutex<Option<Connection>>,
    udp_enabled: Mutex<bool>,
    endpoint: Mutex<Option<Endpoint>>,
}

impl Hy2Client {
    pub fn new(config: Hy2Config) -> Arc<Self> {
        Arc::new(Self {
            config,
            connection: Mutex::new(None),
            udp_enabled: Mutex::new(false),
            endpoint: Mutex::new(None),
        })
    }

    /// Get or create a QUIC connection with HTTP/3 authentication
    pub async fn get_connection(self: &Arc<Self>) -> io::Result<Connection> {
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
        let conn = self.connect().await?;

        // Authenticate via HTTP/3
        self.authenticate(&conn).await?;

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

    async fn connect(&self) -> io::Result<Connection> {
        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(Self::root_certs())
            .with_no_client_auth();

        tls_config.alpn_protocols = vec![b"h3".to_vec()];

        if self.config.insecure {
            tls_config
                .dangerous()
                .set_certificate_verifier(Arc::new(SkipServerVerification));
        }

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(std::time::Duration::from_secs(300))
                .map_err(|e| Error::new(ErrorKind::InvalidInput, e.to_string()))?,
        ));
        transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(15)));

        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
                .map_err(|e| Error::new(ErrorKind::InvalidData, e))?,
        ));
        client_config.transport_config(Arc::new(transport_config));

        let endpoint = if let Some(obfs_password) = &self.config.obfs_password {
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

        // Drive the HTTP/3 connection in background
        let driver_handle = tokio::spawn(async move {
            let e = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
            warn!("h3 driver closed: {e}");
        });

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

        // Cancel the driver since we don't need HTTP/3 anymore
        driver_handle.abort();

        Ok(())
    }

    fn root_certs() -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().expect("failed to load native certs") {
            roots.add(cert).ok();
        }
        roots
    }
}

/// Skip server certificate verification (for insecure mode)
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}
