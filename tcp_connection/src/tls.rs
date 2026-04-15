//! Shared rustls helpers for TLS client connectors.

use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use std::sync::Arc;
use tokio_rustls::TlsConnector;

/// Cached `webpki-roots` root certificate store. Cloned into each new config —
/// loading the ~130 trust anchors on every TLS connection is wasteful.
fn cached_root_store() -> rustls::RootCertStore {
    use std::sync::OnceLock;
    static ROOT_STORE: OnceLock<rustls::RootCertStore> = OnceLock::new();
    ROOT_STORE
        .get_or_init(|| {
            let mut store = rustls::RootCertStore::empty();
            store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            store
        })
        .clone()
}

/// Build a rustls `ClientConfig` with webpki roots.
///
/// `alpn_protocols` may be empty (no ALPN advertised — server falls back to HTTP/1.1
/// for HTTP servers). Pass `&[b"h2", b"http/1.1"]` for a browser-like ALPN profile,
/// or just `&[b"http/1.1"]` when the caller needs HTTP/1.1 semantics.
///
/// When `insecure` is true, certificate verification is disabled (tests only).
pub fn get_tls_config(insecure: bool, alpn_protocols: &[&[u8]]) -> Arc<ClientConfig> {
    let mut tls_config = ClientConfig::builder()
        .with_root_certificates(cached_root_store())
        .with_no_client_auth();

    tls_config.alpn_protocols = alpn_protocols.iter().map(|p| p.to_vec()).collect();

    if insecure {
        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerifier));
    }

    Arc::new(tls_config)
}

/// Default `TlsConnector`: webpki roots, **no ALPN**. Appropriate for HTTP/1.1
/// clients (HTTPS proxy CONNECT, simple HTTP probes) and inner TLS layered on
/// top of a tunnel, where you want the server to speak HTTP/1.1.
pub fn get_tls_connector(insecure: bool) -> TlsConnector {
    TlsConnector::from(get_tls_config(insecure, &[]))
}

/// Certificate verifier that accepts any certificate. Only for tests / insecure mode.
#[derive(Debug)]
pub struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
