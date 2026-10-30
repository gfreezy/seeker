#![cfg(feature = "integration-tests")]

use hysteria2_client::{Hy2Client, Hy2Config};
use std::{sync::Arc, time::Duration};

/// A strict HTTP/3 peer must keep accepting control streams after Hy2 auth.
/// Aborting the H3 client driver used to close those critical streams and
/// cause a remote H3_CLOSED_CRITICAL_STREAM (0x104) on the shared QUIC session.
#[tokio::test]
async fn authentication_keeps_http3_critical_streams_alive() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key.into())
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let listener = endpoint.clone();
    let server = tokio::spawn(async move {
        let connection = listener.accept().await.unwrap().await.unwrap();
        let mut h3 =
            h3::server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(connection))
                .await
                .unwrap();
        let (request, mut stream) = h3
            .accept()
            .await
            .unwrap()
            .unwrap()
            .resolve_request()
            .await
            .unwrap();
        assert_eq!(request.uri().path(), "/auth");
        stream
            .send_response(
                http::Response::builder()
                    .status(233)
                    .header("Hysteria-UDP", "true")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        stream.finish().await.unwrap();
        // Continue enforcing HTTP/3's critical stream lifetime until shutdown.
        let _ = h3.accept().await;
    });
    let client = Hy2Client::new(Hy2Config {
        server_addr: endpoint.local_addr().unwrap(),
        sni: "localhost".to_owned(),
        password: "test-only".to_owned(),
        obfs_password: None,
        insecure: true,
        recv_window: None,
        mimic: None,
    });
    let connection = tokio::time::timeout(Duration::from_secs(3), client.get_connection())
        .await
        .unwrap()
        .unwrap();
    let closed = tokio::time::timeout(Duration::from_millis(200), connection.closed()).await;
    client.shutdown().await;
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
    assert!(
        closed.is_err(),
        "QUIC closed after successful auth: {closed:?}"
    );
}
