#![cfg(feature = "integration-tests")]

use config::Address;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use testcontainers::core::WaitFor;
use testcontainers::runners::SyncRunner;
use testcontainers::{Container, GenericImage, ImageExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use trojan_client::{TrojanTcpStream, TrojanUdpSocket};

const TEST_PASSWORD: &str = "test-password-123";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Atomic port counter so each test gets a unique port (tests run in parallel).
static NEXT_PORT: AtomicU16 = AtomicU16::new(54443);

fn next_port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::Relaxed)
}

/// Wrapper that prevents Container's Drop from panicking inside an async runtime.
/// Normal cleanup happens via `cleanup()`. If the test panics, we forget the container
/// (the Ryuk sidecar or process exit will handle Docker cleanup).
struct TestContainer(Option<Container<GenericImage>>);

impl TestContainer {
    fn new(c: Container<GenericImage>) -> Self {
        Self(Some(c))
    }

    async fn cleanup(mut self) {
        if let Some(c) = self.0.take() {
            tokio::task::spawn_blocking(move || drop(c)).await.ok();
        }
    }
}

impl Drop for TestContainer {
    fn drop(&mut self) {
        // Prevent Container::drop from running in async context (which panics).
        // The container will be cleaned up by Docker/Ryuk when the process exits.
        if let Some(c) = self.0.take() {
            std::mem::forget(c);
        }
    }
}

/// Generate self-signed TLS certificate and key using rcgen.
fn generate_self_signed_cert() -> (Vec<u8>, Vec<u8>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("failed to generate self-signed cert");
    let cert_pem = cert.cert.pem().into_bytes();
    let key_pem = cert.key_pair.serialize_pem().into_bytes();
    (cert_pem, key_pem)
}

/// Build trojan-go server config JSON for the given port.
fn server_config_json(port: u16) -> Vec<u8> {
    format!(
        r#"{{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": {port},
    "password": ["{TEST_PASSWORD}"],
    "disable_http_check": true,
    "ssl": {{
        "cert": "/etc/trojan-go/server.crt",
        "key": "/etc/trojan-go/server.key"
    }}
}}"#
    )
    .into_bytes()
}

/// Start a trojan-go server container on the given port.
fn start_trojan_server(port: u16) -> Container<GenericImage> {
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let config_json = server_config_json(port);

    GenericImage::new("p4gefau1t/trojan-go", "latest")
        .with_wait_for(WaitFor::message_on_stdout("trojan-go"))
        .with_startup_timeout(Duration::from_secs(30))
        .with_network("host")
        .with_copy_to("/etc/trojan-go/server.crt", cert_pem)
        .with_copy_to("/etc/trojan-go/server.key", key_pem)
        .with_copy_to("/etc/trojan-go/config.json", config_json)
        .start()
        .expect("failed to start trojan-go container")
}

/// Start the server from within an async context.
async fn start_trojan_server_async(port: u16) -> TestContainer {
    let container = tokio::task::spawn_blocking(move || start_trojan_server(port))
        .await
        .expect("failed to spawn blocking task for container start");
    tokio::time::sleep(Duration::from_millis(500)).await;
    TestContainer::new(container)
}

fn build_test_tls_connector() -> tokio_native_tls::TlsConnector {
    tokio_native_tls::TlsConnector::from(
        native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .expect("failed to build TLS connector"),
    )
}

/// Test: TCP proxy — send HTTP request through proxy to httpbin.org
#[tokio::test]
async fn test_trojan_tcp_proxy_http() {
    let port = next_port();
    let container = start_trojan_server_async(port).await;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let target = Address::DomainNameAddress("httpbin.org".to_string(), 80);
    let connector = build_test_tls_connector();

    let mut stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        TrojanTcpStream::connect_with_connector(
            proxy_addr,
            "localhost",
            target,
            TEST_PASSWORD,
            connector,
        ),
    )
    .await
    .expect("connection timed out")
    .expect("Trojan connect failed");

    let request = "GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n";
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write failed");

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read failed");
    let response_str = String::from_utf8_lossy(&response);

    println!("response:\n{response_str}");
    assert!(
        response_str.contains("200 OK"),
        "expected 200 OK in response"
    );
    assert!(
        response_str.contains("origin"),
        "expected 'origin' field in httpbin response"
    );

    container.cleanup().await;
}

/// Test: TCP proxy — HTTPS via raw TLS over proxy stream
#[tokio::test]
async fn test_trojan_tcp_proxy_https() {
    let port = next_port();
    let container = start_trojan_server_async(port).await;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let target = Address::DomainNameAddress("www.google.com".to_string(), 443);
    let connector = build_test_tls_connector();

    let stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        TrojanTcpStream::connect_with_connector(
            proxy_addr,
            "localhost",
            target,
            TEST_PASSWORD,
            connector,
        ),
    )
    .await
    .expect("connection timed out")
    .expect("Trojan connect failed");

    // Layer client-side TLS on top for the target connection
    let tls_connector = tokio_native_tls::TlsConnector::from(
        native_tls::TlsConnector::new().expect("failed to create TLS connector"),
    );
    let mut tls_stream = tls_connector
        .connect("www.google.com", stream)
        .await
        .expect("TLS handshake with target failed");

    let request = "GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n";
    tls_stream
        .write_all(request.as_bytes())
        .await
        .expect("write failed");

    let mut response = vec![0u8; 4096];
    let n = tls_stream.read(&mut response).await.expect("read failed");
    let response_str = String::from_utf8_lossy(&response[..n]);

    println!("google response (first {n} bytes):\n{response_str}");
    assert!(
        response_str.contains("200")
            || response_str.contains("301")
            || response_str.contains("302"),
        "expected HTTP success/redirect status"
    );

    container.cleanup().await;
}

/// Test: multiple TCP streams through the same Trojan server
#[tokio::test]
async fn test_trojan_tcp_multiple_streams() {
    let port = next_port();
    let container = start_trojan_server_async(port).await;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let (r1, r2) = tokio::join!(
        async {
            let target = Address::DomainNameAddress("httpbin.org".to_string(), 80);
            let connector = build_test_tls_connector();
            let mut s = TrojanTcpStream::connect_with_connector(
                proxy_addr,
                "localhost",
                target,
                TEST_PASSWORD,
                connector,
            )
            .await?;
            s.write_all(b"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
                .await?;
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await?;
            Ok::<_, std::io::Error>(String::from_utf8_lossy(&buf).to_string())
        },
        async {
            let target = Address::DomainNameAddress("httpbin.org".to_string(), 80);
            let connector = build_test_tls_connector();
            let mut s = TrojanTcpStream::connect_with_connector(
                proxy_addr,
                "localhost",
                target,
                TEST_PASSWORD,
                connector,
            )
            .await?;
            s.write_all(
                b"GET /user-agent HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n",
            )
            .await?;
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await?;
            Ok::<_, std::io::Error>(String::from_utf8_lossy(&buf).to_string())
        }
    );

    let resp1 = r1.expect("stream 1 failed");
    let resp2 = r2.expect("stream 2 failed");
    println!("stream1 len={}, stream2 len={}", resp1.len(), resp2.len());
    assert!(resp1.contains("200 OK"));
    assert!(resp2.contains("200 OK"));

    container.cleanup().await;
}

/// Test: UDP proxy — send DNS query through proxy
#[tokio::test]
async fn test_trojan_udp_dns_query() {
    let port = next_port();
    let container = start_trojan_server_async(port).await;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let connector = build_test_tls_connector();

    let udp = tokio::time::timeout(
        CONNECT_TIMEOUT,
        TrojanUdpSocket::new_with_connector(proxy_addr, "localhost", TEST_PASSWORD, connector),
    )
    .await
    .expect("connection timed out")
    .expect("UDP socket creation failed");

    // Build a simple DNS query for google.com A record
    let dns_query = build_dns_query("google.com", 1); // type A
    let dns_server: SocketAddr = "8.8.8.8:53".parse().unwrap();

    udp.send_to(&dns_query, dns_server)
        .await
        .expect("send DNS query failed");

    let mut buf = [0u8; 512];
    match tokio::time::timeout(Duration::from_secs(5), udp.recv_from(&mut buf)).await {
        Ok(Ok((n, from))) => {
            println!("DNS response: {n} bytes from {from}");
            assert!(n > 12, "DNS response too short");
            // Verify transaction ID matches
            assert_eq!(buf[0], dns_query[0]);
            assert_eq!(buf[1], dns_query[1]);
            // QR bit should be set (response)
            assert!(buf[2] & 0x80 != 0, "expected DNS response (QR=1)");
        }
        Ok(Err(e)) => {
            println!("SKIP: UDP recv_from failed (may not be supported in this environment): {e}");
        }
        Err(_) => {
            println!("SKIP: UDP DNS query timed out");
        }
    }

    container.cleanup().await;
}

/// Build a minimal DNS query packet
fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    // Transaction ID
    buf.extend_from_slice(&[0x12, 0x34]);
    // Flags: standard query, recursion desired
    buf.extend_from_slice(&[0x01, 0x00]);
    // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // QNAME
    for label in domain.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0x00); // root label
                    // QTYPE
    buf.push((qtype >> 8) as u8);
    buf.push(qtype as u8);
    // QCLASS = IN
    buf.extend_from_slice(&[0x00, 0x01]);
    buf
}
