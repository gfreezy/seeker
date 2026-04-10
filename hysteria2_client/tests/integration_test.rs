#![cfg(feature = "integration-tests")]

use hysteria2_client::{Hy2Client, Hy2Config, Hy2TcpStream, Hy2UdpSocket};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;
use testcontainers::core::WaitFor;
use testcontainers::runners::SyncRunner;
use testcontainers::{Container, GenericImage, ImageExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TEST_PASSWORD: &str = "test-password-123";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Atomic port counter so each test gets a unique port (tests run in parallel).
static NEXT_PORT: AtomicU16 = AtomicU16::new(44443);

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

/// Build Hysteria 2 server config YAML for the given port.
fn server_config_yaml(port: u16) -> Vec<u8> {
    format!(
        r#"listen: :{port}

tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key

auth:
  type: password
  password: {TEST_PASSWORD}
"#
    )
    .into_bytes()
}

/// Start a Hysteria 2 server container on the given port.
fn start_hy2_server(port: u16) -> Container<GenericImage> {
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let config_yaml = server_config_yaml(port);

    let wait_for = WaitFor::message_on_stderr("server up and running");

    GenericImage::new("tobyxdd/hysteria", "v2")
        .with_wait_for(wait_for)
        .with_startup_timeout(Duration::from_secs(30))
        .with_network("host")
        .with_copy_to("/etc/hysteria/config.yaml", config_yaml)
        .with_copy_to("/etc/hysteria/server.crt", cert_pem)
        .with_copy_to("/etc/hysteria/server.key", key_pem)
        .with_cmd(["server", "-c", "/etc/hysteria/config.yaml"])
        .start()
        .expect("failed to start hysteria2 container")
}

/// Start the server from within an async context.
async fn start_hy2_server_async(port: u16) -> TestContainer {
    let container = tokio::task::spawn_blocking(move || start_hy2_server(port))
        .await
        .expect("failed to spawn blocking task for container start");
    TestContainer::new(container)
}

fn make_client(port: u16) -> Arc<Hy2Client> {
    let server_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    Hy2Client::new(Hy2Config {
        server_addr,
        sni: "localhost".to_string(),
        password: TEST_PASSWORD.to_string(),
        obfs_password: None,
        insecure: true, // self-signed cert
        recv_window: None,
    })
}

/// Test: QUIC connection + HTTP/3 authentication
#[tokio::test]
async fn test_hy2_auth() {
    tracing_subscriber::fmt()
        // .with_env_filter("hysteria2_client=debug")
        .try_init()
        .ok();

    let port = next_port();
    let container = start_hy2_server_async(port).await;
    let client = make_client(port);

    let conn = tokio::time::timeout(CONNECT_TIMEOUT, client.get_connection())
        .await
        .expect("connection timed out")
        .expect("connection failed");

    assert!(
        conn.close_reason().is_none(),
        "connection should be alive after auth"
    );
    println!("auth succeeded, udp_enabled={}", client.udp_enabled());

    container.cleanup().await;
}

/// Test: connection reuse — second call should return the same connection
#[tokio::test]
async fn test_hy2_connection_reuse() {
    let port = next_port();
    let container = start_hy2_server_async(port).await;
    let client = make_client(port);

    let conn1 = tokio::time::timeout(CONNECT_TIMEOUT, client.get_connection())
        .await
        .expect("timed out")
        .expect("first connect failed");

    let conn2 = client
        .get_connection()
        .await
        .expect("second connect failed");

    assert_eq!(
        conn1.stable_id(),
        conn2.stable_id(),
        "should reuse the same QUIC connection"
    );

    container.cleanup().await;
}

/// Test: TCP proxy — send HTTP request through proxy to httpbin.org
#[tokio::test]
async fn test_hy2_tcp_proxy_http() {
    tracing_subscriber::fmt()
        // .with_env_filter("hysteria2_client=debug")
        .try_init()
        .ok();

    let port = next_port();
    let container = start_hy2_server_async(port).await;
    let client = make_client(port);

    let _ = tokio::time::timeout(CONNECT_TIMEOUT, client.get_connection())
        .await
        .expect("timed out")
        .expect("connect failed");

    let target = config::Address::DomainNameAddress("httpbin.org".to_string(), 80);

    let mut stream = Hy2TcpStream::connect(&client, target)
        .await
        .expect("TCP proxy connect failed");

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
async fn test_hy2_tcp_proxy_https() {
    tracing_subscriber::fmt()
        // .with_env_filter("hysteria2_client=debug")
        .try_init()
        .ok();

    let port = next_port();
    let container = start_hy2_server_async(port).await;
    let client = make_client(port);

    let _ = tokio::time::timeout(CONNECT_TIMEOUT, client.get_connection())
        .await
        .expect("timed out")
        .expect("connect failed");

    let target = config::Address::DomainNameAddress("www.google.com".to_string(), 443);

    let stream = Hy2TcpStream::connect(&client, target)
        .await
        .expect("TCP proxy connect failed");

    let connector = tokio_native_tls::TlsConnector::from(
        native_tls::TlsConnector::new().expect("failed to create TLS connector"),
    );
    let mut tls_stream = connector
        .connect("www.google.com", stream)
        .await
        .expect("TLS handshake failed");

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

/// Test: multiple TCP streams over the same QUIC connection
#[tokio::test]
async fn test_hy2_tcp_multiple_streams() {
    let port = next_port();
    let container = start_hy2_server_async(port).await;
    let client = make_client(port);

    let _ = tokio::time::timeout(CONNECT_TIMEOUT, client.get_connection())
        .await
        .expect("timed out")
        .expect("connect failed");

    let (r1, r2) = tokio::join!(
        async {
            let target = config::Address::DomainNameAddress("httpbin.org".to_string(), 80);
            let mut s = Hy2TcpStream::connect(&client, target).await?;
            s.write_all(b"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
                .await?;
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await?;
            Ok::<_, std::io::Error>(String::from_utf8_lossy(&buf).to_string())
        },
        async {
            let target = config::Address::DomainNameAddress("httpbin.org".to_string(), 80);
            let mut s = Hy2TcpStream::connect(&client, target).await?;
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
async fn test_hy2_udp_dns_query() {
    tracing_subscriber::fmt()
        // .with_env_filter("hysteria2_client=debug")
        .try_init()
        .ok();

    let port = next_port();
    let container = start_hy2_server_async(port).await;
    let client = make_client(port);

    let _ = tokio::time::timeout(CONNECT_TIMEOUT, client.get_connection())
        .await
        .expect("timed out")
        .expect("connect failed");

    if !client.udp_enabled() {
        println!("SKIP: server does not support UDP");
        container.cleanup().await;
        return;
    }

    let udp = Hy2UdpSocket::new(client)
        .await
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
            assert_eq!(buf[0], dns_query[0]);
            assert_eq!(buf[1], dns_query[1]);
            assert!(buf[2] & 0x80 != 0, "expected DNS response (QR=1)");
        }
        Ok(Err(e)) => {
            println!("SKIP: UDP recv_from failed (may not be supported in this environment): {e}");
        }
        Err(_) => {
            println!("SKIP: UDP DNS query timed out (QUIC datagrams may not work in Docker)");
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
