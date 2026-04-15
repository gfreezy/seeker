#![cfg(feature = "integration-tests")]

use config::Address;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use testcontainers::core::WaitFor;
use testcontainers::runners::SyncRunner;
use testcontainers::{Container, GenericImage, ImageExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vmess_client::VMessTcpStream;

const TEST_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Atomic port counter so each test gets a unique port (tests run in parallel).
static NEXT_PORT: AtomicU16 = AtomicU16::new(55443);

fn next_port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::Relaxed)
}

/// Wrapper that prevents Container's Drop from panicking inside an async runtime.
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
        if let Some(c) = self.0.take() {
            std::mem::forget(c);
        }
    }
}

/// Build V2Ray server config JSON for VMess.
fn server_config_json(port: u16) -> Vec<u8> {
    format!(
        r#"{{
    "log": {{ "loglevel": "debug" }},
    "policy": {{
        "levels": {{
            "0": {{
                "uplinkOnly": 10,
                "downlinkOnly": 10
            }}
        }}
    }},
    "inbounds": [{{
        "port": {port},
        "protocol": "vmess",
        "settings": {{
            "clients": [{{
                "id": "{TEST_UUID}",
                "alterId": 0
            }}]
        }}
    }}],
    "outbounds": [{{
        "protocol": "freedom"
    }}]
}}"#
    )
    .into_bytes()
}

/// Start a V2Ray VMess server container on the given port.
fn start_vmess_server(port: u16) -> Container<GenericImage> {
    let config_json = server_config_json(port);

    GenericImage::new("v2fly/v2fly-core", "v4.45.2")
        .with_wait_for(WaitFor::message_on_stdout("started"))
        .with_startup_timeout(Duration::from_secs(30))
        .with_network("host")
        .with_copy_to("/etc/v2ray/config.json", config_json)
        .start()
        .expect("failed to start v2ray container")
}

/// Start the server from within an async context.
async fn start_vmess_server_async(port: u16) -> TestContainer {
    let container = tokio::task::spawn_blocking(move || start_vmess_server(port))
        .await
        .expect("failed to spawn blocking task for container start");
    wait_port_listening(port, Duration::from_secs(30)).await;
    TestContainer::new(container)
}

/// Poll `127.0.0.1:port` until a TCP connection succeeds, or the deadline passes.
/// The container's `WaitFor` signal sometimes fires before the service has actually
/// started listening, causing flaky "Connection refused" in subsequent connects.
async fn wait_port_listening(port: u16, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Test: TCP proxy with AES-128-GCM encryption — HTTP request through VMess
#[tokio::test]
async fn test_vmess_tcp_proxy_http_gcm() {
    let port = next_port();
    let container = start_vmess_server_async(port).await;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let target = Address::DomainNameAddress("www.baidu.com".to_string(), 80);

    let mut stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        VMessTcpStream::connect(proxy_addr, TEST_UUID, target, "aes-128-gcm"),
    )
    .await
    .expect("connection timed out")
    .expect("VMess connect failed");

    let request = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n";
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write failed");
    stream.flush().await.expect("flush failed");

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read failed");
    let response_str = String::from_utf8_lossy(&response);

    println!("response (len={}):\n{response_str}", response.len());
    assert!(
        response_str.contains("200 OK")
            || response_str.contains("301")
            || response_str.contains("302"),
        "expected HTTP success/redirect in response, got {} bytes",
        response.len()
    );
    assert!(!response.is_empty(), "expected non-empty HTTP response");

    container.cleanup().await;
}

/// Test: TCP proxy with AES-128-GCM — HTTPS via raw TLS over VMess proxy stream
#[tokio::test]
async fn test_vmess_tcp_proxy_https_gcm() {
    let port = next_port();
    let container = start_vmess_server_async(port).await;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let target = Address::DomainNameAddress("www.baidu.com".to_string(), 443);

    let stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        VMessTcpStream::connect(proxy_addr, TEST_UUID, target, "aes-128-gcm"),
    )
    .await
    .expect("connection timed out")
    .expect("VMess connect failed");

    // Layer client-side TLS on top for the target connection
    let tls_connector = tcp_connection::tls::get_tls_connector(false);
    let server_name = rustls::pki_types::ServerName::try_from("www.baidu.com".to_string())
        .expect("invalid SNI");
    let mut tls_stream = tls_connector
        .connect(server_name, stream)
        .await
        .expect("TLS handshake with target failed");

    let request = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n";
    tls_stream
        .write_all(request.as_bytes())
        .await
        .expect("write failed");

    let mut response = vec![0u8; 4096];
    let n = tls_stream.read(&mut response).await.expect("read failed");
    let response_str = String::from_utf8_lossy(&response[..n]);

    println!("baidu response (first {n} bytes):\n{response_str}");
    assert!(
        response_str.contains("200")
            || response_str.contains("301")
            || response_str.contains("302"),
        "expected HTTP success/redirect status"
    );

    container.cleanup().await;
}

/// Test: multiple TCP streams with GCM through the same VMess server
#[tokio::test]
async fn test_vmess_tcp_multiple_streams_gcm() {
    let port = next_port();
    let container = start_vmess_server_async(port).await;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let (r1, r2) = tokio::join!(
        async {
            let target = Address::DomainNameAddress("www.baidu.com".to_string(), 80);
            let mut s =
                VMessTcpStream::connect(proxy_addr, TEST_UUID, target, "aes-128-gcm").await?;
            s.write_all(b"GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n")
                .await?;
            s.flush().await?;
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await?;
            Ok::<_, std::io::Error>(String::from_utf8_lossy(&buf).to_string())
        },
        async {
            let target = Address::DomainNameAddress("www.baidu.com".to_string(), 80);
            let mut s =
                VMessTcpStream::connect(proxy_addr, TEST_UUID, target, "aes-128-gcm").await?;
            s.write_all(
                b"GET /s?wd=vmess HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n",
            )
            .await?;
            s.flush().await?;
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await?;
            Ok::<_, std::io::Error>(String::from_utf8_lossy(&buf).to_string())
        }
    );

    let resp1 = r1.expect("stream 1 failed");
    let resp2 = r2.expect("stream 2 failed");
    println!("stream1 len={}, stream2 len={}", resp1.len(), resp2.len());
    assert!(
        resp1.contains("200 OK") || resp1.contains("301") || resp1.contains("302"),
        "stream 1: expected HTTP success/redirect"
    );
    assert!(
        resp2.contains("200 OK") || resp2.contains("301") || resp2.contains("302"),
        "stream 2: expected HTTP success/redirect"
    );

    container.cleanup().await;
}

/// Test: raw TCP bytes read after VMess GCM handshake (debug test)
#[tokio::test]
async fn test_vmess_raw_bytes_gcm() {
    let port = next_port();
    let container = start_vmess_server_async(port).await;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let target = Address::DomainNameAddress("www.baidu.com".to_string(), 80);

    // Connect and send handshake manually via VMessTcpStream
    let mut stream = VMessTcpStream::connect(proxy_addr, TEST_UUID, target, "aes-128-gcm")
        .await
        .expect("connect failed");

    // Write HTTP request
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n")
        .await
        .expect("write failed");
    stream.flush().await.expect("flush failed");

    // Read everything through VMessTcpStream (includes AEAD header + GCM chunk decoding)
    tokio::time::sleep(Duration::from_secs(5)).await;

    let mut buf = vec![0u8; 8192];
    match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
        Ok(Ok(n)) => println!(
            "RAW: read {} bytes: {:?}",
            n,
            String::from_utf8_lossy(&buf[..n.min(200)])
        ),
        Ok(Err(e)) => println!("RAW: read error: {e}"),
        Err(_) => println!("RAW: read timed out"),
    }

    container.cleanup().await;
}

/// Test: TCP proxy with "none" encryption (regression test)
#[tokio::test]
async fn test_vmess_tcp_proxy_http_none() {
    let port = next_port();
    let container = start_vmess_server_async(port).await;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let target = Address::DomainNameAddress("www.baidu.com".to_string(), 80);

    let mut stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        VMessTcpStream::connect(proxy_addr, TEST_UUID, target, "none"),
    )
    .await
    .expect("connection timed out")
    .expect("VMess connect failed");

    let request = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n";
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write failed");
    stream.flush().await.expect("flush failed");

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read failed");
    let response_str = String::from_utf8_lossy(&response);

    assert!(
        response_str.contains("200 OK"),
        "expected 200 OK in response"
    );

    container.cleanup().await;
}
