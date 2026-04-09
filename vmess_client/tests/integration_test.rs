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
    "inbounds": [{{
        "port": {port},
        "protocol": "vmess",
        "settings": {{
            "clients": [{{
                "id": "{TEST_UUID}",
                "alterId": 64
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
        // Legacy VMess is force-disabled since 2022 in V2Ray v4.28+; re-enable it
        .with_env_var("v2ray.vmess.aead.forced", "false")
        .with_copy_to("/etc/v2ray/config.json", config_json)
        .start()
        .expect("failed to start v2ray container")
}

/// Start the server from within an async context.
async fn start_vmess_server_async(port: u16) -> TestContainer {
    let container = tokio::task::spawn_blocking(move || start_vmess_server(port))
        .await
        .expect("failed to spawn blocking task for container start");
    tokio::time::sleep(Duration::from_millis(500)).await;
    TestContainer::new(container)
}

/// Test: TCP proxy — send HTTP request through VMess proxy to httpbin.org
#[tokio::test]
async fn test_vmess_tcp_proxy_http() {
    let port = next_port();
    let container = start_vmess_server_async(port).await;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let target = Address::DomainNameAddress("httpbin.org".to_string(), 80);

    let mut stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        VMessTcpStream::connect(proxy_addr, TEST_UUID, target, "none"),
    )
    .await
    .expect("connection timed out")
    .expect("VMess connect failed");

    let request = "GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n";
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

/// Test: TCP proxy — HTTPS via raw TLS over VMess proxy stream
#[tokio::test]
async fn test_vmess_tcp_proxy_https() {
    let port = next_port();
    let container = start_vmess_server_async(port).await;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let target = Address::DomainNameAddress("www.google.com".to_string(), 443);

    let stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        VMessTcpStream::connect(proxy_addr, TEST_UUID, target, "none"),
    )
    .await
    .expect("connection timed out")
    .expect("VMess connect failed");

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

/// Test: multiple TCP streams through the same VMess server
#[tokio::test]
async fn test_vmess_tcp_multiple_streams() {
    let port = next_port();
    let container = start_vmess_server_async(port).await;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let (r1, r2) = tokio::join!(
        async {
            let target = Address::DomainNameAddress("httpbin.org".to_string(), 80);
            let mut s = VMessTcpStream::connect(proxy_addr, TEST_UUID, target, "none").await?;
            s.write_all(b"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
                .await?;
            s.flush().await?;
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await?;
            Ok::<_, std::io::Error>(String::from_utf8_lossy(&buf).to_string())
        },
        async {
            let target = Address::DomainNameAddress("httpbin.org".to_string(), 80);
            let mut s = VMessTcpStream::connect(proxy_addr, TEST_UUID, target, "none").await?;
            s.write_all(
                b"GET /user-agent HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n",
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
    assert!(resp1.contains("200 OK"));
    assert!(resp2.contains("200 OK"));

    container.cleanup().await;
}
