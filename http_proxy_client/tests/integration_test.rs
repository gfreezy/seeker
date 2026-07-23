#![cfg(feature = "integration-tests")]

use config::Address;
use http_proxy_client::{HttpProxyTcpStream, HttpsProxyTcpStream};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use testcontainers::core::WaitFor;
use testcontainers::runners::SyncRunner;
use testcontainers::{Container, GenericImage, ImageExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;

/// Atomic port counter so each test gets a unique port (tests run in parallel).
static NEXT_PORT: AtomicU16 = AtomicU16::new(18080);

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

/// Generate self-signed TLS certificate and key using rcgen.
fn generate_self_signed_cert() -> (Vec<u8>, Vec<u8>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("failed to generate self-signed cert");
    let cert_pem = cert.cert.pem().into_bytes();
    let key_pem = cert.key_pair.serialize_pem().into_bytes();
    (cert_pem, key_pem)
}

fn start_http_proxy(port: u16) -> Container<GenericImage> {
    let listen_arg = format!("http://:{port}");
    GenericImage::new("ginuerzh/gost", "latest")
        .with_wait_for(WaitFor::message_on_stderr(format!(":{port}")))
        .with_startup_timeout(Duration::from_secs(30))
        .with_network("host")
        .with_cmd(["-L", &listen_arg])
        .start()
        .expect("failed to start HTTP proxy container")
}

async fn start_http_proxy_async(port: u16) -> TestContainer {
    let container = tokio::task::spawn_blocking(move || start_http_proxy(port))
        .await
        .expect("failed to spawn blocking task for container start");
    wait_port_listening(port, Duration::from_secs(30)).await;
    TestContainer::new(container)
}

fn start_https_proxy(port: u16) -> Container<GenericImage> {
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let listen_arg = format!("https://:{port}?cert=/etc/gost/cert.pem&key=/etc/gost/key.pem");

    GenericImage::new("ginuerzh/gost", "latest")
        .with_wait_for(WaitFor::message_on_stderr(format!(":{port}")))
        .with_startup_timeout(Duration::from_secs(30))
        .with_network("host")
        .with_copy_to("/etc/gost/cert.pem", cert_pem)
        .with_copy_to("/etc/gost/key.pem", key_pem)
        .with_cmd(["-L", &listen_arg])
        .start()
        .expect("failed to start HTTPS proxy container")
}

async fn start_https_proxy_async(port: u16) -> TestContainer {
    let container = tokio::task::spawn_blocking(move || start_https_proxy(port))
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

/// Start a one-shot HTTP server on the CI host so proxy tests do not depend on
/// external DNS or internet reachability.
async fn start_http_target() -> (SocketAddr, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind local HTTP target");
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener
            .accept()
            .await
            .expect("failed to accept proxied connection");
        let mut request = [0u8; 1024];
        stream
            .read(&mut request)
            .await
            .expect("failed to read proxied request");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .expect("failed to write target response");
    });
    (addr, handle)
}

#[tokio::test]
async fn test_http_proxy_tcp() {
    let (target_addr, target_server) = start_http_target().await;
    let port = next_port();
    let container = start_http_proxy_async(port).await;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let target = Address::SocketAddress(target_addr);

    let mut stream = HttpProxyTcpStream::connect(proxy_addr, target, None, None)
        .await
        .expect("HTTP proxy connect failed");

    let request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
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

    target_server.await.expect("local HTTP target failed");
    container.cleanup().await;
}

#[tokio::test]
async fn test_https_proxy_tcp() {
    let (target_addr, target_server) = start_http_target().await;
    let port = next_port();
    let container = start_https_proxy_async(port).await;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let target = Address::SocketAddress(target_addr);

    // Use a TLS connector that accepts self-signed certs for the proxy connection
    let tls_connector = tcp_connection::tls::get_tls_connector(true);

    let mut stream = HttpsProxyTcpStream::connect_with_connector(
        proxy_addr,
        "localhost",
        target,
        None,
        None,
        tls_connector,
    )
    .await
    .expect("HTTPS proxy connect failed");

    let request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write failed");

    let mut response = vec![0u8; 4096];
    let n = stream.read(&mut response).await.expect("read failed");
    let response_str = String::from_utf8_lossy(&response[..n]);

    println!("response (first {n} bytes):\n{response_str}");
    assert!(response_str.contains("200 OK"), "expected 200 OK status");

    target_server.await.expect("local HTTP target failed");
    container.cleanup().await;
}
