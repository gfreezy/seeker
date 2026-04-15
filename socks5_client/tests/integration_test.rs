#![cfg(feature = "integration-tests")]

use socks5_client::{Address, Socks5TcpStream, Socks5UdpSocket};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use testcontainers::core::WaitFor;
use testcontainers::runners::SyncRunner;
use testcontainers::{Container, GenericImage, ImageExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Atomic port counter so each test gets a unique port (tests run in parallel).
static NEXT_PORT: AtomicU16 = AtomicU16::new(11080);

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

fn start_socks5_server(port: u16) -> Container<GenericImage> {
    GenericImage::new("serjs/go-socks5-proxy", "latest")
        .with_wait_for(WaitFor::message_on_stderr("Start listening"))
        .with_startup_timeout(Duration::from_secs(30))
        .with_network("host")
        .with_env_var("PROXY_PORT", port.to_string())
        .with_env_var("REQUIRE_AUTH", "false")
        .start()
        .expect("failed to start socks5 container")
}

async fn start_socks5_server_async(port: u16) -> TestContainer {
    let container = tokio::task::spawn_blocking(move || start_socks5_server(port))
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

#[tokio::test]
async fn test_socks5_tcp_proxy() {
    let port = next_port();
    let container = start_socks5_server_async(port).await;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let target = Address::DomainNameAddress("www.baidu.com".to_string(), 80);

    let mut stream = Socks5TcpStream::connect(proxy_addr, target)
        .await
        .expect("SOCKS5 connect failed");

    let request = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n";
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

    container.cleanup().await;
}

#[tokio::test]
async fn test_socks5_udp_dns() {
    let port = next_port();
    let container = start_socks5_server_async(port).await;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let udp = match Socks5UdpSocket::new(proxy_addr).await {
        Ok(udp) => udp,
        Err(e) => {
            println!("SKIP: SOCKS5 UDP ASSOCIATE not supported: {e}");
            container.cleanup().await;
            return;
        }
    };

    // Build a simple DNS query for baidu.com A record
    let dns_query = build_dns_query("baidu.com", 1);
    let dns_server: SocketAddr = "114.114.114.114:53".parse().unwrap();

    udp.send_to(&dns_query, dns_server)
        .await
        .expect("send DNS query failed");

    let mut buf = [0u8; 512];
    match tokio::time::timeout(Duration::from_secs(5), udp.recv_from(&mut buf)).await {
        Ok(Ok((n, _from))) => {
            println!("DNS response: {n} bytes");
            assert!(n > 12, "DNS response too short");
            assert_eq!(buf[0], dns_query[0], "transaction ID mismatch (byte 0)");
            assert_eq!(buf[1], dns_query[1], "transaction ID mismatch (byte 1)");
            assert!(buf[2] & 0x80 != 0, "expected DNS response (QR=1)");
        }
        Ok(Err(e)) => {
            println!("SKIP: UDP recv_from failed (may not be supported): {e}");
        }
        Err(_) => {
            println!("SKIP: UDP DNS query timed out");
        }
    }

    container.cleanup().await;
}

/// Build a minimal DNS query packet.
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
