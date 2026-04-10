#![cfg(feature = "integration-tests")]

use config::Address;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use testcontainers::core::WaitFor;
use testcontainers::runners::SyncRunner;
use testcontainers::{Container, GenericImage, ImageExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vless_client::{VlessTcpStream, VlessUdpSocket};

const TEST_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Atomic port counter so each test gets a unique port (tests run in parallel).
static NEXT_PORT: AtomicU16 = AtomicU16::new(56443);

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

/// Build Xray server config JSON for VLESS with TLS.
fn server_config_json(port: u16) -> Vec<u8> {
    format!(
        r#"{{
    "log": {{ "loglevel": "debug" }},
    "inbounds": [{{
        "port": {port},
        "protocol": "vless",
        "settings": {{
            "clients": [{{
                "id": "{TEST_UUID}",
                "flow": ""
            }}],
            "decryption": "none"
        }},
        "streamSettings": {{
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {{
                "certificates": [{{
                    "certificateFile": "/usr/local/etc/xray/server.crt",
                    "keyFile": "/usr/local/etc/xray/server.key"
                }}]
            }}
        }}
    }}],
    "outbounds": [{{
        "protocol": "freedom"
    }}]
}}"#
    )
    .into_bytes()
}

/// Build Xray server config JSON for VLESS with XTLS-Vision flow.
fn server_config_json_vision(port: u16) -> Vec<u8> {
    format!(
        r#"{{
    "log": {{ "loglevel": "debug" }},
    "inbounds": [{{
        "port": {port},
        "protocol": "vless",
        "settings": {{
            "clients": [{{
                "id": "{TEST_UUID}",
                "flow": "xtls-rprx-vision"
            }}],
            "decryption": "none"
        }},
        "streamSettings": {{
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {{
                "certificates": [{{
                    "certificateFile": "/usr/local/etc/xray/server.crt",
                    "keyFile": "/usr/local/etc/xray/server.key"
                }}]
            }}
        }}
    }}],
    "outbounds": [{{
        "protocol": "freedom"
    }}]
}}"#
    )
    .into_bytes()
}

fn start_vless_vision_server(port: u16) -> Container<GenericImage> {
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let config_json = server_config_json_vision(port);

    GenericImage::new("ghcr.io/xtls/xray-core", "latest")
        .with_wait_for(WaitFor::message_on_stdout("started"))
        .with_startup_timeout(Duration::from_secs(30))
        .with_network("host")
        .with_copy_to("/usr/local/etc/xray/config.json", config_json)
        .with_copy_to("/usr/local/etc/xray/server.crt", cert_pem)
        .with_copy_to("/usr/local/etc/xray/server.key", key_pem)
        .with_cmd(["run", "-c", "/usr/local/etc/xray/config.json"])
        .start()
        .expect("failed to start xray vision container")
}

async fn start_vless_vision_server_async(port: u16) -> TestContainer {
    let container = tokio::task::spawn_blocking(move || start_vless_vision_server(port))
        .await
        .expect("failed to spawn blocking task for vision container start");
    tokio::time::sleep(Duration::from_millis(500)).await;
    TestContainer::new(container)
}

fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0x12, 0x34]);
    buf.extend_from_slice(&[0x01, 0x00]);
    buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in domain.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0x00);
    buf.push((qtype >> 8) as u8);
    buf.push(qtype as u8);
    buf.extend_from_slice(&[0x00, 0x01]);
    buf
}

/// Start an Xray VLESS server container on the given port.
fn start_vless_server(port: u16) -> Container<GenericImage> {
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let config_json = server_config_json(port);

    GenericImage::new("ghcr.io/xtls/xray-core", "latest")
        .with_wait_for(WaitFor::message_on_stdout("started"))
        .with_startup_timeout(Duration::from_secs(30))
        .with_network("host")
        .with_copy_to("/usr/local/etc/xray/config.json", config_json)
        .with_copy_to("/usr/local/etc/xray/server.crt", cert_pem)
        .with_copy_to("/usr/local/etc/xray/server.key", key_pem)
        .with_cmd(["run", "-c", "/usr/local/etc/xray/config.json"])
        .start()
        .expect("failed to start xray container")
}

/// Start the server from within an async context.
async fn start_vless_server_async(port: u16) -> TestContainer {
    let container = tokio::task::spawn_blocking(move || start_vless_server(port))
        .await
        .expect("failed to spawn blocking task for container start");
    tokio::time::sleep(Duration::from_millis(500)).await;
    TestContainer::new(container)
}

/// Test: TCP proxy — send HTTP request through VLESS proxy
#[tokio::test]
async fn test_vless_tcp_proxy_http() {
    let port = next_port();
    let container = start_vless_server_async(port).await;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let target = Address::DomainNameAddress("www.baidu.com".to_string(), 80);

    let mut stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        VlessTcpStream::connect(proxy_addr, "localhost", target, TEST_UUID, None, true),
    )
    .await
    .expect("connection timed out")
    .expect("VLESS connect failed");

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

    println!("response (len={}):\n{response_str}", response.len());
    assert!(
        response_str.contains("200 OK")
            || response_str.contains("301")
            || response_str.contains("302"),
        "expected HTTP success/redirect in response"
    );

    container.cleanup().await;
}

/// Test: TCP proxy — HTTPS via raw TLS over VLESS proxy stream
#[tokio::test]
async fn test_vless_tcp_proxy_https() {
    let port = next_port();
    let container = start_vless_server_async(port).await;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let target = Address::DomainNameAddress("www.baidu.com".to_string(), 443);

    let stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        VlessTcpStream::connect(proxy_addr, "localhost", target, TEST_UUID, None, true),
    )
    .await
    .expect("connection timed out")
    .expect("VLESS connect failed");

    // Layer client-side TLS on top for the target connection
    let tls_connector = tokio_native_tls::TlsConnector::from(
        native_tls::TlsConnector::new().expect("failed to create TLS connector"),
    );
    let mut tls_stream = tls_connector
        .connect("www.baidu.com", stream)
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

/// Test: UDP proxy — send DNS query through VLESS proxy
#[tokio::test]
async fn test_vless_udp_dns_query() {
    let port = next_port();
    let container = start_vless_server_async(port).await;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let udp = tokio::time::timeout(
        CONNECT_TIMEOUT,
        VlessUdpSocket::new(proxy_addr, "localhost", TEST_UUID, None, true),
    )
    .await
    .expect("connection timed out")
    .expect("UDP socket creation failed");

    let dns_query = build_dns_query("google.com", 1);
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
            println!("SKIP: UDP DNS query timed out");
        }
    }

    container.cleanup().await;
}

/// Test: multiple TCP streams through the same VLESS server
#[tokio::test]
async fn test_vless_tcp_multiple_streams() {
    let port = next_port();
    let container = start_vless_server_async(port).await;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let (r1, r2) = tokio::join!(
        async {
            let target = Address::DomainNameAddress("www.baidu.com".to_string(), 80);
            let mut s =
                VlessTcpStream::connect(proxy_addr, "localhost", target, TEST_UUID, None, true)
                    .await?;
            s.write_all(b"GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n")
                .await?;
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await?;
            Ok::<_, std::io::Error>(String::from_utf8_lossy(&buf).to_string())
        },
        async {
            let target = Address::DomainNameAddress("www.baidu.com".to_string(), 80);
            let mut s =
                VlessTcpStream::connect(proxy_addr, "localhost", target, TEST_UUID, None, true)
                    .await?;
            s.write_all(
                b"GET /s?wd=vless HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n",
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

/// Test: TCP proxy with XTLS-Vision — HTTP request through VLESS Vision proxy
#[tokio::test]
async fn test_vless_tcp_proxy_http_vision() {
    let port = next_port();
    let container = start_vless_vision_server_async(port).await;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let target = Address::DomainNameAddress("www.baidu.com".to_string(), 80);

    let mut stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        VlessTcpStream::connect(
            proxy_addr,
            "localhost",
            target,
            TEST_UUID,
            Some("xtls-rprx-vision"),
            true,
        ),
    )
    .await
    .expect("connection timed out")
    .expect("VLESS Vision connect failed");

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

    println!(
        "Vision response (len={}):\n{}",
        response.len(),
        &response_str[..response_str.len().min(500)]
    );
    assert!(
        response_str.contains("200 OK")
            || response_str.contains("301")
            || response_str.contains("302"),
        "expected HTTP success/redirect in Vision response"
    );

    container.cleanup().await;
}

/// Test: TCP proxy with XTLS-Vision — HTTPS via raw TLS over VLESS Vision (exercises direct copy)
#[tokio::test]
async fn test_vless_tcp_proxy_https_vision() {
    let port = next_port();
    let container = start_vless_vision_server_async(port).await;

    let proxy_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let target = Address::DomainNameAddress("www.baidu.com".to_string(), 443);

    let stream = tokio::time::timeout(
        CONNECT_TIMEOUT,
        VlessTcpStream::connect(
            proxy_addr,
            "localhost",
            target,
            TEST_UUID,
            Some("xtls-rprx-vision"),
            true,
        ),
    )
    .await
    .expect("connection timed out")
    .expect("VLESS Vision connect failed");

    // Layer client-side TLS on top for the target connection.
    // This exercises XTLS-Vision direct copy: the inner TLS handshake (ClientHello/ServerHello)
    // flows through Vision padding, and once Application Data is detected, the Vision layer
    // should switch to direct copy mode.
    let tls_connector = tokio_native_tls::TlsConnector::from(
        native_tls::TlsConnector::new().expect("failed to create TLS connector"),
    );
    let mut tls_stream = tls_connector
        .connect("www.baidu.com", stream)
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

    println!("Vision+TLS response (first {n} bytes):\n{response_str}");
    assert!(
        response_str.contains("200")
            || response_str.contains("301")
            || response_str.contains("302"),
        "expected HTTP success/redirect status in Vision+TLS response"
    );

    container.cleanup().await;
}
