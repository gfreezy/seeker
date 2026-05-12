//! End-to-end TLS download against `production.cloudflare.docker.com`.
//!
//! Reproduces the read pattern that previously surfaced
//! `Custom { kind: Other, error: "received plaintext buffer full" }` in
//! `relay_tcp_stream` while pulling Docker layers: open one rustls TLS
//! connection to the Cloudflare-fronted Docker registry CDN, then drain the
//! response body in 1600-byte chunks (the relay's historical buffer size).
//!
//! Run with:
//!   cargo test -p tcp_connection --features integration-tests \
//!     --test cloudflare_docker_test -- --ignored --nocapture
//!
//! Requires outbound HTTPS access to `auth.docker.io`,
//! `registry-1.docker.io`, and `production.cloudflare.docker.com`.

#![cfg(feature = "integration-tests")]

use std::io;
use std::net::ToSocketAddrs;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tcp_connection::tls::{connect_tls, get_tls_connector};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const AUTH_HOST: &str = "auth.docker.io";
const REGISTRY_HOST: &str = "registry-1.docker.io";
const IMAGE: &str = "library/alpine";
const TAG: &str = "3.21";
const PLATFORM_OS: &str = "linux";
const PLATFORM_ARCH: &str = "amd64";
const RELAY_CHUNK: usize = 1600;
const NETWORK_TIMEOUT: Duration = Duration::from_secs(60);

#[tokio::test]
#[ignore = "hits the public docker registry; run explicitly with --ignored"]
async fn download_alpine_layer_via_cloudflare() {
    let token = timeout(NETWORK_TIMEOUT, fetch_token())
        .await
        .expect("auth request timed out")
        .expect("fetch token");

    let layer_digest = timeout(NETWORK_TIMEOUT, fetch_first_layer_digest(&token))
        .await
        .expect("manifest request timed out")
        .expect("fetch layer digest");
    eprintln!("layer digest: {layer_digest}");

    let (cdn_host, cdn_path) = timeout(NETWORK_TIMEOUT, fetch_blob_redirect(&token, &layer_digest))
        .await
        .expect("blob redirect request timed out")
        .expect("fetch blob redirect");
    eprintln!("cdn redirect: https://{cdn_host}{cdn_path}");
    // Docker's blob redirect lands on either `production.cloudflare.docker.com`
    // (the original CDN that surfaced the bug) or a Cloudflare R2 bucket
    // (`*.r2.cloudflarestorage.com`) depending on geography and image. Both are
    // Cloudflare-fronted TLS endpoints that serve large blobs and reproduce the
    // same read-pattern that triggered "received plaintext buffer full".
    assert!(
        cdn_host.contains("cloudflare"),
        "expected redirect to a Cloudflare CDN, got host: {cdn_host}"
    );

    let body_len = timeout(NETWORK_TIMEOUT, download_blob(&cdn_host, &cdn_path))
        .await
        .expect("blob download timed out")
        .expect("download blob");
    eprintln!("downloaded {body_len} bytes from {cdn_host}");
    assert!(
        body_len > 256 * 1024,
        "alpine layer should be >256 KB, got {body_len}"
    );
}

async fn fetch_token() -> io::Result<String> {
    let path = format!("/token?service=registry.docker.io&scope=repository:{IMAGE}:pull");
    let resp = https_get(AUTH_HOST, &path, &[]).await?;
    let body = decode_body(&resp)?;
    let v: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("token json: {e}")))?;
    v["token"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no token in auth response"))
}

async fn fetch_first_layer_digest(token: &str) -> io::Result<String> {
    let manifest = fetch_manifest(token, TAG).await?;
    if let Some(layers) = manifest["layers"].as_array() {
        if let Some(d) = layers.first().and_then(|l| l["digest"].as_str()) {
            return Ok(d.to_string());
        }
    }
    if let Some(entries) = manifest["manifests"].as_array() {
        for entry in entries {
            let os = entry["platform"]["os"].as_str().unwrap_or("");
            let arch = entry["platform"]["architecture"].as_str().unwrap_or("");
            if os == PLATFORM_OS && arch == PLATFORM_ARCH {
                let digest = entry["digest"].as_str().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "platform manifest missing digest")
                })?;
                let inner = fetch_manifest(token, digest).await?;
                let layers = inner["layers"].as_array().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "inner manifest has no layers")
                })?;
                let d = layers.first().and_then(|l| l["digest"].as_str()).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "inner manifest layer missing digest")
                })?;
                return Ok(d.to_string());
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("no usable manifest entry for {PLATFORM_OS}/{PLATFORM_ARCH}"),
    ))
}

async fn fetch_manifest(token: &str, reference: &str) -> io::Result<serde_json::Value> {
    let path = format!("/v2/{IMAGE}/manifests/{reference}");
    let auth = format!("Authorization: Bearer {token}\r\n");
    let accept = "Accept: application/vnd.docker.distribution.manifest.v2+json\r\n\
                  Accept: application/vnd.docker.distribution.manifest.list.v2+json\r\n\
                  Accept: application/vnd.oci.image.manifest.v1+json\r\n\
                  Accept: application/vnd.oci.image.index.v1+json\r\n";
    let resp = https_get(REGISTRY_HOST, &path, &[&auth, accept]).await?;
    let body = decode_body(&resp)?;
    serde_json::from_slice(&body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("manifest json: {e}")))
}

async fn fetch_blob_redirect(token: &str, digest: &str) -> io::Result<(String, String)> {
    let path = format!("/v2/{IMAGE}/blobs/{digest}");
    let auth = format!("Authorization: Bearer {token}\r\n");
    let resp = https_get(REGISTRY_HOST, &path, &[&auth]).await?;
    let header_block = match resp.find("\r\n\r\n") {
        Some(idx) => &resp[..idx],
        None => &resp,
    };
    for line in header_block.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("location:") {
            let value = line[line.len() - rest.len()..].trim();
            let url = value
                .strip_prefix("https://")
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("non-https redirect: {value}")))?;
            let (host, path) = match url.split_once('/') {
                Some((h, p)) => (h.to_string(), format!("/{p}")),
                None => (url.to_string(), "/".to_string()),
            };
            return Ok((host, path));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("no Location header in blob response headers:\n{header_block}"),
    ))
}

async fn download_blob(host: &str, path: &str) -> io::Result<usize> {
    let mut tls = open_tls(host).await?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: seeker-test\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(req.as_bytes()).await?;
    tls.flush().await?;

    // Drain in 1600-byte chunks to match the historical relay loop. This is the
    // pattern under which "received plaintext buffer full" surfaced on Linux.
    let mut total = 0usize;
    let mut buf = vec![0u8; RELAY_CHUNK];
    loop {
        let n = tls.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        total += n;
    }
    Ok(total)
}

async fn https_get(host: &str, path: &str, extra_headers: &[&str]) -> io::Result<String> {
    let mut tls = open_tls(host).await?;
    let mut req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: seeker-test\r\nConnection: close\r\n"
    );
    for h in extra_headers {
        req.push_str(h);
    }
    req.push_str("\r\n");
    tls.write_all(req.as_bytes()).await?;
    tls.flush().await?;

    let mut data = Vec::with_capacity(8 * 1024);
    let mut buf = [0u8; 4096];
    loop {
        let n = tls.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
    }
    Ok(String::from_utf8_lossy(&data).into_owned())
}

async fn open_tls(host: &str) -> io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let connector = get_tls_connector(false);
    let addr = (host, 443u16)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("dns: {host}")))?;
    let tcp = TcpStream::connect(addr).await?;
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("sni: {e}")))?;
    connect_tls(&connector, server_name, tcp).await
}

/// Strip HTTP headers and decode the body, handling `Transfer-Encoding: chunked`
/// (the auth + registry endpoints return JSON over chunked encoding even when
/// `Connection: close` is requested).
fn decode_body(resp: &str) -> io::Result<Vec<u8>> {
    let header_end = resp
        .find("\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no header terminator"))?;
    let headers = &resp[..header_end];
    let body = &resp.as_bytes()[header_end + 4..];

    let chunked = headers
        .lines()
        .filter_map(|l| l.split_once(':'))
        .any(|(k, v)| {
            k.eq_ignore_ascii_case("transfer-encoding")
                && v.split(',').any(|t| t.trim().eq_ignore_ascii_case("chunked"))
        });

    if chunked {
        decode_chunked(body)
    } else {
        Ok(body.to_vec())
    }
}

fn decode_chunked(mut body: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(body.len());
    loop {
        let line_end = body
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunked: no size CRLF"))?;
        let size_line = std::str::from_utf8(&body[..line_end])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("chunk size utf8: {e}")))?;
        let size_str = size_line.split(';').next().unwrap_or(size_line).trim();
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("chunk size hex: {e}")))?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if body.len() < size + 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunked: truncated payload",
            ));
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}
