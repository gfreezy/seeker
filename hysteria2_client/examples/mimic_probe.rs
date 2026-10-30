//! Privileged live interoperability probe. See docs/mimic.md.
use config::{MimicConfig, MimicPadding, RandomPadding};
use hysteria2_client::{Hy2Client, Hy2Config, Hy2TcpStream, Hy2UdpSocket, mimic::MimicSocket};
use quinn::AsyncUdpSocket;
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn tcp_roundtrip(client: &Arc<Hy2Client>, bytes: usize) -> io::Result<()> {
    let stream = Hy2TcpStream::connect(client, "127.0.0.1:18080".parse().unwrap()).await?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let send = async {
        let data: Vec<u8> = (0..65536).map(|n| n as u8).collect();
        let mut sent = 0;
        while sent < bytes {
            let len = (bytes - sent).min(data.len());
            writer.write_all(&data[..len]).await?;
            sent += len;
        }
        io::Result::Ok(())
    };
    let receive = async {
        let mut data = vec![0; 65536];
        let mut received = 0;
        while received < bytes {
            let len = (bytes - received).min(data.len());
            let n = reader.read(&mut data[..len]).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "echo closed"));
            }
            assert!(
                data[..n]
                    .iter()
                    .enumerate()
                    .all(|(i, byte)| *byte == (received + i) as u8)
            );
            received += n;
        }
        io::Result::Ok(())
    };
    tokio::try_join!(send, receive)?;
    Ok(())
}

async fn remote_probe(client: &Arc<Hy2Client>) -> io::Result<()> {
    let started = std::time::Instant::now();
    let connection = client.get_connection().await?;
    println!(
        "PASS: Mimic + QUIC + verified server TLS + Hy2 authentication ({:?})",
        started.elapsed()
    );
    let stream = Hy2TcpStream::connect(client, "example.com:443".parse().unwrap())
        .await
        .map_err(|error| {
            io::Error::other(format!(
                "TCP proxy: {error}; QUIC close reason: {:?}",
                connection.close_reason()
            ))
        })?;
    let connector = tcp_connection::tls::get_tls_connector(false);
    let name = rustls::pki_types::ServerName::try_from("example.com".to_owned()).unwrap();
    let mut tls = tcp_connection::tls::connect_tls(&connector, name, stream).await?;
    tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .await?;
    let mut response = Vec::new();
    tls.take(512 * 1024).read_to_end(&mut response).await?;
    let status = response.split(|b| *b == b'\n').next().unwrap_or_default();
    let status = String::from_utf8_lossy(status);
    if !(status.contains(" 200 ") || status.contains(" 301 ") || status.contains(" 302 ")) {
        return Err(io::Error::other(format!(
            "unexpected HTTPS response: {status}"
        )));
    }
    println!(
        "PASS: proxied HTTPS with verified destination TLS: {} ({} bytes)",
        status.trim(),
        response.len()
    );

    let udp = Hy2UdpSocket::new(client.clone()).await?;
    let query =
        b"\x4d\x43\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
    let mut buffer = [0; 4096];
    for resolver in ["1.1.1.1:53", "8.8.8.8:53"] {
        for _ in 0..2 {
            udp.send_to(query, resolver.parse().unwrap()).await?;
            if let Ok(packet) =
                tokio::time::timeout(Duration::from_secs(3), udp.recv_from(&mut buffer)).await
            {
                let (n, from) = packet?;
                if n >= 12
                    && buffer[..2] == query[..2]
                    && buffer[2] & 0x80 != 0
                    && buffer[3] & 0x0f == 0
                    && u16::from_be_bytes([buffer[6], buffer[7]]) > 0
                {
                    println!("PASS: proxied UDP DNS response from {from} ({n} bytes)");
                    return Ok(());
                }
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "no valid proxied UDP DNS response",
    ))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 3 {
        return Err("usage: mimic_probe echo|hy2 <server-ip:port> [salamander-password], or remote <server-ip:port> <sni> <auth-file>".into());
    }
    let server: SocketAddr = args[2].parse()?;
    let mut mimic = MimicConfig {
        enabled: true,
        ..Default::default()
    };
    if let Ok(padding) = std::env::var("MIMIC_PADDING") {
        mimic.padding = if padding == "random" {
            MimicPadding::Mode(RandomPadding::Random)
        } else {
            MimicPadding::Fixed(padding.parse()?)
        };
    }
    if args[1] == "remote" {
        if args.len() != 5 {
            return Err("remote requires server-ip:port, sni and auth-file".into());
        }
        let client = Hy2Client::new(Hy2Config {
            server_addr: server,
            sni: args[3].clone(),
            password: std::fs::read_to_string(&args[4])?.trim_end().to_string(),
            obfs_password: None,
            insecure: false,
            recv_window: None,
            mimic: Some(mimic),
        });
        let result = tokio::time::timeout(Duration::from_secs(60), remote_probe(&client)).await;
        client.shutdown().await;
        result??;
        return Ok(());
    }
    let password = args.get(3).cloned();
    if args[1] == "hy2" {
        let client = Hy2Client::new(Hy2Config {
            server_addr: server,
            sni: "localhost".into(),
            password: "mimic-test".into(),
            obfs_password: password,
            insecure: true,
            recv_window: None,
            mimic: Some(mimic),
        });
        let result = tokio::time::timeout(Duration::from_secs(30), async {
            let connections =
                futures_util::future::try_join_all((0..4).map(|_| client.get_connection())).await?;
            assert!(
                connections
                    .iter()
                    .all(|c| c.stable_id() == connections[0].stable_id())
            );
            println!("PASS: Hy2 authentication");
            let mut stream =
                Hy2TcpStream::connect(&client, "127.0.0.1:18080".parse().unwrap()).await?;
            let request = b"GET / HTTP/1.0\r\n\r\n";
            stream.write_all(request).await?;
            let mut response = vec![0; request.len()];
            stream.read_exact(&mut response).await?;
            assert_eq!(response, request);
            println!("PASS: Hy2 TCP echo");
            let udp = Hy2UdpSocket::new(client.clone()).await?;
            let target = "127.0.0.1:18081".parse().unwrap();
            let mut buffer = [0; 1024];
            let mut received = None;
            for _ in 0..5 {
                udp.send_to(b"hy2 mimic udp", target).await?;
                if let Ok(packet) =
                    tokio::time::timeout(Duration::from_millis(500), udp.recv_from(&mut buffer))
                        .await
                {
                    received = Some(packet?);
                    break;
                }
            }
            let (n, _) = received
                .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "UDP echo timed out"))?;
            assert_eq!(&buffer[..n], b"hy2 mimic udp");
            println!("PASS: Hy2 UDP echo");
            if let Ok(mib) = std::env::var("MIMIC_BULK_MIB") {
                let bytes = mib.parse::<usize>().unwrap() * 1024 * 1024;
                tcp_roundtrip(&client, bytes).await?;
                println!("PASS: {bytes}-byte TCP echo (window updates)");
                futures_util::future::try_join_all(
                    (0..4).map(|_| tcp_roundtrip(&client, 512 * 1024)),
                )
                .await?;
                println!("PASS: four concurrent TCP streams");
                connections[0].close(0u32.into(), b"probe reconnect");
                let reconnected = client.get_connection().await?;
                assert_ne!(reconnected.stable_id(), connections[0].stable_id());
                tcp_roundtrip(&client, 1024).await?;
                println!("PASS: reconnect after QUIC close");
            }
            io::Result::Ok(())
        })
        .await;
        client.shutdown().await;
        result??;
        println!(
            "PASS: original Hysteria authentication, TCP echo and UDP echo over userspace Mimic"
        );
    } else {
        let socket = Arc::new(MimicSocket::connect(mimic, server, password.as_deref()).await?);
        let result = tokio::time::timeout(Duration::from_secs(30), async {
            for len in [0, 1, 2, 11, 12, 13, 100, 1200, socket.max_payload()] {
                let payload: Vec<u8> = (0..len).map(|n| (n % 251) as u8).collect();
                let mut poller = socket.clone().create_io_poller();
                loop {
                    futures_util::future::poll_fn(|cx| poller.as_mut().poll_writable(cx)).await?;
                    match socket.try_send(&quinn::udp::Transmit {
                        destination: server,
                        ecn: None,
                        contents: &payload,
                        segment_size: None,
                        src_ip: None,
                    }) {
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                        result => {
                            result?;
                            break;
                        }
                    }
                }
                let mut buffer = vec![0; 65535];
                let mut meta = [quinn::udp::RecvMeta::default()];
                futures_util::future::poll_fn(|cx| {
                    socket.poll_recv(cx, &mut [io::IoSliceMut::new(&mut buffer)], &mut meta)
                })
                .await?;
                assert_eq!(&buffer[..meta[0].len], payload);
                println!("PASS: {len}-byte datagram");
            }
            io::Result::Ok(())
        })
        .await;
        socket.close().await;
        result??;
    }
    Ok(())
}
