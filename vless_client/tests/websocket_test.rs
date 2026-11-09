use bytes::BytesMut;
use config::{Address, ServerConfig};
use futures_util::{SinkExt, StreamExt};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::{
    Message,
    handshake::server::{Request, Response},
    protocol::frame::{
        Frame,
        coding::{Data, OpCode},
    },
};
use uuid::Uuid;
use vless_client::{
    VlessTcpStream, VlessUdpSocket,
    protocol::{CMD_TCP, CMD_UDP, encode_vless_request},
};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

fn node(server: SocketAddr, extra: &str) -> ServerConfig {
    serde_yaml::from_str(&format!(
        r#"
name: websocket-test
type: vless
server: 127.0.0.1
port: {}
uuid: {UUID}
servername: tls.example.test
tls: false
{extra}
"#,
        server.port()
    ))
    .unwrap()
}

fn request_header(command: u8, target: &Address) -> Vec<u8> {
    let mut header = BytesMut::new();
    encode_vless_request(
        &Uuid::parse_str(UUID).unwrap(),
        command,
        target,
        None,
        &mut header,
    )
    .unwrap();
    header.to_vec()
}

#[tokio::test]
async fn websocket_tcp_handles_headers_backpressure_fragmentation_and_ping() {
    timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let config = node(server, "network: ws\nws-opts:\n  path: /relay?token=test\n  headers:\n    Host: http.example.test\n    X-Test: present");
        let target = Address::DomainNameAddress("x.com".to_string(), 443);
        let payload = vec![0xab; 2 * 1024 * 1024];
        let mut expected = request_header(CMD_TCP, &target);
        expected.extend_from_slice(&payload);
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_hdr_async(tcp, |req: &Request, response: Response| {
                assert_eq!(req.uri().path_and_query().unwrap().as_str(), "/relay?token=test");
                assert_eq!(req.headers()["Host"], "http.example.test");
                assert_eq!(req.headers()["X-Test"], "present");
                Ok(response)
            }).await.unwrap();
            let mut received = Vec::new();
            while received.len() < expected.len() {
                let Message::Binary(data) = ws.next().await.unwrap().unwrap() else { panic!("expected binary data") };
                received.extend_from_slice(&data);
            }
            assert_eq!(received, expected);
            ws.send(Message::Ping(b"check".to_vec().into())).await.unwrap();
            assert_eq!(ws.next().await.unwrap().unwrap(), Message::Pong(b"check".to_vec().into()));
            // An addon spans messages and separate polls. The payload also
            // spans continuation frames, followed by a clean WebSocket close.
            ws.send(Message::Binary(vec![0, 3, b'a'].into())).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            ws.send(Message::Frame(Frame::message(vec![b'b'], OpCode::Data(Data::Binary), false))).await.unwrap();
            ws.send(Message::Frame(Frame::message(b"creply".to_vec(), OpCode::Data(Data::Continue), true))).await.unwrap();
            ws.close(None).await.unwrap();
            assert!(matches!(ws.next().await, Some(Ok(Message::Close(_))) | None));
        });
        let mut stream = VlessTcpStream::connect_with_config(server, target, &config).await.unwrap();
        stream.write_all(&payload).await.unwrap();
        stream.flush().await.unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"reply");
        task.await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn rejected_websocket_upgrade_is_reported() {
    timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let config = node(server, "network: ws");
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            assert!(
                tokio_tungstenite::accept_hdr_async(tcp, |_: &Request, _: Response| {
                    Err(Response::builder()
                        .status(404)
                        .body(Some("wrong path".into()))
                        .unwrap())
                })
                .await
                .is_err()
            );
        });
        let error = VlessTcpStream::connect_with_config(
            server,
            Address::DomainNameAddress("x.com".into(), 443),
            &config,
        )
        .await
        .err()
        .unwrap();
        assert!(error.to_string().contains("404"), "{error}");
        task.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn plain_tcp_transport_still_works() {
    timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let config = node(server, "");
        let target = Address::DomainNameAddress("x.com".into(), 443);
        let expected = request_header(CMD_TCP, &target);
        let task = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut request = vec![0; expected.len()];
            tcp.read_exact(&mut request).await.unwrap();
            assert_eq!(request, expected);
            tcp.write_all(b"\x00\x00ok").await.unwrap();
        });
        let mut stream = VlessTcpStream::connect_with_config(server, target, &config)
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"ok");
        task.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn unsupported_transport_and_vision_combinations_fail_before_connecting() {
    let server = "127.0.0.1:9".parse().unwrap();
    for (extra, kind) in [
        ("network: grpc", ErrorKind::Unsupported),
        (
            "network: ws\nflow: xtls-rprx-vision",
            ErrorKind::InvalidInput,
        ),
        ("flow: xtls-rprx-vision", ErrorKind::InvalidInput),
    ] {
        let error = VlessTcpStream::connect_with_config(
            server,
            Address::DomainNameAddress("x.com".into(), 443),
            &node(server, extra),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(error.kind(), kind, "{error}");
    }
}

#[tokio::test]
async fn udp_disabled_configuration_is_honored() {
    let server = "127.0.0.1:9".parse().unwrap();
    let error = VlessUdpSocket::new_with_config(server, &node(server, "network: ws\nudp: false"))
        .await
        .err()
        .unwrap();
    assert_eq!(error.kind(), ErrorKind::Unsupported);
}

#[tokio::test]
async fn websocket_udp_preserves_packet_framing() {
    timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let config = node(server, "network: ws\nudp: true");
        let peer: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let mut expected = request_header(CMD_UDP, &Address::SocketAddress(peer));
        expected.extend_from_slice(b"\x00\x05query");
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let mut received = Vec::new();
            while received.len() < expected.len() {
                let Message::Binary(data) = ws.next().await.unwrap().unwrap() else {
                    panic!("expected binary data")
                };
                received.extend_from_slice(&data);
            }
            assert_eq!(received, expected);
            ws.send(Message::Binary(b"\x00\x00\x00\x05reply".to_vec().into()))
                .await
                .unwrap();
        });
        let socket = VlessUdpSocket::new_with_config(server, &config)
            .await
            .unwrap();
        assert_eq!(socket.send_to(b"query", peer).await.unwrap(), 5);
        let mut response = [0; 16];
        let (size, addr) = socket.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..size], b"reply");
        assert_eq!(addr, peer);
        task.await.unwrap();
    })
    .await
    .unwrap();
}
