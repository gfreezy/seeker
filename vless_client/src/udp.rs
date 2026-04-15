use crate::protocol::{encode_vless_request, CMD_UDP, VLESS_VERSION};
use tcp_connection::tls::get_tls_connector;
use bytes::{BufMut, BytesMut};
use config::Address;
use rustls::pki_types::ServerName;
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify};
use tokio_rustls::client::TlsStream;
use uuid::Uuid;

fn normalize_udp_flow(flow: Option<&str>) -> Result<()> {
    match flow {
        None | Some("") => Ok(()),
        Some("xtls-rprx-vision") | Some("xtls-rprx-vision-udp443") => Ok(()),
        Some(other) => Err(Error::new(
            ErrorKind::InvalidInput,
            format!("unsupported VLESS flow: {other}"),
        )),
    }
}

enum ConnectionState {
    Unconnected,
    Connecting,
    Connected(Arc<PlainVlessUdpSocket>),
}

struct PlainReadState {
    reader: ReadHalf<TlsStream<TcpStream>>,
    response_header_parsed: bool,
}

struct PlainVlessUdpSocket {
    peer: SocketAddr,
    read: Mutex<PlainReadState>,
    write: Mutex<WriteHalf<TlsStream<TcpStream>>>,
}

impl PlainVlessUdpSocket {
    async fn connect(
        server: SocketAddr,
        sni: &str,
        peer: SocketAddr,
        uuid: Uuid,
        insecure: bool,
    ) -> Result<Self> {
        let connector = get_tls_connector(insecure);
        let server_name = ServerName::try_from(sni.to_string())
            .map_err(|e| Error::other(format!("invalid SNI: {e}")))?;
        let tcp_stream = TcpStream::connect(server).await?;
        let mut tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(Error::other)?;

        let mut header_buf = BytesMut::with_capacity(128);
        // Xray inbound rejects Vision + RequestCommandUDP, so UDP always uses the plain
        // VLESS packet framing even when the TCP flow is Vision.
        encode_vless_request(
            &uuid,
            CMD_UDP,
            &Address::SocketAddress(peer),
            None,
            &mut header_buf,
        )?;
        tls_stream.write_all(&header_buf).await?;
        tls_stream.flush().await?;

        let (reader, writer) = tokio::io::split(tls_stream);
        Ok(Self {
            peer,
            read: Mutex::new(PlainReadState {
                reader,
                response_header_parsed: false,
            }),
            write: Mutex::new(writer),
        })
    }

    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize> {
        if addr != self.peer {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "VLESS UDP socket already bound to {}, got packet for {}",
                    self.peer, addr
                ),
            ));
        }
        if buf.len() > u16::MAX as usize {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("VLESS UDP packet too large: {}", buf.len()),
            ));
        }

        let mut packet = BytesMut::with_capacity(buf.len() + 2);
        packet.put_u16(buf.len() as u16);
        packet.extend_from_slice(buf);

        let mut writer = self.write.lock().await;
        writer.write_all(&packet).await?;
        writer.flush().await?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let mut read = self.read.lock().await;
        if !read.response_header_parsed {
            read_response_header(&mut read.reader).await?;
            read.response_header_parsed = true;
        }

        let mut len_buf = [0u8; 2];
        read.reader.read_exact(&mut len_buf).await?;
        let packet_len = u16::from_be_bytes(len_buf) as usize;
        let mut packet = vec![0u8; packet_len];
        read.reader.read_exact(&mut packet).await?;

        let copy_len = packet_len.min(buf.len());
        buf[..copy_len].copy_from_slice(&packet[..copy_len]);
        Ok((copy_len, self.peer))
    }
}

async fn read_response_header<R>(reader: &mut R) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 2];
    reader.read_exact(&mut header).await?;
    if header[0] != VLESS_VERSION {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "VLESS: unexpected response version {}, expected {}",
                header[0], VLESS_VERSION
            ),
        ));
    }

    let addons_len = header[1] as usize;
    if addons_len > 0 {
        let mut addons = vec![0u8; addons_len];
        reader.read_exact(&mut addons).await?;
    }

    Ok(())
}

#[derive(Clone)]
pub struct VlessUdpSocket {
    server: SocketAddr,
    sni: String,
    uuid: Uuid,
    insecure: bool,
    state: Arc<Mutex<ConnectionState>>,
    state_change: Arc<Notify>,
}

impl VlessUdpSocket {
    pub async fn new(
        server: SocketAddr,
        sni: &str,
        uuid: &str,
        flow: Option<&str>,
        insecure: bool,
    ) -> Result<Self> {
        normalize_udp_flow(flow)?;
        let uuid =
            Uuid::parse_str(uuid).map_err(|e| Error::other(format!("invalid VLESS uuid: {e}")))?;
        Ok(Self {
            server,
            sni: sni.to_string(),
            uuid,
            insecure,
            state: Arc::new(Mutex::new(ConnectionState::Unconnected)),
            state_change: Arc::new(Notify::new()),
        })
    }

    async fn get_or_connect(&self, addr: SocketAddr) -> Result<Arc<PlainVlessUdpSocket>> {
        loop {
            let should_connect = {
                let mut state = self.state.lock().await;
                match &*state {
                    ConnectionState::Connected(conn) => return Ok(conn.clone()),
                    ConnectionState::Connecting => false,
                    ConnectionState::Unconnected => {
                        *state = ConnectionState::Connecting;
                        true
                    }
                }
            };

            if !should_connect {
                self.state_change.notified().await;
                continue;
            }

            let result = PlainVlessUdpSocket::connect(
                self.server,
                &self.sni,
                addr,
                self.uuid,
                self.insecure,
            )
            .await;

            let mut state = self.state.lock().await;
            match result {
                Ok(conn) => {
                    let conn = Arc::new(conn);
                    *state = ConnectionState::Connected(conn.clone());
                    self.state_change.notify_waiters();
                    return Ok(conn);
                }
                Err(err) => {
                    *state = ConnectionState::Unconnected;
                    self.state_change.notify_waiters();
                    return Err(err);
                }
            }
        }
    }

    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize> {
        let conn = self.get_or_connect(addr).await?;
        match conn.send_to(buf, addr).await {
            Ok(n) => Ok(n),
            Err(e) => {
                // Reset connection so next call attempts reconnection
                let mut state = self.state.lock().await;
                *state = ConnectionState::Unconnected;
                self.state_change.notify_waiters();
                Err(e)
            }
        }
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let conn = loop {
            let state = self.state.lock().await;
            match &*state {
                ConnectionState::Connected(conn) => break conn.clone(),
                ConnectionState::Unconnected | ConnectionState::Connecting => {
                    drop(state);
                    self.state_change.notified().await;
                }
            }
        };
        match conn.recv_from(buf).await {
            Ok(result) => Ok(result),
            Err(e) => {
                let mut state = self.state.lock().await;
                *state = ConnectionState::Unconnected;
                self.state_change.notify_waiters();
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_udp_flow;

    #[test]
    fn test_normalize_udp_flow() {
        assert!(normalize_udp_flow(None).is_ok());
        assert!(normalize_udp_flow(Some("")).is_ok());
        assert!(normalize_udp_flow(Some("xtls-rprx-vision")).is_ok());
        assert!(normalize_udp_flow(Some("xtls-rprx-vision-udp443")).is_ok());
        assert!(normalize_udp_flow(Some("unknown-flow")).is_err());
    }
}
