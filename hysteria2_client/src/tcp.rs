use crate::client::Hy2Client;
use crate::protocol::{decode_tcp_response, encode_tcp_request};
use bytes::BytesMut;
use quinn::{RecvStream, SendStream};
use std::io::{self, Error, ErrorKind};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, error};

/// A TCP stream proxied through Hysteria 2 (QUIC bidirectional stream)
pub struct Hy2TcpStream {
    send: SendStream,
    recv: RecvStream,
}

impl Hy2TcpStream {
    /// Connect to a remote address through the Hysteria 2 proxy
    pub async fn connect(
        client: &Arc<Hy2Client>,
        addr: config::Address,
    ) -> io::Result<Hy2TcpStream> {
        let conn = client.get_connection().await?;

        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| {
            error!("failed to open QUIC bidirectional stream: {e}");
            Error::new(ErrorKind::ConnectionRefused, e.to_string())
        })?;

        // Send TCP request
        let mut buf = BytesMut::new();
        encode_tcp_request(&addr, &mut buf);
        send.write_all(&buf).await.map_err(|e| {
            error!("failed to send TCP request: {e}");
            Error::new(ErrorKind::ConnectionAborted, e.to_string())
        })?;

        debug!(%addr, "sent TCP request");

        // Read TCP response
        // Response format: status(1) + varint(msg_len) + msg + varint(padding_len) + padding
        // We need to read enough bytes. Read in chunks and try to parse.
        let mut resp_buf = BytesMut::new();
        let mut temp = [0u8; 1024];
        loop {
            let chunk = recv.read(&mut temp).await.map_err(|e| {
                error!("failed to read TCP response: {e}");
                Error::new(ErrorKind::ConnectionAborted, e.to_string())
            })?;
            match chunk {
                Some(n) => {
                    resp_buf.extend_from_slice(&temp[..n]);
                    // Try to parse — if we have enough data, break
                    let mut try_buf = resp_buf.clone();
                    match decode_tcp_response(&mut try_buf) {
                        Ok(response) => {
                            if response.status != 0x00 {
                                return Err(Error::new(
                                    ErrorKind::ConnectionRefused,
                                    format!(
                                        "proxy refused connection: status={}, msg={}",
                                        response.status, response.message
                                    ),
                                ));
                            }
                            debug!(status = response.status, "TCP response received");
                            break;
                        }
                        Err(ref e) if e.kind() == ErrorKind::UnexpectedEof => {
                            // Need more data
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }
                None => {
                    return Err(Error::new(
                        ErrorKind::ConnectionAborted,
                        "stream closed before TCP response",
                    ));
                }
            }
        }

        Ok(Hy2TcpStream { send, recv })
    }
}

impl AsyncRead for Hy2TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Use fully-qualified trait method to avoid inherent method shadowing
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for Hy2TcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Use fully-qualified trait method to avoid inherent method shadowing
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}
