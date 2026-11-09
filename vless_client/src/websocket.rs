use bytes::{Buf, Bytes};
use config::WebSocketOptions;
use futures_util::{Sink, Stream};
use std::io::{Error, ErrorKind, Result};
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::{
    Error as WsError, Message,
    client::IntoClientRequest,
    http::{HeaderName, HeaderValue},
    protocol::WebSocketConfig,
};
use tokio_tungstenite::{WebSocketStream, client_async_with_config};

/// A byte stream carried by binary WebSocket messages. Tungstenite handles
/// masking, fragmented frames, handshake validation and control messages.
pub(crate) struct WebSocketIo<S> {
    socket: WebSocketStream<S>,
    buffered: Bytes,
    needs_flush: bool,
    closed: bool,
}

fn websocket_error(error: WsError) -> Error {
    match error {
        WsError::Io(error) => error,
        error => Error::other(format!("VLESS WebSocket: {error}")),
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> WebSocketIo<S> {
    pub async fn connect(
        stream: S,
        authority: &str,
        options: &WebSocketOptions,
        tls: bool,
    ) -> Result<Self> {
        let path = if options.path.is_empty() {
            "/"
        } else {
            &options.path
        };
        if !path.starts_with('/') {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "WebSocket path must start with /",
            ));
        }
        let scheme = if tls { "wss" } else { "ws" };
        let mut request = format!("{scheme}://{authority}{path}")
            .into_client_request()
            .map_err(websocket_error)?;
        for (key, value) in &options.headers {
            let key = HeaderName::from_bytes(key.as_bytes())
                .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
            let value = HeaderValue::from_str(value)
                .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
            request.headers_mut().insert(key, value);
        }
        let config = WebSocketConfig::default()
            .write_buffer_size(0)
            .max_write_buffer_size(256 * 1024)
            .max_message_size(Some(16 * 1024 * 1024))
            .max_frame_size(Some(16 * 1024 * 1024));
        let (socket, _) = client_async_with_config(request, stream, Some(config))
            .await
            .map_err(websocket_error)?;
        Ok(Self {
            socket,
            buffered: Bytes::new(),
            needs_flush: false,
            closed: false,
        })
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WebSocketIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        for _ in 0..32 {
            if !this.buffered.is_empty() {
                let size = buf.remaining().min(this.buffered.len());
                buf.put_slice(&this.buffered[..size]);
                this.buffered.advance(size);
                return Poll::Ready(Ok(()));
            }
            if this.needs_flush {
                match Pin::new(&mut this.socket).poll_flush(cx) {
                    Poll::Ready(result) => {
                        result.map_err(websocket_error)?;
                        this.needs_flush = false;
                    }
                    Poll::Pending if this.closed => return Poll::Pending,
                    // Reading must still progress when outgoing traffic is
                    // blocked, otherwise full duplex tunnels can deadlock.
                    Poll::Pending => {}
                }
            }
            if this.closed {
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut this.socket).poll_next(cx)) {
                Some(Ok(Message::Binary(data))) => this.buffered = data,
                Some(Ok(Message::Ping(_))) => this.needs_flush = true,
                Some(Ok(Message::Pong(_))) => {}
                Some(Ok(Message::Close(_))) => {
                    this.closed = true;
                    this.needs_flush = true;
                }
                None => this.closed = true,
                Some(Err(error)) => return Poll::Ready(Err(websocket_error(error))),
                Some(Ok(_)) => {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::InvalidData,
                        "VLESS WebSocket expected a binary message",
                    )));
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::SinkExt;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn reads_progress_while_the_write_buffer_is_full() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let (client, server) = tokio::io::duplex(64);
            let options = WebSocketOptions::default();
            let (client, server) = tokio::join!(
                WebSocketIo::connect(client, "example.com", &options, false),
                tokio_tungstenite::accept_async(server),
            );
            let mut client = client.unwrap();
            let mut server = server.unwrap();
            // The server deliberately never reads this frame, filling the
            // client's outgoing buffer before it sends a response back.
            client.write_all(&[0xab; 16 * 1024]).await.unwrap();
            server
                .send(Message::Binary(b"reply".to_vec().into()))
                .await
                .unwrap();
            let mut response = [0; 5];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"reply");
        })
        .await
        .unwrap();
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WebSocketIo<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<Result<usize>> {
        let this = self.get_mut();
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.closed {
            return Poll::Ready(Err(ErrorKind::BrokenPipe.into()));
        }
        // Flush the previous frame before accepting another, bounding buffering
        // even when the peer stops reading. Large writes become small frames.
        if this.needs_flush {
            ready!(Pin::new(&mut this.socket).poll_flush(cx)).map_err(websocket_error)?;
            this.needs_flush = false;
        }
        ready!(Pin::new(&mut this.socket).poll_ready(cx)).map_err(websocket_error)?;
        let size = data.len().min(16 * 1024);
        Pin::new(&mut this.socket)
            .start_send(Message::Binary(Bytes::copy_from_slice(&data[..size])))
            .map_err(websocket_error)?;
        this.needs_flush = true;
        Poll::Ready(Ok(size))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();
        ready!(Pin::new(&mut this.socket).poll_flush(cx)).map_err(websocket_error)?;
        this.needs_flush = false;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();
        ready!(Pin::new(&mut this.socket).poll_close(cx)).map_err(websocket_error)?;
        this.closed = true;
        Pin::new(this.socket.get_mut()).poll_shutdown(cx)
    }
}
