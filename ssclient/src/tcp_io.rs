mod aead;
mod stream;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use std::io::{ErrorKind, Result};
use tcp_connection::TcpConnection;

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use std::task::ready;
use bytes::{Bytes, BytesMut};
use tracing::trace;

use crypto::{CipherCategory, CipherType};

use self::{
    aead::{DecryptedReader as AeadDecryptedReader, EncryptedWriter as AeadEncryptedWriter},
    stream::{DecryptedReader as StreamDecryptedReader, EncryptedWriter as StreamEncryptedWriter},
};
use config::Address;
use parking_lot::Mutex;
use std::sync::Arc;

// Wrapper for Arc<Mutex<TcpConnection>> to implement AsyncRead/AsyncWrite
#[derive(Clone)]
pub struct SharedTcpConnection(Arc<Mutex<TcpConnection>>);

impl SharedTcpConnection {
    pub fn new(conn: TcpConnection) -> Self {
        Self(Arc::new(Mutex::new(conn)))
    }

    pub fn lock(&self) -> parking_lot::MutexGuard<'_, TcpConnection> {
        self.0.lock()
    }
}

impl AsyncRead for SharedTcpConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0.lock()).poll_read(cx, buf)
    }
}

impl AsyncWrite for SharedTcpConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.0.lock()).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0.lock()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0.lock()).poll_shutdown(cx)
    }
}

enum DecryptedReader<T> {
    Aead(AeadDecryptedReader<T>),
    Stream(StreamDecryptedReader<T>),
}

enum EncryptedWriter<T> {
    Aead(AeadEncryptedWriter<T>),
    Stream(StreamEncryptedWriter<T>),
}

/// Steps for initializing a DecryptedReader
enum ReadStatus {
    /// Waiting for initializing vector (or nonce for AEAD ciphers)
    ///
    /// (context, Buffer, already_read_bytes, method, key)
    WaitIv(Vec<u8>, usize, CipherType, Bytes),

    /// Connection is established, DecryptedReader is initialized
    Established,
}

/// A bidirectional stream for communicating with ShadowSocks' server
pub struct SSTcpStream {
    stream: SharedTcpConnection,
    dec: Option<Arc<Mutex<DecryptedReader<SharedTcpConnection>>>>,
    enc: Arc<Mutex<EncryptedWriter<SharedTcpConnection>>>,
    read_status: Arc<Mutex<ReadStatus>>,
}

impl SSTcpStream {
    /// Create a new CryptoStream with the underlying stream connection
    pub async fn connect(
        stream: TcpConnection,
        addr: Address,
        method: CipherType,
        key: Bytes,
    ) -> Result<SSTcpStream> {
        let prev_len = match method.category() {
            CipherCategory::Stream => method.iv_size(),
            CipherCategory::Aead => method.salt_size(),
        };

        let iv = match method.category() {
            CipherCategory::Stream => {
                let local_iv = method.gen_init_vec();
                trace!("generated Stream cipher IV {:?}", local_iv);
                local_iv
            }
            CipherCategory::Aead => {
                let local_salt = method.gen_salt();
                trace!("generated AEAD cipher salt {:?}", local_salt);
                local_salt
            }
        };

        let stream_shared = SharedTcpConnection::new(stream);
        let enc = match method.category() {
            CipherCategory::Stream => EncryptedWriter::Stream(StreamEncryptedWriter::new(
                stream_shared.clone(),
                method,
                &key,
                iv,
            )),
            CipherCategory::Aead => {
                EncryptedWriter::Aead(AeadEncryptedWriter::new(stream_shared.clone(), method, &key, iv))
            }
        };

        let mut ss_stream = SSTcpStream {
            stream: stream_shared,
            dec: None,
            enc: Arc::new(Mutex::new(enc)),
            read_status: Arc::new(Mutex::new(ReadStatus::WaitIv(
                vec![0u8; prev_len],
                0usize,
                method,
                key,
            ))),
        };

        let mut addr_buf = BytesMut::with_capacity(addr.serialized_len());
        addr.write_to_buf(&mut addr_buf);
        ss_stream.write_all(&addr_buf).await?;
        Ok(ss_stream)
    }

    pub fn accept(stream: TcpConnection, method: CipherType, key: Bytes) -> SSTcpStream {
        let prev_len = match method.category() {
            CipherCategory::Stream => method.iv_size(),
            CipherCategory::Aead => method.salt_size(),
        };

        let iv = match method.category() {
            CipherCategory::Stream => {
                let local_iv = method.gen_init_vec();
                trace!("generated Stream cipher IV {:?}", local_iv);
                local_iv
            }
            CipherCategory::Aead => {
                let local_salt = method.gen_salt();
                trace!("generated AEAD cipher salt {:?}", local_salt);
                local_salt
            }
        };

        let stream_shared = SharedTcpConnection::new(stream);
        let enc = match method.category() {
            CipherCategory::Stream => EncryptedWriter::Stream(StreamEncryptedWriter::new(
                stream_shared.clone(),
                method,
                &key,
                iv,
            )),
            CipherCategory::Aead => {
                EncryptedWriter::Aead(AeadEncryptedWriter::new(stream_shared.clone(), method, &key, iv))
            }
        };

        SSTcpStream {
            stream: stream_shared,
            dec: None,
            enc: Arc::new(Mutex::new(enc)),
            read_status: Arc::new(Mutex::new(ReadStatus::WaitIv(
                vec![0u8; prev_len],
                0usize,
                method,
                key,
            ))),
        }
    }

    /// Return a reference to the underlying stream
    pub fn get_ref(&self) -> &SharedTcpConnection {
        &self.stream
    }

    fn poll_read_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let ReadStatus::WaitIv(ref mut buf, ref mut pos, method, ref key) =
            *self.read_status.lock()
        {
            while *pos < buf.len() {
                let mut read_buf = tokio::io::ReadBuf::new(&mut buf[*pos..]);
                ready!(Pin::new(&mut self.stream).poll_read(cx, &mut read_buf))?;
                let n = read_buf.filled().len();
                if n == 0 {
                    trace!("wait iv error");
                    return Poll::Ready(Err(ErrorKind::UnexpectedEof.into()));
                }
                *pos += n;
            }

            let dec = match method.category() {
                CipherCategory::Stream => {
                    trace!("got Stream cipher IV {:?}", &buf);
                    DecryptedReader::Stream(StreamDecryptedReader::new(
                        self.stream.clone(),
                        method,
                        key,
                        buf,
                    ))
                }
                CipherCategory::Aead => {
                    trace!("got AEAD cipher salt {:?}", &buf);
                    DecryptedReader::Aead(AeadDecryptedReader::new(
                        self.stream.clone(),
                        method,
                        key,
                        buf,
                    ))
                }
            };

            self.dec = Some(Arc::new(Mutex::new(dec)));
        } else {
            return Poll::Ready(Ok(()));
        };

        *self.read_status.lock() = ReadStatus::Established;
        Poll::Ready(Ok(()))
    }

    fn priv_poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_read_handshake(ctx))?;

        let mut read_buf = tokio::io::ReadBuf::new(buf);
        let result = match *this.dec.as_ref().unwrap().lock() {
            DecryptedReader::Aead(ref mut r) => Pin::new(r).poll_read(ctx, &mut read_buf),
            DecryptedReader::Stream(ref mut r) => Pin::new(r).poll_read(ctx, &mut read_buf),
        };
        match result {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn priv_poll_write(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match *this.enc.lock() {
            EncryptedWriter::Aead(ref mut w) => Pin::new(w).poll_write(ctx, buf),
            EncryptedWriter::Stream(ref mut w) => Pin::new(w).poll_write(ctx, buf),
        }
    }

    fn priv_poll_flush(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().stream), ctx)
    }

    fn priv_poll_close(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().stream), ctx)
    }
}

impl AsyncRead for SSTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut temp_buf = vec![0u8; buf.remaining()];
        match self.as_mut().priv_poll_read(ctx, &mut temp_buf) {
            Poll::Ready(Ok(n)) => {
                buf.put_slice(&temp_buf[..n]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for SSTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.priv_poll_write(ctx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.priv_poll_flush(ctx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.priv_poll_close(ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio::time::sleep;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use std::net::ToSocketAddrs;
    use std::time::Duration;
    use tracing::trace;

    #[allow(dead_code)]
    fn setup_tracing_subscriber() {
        use tracing_subscriber::fmt::Subscriber;
        use tracing_subscriber::EnvFilter;

        let builder = Subscriber::builder().with_env_filter(EnvFilter::new("ssclient=trace"));
        builder.try_init().unwrap();
    }

    #[tokio::test]
    async fn test_tcp_read_write() {
        // setup_tracing_subscriber();
        let method = CipherType::ChaCha20Ietf;
        let password = "GwEU01uXWm0Pp6t08";
        let key = method.bytes_to_key(password.as_bytes());
        let server = "127.0.0.1:14187".to_socket_addrs().unwrap().next().unwrap();
        let data = b"GET / HTTP/1.1\r\n\r\n";
        let addr = Address::DomainNameAddress("twitter.com".to_string(), 443);
            let key_clone = key.clone();
            let addr_clone = addr.clone();
            let listener = TcpListener::bind("0.0.0.0:14187").await.unwrap();
            let h = tokio::task::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                trace!("accept conn");
                let mut ss_server = SSTcpStream::accept(TcpConnection::new(stream), method, key);
                let addr = Address::read_from(&mut ss_server).await.unwrap();
                trace!("read address");
                assert_eq!(addr, addr_clone);
                let mut buf = vec![0; 1024];
                let s = ss_server.read(&mut buf).await.unwrap();
                trace!("read data");
                ss_server.write(data).await.unwrap();
                assert_eq!(&buf[..s], data);
            });

            sleep(Duration::from_secs(3)).await;
            trace!("before connect");
            let conn = TcpConnection::connect_tcp(server).await.unwrap();
            let mut conn = SSTcpStream::connect(conn, addr, method, key_clone)
                .await
                .unwrap();
            trace!("before write");
            conn.write_all(data).await.unwrap();
            trace!("after write");
            drop(conn);
            h.await.unwrap();
    }
}
