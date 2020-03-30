mod aead;
mod stream;

use async_std::io::timeout;
use async_std::io::{Read, Write};
use async_std::prelude::*;
use std::io::{ErrorKind, Result};

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use futures::ready;
use tracing::trace;

use crypto::{CipherCategory, CipherType};

use self::{
    aead::{DecryptedReader as AeadDecryptedReader, EncryptedWriter as AeadEncryptedWriter},
    stream::{DecryptedReader as StreamDecryptedReader, EncryptedWriter as StreamEncryptedWriter},
};
use async_std::net::TcpStream;
use config::Address;
use std::net::SocketAddr;
use std::time::Duration;

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
#[derive(Clone)]
pub struct SSTcpStream {
    stream: TcpStream,
    dec: Option<DecryptedReader<TcpStream>>,
    enc: EncryptedWriter<TcpStream>,
    read_status: ReadStatus,
}

impl SSTcpStream {
    /// Create a new CryptoStream with the underlying stream connection
    pub async fn connect(
        addr: Address,
        server_addr: SocketAddr,
        method: CipherType,
        key: Bytes,
        connect_timeout: Duration,
    ) -> Result<SSTcpStream> {
        let stream = timeout(connect_timeout, TcpStream::connect(server_addr)).await?;
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

        let enc = match method.category() {
            CipherCategory::Stream => EncryptedWriter::Stream(StreamEncryptedWriter::new(
                stream.clone(),
                method,
                &key,
                iv,
            )),
            CipherCategory::Aead => {
                EncryptedWriter::Aead(AeadEncryptedWriter::new(stream.clone(), method, &key, iv))
            }
        };

        let mut ss_stream = SSTcpStream {
            stream,
            dec: None,
            enc,
            read_status: ReadStatus::WaitIv(vec![0u8; prev_len], 0usize, method, key),
        };

        let mut addr_buf = BytesMut::with_capacity(addr.serialized_len());
        addr.write_to_buf(&mut addr_buf);
        timeout(connect_timeout, ss_stream.write_all(&addr_buf)).await?;
        trace!("proxy handshake");
        Ok(ss_stream)
    }

    pub fn accept(stream: TcpStream, method: CipherType, key: Bytes) -> SSTcpStream {
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

        let enc = match method.category() {
            CipherCategory::Stream => EncryptedWriter::Stream(StreamEncryptedWriter::new(
                stream.clone(),
                method,
                &key,
                iv,
            )),
            CipherCategory::Aead => {
                EncryptedWriter::Aead(AeadEncryptedWriter::new(stream.clone(), method, &key, iv))
            }
        };

        SSTcpStream {
            stream,
            dec: None,
            enc,
            read_status: ReadStatus::WaitIv(vec![0u8; prev_len], 0usize, method, key),
        }
    }

    /// Return a reference to the underlying stream
    pub fn get_ref(&self) -> &TcpStream {
        &self.stream
    }

    fn poll_read_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let ReadStatus::WaitIv(ref mut buf, ref mut pos, method, ref key) = self.read_status {
            trace!("wait iv");
            while *pos < buf.len() {
                let n = ready!(Pin::new(&mut self.stream).poll_read(cx, &mut buf[*pos..]))?;
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
                        &buf,
                    ))
                }
                CipherCategory::Aead => {
                    trace!("got AEAD cipher salt {:?}", &buf);
                    DecryptedReader::Aead(AeadDecryptedReader::new(
                        self.stream.clone(),
                        method,
                        key,
                        &buf,
                    ))
                }
            };

            self.dec = Some(dec);
            self.read_status = ReadStatus::Established;
        }

        Poll::Ready(Ok(()))
    }

    fn priv_poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_read_handshake(ctx))?;

        match *this.dec.as_mut().unwrap() {
            DecryptedReader::Aead(ref mut r) => Pin::new(r).poll_read(ctx, buf),
            DecryptedReader::Stream(ref mut r) => Pin::new(r).poll_read(ctx, buf),
        }
    }

    fn priv_poll_write(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.enc {
            EncryptedWriter::Aead(ref mut w) => Pin::new(w).poll_write(ctx, buf),
            EncryptedWriter::Stream(ref mut w) => Pin::new(w).poll_write(ctx, buf),
        }
    }

    fn priv_poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Write::poll_flush(Pin::new(&mut self.stream), ctx)
    }

    fn priv_poll_close(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Write::poll_close(Pin::new(&mut self.stream), ctx)
    }
}

impl Read for SSTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.priv_poll_read(ctx, buf)
    }
}

impl Write for SSTcpStream {
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

    fn poll_close(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.priv_poll_close(ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup_tracing_subscriber;
    use async_std::net::TcpListener;
    use async_std::task::{block_on, spawn};
    use std::net::ToSocketAddrs;

    #[test]
    fn test_tcp_read_write() {
        setup_tracing_subscriber();
        let method = CipherType::ChaCha20Ietf;
        let password = "GwEU01uXWm0Pp6t08";
        let key = method.bytes_to_key(password.as_bytes());
        let server = "127.0.0.1:14187".to_socket_addrs().unwrap().next().unwrap();
        let data = b"GET / HTTP/1.1\r\n\r\n";
        let addr = Address::DomainNameAddress("twitter.com".to_string(), 443);
        block_on(async {
            let key_clone = key.clone();
            let addr_clone = addr.clone();
            let listener = TcpListener::bind("0.0.0.0:14187").await.unwrap();
            let h = spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut ss_server = SSTcpStream::accept(stream, method, key);
                let addr = Address::read_from(&mut ss_server).await.unwrap();
                assert_eq!(addr, addr_clone);
                let mut buf = vec![0; 1024];
                let s = ss_server.read(&mut buf).await.unwrap();
                assert_eq!(&buf[..s], data);
            });

            let mut conn =
                SSTcpStream::connect(addr, server, method, key_clone, Duration::from_secs(10))
                    .await
                    .unwrap();
            conn.write_all(data).await.unwrap();
            drop(conn);
            h.await;
        })
    }
}
