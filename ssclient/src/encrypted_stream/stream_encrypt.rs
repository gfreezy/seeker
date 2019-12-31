use std::io::Result;
use std::time::{Duration, Instant};

use async_std::io;
use async_std::net::{SocketAddr, TcpStream};
use async_std::prelude::*;
use bytes::{Bytes, BytesMut};
use tracing::trace;

use config::Address;
use crypto::{BoxStreamCipher, CipherType, CryptoMode};

use crate::{recv_iv, send_iv, BoxFuture, MAX_PACKET_SIZE};

use super::{EncryptedReader, EncryptedTcpStream, EncryptedWriter};

pub struct StreamEncryptedTcpStream {
    conn: TcpStream,
    method: CipherType,
    read_timeout: Duration,
    write_timeout: Duration,
    key: Bytes,
}

impl StreamEncryptedTcpStream {
    pub async fn new(
        ssserver: SocketAddr,
        method: CipherType,
        key: Bytes,
        connect_timeout: Duration,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Result<Self> {
        let now = Instant::now();
        let conn = io::timeout(connect_timeout, TcpStream::connect(ssserver)).await?;
        let duration = now.elapsed();
        trace!(duration = ?duration, addr = %ssserver, "TcpStream::connect");

        Ok(Self {
            conn,
            method,
            key,
            read_timeout,
            write_timeout,
        })
    }
}

impl EncryptedTcpStream for StreamEncryptedTcpStream {
    fn get_writer<'a, 'b: 'a>(
        &'b self,
    ) -> BoxFuture<'b, Result<Box<dyn EncryptedWriter<'a> + 'a + Send>>> {
        // We need to send iv first, then we can read the iv from ss server.
        Box::pin(async move {
            let writer = StreamEncryptedWriter::new(
                &self.conn,
                self.method,
                self.key.clone(),
                self.write_timeout,
            )
            .await?;
            let w: Box<dyn EncryptedWriter + Send> = Box::new(writer);
            Ok(w)
        })
    }

    fn get_reader<'a, 'b: 'a>(
        &'b self,
    ) -> BoxFuture<'b, Result<Box<dyn EncryptedReader<'a> + 'a + Send>>> {
        // We need to send iv first, then we can read the iv from ss server.
        Box::pin(async move {
            let reader = StreamEncryptedReader::new(
                &self.conn,
                self.method,
                self.key.clone(),
                self.read_timeout,
            )
            .await?;
            let w: Box<dyn EncryptedReader + Send> = Box::new(reader);
            Ok(w)
        })
    }
}

pub struct StreamEncryptedWriter<'a> {
    write_timeout: Duration,
    conn: &'a TcpStream,
    encrypt_cipher: BoxStreamCipher,
    send_buf: BytesMut,
}

impl<'a> StreamEncryptedWriter<'a> {
    pub async fn new(
        conn: &'a TcpStream,
        method: CipherType,
        key: Bytes,
        write_timeout: Duration,
    ) -> Result<StreamEncryptedWriter<'a>> {
        let send_iv = send_iv(&conn, method, write_timeout).await?;
        let encrypt_cipher = crypto::new_stream(method, &key, &send_iv, CryptoMode::Encrypt);

        Ok(StreamEncryptedWriter {
            conn: &conn,
            encrypt_cipher,
            send_buf: BytesMut::with_capacity(MAX_PACKET_SIZE),
            write_timeout,
        })
    }
}

#[async_trait::async_trait]
impl EncryptedWriter<'_> for StreamEncryptedWriter<'_> {
    async fn send_addr(&mut self, addr: &Address) -> Result<()> {
        let mut addr_bytes = BytesMut::with_capacity(100);
        addr.write_to_buf(&mut addr_bytes);
        self.send_all(&addr_bytes).await
    }

    async fn send_all(&mut self, buf: &[u8]) -> Result<()> {
        self.send_buf.clear();
        let reserve_len = self.encrypt_cipher.buffer_size(buf);
        self.send_buf.reserve(reserve_len);
        self.encrypt_cipher.update(buf, &mut self.send_buf)?;
        let now = Instant::now();
        io::timeout(self.write_timeout, self.conn.write_all(&self.send_buf)).await?;
        let duration = now.elapsed();
        let send_size = self.send_buf.len();
        trace!(duration = ?duration, size = send_size, "send to ss server");
        Ok(())
    }
}

pub struct StreamEncryptedReader<'a> {
    read_timeout: Duration,
    conn: &'a TcpStream,
    decrypt_cipher: BoxStreamCipher,
    recv_buf: Vec<u8>,
    recv_output: BytesMut,
}

impl<'a> StreamEncryptedReader<'a> {
    pub async fn new(
        conn: &'a TcpStream,
        method: CipherType,
        key: Bytes,
        read_timeout: Duration,
    ) -> Result<StreamEncryptedReader<'a>> {
        let recv_iv = recv_iv(&conn, method, read_timeout).await?;
        let decrypt_cipher = crypto::new_stream(method, &key, &recv_iv, CryptoMode::Decrypt);
        Ok(StreamEncryptedReader {
            read_timeout,
            conn: &conn,
            decrypt_cipher,
            recv_buf: vec![0; MAX_PACKET_SIZE],
            recv_output: BytesMut::with_capacity(MAX_PACKET_SIZE),
        })
    }
}

#[async_trait::async_trait]
impl EncryptedReader<'_> for StreamEncryptedReader<'_> {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let now = Instant::now();
        let size = io::timeout(self.read_timeout, self.conn.read(&mut self.recv_buf)).await?;
        let duration = now.elapsed();
        trace!(duration = ?duration, size = size, "read from ss server");

        let buffer_size = self.decrypt_cipher.buffer_size(&self.recv_buf[..size]);
        self.recv_output.clear();
        self.recv_output.reserve(buffer_size);

        if size > 0 {
            self.decrypt_cipher
                .update(&self.recv_buf[..size], &mut self.recv_output)?;
        } else {
            self.decrypt_cipher.finalize(&mut self.recv_output)?;
        }
        let output_len = self.recv_output.len();
        assert!(buf.len() >= output_len, dbg!(buf.len(), output_len));
        buf[..output_len].copy_from_slice(&self.recv_output);

        Ok(output_len)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use async_std::net::TcpListener;
    use async_std::prelude::*;
    use async_std::task;

    use config::{ServerAddr, ServerConfig};
    use crypto::CipherType;

    use super::*;

    #[test]
    fn test_encrypted_stream() {
        const BIND_ADDR: &str = "127.0.0.1:65510";
        let srv_cfg = Arc::new(ServerConfig::new(
            "servername".to_string(),
            ServerAddr::DomainName("sdf".to_string(), 112),
            "pass".to_string(),
            CipherType::ChaCha20Ietf,
            Duration::from_secs(3),
            Duration::from_secs(3),
            Duration::from_secs(3),
            10,
        ));
        const DATA: &[u8] = b"hello,worldasdfklewjflksajdflkjcxlkjvaoiduf0923fhsdaklfnskadnvasjfp2efu98fsalhfksalfjaslkdjfpefuew9p8hfwaef";
        let addr = Address::DomainNameAddress("www.baidu.com".to_string(), 80);
        let addr_clone = addr.clone();

        let _ = task::block_on(async move {
            let srv_cfg_clone = srv_cfg.clone();
            task::spawn(async move {
                task::sleep(Duration::from_secs(1)).await;

                let conn = TcpStream::connect(BIND_ADDR).await?;
                let mut writer = StreamEncryptedWriter::new(
                    &conn,
                    srv_cfg_clone.method(),
                    srv_cfg_clone.key(),
                    srv_cfg_clone.write_timeout(),
                )
                .await?;
                writer.send_addr(&addr_clone).await?;
                task::sleep(Duration::from_secs(1)).await;
                writer.send_all(DATA).await?;

                let ret: Result<()> = Ok(());
                ret
            });

            let listener: TcpListener = TcpListener::bind(BIND_ADDR).await?;
            let mut incoming = listener.incoming();
            let mut buf = vec![0; 1024];
            if let Some(stream) = incoming.next().await {
                let conn = stream?;
                let mut reader = StreamEncryptedReader::new(
                    &conn,
                    srv_cfg.method(),
                    srv_cfg.key(),
                    srv_cfg.read_timeout(),
                )
                .await?;
                let _size = reader.recv(&mut buf).await?;
                let recv_addr = Address::read_from(&mut buf.as_slice())?;
                assert_eq!(recv_addr, addr);
                let size = reader.recv(&mut buf).await?;
                assert_eq!(&buf[..size], &DATA[..]);
            }
            let ret: Result<()> = Ok(());
            ret
        });
    }
}
