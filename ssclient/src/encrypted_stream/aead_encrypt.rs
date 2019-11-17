use std::io::Result;
use std::time::Instant;

use async_std::io;
use async_std::net::{SocketAddr, TcpStream};
use async_std::sync::Arc;
use bytes::BytesMut;
use futures::{AsyncWriteExt, FutureExt};
use tracing::trace;

use config::{Address, ServerConfig};
use crypto::{BoxAeadDecryptor, BoxAeadEncryptor};

use super::{EncryptedReader, EncryptedTcpStream, EncryptedWriter};
use crate::tcp_io::{aead_decrypted_read, aead_encrypted_write};
use crate::{recv_iv, send_iv, MAX_PACKET_SIZE};
use futures::future::BoxFuture;

pub struct AeadEncryptedTcpStream {
    srv_cfg: Arc<ServerConfig>,
    conn: TcpStream,
}

impl AeadEncryptedTcpStream {
    pub async fn new(srv_cfg: Arc<ServerConfig>, ssserver: SocketAddr) -> Result<Self> {
        let now = Instant::now();
        let conn = io::timeout(srv_cfg.connect_timeout(), TcpStream::connect(ssserver)).await?;
        let duration = now.elapsed();
        trace!(duration = ?duration, addr = %ssserver, "TcpStream::connect");

        Ok(Self { srv_cfg, conn })
    }
}

impl<'a, 'b: 'a> EncryptedTcpStream<'a, 'b> for AeadEncryptedTcpStream {
    fn get_writer(&'b self) -> BoxFuture<'b, Result<Box<dyn EncryptedWriter<'a> + 'a + Send>>> {
        // We need to send iv first, then we can read the iv from ss server.
        async move {
            let writer = AeadEncryptedWriter::new(self.srv_cfg.clone(), &self.conn).await?;
            let w: Box<dyn EncryptedWriter + Send> = Box::new(writer);
            Ok(w)
        }
            .boxed()
    }

    fn get_reader(&'b self) -> BoxFuture<'b, Result<Box<dyn EncryptedReader<'a> + 'a + Send>>> {
        // We need to send iv first, then we can read the iv from ss server.
        async move {
            let reader = AeadEncryptedReader::new(self.srv_cfg.clone(), &self.conn).await?;
            let w: Box<dyn EncryptedReader + Send> = Box::new(reader);
            Ok(w)
        }
            .boxed()
    }
}

pub struct AeadEncryptedWriter<'a> {
    srv_cfg: Arc<ServerConfig>,
    conn: &'a TcpStream,
    encrypt_cipher: BoxAeadEncryptor,
    send_buf: Vec<u8>,
}

impl<'a> AeadEncryptedWriter<'a> {
    pub async fn new(
        srv_cfg: Arc<ServerConfig>,
        conn: &'a TcpStream,
    ) -> Result<AeadEncryptedWriter<'a>> {
        let key = srv_cfg.key();
        let cipher_type = srv_cfg.method();

        let iv = send_iv(&conn, srv_cfg.clone()).await?;
        let cipher = crypto::new_aead_encryptor(cipher_type, key, &iv);

        Ok(AeadEncryptedWriter {
            srv_cfg: srv_cfg.clone(),
            conn: &conn,
            encrypt_cipher: cipher,
            send_buf: vec![0; MAX_PACKET_SIZE],
        })
    }
}

#[async_trait::async_trait]
impl EncryptedWriter<'_> for AeadEncryptedWriter<'_> {
    async fn send_addr(&mut self, addr: &Address) -> Result<()> {
        let mut addr_bytes = BytesMut::with_capacity(100);
        addr.write_to_buf(&mut addr_bytes);
        self.send_all(&addr_bytes).await
    }

    async fn send_all(&mut self, buf: &[u8]) -> Result<()> {
        let cipher_type = self.srv_cfg.method();
        let size = aead_encrypted_write(
            &mut self.encrypt_cipher,
            &buf,
            &mut self.send_buf,
            cipher_type,
        )?;
        let now = Instant::now();

        io::timeout(
            self.srv_cfg.write_timeout(),
            self.conn.write_all(&self.send_buf[..size]),
        )
        .await?;
        let duration = now.elapsed();
        trace!(duration = ?duration, size = size, "send to ss server");

        Ok(())
    }
}

pub struct AeadEncryptedReader<'a> {
    srv_cfg: Arc<ServerConfig>,
    conn: &'a TcpStream,
    decrypt_cipher: BoxAeadDecryptor,
    recv_buf: Vec<u8>,
}

impl<'a> AeadEncryptedReader<'a> {
    pub async fn new(
        srv_cfg: Arc<ServerConfig>,
        conn: &'a TcpStream,
    ) -> Result<AeadEncryptedReader<'a>> {
        let key = srv_cfg.key();
        let cipher_type = srv_cfg.method();

        let iv = recv_iv(&conn, srv_cfg.clone()).await?;
        let decrypt_cipher = crypto::new_aead_decryptor(cipher_type, key, &iv);

        Ok(AeadEncryptedReader {
            srv_cfg: srv_cfg.clone(),
            conn: &conn,
            decrypt_cipher,
            recv_buf: vec![0; MAX_PACKET_SIZE],
        })
    }
}

#[async_trait::async_trait]
impl EncryptedReader<'_> for AeadEncryptedReader<'_> {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let cipher_type = self.srv_cfg.method();

        let now = Instant::now();
        let size = io::timeout(
            self.srv_cfg.read_timeout(),
            aead_decrypted_read(
                &mut self.decrypt_cipher,
                self.conn,
                &mut self.recv_buf,
                buf,
                cipher_type,
            ),
        )
        .await?;
        let duration = now.elapsed();
        trace!(duration = ?duration, size = size, "read from ss server");
        Ok(size)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use async_std::net::TcpListener;
    use async_std::prelude::*;
    use async_std::task;

    use config::ServerAddr;
    use crypto::CipherType;

    use super::*;

    #[test]
    fn test_encrypted_stream() {
        const BIND_ADDR: &str = "127.0.0.1:65510";
        let srv_cfg = Arc::new(ServerConfig::new(
            ServerAddr::DomainName("sdf".to_string(), 112),
            "pass".to_string(),
            CipherType::Aes128Gcm,
            Duration::from_secs(3),
            Duration::from_secs(3),
            Duration::from_secs(3),
        ));
        const DATA: &[u8] = b"hello,worldasdfklewjflksajdflkjcxlkjvaoiduf0923fhsdaklfnskadnvasjfp2efu98fsalhfksalfjaslkdjfpefuew9p8hfwaef";
        let addr = Address::DomainNameAddress("www.baidu.com".to_string(), 80);
        let addr_clone = addr.clone();

        let _ = task::block_on(async move {
            let srv_cfg_clone = srv_cfg.clone();
            task::spawn(async move {
                task::sleep(Duration::from_secs(1)).await;

                let conn = TcpStream::connect(BIND_ADDR).await?;
                let mut writer = AeadEncryptedWriter::new(srv_cfg_clone, &conn).await?;
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
                let mut reader = AeadEncryptedReader::new(srv_cfg, &conn).await?;
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
