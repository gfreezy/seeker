use std::io::Result;
use std::time::{Duration, Instant};

use async_std::io;
use async_std::net::{SocketAddr, TcpStream};
use async_std::prelude::*;
use bytes::{Bytes, BytesMut};
use tracing::trace;

use config::Address;
use crypto::{BoxAeadDecryptor, BoxAeadEncryptor, CipherType};

use crate::tcp_io::{aead_decrypted_read, aead_encrypted_write};
use crate::{recv_iv, send_iv, BoxFuture, MAX_PACKET_SIZE};

use super::{EncryptedReader, EncryptedTcpStream, EncryptedWriter};

pub struct AeadEncryptedTcpStream {
    conn: TcpStream,
    method: CipherType,
    key: Bytes,
    read_timeout: Duration,
    write_timeout: Duration,
    connect_timeout: Duration,
}

impl AeadEncryptedTcpStream {
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
            connect_timeout,
        })
    }
}

impl EncryptedTcpStream for AeadEncryptedTcpStream {
    fn get_writer<'a, 'b: 'a>(
        &'b self,
    ) -> BoxFuture<'b, Result<Box<dyn EncryptedWriter<'a> + 'a + Send>>> {
        // We need to send iv first, then we can read the iv from ss server.
        Box::pin(async move {
            let writer = AeadEncryptedWriter::new(
                &self.conn,
                self.method,
                self.key.clone(),
                self.connect_timeout,
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
            let reader = AeadEncryptedReader::new(
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

pub struct AeadEncryptedWriter<'a> {
    conn: &'a TcpStream,
    encrypt_cipher: BoxAeadEncryptor,
    send_buf: Vec<u8>,
    method: CipherType,
    write_timeout: Duration,
}

impl<'a> AeadEncryptedWriter<'a> {
    pub async fn new(
        conn: &'a TcpStream,
        method: CipherType,
        key: Bytes,
        connect_timeout: Duration,
        write_timeout: Duration,
    ) -> Result<AeadEncryptedWriter<'a>> {
        let cipher_type = method;

        let iv = send_iv(&conn, method, connect_timeout).await?;
        let cipher = crypto::new_aead_encryptor(cipher_type, &key, &iv);

        Ok(AeadEncryptedWriter {
            conn: &conn,
            encrypt_cipher: cipher,
            send_buf: vec![0; MAX_PACKET_SIZE],
            method,
            write_timeout,
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
        let cipher_type = self.method;
        let size = aead_encrypted_write(
            &mut self.encrypt_cipher,
            &buf,
            &mut self.send_buf,
            cipher_type,
        )?;
        let now = Instant::now();

        io::timeout(
            self.write_timeout,
            self.conn.write_all(&self.send_buf[..size]),
        )
        .await?;
        let duration = now.elapsed();
        trace!(duration = ?duration, size = size, "send to ss server");

        Ok(())
    }
}

pub struct AeadEncryptedReader<'a> {
    conn: &'a TcpStream,
    decrypt_cipher: BoxAeadDecryptor,
    recv_buf: Vec<u8>,
    method: CipherType,
    read_timeout: Duration,
}

impl<'a> AeadEncryptedReader<'a> {
    pub async fn new(
        conn: &'a TcpStream,
        method: CipherType,
        key: Bytes,
        read_timeout: Duration,
    ) -> Result<AeadEncryptedReader<'a>> {
        let cipher_type = method;

        let iv = recv_iv(&conn, method, read_timeout).await?;
        let decrypt_cipher = crypto::new_aead_decryptor(cipher_type, &key, &iv);

        Ok(AeadEncryptedReader {
            conn: &conn,
            decrypt_cipher,
            recv_buf: vec![0; MAX_PACKET_SIZE],
            method,
            read_timeout,
        })
    }
}

#[async_trait::async_trait]
impl EncryptedReader<'_> for AeadEncryptedReader<'_> {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        let cipher_type = self.method;

        let now = Instant::now();
        let size = io::timeout(
            self.read_timeout,
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
    use std::sync::Arc;
    use std::time::Duration;

    use async_std::net::TcpListener;
    use async_std::prelude::*;
    use async_std::task;

    use config::{ServerAddr, ShadowsocksServerConfig};
    use crypto::CipherType;

    use super::*;

    #[test]
    fn test_encrypted_stream() {
        const BIND_ADDR: &str = "127.0.0.1:65510";
        let srv_cfg = Arc::new(ShadowsocksServerConfig::new(
            "servername".to_string(),
            ServerAddr::DomainName("sdf".to_string(), 112),
            "pass".to_string(),
            CipherType::Aes128Gcm,
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
                let mut writer = AeadEncryptedWriter::new(
                    &conn,
                    srv_cfg_clone.method(),
                    srv_cfg_clone.key(),
                    srv_cfg_clone.write_timeout(),
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
                let mut reader = AeadEncryptedReader::new(
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
