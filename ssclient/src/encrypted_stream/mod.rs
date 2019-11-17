use std::io::Result;

#[async_trait::async_trait]
pub(crate) trait EncryptedReader<'a> {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize>;
}

#[async_trait::async_trait]
pub(crate) trait EncryptedWriter<'a> {
    async fn send_addr(&mut self, addr: &Address) -> Result<()>;

    async fn send_all(&mut self, buf: &[u8]) -> Result<()>;
}

pub(crate) trait EncryptedTcpStream {
    fn get_writer<'a, 'b: 'a>(
        &'b self,
    ) -> BoxFuture<'b, Result<Box<dyn EncryptedWriter<'a> + 'a + Send>>>;

    fn get_reader<'a, 'b: 'a>(
        &'b self,
    ) -> BoxFuture<'b, Result<Box<dyn EncryptedReader<'a> + 'a + Send>>>;
}

mod aead_encrypt;
mod stream_encrypt;

pub use aead_encrypt::{AeadEncryptedReader, AeadEncryptedTcpStream, AeadEncryptedWriter};
use config::Address;
use futures::future::BoxFuture;
pub use stream_encrypt::{StreamEncryptedReader, StreamEncryptedTcpStream, StreamEncryptedWriter};
