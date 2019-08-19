use super::ahead::DecryptedReader as AeadDecryptedReader;
use super::ahead::EncryptedWriter as AeadEncryptedWriter;
use super::stream::DecryptedReader as StreamDecryptedReader;
use super::stream::EncryptedWriter as StreamEncryptedWriter;
use crate::ssclient::{resolve_remote_server, try_timeout};
use bytes::BufMut;
use log::debug;
use shadowsocks::relay::boxed_future;
use shadowsocks::relay::tcprelay::{DecryptedRead, EncryptedWrite};
use shadowsocks::ServerConfig;
use std::io;
use std::io::{BufRead, Read, Write};
use std::sync::Arc;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::prelude::{AsyncRead, AsyncWrite, Future};
use trust_dns_resolver::AsyncResolver;

type TcpReadHalf<S /* : Read + Write + AsyncRead + AsyncWrite + Send */> = ReadHalf<S>;
type TcpWriteHalf<S /* : Read + Write + AsyncRead + AsyncWrite + Send */> = WriteHalf<S>;

/// `ReadHalf `of `TcpStream` with decryption
pub enum DecryptedHalf<S>
where
    S: Read + Write + AsyncRead + AsyncWrite + Send,
{
    Stream(StreamDecryptedReader<TcpReadHalf<S>>),
    Aead(AeadDecryptedReader<TcpReadHalf<S>>),
}

macro_rules! ref_half_do {
    ($self:expr,$t:ident,$m:ident$(,$p:expr)*) => {
        match *$self {
            $t::Stream(ref d) => d.$m($($p),*),
            $t::Aead(ref d) => d.$m($($p),*),
        }
    }
}

macro_rules! mut_half_do {
    ($self:expr,$t:ident,$m:ident$(,$p:expr)*) => {
        match *$self {
            $t::Stream(ref mut  d) => d.$m($($p),*),
            $t::Aead(ref mut d) => d.$m($($p),*),
        }
    }
}

impl<S> Read for DecryptedHalf<S>
where
    S: Read + Write + AsyncRead + AsyncWrite + Send,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        mut_half_do!(self, DecryptedHalf, read, buf)
    }
}

impl<S> DecryptedRead for DecryptedHalf<S>
where
    S: Read + Write + AsyncRead + AsyncWrite + Send,
{
    fn buffer_size(&self, data: &[u8]) -> usize {
        ref_half_do!(self, DecryptedHalf, buffer_size, data)
    }
}

impl<S> AsyncRead for DecryptedHalf<S> where S: Read + Write + AsyncRead + AsyncWrite + Send {}

impl<S> BufRead for DecryptedHalf<S>
where
    S: Read + Write + AsyncRead + AsyncWrite + Send,
{
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        mut_half_do!(self, DecryptedHalf, fill_buf)
    }

    fn consume(&mut self, amt: usize) {
        mut_half_do!(self, DecryptedHalf, consume, amt)
    }
}

impl<S> From<StreamDecryptedReader<TcpReadHalf<S>>> for DecryptedHalf<S>
where
    S: Read + Write + AsyncRead + AsyncWrite + Send,
{
    fn from(r: StreamDecryptedReader<TcpReadHalf<S>>) -> DecryptedHalf<S> {
        DecryptedHalf::Stream(r)
    }
}

impl<S> From<AeadDecryptedReader<TcpReadHalf<S>>> for DecryptedHalf<S>
where
    S: Read + Write + AsyncRead + AsyncWrite + Send,
{
    fn from(r: AeadDecryptedReader<TcpReadHalf<S>>) -> DecryptedHalf<S> {
        DecryptedHalf::Aead(r)
    }
}

/// `WriteHalf` of `TcpStream` with encryption
pub enum EncryptedHalf<S>
where
    S: Read + Write + AsyncRead + AsyncWrite + Send,
{
    Stream(StreamEncryptedWriter<TcpWriteHalf<S>>),
    Aead(AeadEncryptedWriter<TcpWriteHalf<S>>),
}

impl<S> EncryptedWrite for EncryptedHalf<S>
where
    S: Read + Write + AsyncRead + AsyncWrite + Send,
{
    fn write_raw(&mut self, data: &[u8]) -> io::Result<usize> {
        mut_half_do!(self, EncryptedHalf, write_raw, data)
    }

    fn flush(&mut self) -> io::Result<()> {
        mut_half_do!(self, EncryptedHalf, flush)
    }

    fn encrypt<B: BufMut>(&mut self, data: &[u8], buf: &mut B) -> io::Result<()> {
        mut_half_do!(self, EncryptedHalf, encrypt, data, buf)
    }

    fn buffer_size(&self, data: &[u8]) -> usize {
        ref_half_do!(self, EncryptedHalf, buffer_size, data)
    }
}

impl<S> From<StreamEncryptedWriter<TcpWriteHalf<S>>> for EncryptedHalf<S>
where
    S: Read + Write + AsyncRead + AsyncWrite + Send,
{
    fn from(d: StreamEncryptedWriter<TcpWriteHalf<S>>) -> EncryptedHalf<S> {
        EncryptedHalf::Stream(d)
    }
}

impl<S> From<AeadEncryptedWriter<TcpWriteHalf<S>>> for EncryptedHalf<S>
where
    S: Read + Write + AsyncRead + AsyncWrite + Send,
{
    fn from(d: AeadEncryptedWriter<TcpWriteHalf<S>>) -> EncryptedHalf<S> {
        EncryptedHalf::Aead(d)
    }
}

pub fn connect_proxy_server(
    svr_cfg: Arc<ServerConfig>,
    async_resolver: &AsyncResolver,
) -> impl Future<Item = TcpStream, Error = io::Error> + Send {
    let timeout = svr_cfg.timeout();
    debug!(
        "Connecting to proxy {:?}, timeout: {:?}",
        svr_cfg.addr(),
        timeout
    );
    let fut = resolve_remote_server(async_resolver, svr_cfg)
        .and_then(move |addr| try_timeout(TcpStream::connect(&addr), timeout));
    boxed_future(fut)
}
