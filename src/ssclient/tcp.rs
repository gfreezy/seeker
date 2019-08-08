use super::ahead::DecryptedReader as AeadDecryptedReader;
use super::ahead::EncryptedWriter as AeadEncryptedWriter;
use super::stream::DecryptedReader as StreamDecryptedReader;
use super::stream::EncryptedWriter as StreamEncryptedWriter;
use byte_string::ByteStr;
use bytes::{BufMut, BytesMut};
use log::debug;
use log::trace;
use shadowsocks::crypto::CipherCategory;
use shadowsocks::relay::boxed_future;
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::tcprelay::{DecryptedRead, EncryptedWrite, TimeoutFuture};
use shadowsocks::{ServerAddr, ServerConfig};
use std::io;
use std::io::{BufRead, Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::write_all;
use tokio::io::{read_exact, ReadHalf, WriteHalf};
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

fn try_timeout<T, F>(
    fut: F,
    dur: Option<Duration>,
) -> impl Future<Item = T, Error = io::Error> + Send
where
    F: Future<Item = T, Error = io::Error> + Send + 'static,
    T: 'static,
{
    use tokio::prelude::*;

    match dur {
        Some(dur) => TimeoutFuture::Wait(fut.timeout(dur)),
        _ => TimeoutFuture::Direct(fut),
    }
}

pub fn connect_proxy_server(
    svr_cfg: Arc<ServerConfig>,
    async_resolver: &AsyncResolver,
) -> impl Future<Item = TcpStream, Error = io::Error> + Send {
    let timeout = svr_cfg.timeout();

    let svr_addr = svr_cfg.addr();

    debug!("Connecting to proxy {:?}, timeout: {:?}", svr_addr, timeout);
    match svr_addr {
        ServerAddr::SocketAddr(addr) => {
            addr;
            let fut = try_timeout(TcpStream::connect(addr), timeout);
            boxed_future(fut)
        }
        ServerAddr::DomainName(domain, port) => {
            let port = *port;
            let fut = {
                try_timeout(
                    async_resolver.lookup_ip(domain.as_str()).map_err(|e| {
                        debug!("resolve error: {}", e);
                        e.into()
                    }),
                    timeout,
                )
                .and_then(move |ips| {
                    let ip = ips.into_iter().next().unwrap();
                    let fut = TcpStream::connect(&SocketAddr::new(ip, port));
                    try_timeout(fut, timeout)
                })
                .map_err(|e| {
                    debug!("resolve error2: {}", e);
                    e
                })
            };
            boxed_future(fut)
        }
    }
}
