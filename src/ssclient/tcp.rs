use super::ahead::DecryptedReader as AeadDecryptedReader;
use super::ahead::EncryptedWriter as AeadEncryptedWriter;
use super::stream::DecryptedReader as StreamDecryptedReader;
use super::stream::EncryptedWriter as StreamEncryptedWriter;
use byte_string::ByteStr;
use bytes::{BufMut, BytesMut};
use futures::TryStreamExt;
use log::debug;
use log::trace;
use shadowsocks::crypto::CipherCategory;
use shadowsocks::relay::boxed_future;
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::tcprelay::{DecryptedRead, EncryptedWrite, TimeoutFuture};
use shadowsocks::{Config, ConfigType, ServerAddr, ServerConfig};
use std::io;
use std::io::{BufRead, Read, Write};
use std::net::{IpAddr, SocketAddr};
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
        //        Some(dur) => TimeoutFuture::Wait(fut.timeout(dur)),
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
            dbg!(addr);
            let fut = try_timeout(TcpStream::connect(addr), timeout);
            boxed_future(fut)
        }
        ServerAddr::DomainName(domain, port) => {
            dbg!(domain, port);
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
                    dbg!(&ips);
                    let ip = ips.into_iter().next().unwrap();
                    let fut = TcpStream::connect(&SocketAddr::new(ip, port));
                    try_timeout(fut, timeout)
                })
                .map_err(|e| {
                    debug!("resolve error: {}", e);
                    e
                })
            };
            boxed_future(fut)
        }
    }
}

/// Handshake logic for ShadowSocks Client
pub fn proxy_server_handshake<S>(
    remote_stream: S,
    svr_cfg: Arc<ServerConfig>,
    relay_addr: Address,
) -> io::Result<(
    impl Future<Item = DecryptedHalf<S>, Error = io::Error> + Send,
    impl Future<Item = EncryptedHalf<S>, Error = io::Error> + Send,
)>
where
    S: Read + Write + AsyncRead + AsyncWrite + Send + 'static,
{
    let timeout = svr_cfg.timeout();
    proxy_handshake(remote_stream, svr_cfg).map(move |(r_fut, w_fut)| {
        let w_fut = w_fut.and_then(move |enc_w| {
            // Send relay address to remote
            let mut buf = BytesMut::with_capacity(relay_addr.len());
            relay_addr.write_to_buf(&mut buf);

            trace!(
                "Got encrypt stream and going to send addr: {:?}, buf: {:?}",
                relay_addr,
                buf
            );

            try_timeout(enc_w.write_all(buf), timeout).map(|(w, _)| w)
        });

        (r_fut, w_fut)
    })
}

/// ShadowSocks Client-Server handshake protocol
/// Exchange cipher IV and creates stream wrapper
pub fn proxy_handshake<S>(
    remote_stream: S,
    svr_cfg: Arc<ServerConfig>,
) -> io::Result<(
    impl Future<Item = DecryptedHalf<S>, Error = io::Error> + Send,
    impl Future<Item = EncryptedHalf<S>, Error = io::Error> + Send,
)>
where
    S: Read + Write + AsyncRead + AsyncWrite + Send + 'static,
{
    let (r, w) = remote_stream.split();
    let timeout = svr_cfg.timeout();

    let svr_cfg_cloned = svr_cfg.clone();

    let enc = {
        // Encrypt data to remote server

        // Send initialize vector to remote and create encryptor

        let method = svr_cfg.method();
        let prev_buf = match method.category() {
            CipherCategory::Stream => {
                let local_iv = method.gen_init_vec();
                trace!("Going to send initialize vector: {:?}", local_iv);
                local_iv
            }
            CipherCategory::Aead => {
                let local_salt = method.gen_salt();
                trace!("Going to send salt: {:?}", local_salt);
                local_salt
            }
        };

        try_timeout(write_all(w, prev_buf), timeout).and_then(move |(w, prev_buf)| {
            match svr_cfg.method().category() {
                CipherCategory::Stream => {
                    let local_iv = prev_buf;
                    let wtr =
                        StreamEncryptedWriter::new(w, svr_cfg.method(), svr_cfg.key(), &local_iv);
                    Ok(From::from(wtr))
                }
                CipherCategory::Aead => {
                    let local_salt = prev_buf;
                    let wtr = AeadEncryptedWriter::new(
                        w,
                        svr_cfg.method(),
                        svr_cfg.key(),
                        &local_salt[..],
                    );
                    Ok(From::from(wtr))
                }
            }
        })
    };

    let dec = {
        let svr_cfg = svr_cfg_cloned;

        // Decrypt data from remote server

        let method = svr_cfg.method();
        let prev_len = match method.category() {
            CipherCategory::Stream => method.iv_size(),
            CipherCategory::Aead => method.salt_size(),
        };

        try_timeout(read_exact(r, vec![0u8; prev_len]), timeout).and_then(move |(r, remote_iv)| {
            match svr_cfg.method().category() {
                CipherCategory::Stream => {
                    trace!("Got initialize vector {:?}", ByteStr::new(&remote_iv));
                    let decrypt_stream =
                        StreamDecryptedReader::new(r, svr_cfg.method(), svr_cfg.key(), &remote_iv);
                    Ok(From::from(decrypt_stream))
                }
                CipherCategory::Aead => {
                    trace!("Got salt {:?}", ByteStr::new(&remote_iv));
                    let dr =
                        AeadDecryptedReader::new(r, svr_cfg.method(), svr_cfg.key(), &remote_iv);
                    Ok(From::from(dr))
                }
            }
        })
    };

    Ok((dec, enc))
}
