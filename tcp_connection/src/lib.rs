use async_std::{
    io::{Read, Write},
    net::TcpStream,
    task::ready,
};
use dyn_clone::DynClone;
use nanorand::{tls_rng, Rng};
use serde::Deserialize;

use std::{
    fmt::Debug,
    io::{ErrorKind, IoSlice, IoSliceMut, Result},
    net::SocketAddr,
    ops::DerefMut,
    pin::Pin,
    sync::{Arc, Mutex},
    task::Poll,
    vec,
};

pub trait Connection: Read + Write + Unpin + Send + Sync + DynClone {}

dyn_clone::clone_trait_object!(Connection);

/// Combined async reader and writer, `futures 0.3` version.
/// Note that this struct is only present in `readwrite` if "asyncstd" Cargo feature is enabled.
#[derive(Clone)]
pub struct TcpConnection {
    inner: Box<dyn Connection>,
}

#[derive(Clone, Copy, PartialEq, Debug, Deserialize)]
pub enum ObfsMode {
    Http,
    // Ssl,
}

impl Connection for TcpStream {}
impl Connection for ObfsHttpTcpStream {}

impl TcpConnection {
    pub async fn connect_obfs(
        addr: SocketAddr,
        host: String,
        mode: ObfsMode,
    ) -> std::io::Result<Self> {
        let conn = match mode {
            ObfsMode::Http => {
                Box::new(ObfsHttpTcpStream::connect(addr, host).await?) as Box<dyn Connection>
            }
        };

        Ok(TcpConnection { inner: conn })
    }

    pub async fn connect_tcp(addr: SocketAddr) -> std::io::Result<Self> {
        let conn = Box::new(TcpStream::connect(addr).await?);

        Ok(TcpConnection { inner: conn })
    }

    pub fn new(conn: TcpStream) -> Self {
        TcpConnection {
            inner: Box::new(conn),
        }
    }
}

impl Read for TcpConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<Result<usize>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }

    fn poll_read_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
    ) -> std::task::Poll<Result<usize>> {
        Pin::new(&mut self.inner).poll_read_vectored(cx, bufs)
    }
}

impl Write for TcpConnection {
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> std::task::Poll<Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

#[derive(Clone)]
struct ObfsHttpTcpStream {
    conn: TcpStream,
    sent_first_request: bool,
    recvd_first_response: bool,
    host: String,

    recv_buf: Arc<Mutex<Vec<u8>>>,
}

impl ObfsHttpTcpStream {
    async fn connect(addr: SocketAddr, host: String) -> std::io::Result<Self> {
        let conn = TcpStream::connect(addr).await?;

        Ok(ObfsHttpTcpStream {
            conn,
            sent_first_request: false,
            recvd_first_response: false,
            host,
            recv_buf: Arc::new(Mutex::new(vec![])),
        })
    }

    fn build_request(&mut self, content_length: usize) -> Vec<u8> {
        let mut rng = tls_rng();

        let chars = (0..31)
            .map(|_| rng.generate::<u8>())
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        let key = chars.concat();

        // Http Get request text
        let headers = [
            "GET / HTTP/1.1\r\n",
            "Host: ",
            self.host.as_str(),
            "\r\n",
            "Connection: keep-alive\r\n",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36\r\n",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n",
            "Accept-Language: zh-CN,zh;q=0.9\r\n",
            "Accept-Encoding: gzip, deflate\r\n",
            "Content-Length: ",
            content_length.to_string().as_str(),
            "\r\n",
            "Upgrade-Insecure-Requests: 1\r\n",
            "Sec-Fetch-User: ?1\r\n",
            "Sec-Fetch-Site: same-origin\r\n",
            "Sec-Fetch-Mode: navigate\r\n",
            "Sec-Fetch-Dest: document\r\n",
            "Sec-WebSocket-Key: ",
            key.as_str(),
            "\r\n\r\n",
        ].concat().into_bytes();
        headers
    }
}

impl Read for ObfsHttpTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<Result<usize>> {
        {
            let mut recv_buf = self.recv_buf.lock().unwrap();
            if !recv_buf.is_empty() {
                let consumed = recv_buf.len().min(buf.len());
                buf[..consumed].copy_from_slice(&recv_buf[..consumed]);
                recv_buf.drain(0..consumed);
                return Poll::Ready(Ok(consumed));
            }
        }

        if !self.recvd_first_response {
            let this = self.deref_mut();
            let mut recv_buf = this.recv_buf.lock().unwrap();
            recv_buf.resize(1024, 0);

            return match Pin::new(&mut this.conn).poll_read(cx, &mut recv_buf) {
                Poll::Ready(Ok(total_read_size)) => {
                    this.recvd_first_response = true;

                    let index = memchr::memmem::find(&recv_buf, b"\r\n\r\n");
                    match index {
                        Some(i) => {
                            let content_offset = i + 4;
                            let content_size = total_read_size - content_offset;
                            let consumed = content_size.min(buf.len());
                            buf[..consumed].copy_from_slice(
                                &recv_buf[content_offset..content_offset + consumed],
                            );
                            recv_buf.drain(0..content_offset + consumed);
                            recv_buf.truncate(total_read_size - content_offset - consumed);
                            Poll::Ready(Ok(consumed))
                        }
                        None => Poll::Ready(Err(ErrorKind::UnexpectedEof.into())),
                    }
                }
                Poll::Ready(e) => Poll::Ready(e),
                Poll::Pending => {
                    recv_buf.truncate(0);
                    Poll::Pending
                }
            };
        }

        Pin::new(&mut self.conn).poll_read(cx, buf)
    }
}

impl Write for ObfsHttpTcpStream {
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> std::task::Poll<Result<usize>> {
        if !self.sent_first_request {
            let buf_len = bufs.iter().map(|b| b.len()).sum();
            let send_buf = self.build_request(buf_len);
            self.sent_first_request = true;

            let http_req_size = send_buf.len();
            let buf = IoSlice::new(&send_buf);
            let mut new_bufs = bufs.to_vec();
            new_bufs.insert(0, buf);

            let ret = ready!(Pin::new(&mut self.conn).poll_write_vectored(cx, &new_bufs));
            let ret = match ret {
                Ok(size) => {
                    if size <= http_req_size {
                        return Poll::Ready(Err(ErrorKind::UnexpectedEof.into()));
                    }
                    Ok(size - http_req_size)
                }
                e => e,
            };
            return Poll::Ready(ret);
        }
        Pin::new(&mut self.conn).poll_write_vectored(cx, bufs)
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize>> {
        if !self.sent_first_request {
            let mut send_buf = self.build_request(buf.len());
            self.sent_first_request = true;

            let http_req_size = send_buf.len();
            send_buf.extend_from_slice(buf);

            let ret = ready!(Pin::new(&mut self.conn).poll_write(cx, &send_buf));
            let ret = match ret {
                Ok(size) => {
                    assert!(size > http_req_size);
                    Ok(size - http_req_size)
                }
                e => e,
            };
            return Poll::Ready(ret);
        }
        Pin::new(&mut self.conn).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<()>> {
        Pin::new(&mut self.conn).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<()>> {
        Pin::new(&mut self.conn).poll_close(cx)
    }
}
