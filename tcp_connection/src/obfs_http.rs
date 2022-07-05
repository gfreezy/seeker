use std::{
    io::{ErrorKind, IoSlice, Result},
    net::SocketAddr,
    ops::DerefMut,
    pin::Pin,
    sync::{Arc, Mutex},
    task::Poll,
};

use async_std::{
    io::{Read, Write},
    net::TcpStream,
    task::ready,
};
use nanorand::{tls_rng, Rng};

use crate::Connection;

#[derive(Clone)]
pub(crate) struct ObfsHttpTcpStream {
    conn: TcpStream,
    sent_first_request: bool,
    recvd_first_response: bool,
    host: String,

    // ObfsHttpTcpStream is a cloneable object, so we can use Arc<Mutex> to protect the state.
    recv_buf: Arc<Mutex<Vec<u8>>>,
}

impl Connection for ObfsHttpTcpStream {}

impl ObfsHttpTcpStream {
    /// Constructs a new ObfsHttpTcpStream from TcpStream, used only in tests.
    #[cfg(test)]
    fn new(conn: TcpStream, host: String) -> Self {
        ObfsHttpTcpStream {
            conn,
            sent_first_request: false,
            recvd_first_response: false,
            host,
            recv_buf: Arc::new(Mutex::new(vec![])),
        }
    }

    pub(crate) async fn connect(addr: SocketAddr, host: String) -> std::io::Result<Self> {
        let conn = TcpStream::connect(addr).await?;

        Ok(ObfsHttpTcpStream {
            conn,
            sent_first_request: false,
            recvd_first_response: false,
            host,
            recv_buf: Arc::new(Mutex::new(vec![])),
        })
    }

    /// Build initial HTTP request to the server.
    /// Returns the request as a slice of bytes.
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
            // If we have data in the buffer, copy it to the user's buffer.
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
            // Initialize the receive buffer only once.
            recv_buf.resize(1024, 0);

            // Read the first response from the server.
            return match Pin::new(&mut this.conn).poll_read(cx, &mut recv_buf) {
                Poll::Ready(Ok(total_read_size)) => {
                    this.recvd_first_response = true;

                    // Find the end of the headers.
                    let index = memchr::memmem::find(&recv_buf, b"\r\n\r\n");
                    match index {
                        Some(i) => {
                            // Offset of the real data.
                            let content_offset = i + 4;
                            let content_size = total_read_size - content_offset;
                            let consumed = content_size.min(buf.len());
                            buf[..consumed].copy_from_slice(
                                &recv_buf[content_offset..content_offset + consumed],
                            );
                            // Remove the copied data from the buffer.
                            recv_buf.drain(0..content_offset + consumed);
                            // Truncate the buffer to the real size.
                            recv_buf.truncate(total_read_size - content_offset - consumed);
                            Poll::Ready(Ok(consumed))
                        }
                        None => Poll::Ready(Err(ErrorKind::UnexpectedEof.into())),
                    }
                }
                Poll::Ready(e)  // Error encountered, abort.
                    => Poll::Ready(e),
                Poll::Pending // Data not ready, continue.
                    => {
                    // If the first response is not ready, truncate the receive buffer. Avoid dirtying the buffer.
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
                    // If the first request is not sent completely, abort.
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use async_std::{
        io::{ReadExt, WriteExt},
        net::TcpListener,
        prelude::StreamExt,
        task::{sleep, spawn},
    };

    #[async_std::test]
    async fn test_obfs_http_connect() {
        const HOST: &str = "baidu.com";
        const REQ: &str = "hello";
        const RESP: &str = "world";

        let listener = TcpListener::bind("localhost:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = spawn(async move {
            while let Some(conn) = listener.incoming().next().await {
                let mut stream = conn.unwrap();
                let mut buf = [0; 1024];
                let n = stream.read(&mut buf).await.unwrap();
                let header_end = memchr::memmem::find(&buf, b"\r\n\r\n").unwrap();
                let content_offset = header_end + 4;
                assert_eq!(&buf[content_offset..n], REQ.as_bytes());
                let resp = "HTTP/1.1 200 OK\r\n\r\n".to_string() + RESP;
                let n = stream.write(resp.as_bytes()).await.unwrap();
                assert_eq!(n, resp.len());
            }
        });

        sleep(Duration::from_secs(1)).await;
        let mut stream = ObfsHttpTcpStream::connect(addr, HOST.to_string())
            .await
            .unwrap();

        let mut buf = [0; 1024];
        let sent = stream.write(REQ.as_bytes()).await.unwrap();
        assert_eq!(sent, REQ.len());
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], RESP.as_bytes());

        let _ = handle.cancel().await;
    }
}
