use std::{
    io::{ErrorKind, IoSlice, Result},
    net::SocketAddr,
    ops::DerefMut,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    task::Poll,
};

use nanorand::{tls_rng, Rng};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

use crate::Connection;

pub(crate) struct ObfsHttpTcpStream {
    addr: SocketAddr,
    conn: TcpStream,
    sent_first_request: Arc<AtomicBool>,
    recvd_first_response: Arc<AtomicBool>,
    host: String,

    // ObfsHttpTcpStream is a cloneable object, so we can use Arc<Mutex> to protect the state.
    recv_buf: Arc<Mutex<Vec<u8>>>,
}

impl Connection for ObfsHttpTcpStream {}

impl ObfsHttpTcpStream {
    pub(crate) async fn connect(addr: SocketAddr, host: String) -> std::io::Result<Self> {
        let conn = TcpStream::connect(addr).await?;

        Ok(ObfsHttpTcpStream {
            addr,
            conn,
            sent_first_request: Arc::new(AtomicBool::new(false)),
            recvd_first_response: Arc::new(AtomicBool::new(false)),
            host,
            recv_buf: Arc::new(Mutex::new(vec![])),
        })
    }

    /// Build initial HTTP request to the server.
    /// Returns the request as a slice of bytes.
    fn build_request(&mut self, content_length: usize) -> Vec<u8> {
        let mut rng = tls_rng();
        let random_num: u128 = rng.generate();
        let random_bytes = random_num.to_be_bytes();
        let key = base64::encode(random_bytes);
        let host = if self.addr.port() != 80 {
            format!("{}:{}", self.host, self.addr.port())
        } else {
            self.host.clone()
        };
        // Http Get request text
        let headers = [
            "GET / HTTP/1.1\r\n",
            "Host: ",
            host.as_str(),
            "\r\n",
            "User-Agent: curl/7.1.3\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Content-Length: ",
            content_length.to_string().as_str(),
            "\r\n",
            "Sec-WebSocket-Key: ",
            key.as_str(),
            "\r\n\r\n",
        ]
        .concat()
        .into_bytes();
        headers
    }
}

impl AsyncRead for ObfsHttpTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<Result<()>> {
        {
            let mut recv_buf = self.recv_buf.lock().unwrap();
            // If we have data in the buffer, copy it to the user's buffer.
            if !recv_buf.is_empty() {
                let consumed = recv_buf.len().min(buf.remaining());
                buf.put_slice(&recv_buf[..consumed]);
                recv_buf.drain(0..consumed);
                return Poll::Ready(Ok(()));
            }
        }

        if !self.recvd_first_response.load(Ordering::SeqCst) {
            let this = self.deref_mut();
            let mut recv_buf = this.recv_buf.lock().unwrap();
            // Initialize the receive buffer only once.
            recv_buf.resize(1024, 0);

            // Read the first response from the server.
            let mut read_buf = tokio::io::ReadBuf::new(&mut recv_buf);
            return match Pin::new(&mut this.conn).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    this.recvd_first_response.store(true, Ordering::SeqCst);
                    let total_read_size = read_buf.filled().len();

                    // Find the end of the headers.
                    let index = memchr::memmem::find(read_buf.filled(), b"\r\n\r\n");
                    match index {
                        Some(i) => {
                            // Offset of the real data.
                            let content_offset = i + 4;
                            let content_size = total_read_size - content_offset;
                            let consumed = content_size.min(buf.remaining());
                            buf.put_slice(
                                &read_buf.filled()[content_offset..content_offset + consumed],
                            );
                            // Remove the copied data from the buffer.
                            recv_buf.drain(0..content_offset + consumed);
                            // Truncate the buffer to the real size.
                            recv_buf.truncate(total_read_size - content_offset - consumed);
                            Poll::Ready(Ok(()))
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

impl AsyncWrite for ObfsHttpTcpStream {
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> std::task::Poll<Result<usize>> {
        if !self.sent_first_request.load(Ordering::SeqCst) {
            let buf_len = bufs.iter().map(|b| b.len()).sum();
            let send_buf = self.build_request(buf_len);
            self.sent_first_request.store(true, Ordering::SeqCst);

            let http_req_size = send_buf.len();
            let buf = IoSlice::new(&send_buf);
            let mut new_bufs = bufs.to_vec();
            new_bufs.insert(0, buf);

            let ret = Pin::new(&mut self.conn).poll_write_vectored(cx, &new_bufs);
            let ret = match ret {
                Poll::Ready(Ok(size)) => {
                    if size <= http_req_size {
                        return Poll::Ready(Err(ErrorKind::UnexpectedEof.into()));
                    }
                    Ok(size - http_req_size)
                }
                Poll::Ready(e) => e,
                Poll::Pending => {
                    panic!("obfs should be written once.");
                }
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
        if !self.sent_first_request.load(Ordering::SeqCst) {
            let mut send_buf = self.build_request(buf.len());
            self.sent_first_request.store(true, Ordering::SeqCst);

            let http_req_size = send_buf.len();
            send_buf.extend_from_slice(buf);

            let ret = Pin::new(&mut self.conn).poll_write(cx, &send_buf);
            let ret = match ret {
                Poll::Ready(Ok(size)) => {
                    // If the first request is not sent completely, abort.
                    assert!(size > http_req_size);
                    Ok(size - http_req_size)
                }
                Poll::Ready(e) => e,
                Poll::Pending => {
                    panic!("obfs should be written once.");
                }
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

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<()>> {
        Pin::new(&mut self.conn).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {

    use std::time::Duration;

    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        time::sleep,
    };
    // StreamExt removed as it's not available

    #[tokio::test]
    async fn test_obfs_http_connect() {
        const HOST: &str = "baidu.com";
        const REQ: &str = "hello";
        const RESP: &str = "world";

        let listener = TcpListener::bind("localhost:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::task::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
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

        handle.abort();
    }

    /// This test use docker so it can only be run in linux x86_64
    #[cfg(all(target_arch = "x86_64", target_env = "gnu"))]
    #[tokio::test]
    async fn test_obfs_docker_http_read_write() {
        use crate::run_obfs_server;
        use std::str::FromStr;

        const HOST: &str = "baidu.com";
        const REQ: &str = "hello";
        const RESP: &str = "world";

        let _c = run_obfs_server("http", 8388, 12345);

        let listener = TcpListener::bind("0.0.0.0:12345").await.unwrap();

        let handle = tokio::task::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = [0; 1024];
                let n = stream.read(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], REQ.as_bytes());
                let n = stream.write(RESP.as_bytes()).await.unwrap();
                assert_eq!(n, RESP.len());
            }
        });

        sleep(Duration::from_secs(1)).await;
        let mut stream = ObfsHttpTcpStream::connect(
            SocketAddr::from_str("127.0.0.1:8388").unwrap(),
            HOST.to_string(),
        )
        .await
        .unwrap();

        let mut buf = [0; 1024];
        let sent = stream.write(REQ.as_bytes()).await.unwrap();
        assert_eq!(sent, REQ.len());
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], RESP.as_bytes());

        handle.abort();
    }
}
