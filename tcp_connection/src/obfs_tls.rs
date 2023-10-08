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
    time::SystemTime,
};

use async_std::{
    io::{Read, Write},
    net::TcpStream,
};
use nanorand::{tls_rng, Rng};

use crate::Connection;

const HANDSHAKE_FOOT_LEN: usize = 84;
const MESSAGE_HEAD_LEN: usize = 5;

#[derive(Clone)]
pub(crate) struct ObfsTlsTcpStream {
    conn: TcpStream,
    sent_first_request: Arc<AtomicBool>,
    recvd_first_response: Arc<AtomicBool>,
    host: String,
    recv_buf: Arc<Mutex<Vec<u8>>>,
}

impl Connection for ObfsTlsTcpStream {}

impl ObfsTlsTcpStream {
    pub(crate) async fn connect(addr: SocketAddr, host: String) -> std::io::Result<Self> {
        let conn = TcpStream::connect(addr).await?;

        Ok(Self {
            conn,
            sent_first_request: Arc::new(AtomicBool::new(false)),
            recvd_first_response: Arc::new(AtomicBool::new(false)),
            host,
            recv_buf: Arc::new(Mutex::new(vec![])),
        })
    }

    fn build_handshake_head(&self, content_len: usize) -> Vec<u8> {
        let mut rng = tls_rng();
        let mut random = [0u8; 28];
        rng.fill_bytes(&mut random);
        let mut session_id = [0u8; 32];
        rng.fill_bytes(&mut session_id);
        let arg_length = content_len + self.host.len();
        let mut buf: Vec<u8> = Vec::new();

        buf.push(0x22);
        buf.extend(&[0x03, 0x01]);
        buf.push(((arg_length + 212) as u16 >> 8) as u8);
        buf.push(((arg_length + 212) as u16 & 0xff) as u8);
        buf.push(0x01);
        buf.push(0x00);
        buf.extend(&((208 + arg_length) as u16).to_be_bytes());
        buf.extend_from_slice(&[0x03, 0x03]);

        // // random with timestamp, sid len, sid
        let ts = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;
        buf.extend(ts.to_be_bytes());
        buf.extend(random);
        buf.push(0x32);
        buf.extend(session_id);

        // // cipher suites
        buf.extend(&[0x00, 0x38]);
        buf.extend(&[
            0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b,
            0xc0, 0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27,
            0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33,
            0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
        ]);
        // // compression
        buf.extend(&[0x01, 0x00]);
        // // extension length
        buf.extend(((arg_length + 79) as u16).to_be_bytes());
        // // session ticket
        buf.extend(&[0x00, 0x23]);
        buf.extend((content_len as u16).to_be_bytes());
        buf
    }

    fn build_handshake_foot(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        // // server name
        buf.extend(&[0x00, 0x00]);
        buf.extend(((self.host.len() + 5) as u16).to_be_bytes());
        buf.extend(((self.host.len() + 3) as u16).to_be_bytes());
        buf.push(0);
        buf.extend(((self.host.len()) as u16).to_be_bytes());
        buf.extend(self.host.as_bytes());
        // // ec_point

        buf.extend(&[0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02]);
        // // groups

        buf.extend(&[
            0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18,
        ]);
        // // signature
        buf.extend(&[
            0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01,
            0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02,
            0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
        ]);
        // // encrypt then mac

        buf.extend(&[0x00, 0x16, 0x00, 0x00]);
        // // extended master secret
        buf.extend(&[0x00, 0x17, 0x00, 0x00]);
        buf
    }

    fn build_message_head(content_len: usize) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::with_capacity(MESSAGE_HEAD_LEN);
        buf.extend(&[0x17, 0x03, 0x03]);
        buf.extend((content_len as u16).to_be_bytes());
        buf
    }
}

impl Read for ObfsTlsTcpStream {
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

        if !self.recvd_first_response.load(Ordering::SeqCst) {
            let this = self.deref_mut();
            let mut recv_buf = this.recv_buf.lock().unwrap();
            // Initialize the receive buffer only once.
            recv_buf.resize(1024, 0);

            // Read the first response from the server.
            return match Pin::new(&mut this.conn).poll_read(cx, &mut recv_buf) {
              Poll::Ready(Ok(total_read_size)) => {
                  this.recvd_first_response.store(true, Ordering::SeqCst);

                let content_size = total_read_size;
                let consumed = content_size.min(buf.len());
                buf[..consumed].copy_from_slice(
                    &recv_buf[0..consumed],
                );
                // Remove the copied data from the buffer.
                recv_buf.drain(0..consumed);
                // Truncate the buffer to the real size.
                recv_buf.truncate(total_read_size  - consumed);
                Poll::Ready(Ok(consumed))
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

impl Write for ObfsTlsTcpStream {
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> std::task::Poll<Result<usize>> {
        let buf_len = bufs.iter().map(|b| b.len()).sum();
        if !self.sent_first_request.load(Ordering::SeqCst) {
            let send_buf = self.build_handshake_head(buf_len);
            let send_buf2 = self.build_handshake_foot();
            self.sent_first_request.store(true, Ordering::SeqCst);

            let req_size = send_buf.len();
            let buf = IoSlice::new(&send_buf);
            let mut new_bufs = bufs.to_vec();
            new_bufs.insert(0, buf);
            new_bufs.push(IoSlice::new(&send_buf2));
            let ret = Pin::new(&mut self.conn).poll_write_vectored(cx, &new_bufs);
            let ret = match ret {
                Poll::Ready(Ok(size)) => {
                    if size <= req_size + HANDSHAKE_FOOT_LEN {
                        return Poll::Ready(Err(ErrorKind::UnexpectedEof.into()));
                    }
                    Ok(size - req_size - HANDSHAKE_FOOT_LEN)
                }
                Poll::Ready(e) => e,
                Poll::Pending => {
                    panic!("obfs should be written once.");
                }
            };
            return Poll::Ready(ret);
        }

        match Pin::new(&mut self.conn).poll_write(cx, &Self::build_message_head(buf_len)) {
            Poll::Ready(Ok(size)) => {
                if size <= MESSAGE_HEAD_LEN {
                    return Poll::Ready(Err(ErrorKind::UnexpectedEof.into()));
                }
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => {
                panic!("obfs should be written at once.");
            }
        }
        Pin::new(&mut self.conn).poll_write_vectored(cx, bufs)
    }

    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize>> {
        if !self.sent_first_request.load(Ordering::SeqCst) {
            let mut send_buf = self.build_handshake_head(buf.len());
            self.sent_first_request.store(true, Ordering::SeqCst);

            let req_size = send_buf.len();
            send_buf.extend_from_slice(buf);
            send_buf.extend(self.build_handshake_foot());

            let ret = Pin::new(&mut self.conn).poll_write(cx, &send_buf);
            let ret = match ret {
                Poll::Ready(Ok(size)) => {
                    // If the first request is not sent completely, abort.
                    assert!(size > req_size + HANDSHAKE_FOOT_LEN);
                    Ok(size - req_size - HANDSHAKE_FOOT_LEN)
                }
                Poll::Ready(e) => e,
                Poll::Pending => {
                    panic!("obfs should be written once.");
                }
            };
            return Poll::Ready(ret);
        }

        match Pin::new(&mut self.conn).poll_write(cx, &Self::build_message_head(buf.len())) {
            Poll::Ready(Ok(size)) => {
                if size <= MESSAGE_HEAD_LEN {
                    return Poll::Ready(Err(ErrorKind::UnexpectedEof.into()));
                }
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => {
                panic!("obfs should be written at once.");
            }
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

    

    const HANDSHAKE_HEAD_LEN: usize = 142;

    #[async_std::test]
    async fn test_obfs_tls_connect() {
        const HOST: &str = "baidu.com";
        const REQ: &str = "hello";
        const RESP: &str = "world"; // not actual encrypted response

        let listener = TcpListener::bind("localhost:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = spawn(async move {
            while let Some(conn) = listener.incoming().next().await {
                let mut stream = conn.unwrap();
                let mut buf = [0; 1024];
                let n = stream.read(&mut buf).await.unwrap();
                assert_eq!(n, HANDSHAKE_HEAD_LEN + REQ.len() + HANDSHAKE_FOOT_LEN);
                let _ = stream.write(RESP.as_bytes()).await.unwrap();
            }
        });

        sleep(Duration::from_secs(1)).await;
        let mut stream = ObfsTlsTcpStream::connect(addr, HOST.to_string())
            .await
            .unwrap();

        let mut buf = [0; 1024];
        let sent = stream.write(REQ.as_bytes()).await.unwrap();

        assert_eq!(sent, REQ.len());
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], RESP.as_bytes());

        let _ = handle.cancel().await;
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
    #[async_std::test]
    async fn test_obfs_docker_tls_read_write() {
        const HOST: &str = "baidu.com";
        const REQ: &str = "hello";
        const RESP: &str = "world";

        let docker = Cli::default();
        let _c = run_obfs_server(&docker, "tls", 8389, 12346);

        let listener = TcpListener::bind("0.0.0.0:12346").await.unwrap();

        let handle = spawn(async move {
            while let Some(conn) = listener.incoming().next().await {
                let mut stream = conn.unwrap();
                let mut buf = [0; 1024];
                let n = stream.read(&mut buf).await.unwrap();
                assert_eq!(
                    &buf[HANDSHAKE_HEAD_LEN..HANDSHAKE_HEAD_LEN + REQ.len()],
                    REQ.as_bytes()
                );
                let n = stream.write(RESP.as_bytes()).await.unwrap();
                assert_eq!(n, RESP.len());
            }
        });

        sleep(Duration::from_secs(1)).await;
        let mut stream = ObfsTlsTcpStream::connect(
            SocketAddr::from_str("127.0.0.1:8389").unwrap(),
            HOST.to_string(),
        )
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
