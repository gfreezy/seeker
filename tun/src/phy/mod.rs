use async_std::io::{Read, Write};
use async_std::net::driver::Watcher;
use std::io;
use std::io::{Read as _, Write as _};
use std::pin::Pin;
use std::task::{Context, Poll};
mod sys;

pub(crate) struct TunSocket {
    mtu: usize,
    name: String,
    watcher: Watcher<sys::TunSocket>,
}

impl TunSocket {
    pub fn new(name: &str) -> TunSocket {
        let watcher = Watcher::new(sys::TunSocket::new(name).expect("TunSocket::new"));
        TunSocket {
            name: watcher.get_ref().name().expect("get name"),
            mtu: watcher.get_ref().mtu().expect("get mut"),
            watcher,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }
}

impl Read for TunSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut &*self).poll_read(cx, buf)
    }
}

impl Read for &TunSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.watcher.poll_read_with(cx, |mut inner| inner.read(buf))
    }
}

impl Write for TunSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut &*self).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut &*self).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut &*self).poll_close(cx)
    }
}

impl Write for &TunSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.watcher
            .poll_write_with(cx, |mut inner| inner.write(buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.watcher.poll_write_with(cx, |mut inner| inner.flush())
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_std::io::timeout;
    use async_std::net::UdpSocket;
    use async_std::task;
    use async_std::task::block_on;
    use futures::{AsyncReadExt, AsyncWriteExt};
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::*;
    use std::time::Duration;
    use sysconfig::setup_ip;

    #[test]
    fn test_recv_packets_from_tun() {
        let tun_name = "utun5";
        let mut tun_socket = TunSocket::new(tun_name);
        if cfg!(target_os = "macos") {
            setup_ip(tun_name, "10.0.1.1", "10.0.1.0/24");
        } else {
            setup_ip(tun_name, "10.0.1.1/24", "10.0.1.0/24");
        }

        const DATA: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];

        block_on(async move {
            task::spawn(async {
                task::sleep(Duration::from_secs(1)).await;
                let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
                socket.send_to(&DATA, ("10.0.1.2", 9090)).await.unwrap();
            });

            let (buf, size) = loop {
                let mut buf = vec![0; 1024];
                let size = tun_socket.read(&mut buf).await.unwrap();
                // process ipv4 only
                if size > 0 && IpVersion::of_packet(&buf[..size]).unwrap() == IpVersion::Ipv4 {
                    break (buf, size);
                }
            };
            let ipv4_packet = Ipv4Packet::new_unchecked(&buf[..size]);
            let ipv4_repr =
                Ipv4Repr::parse(&ipv4_packet, &ChecksumCapabilities::default()).unwrap();
            assert_eq!(ipv4_repr.protocol, IpProtocol::Udp);
            let udp_packet = UdpPacket::new_unchecked(&buf[ipv4_repr.buffer_len()..size]);
            let udp_repr = UdpRepr::parse(
                &udp_packet,
                &ipv4_repr.src_addr.into(),
                &ipv4_repr.dst_addr.into(),
                &ChecksumCapabilities::default(),
            )
            .unwrap();
            assert_eq!(udp_repr.dst_port, 9090);
            assert_eq!(udp_repr.payload, DATA);
        })
    }

    #[test]
    fn test_send_packets_to_tun() {
        let tun_name = "utun6";
        let mut tun_socket = TunSocket::new(tun_name);
        if cfg!(target_os = "macos") {
            setup_ip(tun_name, "10.0.2.1", "10.0.2.0/24");
        } else {
            setup_ip(tun_name, "10.0.2.1/24", "10.0.2.0/24");
        }

        let data = "hello".as_bytes();

        block_on(async move {
            let socket = UdpSocket::bind("0.0.0.0:1234").await.unwrap();
            let handle = task::spawn(async move {
                let mut buf = vec![0; 1000];
                timeout(Duration::from_secs(10), socket.recv_from(&mut buf)).await
            });
            task::sleep(Duration::from_secs(1)).await;

            let src_addr = Ipv4Address::new(10, 0, 2, 10);
            let dst_addr = Ipv4Address::new(10, 0, 2, 1);
            let udp_repr = UdpRepr {
                src_port: 1234,
                dst_port: 1234,
                payload: &data,
            };
            let mut udp_buf = vec![0; udp_repr.buffer_len()];
            let mut udp_packet = UdpPacket::new_unchecked(&mut udp_buf);
            udp_repr.emit(
                &mut udp_packet,
                &src_addr.into(),
                &dst_addr.into(),
                &ChecksumCapabilities::default(),
            );
            let ip_repr = Ipv4Repr {
                src_addr,
                dst_addr,
                protocol: IpProtocol::Udp,
                payload_len: udp_packet.len() as usize,
                hop_limit: 64,
            };
            let mut ip_buf = vec![0; ip_repr.buffer_len() + ip_repr.payload_len];
            let mut ip_packet = Ipv4Packet::new_unchecked(&mut ip_buf);
            ip_repr.emit(&mut ip_packet, &ChecksumCapabilities::default());
            ip_buf[ip_repr.buffer_len()..].copy_from_slice(&udp_buf);
            let size = tun_socket.write(&ip_buf).await.unwrap();
            assert_eq!(size, ip_buf.len());
            let (s, _src) = handle.await.unwrap();
            assert_eq!(data.len(), s);
        })
    }
}
