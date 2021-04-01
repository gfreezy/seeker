//! client for sending DNS queries to other servers

use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;

use crate::dns::buffer::{BytePacketBuffer, PacketBuffer};
use crate::dns::protocol::{DnsPacket, DnsQuestion, QueryType};
use async_std::channel::{bounded, Receiver, Sender};
use async_std::future;
use async_std::io::timeout;
use async_std::net::UdpSocket;
use async_std::prelude::FutureExt;
use async_std::task;
use async_trait::async_trait;
use std::time::Duration;
use tracing::{error, trace, trace_span};
use tracing_futures::Instrument;

#[async_trait]
pub trait DnsClient {
    fn get_sent_count(&self) -> usize;
    fn get_failed_count(&self) -> usize;

    async fn send_query(
        &self,
        qname: &str,
        qtype: QueryType,
        server: (&str, u16),
        recursive: bool,
    ) -> Result<DnsPacket>;
}

/// The UDP client
///
/// This includes a fair bit of synchronization due to the stateless nature of UDP.
/// When many queries are sent in parallell, the response packets can come back
/// in any order. For that reason, we fire off replies on the sending thread, but
/// handle replies on a single thread. A channel is created for every response,
/// and the caller will block on the channel until the a response is received.
#[derive(Clone)]
pub struct DnsNetworkClient {
    total_sent: Arc<AtomicUsize>,
    total_failed: Arc<AtomicUsize>,

    /// Counter for assigning packet ids
    seq: Arc<AtomicUsize>,
    port: u16,
    timeout: Duration,

    sender: Sender<DnsRequest>,
    receiver: Receiver<DnsRequest>,
}

struct DnsRequest {
    packet: DnsPacket,
    server: (String, u16),
    resp: Sender<DnsPacket>,
}

impl DnsNetworkClient {
    pub async fn new(bind_port: u16, timeout: Duration) -> DnsNetworkClient {
        let (sender, receiver) = bounded(1);
        let client = DnsNetworkClient {
            total_sent: Arc::new(AtomicUsize::new(0)),
            total_failed: Arc::new(AtomicUsize::new(0)),
            seq: Arc::new(AtomicUsize::new(0)),
            port: bind_port,
            timeout,
            sender,
            receiver,
        };

        let c = client.clone();
        let _ = task::spawn(
            async move {
                loop {
                    match c.run().await {
                        Ok(_) => {}
                        Err(e) => {
                            error!(error=?e, "dns error");
                        }
                    }
                }
            }
            .instrument(trace_span!("background dns runner")),
        );
        client
    }

    #[allow(unreachable_code)]
    pub async fn run(&self) -> Result<()> {
        let addr = format!("0.0.0.0:{}", self.port);
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        let req_resp_map: Arc<Mutex<HashMap<u16, Sender<DnsPacket>>>> =
            Arc::new(Mutex::new(HashMap::with_capacity(10)));

        let req_resp_map2 = req_resp_map.clone();
        let socket2 = socket.clone();
        let t2 = self.timeout;

        let read_task = async move {
            // Read data into a buffer
            let mut res_buffer = BytePacketBuffer::new();
            loop {
                res_buffer.seek(0)?;
                let (size, src) = socket2.recv_from(&mut res_buffer.buf).await?;
                trace!(size = size, src = ?src, "recv dns packet from udp");
                assert!(res_buffer.buf.len() >= size);

                // Construct a DnsPacket from buffer, skipping the packet if parsing
                // failed
                if let Ok(packet) = DnsPacket::from_buffer(&mut res_buffer) {
                    let resp = { req_resp_map2.lock().unwrap().remove(&packet.header.id) };
                    if let Some(resp) = resp {
                        resp.send(packet).await.expect("send error");
                    }
                } else {
                    error!("invalid udp packet");
                }
            }
            Ok::<(), Error>(())
        };

        let req_receiver = self.receiver.clone();
        let write_task = async move {
            let mut req_buffer = BytePacketBuffer::new();
            while let Ok(mut req) = req_receiver.recv().await {
                let server = (req.server.0.as_str(), req.server.1);
                req_buffer.seek(0)?;
                req.packet.write(&mut req_buffer, 512)?;
                let size = timeout(
                    t2,
                    socket.send_to(&req_buffer.buf[0..req_buffer.pos], server),
                )
                .await?;
                assert_eq!(size, req_buffer.pos);
                {
                    req_resp_map
                        .lock()
                        .unwrap()
                        .insert(req.packet.header.id, req.resp);
                }
            }
            Ok::<(), Error>(())
        };

        read_task.race(write_task).await?;
        Ok(())
    }

    /// Send a DNS query using UDP transport
    ///
    /// This will construct a query packet, and fire it off to the specified server.
    /// The query is sent from the callee thread, but responses are read on a
    /// worker thread, and returned to this thread through a channel. Thus this
    /// method is thread safe, and can be used from any number of threads in
    /// parallell.
    async fn send_udp_query(
        &self,
        qname: &str,
        qtype: QueryType,
        (server, port): (&str, u16),
        recursive: bool,
    ) -> Result<DnsPacket> {
        let _ = self.total_sent.fetch_add(1, Ordering::Release);

        // Prepare request
        let mut packet = DnsPacket::new();

        packet.header.id = self.seq.fetch_add(1, Ordering::SeqCst) as u16;
        if packet.header.id + 1 == 0xFFFF {
            let _ = self
                .seq
                .compare_exchange(0xFFFF, 0, Ordering::SeqCst, Ordering::SeqCst);
        }

        packet.header.questions = 1;
        packet.header.recursion_desired = recursive;

        packet
            .questions
            .push(DnsQuestion::new(qname.to_string(), qtype));

        let (sender, receiver) = bounded(1);

        self.sender
            .send(DnsRequest {
                packet,
                server: (server.to_string(), port),
                resp: sender,
            })
            .await
            .expect("send error");

        match future::timeout(self.timeout, receiver.recv()).await {
            Ok(Ok(qr)) => Ok(qr),
            Ok(Err(_)) => {
                let _ = self.total_failed.fetch_add(1, Ordering::Release);
                Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("Domain {} not found", qname),
                ))
            }
            Err(_) => {
                let _ = self.total_failed.fetch_add(1, Ordering::Release);
                Err(Error::new(
                    ErrorKind::TimedOut,
                    format!("Domain \"{}\" resolve timed out", qname),
                ))
            }
        }
    }
}

#[async_trait]
impl DnsClient for DnsNetworkClient {
    fn get_sent_count(&self) -> usize {
        self.total_sent.load(Ordering::Acquire)
    }

    fn get_failed_count(&self) -> usize {
        self.total_failed.load(Ordering::Acquire)
    }

    async fn send_query(
        &self,
        qname: &str,
        qtype: QueryType,
        server: (&str, u16),
        recursive: bool,
    ) -> Result<DnsPacket> {
        let packet = self.send_udp_query(qname, qtype, server, recursive).await?;
        if !packet.header.truncated_message {
            return Ok(packet);
        }

        eprint!("error resolve domain: {}", qname);
        Err(Error::new(ErrorKind::UnexpectedEof, "truncated message"))
    }
}

#[cfg(test)]
pub mod tests {
    use std::io::Result;
    use std::time::Duration;

    use async_std::io::timeout;
    use async_std::task::block_on;

    use crate::dns::protocol::{DnsPacket, DnsRecord, QueryType};

    use super::*;

    pub type StubCallback = dyn Fn(&str, QueryType, (&str, u16), bool) -> Result<DnsPacket>;

    pub struct DnsStubClient {
        callback: Box<StubCallback>,
    }

    impl<'a> DnsStubClient {
        pub fn new(callback: Box<StubCallback>) -> DnsStubClient {
            DnsStubClient { callback }
        }
    }

    unsafe impl Send for DnsStubClient {}

    unsafe impl Sync for DnsStubClient {}

    #[async_trait]
    impl DnsClient for DnsStubClient {
        fn get_sent_count(&self) -> usize {
            0
        }

        fn get_failed_count(&self) -> usize {
            0
        }

        async fn send_query(
            &self,
            qname: &str,
            qtype: QueryType,
            server: (&str, u16),
            recursive: bool,
        ) -> Result<DnsPacket> {
            (self.callback)(qname, qtype, server, recursive)
        }
    }

    #[test]
    pub fn test_udp_client() {
        block_on(async {
            let client = DnsNetworkClient::new(31456, Duration::from_secs(3)).await;
            let dns = std::env::var("DNS").unwrap_or_else(|_| "223.5.5.5".to_string());

            let res = timeout(
                Duration::from_secs(3),
                client.send_udp_query("google.com", QueryType::A, (&dns, 53), true),
            )
            .await
            .unwrap();

            assert_eq!(res.questions[0].name, "google.com");
            assert!(!res.answers.is_empty());

            match res.answers[0] {
                DnsRecord::A { ref domain, .. } => {
                    assert_eq!("google.com", domain);
                }
                _ => panic!(),
            }
        });
    }
}
