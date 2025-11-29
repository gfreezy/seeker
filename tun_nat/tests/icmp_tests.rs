//! ICMP unit tests.

use std::net::Ipv4Addr;
use std::time::Duration;
use tun_nat::IcmpEchoRequest;

/// Test ICMP request channel communication (no actual network).
#[test]
fn test_icmp_request_channel_communication() {
    let (request_tx, request_rx) = crossbeam_channel::unbounded::<IcmpEchoRequest>();

    // Send a request
    let request = IcmpEchoRequest {
        src_ip: Ipv4Addr::new(192, 168, 1, 100),
        dst_ip: Ipv4Addr::new(11, 0, 0, 10),
        ident: 5678,
        seq_no: 2,
        payload: vec![1, 2, 3, 4],
        ttl: 64,
    };
    request_tx.send(request.clone()).unwrap();

    // Receive the request
    let received = request_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(received.ident, 5678);
    assert_eq!(received.seq_no, 2);
    assert_eq!(received.src_ip, Ipv4Addr::new(192, 168, 1, 100));
    assert_eq!(received.dst_ip, Ipv4Addr::new(11, 0, 0, 10));
}
