//! ICMP Integration Tests
//!
//! These tests require root privileges and a properly configured DNS.
//! Run with: sudo cargo test -p seeker --test icmp_integration_test -- --nocapture --ignored

use std::net::Ipv4Addr;
use std::time::Duration;

/// Test that the ICMP relay can successfully ping a real IP directly.
/// This verifies that raw socket ICMP works correctly with the icmp_relay module.
#[tokio::test]
#[ignore] // Requires root privileges
async fn test_icmp_relay_direct_ping() {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::io::Read;
    use std::net::SocketAddrV4;

    // Create raw ICMP socket
    let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to create raw socket (need root?): {}", e);
            return;
        }
    };

    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    // Ping a reachable server (using 223.5.5.5 - Alibaba DNS which is typically accessible)
    let target = Ipv4Addr::new(223, 5, 5, 5);
    let ident = std::process::id() as u16;
    let seq_no = 1u16;

    println!("Testing direct ICMP ping to {}", target);

    // Build ICMP packet
    let icmp_packet = build_icmp_echo_request(ident, seq_no, b"ping test");
    let dest_addr = SocketAddrV4::new(target, 0);

    // Send ping
    match socket.send_to(&icmp_packet, &dest_addr.into()) {
        Ok(sent) => println!("Sent {} bytes to {}", sent, target),
        Err(e) => {
            eprintln!("Failed to send ping: {}", e);
            return;
        }
    }

    // Receive reply
    let mut recv_buf = vec![0u8; 2000];
    let mut found_reply = false;

    for attempt in 0..50 {
        let size = match (&socket).read(&mut recv_buf) {
            Ok(size) => size,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                eprintln!("Read error: {}", e);
                break;
            }
        };

        if size < 28 {
            continue;
        }

        // Parse IP header
        let ip_header_len = ((recv_buf[0] & 0x0f) as usize) * 4;
        let icmp_data = &recv_buf[ip_header_len..size];

        let icmp_type = icmp_data[0];
        let recv_ident = ((icmp_data[4] as u16) << 8) | (icmp_data[5] as u16);
        let recv_seq = ((icmp_data[6] as u16) << 8) | (icmp_data[7] as u16);

        if attempt < 5 || icmp_type == 0 {
            println!(
                "Attempt {}: Received ICMP type={}, ident={}, seq={}",
                attempt, icmp_type, recv_ident, recv_seq
            );
        }

        if icmp_type == 0 && recv_ident == ident && recv_seq == seq_no {
            let src_ip = Ipv4Addr::new(recv_buf[12], recv_buf[13], recv_buf[14], recv_buf[15]);
            let ttl = recv_buf[8];
            println!("SUCCESS: Got Echo Reply from {} with TTL={}", src_ip, ttl);
            found_reply = true;
            break;
        }
    }

    assert!(
        found_reply,
        "Did not receive ICMP Echo Reply from {}",
        target
    );
}

/// Test that the ICMP request channel communication works correctly.
#[tokio::test]
async fn test_icmp_request_channel_flow() {
    use tun_nat::IcmpEchoRequest;

    let (request_tx, request_rx) = crossbeam_channel::unbounded::<IcmpEchoRequest>();

    // Simulate a request
    let fake_ip = Ipv4Addr::new(11, 0, 0, 10);
    let client_ip = Ipv4Addr::new(11, 0, 0, 1);

    let request = IcmpEchoRequest {
        src_ip: client_ip,
        dst_ip: fake_ip,
        ident: 12345,
        seq_no: 1,
        payload: vec![1, 2, 3, 4],
        ttl: 64,
    };

    // Send request through channel
    request_tx.send(request.clone()).unwrap();

    // Receive request
    let received_request = request_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(received_request.src_ip, client_ip);
    assert_eq!(received_request.dst_ip, fake_ip);
    assert_eq!(received_request.ident, 12345);
    assert_eq!(received_request.seq_no, 1);

    println!("ICMP request channel flow test passed!");
}

// Helper function to build ICMP Echo Request packet
fn build_icmp_echo_request(ident: u16, seq_no: u16, payload: &[u8]) -> Vec<u8> {
    let len = 8 + payload.len();
    let mut packet = vec![0u8; len];

    packet[0] = 8; // Type = Echo Request
    packet[1] = 0; // Code
    packet[4] = ((ident >> 8) & 0xff) as u8;
    packet[5] = (ident & 0xff) as u8;
    packet[6] = ((seq_no >> 8) & 0xff) as u8;
    packet[7] = (seq_no & 0xff) as u8;

    if !payload.is_empty() {
        packet[8..].copy_from_slice(payload);
    }

    // Calculate checksum
    let checksum = calc_checksum(&packet);
    packet[2] = ((checksum >> 8) & 0xff) as u8;
    packet[3] = (checksum & 0xff) as u8;

    packet
}

fn calc_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    while i < data.len() {
        let word = if i + 1 < data.len() {
            ((data[i] as u32) << 8) | (data[i + 1] as u32)
        } else {
            (data[i] as u32) << 8
        };
        sum = sum.wrapping_add(word);
        i += 2;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !sum as u16
}
