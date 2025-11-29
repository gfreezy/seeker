//! Test raw ICMP socket functionality.
//!
//! This test requires root privileges to run.
//! Run with: sudo cargo test -p tun_nat --test icmp_raw_socket_test -- --nocapture

use socket2::{Domain, Protocol, Socket, Type};
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

/// Calculate ICMP checksum
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

/// Build an ICMP Echo Request packet (without IP header)
fn build_icmp_echo_request(ident: u16, seq_no: u16, payload: &[u8]) -> Vec<u8> {
    let len = 8 + payload.len();
    let mut packet = vec![0u8; len];

    packet[0] = 8; // Type = Echo Request
    packet[1] = 0; // Code
                   // Checksum at [2..4] - filled later
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

#[test]
#[ignore] // Requires root privileges
fn test_raw_icmp_socket_ping() {
    // Create raw ICMP socket
    let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to create raw socket (need root?): {}", e);
            return;
        }
    };

    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();

    // Ping 1.1.1.1 (Cloudflare DNS) - using this instead of 8.8.8.8 as it may be more reliable
    let target = Ipv4Addr::new(1, 1, 1, 1);
    let ident = std::process::id() as u16;
    let seq_no = 1u16;
    let payload = b"test ping".to_vec();

    let icmp_packet = build_icmp_echo_request(ident, seq_no, &payload);
    let dest_addr = SocketAddrV4::new(target, 0);

    println!(
        "Sending ICMP Echo Request to {} (ident={}, seq={})",
        target, ident, seq_no
    );

    match socket.send_to(&icmp_packet, &dest_addr.into()) {
        Ok(sent) => println!("Sent {} bytes", sent),
        Err(e) => {
            eprintln!("Failed to send: {}", e);
            return;
        }
    }

    // Receive reply
    let mut recv_buf = vec![0u8; 2000];
    let mut found_reply = false;

    for _ in 0..10 {
        let size = match (&socket).read(&mut recv_buf) {
            Ok(size) => size,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
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

        println!(
            "Received ICMP: type={}, ident={}, seq={} (expecting ident={}, seq={})",
            icmp_type, recv_ident, recv_seq, ident, seq_no
        );

        // Check if it's our reply (type 0 = Echo Reply)
        if icmp_type == 0 && recv_ident == ident && recv_seq == seq_no {
            let src_ip = Ipv4Addr::new(recv_buf[12], recv_buf[13], recv_buf[14], recv_buf[15]);
            let ttl = recv_buf[8];
            println!("Got Echo Reply from {} with TTL={}", src_ip, ttl);
            found_reply = true;
            break;
        }
    }

    assert!(found_reply, "Did not receive ICMP Echo Reply");
}

#[test]
#[ignore] // Requires root privileges
fn test_raw_icmp_socket_localhost() {
    // Create raw ICMP socket
    let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to create raw socket (need root?): {}", e);
            return;
        }
    };

    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    // Ping localhost
    let target = Ipv4Addr::new(127, 0, 0, 1);
    let ident = (std::process::id() + 1) as u16;
    let seq_no = 1u16;
    let payload = b"localhost test".to_vec();

    let icmp_packet = build_icmp_echo_request(ident, seq_no, &payload);
    let dest_addr = SocketAddrV4::new(target, 0);

    println!(
        "Sending ICMP Echo Request to localhost (ident={}, seq={})",
        ident, seq_no
    );

    match socket.send_to(&icmp_packet, &dest_addr.into()) {
        Ok(sent) => println!("Sent {} bytes to localhost", sent),
        Err(e) => {
            eprintln!("Failed to send to localhost: {}", e);
            return;
        }
    }

    // Receive reply
    let mut recv_buf = vec![0u8; 2000];
    let mut found_reply = false;

    for attempt in 0..20 {
        let size = match (&socket).read(&mut recv_buf) {
            Ok(size) => size,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    println!("Attempt {}: WouldBlock", attempt);
                    continue;
                }
                eprintln!("Read error: {}", e);
                break;
            }
        };

        if size < 28 {
            continue;
        }

        let ip_header_len = ((recv_buf[0] & 0x0f) as usize) * 4;
        let icmp_data = &recv_buf[ip_header_len..size];

        let icmp_type = icmp_data[0];
        let recv_ident = ((icmp_data[4] as u16) << 8) | (icmp_data[5] as u16);
        let recv_seq = ((icmp_data[6] as u16) << 8) | (icmp_data[7] as u16);

        println!(
            "Attempt {}: Received ICMP type={}, ident={}, seq={}",
            attempt, icmp_type, recv_ident, recv_seq
        );

        if icmp_type == 0 && recv_ident == ident && recv_seq == seq_no {
            println!("Got Echo Reply from localhost");
            found_reply = true;
            break;
        }
    }

    assert!(
        found_reply,
        "Did not receive ICMP Echo Reply from localhost"
    );
}
