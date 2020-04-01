use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::thread;

fn main() {
    thread::spawn(move || {
        let udp_socket = UdpSocket::bind("0.0.0.0:1300").unwrap();
        let mut buf = vec![0; 1500];
        loop {
            let (size, addr) = udp_socket.recv_from(&mut buf).unwrap();
            println!("recv {} bytes from {}", size, &addr);
            udp_socket.send_to(&buf[..size], addr).unwrap();
        }
    });

    let listener = TcpListener::bind("0.0.0.0:1300").unwrap();
    while let Ok((mut conn, addr)) = listener.accept() {
        thread::spawn(move || {
            let mut buf = vec![0; 1500];
            let size = conn.read(&mut buf).unwrap();
            println!("recv {} bytes from {}", size, &addr);
            conn.write_all(&buf[..size]).unwrap();
        });
    }
}
