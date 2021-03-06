use std::io;
use std::net::UdpSocket;

fn main() -> io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:10240")?;
    let mut buf = vec![0; 1440];
    loop {
        let (size, addr) = socket.recv_from(&mut buf)?;
        println!("{}", String::from_utf8_lossy(&buf[..size]));
        socket.send_to(&buf[..size], addr)?;
    }
}
