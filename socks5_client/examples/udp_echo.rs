use std::io;
use std::net::UdpSocket;

fn main() -> io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:10240")?;
    let mut buf = vec![0; 1440];
    while true {
        let (size, addr) = socket.recv_from(&mut buf)?;
        socket.send_to(&buf[..size], addr)?;
    }
    Ok(())
}
