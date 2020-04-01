mod tcp_io;
mod udp_io;

const BUFFER_SIZE: usize = 8 * 1024; // 8K buffer

pub use tcp_io::SSTcpStream;
pub use udp_io::SSUdpSocket;
