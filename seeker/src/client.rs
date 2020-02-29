pub mod direct_client;
pub mod ruled_client;
pub mod shadowsocks_client;
pub mod socks5_client;

use config::Address;
use std::io::Result;
use tun::socket::{TunTcpSocket, TunUdpSocket};

#[async_trait::async_trait]
pub trait Client {
    async fn handle_tcp(&self, socket: TunTcpSocket, addr: Address) -> Result<()>;
    async fn handle_udp(&self, socket: TunUdpSocket, addr: Address) -> Result<()>;
}
