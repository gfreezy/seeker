use crate::client::Client;
use async_std::net::TcpStream;
use config::Address;
use ssclient::SSClient;
use std::io::Result;
use tun::socket::TunUdpSocket;

#[async_trait::async_trait]
impl Client for SSClient {
    async fn handle_tcp(&self, socket: TcpStream, addr: Address) -> Result<()> {
        self.handle_tcp_connection(socket, addr).await
    }

    async fn handle_udp(&self, socket: TunUdpSocket, addr: Address) -> Result<()> {
        self.handle_udp_connection(socket, addr).await
    }
}
