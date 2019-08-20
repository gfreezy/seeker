pub mod rule;

use rule::ProxyRules;
use shadowsocks::ServerConfig;
use smoltcp::wire::{IpAddress, IpCidr};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

pub struct Config {
    pub server_config: Arc<ServerConfig>,
    pub dns_start_ip: Ipv4Addr,
    pub dns_server: SocketAddr,
    pub tun_name: String,
    pub tun_ip: IpAddress,
    pub tun_cidr: IpCidr,
    pub rules: ProxyRules,
}
