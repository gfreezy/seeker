use etherparse::{Ipv4Header, PacketBuilder};
use std::io::Write;
use sysconfig::setup_ip;
use tun_nat::TunSocket;

fn main() {
    let mut tun = TunSocket::new("utun4").unwrap();
    let tun_name = tun.name().unwrap();
    setup_ip(&tun_name, "11.0.0.1", "11.0.0.0/16");

    let builder = PacketBuilder::ipv4([11, 0, 0, 10], [11, 0, 0, 1], 10).udp(6500, 1300);

    //payload of the udp packet
    let payload = b"a";

    //get some memory to store the result
    let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));

    //serialize
    builder.write(&mut result, &payload[..]).unwrap();
    tun.write(&result).unwrap();
}
