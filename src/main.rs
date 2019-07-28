#![feature(async_await)]

mod tun;

use tun::{Addr, Tun, SocketBuf};
use futures::executor;
use log::debug;
use std::env;
use std::io;

fn main() -> io::Result<()> {
    env_logger::init();
    better_panic::install();

    let args = env::args().collect::<Vec<String>>();
    let name = &args[1];
    let mut client = Tun::new(dbg!(&args[1]));

    executor::block_on(async {
        debug!("begin start");
        loop {
            debug!("loop start");
            let mut tx_data = Vec::new();
            let rx_data: Vec<SocketBuf> = client.recv().await?;
            for socket_buf in rx_data {
                match socket_buf {
                    SocketBuf::Tcp(Addr { src, dst }, buf) => {
                        debug!(
                            "src: {}, dst: {}, buf: {}",
                            src,
                            dst,
                            String::from_utf8_lossy(&buf)
                        );
                        tx_data.push(SocketBuf::Tcp(Addr { src: dst, dst: src }, buf))
                    }
                    SocketBuf::Udp(Addr { src, dst }, buf) => {
                        debug!(
                            "src: {}, dst: {}, buf: {}",
                            src,
                            dst,
                            String::from_utf8_lossy(&buf)
                        );
                        tx_data.push(SocketBuf::Udp(Addr { src: dst, dst: src }, buf))
                    }
                }
            }
            debug!("client.send");
            client.send(tx_data).await?;
        }
        Ok(())
    })
}
