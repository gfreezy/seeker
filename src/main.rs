#![feature(async_await)]

mod device;

use std::error::Error;
use device::TunSocket;
use device::drop_privileges::drop_privileges;
use futures::AsyncReadExt;
use std::io;

#[runtime::main]
async fn main() {
    let mut tun = TunSocket::new("utun4").expect("open tun");
    drop_privileges().expect("drop privileges");

    let mut buf = vec![0; 512];
    tun.read(&mut buf).await.expect("read");

    println!("read: {:#?}", buf);
}
