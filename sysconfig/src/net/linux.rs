use crate::net::run_cmd;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use tracing::info;

pub struct DNSSetup {
    original: Vec<u8>,
}

impl DNSSetup {
    pub fn new() -> Self {
        info!("setup dns");
        let mut resolv = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/etc/resolv.conf")
            .unwrap();
        let mut buf = vec![];
        let _ = resolv.read_to_end(&mut buf).unwrap();

        info!(
            "original resolve.conf: {}",
            std::str::from_utf8(&buf).unwrap()
        );
        resolv.set_len(0).unwrap();
        resolv.seek(SeekFrom::Start(0)).unwrap();
        resolv.write_all(b"nameserver 127.0.0.1").unwrap();

        DNSSetup { original: buf }
    }
}

impl Drop for DNSSetup {
    fn drop(&mut self) {
        info!("clear dns");
        let mut resolv = OpenOptions::new()
            .write(true)
            .open("/etc/resolv.conf")
            .unwrap();
        resolv.write_all(&self.original).unwrap();
    }
}

pub fn setup_ip(tun_name: &str, ip: &str, _cidr: &str) {
    let _ = run_cmd("ip", &["addr", "add", ip, "dev", tun_name]);
    let _ = run_cmd("ip", &["link", "set", tun_name, "up"]);
}
