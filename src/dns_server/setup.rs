use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(target_os = "macos")]
use std::process::Command;
use tracing::info;

pub struct DNSSetup {
    original: Vec<u8>,
}

impl DNSSetup {
    #[cfg(target_os = "macos")]
    pub fn new() -> Self {
        info!("setup dns");
        let output = Command::new("networksetup")
            .args(&["-setdnsservers", "Wi-Fi", "127.0.0.1"])
            .output()
            .expect("setup local dns");
        if !output.status.success() {
            panic!(
                "stdout: {}\nstderr: {}",
                std::str::from_utf8(&output.stdout).expect("utf8"),
                std::str::from_utf8(&output.stderr).expect("utf8")
            );
        }
        DNSSetup { original: vec![] }
    }

    #[cfg(target_os = "linux")]
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
    #[cfg(target_os = "macos")]
    fn drop(&mut self) {
        info!("clear dns");
        let output = Command::new("networksetup")
            .args(&["-setdnsservers", "Wi-Fi", "empty"])
            .output()
            .expect("clear local dns");
        if !output.status.success() {
            panic!(
                "stdout: {}\nstderr: {}",
                std::str::from_utf8(&output.stdout).expect("utf8"),
                std::str::from_utf8(&output.stderr).expect("utf8")
            );
        }
    }

    #[cfg(target_os = "linux")]
    fn drop(&mut self) {
        info!("clear dns");
        let mut resolv = OpenOptions::new()
            .write(true)
            .open("/etc/resolv.conf")
            .unwrap();
        resolv.write_all(&self.original).unwrap();
    }
}
