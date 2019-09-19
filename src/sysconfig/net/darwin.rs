use smoltcp::wire::{IpAddress, IpCidr};
use std::process::Command;
use tracing::info;

pub struct DNSSetup;

impl DNSSetup {
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
        DNSSetup
    }
}

impl Drop for DNSSetup {
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
}

pub fn setup_ip(tun_name: &str, ip: IpAddress, cidr: IpCidr) {
    let ip_s = ip.to_string();
    let output = Command::new("ifconfig")
        .args(&[tun_name, &ip_s, &ip_s])
        .output()
        .expect("run ifconfig");
    if !output.status.success() {
        panic!(
            "stdout: {}\nstderr: {}",
            std::str::from_utf8(&output.stdout).expect("utf8"),
            std::str::from_utf8(&output.stderr).expect("utf8")
        );
    }
    let output = Command::new("route")
        .arg("add")
        .arg(cidr.to_string())
        .arg(ip_s)
        .output()
        .expect("add route");
    if !output.status.success() {
        panic!(
            "stdout: {}\nstderr: {}",
            std::str::from_utf8(&output.stdout).expect("utf8"),
            std::str::from_utf8(&output.stderr).expect("utf8")
        );
    }
}
