use crate::command::run_cmd;

pub struct IptablesSetup {
    port: u16,
    cidr: String,
}

impl IptablesSetup {
    pub fn new(port: u16, cidr: String) -> Self {
        IptablesSetup { port, cidr }
    }

    pub fn start(&self) {
        setup_redirect_iptables(&self.cidr, self.port);
    }
}

impl Drop for IptablesSetup {
    fn drop(&mut self) {
        teardown_redirect_iptables(&self.cidr, self.port);
    }
}

fn teardown_redirect_iptables(cidr: &str, port: u16) {
    let _ = run_cmd(
        "iptables",
        &[
            "-t",
            "nat",
            "-D",
            "PREROUTING",
            "-d",
            cidr,
            "-p",
            "tcp",
            "-j",
            "REDIRECT",
            "--to-ports",
            &port.to_string(),
        ],
    );
}

fn setup_redirect_iptables(cidr: &str, port: u16) {
    let _ = run_cmd(
        "iptables",
        &[
            "-t",
            "nat",
            "-A",
            "PREROUTING",
            "-d",
            cidr,
            "-p",
            "tcp",
            "-j",
            "REDIRECT",
            "--to-ports",
            &port.to_string(),
        ],
    );
}
