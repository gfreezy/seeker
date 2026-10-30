//! Dedicated L3 interface: the host routes these packets, it does not own the
//! userspace stack's address or create a TCP socket for it.
use config::MimicConfig;
use std::collections::HashSet;
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use tun_rs::{AsyncDevice, DeviceBuilder};

static NEXT_NETWORK: AtomicU32 = AtomicU32::new(0);
static NETWORKS: LazyLock<Mutex<HashSet<u16>>> = LazyLock::new(|| Mutex::new(HashSet::new()));
static FORWARDING: Mutex<(usize, Option<String>)> = Mutex::new((0, None));

struct Subnet(u16);
impl Subnet {
    fn acquire() -> io::Result<Self> {
        let mut networks = NETWORKS.lock().unwrap_or_else(|e| e.into_inner());
        for _ in 0..16384 {
            let id = (std::process::id().wrapping_add(NEXT_NETWORK.fetch_add(1, Ordering::Relaxed))
                % 16384) as u16;
            if networks.insert(id) {
                return Ok(Self(id));
            }
        }
        Err(io::Error::other(
            "mimic exhausted its virtual IPv4 subnet pool",
        ))
    }
}
impl Drop for Subnet {
    fn drop(&mut self) {
        NETWORKS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.0);
    }
}

#[cfg(target_os = "linux")]
const FORWARD_KEY: &str = "net.ipv4.ip_forward";
#[cfg(target_os = "macos")]
const FORWARD_KEY: &str = "net.inet.ip.forwarding";

fn command(program: &str, args: &[String], input: Option<&str>) -> io::Result<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| io::Error::new(e.kind(), format!("mimic: cannot run {program}: {e}")))?;
    if let Some(input) = input {
        child.stdin.take().unwrap().write_all(input.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "mimic: {program} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    // pfctl prints its enable token to stderr on some macOS versions.
    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| (*s).into()).collect()
}

struct Forwarding;
impl Forwarding {
    fn acquire() -> io::Result<Self> {
        let mut state = FORWARDING.lock().unwrap_or_else(|e| e.into_inner());
        if state.0 == 0 {
            let original = command("sysctl", &args(&["-n", FORWARD_KEY]), None)?
                .trim()
                .to_string();
            if original != "1" {
                command("sysctl", &args(&["-w", &format!("{FORWARD_KEY}=1")]), None)?;
            }
            state.1 = Some(original);
        }
        state.0 += 1;
        Ok(Self)
    }
}
impl Drop for Forwarding {
    fn drop(&mut self) {
        let mut state = FORWARDING.lock().unwrap_or_else(|e| e.into_inner());
        state.0 -= 1;
        if state.0 == 0
            && let Some(original) = state.1.take()
            && original != "1"
            && let Err(e) = command(
                "sysctl",
                &args(&["-w", &format!("{FORWARD_KEY}={original}")]),
                None,
            )
        {
            tracing::warn!("{e}");
        }
    }
}

pub struct Network {
    pub device: Arc<AsyncDevice>,
    pub local: Ipv4Addr,
    cleanup: Vec<(&'static str, Vec<String>)>,
    _forwarding: Forwarding,
    _subnet: Subnet,
}

impl Network {
    pub fn open(config: &MimicConfig, remote: SocketAddrV4) -> io::Result<Self> {
        config
            .validate()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let interface = match &config.interface {
            Some(name) => name.clone(),
            None => outbound_interface(*remote.ip())?,
        };
        // Reserve one /30 per transport. The gateway belongs to the host;
        // only Seeker owns local, the peer address, so inbound packets are
        // forwarded to TUN instead of being delivered to the kernel TCP stack.
        let allocation = Subnet::acquire()?;
        let subnet = allocation.0 as u32 * 4;
        let gateway = Ipv4Addr::new(198, 19, (subnet >> 8) as u8, (subnet as u8) + 1);
        let local = Ipv4Addr::new(198, 19, (subnet >> 8) as u8, (subnet as u8) + 2);
        let mut builder = DeviceBuilder::new()
            .mtu(config.mtu)
            .ipv4(gateway, 30, Some(local));
        if let Some(name) = &config.tun_name {
            builder = builder.name(name);
        }
        let device = Arc::new(builder.build_async()?);
        let tun = device.name()?;
        if tun == interface {
            return Err(io::Error::other(
                "mimic outbound interface must differ from its TUN",
            ));
        }
        let mut network = Self {
            device,
            local,
            cleanup: Vec::new(),
            _forwarding: Forwarding::acquire()?,
            _subnet: allocation,
        };
        network.configure(&tun, &interface, remote)?;
        tracing::info!(%tun, %interface, %local, %remote, "Mimic userspace transport ready");
        Ok(network)
    }

    #[cfg(target_os = "linux")]
    fn configure(&mut self, tun: &str, interface: &str, remote: SocketAddrV4) -> io::Result<()> {
        let local = format!("{}/32", self.local);
        let remote_ip = format!("{}/32", remote.ip());
        let port = remote.port().to_string();
        for rule in [
            args(&[
                "-t",
                "nat",
                "-I",
                "POSTROUTING",
                "-s",
                &local,
                "-d",
                &remote_ip,
                "-p",
                "tcp",
                "--dport",
                &port,
                "-o",
                interface,
                "-j",
                "MASQUERADE",
            ]),
            args(&[
                "-I", "FORWARD", "-i", tun, "-s", &local, "-d", &remote_ip, "-p", "tcp", "--dport",
                &port, "-j", "ACCEPT",
            ]),
            args(&[
                "-I", "FORWARD", "-o", tun, "-d", &local, "-s", &remote_ip, "-p", "tcp", "--sport",
                &port, "-j", "ACCEPT",
            ]),
        ] {
            command("iptables", &rule, None)?;
            let undo = rule
                .into_iter()
                .map(|s| if s == "-I" { "-D".into() } else { s })
                .collect();
            self.cleanup.push(("iptables", undo));
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn configure(&mut self, tun: &str, interface: &str, remote: SocketAddrV4) -> io::Result<()> {
        // Use the system's existing wildcard attachment points. Never replace
        // the main PF ruleset, which may belong to Internet Sharing or a VPN.
        let filters = command("pfctl", &args(&["-sr"]), None)?;
        let nat = command("pfctl", &args(&["-sn"]), None)?;
        if !filters.contains("anchor \"com.apple/*\"")
            || !nat.contains("nat-anchor \"com.apple/*\"")
        {
            return Err(io::Error::other(
                "mimic needs the standard com.apple/* PF filter and NAT anchors; restore those attachment points in pf.conf",
            ));
        }
        // PF retains empty anchor names. Reuse the OS-unique interface name so
        // repeated daemon starts do not accumulate an anchor per process ID.
        let anchor = format!("com.apple/seeker-mimic-{tun}");
        let rules = format!(
            "nat on {interface} inet proto tcp from {local} to {ip} port {port} -> ({interface})\n\
             pass quick on {tun} inet proto tcp from {local} to {ip} port {port} flags any keep state\n\
             pass quick on {tun} inet proto tcp from {ip} port {port} to {local} flags any keep state\n\
             pass out quick on {interface} inet proto tcp to {ip} port {port} flags any keep state\n",
            local = self.local,
            ip = remote.ip(),
            port = remote.port(),
        );
        command("pfctl", &args(&["-a", &anchor, "-f", "-"]), Some(&rules))?;
        self.cleanup
            .push(("pfctl", args(&["-a", &anchor, "-F", "nat"])));
        self.cleanup
            .push(("pfctl", args(&["-a", &anchor, "-F", "rules"])));
        self.cleanup.push((
            "pfctl",
            args(&[
                "-k",
                &self.local.to_string(),
                "-k",
                &remote.ip().to_string(),
            ]),
        ));
        let output = command("pfctl", &args(&["-E"]), None)?;
        let token = output
            .lines()
            .find_map(|line| {
                line.trim()
                    .strip_prefix("Token :")
                    .or_else(|| line.trim().strip_prefix("Token:"))
            })
            .map(str::trim)
            .ok_or_else(|| {
                io::Error::other(format!(
                    "mimic could not read PF enable reference: {output}"
                ))
            })?;
        self.cleanup.insert(0, ("pfctl", args(&["-X", token])));
        Ok(())
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        for (program, args) in self.cleanup.iter().rev() {
            if let Err(e) = command(program, args, None) {
                tracing::warn!("{e}");
            }
        }
    }
}

fn outbound_interface(remote: Ipv4Addr) -> io::Result<String> {
    #[cfg(target_os = "linux")]
    let output = command(
        "ip",
        &args(&["-4", "route", "get", &remote.to_string()]),
        None,
    )?;
    #[cfg(target_os = "linux")]
    let interface = output
        .split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .find(|w| w[0] == "dev")
        .map(|w| w[1].to_string());
    #[cfg(target_os = "macos")]
    let output = command("route", &args(&["-n", "get", &remote.to_string()]), None)?;
    #[cfg(target_os = "macos")]
    let interface = output.lines().find_map(|line| {
        line.trim()
            .strip_prefix("interface:")
            .map(|s| s.trim().to_string())
    });
    interface.ok_or_else(|| {
        io::Error::other("mimic cannot determine outbound interface; set mimic.interface")
    })
}
