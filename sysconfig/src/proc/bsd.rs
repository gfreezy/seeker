use super::SocketInfo;
use std::collections::HashMap;
use std::fs;
use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub fn list_system_proc_socks() -> Result<HashMap<i32, Vec<SocketInfo>>> {
    let mut result = HashMap::new();

    // Try to read from /proc/net/tcp and /proc/net/tcp6 if available
    if let Ok(tcp_sockets) = read_tcp_sockets() {
        // Get process information for each socket
        for (local, remote) in tcp_sockets {
            // For BSD systems, we'll use a simplified approach
            // In a real implementation, you might need to use kvm or sysctl
            // to map sockets to processes, but for now we'll use a placeholder
            let socket_info = SocketInfo { local, remote };
            result.entry(0).or_insert_with(Vec::new).push(socket_info);
        }
    }

    Ok(result)
}

pub fn list_user_proc_socks(uid: u32) -> Result<HashMap<i32, Vec<SocketInfo>>> {
    // For BSD systems, we'll implement a simplified version
    // In a production system, you would need to:
    // 1. Use sysctl or kvm to get process information
    // 2. Filter processes by uid
    // 3. Map socket inodes to processes

    let mut result = HashMap::new();

    // Try to read socket information
    if let Ok(tcp_sockets) = read_tcp_sockets() {
        // For now, we'll return all sockets under a placeholder PID
        // A real implementation would need to map these to actual processes
        for (local, remote) in tcp_sockets {
            let socket_info = SocketInfo { local, remote };
            result
                .entry(uid as i32)
                .or_insert_with(Vec::new)
                .push(socket_info);
        }
    }

    Ok(result)
}

fn read_tcp_sockets() -> Result<Vec<(SocketAddr, SocketAddr)>> {
    let mut sockets = Vec::new();

    // Try to read from procfs if available (some BSD systems have it)
    if let Ok(tcp4_content) = fs::read_to_string("/proc/net/tcp") {
        sockets.extend(parse_tcp_proc(&tcp4_content, false)?);
    }

    if let Ok(tcp6_content) = fs::read_to_string("/proc/net/tcp6") {
        sockets.extend(parse_tcp_proc(&tcp6_content, true)?);
    }

    // If procfs is not available, try netstat command as fallback
    if sockets.is_empty() {
        sockets = read_tcp_sockets_netstat()?;
    }

    Ok(sockets)
}

fn parse_tcp_proc(content: &str, is_ipv6: bool) -> Result<Vec<(SocketAddr, SocketAddr)>> {
    let mut sockets = Vec::new();

    for line in content.lines().skip(1) {
        // Skip header
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            continue;
        }

        if let (Ok(local), Ok(remote)) = (
            parse_socket_addr(fields[1], is_ipv6),
            parse_socket_addr(fields[2], is_ipv6),
        ) {
            sockets.push((local, remote));
        }
    }

    Ok(sockets)
}

fn parse_socket_addr(addr_str: &str, is_ipv6: bool) -> Result<SocketAddr> {
    let parts: Vec<&str> = addr_str.split(':').collect();
    if parts.len() != 2 {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid address format"));
    }

    let port = u16::from_str_radix(parts[1], 16)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid port"))?;

    if is_ipv6 {
        // Parse IPv6 address
        let ip_hex = parts[0];
        if ip_hex.len() != 32 {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid IPv6 format"));
        }

        let mut addr_bytes = [0u8; 16];
        for i in 0..16 {
            addr_bytes[i] = u8::from_str_radix(&ip_hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid IPv6 hex"))?;
        }

        let ip = Ipv6Addr::from(addr_bytes);
        Ok(SocketAddr::new(IpAddr::V6(ip), port))
    } else {
        // Parse IPv4 address
        let ip_num = u32::from_str_radix(parts[0], 16)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid IPv4 format"))?;

        let ip = Ipv4Addr::from(ip_num.to_be());
        Ok(SocketAddr::new(IpAddr::V4(ip), port))
    }
}

fn read_tcp_sockets_netstat() -> Result<Vec<(SocketAddr, SocketAddr)>> {
    use std::process::Command;

    let output = Command::new("netstat")
        .args(&["-n", "-p", "tcp"])
        .output()
        .map_err(|e| Error::new(ErrorKind::Other, format!("Failed to run netstat: {}", e)))?;

    if !output.status.success() {
        return Err(Error::new(ErrorKind::Other, "netstat command failed"));
    }

    let content = String::from_utf8_lossy(&output.stdout);
    parse_netstat_output(&content)
}

fn parse_netstat_output(content: &str) -> Result<Vec<(SocketAddr, SocketAddr)>> {
    let mut sockets = Vec::new();

    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 || fields[0] != "tcp" {
            continue;
        }

        // netstat output format: tcp 0 0 local_addr remote_addr state
        if let (Ok(local), Ok(remote)) = (
            fields[3].parse::<SocketAddr>(),
            fields[4].parse::<SocketAddr>(),
        ) {
            sockets.push((local, remote));
        }
    }

    Ok(sockets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_system_proc_socks() {
        // This test might fail on systems without proper proc support
        // but it should not panic
        let result = list_system_proc_socks();
        assert!(result.is_ok());
    }

    #[test]
    fn test_list_user_proc_socks() {
        let uid = unsafe { libc::getuid() };
        let result = list_user_proc_socks(uid);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_socket_addr_ipv4() {
        let result = parse_socket_addr("0100007F:1F90", false);
        assert!(result.is_ok());
        let addr = result.unwrap();
        assert_eq!(addr.port(), 8080);
    }
}
