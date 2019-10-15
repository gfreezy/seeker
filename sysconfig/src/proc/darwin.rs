#![allow(dead_code)]
use anyhow::Result;
use libproc::libproc::proc_pid::{
    listpidinfo, listpids, pidfdinfo, InSockInfo, ListFDs, ProcFDType, ProcType, SocketFDInfo,
    SocketInfoKind,
};
use std::collections::HashMap;
use std::convert::TryInto;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct SocketInfo {
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

pub fn list_system_proc_socks() -> Result<HashMap<i32, Vec<SocketInfo>>> {
    let pids = listpids(ProcType::ProcAllPIDS, 0)?;
    let mut pid_sockaddr_map = HashMap::new();
    for pid in pids {
        let pid = pid.try_into()?;
        pid_sockaddr_map.insert(pid, list_sockaddr(pid)?);
    }

    Ok(pid_sockaddr_map)
}

pub fn list_user_proc_socks(uid: u32) -> Result<HashMap<i32, Vec<SocketInfo>>> {
    let pids = listpids(ProcType::ProcUIDOnly, uid)?;
    let mut pid_sockaddr_map = HashMap::new();
    for pid in pids {
        let pid = pid.try_into()?;
        let socket_infos = list_sockaddr(pid)?;
        if !socket_infos.is_empty() {
            pid_sockaddr_map.insert(pid, socket_infos);
        }
    }

    Ok(pid_sockaddr_map)
}

fn list_sockaddr(pid: i32) -> Result<Vec<SocketInfo>> {
    let mut addrs = vec![];
    for fd in listpidinfo::<ListFDs>(pid, 4000)? {
        if let ProcFDType::Socket = fd.proc_fdtype.into() {
            if let Ok(socket) = pidfdinfo::<SocketFDInfo>(pid, fd.proc_fd) {
                if let SocketInfoKind::Tcp = socket.psi.soi_kind.into() {
                    // access to the member of `soi_proto` is unsafe becasuse of union type.
                    let info = unsafe { socket.psi.soi_proto.pri_tcp };
                    let local = get_local_addr(info.tcpsi_ini, socket.psi.soi_family);
                    let remote = get_foreign_addr(info.tcpsi_ini, socket.psi.soi_family);
                    addrs.push(SocketInfo { local, remote });
                }
            }
        }
    }

    Ok(addrs)
}

fn get_local_addr(in_sock_info: InSockInfo, family: i32) -> SocketAddr {
    // change endian and cut off because insi_lport is network endian and 16bit witdh.
    let mut port = 0;
    port |= in_sock_info.insi_lport >> 8 & 0x00ff;
    port |= in_sock_info.insi_lport << 8 & 0xff00;

    if family == libc::AF_INET {
        // access to the member of `insi_laddr` is unsafe becasuse of union type.
        let s_addr = unsafe { in_sock_info.insi_laddr.ina_46.i46a_addr4.s_addr };

        // s_addr is in bit endian, and Ipv4Addr::from needs small endian.
        let ip = Ipv4Addr::from(s_addr.swap_bytes()).into();
        SocketAddr::new(ip, port as u16)
    } else {
        // access to the member of `insi_laddr` is unsafe becasuse of union type.
        let s_addr = unsafe { in_sock_info.insi_laddr.ina_6.s6_addr };
        let ip = Ipv6Addr::from(s_addr).into();
        SocketAddr::new(ip, port as u16)
    }
}

fn get_foreign_addr(in_sock_info: InSockInfo, family: i32) -> SocketAddr {
    // change endian and cut off because insi_lport is network endian and 16bit witdh.
    let mut port = 0;
    port |= in_sock_info.insi_fport >> 8 & 0x00ff;
    port |= in_sock_info.insi_fport << 8 & 0xff00;

    if family == libc::AF_INET {
        // access to the member of `insi_faddr` is unsafe becasuse of union type.
        let s_addr = unsafe { in_sock_info.insi_faddr.ina_46.i46a_addr4.s_addr };

        // s_addr is in bit endian, and Ipv4Addr::from needs small endian.
        let ip = Ipv4Addr::from(s_addr.swap_bytes()).into();
        SocketAddr::new(ip, port as u16)
    } else {
        // access to the member of `insi_faddr` is unsafe becasuse of union type.
        let s_addr = unsafe { in_sock_info.insi_faddr.ina_6.s6_addr };
        let ip = Ipv6Addr::from(s_addr).into();
        SocketAddr::new(ip, port as u16)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use libc;

    #[test]
    fn test_list_system_proc_socks() {
        assert!(list_system_proc_socks().unwrap().len() > 1);
    }

    #[test]
    fn test_list_user_proc_socks() {
        let uid = unsafe { libc::getuid() };
        let socket = std::net::TcpListener::bind("0.0.0.0:8888").unwrap();
        let s = list_user_proc_socks(uid).unwrap();
        assert!(s
            .values()
            .find(|sockets| sockets.iter().find(|s| s.local.port() == 8888).is_some())
            .is_some());
    }
}
