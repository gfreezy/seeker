use failure::Fallible;
use libproc::libproc::proc_pid::{
    listpidinfo, listpids, pidfdinfo, ListFDs, ProcFDType, ProcType, SocketFDInfo, SocketInfoKind,
};
use std::collections::HashMap;
use std::convert::TryInto;
use std::net::{Ipv4Addr, SocketAddrV4};

pub fn list_system_proc_socks() -> Fallible<HashMap<i32, Vec<SocketAddrV4>>> {
    let pids = listpids(ProcType::ProcAllPIDS, 0)?;
    let mut pid_sockaddr_map = HashMap::new();
    for pid in pids {
        let pid = pid.try_into()?;
        pid_sockaddr_map.insert(pid, list_sockaddr(pid)?);
    }

    Ok(pid_sockaddr_map)
}

pub fn list_user_proc_socks(uid: u32) -> Fallible<HashMap<i32, Vec<SocketAddrV4>>> {
    let pids = listpids(ProcType::ProcUIDOnly, uid)?;
    let mut pid_sockaddr_map = HashMap::new();
    for pid in pids {
        let pid = pid.try_into()?;
        pid_sockaddr_map.insert(pid, list_sockaddr(pid)?);
    }

    Ok(pid_sockaddr_map)
}

fn list_sockaddr(pid: i32) -> Fallible<Vec<SocketAddrV4>> {
    let mut addrs = vec![];
    for fd in listpidinfo::<ListFDs>(pid, 4000)? {
        if let ProcFDType::Socket = fd.proc_fdtype.into() {
            if let Ok(socket) = pidfdinfo::<SocketFDInfo>(pid, fd.proc_fd) {
                if let SocketInfoKind::Tcp = socket.psi.soi_kind.into() {
                    // access to the member of `soi_proto` is unsafe becasuse of union type.
                    let info = unsafe { socket.psi.soi_proto.pri_tcp };

                    // change endian and cut off because insi_lport is network endian and 16bit witdh.
                    let mut port = 0;
                    port |= info.tcpsi_ini.insi_lport >> 8 & 0x00ff;
                    port |= info.tcpsi_ini.insi_lport << 8 & 0xff00;

                    // access to the member of `insi_laddr` is unsafe becasuse of union type.
                    let s_addr = unsafe { info.tcpsi_ini.insi_laddr.ina_46.i46a_addr4.s_addr };

                    // s_addr is in bit endian, and Ipv4Addr::from needs small endian.
                    let ip = Ipv4Addr::from(s_addr.swap_bytes());
                    let sock = SocketAddrV4::new(ip, port as u16);
                    addrs.push(sock);
                }
            }
        }
    }

    Ok(addrs)
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
        let s = list_user_proc_socks(uid).unwrap();
        assert!(s.len() > 1);
        dbg!(s);
    }
}
