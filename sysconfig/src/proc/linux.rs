use crate::SocketInfo;
use procfs::process::FDTarget;
use procfs::{ProcError, ProcResult};
use std::collections::HashMap;
use std::io::Result;

fn to_io_error(e: ProcError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}
pub fn list_system_proc_socks() -> Result<HashMap<i32, Vec<SocketInfo>>> {
    _list_system_proc_socks().map_err(to_io_error)
}

fn _list_system_proc_socks() -> ProcResult<HashMap<i32, Vec<SocketInfo>>> {
    let all_procs = procfs::process::all_processes()?;

    // build up a map between socket inodes and processes:
    let mut map = HashMap::new();
    for process in all_procs {
        let process = process?;
        let pid = process.pid();
        for fd in process.fd()? {
            if let FDTarget::Socket(inode) = fd?.target {
                map.insert(inode, pid);
            }
        }
    }

    let mut socks_map = HashMap::new();
    // get the tcp table
    let tcp = procfs::net::tcp().unwrap();
    let tcp6 = procfs::net::tcp6().unwrap();
    for entry in tcp.into_iter().chain(tcp6) {
        // find the process (if any) that has an open FD to this entry's inode
        if let Some(pid) = map.get(&entry.inode) {
            let item = socks_map.entry(*pid).or_insert(vec![]);
            item.push(SocketInfo {
                local: entry.local_address,
                remote: entry.remote_address,
            });
        } 
    }
    Ok(socks_map)
}

pub fn list_user_proc_socks(expected_uid: u32) -> Result<HashMap<i32, Vec<SocketInfo>>> {
    _list_user_proc_socks(expected_uid).map_err(to_io_error)
}

fn _list_user_proc_socks(expected_uid: u32) -> ProcResult<HashMap<i32, Vec<SocketInfo>>> {
    let all_procs = procfs::process::all_processes()?;

    // build up a map between socket inodes and processes:
    let mut map = HashMap::new();
    for process in all_procs {
        let p = process?;
        let pid = p.pid();
        if expected_uid != p.uid()? {
            continue;
        }

        for fd in p.fd()? {
            if let FDTarget::Socket(inode) = fd?.target {
                map.insert(inode, pid);
            }
        }
    }
    let mut socks_map = HashMap::new();
    // get the tcp table
    let tcp = procfs::net::tcp().unwrap();
    let tcp6 = procfs::net::tcp6().unwrap();
    for entry in tcp.into_iter().chain(tcp6) {
        // find the process (if any) that has an open FD to this entry's inode
        if let Some(pid) = map.get(&entry.inode) {
            let item = socks_map.entry(*pid).or_insert(vec![]);
            item.push(SocketInfo {
                local: entry.local_address,
                remote: entry.remote_address,
            });
        } 
    }
    Ok(socks_map)
}

#[cfg(test)]
mod test {
    use super::*;
    use libc;

    #[test]
    fn test_list_user_proc_socks() {
        let uid = unsafe { libc::getuid() };
        let _socket = std::net::TcpListener::bind("0.0.0.0:65532").unwrap();
        let s = list_user_proc_socks(uid).unwrap();
        assert!(s
            .values()
            .any(|sockets| sockets.iter().any(|s| s.local.port() == 65532)));
    }
}
