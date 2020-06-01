use crate::SocketInfo;
use procfs::process::FDTarget;
use std::collections::HashMap;
use std::io::Result;

pub fn list_system_proc_socks() -> Result<HashMap<i32, Vec<SocketInfo>>> {
    let all_procs = procfs::process::all_processes().expect("list all processes");

    // build up a map between socket inodes and processes:
    let mut map = HashMap::new();
    for process in &all_procs {
        if let Ok(fds) = process.fd() {
            for fd in fds {
                if let FDTarget::Socket(inode) = fd.target {
                    map.insert(inode, process);
                }
            }
        }
    }

    let mut socks_map = HashMap::new();
    // get the tcp table
    let tcp = procfs::net::tcp().unwrap();
    let tcp6 = procfs::net::tcp6().unwrap();
    for entry in tcp.into_iter().chain(tcp6) {
        // find the process (if any) that has an open FD to this entry's inode
        if let Some(process) = map.get(&entry.inode) {
            let item = socks_map.entry(process.pid()).or_insert_with(|| vec![]);
            item.push(SocketInfo {
                local: entry.local_address,
                remote: entry.remote_address,
            });
        } else {
        }
    }
    Ok(socks_map)
}

pub fn list_user_proc_socks(uid: u32) -> Result<HashMap<i32, Vec<SocketInfo>>> {
    let all_procs = procfs::process::all_processes().expect("list all processes");

    // build up a map between socket inodes and processes:
    let mut map = HashMap::new();
    for process in all_procs.iter().filter(|p| p.owner == uid) {
        if let Ok(fds) = process.fd() {
            for fd in fds {
                if let FDTarget::Socket(inode) = fd.target {
                    map.insert(inode, process);
                }
            }
        }
    }
    let mut socks_map = HashMap::new();
    // get the tcp table
    let tcp = procfs::net::tcp().unwrap();
    let tcp6 = procfs::net::tcp6().unwrap();
    for entry in tcp.into_iter().chain(tcp6) {
        // find the process (if any) that has an open FD to this entry's inode
        if let Some(process) = map.get(&entry.inode) {
            let item = socks_map.entry(process.pid()).or_insert_with(|| vec![]);
            item.push(SocketInfo {
                local: entry.local_address,
                remote: entry.remote_address,
            });
        } else {
        }
    }
    Ok(socks_map)
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
        let _socket = std::net::TcpListener::bind("0.0.0.0:65532").unwrap();
        let s = list_user_proc_socks(uid).unwrap();
        assert!(s
            .values()
            .any(|sockets| sockets.iter().any(|s| s.local.port() == 65532)));
    }
}
