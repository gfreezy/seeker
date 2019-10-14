// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
#![allow(dead_code)]
use libc::*;
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::os::unix::io::{AsRawFd, RawFd};

const TUNSETIFF: u64 = 0x4004_54ca;

#[repr(C)]
union IfrIfru {
    ifru_addr: sockaddr,
    ifru_addr_v4: sockaddr_in,
    ifru_addr_v6: sockaddr_in,
    ifru_dstaddr: sockaddr,
    ifru_broadaddr: sockaddr,
    ifru_flags: c_short,
    ifru_metric: c_int,
    ifru_mtu: c_int,
    ifru_phys: c_int,
    ifru_media: c_int,
    ifru_intval: c_int,
    //ifru_data: caddr_t,
    //ifru_devmtu: ifdevmtu,
    //ifru_kpi: ifkpi,
    ifru_wake_flags: u32,
    ifru_route_refcnt: u32,
    ifru_cap: [c_int; 2],
    ifru_functional_type: u32,
}

#[repr(C)]
pub struct ifreq {
    ifr_name: [c_uchar; IFNAMSIZ],
    ifr_ifru: IfrIfru,
}

#[derive(Default, Debug)]
pub struct TunSocket {
    fd: RawFd,
    name: String,
}

impl Drop for TunSocket {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
    }
}

impl AsRawFd for TunSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl TunSocket {
    pub fn new(name: &str) -> Result<TunSocket> {
        let fd = match unsafe { open(b"/dev/net/tun\0".as_ptr() as _, O_RDWR) } {
            -1 => return Err(Error::last_os_error()),
            fd => fd,
        };

        let iface_name = name.as_bytes();
        let mut ifr = ifreq {
            ifr_name: [0; IFNAMSIZ],
            ifr_ifru: IfrIfru {
                ifru_flags: (IFF_TUN | IFF_NO_PI) as _,
            },
        };

        if iface_name.len() >= ifr.ifr_name.len() {
            return Err(Error::new(ErrorKind::Other, "Invalid tun name"));
        }

        ifr.ifr_name[..iface_name.len()].copy_from_slice(iface_name);

        if unsafe { ioctl(fd, TUNSETIFF as _, &ifr) } < 0 {
            return Err(Error::last_os_error());
        }

        let name = name.to_string();

        let socket = TunSocket { fd, name };
        socket.set_non_blocking()
    }

    pub fn name(&self) -> Result<String> {
        Ok(self.name.clone())
    }

    pub fn set_non_blocking(self) -> Result<TunSocket> {
        match unsafe { fcntl(self.fd, F_GETFL) } {
            -1 => Err(Error::last_os_error()),
            flags => match unsafe { fcntl(self.fd, F_SETFL, flags | O_NONBLOCK) } {
                -1 => Err(Error::last_os_error()),
                _ => Ok(self),
            },
        }
    }

    /// Get the current MTU value
    pub fn mtu(&self) -> Result<usize> {
        let fd = match unsafe { socket(AF_INET, SOCK_STREAM, IPPROTO_IP) } {
            -1 => return Err(Error::last_os_error()),
            fd @ _ => fd,
        };

        let name = self.name()?;
        let iface_name: &[u8] = name.as_ref();
        let mut ifr = ifreq {
            ifr_name: [0; IF_NAMESIZE],
            ifr_ifru: IfrIfru { ifru_mtu: 0 },
        };

        ifr.ifr_name[..iface_name.len()].copy_from_slice(iface_name);

        if unsafe { ioctl(fd, SIOCGIFMTU as _, &ifr) } < 0 {
            return Err(Error::last_os_error());
        }

        unsafe { close(fd) };

        Ok(unsafe { ifr.ifr_ifru.ifru_mtu } as _)
    }
}

impl Read for TunSocket {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match unsafe { read(self.fd, buf.as_mut_ptr() as _, buf.len()) } {
            -1 => Err(Error::last_os_error()),
            n => Ok(n as usize),
        }
    }
}

impl Write for TunSocket {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        match unsafe { write(self.fd, buf.as_ptr() as _, buf.len() as _) } {
            -1 => Ok(0),
            n => Ok(n as usize),
        }
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Read for &TunSocket {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        match unsafe { read(self.fd, buf.as_mut_ptr() as _, buf.len()) } {
            -1 => Err(Error::last_os_error()),
            n => Ok(n as usize),
        }
    }
}

impl Write for &TunSocket {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        match unsafe { write(self.fd, buf.as_ptr() as _, buf.len() as _) } {
            -1 => Ok(0),
            n => Ok(n as usize),
        }
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}
