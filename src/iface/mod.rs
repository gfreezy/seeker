use crate::phy::TunSocket;
use mio::unix::EventedFd;
use mio::{Evented, Poll, PollOpt, Ready, Token};
use smoltcp::socket::SocketSet;
use std::io;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;

pub mod ethernet;

pub struct Iface {
    inner: ethernet::Interface<'static, TunSocket>,
    sockets: SocketSet<'static, 'static, 'static>,
}

impl Iface {
    pub fn new(inner: ethernet::Interface<'static, TunSocket>) -> Self {
        let sockets = SocketSet::new(vec![]);
        Iface { inner, sockets }
    }
}

impl Evented for Iface {
    fn register(
        &self,
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        EventedFd(&self.inner.device().as_raw_fd()).register(poll, token, interest, opts)
    }

    fn reregister(
        &self,
        poll: &Poll,
        token: Token,
        interest: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        EventedFd(&self.inner.device().as_raw_fd()).reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &Poll) -> io::Result<()> {
        EventedFd(&self.inner.device().as_raw_fd()).deregister(poll)
    }
}

impl Read for Iface {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unimplemented!()
    }
}

impl Write for Iface {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        unimplemented!()
    }

    fn flush(&mut self) -> io::Result<()> {
        unimplemented!()
    }
}
