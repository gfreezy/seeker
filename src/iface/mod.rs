use crate::iface::phony_socket::PhonySocket;
use crate::phy::TunSocket;
use mio::unix::EventedFd;
use mio::{Evented, Poll, PollOpt, Ready, Token};
use smoltcp::socket::SocketSet;
use std::io;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;

pub mod ethernet;
pub mod phony_socket;
