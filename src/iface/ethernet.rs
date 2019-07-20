use log::debug;
use managed::{Managed, ManagedSlice};
use smoltcp::phy::RxToken;
use smoltcp::phy::{Device, DeviceCapabilities, TxToken};
use smoltcp::socket::TcpSocket;
use smoltcp::socket::{AnySocket, UdpPacketMetadata, UdpSocketBuffer};
use smoltcp::socket::{PollAt, Socket, SocketSet, UdpSocket};
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{
    EthernetFrame, IpAddress, IpCidr, IpProtocol, IpRepr, Ipv4Address, Ipv4Packet, Ipv4Repr,
    PrettyPrinter, TcpControl, TcpPacket, TcpRepr, UdpPacket, UdpRepr,
};
use smoltcp::{Error, Result};

#[derive(Debug, PartialEq)]
enum Packet<'a> {
    None,
    Udp((IpRepr, UdpRepr<'a>)),
    Tcp((IpRepr, TcpRepr<'a>)),
}

/// An Ethernet network interface.
///
/// The network interface logically owns a number of other data structures; to avoid
/// a dependency on heap allocation, it instead owns a `BorrowMut<[T]>`, which can be
/// a `&mut [T]`, or `Vec<T>` if a heap is available.
pub struct Interface<'a, DeviceT: for<'d> Device<'d>> {
    device: DeviceT,
    inner: InterfaceInner<'a>,
}

struct InterfaceInner<'a> {
    device_capabilities: DeviceCapabilities,
    ip_addrs: ManagedSlice<'a, IpCidr>,
    any_ip: bool,
}

pub struct InterfaceBuilder<'a, DeviceT: for<'d> Device<'d>> {
    device: DeviceT,
    ip_addrs: ManagedSlice<'a, IpCidr>,
    any_ip: bool,
}

impl<'a, DeviceT> InterfaceBuilder<'a, DeviceT>
where
    DeviceT: for<'d> Device<'d>,
{
    pub fn new(device: DeviceT) -> Self {
        InterfaceBuilder {
            device,
            ip_addrs: ManagedSlice::Borrowed(&mut []),
            any_ip: false,
        }
    }

    pub fn ip_addrs<T>(mut self, ip_addrs: T) -> Self
    where
        T: Into<ManagedSlice<'a, IpCidr>>,
    {
        let ip_addrs = ip_addrs.into();
        self.ip_addrs = ip_addrs;
        self
    }

    pub fn any_ip(mut self, any_ip: bool) -> Self {
        self.any_ip = any_ip;
        self
    }

    pub fn finalize(self) -> Interface<'a, DeviceT> {
        let cap = self.device.capabilities();
        Interface {
            device: self.device,
            inner: InterfaceInner {
                ip_addrs: self.ip_addrs,
                device_capabilities: cap,
                any_ip: self.any_ip,
            },
        }
    }
}

impl<'a, DeviceT> Interface<'a, DeviceT>
where
    DeviceT: for<'d> Device<'d>,
{
    /// Get a reference to the inner device.
    pub fn device(&self) -> &DeviceT {
        &self.device
    }

    /// Get a mutable reference to the inner device.
    ///
    /// There are no invariants imposed on the device by the interface itself. Furthermore the
    /// trait implementations, required for references of all lifetimes, guarantees that the
    /// mutable reference can not invalidate the device as such. For some devices, such access may
    /// still allow modifications with adverse effects on the usability as a `phy` device. You
    /// should not use them this way.
    pub fn device_mut(&mut self) -> &mut DeviceT {
        &mut self.device
    }

    /// Transmit packets queued in the given sockets, and receive packets queued
    /// in the device.
    ///
    /// This function returns a boolean value indicating whether any packets were
    /// processed or emitted, and thus, whether the readiness of any socket might
    /// have changed.
    ///
    /// # Errors
    /// This method will routinely return errors in response to normal network
    /// activity as well as certain boundary conditions such as buffer exhaustion.
    /// These errors are provided as an aid for troubleshooting, and are meant
    /// to be logged and ignored.
    ///
    /// As a special case, `Err(Error::Unrecognized)` is returned in response to
    /// packets containing any unsupported protocol, option, or form, which is
    /// a very common occurrence and on a production system it should not even
    /// be logged.
    pub fn poll(&mut self, sockets: &mut SocketSet, timestamp: Instant) -> Result<bool> {
        let mut readiness_may_have_changed = false;
        loop {
            let processed_any = self.socket_ingress(sockets, timestamp)?;
            let emitted_any = self.socket_egress(sockets, timestamp)?;

            if processed_any || emitted_any {
                readiness_may_have_changed = true;
            } else {
                break;
            }
        }
        Ok(readiness_may_have_changed)
    }

    /// Return a _soft deadline_ for calling [poll] the next time.
    /// The [Instant] returned is the time at which you should call [poll] next.
    /// It is harmless (but wastes energy) to call it before the [Instant], and
    /// potentially harmful (impacting quality of service) to call it after the
    /// [Instant]
    ///
    /// [poll]: #method.poll
    /// [Instant]: struct.Instant.html
    pub fn poll_at(&self, sockets: &SocketSet, timestamp: Instant) -> Option<Instant> {
        sockets
            .iter()
            .filter_map(|socket| match socket.poll_at() {
                PollAt::Now => Some(Instant::from_millis(0)),
                PollAt::Time(t) => Some(t),
                PollAt::Ingress => None,
            })
            .min()
    }

    /// Return an _advisory wait time_ for calling [poll] the next time.
    /// The [Duration] returned is the time left to wait before calling [poll] next.
    /// It is harmless (but wastes energy) to call it before the [Duration] has passed,
    /// and potentially harmful (impacting quality of service) to call it after the
    /// [Duration] has passed.
    ///
    /// [poll]: #method.poll
    /// [Duration]: struct.Duration.html
    pub fn poll_delay(&self, sockets: &SocketSet, timestamp: Instant) -> Option<Duration> {
        match self.poll_at(sockets, timestamp) {
            Some(poll_at) if timestamp < poll_at => Some(poll_at - timestamp),
            Some(_) => Some(Duration::from_millis(0)),
            _ => None,
        }
    }

    fn socket_ingress(&mut self, sockets: &mut SocketSet, timestamp: Instant) -> Result<bool> {
        let mut processed_any = false;
        loop {
            let &mut Self {
                ref mut device,
                ref mut inner,
            } = self;
            let (rx_token, tx_token) = match device.receive() {
                None => break,
                Some(tokens) => tokens,
            };
            rx_token.consume(timestamp, |frame| {
                inner
                    .process_ipv4(sockets, timestamp, &frame)
                    .map_err(|err| {
                        debug!("cannot process ingress packet: {}", err);
                        debug!(
                            "packet dump follows:\n{}",
                            PrettyPrinter::<EthernetFrame<&[u8]>>::new("", &frame)
                        );
                        err
                    })
                    .and_then(|response| {
                        processed_any = true;
                        inner
                            .dispatch(tx_token, timestamp, response)
                            .map_err(|err| {
                                debug!("cannot dispatch response packet: {}", err);
                                err
                            })
                    })
            })?;
        }
        Ok(processed_any)
    }

    fn socket_egress(&mut self, sockets: &mut SocketSet, timestamp: Instant) -> Result<bool> {
        let mut emitted_any = false;
        let caps = self.inner.device_capabilities.clone();
        for mut socket in sockets.iter_mut() {
            let mut device_result = Ok(());
            let &mut Self {
                ref mut device,
                ref mut inner,
            } = self;

            macro_rules! respond {
                ($response:expr) => {{
                    let response = $response;
                    let tx_token = device.transmit().ok_or(Error::Exhausted)?;
                    device_result = inner.dispatch(tx_token, timestamp, response);
                    device_result
                }};
            }

            let socket_result = match *socket {
                Socket::Udp(ref mut socket) => {
                    socket.dispatch(|response| respond!(Packet::Udp(response)))
                }
                Socket::Tcp(ref mut socket) => {
                    socket.dispatch(timestamp, &caps, |response| respond!(Packet::Tcp(response)))
                }
                Socket::__Nonexhaustive(_) => unreachable!(),
                _ => unreachable!(),
            };

            match (device_result, socket_result) {
                (Err(Error::Exhausted), _) => break,   // nowhere to transmit
                (Ok(()), Err(Error::Exhausted)) => (), // nothing to transmit
                (Err(err), _) | (_, Err(err)) => {
                    debug!(
                        "{}: cannot dispatch egress packet: {}",
                        socket.meta().handle,
                        err
                    );
                    return Err(err);
                }
                (Ok(()), Ok(())) => emitted_any = true,
            }
        }
        Ok(emitted_any)
    }
}

impl<'a> InterfaceInner<'a> {
    /// Check whether the interface has the given IP address assigned.
    fn has_ip_addr<T: Into<IpAddress>>(&self, addr: T) -> bool {
        let addr = addr.into();
        self.ip_addrs.iter().any(|probe| probe.address() == addr)
    }

    /// Get the first IPv4 address of the interface.
    #[cfg(feature = "proto-ipv4")]
    pub fn ipv4_address(&self) -> Option<Ipv4Address> {
        self.ip_addrs
            .iter()
            .filter_map(|addr| match addr {
                &IpCidr::Ipv4(cidr) => Some(cidr.address()),
                _ => None,
            })
            .next()
    }

    fn process_ipv4<'frame, T: AsRef<[u8]>>(
        &mut self,
        sockets: &mut SocketSet,
        timestamp: Instant,
        frame: &'frame T,
    ) -> Result<Packet<'frame>> {
        let ipv4_packet = Ipv4Packet::new_checked(frame)?;
        let checksum_caps = self.device_capabilities.checksum.clone();;
        let ipv4_repr = Ipv4Repr::parse(&ipv4_packet, &checksum_caps)?;

        if !ipv4_repr.src_addr.is_unicast() {
            // Discard packets with non-unicast source addresses.
            debug!("non-unicast source address");
            return Err(Error::Malformed);
        }

        let ip_repr = IpRepr::Ipv4(ipv4_repr);
        let ip_payload = ipv4_packet.payload();

        debug!("recv ip packet: {:?}", &ip_repr);

        if !self.has_ip_addr(ipv4_repr.dst_addr)
            && !ipv4_repr.dst_addr.is_broadcast()
            && !self.any_ip
        {
            // Ignore IP packets not directed at us, or broadcast.
            // If AnyIP is enabled, also check if the packet is routed locally.
            return Ok(Packet::None);
        }

        match ipv4_repr.protocol {
            IpProtocol::Udp => self.process_udp(sockets, ip_repr, ip_payload),

            IpProtocol::Tcp => self.process_tcp(sockets, timestamp, ip_repr, ip_payload),

            _ => Ok(Packet::None),
        }
    }

    fn process_udp<'frame>(
        &self,
        sockets: &mut SocketSet,
        ip_repr: IpRepr,
        ip_payload: &'frame [u8],
    ) -> Result<Packet<'frame>> {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
        let udp_packet = UdpPacket::new_checked(ip_payload)?;
        let checksum_caps = self.device_capabilities.checksum.clone();;
        let udp_repr = UdpRepr::parse(&udp_packet, &src_addr, &dst_addr, &checksum_caps)?;

        for mut udp_socket in sockets.iter_mut().filter_map(UdpSocket::downcast) {
            if !udp_socket.accepts(&ip_repr, &udp_repr) {
                continue;
            }

            match udp_socket.process(&ip_repr, &udp_repr) {
                // The packet is valid and handled by socket.
                Ok(()) => return Ok(Packet::None),
                // The packet is malformed, or the socket buffer is full.
                Err(e) => return Err(e),
            }
        }

        unreachable!()
    }

    fn new_udp_socket(&self, sockets: &mut SocketSet, ip_repr: &IpRepr, udp_repr: &UdpRepr) {
        let udp_rx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 64]);
        let udp_tx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 128]);
        let udp_socket = UdpSocket::new(udp_rx_buffer, udp_tx_buffer);

        sockets.add(udp_socket);
    }

    fn process_tcp<'frame>(
        &self,
        sockets: &mut SocketSet,
        timestamp: Instant,
        ip_repr: IpRepr,
        ip_payload: &'frame [u8],
    ) -> Result<Packet<'frame>> {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
        let tcp_packet = TcpPacket::new_checked(ip_payload)?;
        let checksum_caps = self.device_capabilities.checksum.clone();;
        let tcp_repr = TcpRepr::parse(&tcp_packet, &src_addr, &dst_addr, &checksum_caps)?;

        for mut tcp_socket in sockets.iter_mut().filter_map(TcpSocket::downcast) {
            if !tcp_socket.accepts(&ip_repr, &tcp_repr) {
                continue;
            }

            match tcp_socket.process(timestamp, &ip_repr, &tcp_repr) {
                // The packet is valid and handled by socket.
                Ok(reply) => return Ok(reply.map_or(Packet::None, Packet::Tcp)),
                // The packet is malformed, or doesn't match the socket state,
                // or the socket buffer is full.
                Err(e) => return Err(e),
            }
        }

        if tcp_repr.control == TcpControl::Rst {
            // Never reply to a TCP RST packet with another TCP RST packet.
            Ok(Packet::None)
        } else {
            // The packet wasn't handled by a socket, send a TCP RST packet.
            Ok(Packet::Tcp(TcpSocket::rst_reply(&ip_repr, &tcp_repr)))
        }
    }

    fn dispatch<Tx>(&mut self, tx_token: Tx, timestamp: Instant, packet: Packet) -> Result<()>
    where
        Tx: TxToken,
    {
        let checksum_caps = self.device_capabilities.checksum.clone();;
        match packet {
            Packet::Udp((ip_repr, udp_repr)) => {
                self.dispatch_ip(tx_token, timestamp, ip_repr, |ip_repr, payload| {
                    udp_repr.emit(
                        &mut UdpPacket::new_unchecked(payload),
                        &ip_repr.src_addr(),
                        &ip_repr.dst_addr(),
                        &checksum_caps,
                    );
                })
            }
            Packet::Tcp((ip_repr, mut tcp_repr)) => {
                let caps = self.device_capabilities.clone();
                self.dispatch_ip(tx_token, timestamp, ip_repr, |ip_repr, payload| {
                    // This is a terrible hack to make TCP performance more acceptable on systems
                    // where the TCP buffers are significantly larger than network buffers,
                    // e.g. a 64 kB TCP receive buffer (and so, when empty, a 64k window)
                    // together with four 1500 B Ethernet receive buffers. If left untreated,
                    // this would result in our peer pushing our window and sever packet loss.
                    //
                    // I'm really not happy about this "solution" but I don't know what else to do.
                    if let Some(max_burst_size) = caps.max_burst_size {
                        let mut max_segment_size = caps.max_transmission_unit;
                        max_segment_size -= EthernetFrame::<&[u8]>::header_len();
                        max_segment_size -= ip_repr.buffer_len();
                        max_segment_size -= tcp_repr.header_len();

                        let max_window_size = max_burst_size * max_segment_size;
                        if tcp_repr.window_len as usize > max_window_size {
                            tcp_repr.window_len = max_window_size as u16;
                        }
                    }

                    tcp_repr.emit(
                        &mut TcpPacket::new_unchecked(payload),
                        &ip_repr.src_addr(),
                        &ip_repr.dst_addr(),
                        &checksum_caps,
                    );
                })
            }
            Packet::None => Ok(()),
        }
    }

    fn dispatch_ip<Tx, F>(
        &mut self,
        tx_token: Tx,
        timestamp: Instant,
        ip_repr: IpRepr,
        f: F,
    ) -> Result<()>
    where
        Tx: TxToken,
        F: FnOnce(IpRepr, &mut [u8]),
    {
        let ip_repr = ip_repr.lower(&self.ip_addrs)?;
        let checksum_caps = self.device_capabilities.checksum.clone();;

        tx_token.consume(timestamp, ip_repr.total_len(), |tx_buffer| {
            ip_repr.emit(tx_buffer.as_mut(), &checksum_caps);

            let payload = &mut tx_buffer[ip_repr.buffer_len()..];
            f(ip_repr, payload);
            Ok(())
        })
    }
}
