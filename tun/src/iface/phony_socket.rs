use smoltcp::phy::{Device, DeviceCapabilities};
use smoltcp::storage::RingBuffer;
use smoltcp::time::Instant;
use smoltcp::Result;
use smoltcp::{phy, Error};
use tracing::debug;

const MAX_PACKETS: usize = 1024;

#[derive(Debug)]
pub struct PhonySocket {
    mtu: usize,
    rx: RingBuffer<'static, Vec<u8>>,
    tx: RingBuffer<'static, Vec<u8>>,
}

fn enqueue<'a>(
    ring_buffer: &'a mut RingBuffer<'static, Vec<u8>>,
    mtu: usize,
) -> Result<&'a mut Vec<u8>> {
    let buf = ring_buffer.enqueue_one()?;
    buf.resize(mtu, 0);
    Ok(buf)
}

fn deque<'a>(ring_buffer: &'a mut RingBuffer<'static, Vec<u8>>) -> Option<&'a mut Vec<u8>> {
    //    NLL 目前没法支持这种类型的代码，只能写出这样来绕过 borrow checker
    //    loop {
    //        let buf = ring_buffer.dequeue_one()?;
    //        if !buf.is_empty() {
    //            return Some(buf);
    //        }
    //    }

    loop {
        let buf = ring_buffer.dequeue_one_with(|buf| {
            if !buf.is_empty() {
                Err(smoltcp::Error::Checksum)
            } else {
                Ok(buf)
            }
        });
        match buf {
            Ok(_) => {}
            Err(Error::Checksum) => break,
            Err(Error::Exhausted) => return None,
            Err(_) => unreachable!(),
        }
    }
    match ring_buffer.dequeue_one() {
        Ok(buf) => Some(buf),
        Err(Error::Exhausted) => None,
        Err(_) => unreachable!(),
    }
}

impl PhonySocket {
    pub fn new(mtu: usize) -> Self {
        let rx: Vec<_> = (0..MAX_PACKETS).map(|_| vec![0; mtu]).collect();
        let tx: Vec<_> = (0..MAX_PACKETS).map(|_| vec![0; mtu]).collect();
        PhonySocket {
            mtu,
            rx: RingBuffer::new(rx),
            tx: RingBuffer::new(tx),
        }
    }

    pub fn populate_rx(&mut self) -> Option<&mut Vec<u8>> {
        enqueue(&mut self.rx, self.mtu).ok()
    }

    pub fn vacate_tx(&mut self) -> Option<&mut Vec<u8>> {
        deque(&mut self.tx)
    }
}

impl<'a> Device<'a> for PhonySocket {
    type RxToken = RxToken<'a>;
    type TxToken = TxToken<'a>;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        let buf = deque(&mut self.rx)?;
        let rx = RxToken { buf };
        let tx = TxToken {
            ring_buffer: &mut self.tx,
        };
        Some((rx, tx))
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        let tx = TxToken {
            ring_buffer: &mut self.tx,
        };
        Some(tx)
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut cap = DeviceCapabilities::default();
        cap.max_transmission_unit = self.mtu;
        cap
    }
}

#[doc(hidden)]
pub struct TxToken<'a> {
    ring_buffer: &'a mut RingBuffer<'static, Vec<u8>>,
}

#[doc(hidden)]
pub struct RxToken<'a> {
    buf: &'a mut [u8],
}

impl<'a> phy::TxToken for TxToken<'a> {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        let buf = enqueue(self.ring_buffer, len)?;
        buf.resize(len, 0);
        let ret = f(buf);
        debug!("TxToken.consume {} bytes", len);
        ret
    }
}

impl<'a> phy::RxToken for RxToken<'a> {
    fn consume<R, F>(self, _timestamp: Instant, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        f(self.buf)
    }
}
