use smoltcp::phy;
use smoltcp::phy::{Device, DeviceCapabilities};
use smoltcp::storage::RingBuffer;
use smoltcp::time::Instant;
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
) -> Option<&'a mut Vec<u8>> {
    let buf = ring_buffer.enqueue_one().ok()?;
    buf.resize(mtu, 0);
    Some(buf)
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
            Err(smoltcp::Error::Checksum) => break,
            Err(_) => return None,
        }
    }
    ring_buffer.dequeue_one().ok()
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
        enqueue(&mut self.rx, self.mtu)
    }

    pub fn vacate_tx(&mut self) -> Option<&mut Vec<u8>> {
        deque(&mut self.tx)
    }
}

impl<'a> Device<'a> for PhonySocket {
    type RxToken = Token<'a>;
    type TxToken = Token<'a>;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        let rx = Token {
            buf: deque(&mut self.rx)?,
        };
        let tx = Token {
            buf: enqueue(&mut self.tx, self.mtu)?,
        };
        Some((rx, tx))
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        let tx = Token {
            buf: enqueue(&mut self.tx, self.mtu)?,
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
pub struct Token<'a> {
    buf: &'a mut Vec<u8>,
}

impl<'a> phy::TxToken for Token<'a> {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        self.buf.resize(len, 0);
        let ret = f(self.buf);
        debug!("TxToken.consume {} bytes", len);
        ret
    }
}

impl<'a> phy::RxToken for Token<'a> {
    fn consume<R, F>(self, _timestamp: Instant, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        f(self.buf)
    }
}
