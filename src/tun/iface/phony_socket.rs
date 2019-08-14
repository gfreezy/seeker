use log::debug;
use smoltcp::phy;
use smoltcp::phy::{Device, DeviceCapabilities};
use smoltcp::storage::RingBuffer;
use smoltcp::time::Instant;
use std::cell::{RefCell, RefMut};
use std::rc::Rc;

const MAX_PACKETS: usize = 102400;

#[derive(Debug)]
pub struct PhonySocket {
    lower: Rc<RefCell<Lower>>,
    mtu: usize,
}

impl PhonySocket {
    pub fn new(mtu: usize) -> Self {
        PhonySocket {
            lower: Rc::new(RefCell::new(Lower::new(mtu))),
            mtu,
        }
    }

    pub fn lower(&self) -> RefMut<Lower> {
        self.lower.borrow_mut()
    }
}

#[derive(Debug)]
pub struct Lower {
    pub rx: RingBuffer<'static, u8>,
    pub tx: RingBuffer<'static, Vec<u8>>,
}

impl Lower {
    pub fn new(mtu: usize) -> Self {
        let tx = {
            let mut tx = Vec::with_capacity(MAX_PACKETS);
            for _i in 0..MAX_PACKETS {
                tx.push(vec![0; mtu])
            }
            tx
        };
        Lower {
            rx: RingBuffer::new(vec![0; mtu * MAX_PACKETS]),
            tx: RingBuffer::new(tx),
        }
    }
}

impl<'a> Device<'a> for PhonySocket {
    type RxToken = RxToken;
    type TxToken = TxToken;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        let mut lower = self.lower.borrow_mut();
        if lower.rx.is_empty() {
            return None;
        }

        let mut buf = vec![0; self.mtu];
        let size = lower.rx.dequeue_slice(&mut buf);
        debug!("dequeue {} bytes", size);
        buf.truncate(size);
        let rx = RxToken { buf };
        let tx = TxToken {
            lower: self.lower.clone(),
        };
        Some((rx, tx))
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        Some(TxToken {
            lower: self.lower.clone(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut cap = DeviceCapabilities::default();
        cap.max_transmission_unit = self.mtu;
        cap
    }
}

#[doc(hidden)]
pub struct RxToken {
    buf: Vec<u8>,
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(mut self, _timestamp: Instant, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        f(&mut self.buf)
    }
}

#[doc(hidden)]
pub struct TxToken {
    lower: Rc<RefCell<Lower>>,
}

impl phy::TxToken for TxToken {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        let mut lower = self.lower.borrow_mut();
        let buf = lower.tx.enqueue_one()?;
        buf.resize(len, 0);
        let ret = f(buf);
        debug!("TxToken.consume {} bytes", len);
        ret
    }
}
