use smoltcp::phy;
use smoltcp::phy::{Device, DeviceCapabilities};
use smoltcp::storage::RingBuffer;
use smoltcp::time::Instant;
use std::cell::{RefCell, RefMut};
use std::rc::Rc;

#[derive(Debug)]
pub struct PhonySocket {
    lower: Rc<RefCell<Lower>>,
    mtu: usize,
}

impl PhonySocket {
    pub fn new(mtu: usize) -> Self {
        PhonySocket {
            lower: Rc::new(RefCell::new(Lower::new())),
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
    pub tx: RingBuffer<'static, u8>,
}

impl Lower {
    pub fn new() -> Self {
        Lower {
            rx: RingBuffer::new(vec![0; 1024 * 10]),
            tx: RingBuffer::new(vec![0; 1024 * 10]),
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
        let mut buf = vec![0; len];
        let ret = f(&mut buf);
        let size = lower.tx.enqueue_slice(&buf);
        assert_eq!(size, len);
        ret
    }
}
