use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Clone, Default)]
pub struct Traffic {
    recv: Arc<AtomicUsize>,
    send: Arc<AtomicUsize>,
}

impl Traffic {
    pub fn recv(&self, size: usize) {
        self.recv.fetch_add(size, Ordering::Relaxed);
    }

    pub fn send(&self, size: usize) {
        self.send.fetch_add(size, Ordering::Relaxed);
    }

    pub fn received_bytes(&self) -> usize {
        self.recv.load(Ordering::Relaxed)
    }

    pub fn sent_bytes(&self) -> usize {
        self.send.load(Ordering::Relaxed)
    }
}
