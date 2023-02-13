use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct Traffic {
    connect_time: Instant,
    recv: Arc<AtomicUsize>,
    send: Arc<AtomicUsize>,
}

impl Default for Traffic {
    fn default() -> Self {
        Self {
            connect_time: Instant::now(),
            recv: Arc::new(AtomicUsize::new(0)),
            send: Arc::new(AtomicUsize::new(0)),
        }
    }
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

    pub fn duration(&self) -> Duration {
        Instant::now().duration_since(self.connect_time)
    }
}
