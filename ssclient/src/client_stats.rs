use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use async_std::future;
use async_std::sync::RwLock;

use chrono::{DateTime, Local, TimeZone};
use config::Address;
use lazy_static::lazy_static;
use std::sync::atomic::Ordering::SeqCst;

lazy_static! {
    static ref NEVER: DateTime<Local> = Local.ymd(9999, 1, 1).and_hms(0, 0, 0);
}

#[derive(Debug)]
pub struct ConnectionStats {
    pub address: Address,
    pub open_time: DateTime<Local>,
    pub close_time: DateTime<Local>,
    pub sent_bytes: u64,
    pub recv_bytes: u64,
}

impl ConnectionStats {
    fn new(addr: Address) -> ConnectionStats {
        ConnectionStats {
            address: addr,
            open_time: Local::now(),
            close_time: *NEVER,
            sent_bytes: 0,
            recv_bytes: 0,
        }
    }

    pub fn is_open(&self) -> bool {
        self.close_time.timestamp() == NEVER.timestamp()
    }

    pub fn is_closed(&self) -> bool {
        !self.is_open()
    }
}
#[derive(Default)]
pub struct ClientStats {
    counter: AtomicU64,
    inner: RwLock<HashMap<u64, ConnectionStats>>,
}

impl ClientStats {
    pub fn new() -> ClientStats {
        ClientStats::default()
    }

    pub async fn add_connection(&self, addr: Address) -> u64 {
        let idx = self.counter.fetch_add(1, SeqCst);
        let mut guard = future::timeout(Duration::from_secs(3), self.inner.write())
            .await
            .expect("stats write lock timed out");
        guard.insert(idx, ConnectionStats::new(addr));
        idx
    }

    pub async fn is_empty(&self) -> bool {
        let guard = future::timeout(Duration::from_secs(3), self.inner.read())
            .await
            .expect("lock stats for write");
        guard.is_empty()
    }

    pub async fn recycle_stats(&self) {
        let mut guard = future::timeout(Duration::from_secs(3), self.inner.write())
            .await
            .expect("lock stats for write");
        guard.retain(|_, v| !v.is_closed())
    }

    pub async fn update_connection_stats<F>(&self, idx: u64, f: F)
    where
        F: FnOnce(&mut ConnectionStats),
    {
        let mut guard = future::timeout(Duration::from_secs(3), self.inner.write())
            .await
            .expect("lock stats for write");
        if let Some(stats) = guard.get_mut(&idx) {
            f(stats)
        }
    }

    pub async fn iter_items<F>(&self, f: F)
    where
        F: Fn(&u64, &ConnectionStats),
    {
        let guard = self.inner.read().await;
        for (k, v) in guard.iter() {
            f(k, v)
        }
    }

    pub async fn print_stats(&self) {
        let stats = self.inner.read().await;
        if stats.is_empty() {
            return;
        }
        for conn in stats.values() {
            if conn.is_open() {
                println!(
                    "Connect time: {}, duration: {}s, addr: {}, sent_bytes: {}, recv_bytes: {}",
                    conn.open_time.format("%Y-%m-%d %H:%M:%S").to_string(),
                    (Local::now() - conn.open_time).num_seconds(),
                    conn.address,
                    conn.sent_bytes,
                    conn.recv_bytes
                );
            } else {
                println!(
                    "Connect time: {}, close time: {}, addr: {}, sent_bytes: {}, recv_bytes: {}",
                    conn.open_time.format("%Y-%m-%d %H:%M:%S").to_string(),
                    conn.close_time.format("%Y-%m-%d %H:%M:%S").to_string(),
                    conn.address,
                    conn.sent_bytes,
                    conn.recv_bytes
                );
            }
        }
    }
}
