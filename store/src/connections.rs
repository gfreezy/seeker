use std::sync::atomic::Ordering;
use std::time::Instant;

use crate::{now, Store};
use anyhow::Result;
use rusqlite::params;
use std::sync::LazyLock;

#[derive(Debug, Default, PartialEq)]
pub struct Connection {
    pub id: u64,
    pub host: String,
    pub network: String,
    pub conn_type: String,
    pub recv_bytes: u64,
    pub sent_bytes: u64,
    pub proxy_server: String,
    pub connect_time: u64,
    pub last_update: u64,
    pub is_alive: bool,
}

impl Store {
    // create connection with the following data:
    // | id | host | network | type | recv_bytes | sent_bytes | proxy_server | connect_time | last_update | is_alive |
    pub fn new_connection(
        &self,
        id: u64,
        host: &str,
        network: &str,
        conn_type: &str,
        proxy_server: &str,
    ) -> Result<()> {
        let conn = self.conn.lock();
        let _ = conn.execute(
            &format!(
                r#"
            INSERT INTO {} (id, host, network, type, recv_bytes, sent_bytes, proxy_server, connect_time, last_update, is_alive)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            "#,
                Self::TABLE_CONNECTIONS,
            ),
            params![
                id,
                host,
                network,
                conn_type,
                0,
                0,
                proxy_server,
                now(),
                now(),
            ],
        )?;
        Ok(())
    }

    pub fn update_connection(
        &self,
        id: u64,
        recv_bytes: u64,
        sent_bytes: u64,
        last_update: Option<u64>,
    ) -> Result<()> {
        let conn = self.conn.lock();
        let _ = conn.execute(
            &format!(
                r#"
            UPDATE {} SET recv_bytes = ?, sent_bytes = ?, last_update = ?
            WHERE id = ?
            "#,
                Self::TABLE_CONNECTIONS,
            ),
            params![recv_bytes, sent_bytes, last_update.unwrap_or_else(now), id],
        )?;
        Ok(())
    }

    pub fn incr_connection_recv_bytes(&self, id: u64, bytes: u64) -> Result<()> {
        {
            let key = format!("recv_bytes:{}", id);
            let mut cache = self.cache_stats.write();
            *cache.entry(key).or_insert(0) += bytes;
        }
        self.maybe_flush_stats()?;
        Ok(())
    }

    pub fn incr_connection_sent_bytes(&self, id: u64, bytes: u64) -> Result<()> {
        {
            let key = format!("sent_bytes:{}", id);
            let mut cache = self.cache_stats.write();
            *cache.entry(key).or_insert(0) += bytes;
        }
        self.maybe_flush_stats()?;
        Ok(())
    }

    fn maybe_flush_stats(&self) -> Result<()> {
        static INITIAL: LazyLock<Instant> = LazyLock::new(Instant::now);
        const FLUSH_INTERVAL: u64 = 5; // Flush every 5 seconds
        let last_flush = self.last_flush_ts.load(Ordering::SeqCst) as u64;
        let current_time = INITIAL.elapsed().as_secs();
        if current_time - last_flush >= FLUSH_INTERVAL {
            self.flush_stats()?;
            self.last_flush_ts
                .store(current_time as u32, Ordering::SeqCst);
        }
        Ok(())
    }

    fn flush_stats(&self) -> Result<()> {
        {
            let cache = self.cache_stats.read();
            let conn = self.conn.lock();
            for (key, &value) in cache.iter() {
                let (column, id) = key.split_once(':').unwrap();
                conn.execute(
                    &format!(
                        r#"
                UPDATE {} SET {} = {} + ?, last_update = ?
                WHERE id = ?
                "#,
                        Self::TABLE_CONNECTIONS,
                        column,
                        column
                    ),
                    params![value, now(), id],
                )?;
            }
        }
        self.cache_stats.write().clear();
        Ok(())
    }

    pub fn shutdown_connection(&self, id: u64) -> Result<()> {
        let conn = self.conn.lock();
        let _ = conn.execute(
            &format!(
                r#"
            UPDATE {} SET is_alive = 0, last_update = ?
            WHERE id = ?
            "#,
                Self::TABLE_CONNECTIONS,
            ),
            params![now(), id],
        )?;
        self.clear_dead_connections(60 * 30)?;
        Ok(())
    }

    pub fn clear_dead_connections(&self, timeout_secs: u64) -> Result<()> {
        let conn = self.conn.lock();
        let _ = conn.execute(
            &format!(
                r#"
            DELETE FROM {} WHERE is_alive = 0 AND last_update <= ?
            "#,
                Self::TABLE_CONNECTIONS,
            ),
            params![now() - timeout_secs],
        )?;
        Ok(())
    }

    pub fn list_connections(&self) -> Result<Vec<Connection>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(&format!(
            r#"
            SELECT id, host, network, type, recv_bytes, sent_bytes, proxy_server, connect_time, last_update, is_alive
            FROM {}
            "#,
            Self::TABLE_CONNECTIONS,
        ))?;
        let mut rows = stmt.query(params![])?;
        let mut connections = Vec::new();
        while let Some(row) = rows.next()? {
            let connection = Connection {
                id: row.get(0)?,
                host: row.get(1)?,
                network: row.get(2)?,
                conn_type: row.get(3)?,
                recv_bytes: row.get(4)?,
                sent_bytes: row.get(5)?,
                proxy_server: row.get(6)?,
                connect_time: row.get(7)?,
                last_update: row.get(8)?,
                is_alive: row.get(9)?,
            };
            connections.push(connection);
        }
        Ok(connections)
    }
}

// tests
#[cfg(test)]
mod tests {
    use super::*;

    // insert a new connection and check if it is inserted correctly
    #[test]
    fn test_new_connection() {
        let store = Store::store_for_test();
        let id = 1;
        let host = "baidu.com";
        let network = "tcp";
        let conn_type = "client";
        let proxy_server = "proxy.com";
        store
            .new_connection(id, host, network, conn_type, proxy_server)
            .unwrap();
        let connections = store.list_connections().unwrap();
        assert_eq!(connections.len(), 1);
        let connection = &connections[0];
        assert_eq!(connection.id, id);
    }

    // update a connection and check if it is updated correctly
    #[test]
    fn test_update_connection() {
        let store = Store::store_for_test();
        let id = 1;
        let host = "baidu.com";
        let network = "tcp";
        let conn_type = "client";
        let proxy_server = "proxy.com";
        store
            .new_connection(id, host, network, conn_type, proxy_server)
            .unwrap();
        let recv_bytes = 100;
        let sent_bytes = 200;
        store
            .update_connection(id, recv_bytes, sent_bytes, None)
            .unwrap();
        let connections = store.list_connections().unwrap();
        assert_eq!(connections.len(), 1);
        let connection = &connections[0];
        assert_eq!(connection.id, id);
        assert_eq!(connection.recv_bytes, recv_bytes);
        assert_eq!(connection.sent_bytes, sent_bytes);
    }

    // shutdown a connection and check if it is shutdown correctly
    #[test]
    fn test_shutdown_connection() {
        let store = Store::store_for_test();
        let id = 1;
        let host = "baidu.com";
        let network = "tcp";
        let conn_type = "client";
        let proxy_server = "proxy.com";
        store
            .new_connection(id, host, network, conn_type, proxy_server)
            .unwrap();
        store.shutdown_connection(id).unwrap();
        let connections = store.list_connections().unwrap();
        assert_eq!(connections.len(), 1);
        let connection = &connections[0];
        assert_eq!(connection.id, id);
        assert!(!connection.is_alive);
    }

    // clear dead connections and check if it is cleared correctly
    #[test]
    fn test_clear_dead_connections() {
        let store = Store::store_for_test();
        let id = 1;
        let host = "baidu.com";
        let network = "tcp";
        let conn_type = "client";
        let proxy_server = "proxy.com";
        store
            .new_connection(id, host, network, conn_type, proxy_server)
            .unwrap();
        store
            .new_connection(id + 1, host, network, conn_type, proxy_server)
            .unwrap();
        store
            .new_connection(id + 2, host, network, conn_type, proxy_server)
            .unwrap();
        store
            .new_connection(id + 3, host, network, conn_type, proxy_server)
            .unwrap();
        store.shutdown_connection(id).unwrap();
        store.clear_dead_connections(0).unwrap();
        let connections = store.list_connections().unwrap();
        assert_eq!(connections.len(), 3);
    }
}
