mod config;
mod connections;
mod dns;

use parking_lot::ReentrantMutex;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use once_cell::sync::OnceCell;
use rusqlite::Connection;

#[derive(Debug)]
pub struct Store {
    conn: ReentrantMutex<Connection>,
    initial_ip: Ipv4Addr,
    db_path: PathBuf,
}

static INSTANCE: OnceCell<Store> = OnceCell::new();

impl Clone for Store {
    fn clone(&self) -> Self {
        Self {
            conn: ReentrantMutex::new(Connection::open(&self.db_path).expect("open db")),
            initial_ip: self.initial_ip,
            db_path: self.db_path.clone(),
        }
    }
}

impl Store {
    const TABLE_HOST_IP: &str = "host_ip";
    const TABLE_REMOTE_CONFIG_CACHE: &str = "remote_config_cache";
    const TABLE_CONNECTIONS: &str = "connections";

    pub fn setup_global(path: impl AsRef<Path>, initial_ip: Ipv4Addr) {
        Self::try_setup_global(path, initial_ip).expect("init global store")
    }

    pub fn try_setup_global(path: impl AsRef<Path>, initial_ip: Ipv4Addr) -> Result<(), Self> {
        let store = Store::new(path, initial_ip).expect("init store");
        INSTANCE.set(store)
    }

    pub fn setup_global_for_test() {
        let _ = INSTANCE
            .get_or_init(|| Store::new_in_memory("10.0.0.1".parse().unwrap()).expect("init store"));
    }

    pub fn global() -> &'static Self {
        INSTANCE.get().expect("global store is not initialized")
    }

    pub fn new(db_path: impl AsRef<Path>, initial_ip: Ipv4Addr) -> Result<Self> {
        let path = db_path.as_ref().to_path_buf();
        let conn = match Connection::open(&path) {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!(
                    "Open db `{:?}` error: {}.\nDelete and reinitialize db",
                    &path, e
                );
                std::fs::remove_dir_all(&path)?;
                Connection::open(&path)?
            }
        };
        conn.pragma_update(None, "journal_mode", "WAL")
            .expect("set journal_mode");
        conn.pragma_update(None, "synchronous", "off")
            .expect("set synchronous");
        conn.pragma_update(None, "temp_store", "memory")
            .expect("set temp_store");
        let store = Store {
            db_path: path,
            conn: ReentrantMutex::new(conn),
            initial_ip,
        };
        store.init_tables()?;
        Ok(store)
    }

    #[cfg(test)]
    pub fn store_for_test() -> Self {
        Store::new_in_memory(Ipv4Addr::new(127, 0, 0, 1)).expect("init store")
    }

    pub fn new_in_memory(initial_ip: Ipv4Addr) -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Store {
            db_path: PathBuf::new(),
            conn: ReentrantMutex::new(conn),
            initial_ip,
        };
        store.init_tables()?;
        Ok(store)
    }

    fn init_tables(&self) -> Result<()> {
        let conn = self.conn.lock();
        let _ = conn.execute(
            &format!(
                r#"
            CREATE TABLE IF NOT EXISTS {} (
                ip INTEGER PRIMARY KEY,
                host TEXT NOT NULL UNIQUE
            )
            "#,
                Self::TABLE_HOST_IP,
            ),
            (),
        )?;

        // region: remote_config_cache
        conn.execute_batch(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {table} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL UNIQUE,
                data BLOB NOT NULL,
                last_update INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS {table}_last_update ON {table} (last_update);
            "#,
            table = Self::TABLE_REMOTE_CONFIG_CACHE,
        ))?;
        let mut stmt = conn.prepare_cached(&format!(
            r#"INSERT OR IGNORE INTO {} (ip, host) VALUES (?, ?)"#,
            Self::TABLE_HOST_IP
        ))?;
        let ip_num: u32 = self.initial_ip.into();
        assert!(ip_num > 1, "initial ip should be greater than 1");
        let prev: Ipv4Addr = (ip_num - 1).into();
        let _ = stmt.execute((Into::<u32>::into(prev), ""))?;
        // endregion: remote_config_cache

        // region: connections
        // | id | host | network | type | recv_bytes | sent_bytes | proxy_server | connect_time | last_update | is_alive |
        // connection data is cleared whenever the process starts.
        conn.execute_batch(&format!(
            r#"
            DROP TABLE IF EXISTS {table};
            CREATE TABLE IF NOT EXISTS {table} (
                id INTEGER PRIMARY KEY,
                host TEXT NOT NULL,
                network TEXT NOT NULL,
                type TEXT NOT NULL,
                recv_bytes INTEGER NOT NULL,
                sent_bytes INTEGER NOT NULL,
                proxy_server TEXT NOT NULL,
                connect_time INTEGER NOT NULL,
                last_update INTEGER NOT NULL,
                is_alive INTEGER NOT NULL
            );
            "#,
            table = Self::TABLE_CONNECTIONS,
        ))?;
        // endregion: connections
        Ok(())
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
