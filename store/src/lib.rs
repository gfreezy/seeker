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

impl Clone for Store {
    fn clone(&self) -> Self {
        Self {
            conn: ReentrantMutex::new(Connection::open(&self.db_path).expect("open db")),
            initial_ip: self.initial_ip,
            db_path: self.db_path.clone(),
        }
    }
}

const CONFIG_REMOTE_SERVERS_CACHE_TTL: u64 = 60 * 60 * 24 * 90; // 90 days
static INSTANCE: OnceCell<Store> = OnceCell::new();

impl Store {
    const TABLE_HOST_IP: &str = "host_ip";
    const TABLE_REMOTE_CONFIG_CACHE: &str = "remote_config_cache";

    pub fn setup_global(path: impl AsRef<Path>, initial_ip: Ipv4Addr) {
        Self::try_setup_global(path, initial_ip).expect("init global store")
    }

    pub fn try_setup_global(path: impl AsRef<Path>, initial_ip: Ipv4Addr) -> Result<(), Self> {
        let store = if cfg!(test) {
            Store::new_in_memory(initial_ip).expect("init store")
        } else {
            Store::new(path, initial_ip).expect("init store")
        };
        INSTANCE.set(store)
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
        let store = Store {
            db_path: path,
            conn: ReentrantMutex::new(conn),
            initial_ip,
        };
        store.init_tables()?;
        Ok(store)
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
        Ok(())
    }
}

// region: host and ip mapping
impl Store {
    pub fn get_host_by_ipv4(&self, ip: Ipv4Addr) -> Result<Option<String>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(&format!(
            r#"SELECT host FROM {} WHERE ip = ?"#,
            Self::TABLE_HOST_IP
        ))?;
        let ret = stmt.query_row([Into::<u32>::into(ip)], |row| row.get::<_, String>("host"));
        match ret {
            Ok(host) => Ok(Some(host)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn get_ipv4_by_host(&self, host: &str) -> Result<Ipv4Addr> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(&format!(
            r#"SELECT ip FROM {} WHERE host = ?"#,
            Self::TABLE_HOST_IP
        ))?;
        match stmt.query_row((host,), |row| row.get::<_, u32>("ip")) {
            Ok(v) => Ok(Ipv4Addr::from(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                let next_ip = self.next_ip()?;
                self.associate_ipv4_and_host(next_ip, host)?;
                Ok(next_ip)
            }
            Err(e) => Err(e.into()),
        }
    }

    fn next_ip(&self) -> Result<Ipv4Addr> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(&format!(
            r#"SELECT MAX(ip) AS ip FROM {}"#,
            Self::TABLE_HOST_IP
        ))?;
        match stmt.query_row((), |row| row.get::<_, u32>("ip")) {
            Ok(v) => Ok(Ipv4Addr::from(v.checked_add(1).expect("ip addr overflow"))),
            Err(e) => Err(e.into()),
        }
    }

    fn associate_ipv4_and_host(&self, ip: Ipv4Addr, host: &str) -> Result<()> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(&format!(
            r#"INSERT INTO {} (ip, host) VALUES (?, ?)"#,
            Self::TABLE_HOST_IP
        ))?;
        let affected = stmt.execute((Into::<u32>::into(ip), host))?;
        assert_eq!(affected, 1);
        Ok(())
    }
}
// endregion: host and ip mapping

// region: config
impl Store {
    pub fn get_cached_remote_config_data(&self, remote_url: &str) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(&format!(
            r#"SELECT * FROM {} WHERE url = ?"#,
            Self::TABLE_REMOTE_CONFIG_CACHE
        ))?;
        let ret = stmt.query_row((remote_url,), |row| {
            Ok((
                row.get::<_, Vec<u8>>("data")?,
                row.get::<_, u64>("last_update")?,
            ))
        });
        let (data, last_update) = match ret {
            Ok(value) => value,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if last_update + CONFIG_REMOTE_SERVERS_CACHE_TTL < now() {
            self.delete_cached_data(remote_url)?;
            return Ok(None);
        }
        Ok(Some(data))
    }

    pub fn cache_remote_config_data(&self, url: &str, data: &[u8]) -> Result<()> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(&format!(
            r#"INSERT OR REPLACE INTO {} (url, data, last_update) VALUES (?, ?, ?)"#,
            Self::TABLE_REMOTE_CONFIG_CACHE
        ))?;
        let affected = stmt.execute((url, data, &now()))?;
        assert_eq!(affected, 1);
        self.delete_expired_data()?;
        Ok(())
    }

    fn delete_cached_data(&self, url: &str) -> Result<()> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(&format!(
            r#"DELETE FROM {} WHERE url = ?"#,
            Self::TABLE_REMOTE_CONFIG_CACHE
        ))?;
        let _affected = stmt.execute((url,))?;
        Ok(())
    }

    fn delete_expired_data(&self) -> Result<()> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(&format!(
            r#"DELETE FROM {} WHERE last_update < ?"#,
            Self::TABLE_REMOTE_CONFIG_CACHE
        ))?;
        let _affected = stmt.execute([(now() - CONFIG_REMOTE_SERVERS_CACHE_TTL)])?;
        Ok(())
    }
}
// endregion: config

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_ipv4_by_host() -> Result<()> {
        let initial_ip = "168.0.0.1".parse().unwrap();
        let store = Store::new_in_memory(initial_ip)?;
        let baidu_domain = "www.baidu.com";
        let baidu_ip = store.get_ipv4_by_host(baidu_domain)?;
        assert_eq!(baidu_ip, Ipv4Addr::from(Into::<u32>::into(initial_ip)));
        assert_eq!(
            store.get_host_by_ipv4(baidu_ip)?,
            Some(baidu_domain.to_string())
        );
        Ok(())
    }

    #[test]
    fn test_cache_remote_config_data() -> Result<()> {
        let initial_ip = "168.0.0.1".parse().unwrap();
        let store = Store::new_in_memory(initial_ip)?;
        let data = store.get_cached_remote_config_data("https://www.baidu.com")?;
        assert!(data.is_none());
        let data = b"hello".to_vec();
        store.cache_remote_config_data("https://www.baidu.com", &data)?;
        let data2 = store.get_cached_remote_config_data("https://www.baidu.com")?;
        assert_eq!(data2, Some(data));
        Ok(())
    }
}
