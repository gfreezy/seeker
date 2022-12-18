use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::Result;
use rusqlite::Connection;

#[derive(Debug)]
pub struct Store {
    conn: Connection,
    initial_ip: Ipv4Addr,
    db_path: PathBuf,
}

impl Clone for Store {
    fn clone(&self) -> Self {
        Self {
            conn: Connection::open(&self.db_path).expect("open db"),
            initial_ip: self.initial_ip,
            db_path: self.db_path.clone(),
        }
    }
}

unsafe impl Send for Store {}

impl Store {
    const TABLE_HOST_IP: &str = "host_ip";

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
            conn,
            initial_ip,
        };
        store.init_tables()?;
        Ok(store)
    }

    #[cfg(test)]
    pub fn new_in_memory(initial_ip: Ipv4Addr) -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Store {
            db_path: PathBuf::new(),
            conn,
            initial_ip,
        };
        store.init_tables()?;
        Ok(store)
    }

    fn init_tables(&self) -> Result<()> {
        let _ = self.conn.execute(
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
        let mut stmt = self.conn.prepare_cached(&format!(
            r#"INSERT OR IGNORE INTO {} (ip, host) VALUES (?, ?)"#,
            Self::TABLE_HOST_IP
        ))?;
        let _ = stmt.execute((Into::<u32>::into(self.initial_ip), ""))?;
        Ok(())
    }

    pub fn get_host_by_ipv4(&self, ip: Ipv4Addr) -> Result<Option<String>> {
        let mut stmt = self.conn.prepare_cached(&format!(
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
        let mut stmt = self.conn.prepare_cached(&format!(
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
        let mut stmt = self.conn.prepare_cached(&format!(
            r#"SELECT MAX(ip) AS ip FROM {}"#,
            Self::TABLE_HOST_IP
        ))?;
        match stmt.query_row((), |row| row.get::<_, u32>("ip")) {
            Ok(v) => Ok(Ipv4Addr::from(v.checked_add(1).expect("ip addr overflow"))),
            Err(e) => Err(e.into()),
        }
    }

    fn associate_ipv4_and_host(&self, ip: Ipv4Addr, host: &str) -> Result<()> {
        let mut stmt = self.conn.prepare_cached(&format!(
            r#"INSERT INTO {} (ip, host) VALUES (?, ?)"#,
            Self::TABLE_HOST_IP
        ))?;
        let affected = stmt.execute((Into::<u32>::into(ip), host))?;
        assert_eq!(affected, 1);
        Ok(())
    }
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
        assert_eq!(baidu_ip, Ipv4Addr::from(Into::<u32>::into(initial_ip) + 1));
        assert_eq!(
            store.get_host_by_ipv4(baidu_ip)?,
            Some(baidu_domain.to_string())
        );
        Ok(())
    }
}
