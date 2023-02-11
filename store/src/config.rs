use crate::{now, Store};
use anyhow::Result;

const CONFIG_REMOTE_SERVERS_CACHE_TTL: u64 = 60 * 60 * 24 * 90; // 90 days

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

#[cfg(test)]
mod tests {
    use super::*;

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
