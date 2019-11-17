use std::collections::VecDeque;
use std::io::Result;
use std::sync::Arc;
use std::time::Instant;

use async_std::sync::Mutex;
use async_std::sync::{channel, Receiver, Sender};
use futures::future::BoxFuture;
use tracing::trace;

use crate::encrypted_stream::EncryptedTcpStream;

pub(crate) type EncryptedStremBox = Box<dyn EncryptedTcpStream + Send + Sync>;

pub(crate) type Connector =
    Arc<dyn Fn() -> BoxFuture<'static, Result<EncryptedStremBox>> + Send + Sync + 'static>;

#[derive(Clone)]
pub(crate) struct Pool {
    max_idle: usize,
    connections: Arc<Mutex<VecDeque<EncryptedStremBox>>>,
    connector: Connector,
    sender: Sender<()>,
    receiver: Receiver<()>,
}

impl Pool {
    pub(crate) fn new(max_idle: usize, connector: Connector) -> Self {
        let (sender, receiver) = channel(1);
        Self {
            max_idle,
            connections: Arc::new(Mutex::new(VecDeque::with_capacity(max_idle))),
            connector,
            sender,
            receiver,
        }
    }

    pub(crate) async fn run_connection_pool(&self) -> Result<()> {
        let connections = self.connections.clone();
        loop {
            let len = connections.lock().await.len();
            for _ in 0..(self.max_idle - len) {
                let conn = self.new_connection().await?;
                let mut conns = connections.lock().await;
                conns.push_back(conn);
            }
            if self.receiver.recv().await == None {
                break;
            }
        }
        Ok(())
    }

    async fn new_connection(&self) -> Result<EncryptedStremBox> {
        let now = Instant::now();
        let conn = (self.connector)().await?;
        let duration = now.elapsed();
        trace!(duration = ?duration, "Pool.new_connection");
        Ok(conn)
    }

    pub(crate) async fn get_connection(&self) -> Result<EncryptedStremBox> {
        let ret = match self.connections.lock().await.pop_front() {
            Some(conn) => Ok(conn),
            None => self.new_connection().await,
        };
        let size = self.size().await;
        trace!(size = size, "connection pool size");
        self.sender.send(()).await;
        ret
    }

    #[allow(dead_code)]
    pub(crate) async fn size(&self) -> usize {
        self.connections.lock().await.len()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Result;
    use std::sync::Arc;
    use std::time::Duration;

    use async_std::task;
    use futures::FutureExt;

    use config::{ServerAddr, ServerConfig};
    use crypto::CipherType;

    use crate::connection_pool::Pool;
    use crate::encrypted_stream::StreamEncryptedTcpStream;

    use super::*;

    #[test]
    fn test_pool() {
        let srv_cfg = Arc::new(ServerConfig::new(
            ServerAddr::DomainName("sdf".to_string(), 112),
            "pass".to_string(),
            CipherType::ChaCha20Ietf,
            Duration::from_secs(3),
            Duration::from_secs(3),
            Duration::from_secs(3),
            10,
        ));
        let ssserver = "114.114.114.114:53".parse().unwrap();

        let ret: Result<()> = task::block_on(async {
            let pool = Pool::new(
                10,
                Arc::new(move || {
                    let srv_cfg_clone = srv_cfg.clone();
                    async move {
                        let conn: EncryptedStremBox =
                            Box::new(StreamEncryptedTcpStream::new(srv_cfg_clone, ssserver).await?);
                        Ok(conn)
                    }
                        .boxed()
                }),
            );
            let pool_clone = pool.clone();
            task::spawn(async move {
                pool_clone.run_connection_pool().await.unwrap();
            });
            let _conn = pool.get_connection().await?;
            task::sleep(Duration::from_secs(1)).await;
            assert!(pool.size().await > 0);
            Ok(())
        });
        ret.unwrap();
    }
}
