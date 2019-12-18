use std::collections::VecDeque;
use std::io::Result;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_std::future;
use async_std::io;
use async_std::sync::{channel, Mutex, Receiver, Sender};
use futures::future::BoxFuture;
use tracing::{error, trace};

use crate::encrypted_stream::EncryptedTcpStream;

pub(crate) type EncryptedStremBox = Box<dyn EncryptedTcpStream + Send + Sync>;

pub(crate) type Connector =
    Arc<dyn Fn() -> BoxFuture<'static, Result<EncryptedStremBox>> + Send + Sync + 'static>;

#[derive(Clone)]
pub(crate) struct Pool {
    max_idle: usize,
    connections: Arc<Mutex<VecDeque<EncryptedStremBox>>>,
    connector: Connector,
    connect_timeout: Duration,
    sender: Sender<()>,
    receiver: Receiver<()>,
}

impl Pool {
    pub(crate) fn new(connector: Connector, max_idle: usize, connect_timeout: Duration) -> Self {
        let (sender, receiver) = channel(1);
        Self {
            max_idle,
            connections: Arc::new(Mutex::new(VecDeque::with_capacity(max_idle))),
            connector,
            connect_timeout,
            sender,
            receiver,
        }
    }

    pub(crate) async fn run_connection_pool(&self) {
        let connections = self.connections.clone();
        loop {
            let mut len = connections.lock().await.len();
            while len < self.max_idle {
                trace!(
                    current_idle = len,
                    max_idle = self.max_idle,
                    "create new connection"
                );
                let conn = match self.new_connection().await {
                    Ok(conn) => conn,
                    Err(e) => {
                        error!(error = ?e, "create new connection error");
                        continue;
                    }
                };
                let mut conns = connections.lock().await;
                conns.push_back(conn);
                len = conns.len();
            }
            if self.receiver.recv().await == None {
                break;
            }
        }
    }

    async fn new_connection(&self) -> Result<EncryptedStremBox> {
        let now = Instant::now();
        let conn = match io::timeout(self.connect_timeout, (self.connector)()).await {
            Ok(conn) => conn,
            Err(e) => {
                error!(err = ?e, "new connection error");
                return Err(e);
            }
        };
        let duration = now.elapsed();
        trace!(duration = ?duration, "Pool.new_connection");
        Ok(conn)
    }

    pub(crate) async fn get_connection(&self) -> Result<EncryptedStremBox> {
        let conn = self.connections.lock().await.pop_front();
        let ret = match conn {
            Some(conn) => Ok(conn),
            None => {
                trace!("connection pool empty, create connection directly");
                self.new_connection().await
            }
        };
        let size = self.size().await;
        trace!(size = size, "connection pool size");
        let send_ret = future::timeout(Duration::from_secs(5), self.sender.send(())).await;
        if let Err(e) = send_ret {
            error!(error = ?e, "send error");
        }

        match ret {
            Ok(conn) => Ok(conn),
            Err(e) => {
                error!(err = ?e, "create connection directly error when get connection");
                Err(e)
            }
        }
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
            "srvname".to_string(),
            ServerAddr::DomainName("sdf".to_string(), 112),
            "pass".to_string(),
            CipherType::ChaCha20Ietf,
            Duration::from_secs(3),
            Duration::from_secs(3),
            Duration::from_secs(3),
            10,
        ));
        let ssserver = "119.29.29.29:80".parse().unwrap();

        let ret: Result<()> = task::block_on(async {
            let pool = Pool::new(
                Arc::new(move || {
                    let srv_cfg_clone = srv_cfg.clone();
                    async move {
                        let conn: EncryptedStremBox = Box::new(
                            StreamEncryptedTcpStream::new(
                                ssserver,
                                srv_cfg_clone.method(),
                                srv_cfg_clone.key(),
                                srv_cfg_clone.connect_timeout(),
                                srv_cfg_clone.read_timeout(),
                                srv_cfg_clone.write_timeout(),
                            )
                            .await?,
                        );
                        Ok(conn)
                    }
                        .boxed()
                }),
                10,
                Duration::from_secs(5),
            );
            let pool_clone = pool.clone();
            task::spawn(async move {
                pool_clone.run_connection_pool().await;
            });
            let _conn = pool.get_connection().await?;
            task::sleep(Duration::from_secs(1)).await;
            assert!(pool.size().await > 0);
            Ok(())
        });
        ret.unwrap();
    }
}
