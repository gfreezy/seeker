const MAX_PACKET_SIZE: usize = 0x3FFF;

mod ahead;

use crate::ahead::{ahead_decrypted_read, ahead_encrypted_write};
use async_std::future::try_join;
use async_std::net::TcpStream;
use bytes::Bytes;
use config::{ServerAddr, ServerConfig};
use crypto::CipherCategory;
use futures::io::ErrorKind;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use hermesdns::{DnsClient, DnsNetworkClient, QueryType};
use std::io;
use std::io::{Error, Result};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tracing::trace;
use tun::socket::TunUdpSocket;

#[derive(Clone)]
pub struct SSClient {
    srv_cfg: Arc<ServerConfig>,
    dns_server: (String, u16),
    resolver: Arc<DnsNetworkClient>,
}

impl SSClient {
    pub async fn new(server_config: Arc<ServerConfig>, dns_server: (String, u16)) -> SSClient {
        SSClient {
            srv_cfg: server_config,
            resolver: Arc::new(DnsNetworkClient::new(0).await),
            dns_server,
        }
    }

    pub async fn handle_connect<T: AsyncRead + AsyncWrite + Clone + Unpin>(
        &self,
        mut socket: T,
        addr: String,
    ) -> Result<()> {
        let ssserver = get_remote_ssserver_addr(
            &*self.resolver,
            self.srv_cfg.clone(),
            (&self.dns_server.0, self.dns_server.1),
        )
        .await?;
        let conn = TcpStream::connect(ssserver).await?;
        let iv = proxy_handshake(&conn, self.srv_cfg.clone()).await?;

        let mut socket_read = socket.clone();
        let cipher_type = self.srv_cfg.method();
        let key = self.srv_cfg.key();
        let a = async {
            let mut buf = vec![0; MAX_PACKET_SIZE];
            let mut dst = vec![0; MAX_PACKET_SIZE];
            let mut cipher = crypto::new_aead_encryptor(cipher_type, key, &iv);
            let size = ahead_encrypted_write(&mut cipher, &buf, &mut dst, cipher_type)?;
            (&conn).write_all(&dst[..size]).await?;

            let addr_bytes = addr.as_bytes();
            let mut offset = addr_bytes.len();
            buf[..offset].copy_from_slice(addr_bytes);
            loop {
                let size = socket.read(&mut buf[offset..]).await?;
                if size == 0 {
                    break;
                }
                let s = ahead_encrypted_write(
                    &mut cipher,
                    &buf[..offset + size],
                    &mut dst,
                    cipher_type,
                )?;
                (&conn).write_all(&dst[..s]).await?;
                offset = 0;
            }
            Ok(())
        };

        let b = async {
            let mut buf = vec![0; MAX_PACKET_SIZE];
            let mut output = vec![0; MAX_PACKET_SIZE];
            let mut cipher = crypto::new_aead_decryptor(cipher_type, key, &iv);

            loop {
                let size =
                    ahead_decrypted_read(&mut cipher, &conn, &mut buf, &mut output, cipher_type)
                        .await?;
                if size == 0 {
                    break;
                }
                socket_read.write_all(&output[..size]).await?;
            }
            Ok(())
        };

        let _: Result<((), ())> = try_join!(a, b).await;

        Ok(())
    }

    pub async fn handle_packets(&self, _socket: TunUdpSocket, _addr: String) -> Result<()> {
        Ok(())
    }
}

async fn proxy_handshake(mut conn: &TcpStream, srv_cfg: Arc<ServerConfig>) -> Result<Bytes> {
    let method = srv_cfg.method();
    let iv = match method.category() {
        CipherCategory::Stream => {
            let local_iv = method.gen_init_vec();
            trace!("Going to send initialize vector: {:?}", local_iv);
            local_iv
        }
        CipherCategory::Aead => {
            let local_salt = method.gen_salt();
            trace!("Going to send salt: {:?}", local_salt);
            local_salt
        }
    };

    conn.write_all(&iv).await?;
    Ok(iv)
}

async fn resolve_domain<T: DnsClient>(
    resolver: &T,
    server: (&str, u16),
    domain: &str,
) -> Result<Option<IpAddr>> {
    let packet = resolver
        .send_query(domain, QueryType::A, server, true)
        .await?;
    packet
        .get_random_a()
        .map(|ip| {
            ip.parse::<IpAddr>()
                .map_err(|e| io::Error::new(ErrorKind::Other, e))
        })
        .transpose()
}

async fn get_remote_ssserver_addr(
    resolver: &impl DnsClient,
    cfg: Arc<ServerConfig>,
    dns_server: (&str, u16),
) -> Result<SocketAddr> {
    let addr = match cfg.addr() {
        ServerAddr::SocketAddr(addr) => *addr,
        ServerAddr::DomainName(domain, port) => {
            let ip = resolve_domain(resolver, (&dns_server.0, dns_server.1), &domain).await?;
            let ip = match ip {
                Some(i) => i,
                None => {
                    return Err(Error::new(
                        ErrorKind::NotFound,
                        "Domain can not be resolved",
                    ))
                }
            };
            SocketAddr::new(ip, *port)
        }
    };
    Ok(addr)
}
