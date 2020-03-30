// pub mod direct_client;
// pub mod ruled_client;
// pub mod shadowsocks_client;
// pub mod socks5_client;

use async_std::net::TcpStream;
use config::Address;
use std::io::Result;
use tun::socket::TunUdpSocket;

async fn handle_connection<T: Read + Write + Clone>(
    client: T,
    session_manager: Arc<RwLock<SessionManager>>,
    config: Config,
    term: Arc<AtomicBool>,
) {
    let (dns_server, resolver) = create_dns_server(
        "dns.db",
        config.dns_listen.clone(),
        config.dns_start_ip,
        config.rules.clone(),
        (config.dns_server.ip().to_string(), config.dns_server.port()),
    )
    .await;
    println!("Spawn DNS server");
    spawn(
        dns_server
            .run_server()
            .instrument(trace_span!("dns_server.run_server")),
    );

    let tcp_relay = async {
        let listener = TcpListener::bind((config.tun_ip, 1300)).await?;
        let mut incoming = listener.incoming();
        loop {
            let conn = timeout(Duration::from_secs(1), async {
                incoming.next().await.transpose()
            })
            .await;
            let conn = match conn {
                Ok(Some(conn)) => conn,
                Ok(None) => break,
                Err(e) if e.kind() == ErrorKind::TimedOut => {
                    if term.load(Ordering::SeqCst) {
                        break;
                    }
                    continue;
                }
                Err(e) => return Err(e),
            };
            let remote_addr = conn.peer_addr()?;
            let manager = session_manager.read();
            let assoc = manager.get_by_port(remote_addr.port());
            let real_dest_addr = SocketAddrV4::new(assoc.dest_addr, assoc.dest_port);
            let real_src_addr = SocketAddrV4::new(assoc.src_addr, assoc.src_port);
            let resolver_clone = resolver.clone();
            let client_clone = client.clone();

            spawn(async move {
                let ip = real_dest_addr.ip().to_string();
                let host = resolver_clone
                    .lookup_host(&ip)
                    .instrument(trace_span!("lookup host", ip = ?ip))
                    .await
                    .map(|s| Address::DomainNameAddress(s, real_dest_addr.port()))
                    .unwrap_or_else(|| Address::SocketAddress(real_dest_addr.into()));

                trace!(ip = ?ip, host = ?host, "lookup host");

                client_clone
                    .handle_tcp(conn, host.clone())
                    .instrument(trace_span!("handle tcp", src_addr = %real_src_addr, host = %host))
                    .await
            });
        }
        Ok::<(), io::Error>(())
    };

    tcp_relay.await.unwrap();
}
