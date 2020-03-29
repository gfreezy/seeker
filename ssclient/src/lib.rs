mod tcp_io;
mod udp_io;

const BUFFER_SIZE: usize = 8 * 1024; // 8K buffer

pub use tcp_io::SSTcpStream;
pub use udp_io::SSUdpSocket;

#[cfg(test)]
fn setup_tracing_subscriber() {
    use tracing_subscriber::fmt::Subscriber;
    use tracing_subscriber::EnvFilter;

    let builder = Subscriber::builder().with_env_filter(EnvFilter::new("ssclient=trace"));
    builder.try_init().unwrap();
}
