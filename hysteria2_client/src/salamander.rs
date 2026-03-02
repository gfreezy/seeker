use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

type Blake2b256 = Blake2b<U32>;
use quinn::AsyncUdpSocket;
use rand::Rng;
use std::io;
use std::net::SocketAddr;
use std::task::{Context, Poll};

const SALT_LEN: usize = 8;
const HASH_LEN: usize = 32;

/// Derive XOR key from password and salt using BLAKE2b-256
fn derive_key(password: &[u8], salt: &[u8; SALT_LEN]) -> [u8; HASH_LEN] {
    let mut hasher = Blake2b256::new();
    hasher.update(password);
    hasher.update(salt);
    hasher.finalize().into()
}

/// XOR data with key, cycling through the 32-byte key
fn xor_with_key(data: &mut [u8], key: &[u8; HASH_LEN]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % HASH_LEN];
    }
}

/// Salamander obfuscation wrapper around a UDP socket.
/// Intercepts raw QUIC packets and applies BLAKE2b-256 XOR obfuscation.
pub struct SalamanderSocket {
    inner: std::net::UdpSocket,
    password: Vec<u8>,
}

impl SalamanderSocket {
    pub fn new(inner: std::net::UdpSocket, password: &str) -> io::Result<Self> {
        inner.set_nonblocking(true)?;
        Ok(Self {
            inner,
            password: password.as_bytes().to_vec(),
        })
    }

    /// Obfuscate an outgoing packet: salt(8) + XOR(payload, BLAKE2b(password + salt))
    fn obfuscate(&self, data: &[u8]) -> Vec<u8> {
        let mut salt = [0u8; SALT_LEN];
        rand::rng().fill(&mut salt);
        let key = derive_key(&self.password, &salt);
        let mut result = Vec::with_capacity(SALT_LEN + data.len());
        result.extend_from_slice(&salt);
        result.extend_from_slice(data);
        xor_with_key(&mut result[SALT_LEN..], &key);
        result
    }

    /// Deobfuscate an incoming packet: extract salt, compute key, XOR payload
    fn deobfuscate(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < SALT_LEN {
            return None;
        }
        let salt: [u8; SALT_LEN] = data[..SALT_LEN].try_into().ok()?;
        let key = derive_key(&self.password, &salt);
        let mut payload = data[SALT_LEN..].to_vec();
        xor_with_key(&mut payload, &key);
        Some(payload)
    }
}

impl std::fmt::Debug for SalamanderSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SalamanderSocket")
            .field("inner", &self.inner)
            .finish()
    }
}

impl AsyncUdpSocket for SalamanderSocket {
    fn create_io_poller(self: std::sync::Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        // Create a tokio UdpSocket wrapper for polling
        let socket = self.inner.try_clone().expect("failed to clone socket");
        let tokio_socket =
            tokio::net::UdpSocket::from_std(socket).expect("failed to create tokio socket");
        let arc_socket = std::sync::Arc::new(tokio_socket);
        Box::pin(SalamanderPoller { socket: arc_socket })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        let obfuscated = self.obfuscate(transmit.contents);
        self.inner
            .send_to(&obfuscated, transmit.destination)
            .map(|_| ())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // Use mio-style nonblocking recv
        let mut temp_buf = vec![0u8; 65536];
        match self.inner.recv_from(&mut temp_buf) {
            Ok((n, src)) => {
                let data = &temp_buf[..n];
                if let Some(deobfuscated) = self.deobfuscate(data) {
                    let copy_len = deobfuscated.len().min(bufs[0].len());
                    bufs[0][..copy_len].copy_from_slice(&deobfuscated[..copy_len]);
                    meta[0] = quinn::udp::RecvMeta {
                        addr: src,
                        len: copy_len,
                        stride: copy_len,
                        ecn: None,
                        dst_ip: None,
                    };
                    Poll::Ready(Ok(1))
                } else {
                    // Invalid packet, try again
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        false
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}

/// Poller implementation for the Salamander socket
#[derive(Debug)]
struct SalamanderPoller {
    socket: std::sync::Arc<tokio::net::UdpSocket>,
}

impl quinn::UdpPoller for SalamanderPoller {
    fn poll_writable(self: std::pin::Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.socket.poll_send_ready(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_obfuscate_deobfuscate() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let s = SalamanderSocket::new(socket, "test-password").unwrap();
        let data = b"hello world";
        let obfuscated = s.obfuscate(data);
        assert_ne!(&obfuscated[SALT_LEN..], data);
        let deobfuscated = s.deobfuscate(&obfuscated).unwrap();
        assert_eq!(&deobfuscated, data);
    }

    #[test]
    fn test_obfuscate_produces_salt_prefix() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let s = SalamanderSocket::new(socket, "password").unwrap();
        let data = b"test";
        let obfuscated = s.obfuscate(data);
        // Output should be salt (8 bytes) + XOR'd payload
        assert_eq!(obfuscated.len(), SALT_LEN + data.len());
    }

    #[test]
    fn test_obfuscate_different_each_time() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let s = SalamanderSocket::new(socket, "password").unwrap();
        let data = b"same data";
        let obfuscated1 = s.obfuscate(data);
        let obfuscated2 = s.obfuscate(data);
        // Random salts mean different outputs each time
        assert_ne!(obfuscated1, obfuscated2);
        // But both deobfuscate to the same original
        assert_eq!(s.deobfuscate(&obfuscated1).unwrap(), data);
        assert_eq!(s.deobfuscate(&obfuscated2).unwrap(), data);
    }

    #[test]
    fn test_deobfuscate_wrong_password() {
        let socket1 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let s1 = SalamanderSocket::new(socket1, "password-1").unwrap();
        let socket2 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let s2 = SalamanderSocket::new(socket2, "password-2").unwrap();

        let data = b"secret message";
        let obfuscated = s1.obfuscate(data);
        // Wrong password deobfuscates but produces wrong data
        let wrong = s2.deobfuscate(&obfuscated).unwrap();
        assert_ne!(&wrong[..], data);
    }

    #[test]
    fn test_deobfuscate_too_short() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let s = SalamanderSocket::new(socket, "password").unwrap();
        // Data shorter than salt length should return None
        assert!(s.deobfuscate(&[1, 2, 3]).is_none());
        assert!(s.deobfuscate(&[]).is_none());
    }

    #[test]
    fn test_obfuscate_empty_data() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let s = SalamanderSocket::new(socket, "password").unwrap();
        let data = b"";
        let obfuscated = s.obfuscate(data);
        assert_eq!(obfuscated.len(), SALT_LEN); // only salt, no payload
        let deobfuscated = s.deobfuscate(&obfuscated).unwrap();
        assert!(deobfuscated.is_empty());
    }

    #[test]
    fn test_obfuscate_large_data() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let s = SalamanderSocket::new(socket, "password").unwrap();
        // Payload larger than HASH_LEN to test key cycling
        let data = vec![0xAB; 100];
        let obfuscated = s.obfuscate(&data);
        let deobfuscated = s.deobfuscate(&obfuscated).unwrap();
        assert_eq!(deobfuscated, data);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let salt = [1u8; SALT_LEN];
        let key1 = derive_key(b"password", &salt);
        let key2 = derive_key(b"password", &salt);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_different_salts_different_keys() {
        let salt1 = [1u8; SALT_LEN];
        let salt2 = [2u8; SALT_LEN];
        let key1 = derive_key(b"password", &salt1);
        let key2 = derive_key(b"password", &salt2);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_different_passwords_different_keys() {
        let salt = [1u8; SALT_LEN];
        let key1 = derive_key(b"password-a", &salt);
        let key2 = derive_key(b"password-b", &salt);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_xor_with_key_reversible() {
        let key = [0xAA; HASH_LEN];
        let mut data = b"hello world!".to_vec();
        let original = data.clone();
        xor_with_key(&mut data, &key);
        assert_ne!(data, original);
        xor_with_key(&mut data, &key);
        assert_eq!(data, original);
    }
}
