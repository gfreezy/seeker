//! REALITY TLS authentication. Wire format follows XTLS/Xray-core and XTLS/REALITY.
//! TLS record protection and transcript verification remain in rustls.
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, ML_KEM_768};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use config::RealityOptions;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{Rng, seq::SliceRandom};
use rustls::client::{
    ClientHelloCustomizer, Resumption,
    danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
};
use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, Error, NamedGroup, SignatureScheme};
use sha2::{Sha256, Sha512};
use std::{
    io,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use x509_parser::prelude::FromDer;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

fn fail(message: &str) -> Error {
    Error::General(format!("REALITY: {message}"))
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("REALITY: {message}"))
}

#[derive(Clone, Debug)]
pub(crate) struct Options {
    public_key: [u8; 32],
    short_id: [u8; 8],
    hybrid: bool,
}

impl Options {
    pub fn parse(options: &RealityOptions, fingerprint: Option<&str>) -> io::Result<Self> {
        if !matches!(fingerprint.unwrap_or("chrome"), "chrome") {
            return Err(invalid("supported client-fingerprint: chrome"));
        }
        let public_key: [u8; 32] = URL_SAFE_NO_PAD
            .decode(options.public_key.trim_end_matches('='))
            .map_err(|_| invalid("public-key must be base64url"))?
            .try_into()
            .map_err(|_| invalid("public-key must contain 32 bytes"))?;
        let hex = options.short_id.as_bytes();
        if hex.len() > 16 || hex.len() % 2 != 0 {
            return Err(invalid(
                "short-id must be even-length hex, at most 16 characters",
            ));
        }
        let mut short_id = [0; 8];
        for (i, pair) in hex.chunks_exact(2).enumerate() {
            let digit = |b: u8| {
                (b as char)
                    .to_digit(16)
                    .ok_or_else(|| invalid("short-id must be hexadecimal"))
            };
            short_id[i] = ((digit(pair[0])? << 4) | digit(pair[1])?) as u8;
        }
        // Reject low-order public keys before attempting network I/O.
        if !StaticSecret::from([42; 32])
            .diffie_hellman(&PublicKey::from(public_key))
            .was_contributory()
        {
            return Err(invalid("invalid X25519 public-key"));
        }
        Ok(Self {
            public_key,
            short_id,
            hybrid: options.support_x25519mlkem768,
        })
    }

    pub fn tls_config(&self) -> io::Result<Arc<ClientConfig>> {
        let state = Arc::new(Auth {
            options: self.clone(),
            key: Mutex::new(None),
        });
        let mut provider = rustls::crypto::ring::default_provider();
        provider.kx_groups = if self.hybrid {
            vec![&HYBRID, &CLASSICAL]
        } else {
            vec![&CLASSICAL]
        };
        provider.kx_groups.extend([
            rustls::crypto::ring::kx_group::SECP256R1,
            rustls::crypto::ring::kx_group::SECP384R1,
        ]);
        let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(io::Error::other)?
            .dangerous()
            .with_custom_certificate_verifier(state.clone())
            .with_no_client_auth();
        config.resumption = Resumption::disabled();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        config.client_hello_customizer = Some(state);
        Ok(Arc::new(config))
    }
}

#[derive(Debug)]
struct Group(bool);
static HYBRID: Group = Group(true);
static CLASSICAL: Group = Group(false);

struct Exchange {
    secret: StaticSecret,
    classical_public: [u8; 32],
    kem: Option<DecapsulationKey>,
    public: Vec<u8>,
}

impl SupportedKxGroup for Group {
    fn name(&self) -> NamedGroup {
        if self.0 {
            NamedGroup::X25519MLKEM768
        } else {
            NamedGroup::X25519
        }
    }
    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut random = [0; 32];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut random)
            .map_err(|_| fail("random generator failed"))?;
        let secret = StaticSecret::from(random);
        random.zeroize();
        let classical_public = PublicKey::from(&secret).to_bytes();
        let kem = self
            .0
            .then(|| DecapsulationKey::generate(&ML_KEM_768))
            .transpose()
            .map_err(|_| fail("ML-KEM key generation failed"))?;
        let mut public = Vec::new();
        if let Some(kem) = &kem {
            public.extend_from_slice(
                kem.encapsulation_key()
                    .map_err(|_| fail("ML-KEM public key"))?
                    .key_bytes()
                    .map_err(|_| fail("ML-KEM public key"))?
                    .as_ref(),
            );
        }
        public.extend_from_slice(&classical_public);
        Ok(Box::new(Exchange {
            secret,
            classical_public,
            kem,
            public,
        }))
    }
}

impl Exchange {
    fn dh(&self, peer: &[u8]) -> Result<[u8; 32], Error> {
        let public: [u8; 32] = peer
            .try_into()
            .map_err(|_| fail("invalid X25519 key length"))?;
        let shared = self.secret.diffie_hellman(&PublicKey::from(public));
        if !shared.was_contributory() {
            return Err(fail("invalid X25519 peer key"));
        }
        Ok(shared.to_bytes())
    }
}

impl ActiveKeyExchange for Exchange {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }
    fn pub_key(&self) -> &[u8] {
        &self.public
    }
    fn group(&self) -> NamedGroup {
        if self.kem.is_some() {
            NamedGroup::X25519MLKEM768
        } else {
            NamedGroup::X25519
        }
    }
    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        self.kem
            .as_ref()
            .map(|_| (NamedGroup::X25519, self.classical_public.as_slice()))
    }
    fn complete_hybrid_component(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        Ok(SharedSecret::from(self.dh(peer)?.as_slice()))
    }
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        if let Some(kem) = &self.kem {
            if peer.len() != 1088 + 32 {
                return Err(fail("invalid X25519MLKEM768 server share"));
            }
            let pq = kem
                .decapsulate(Ciphertext::from(&peer[..1088]))
                .map_err(|_| fail("ML-KEM decapsulation failed"))?;
            let mut secret = pq.as_ref().to_vec();
            secret.extend_from_slice(&self.dh(&peer[1088..])?);
            Ok(SharedSecret::from(secret))
        } else {
            Ok(SharedSecret::from(self.dh(peer)?.as_slice()))
        }
    }
}

// Never log auth keys. This state is fresh for every TLS connection and is also
// shared by the verifier, which prevents accepting a cover site's ordinary cert.
struct Auth {
    options: Options,
    key: Mutex<Option<Zeroizing<[u8; 32]>>>,
}
impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RealityAuthenticator")
    }
}

impl ClientHelloCustomizer for Auth {
    fn customize(
        &self,
        hello: &mut Vec<u8>,
        exchange: Option<&dyn ActiveKeyExchange>,
    ) -> Result<(), Error> {
        let exchange = exchange
            .and_then(|e| e.as_any())
            .and_then(|e| e.downcast_ref::<Exchange>())
            .ok_or_else(|| fail("missing authentication key exchange"))?;
        chrome_hello(hello, self.options.hybrid)?;
        let shared = Zeroizing::new(exchange.dh(&self.options.public_key)?);
        let mut key = Zeroizing::new([0; 32]);
        Hkdf::<Sha256>::new(Some(&hello[6..26]), shared.as_ref())
            .expand(b"REALITY", key.as_mut())
            .map_err(|_| fail("HKDF failed"))?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| fail("system clock is before Unix epoch"))?
            .as_secs();
        let sid = seal_session_id(hello, &key, self.options.short_id, timestamp as u32)?;
        hello[39..71].copy_from_slice(&sid);
        *self
            .key
            .lock()
            .map_err(|_| fail("authentication state poisoned"))? = Some(key);
        Ok(())
    }
}

fn seal_session_id(
    hello: &[u8],
    key: &[u8; 32],
    short_id: [u8; 8],
    timestamp: u32,
) -> Result<Vec<u8>, Error> {
    let mut plaintext = [0; 16];
    // REALITY protocol compatibility version, following Xray's wire version.
    plaintext[..3].copy_from_slice(&[26, 10, 31]);
    plaintext[4..8].copy_from_slice(&timestamp.to_be_bytes());
    plaintext[8..].copy_from_slice(&short_id);
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| fail("AES key"))?
        .encrypt(
            &Nonce::from(<[u8; 12]>::try_from(&hello[26..38]).map_err(|_| fail("invalid random"))?),
            Payload {
                msg: &plaintext,
                aad: hello,
            },
        )
        .map_err(|_| fail("session ID encryption failed"))
}

fn certificate_key(cert: &CertificateDer<'_>) -> Result<Vec<u8>, Error> {
    let (rest, parsed) = x509_parser::certificate::X509Certificate::from_der(cert.as_ref())
        .map_err(|_| fail("invalid server certificate"))?;
    let spki = parsed.public_key();
    if !rest.is_empty()
        || spki.algorithm.algorithm.to_id_string() != "1.3.101.112"
        || spki.subject_public_key.data.len() != 32
        || spki.subject_public_key.unused_bits != 0
    {
        return Err(fail("server certificate is not Ed25519"));
    }
    Ok(spki.subject_public_key.data.to_vec())
}

impl ServerCertVerifier for Auth {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let public = certificate_key(cert)?;
        let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(cert.as_ref())
            .map_err(|_| fail("invalid certificate"))?;
        let guard = self
            .key
            .lock()
            .map_err(|_| fail("authentication state poisoned"))?;
        let key = guard
            .as_ref()
            .ok_or_else(|| fail("authentication key unavailable"))?;
        let mut mac =
            <Hmac<Sha512> as Mac>::new_from_slice(key.as_ref()).map_err(|_| fail("HMAC key"))?;
        mac.update(&public);
        mac.verify_slice(&parsed.signature_value.data)
            .map_err(|_| {
                fail("server authentication failed (public-key, short-id, SNI or clock mismatch)")
            })?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(fail("TLS 1.3 is required"))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        if signature.scheme != SignatureScheme::ED25519 {
            return Err(fail("unexpected CertificateVerify signature scheme"));
        }
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, certificate_key(cert)?)
            .verify(message, signature.signature())
            .map_err(|_| fail("invalid CertificateVerify signature"))?;
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn u16_bytes(values: &[u16]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_be_bytes()).collect()
}
fn vector(bytes: &[u8]) -> Vec<u8> {
    let mut out = (bytes.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

// Chrome's TLS 1.3 ClientHello layout: GREASE, shuffled extensions, hybrid and
// classical shares, Chrome cipher order. Preserve rustls' actual random/shares.
// Unsupported certificate compression and ALPS are deliberately not advertised.
fn chrome_hello(hello: &mut Vec<u8>, hybrid: bool) -> Result<(), Error> {
    if hello.len() < 76 || hello[0] != 1 {
        return Err(fail("invalid ClientHello"));
    }
    let mut offset = 39 + hello[38] as usize;
    let read16 = |bytes: &[u8], offset: usize| -> Result<usize, Error> {
        let v = bytes
            .get(offset..offset + 2)
            .ok_or_else(|| fail("truncated ClientHello"))?;
        Ok(u16::from_be_bytes([v[0], v[1]]) as usize)
    };
    offset += 2 + read16(hello, offset)?;
    offset += 1 + *hello
        .get(offset)
        .ok_or_else(|| fail("missing compression"))? as usize;
    let end = offset + 2 + read16(hello, offset)?;
    offset += 2;
    let mut extensions = Vec::new();
    while offset < end {
        let kind = read16(hello, offset)? as u16;
        let len = read16(hello, offset + 2)?;
        let body = hello
            .get(offset + 4..offset + 4 + len)
            .ok_or_else(|| fail("truncated extension"))?
            .to_vec();
        extensions.push((kind, body));
        offset += 4 + len;
    }
    if offset != end || end != hello.len() {
        return Err(fail("invalid extensions length"));
    }
    let mut rng = rand::rng();
    let grease = 0x0a0a + 0x1010 * rng.random_range(0..16u16);
    let groups = if hybrid {
        vec![grease, 0x11ec, 29, 23, 24]
    } else {
        vec![grease, 29, 23, 24]
    };
    for (kind, body) in &mut extensions {
        match *kind {
            10 => *body = vector(&u16_bytes(&groups)),
            43 => {
                *body = vec![6];
                body.extend(u16_bytes(&[grease, 0x0304, 0x0303]));
            }
            51 => {
                let mut shares = u16_bytes(&[grease, 1]);
                shares.push(0);
                shares.extend_from_slice(&body[2..]);
                *body = vector(&shares);
            }
            _ => {}
        }
    }
    for (kind, body) in [
        (23, vec![]),
        (65281, vec![0]),
        (11, vec![1, 0]),
        (35, vec![]),
        (5, vec![1, 0, 0, 0, 0]),
        (18, vec![]),
    ] {
        if !extensions.iter().any(|(k, _)| *k == kind) {
            extensions.push((kind, body));
        }
    }
    extensions.shuffle(&mut rng);
    extensions.insert(0, (grease, vec![]));
    extensions.push((
        if grease == 0xfafa {
            0x0a0a
        } else {
            grease + 0x1010
        },
        vec![0],
    ));
    let mut wire = Vec::new();
    for (kind, body) in extensions {
        wire.extend(kind.to_be_bytes());
        wire.extend(vector(&body));
    }
    let mut rebuilt = hello[..38].to_vec();
    rebuilt.push(32);
    rebuilt.extend([0; 32]);
    rebuilt.extend(vector(&u16_bytes(&[
        grease, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
        0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ])));
    rebuilt.extend([1, 0]);
    rebuilt.extend(vector(&wire));
    let length = (rebuilt.len() - 4) as u32;
    rebuilt[1..4].copy_from_slice(&length.to_be_bytes()[1..]);
    *hello = rebuilt;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::kem::EncapsulationKey;
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use rustls::{ClientConnection, ServerConfig, ServerConnection};
    use std::io::Cursor;

    fn options(secret: &StaticSecret, hybrid: bool) -> Options {
        Options {
            public_key: PublicKey::from(secret).to_bytes(),
            short_id: [1, 2, 3, 4, 5, 6, 7, 8],
            hybrid,
        }
    }

    fn extensions(hello: &[u8]) -> Vec<(u16, &[u8])> {
        let mut i = 39 + hello[38] as usize;
        i += 2 + u16::from_be_bytes(hello[i..i + 2].try_into().unwrap()) as usize;
        i += 1 + hello[i] as usize;
        i += 2;
        let mut out = Vec::new();
        while i < hello.len() {
            let kind = u16::from_be_bytes(hello[i..i + 2].try_into().unwrap());
            let len = u16::from_be_bytes(hello[i + 2..i + 4].try_into().unwrap()) as usize;
            out.push((kind, &hello[i + 4..i + 4 + len]));
            i += 4 + len;
        }
        out
    }

    fn hello_and_key(
        client: &mut ClientConnection,
        server_secret: &StaticSecret,
        hybrid: bool,
    ) -> (Vec<u8>, [u8; 32]) {
        let mut wire = Vec::new();
        client.write_tls(&mut wire).unwrap();
        let hello = &wire[5..];
        assert_eq!(hello[38], 32);
        let exts = extensions(hello);
        let shares = exts.iter().find(|(k, _)| *k == 51).unwrap().1;
        // Skip GREASE share (5 bytes), then the real share header.
        let group = u16::from_be_bytes(shares[7..9].try_into().unwrap());
        assert_eq!(group, if hybrid { 0x11ec } else { 29 });
        let len = u16::from_be_bytes(shares[9..11].try_into().unwrap()) as usize;
        assert_eq!(len, if hybrid { 1216 } else { 32 });
        let public: [u8; 32] = shares[11 + len - 32..11 + len].try_into().unwrap();
        let shared = server_secret.diffie_hellman(&PublicKey::from(public));
        let mut key = [0; 32];
        Hkdf::<Sha256>::new(Some(&hello[6..26]), shared.as_bytes())
            .expand(b"REALITY", &mut key)
            .unwrap();
        let mut aad = hello.to_vec();
        aad[39..71].fill(0);
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = Nonce::from(<[u8; 12]>::try_from(&hello[26..38]).unwrap());
        let plain = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &hello[39..71],
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(&plain[..4], &[26, 10, 31, 0]);
        assert_eq!(&plain[8..], &[1, 2, 3, 4, 5, 6, 7, 8]);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        assert!(now.abs_diff(u32::from_be_bytes(plain[4..8].try_into().unwrap())) < 5);
        aad[6] ^= 1;
        assert!(
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: &hello[39..71],
                        aad: &aad
                    }
                )
                .is_err()
        );
        (wire, key)
    }

    #[test]
    fn authenticated_client_hello_classical_and_hybrid() {
        let secret = StaticSecret::from([7; 32]);
        for hybrid in [false, true] {
            let mut client = ClientConnection::new(
                options(&secret, hybrid).tls_config().unwrap(),
                ServerName::try_from("example.com").unwrap(),
            )
            .unwrap();
            hello_and_key(&mut client, &secret, hybrid);
        }
    }

    #[test]
    fn hybrid_exchange_combines_mlkem_and_x25519() {
        let exchange = HYBRID.start().unwrap();
        let public = exchange.pub_key();
        assert_eq!(public.len(), 1216);
        let kem = EncapsulationKey::new(&ML_KEM_768, &public[..1184]).unwrap();
        let (ciphertext, pq) = kem.encapsulate().unwrap();
        let secret = StaticSecret::from([17; 32]);
        let shared = secret.diffie_hellman(&PublicKey::from(
            <[u8; 32]>::try_from(&public[1184..]).unwrap(),
        ));
        let mut expected = pq.as_ref().to_vec();
        expected.extend(shared.as_bytes());
        let mut server_share = ciphertext.as_ref().to_vec();
        server_share.extend(PublicKey::from(&secret).as_bytes());
        assert_eq!(
            exchange.complete(&server_share).unwrap().secret_bytes(),
            expected
        );
        assert!(HYBRID.start().unwrap().complete(&[0; 32]).is_err());
        assert!(CLASSICAL.start().unwrap().complete(&[0; 32]).is_err());
        let exchange = HYBRID.start().unwrap();
        let public: [u8; 32] = exchange.hybrid_component().unwrap().1.try_into().unwrap();
        let expected = secret.diffie_hellman(&PublicKey::from(public));
        assert_eq!(
            exchange
                .complete_hybrid_component(PublicKey::from(&secret).as_bytes())
                .unwrap()
                .secret_bytes(),
            expected.as_bytes()
        );
    }

    fn certificate(
        auth_key: Option<[u8; 32]>,
    ) -> (CertificateDer<'static>, PrivatePkcs8KeyDer<'static>) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["example.com".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let mut der = cert.der().to_vec();
        if let Some(auth_key) = auth_key {
            let public = certificate_key(&CertificateDer::from(der.clone())).unwrap();
            let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&auth_key).unwrap();
            mac.update(&public);
            let end = der.len();
            der[end - 64..].copy_from_slice(&mac.finalize().into_bytes());
        }
        (
            CertificateDer::from(der),
            PrivatePkcs8KeyDer::from(key.serialize_der()),
        )
    }

    // Real rustls client/server handshake verifies that customized bytes enter
    // the transcript, the echoed session ID matches, HMAC trust works and the
    // real Ed25519 CertificateVerify is still checked.
    #[test]
    fn full_handshake_authenticates_server_and_rejects_cover_certificate() {
        for authentication in [0, 1, 2] {
            let secret = StaticSecret::from([23; 32]);
            let mut client = ClientConnection::new(
                options(&secret, false).tls_config().unwrap(),
                ServerName::try_from("example.com").unwrap(),
            )
            .unwrap();
            let (hello, key) = hello_and_key(&mut client, &secret, false);
            let (cert, private_key) = certificate(match authentication {
                0 => Some(key),
                1 => None,
                _ => Some([0; 32]),
            });
            let config = ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], private_key.into())
            .unwrap();
            let mut server = ServerConnection::new(Arc::new(config)).unwrap();
            server.read_tls(&mut Cursor::new(hello)).unwrap();
            server.process_new_packets().unwrap();
            let mut result = Ok(());
            for _ in 0..6 {
                let mut wire = Vec::new();
                server.write_tls(&mut wire).unwrap();
                if !wire.is_empty() {
                    client.read_tls(&mut Cursor::new(wire)).unwrap();
                    result = client.process_new_packets().map(|_| ());
                    if result.is_err() {
                        break;
                    }
                }
                let mut wire = Vec::new();
                client.write_tls(&mut wire).unwrap();
                if !wire.is_empty() {
                    server.read_tls(&mut Cursor::new(wire)).unwrap();
                    server.process_new_packets().unwrap();
                }
                if !client.is_handshaking() && !server.is_handshaking() {
                    break;
                }
            }
            if authentication == 0 {
                result.unwrap();
                assert!(!client.is_handshaking());
                assert!(!server.is_handshaking());
            } else {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("authentication failed")
                );
            }
        }
    }

    #[test]
    fn rejects_bad_configuration() {
        let secret = StaticSecret::from([6; 32]);
        let mut raw = RealityOptions {
            public_key: URL_SAFE_NO_PAD.encode(PublicKey::from(&secret).as_bytes()),
            short_id: "aabb".into(),
            support_x25519mlkem768: true,
        };
        assert_eq!(
            Options::parse(&raw, Some("chrome")).unwrap().short_id,
            [0xaa, 0xbb, 0, 0, 0, 0, 0, 0]
        );
        assert!(Options::parse(&raw, Some("firefox")).is_err());
        for sid in ["a", "zz", "000000000000000000"] {
            raw.short_id = sid.into();
            assert!(Options::parse(&raw, None).is_err());
        }
        raw.short_id.clear();
        for public in [
            "not base64!".to_string(),
            URL_SAFE_NO_PAD.encode([1; 31]),
            URL_SAFE_NO_PAD.encode([0; 32]),
        ] {
            raw.public_key = public;
            assert!(Options::parse(&raw, None).is_err());
        }
    }

    #[test]
    fn rejects_incompatible_transports_before_connecting() {
        for (network, tls) in [("ws", true), ("tcp", false), ("grpc", true)] {
            let yaml = format!(
                "name: invalid\ntype: vless\nserver: example.com\nport: 443\nnetwork: {network}\ntls: {tls}\nreality-opts:\n  public-key: CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk\n"
            );
            let config: config::ServerConfig = serde_yaml::from_str(&yaml).unwrap();
            assert!(crate::transport::TransportOptions::from_config(&config).is_err());
        }
    }
}
