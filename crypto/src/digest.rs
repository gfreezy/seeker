//! Message digest algorithm

use digest::OutputSizeUser;
use md5::Md5;
use sha1::Sha1;

use bytes::BufMut;

/// Digest trait
pub trait Digest: Send {
    /// Update data
    fn update(&mut self, data: &[u8]);

    /// Generates digest
    fn digest_reset<B: BufMut>(&mut self, buf: &mut B);

    /// Length of digest
    fn digest_len(&self) -> usize;
}

/// Type of defined digests
#[derive(Clone, Copy)]
pub enum DigestType {
    Md5,
    Sha1,
    Sha,
}

/// Create digest with type
pub fn with_type(t: DigestType) -> DigestVariant {
    match t {
        DigestType::Md5 => DigestVariant::Md5(Md5::default()),
        DigestType::Sha1 | DigestType::Sha => DigestVariant::Sha1(Sha1::default()),
    }
}

/// Variant of supported digest
pub enum DigestVariant {
    Md5(Md5),
    Sha1(Sha1),
}

impl Digest for DigestVariant {
    fn update(&mut self, data: &[u8]) {
        use md5::Digest;

        match *self {
            DigestVariant::Md5(ref mut d) => d.update(data),
            DigestVariant::Sha1(ref mut d) => d.update(data),
        }
    }

    fn digest_reset<B: BufMut>(&mut self, buf: &mut B) {
        use digest::Digest;
        match self {
            DigestVariant::Md5(d) => buf.put(&*d.finalize_reset()),
            DigestVariant::Sha1(d) => buf.put(&*d.finalize_reset()),
        }
    }

    fn digest_len(&self) -> usize {
        match *self {
            DigestVariant::Md5(_) => <Md5 as OutputSizeUser>::output_size(),
            DigestVariant::Sha1(_) => <Sha1 as OutputSizeUser>::output_size(),
        }
    }
}
