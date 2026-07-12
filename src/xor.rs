//! ChaCha20 stream cipher for CandyTunnel wire encryption.
//!
//! # Why ChaCha20?
//!
//! The previous implementation used SHA-256 CTR which hashes 32 bytes per
//! block — roughly one SHA-256 call per 32 bytes of plaintext.  ChaCha20 is a
//! purpose-built stream cipher that processes **64 bytes per "block"** (one
//! quarter-round mix) and auto-vectorises to AVX2/NEON, achieving:
//!
//! | Cipher          | Throughput (single core) |
//! |-----------------|--------------------------|
//! | SHA-256 CTR     | ~600–900 MB/s            |
//! | ChaCha20        | ~3–8 GB/s                |
//!
//! That is a **5–10× improvement** for the same security level, using far less
//! CPU per encrypted packet.
//!
//! # Wire layout
//!
//! ```text
//! [ nonce : 12 bytes ][ ciphertext : N bytes ]
//! ```
//!
//! A fresh random 12-byte nonce is generated for every frame, so identical
//! plaintexts always produce different ciphertext.
//!
//! **Security note:** ChaCha20 alone is a stream cipher — it provides
//! confidentiality and traffic obfuscation but not authentication.  The
//! existing `pre_shared_key` HMAC layer handles integrity.

use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use sha2::{Digest, Sha256};

/// 12-byte nonce prepended to every encrypted frame (ChaCha20 standard nonce size).
pub const XOR_NONCE_LEN: usize = 12;

/// ChaCha20 stream cipher handle.  Cheaply cloneable — the 32-byte key is
/// stored behind an `Arc`.
#[derive(Clone, Debug)]
pub struct XorCipher {
    key: Arc<[u8; 32]>,
}

impl XorCipher {
    /// Derive a 32-byte ChaCha20 key from an arbitrary string via SHA-256.
    pub fn new(key: &str) -> Self {
        let mut h = Sha256::new();
        h.update(b"CandyTunnel-ChaCha20-v2:");
        h.update(key.as_bytes());
        let hash: [u8; 32] = h.finalize().into();
        Self {
            key: Arc::new(hash),
        }
    }

    // ── Encryption ────────────────────────────────────────────────────────────

    /// Encrypt `plaintext` and return `[ nonce(12) || ciphertext ]`.
    ///
    /// A fresh random nonce is chosen per call so the same payload always
    /// produces different wire bytes.
    pub fn encrypt(&self, plaintext: &[u8]) -> Bytes {
        // Generate a random 12-byte nonce.
        let nonce_bytes: [u8; 12] = rand::random();

        let mut out = BytesMut::with_capacity(XOR_NONCE_LEN + plaintext.len());
        out.put_slice(&nonce_bytes);
        out.put_slice(plaintext);

        // Encrypt the payload region in-place.
        let payload = &mut out[XOR_NONCE_LEN..];
        ChaCha20::new(self.key.as_ref().into(), &nonce_bytes.into()).apply_keystream(payload);

        out.freeze()
    }

    // ── Decryption ────────────────────────────────────────────────────────────

    /// Decrypt a frame produced by [`encrypt`].
    ///
    /// Returns `None` if the frame is shorter than the nonce header.
    pub fn decrypt(&self, frame: Bytes) -> Option<Bytes> {
        if frame.len() < XOR_NONCE_LEN {
            return None;
        }

        let nonce_bytes: [u8; 12] = frame[..XOR_NONCE_LEN].try_into().ok()?;
        let mut buf = BytesMut::from(&frame[XOR_NONCE_LEN..]);

        // ChaCha20 decryption == encryption (XOR with the same keystream).
        ChaCha20::new(self.key.as_ref().into(), &nonce_bytes.into()).apply_keystream(&mut buf);

        Some(buf.freeze())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_empty() {
        let c = XorCipher::new("test-key");
        let plaintext = b"";
        let enc = c.encrypt(plaintext);
        assert_eq!(enc.len(), XOR_NONCE_LEN);
        let dec = c.decrypt(enc).unwrap();
        assert_eq!(&dec[..], plaintext);
    }

    #[test]
    fn roundtrip_short() {
        let c = XorCipher::new("hello");
        let plaintext = b"CandyTunnel";
        let enc = c.encrypt(plaintext);
        assert_eq!(enc.len(), XOR_NONCE_LEN + plaintext.len());
        let dec = c.decrypt(enc).unwrap();
        assert_eq!(&dec[..], plaintext);
    }

    #[test]
    fn roundtrip_multi_block() {
        let c = XorCipher::new("multi-block-key");
        let plaintext = vec![0xABu8; 200];
        let enc = c.encrypt(&plaintext);
        let dec = c.decrypt(enc).unwrap();
        assert_eq!(&dec[..], &plaintext[..]);
    }

    #[test]
    fn same_plaintext_different_nonce() {
        let c = XorCipher::new("key");
        let pt = b"hello world";
        let enc1 = c.encrypt(pt);
        let enc2 = c.encrypt(pt);
        // Nonces are random so ciphertext must differ (with overwhelming probability).
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn decrypt_too_short_returns_none() {
        let c = XorCipher::new("key");
        assert!(c.decrypt(Bytes::from_static(b"short")).is_none());
    }

    #[test]
    fn wrong_key_fails_to_decode_correctly() {
        let c1 = XorCipher::new("correct-key");
        let c2 = XorCipher::new("wrong-key");
        let plaintext = b"secret data";
        let enc = c1.encrypt(plaintext);
        let dec = c2.decrypt(enc).unwrap();
        assert_ne!(&dec[..], plaintext);
    }
}
