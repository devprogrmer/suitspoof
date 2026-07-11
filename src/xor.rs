//!rust```
//! XOR-style framing helper.
//! [ nonce : 12 bytes ][ ciphertext : N bytes ]
//!
//! The previous implementation used SHA-256 CTR which hashes 32 bytes per
//! block -- roughly one SHA-256 call per 32 bytes of plaintext. ChaCha20 is a
//! purpose-built stream cipher that processes 64 bytes per "block" and
//! auto-vectorises to AVX2/NEON, achieving substantially better throughput
//! with lower CPU cost.
//!
//! # Wire layout
//!
//!
```text
//! [ nonce : 12 bytes ][ ciphertext : N bytes ]
//! 
