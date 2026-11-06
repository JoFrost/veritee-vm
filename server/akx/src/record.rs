//! Directional AEAD record layer (AES-256-GCM) with monotonic sequence numbers.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};

use super::AkxError;

/// Direction tag: client -> server records.
pub const DIR_C2S: u8 = 0x01;
/// Direction tag: server -> client records.
pub const DIR_S2C: u8 = 0x02;

/// One direction of an established channel. Holds the AEAD key and a strictly
/// monotonic per-direction sequence counter used to derive unique nonces and to
/// provide ordering / anti-replay. The two peers keep mirror-image `RecordKey`s
/// (the sealing side on one, the opening side on the other) and stay in
/// lockstep as long as records are processed in order.
pub struct RecordKey {
    cipher: Aes256Gcm,
    dir: u8,
    seq: u64,
}

impl RecordKey {
    pub fn new(key: [u8; 32], dir: u8) -> Self {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        Self {
            cipher,
            dir,
            seq: 0,
        }
    }

    /// Deterministic 96-bit nonce = `dir(1) || 0x000000 || seq_be(8)`. The
    /// direction byte guarantees the c2s and s2c streams never collide even
    /// though they may share sequence values, and the monotonic counter
    /// guarantees nonce uniqueness within a direction.
    fn next_nonce(&mut self) -> Result<[u8; 12], AkxError> {
        let seq = self.seq;
        self.seq = self.seq.checked_add(1).ok_or(AkxError::SeqOverflow)?;
        let mut nonce = [0u8; 12];
        nonce[0] = self.dir;
        nonce[4..12].copy_from_slice(&seq.to_be_bytes());
        Ok(nonce)
    }

    /// Seal `plaintext` with the given associated data. Returns ciphertext with
    /// the 16-byte GCM tag appended.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, AkxError> {
        let nonce = self.next_nonce()?;
        self.cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| AkxError::Aead)
    }

    /// Open a sealed record. Advances the sequence counter on **every** call
    /// (including AEAD failures) so a rejected/forged record cannot be
    /// retried under a later sequence number (anti-probe). Callers that see
    /// `AkxError::Aead` must drop the session — the streams are desynchronised.
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, AkxError> {
        let nonce = self.next_nonce()?;
        self.cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| AkxError::Aead)
    }

    /// Current sequence position (number of records processed in this
    /// direction). Exposed for observability / tests.
    pub fn seq(&self) -> u64 {
        self.seq
    }
}
