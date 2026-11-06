//! Epoch-tier signing key (Ed25519) and its SEV-SNP `report_data` binding.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use super::transcript::LABEL;
use super::AkxError;

/// A medium-lived enclave signing key. Its public half is committed into the
/// SEV-SNP `report_data`; it signs each per-session handshake transcript.
pub struct EpochKey {
    signing: SigningKey,
    /// Monotonic epoch counter (e.g. incremented per boot / rotation).
    pub epoch: u64,
}

impl EpochKey {
    /// Generate a fresh epoch key from the OS CSPRNG. This must be called
    /// *inside* the TEE; the private key must never leave the enclave.
    pub fn generate(epoch: u64) -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
            epoch,
        }
    }

    /// The 32-byte Ed25519 public key, as committed into the attestation.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Sign an arbitrary message (in practice, a transcript hash).
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }

    /// The 64-byte SEV-SNP `report_data` value committing to this epoch key.
    pub fn report_data(&self) -> [u8; 64] {
        report_data_for(self.epoch, &self.public_bytes())
    }
}

/// Deterministically derive the 64-byte `report_data` that binds an epoch public
/// key into an SEV-SNP attestation. The client recomputes this from the epoch
/// public key it received and checks it against the report before trusting the
/// key. The SHA-256 digest occupies the first 32 bytes; the remainder is zero.
pub fn report_data_for(epoch: u64, epoch_pub: &[u8; 32]) -> [u8; 64] {
    let mut h = Sha256::new();
    h.update(LABEL);
    h.update(b"epoch");
    h.update(epoch.to_be_bytes());
    h.update(epoch_pub);
    let digest = h.finalize();

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&digest);
    out
}

/// Verify an epoch-key signature over `msg`. Uses `verify_strict` to reject
/// malleable / non-canonical signatures and small-order public keys.
pub fn verify_epoch_sig(epoch_pub: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<(), AkxError> {
    let vk = VerifyingKey::from_bytes(epoch_pub).map_err(|_| AkxError::BadKey)?;
    let signature = Signature::from_bytes(sig);
    vk.verify_strict(msg, &signature)
        .map_err(|_| AkxError::BadSignature)
}
