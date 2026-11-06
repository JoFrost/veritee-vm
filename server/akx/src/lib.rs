//! Attested key-exchange (AKX) crypto core.
//!
//! Implements the cryptographic primitives of the attested channel described in
//! `docs/tls-channel-binding.md` (§6), using the **two-tier** key model:
//!
//!  1. **Epoch tier** — the enclave holds a medium-lived Ed25519 signing key
//!     (`EpochKey`) whose public key is committed into the SEV-SNP
//!     `report_data`. This attestation is minted once per epoch and can be
//!     cached / polled by clients.
//!  2. **Session tier** — per session the enclave generates a fresh HPKE
//!     (X25519) recipient keypair, signs the handshake transcript with the
//!     epoch key, and both parties derive directional AEAD record keys. This
//!     gives forward secrecy and per-session transcript binding without a fresh
//!     attestation each time.
//!
//! This crate is deliberately transport-agnostic and free of any TPM / SNP /
//! HTTP dependencies so it can be unit-tested exhaustively without a TEE.

mod attest;
mod epoch;
mod epoch_manager;
mod record;
mod session;
mod session_store;
mod transcript;

pub use attest::{Attester, FakeAttester, FAKE_ATTESTATION_PREFIX};
pub use epoch::{report_data_for, verify_epoch_sig, EpochKey};
pub use epoch_manager::EpochManager;
pub use record::{RecordKey, DIR_C2S, DIR_S2C};
pub use session::{
    client_establish, enclave_begin, enclave_complete, EnclaveHandshake, EnclavePending,
};
pub use session_store::{SessionConfig, SessionError, SessionStore};
pub use transcript::{transcript_hash, LABEL};

/// Errors surfaced by the AKX crypto core. Intentionally coarse so that a
/// remote peer cannot distinguish failure sub-cases (avoids padding-oracle
/// style leaks); callers should treat any error as an aborting condition.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AkxError {
    #[error("invalid key encoding")]
    BadKey,
    #[error("epoch signature verification failed")]
    BadSignature,
    #[error("HPKE key-establishment failure")]
    Hpke,
    #[error("AEAD open/seal failure")]
    Aead,
    #[error("record sequence number overflow")]
    SeqOverflow,
    #[error("attestation failed: {0}")]
    Attest(String),
}

#[cfg(test)]
mod tests;
