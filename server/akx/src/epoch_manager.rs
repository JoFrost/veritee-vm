//! Epoch manager: owns the enclave's epoch signing key and its cached
//! attestation, and starts per-session handshakes.
//!
//! One `EpochManager` is created per epoch inside the TEE. It attests the epoch
//! public key **once** (the expensive step, cacheable/pollable), then serves
//! many cheap per-session handshakes signed by the epoch key. This is the
//! two-tier model from `docs/tls-channel-binding.md` §6.1.
//!
//! The attestation bundle can be **refreshed** in the background (same key, fresh
//! evidence) so clients that poll `GET /enclave-key` always see recent evidence
//! without blocking the request path. The key itself can be **rotated** (new
//! epoch counter + new key + new attestation) on a policy interval or at boot.

use std::sync::RwLock;

use super::attest::Attester;
use super::epoch::EpochKey;
use super::session::{enclave_begin, EnclaveHandshake, EnclavePending};
use super::AkxError;

struct EpochInner {
    epoch_key: EpochKey,
    attestation: Vec<u8>,
}

/// The enclave's epoch state: the signing key plus the attestation that binds
/// its public key. Internally synchronized so a background task can refresh or
/// rotate the attestation without blocking session handshakes longer than a
/// brief write lock. The private key never leaves this struct.
pub struct EpochManager {
    inner: RwLock<EpochInner>,
}

impl EpochManager {
    /// Generate a fresh epoch key inside the TEE and attest its public key.
    ///
    /// `report_data = H("temenos-akx-v1" ‖ epoch ‖ pk_e)` is computed by the
    /// [`EpochKey`] and handed to the `attester`; the resulting bundle is cached
    /// for the lifetime of the epoch and served from `GET /enclave-key`.
    pub fn new<A: Attester>(attester: &A, epoch: u64) -> Result<Self, AkxError> {
        let epoch_key = EpochKey::generate(epoch);
        let attestation = attester.attest(&epoch_key.report_data())?;
        Ok(Self {
            inner: RwLock::new(EpochInner {
                epoch_key,
                attestation,
            }),
        })
    }

    /// The epoch counter this manager currently holds.
    pub fn epoch(&self) -> u64 {
        self.inner.read().expect("epoch poisoned").epoch_key.epoch
    }

    /// The 32-byte Ed25519 epoch public key (as bound into the attestation).
    pub fn epoch_public(&self) -> [u8; 32] {
        self.inner
            .read()
            .expect("epoch poisoned")
            .epoch_key
            .public_bytes()
    }

    /// The cached attestation bundle (opaque; forwarded to Warden by the client).
    pub fn attestation(&self) -> Vec<u8> {
        self.inner
            .read()
            .expect("epoch poisoned")
            .attestation
            .clone()
    }

    /// Re-attest the **current** epoch public key (same `sk_e` / `pk_e`, fresh
    /// evidence). Used by the background refresh task so clients polling
    /// `GET /enclave-key` get a recent MAA/HCL bundle without paying the ~3 s
    /// cost on the request path.
    pub fn refresh_attestation<A: Attester>(&self, attester: &A) -> Result<(), AkxError> {
        let report_data = {
            let guard = self.inner.read().expect("epoch poisoned");
            guard.epoch_key.report_data()
        };
        let attestation = attester.attest(&report_data)?;
        self.inner.write().expect("epoch poisoned").attestation = attestation;
        Ok(())
    }

    /// Rotate to a new epoch: mint a fresh signing key for `new_epoch`, attest
    /// it, and replace the cached state. Existing sessions keep working under
    /// the old record keys; new handshakes use the new epoch key. Clients
    /// discover the rotation on the next `GET /enclave-key`.
    pub fn rotate<A: Attester>(&self, attester: &A, new_epoch: u64) -> Result<(), AkxError> {
        let epoch_key = EpochKey::generate(new_epoch);
        let attestation = attester.attest(&epoch_key.report_data())?;
        *self.inner.write().expect("epoch poisoned") = EpochInner {
            epoch_key,
            attestation,
        };
        Ok(())
    }

    /// Begin a per-session handshake: mint a fresh ephemeral key and sign the
    /// transcript with the epoch key. Returns the secret pending state (to keep
    /// in the session store) and the handshake message (to send to the client).
    pub fn begin_session(&self, sid: &[u8], nonce_c: &[u8]) -> (EnclavePending, EnclaveHandshake) {
        let guard = self.inner.read().expect("epoch poisoned");
        enclave_begin(&guard.epoch_key, sid, nonce_c)
    }
}
