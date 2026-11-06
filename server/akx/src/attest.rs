//! Attestation abstraction.
//!
//! The AKX layer needs to *bind* the enclave epoch public key into a platform
//! attestation, but it does not itself parse or verify SEV-SNP / vTPM evidence
//! (client-side verification is delegated to Warden). We therefore model the
//! attester as an opaque producer: given a 64-byte `report_data`, return a
//! verifier-specific attestation bundle that the client forwards to Warden.
//!
//! This keeps the crypto core free of any TPM/SNP dependency: the real
//! implementation lives in the server crate (SEV-SNP + vTPM), while tests and
//! CI use [`FakeAttester`].

use super::AkxError;

/// Produces a platform attestation whose `report_data` commits to the given
/// 64-byte value. The returned bytes are an opaque, verifier-specific bundle
/// (e.g. SNP report + vTPM quote + cert chain, serialized); the AKX layer never
/// interprets them.
pub trait Attester {
    fn attest(&self, report_data: &[u8; 64]) -> Result<Vec<u8>, AkxError>;
}

/// Deterministic attester for tests / CI. It emits a `b"FAKE"` marker followed
/// by the verbatim `report_data`, so a test can assert exactly what was bound —
/// with no TPM or SEV-SNP hardware required. Obviously **not** for production.
#[derive(Debug, Default, Clone, Copy)]
pub struct FakeAttester;

/// Marker prefix emitted by [`FakeAttester`].
pub const FAKE_ATTESTATION_PREFIX: &[u8; 4] = b"FAKE";

impl Attester for FakeAttester {
    fn attest(&self, report_data: &[u8; 64]) -> Result<Vec<u8>, AkxError> {
        let mut out = Vec::with_capacity(FAKE_ATTESTATION_PREFIX.len() + report_data.len());
        out.extend_from_slice(FAKE_ATTESTATION_PREFIX);
        out.extend_from_slice(report_data);
        Ok(out)
    }
}
