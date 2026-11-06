//! Epoch key + attestation, exposed via `GET /enclave-key`.
//!
//! The cryptography lives in the `akx` crate (TPM-free, unit-tested). This
//! module provides the **real** [`akx::Attester`] implementation and the Axum
//! handler that serves the cached epoch attestation.
//!
//! ## `report_data` binding (reuses `generate_attestation` from PR #11)
//!
//! We do **not** open `/dev/sev-guest` ourselves. Epoch-key attestation goes
//! through [`crate::generate_attestation`] — the same path as `GET /` — so both
//! build modes from PR #11 work:
//!
//! - **`maa` (default):** `report_data` (base64) is the MAA `client_payload.payload`;
//!   the token commits to it.
//! - **`raw-report`:** `nonce` + `payload` are hashed by `report_data_binding` and
//!   fed to Azure HCL `get_report_with_report_data`.
//!
//! Warden already verifies the resulting `ResponseStruct` /
//! `AttestationEvidence` shapes; it binds the epoch key by recomputing
//! `report_data = H("temenos-akx-v1" ‖ epoch ‖ pk_e)` from the returned `pk_e`.

use std::sync::Arc;

use crate::b64::prelude::{Engine as _, BASE64_STANDARD};
use akx::{Attester, EpochManager};
use axum::{extract::State, Json};
use serde::Serialize;

use crate::generate_attestation;

/// Real attester for the epoch key. Reuses [`crate::generate_attestation`]
/// (MAA *or* raw SEV-SNP, depending on cargo features) rather than
/// re-implementing evidence collection.
pub struct PlatformAttester;

/// Backward-compatible alias used by older call sites / docs.
pub type MaaAttester = PlatformAttester;

impl Attester for PlatformAttester {
    fn attest(&self, report_data: &[u8; 64]) -> Result<Vec<u8>, akx::AkxError> {
        // Bind the epoch key: payload carries base64(report_data). A fixed
        // nonce is required by the raw-report path when a payload is present;
        // MAA accepts it as client_payload.nonce.
        let payload = BASE64_STANDARD.encode(report_data);
        let nonce = Some("temenos-akx-v1-epoch".to_string());

        // `attest` is synchronous and must only be called from a blocking
        // context (`spawn_blocking` at startup / refresh / rotate). Do not wrap
        // in `block_in_place` — that panics when already on the blocking pool.
        let response = tokio::runtime::Handle::current()
            .block_on(generate_attestation(nonce, Some(payload)))
            .map_err(|e| akx::AkxError::Attest(e.to_string()))?;

        serde_json::to_vec(&response).map_err(|e| akx::AkxError::Attest(e.to_string()))
    }
}

/// Response body for `GET /enclave-key`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveKeyResponse {
    /// Epoch counter this key belongs to.
    epoch: u64,
    /// 32-byte Ed25519 epoch public key (`pk_e`).
    #[serde(with = "crate::base64")]
    epoch_public: Vec<u8>,
    /// Opaque attestation (`ResponseStruct` JSON) binding `report_data`,
    /// forwarded verbatim to Warden.
    #[serde(with = "crate::base64")]
    attestation: Vec<u8>,
}

/// `GET /enclave-key` — serve the cached epoch key + attestation. Infallible:
/// the attestation is minted at startup (and refreshed in the background) and
/// read from the [`EpochManager`].
pub async fn get_enclave_key(State(epoch): State<Arc<EpochManager>>) -> Json<EnclaveKeyResponse> {
    Json(EnclaveKeyResponse {
        epoch: epoch.epoch(),
        epoch_public: epoch.epoch_public().to_vec(),
        attestation: epoch.attestation(),
    })
}
