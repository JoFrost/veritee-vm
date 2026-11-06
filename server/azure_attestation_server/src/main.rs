#[cfg(all(feature = "maa", feature = "raw-report"))]
compile_error!("features `maa` and `raw-report` are mutually exclusive; enable exactly one");

#[cfg(not(any(feature = "maa", feature = "raw-report")))]
compile_error!("one attestation feature must be enabled: `maa` or `raw-report`");

mod base64;
mod base64_str;
mod base64url;
mod enclave_key;
mod eph_key_tpm;
mod imds_operations;
mod json_base64;
mod json_base64url;

mod maa_jwt;
mod proxy_routes;
mod session_routes;
mod state;
pub(crate) mod tpm;
pub(crate) mod vtpm;

extern crate base64 as b64;
use anyhow::anyhow;
use axum::extract::Query;
use b64::prelude::*;
use tss_esapi::Context;
use vtpm::get_quote;

use std::{fs, str::FromStr};

use tss_esapi::TctiNameConf;

use crate::vtpm::HclReport;
use anyhow::bail;
use anyhow::Context as AnyhowContext;
use binrw::binrw;
use eph_key_tpm::create_ephemeral_key;
use fn_error_context::context;
use imds_operations::get_vcek_certchain;
use reqwest::Client;
#[cfg(feature = "raw-report")]
use ring::digest::{digest, SHA256};
#[cfg(all(feature = "maa", feature = "dev-unbound-attestation"))]
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use tss_esapi::{
    handles::KeyHandle,
    structures::{Attest, AttestInfo, Digest, PcrSelectionList, PcrSlot, PublicBuffer, Signature},
    tcti_ldr::DeviceConfig,
    traits::{Marshall, UnMarshall},
};

use crate::enclave_key::{get_enclave_key, PlatformAttester};
use crate::eph_key_tpm::decrypt_inner_key;
use crate::proxy_routes::{post_proxy, DappUpstream, ProxyGates};
use crate::session_routes::{post_session, post_session_complete};
use crate::state::AppState;
use akx::{EpochManager, SessionConfig, SessionStore};
use axum::{
    debug_handler,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use std::process::Command;
use std::sync::Arc;

#[cfg(feature = "raw-report")]
use sev::parser::ByteParser;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Root {
    #[serde(with = "json_base64url")]
    pub attestation_info: AttestationInfo,
}

#[binrw]
#[brw(big)]
struct Tpm2bAttest {
    #[bw(try_calc(u16::try_from(attestation_data.len())))]
    size: u16,
    #[br(count = size)]
    attestation_data: Vec<u8>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Proof {
    #[serde(with = "base64url")]
    pub snp_report: Vec<u8>,
    #[serde(with = "base64_str")]
    pub vcek_cert_chain: String,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AttestationInfo {
    pub attestation_protocol_version: String,
    pub client_payload: ClientPayload,
    pub isolation_info: IsolationInfo,
    #[serde(rename = "OSBuild")]
    #[serde(with = "base64_str")]
    pub os_build: String,
    #[serde(rename = "OSDistro")]
    #[serde(with = "base64_str")]
    pub os_distro: String,
    #[serde(rename = "OSType")]
    #[serde(with = "base64_str")]
    pub os_type: String,
    #[serde(rename = "OSVersionMajor")]
    pub os_version_major: i64,
    #[serde(rename = "OSVersionMinor")]
    pub os_version_minor: i64,
    #[serde(with = "base64")]
    pub tcg_logs: Vec<u8>,
    pub tpm_info: TpmInfo,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientPayload {
    pub nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct IsolationInfo {
    pub evidence: Evidence,
    #[serde(rename = "Type")]
    pub type_field: String,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Evidence {
    #[serde(with = "json_base64")]
    pub proof: Proof,
    #[serde(with = "base64")]
    pub run_time_data: Vec<u8>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TpmInfo {
    #[serde(with = "base64")]
    pub aik_cert: Vec<u8>,
    #[serde(with = "base64")]
    pub aik_pub: Vec<u8>,
    #[serde(with = "base64")]
    pub enc_key_certify_info: Vec<u8>,
    #[serde(with = "base64")]
    pub enc_key_certify_info_signature: Vec<u8>,
    #[serde(with = "base64")]
    pub enc_key_pub: Vec<u8>,
    #[serde(rename = "PCRs")]
    pub pcrs: Vec<Pcr>,
    #[serde(with = "base64")]
    pub pcr_quote: Vec<u8>,
    pub pcr_set: Vec<u8>,
    #[serde(with = "base64")]
    pub pcr_signature: Vec<u8>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Pcr {
    #[serde(with = "base64")]
    pub digest: Vec<u8>,
    pub index: u8,
}

#[derive(Debug, Serialize, Deserialize)]
struct MaaResponse {
    #[serde(with = "json_base64url")]
    token: EncryptedJwt,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EncryptedJwt {
    #[serde(with = "base64")]
    pub jwt: Vec<u8>,
    #[serde(with = "base64")]
    pub encrypted_inner_key: Vec<u8>,
    pub encryption_params: EncryptionParams,
    #[serde(with = "base64")]
    pub authentication_data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BlockMode {
    #[serde(rename = "ChainingModeGCM")]
    ChainingModeGcm,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BlockCipherPadding {
    PKCS7,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CipherAlgorithm {
    AES,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EncryptionParams {
    pub block_mode: BlockMode,
    pub block_padding: BlockCipherPadding,
    pub cipher: CipherAlgorithm,
    pub key_size_in_bits: u64,
    #[serde(with = "base64")]
    pub iv: Vec<u8>,
}

#[test]
fn test_deserialize() {
    let input = fs::read_to_string("src/test_req_maa.json").unwrap();
    let response: ResponseStruct = serde_json::from_str(&input).expect("Parsing error");
    let roundtrip = serde_json::to_string(&response).unwrap();
    let response2: ResponseStruct = serde_json::from_str(&roundtrip).expect("Parsing error");
    assert_eq!(response, response2);
}

#[cfg(feature = "raw-report")]
#[test]
fn test_raw_response_serialization_roundtrip() {
    let response = ResponseStruct {
        version: "1".to_string(),
        attestation: AttestationEvidence::RawSevSnp {
            report: "c25wLXJlcG9ydA==".to_string(),
            vcek: "vcek-cert-chain".to_string(),
            runtime_data: "cnVudGltZS1kYXRh".to_string(),
            binary_bios_measurements: Some("dGNnLWV2ZW50LWxvZw==".to_string()),
        },
        msg: "quote-message".to_string(),
        sig: "quote-signature".to_string(),
        pcr: "pcr-values".to_string(),
    };

    let serialized = serde_json::to_value(&response).expect("raw response should serialize");
    assert_eq!(serialized["attestation"]["mode"], "raw_sev_snp");
    assert_eq!(
        serialized["attestation"]["evidence"]["binary_bios_measurements"],
        "dGNnLWV2ZW50LWxvZw=="
    );

    let deserialized: ResponseStruct =
        serde_json::from_value(serialized).expect("raw response should deserialize");
    assert_eq!(response, deserialized);
}

fn pcr_slot_to_index(pcr_slot: &PcrSlot) -> u8 {
    match pcr_slot {
        PcrSlot::Slot0 => 0,
        PcrSlot::Slot1 => 1,
        PcrSlot::Slot2 => 2,
        PcrSlot::Slot3 => 3,
        PcrSlot::Slot4 => 4,
        PcrSlot::Slot5 => 5,
        PcrSlot::Slot6 => 6,
        PcrSlot::Slot7 => 7,
        PcrSlot::Slot8 => 8,
        PcrSlot::Slot9 => 9,
        PcrSlot::Slot10 => 10,
        PcrSlot::Slot11 => 11,
        PcrSlot::Slot12 => 12,
        PcrSlot::Slot13 => 13,
        PcrSlot::Slot14 => 14,
        PcrSlot::Slot15 => 15,
        PcrSlot::Slot16 => 16,
        PcrSlot::Slot17 => 17,
        PcrSlot::Slot18 => 18,
        PcrSlot::Slot19 => 19,
        PcrSlot::Slot20 => 20,
        PcrSlot::Slot21 => 21,
        PcrSlot::Slot22 => 22,
        PcrSlot::Slot23 => 23,
        PcrSlot::Slot24 => 24,
        PcrSlot::Slot25 => 25,
        PcrSlot::Slot26 => 26,
        PcrSlot::Slot27 => 27,
        PcrSlot::Slot28 => 28,
        PcrSlot::Slot29 => 29,
        PcrSlot::Slot30 => 30,
        PcrSlot::Slot31 => 31,
    }
}
#[context("Failed to get TpmInfo")]
fn get_tpm_info(
    ctx: &mut tss_esapi::Context,
) -> anyhow::Result<(TpmInfo, KeyHandle, Digest, PcrSelectionList)> {
    let ak_cert = tpm::get_ak_cert()?;
    let ak_pub = tpm::get_ak_pub()?;

    let quote = get_quote(&[])?;

    let msg = quote.message();
    let sig = quote.signature();

    let rquote = Attest::unmarshall(&msg)?;

    let &AttestInfo::Quote {
        info: ref quote_info,
    } = rquote.attested()
    else {
        bail!("Failed to extract quote from attested");
    };

    let pcr_data = quote.pcr_data();
    let pcr_sha256 = pcr_data
        .pcr_bank(tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256)
        .context("Bad selection, no SHA256 bank in PCRData")?;

    let pcrs: Vec<Pcr> = pcr_sha256
        .into_iter()
        .map(|(pcr_slot, digest)| Pcr {
            digest: digest.to_vec(),
            index: pcr_slot_to_index(&pcr_slot),
        })
        .collect();

    let pcr_set: Vec<u8> = pcr_sha256
        .into_iter()
        .map(|(pcr_slot, _digest)| pcr_slot_to_index(&pcr_slot))
        .collect();

    let (primarykey_res, certify_info, certify_sig) =
        create_ephemeral_key(ctx, quote_info.pcr_digest(), quote_info.pcr_selection())?;

    let Signature::RsaSsa(ref certify_rsa_sig) = certify_sig else {
        Err(vtpm::QuoteError::WrongSignature)?
    };
    let certify_sig = certify_rsa_sig.signature().to_vec();

    let tpm_info = TpmInfo {
        aik_cert: ak_cert,
        aik_pub: ak_pub,
        enc_key_certify_info: certify_info.marshall()?,
        enc_key_certify_info_signature: certify_sig,
        enc_key_pub: PublicBuffer::try_from(primarykey_res.out_public)?.marshall()?,
        pcrs: pcrs,
        pcr_quote: msg,
        pcr_set: pcr_set,
        pcr_signature: sig,
    };
    Ok((
        tpm_info,
        primarykey_res.key_handle,
        quote_info.pcr_digest().clone(),
        quote_info.pcr_selection().clone(),
    ))
}

async fn get_isolation_info() -> anyhow::Result<IsolationInfo> {
    let hcl_report = HclReport::new(vtpm::get_report()?)?;
    let snp_report = hcl_report.report_slice().to_vec();
    let runtime_data = hcl_report.var_data_slice().to_vec();

    Ok(IsolationInfo {
        evidence: Evidence {
            proof: Proof {
                snp_report,
                vcek_cert_chain: get_vcek_certchain().await?,
            },
            run_time_data: runtime_data,
        },
        type_field: "SevSnp".to_string(),
    })
}

#[derive(Debug)]
enum ServerError {
    BadRequest(String),
    InternalServerError(String),
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            ServerError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ServerError::InternalServerError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };
        let body = format!("Error: {}", msg);

        (status, body).into_response()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AttestationType {
    Maa = 0,
    SevSnp,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", content = "evidence", rename_all = "snake_case")]
pub enum AttestationEvidence {
    Maa {
        token: EncryptedJwt,
        key: Vec<u8>,
    },
    RawSevSnp {
        report: String,
        vcek: String,
        runtime_data: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        binary_bios_measurements: Option<String>,
    },
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ResponseStruct {
    version: String,
    attestation: AttestationEvidence,
    msg: String,
    sig: String,
    pcr: String,
}

#[derive(Debug, Deserialize)]
struct AttestationRequest {
    nonce: Option<String>,
    payload: Option<String>,
    // Optional because the TCG event log can make the responses much larger.
    // Should be requested only when the verifier needs to replay boot events into PCR values.
    #[cfg(feature = "raw-report")]
    binary_bios_measurements: Option<bool>,
}

use tempfile::NamedTempFile;

fn get_tpm2_quote_files() -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), ServerError> {
    let msg_file =
        NamedTempFile::new().map_err(|e| ServerError::InternalServerError(e.to_string()))?;
    let sig_file =
        NamedTempFile::new().map_err(|e| ServerError::InternalServerError(e.to_string()))?;
    let pcr_file =
        NamedTempFile::new().map_err(|e| ServerError::InternalServerError(e.to_string()))?;

    let output = Command::new("tpm2_quote")
        .arg("--quiet")
        .arg("--key-context")
        .arg("0x81000003")
        .arg("--pcr-list")
        .arg("sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15")
        .arg("--message")
        .arg(msg_file.path())
        .arg("--signature")
        .arg(sig_file.path())
        .arg("--pcr")
        .arg(pcr_file.path())
        .arg("--hash-algorithm")
        .arg("sha256")
        .output()
        .map_err(|e| {
            ServerError::InternalServerError(format!("failed to execute tpm2_quote: {e}"))
        })?;

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let details = match (stdout.trim().is_empty(), stderr.trim().is_empty()) {
            (true, true) => "no output".to_string(),
            (false, true) => format!("stdout: {}", stdout.trim()),
            (true, false) => format!("stderr: {}", stderr.trim()),
            (false, false) => format!("stdout: {}; stderr: {}", stdout.trim(), stderr.trim()),
        };
        return Err(ServerError::InternalServerError(format!(
            "tpm2_quote failed with status {}: {}",
            output.status, details
        )));
    }

    let msg_data =
        fs::read(msg_file.path()).map_err(|e| ServerError::InternalServerError(e.to_string()))?;
    let sig_data =
        fs::read(sig_file.path()).map_err(|e| ServerError::InternalServerError(e.to_string()))?;
    let pcr_data =
        fs::read(pcr_file.path()).map_err(|e| ServerError::InternalServerError(e.to_string()))?;

    if msg_data.is_empty() || sig_data.is_empty() || pcr_data.is_empty() {
        return Err(ServerError::InternalServerError(
            "tpm2_quote succeeded but did not produce complete quote files".to_string(),
        ));
    }

    Ok((msg_data, sig_data, pcr_data))
}

#[cfg(feature = "raw-report")]
#[derive(Debug, Serialize, Deserialize)]
pub struct ReportData {
    nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<String>,
}

#[cfg(feature = "dev-unbound-attestation")]
fn allow_unbound_attestation() -> bool {
    std::env::var("TEMENOS_ALLOW_UNBOUND_ATTESTATION")
        .map(|value| {
            matches!(
                value.trim().to_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

#[cfg(not(feature = "dev-unbound-attestation"))]
fn allow_unbound_attestation() -> bool {
    false
}

fn normalize_nonce(nonce: Option<String>) -> Option<String> {
    nonce
        .map(|nonce| nonce.trim().to_string())
        .filter(|nonce| !nonce.is_empty())
}

fn normalize_payload(payload: Option<String>) -> Option<String> {
    payload.filter(|payload| !payload.is_empty())
}

fn validate_attestation_inputs(
    nonce: Option<String>,
    payload: Option<String>,
    allow_unbound: bool,
) -> Result<(Option<String>, Option<String>), &'static str> {
    let nonce = normalize_nonce(nonce);
    let payload = normalize_payload(payload);

    match (&nonce, &payload) {
        (Some(_), _) => Ok((nonce, payload)),
        (None, Some(_)) => Err("payload requires a nonce"),
        (None, None) if allow_unbound => Ok((None, None)),
        (None, None) => Err(
            "nonce is required for attestation; unbound evidence is available only in explicitly configured debug images",
        ),
    }
}

fn attestation_inputs(
    nonce: Option<String>,
    payload: Option<String>,
) -> Result<(Option<String>, Option<String>), &'static str> {
    validate_attestation_inputs(nonce, payload, allow_unbound_attestation())
}

#[cfg(feature = "maa")]
fn maa_client_nonce(nonce: Option<String>) -> anyhow::Result<String> {
    if let Some(nonce) = nonce {
        return Ok(nonce);
    }

    #[cfg(feature = "dev-unbound-attestation")]
    {
        // MAA requires a nonce even when a debug client deliberately omits its
        // own. This value is server-generated and is not a client freshness
        // binding, but it avoids issuing every debug report under one constant.
        let mut nonce = [0_u8; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| anyhow!("failed to generate debug MAA nonce"))?;
        return Ok(BASE64_URL_SAFE_NO_PAD.encode(nonce));
    }

    #[cfg(not(feature = "dev-unbound-attestation"))]
    anyhow::bail!("nonce is required for attestation")
}

#[cfg(test)]
mod attestation_input_tests {
    #[cfg(not(feature = "dev-unbound-attestation"))]
    use super::allow_unbound_attestation;
    #[cfg(feature = "maa")]
    use super::maa_client_nonce;
    use super::validate_attestation_inputs;

    #[test]
    fn accepts_nonce_bound_inputs() {
        let inputs = validate_attestation_inputs(
            Some("  client-nonce  ".to_string()),
            Some("payload".to_string()),
            false,
        );

        assert_eq!(
            inputs,
            Ok((
                Some("client-nonce".to_string()),
                Some("payload".to_string())
            ))
        );
    }

    #[test]
    fn rejects_unbound_inputs_by_default() {
        let error = validate_attestation_inputs(None, None, false).unwrap_err();

        assert!(error.contains("nonce is required"));
    }

    #[cfg(not(feature = "dev-unbound-attestation"))]
    #[test]
    fn production_binary_has_no_unbound_capability() {
        assert!(!allow_unbound_attestation());
    }

    #[cfg(all(feature = "maa", not(feature = "dev-unbound-attestation")))]
    #[test]
    fn production_maa_nonce_has_no_fallback() {
        assert!(maa_client_nonce(None).is_err());
    }

    #[cfg(all(feature = "maa", feature = "dev-unbound-attestation"))]
    #[test]
    fn debug_unbound_maa_nonce_is_generated_per_request() {
        let first = maa_client_nonce(None).expect("debug nonce should be generated");
        let second = maa_client_nonce(None).expect("debug nonce should be generated");

        assert!(!first.is_empty());
        assert_ne!(first, second);
    }

    #[test]
    fn permits_unbound_inputs_only_when_explicitly_allowed() {
        assert_eq!(
            validate_attestation_inputs(None, None, true),
            Ok((None, None))
        );
    }

    #[test]
    fn rejects_payload_without_nonce_even_when_unbound_is_allowed() {
        assert_eq!(
            validate_attestation_inputs(None, Some("payload".to_string()), true),
            Err("payload requires a nonce")
        );
    }
}

#[cfg(feature = "raw-report")]
fn report_data_binding(nonce: String, payload: Option<String>) -> Result<[u8; 32], ServerError> {
    let report_data = ReportData { nonce, payload };
    let report_data = serde_json::to_vec(&report_data)
        .map_err(|e| ServerError::InternalServerError(e.to_string()))?;
    Ok(digest(&SHA256, &report_data)
        .as_ref()
        .try_into()
        .expect("SHA-256 is 32 bytes"))
}

#[cfg(feature = "raw-report")]
#[debug_handler]
async fn get_attestation(
    Query(request): Query<AttestationRequest>,
) -> Result<Json<ResponseStruct>, ServerError> {
    let (nonce, payload) = attestation_inputs(request.nonce, request.payload)
        .map_err(|message| ServerError::BadRequest(message.to_string()))?;

    let report_data = match (nonce, payload) {
        (Some(nonce), payload) => Some(report_data_binding(nonce, payload)?),
        (None, None) => None,
        (None, Some(_)) => unreachable!("attestation inputs were validated"),
    };

    let report = match report_data.as_ref() {
        Some(report_data) => az_snp_vtpm::vtpm::get_report_with_report_data(report_data),
        // Explicit dev/test escape hatch only; default raw mode requires
        // report_data binding so evidence is nonce-bound.
        None => az_snp_vtpm::vtpm::get_report(),
    }
    .map_err(|e| ServerError::InternalServerError(e.to_string()))?;

    // az-snp-vtpm returns a serialized HCL report: the SNP report plus runtime data.
    // Convert it so raw mode can expose those fields alongside the VCEK cert chain.
    let hcl_report = az_snp_vtpm::hcl::HclReport::new(report)
        .map_err(|e| ServerError::InternalServerError(e.to_string()))?;
    // Keep the runtime data before converting the HCL wrapper into the SNP report.
    let runtime_data = hcl_report.var_data().to_vec();
    let snp_report: az_snp_vtpm::report::AttestationReport = hcl_report.try_into().unwrap();

    // Get the VCEK cert chain and AMD chain of trust from IMDS.
    // Azure can provide the exact VCEK cert without requiring us to know the AMD CPU family.
    let vcek = get_vcek_certchain()
        .await
        .map_err(|e| ServerError::InternalServerError(e.to_string()))?;

    let (msg_data, sig_data, pcr_data) = get_tpm2_quote_files()?;

    let b64_msg_data = BASE64_STANDARD.encode(msg_data);
    let b64_sig_data = BASE64_STANDARD.encode(sig_data);
    let b64_pcr_data = BASE64_STANDARD.encode(pcr_data);

    let binary_bios_measurements = if request.binary_bios_measurements.unwrap_or(false) {
        let event_log =
            fs::read("/sys/kernel/security/tpm0/binary_bios_measurements").map_err(|e| {
                ServerError::InternalServerError(format!(
                    "requested binary_bios_measurements but failed to read TCG event log: {}",
                    e
                ))
            })?;
        Some(BASE64_STANDARD.encode(event_log))
    } else {
        None
    };

    let new_struct = ResponseStruct {
        version: "1".to_owned(),
        attestation: AttestationEvidence::RawSevSnp {
            report: BASE64_STANDARD.encode(
                snp_report
                    .to_bytes()
                    .map_err(|e| ServerError::InternalServerError(e.to_string()))?,
            ),
            vcek: vcek,
            runtime_data: BASE64_STANDARD.encode(runtime_data),
            binary_bios_measurements,
        },
        msg: b64_msg_data,
        sig: b64_sig_data,
        pcr: b64_pcr_data,
    };

    Ok(axum::Json(new_struct))
}

#[cfg(feature = "maa")]
#[debug_handler]
async fn get_attestation(
    Query(request): Query<AttestationRequest>,
) -> Result<Json<ResponseStruct>, ServerError> {
    let (nonce, payload) = attestation_inputs(request.nonce, request.payload)
        .map_err(|message| ServerError::BadRequest(message.to_string()))?;

    generate_attestation(nonce, payload)
        .await
        .map(Json)
        .map_err(|e| ServerError::InternalServerError(e.to_string()))
}

/// Produce a full attestation evidence bundle, optionally binding a client
/// `nonce` / `payload`. Shared by `GET /` and the epoch-key attester
/// (`GET /enclave-key`) so the attested-channel work reuses the deployment-
/// tested evidence path rather than re-implementing SNP/vTPM collection.
///
/// - **`maa` feature:** binds via MAA `client_payload` (token commits to it).
/// - **`raw-report` feature:** binds via Azure HCL
///   `get_report_with_report_data` (PR #11).
///
/// This helper enforces the nonce policy itself so internal callers cannot
/// bypass the HTTP-layer validation. Unbound evidence is available only when
/// the binary includes the `dev-unbound-attestation` feature and its debug
/// image enables `TEMENOS_ALLOW_UNBOUND_ATTESTATION`.
pub(crate) async fn generate_attestation(
    nonce: Option<String>,
    payload: Option<String>,
) -> anyhow::Result<ResponseStruct> {
    let (nonce, payload) = attestation_inputs(nonce, payload).map_err(anyhow::Error::msg)?;

    #[cfg(feature = "maa")]
    {
        let isolation_info = get_isolation_info().await?;

        let conf: TctiNameConf = TctiNameConf::Device(DeviceConfig::from_str("/dev/tpmrm0")?);
        let mut ctx = Context::new(conf)?;

        let (tpm_info, key_handle, pcr_digest, pcr_selection) = get_tpm_info(&mut ctx)?;

        let attest_info = AttestationInfo {
            attestation_protocol_version: "2.0".to_string(),
            client_payload: ClientPayload {
                nonce: maa_client_nonce(nonce)?,
                payload,
            },
            isolation_info,
            // For Linux, this field is not applicable and is ignored by Azure Attestation.
            os_build: "NotApplication".to_string(),
            os_distro: "Ubuntu".to_string(),
            os_type: "Linux".to_string(),
            os_version_major: 22,
            os_version_minor: 4,
            tcg_logs: fs::read("/sys/kernel/security/tpm0/binary_bios_measurements")?,
            tpm_info,
        };
        let req_body = Root {
            attestation_info: attest_info,
        };

        let client = Client::new();
        let resp = client
            .post(
                "https://midnightl2.eus.attest.azure.net/attest/AzureGuest?api-version=2020-10-01",
            )
            .json(&req_body)
            .send()
            .await;

        if let Ok(pretty) = serde_json::to_string(&req_body) {
            let _ = fs::write("/tmp/maa-request.json", &pretty);
        }

        let response = resp?.error_for_status()?;
        let maa_response: MaaResponse = response.json().await?;

        let inner_key = decrypt_inner_key(
            &mut ctx,
            &maa_response.token.encrypted_inner_key,
            &key_handle,
            &pcr_digest,
            &pcr_selection,
        )?;

        let (msg_data, sig_data, pcr_data) =
            get_tpm2_quote_files().map_err(|e| anyhow::anyhow!("{e:?}"))?;

        Ok(ResponseStruct {
            version: "1".to_owned(),
            attestation: AttestationEvidence::Maa {
                token: maa_response.token,
                key: inner_key,
            },
            msg: BASE64_STANDARD.encode(msg_data),
            sig: BASE64_STANDARD.encode(sig_data),
            pcr: BASE64_STANDARD.encode(pcr_data),
        })
    }

    #[cfg(feature = "raw-report")]
    {
        let report_data = match (nonce, payload) {
            (Some(nonce), payload) => {
                Some(report_data_binding(nonce, payload).map_err(|e| anyhow::anyhow!("{e:?}"))?)
            }
            (None, None) => None,
            (None, Some(_)) => unreachable!("attestation inputs were validated"),
        };

        let report = match report_data.as_ref() {
            Some(report_data) => az_snp_vtpm::vtpm::get_report_with_report_data(report_data),
            None => az_snp_vtpm::vtpm::get_report(),
        }?;

        let hcl_report = az_snp_vtpm::hcl::HclReport::new(report)?;
        let runtime_data = hcl_report.var_data().to_vec();
        let snp_report: az_snp_vtpm::report::AttestationReport = hcl_report.try_into()?;

        let vcek = get_vcek_certchain().await?;

        let (msg_data, sig_data, pcr_data) =
            get_tpm2_quote_files().map_err(|e| anyhow::anyhow!("{e:?}"))?;

        Ok(ResponseStruct {
            version: "1".to_owned(),
            attestation: AttestationEvidence::RawSevSnp {
                report: BASE64_STANDARD.encode(snp_report.to_bytes()?),
                vcek,
                runtime_data: BASE64_STANDARD.encode(runtime_data),
                binary_bios_measurements: None,
            },
            msg: BASE64_STANDARD.encode(msg_data),
            sig: BASE64_STANDARD.encode(sig_data),
            pcr: BASE64_STANDARD.encode(pcr_data),
        })
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Epoch key-gen at process start (systemd starts us after network /
    // measured-setup). The persisted counter in AKX_EPOCH_FILE increments once
    // per boot so each reboot is a new epoch; timed rotation is optional via
    // AKX_EPOCH_ROTATE_SECS (Phase 6).
    let epoch = next_boot_epoch();
    // PlatformAttester::attest uses Handle::block_on and must run off the async
    // worker (also used by background refresh/rotate via spawn_blocking).
    let epoch_mgr = Arc::new(
        tokio::task::spawn_blocking(move || EpochManager::new(&PlatformAttester, epoch))
            .await
            .map_err(|e| anyhow!("epoch key attestation join error: {e}"))?
            .map_err(|e| anyhow!("epoch key attestation failed: {e}"))?,
    );
    println!("Minted epoch key (epoch={epoch})");

    spawn_epoch_maintenance(epoch_mgr.clone());

    let upstream = DappUpstream::from_env()?;
    let state = AppState {
        epoch: epoch_mgr,
        sessions: Arc::new(SessionStore::new(SessionConfig::default())),
        upstream,
        proxy_gates: Arc::new(ProxyGates::new()),
    };

    let app = Router::new()
        .route("/", get(get_attestation))
        .route("/enclave-key", get(get_enclave_key))
        .route("/session", post(post_session))
        .route("/session/complete", post(post_session_complete))
        .route("/proxy", post(post_proxy))
        .with_state(state);

    // Caddy runs in Docker and reaches this listener through the host-gateway
    // address. Guest iptables restricts port 8000 to Docker bridge interfaces;
    // public access is TLS-only through Caddy on port 443.
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await?;
    println!("Starting http server at : 0.0.0.0:8000");
    Ok(axum::serve(listener, app).await?)
}

/// Load the persisted epoch counter, increment it, and write it back. Falls
/// back to `1` (and creates the file) if unset / unreadable. Override the path
/// with `AKX_EPOCH_FILE` (systemd sets `/var/lib/attestation_server/epoch`).
fn next_boot_epoch() -> u64 {
    let path = std::env::var("AKX_EPOCH_FILE")
        .unwrap_or_else(|_| "/var/lib/attestation_server/epoch".to_string());
    let prev = fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);
    let next = prev.saturating_add(1).max(1);
    if let Some(parent) = std::path::Path::new(&path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Err(e) = fs::write(&path, format!("{next}\n")) {
        eprintln!("warning: could not persist epoch counter to {path}: {e}");
    }
    next
}

/// Background tasks (Phase 6):
/// - periodically **refresh** the attestation of the current epoch key so
///   clients polling `GET /enclave-key` get fresh evidence without blocking;
/// - optionally **rotate** the epoch key on a longer interval.
fn spawn_epoch_maintenance(epoch: Arc<EpochManager>) {
    let refresh_secs: u64 = std::env::var("AKX_ATTEST_REFRESH_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);
    let rotate_secs: u64 = std::env::var("AKX_EPOCH_ROTATE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    if refresh_secs > 0 {
        let epoch_r = epoch.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(refresh_secs));
            ticker.tick().await; // skip the immediate first tick (just attested at boot)
            loop {
                ticker.tick().await;
                match tokio::task::spawn_blocking({
                    let epoch_r = epoch_r.clone();
                    move || epoch_r.refresh_attestation(&PlatformAttester)
                })
                .await
                {
                    Ok(Ok(())) => {
                        println!("Refreshed epoch attestation (epoch={})", epoch_r.epoch());
                    }
                    Ok(Err(e)) => eprintln!("epoch attestation refresh failed: {e}"),
                    Err(e) => eprintln!("epoch attestation refresh join error: {e}"),
                }
            }
        });
    }

    if rotate_secs > 0 {
        let epoch_r = epoch;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(rotate_secs));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let new_epoch = epoch_r.epoch().saturating_add(1);
                match tokio::task::spawn_blocking({
                    let epoch_r = epoch_r.clone();
                    move || epoch_r.rotate(&PlatformAttester, new_epoch)
                })
                .await
                {
                    Ok(Ok(())) => {
                        // Keep the persisted counter in sync with timed rotations.
                        if let Ok(path) = std::env::var("AKX_EPOCH_FILE") {
                            let _ = fs::write(&path, format!("{new_epoch}\n"));
                        }
                        println!("Rotated epoch key (epoch={new_epoch})");
                    }
                    Ok(Err(e)) => eprintln!("epoch rotation failed: {e}"),
                    Err(e) => eprintln!("epoch rotation join error: {e}"),
                }
            }
        });
    }
}
