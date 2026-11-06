//! Session-tier handshake: HPKE (X25519 / HKDF-SHA256 / AES-256-GCM) key
//! establishment authenticated by the epoch key's signature over the transcript.

use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use rand::rngs::OsRng;

use super::epoch::{verify_epoch_sig, EpochKey};
use super::record::{RecordKey, DIR_C2S, DIR_S2C};
use super::transcript::transcript_hash;
use super::AkxError;

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = AesGcm256;

/// Exporter context strings for the two directional record keys.
const EXPORT_C2S: &[u8] = b"temenos-akx-v1 c2s";
const EXPORT_S2C: &[u8] = b"temenos-akx-v1 s2c";

/// The enclave's response to a `ClientHello`, sent to the client.
#[derive(Clone)]
pub struct EnclaveHandshake {
    /// Serialized per-session HPKE recipient public key (`S_sess`).
    pub enclave_session_pub: Vec<u8>,
    /// Ed25519 signature by the epoch key over `transcript_hash(sid, nonce_c, S_sess)`.
    pub signature: [u8; 64],
}

/// Enclave-side secret state retained between `enclave_begin` and
/// `enclave_complete` (stored in the session store, keyed by `sid`).
pub struct EnclavePending {
    sk: <Kem as KemTrait>::PrivateKey,
    transcript: [u8; 32],
}

/// Derive the two directional record keys from an established HPKE context.
/// Works for both the sender (`AeadCtxS`) and receiver (`AeadCtxR`) contexts,
/// which export identical secrets for identical exporter info.
macro_rules! derive_record_keys {
    ($ctx:expr) => {{
        let mut k_c2s = [0u8; 32];
        let mut k_s2c = [0u8; 32];
        $ctx.export(EXPORT_C2S, &mut k_c2s)
            .map_err(|_| AkxError::Hpke)?;
        $ctx.export(EXPORT_S2C, &mut k_s2c)
            .map_err(|_| AkxError::Hpke)?;
        (
            RecordKey::new(k_c2s, DIR_C2S),
            RecordKey::new(k_s2c, DIR_S2C),
        )
    }};
}

/// **Enclave, step 1** — on receiving `ClientHello { sid, nonce_c }`, mint a
/// fresh per-session HPKE keypair and sign the transcript with the epoch key.
/// Returns the secret pending state (to keep) and the handshake (to send).
pub fn enclave_begin(
    epoch: &EpochKey,
    sid: &[u8],
    nonce_c: &[u8],
) -> (EnclavePending, EnclaveHandshake) {
    let (sk, pk) = Kem::gen_keypair(&mut OsRng);
    let pk_bytes = pk.to_bytes().to_vec();
    let transcript = transcript_hash(sid, nonce_c, &pk_bytes);
    let signature = epoch.sign(&transcript);
    (
        EnclavePending { sk, transcript },
        EnclaveHandshake {
            enclave_session_pub: pk_bytes,
            signature,
        },
    )
}

/// **Enclave, step 2** — once the client's HPKE encapsulated key arrives, set up
/// the receiver context and derive the directional record keys.
pub fn enclave_complete(
    pending: EnclavePending,
    enc_bytes: &[u8],
) -> Result<(RecordKey, RecordKey), AkxError> {
    let enc =
        <Kem as KemTrait>::EncappedKey::from_bytes(enc_bytes).map_err(|_| AkxError::BadKey)?;
    let ctx = hpke::setup_receiver::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &pending.sk,
        &enc,
        &pending.transcript,
    )
    .map_err(|_| AkxError::Hpke)?;
    Ok(derive_record_keys!(ctx))
}

/// **Client** — verify the enclave handshake against the (attested) epoch public
/// key, then set up the HPKE sender context. Returns the encapsulated key to
/// send to the enclave plus the two directional record keys.
///
/// The caller MUST have already verified, via the SEV-SNP attestation, that
/// `epoch_pub` is committed in the enclave's `report_data`. This function only
/// establishes that the handshake was signed by that (attested) epoch key.
pub fn client_establish(
    epoch_pub: &[u8; 32],
    sid: &[u8],
    nonce_c: &[u8],
    handshake: &EnclaveHandshake,
) -> Result<(Vec<u8>, RecordKey, RecordKey), AkxError> {
    // Recompute the transcript from the client's *own* sid/nonce and the
    // received key, and require the epoch key to have signed exactly that.
    let transcript = transcript_hash(sid, nonce_c, &handshake.enclave_session_pub);
    verify_epoch_sig(epoch_pub, &transcript, &handshake.signature)?;

    let pk = <Kem as KemTrait>::PublicKey::from_bytes(&handshake.enclave_session_pub)
        .map_err(|_| AkxError::BadKey)?;
    let (enc, ctx) =
        hpke::setup_sender::<Aead, Kdf, Kem, _>(&OpModeS::Base, &pk, &transcript, &mut OsRng)
            .map_err(|_| AkxError::Hpke)?;
    let (c2s, s2c) = derive_record_keys!(ctx);
    Ok((enc.to_bytes().to_vec(), c2s, s2c))
}
