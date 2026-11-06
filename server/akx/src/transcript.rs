//! Domain-separated, length-prefixed transcript hashing.

use sha2::{Digest, Sha256};

/// Protocol + version domain-separation label. Bumping this string is how we
/// version the protocol; a client and enclave that disagree on the label will
/// derive different transcripts and abort.
pub const LABEL: &[u8] = b"temenos-akx-v1";

/// Absorb a single variable-length field with an 8-byte big-endian length
/// prefix, so that distinct field boundaries can never be confused (i.e. the
/// encoding is injective over the tuple of inputs).
fn absorb(hasher: &mut Sha256, field: &[u8]) {
    hasher.update((field.len() as u64).to_be_bytes());
    hasher.update(field);
}

/// Compute the handshake transcript hash that the enclave signs with its epoch
/// key and that both parties feed into the HPKE key schedule (`info`).
///
/// It commits to the session id, the client nonce (freshness) and the enclave's
/// per-session public key (server authentication / anti-splicing). The client's
/// own ephemeral contribution is the HPKE encapsulated key, which is bound into
/// the derived keys by HPKE itself when this hash is used as `info`.
pub fn transcript_hash(sid: &[u8], nonce_c: &[u8], enclave_session_pub: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    absorb(&mut h, LABEL);
    absorb(&mut h, sid);
    absorb(&mut h, nonce_c);
    absorb(&mut h, enclave_session_pub);
    h.finalize().into()
}
