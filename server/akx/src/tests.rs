//! Unit tests for the AKX crypto core, including the concrete attacks from
//! `docs/tls-channel-binding.md` §7 that the crypto layer is responsible for.

use super::*;

/// Drive a full handshake and return the four record keys:
/// (client c2s, client s2c, enclave c2s, enclave s2c).
fn full_handshake(
    epoch: &EpochKey,
    sid: &[u8],
    nonce_c: &[u8],
) -> (RecordKey, RecordKey, RecordKey, RecordKey) {
    let (pending, handshake) = enclave_begin(epoch, sid, nonce_c);
    let (enc, client_c2s, client_s2c) =
        client_establish(&epoch.public_bytes(), sid, nonce_c, &handshake)
            .expect("client establish");
    let (enclave_c2s, enclave_s2c) = enclave_complete(pending, &enc).expect("enclave complete");
    (client_c2s, client_s2c, enclave_c2s, enclave_s2c)
}

#[test]
fn handshake_and_bidirectional_records_roundtrip() {
    let epoch = EpochKey::generate(1);
    let sid = b"session-abc";
    let nonce_c = b"client-nonce-0123456789";

    let (mut c_c2s, mut c_s2c, mut e_c2s, mut e_s2c) = full_handshake(&epoch, sid, nonce_c);

    // client -> server
    for msg in [b"hello".as_slice(), b"second request", b""] {
        let ct = c_c2s.seal(sid, msg).unwrap();
        let pt = e_c2s.open(sid, &ct).unwrap();
        assert_eq!(pt, msg);
    }

    // server -> client
    for msg in [b"proof-response".as_slice(), b"another"] {
        let ct = e_s2c.seal(sid, msg).unwrap();
        let pt = c_s2c.open(sid, &ct).unwrap();
        assert_eq!(pt, msg);
    }
}

/// §7 A2/A8 — MITM key substitution: the enclave's session public key is
/// swapped for the attacker's. The epoch signature no longer covers it, so the
/// client aborts.
#[test]
fn rejects_substituted_session_key() {
    let epoch = EpochKey::generate(1);
    let sid = b"sid";
    let nonce_c = b"nonce";
    let (_pending, mut handshake) = enclave_begin(&epoch, sid, nonce_c);

    // Attacker replaces the session key with one they control.
    let attacker = EpochKey::generate(99); // any 32 bytes will do
    handshake.enclave_session_pub = attacker.public_bytes().to_vec();

    assert!(matches!(
        client_establish(&epoch.public_bytes(), sid, nonce_c, &handshake),
        Err(AkxError::BadSignature)
    ));
}

/// A client that verifies against the wrong epoch key (e.g. an unattested one)
/// must reject an otherwise-valid handshake.
#[test]
fn rejects_wrong_epoch_key() {
    let real = EpochKey::generate(1);
    let impostor = EpochKey::generate(1);
    let sid = b"sid";
    let nonce_c = b"nonce";
    let (_pending, handshake) = enclave_begin(&real, sid, nonce_c);

    assert!(matches!(
        client_establish(&impostor.public_bytes(), sid, nonce_c, &handshake),
        Err(AkxError::BadSignature)
    ));
}

/// §7 A3 — replayed/stale handshake bound to a different nonce: the client's
/// recomputed transcript won't match the signature.
#[test]
fn rejects_transcript_binding_mismatch() {
    let epoch = EpochKey::generate(1);
    let (_pending, handshake) = enclave_begin(&epoch, b"sid", b"nonce-A");

    // Client believes it used a different nonce than what was signed.
    assert!(matches!(
        client_establish(&epoch.public_bytes(), b"sid", b"nonce-B", &handshake),
        Err(AkxError::BadSignature)
    ));
}

/// §7 A6 — record tampering: flipping any ciphertext bit fails AEAD open.
#[test]
fn rejects_tampered_ciphertext() {
    let epoch = EpochKey::generate(1);
    let (mut c_c2s, _, mut e_c2s, _) = full_handshake(&epoch, b"sid", b"nonce");

    let mut ct = c_c2s.seal(b"sid", b"payload").unwrap();
    ct[0] ^= 0x01;
    assert_eq!(e_c2s.open(b"sid", &ct).unwrap_err(), AkxError::Aead);
}

/// §7 A6 — associated-data tampering (e.g. rebinding to a different session id).
#[test]
fn rejects_wrong_aad() {
    let epoch = EpochKey::generate(1);
    let (mut c_c2s, _, mut e_c2s, _) = full_handshake(&epoch, b"sid", b"nonce");

    let ct = c_c2s.seal(b"sid", b"payload").unwrap();
    assert_eq!(e_c2s.open(b"other-sid", &ct).unwrap_err(), AkxError::Aead);
}

/// §7 A5 — reordering / replay: records opened out of sequence fail because the
/// derived nonce no longer matches.
#[test]
fn rejects_reordered_records() {
    let epoch = EpochKey::generate(1);
    let (mut c_c2s, _, mut e_c2s, _) = full_handshake(&epoch, b"sid", b"nonce");

    let ct0 = c_c2s.seal(b"sid", b"first").unwrap();
    let ct1 = c_c2s.seal(b"sid", b"second").unwrap();

    // Deliver ct1 before ct0: opener expects seq 0, gets a seq-1 record.
    assert_eq!(e_c2s.open(b"sid", &ct1).unwrap_err(), AkxError::Aead);
    // Stream is now desynchronised; even the "correct" first record won't open.
    assert!(e_c2s.open(b"sid", &ct0).is_err());
}

/// The two directions are cryptographically separated: a c2s record must not
/// open as an s2c record even at the same sequence position.
#[test]
fn directions_are_separated() {
    let epoch = EpochKey::generate(1);
    let (mut c_c2s, _c_s2c, _e_c2s, mut e_s2c) = full_handshake(&epoch, b"sid", b"nonce");

    let ct = c_c2s.seal(b"sid", b"payload").unwrap();
    // Try to open a client->server record using the server->client key.
    assert!(e_s2c.open(b"sid", &ct).is_err());
}

/// `report_data` is deterministic in (epoch, pubkey) and changes when either
/// input changes — this is what the client recomputes to bind the epoch key to
/// the attestation.
#[test]
fn report_data_is_bound_to_epoch_and_key() {
    let k = EpochKey::generate(7);
    let pk = k.public_bytes();

    assert_eq!(report_data_for(7, &pk), k.report_data());
    assert_ne!(report_data_for(7, &pk), report_data_for(8, &pk));

    let other = EpochKey::generate(7).public_bytes();
    assert_ne!(report_data_for(7, &pk), report_data_for(7, &other));

    // Digest lives in the first 32 bytes; the rest is zero padding.
    assert_eq!(k.report_data()[32..], [0u8; 32]);
}

/// Distinct sessions derive distinct keys even with identical inputs, thanks to
/// the fresh per-session HPKE keypair and encapsulation (forward secrecy).
#[test]
fn distinct_sessions_have_distinct_keys() {
    let epoch = EpochKey::generate(1);
    let (mut a, _, _, _) = full_handshake(&epoch, b"sid", b"nonce");
    let (mut b, _, _, _) = full_handshake(&epoch, b"sid", b"nonce");

    let ct = a.seal(b"sid", b"same-plaintext").unwrap();
    let ct2 = b.seal(b"sid", b"same-plaintext").unwrap();
    assert_ne!(ct, ct2);
}

// --- Phase 1: attester + epoch manager --------------------------------------

/// The epoch manager attests exactly `H("temenos-akx-v1" ‖ epoch ‖ pk_e)` — the
/// value the client will recompute from the epoch public key it receives.
#[test]
fn epoch_manager_binds_epoch_public_key() {
    let epoch = 5u64;
    let mgr = EpochManager::new(&FakeAttester, epoch).expect("attest");

    let expected_report_data = report_data_for(epoch, &mgr.epoch_public());
    let mut expected = FAKE_ATTESTATION_PREFIX.to_vec();
    expected.extend_from_slice(&expected_report_data);

    assert_eq!(mgr.epoch(), epoch);
    assert_eq!(mgr.attestation(), expected);
}

/// A handshake begun by the epoch manager completes end to end against a client
/// that only knows the manager's (attested) epoch public key.
#[test]
fn epoch_manager_begin_session_roundtrip() {
    let mgr = EpochManager::new(&FakeAttester, 1).expect("attest");
    let sid = b"sid-xyz";
    let nonce_c = b"client-nonce";

    let (pending, handshake) = mgr.begin_session(sid, nonce_c);
    let (enc, mut client_c2s, _client_s2c) =
        client_establish(&mgr.epoch_public(), sid, nonce_c, &handshake).expect("client establish");
    let (mut enclave_c2s, _enclave_s2c) =
        enclave_complete(pending, &enc).expect("enclave complete");

    let ct = client_c2s.seal(sid, b"ping").unwrap();
    assert_eq!(enclave_c2s.open(sid, &ct).unwrap(), b"ping");
}

/// An attester failure surfaces as `AkxError::Attest` from `EpochManager::new`.
#[test]
fn epoch_manager_propagates_attester_failure() {
    struct FailingAttester;
    impl Attester for FailingAttester {
        fn attest(&self, _report_data: &[u8; 64]) -> Result<Vec<u8>, AkxError> {
            Err(AkxError::Attest("boom".into()))
        }
    }

    assert!(matches!(
        EpochManager::new(&FailingAttester, 1),
        Err(AkxError::Attest(_))
    ));
}

// --- Phase 2: session store -------------------------------------------------

use std::time::Duration;

fn test_store() -> (EpochManager, SessionStore) {
    let mgr = EpochManager::new(&FakeAttester, 1).expect("attest");
    let store = SessionStore::new(SessionConfig {
        ttl: Duration::from_secs(300),
        max_sessions: 4,
    });
    (mgr, store)
}

/// Full store-driven handshake: hello → insert_pending → client establish →
/// complete → exchange a record through the stored keys.
#[test]
fn session_store_full_handshake_via_store() {
    let (mgr, store) = test_store();
    let sid = b"sid-1".to_vec();
    let nonce_c = b"nonce-1";

    let (pending, handshake) = mgr.begin_session(&sid, nonce_c);
    store.insert_pending(sid.clone(), pending).unwrap();

    let (enc, mut client_c2s, mut client_s2c) =
        client_establish(&mgr.epoch_public(), &sid, nonce_c, &handshake).unwrap();
    store.complete(&sid, &enc).unwrap();

    // client -> server, decrypted via the stored c2s key
    let ct = client_c2s.seal(&sid, b"request").unwrap();
    let got = store
        .with_records(&sid, |c2s, _s2c| c2s.open(&sid, &ct))
        .unwrap()
        .unwrap();
    assert_eq!(got, b"request");

    // server -> client, sealed via the stored s2c key
    let resp_ct = store
        .with_records(&sid, |_c2s, s2c| s2c.seal(&sid, b"response"))
        .unwrap()
        .unwrap();
    assert_eq!(client_s2c.open(&sid, &resp_ct).unwrap(), b"response");
}

#[test]
fn session_store_rejects_duplicate_sid() {
    let (mgr, store) = test_store();
    let sid = b"dup".to_vec();
    let (p1, _) = mgr.begin_session(&sid, b"n");
    let (p2, _) = mgr.begin_session(&sid, b"n");
    store.insert_pending(sid.clone(), p1).unwrap();
    assert_eq!(store.insert_pending(sid, p2), Err(SessionError::Duplicate));
}

#[test]
fn session_store_enforces_capacity() {
    let (mgr, store) = test_store(); // max_sessions = 4
    for i in 0..4u8 {
        let sid = vec![i];
        let (p, _) = mgr.begin_session(&sid, b"n");
        store.insert_pending(sid, p).unwrap();
    }
    let (p, _) = mgr.begin_session(b"overflow", b"n");
    assert_eq!(
        store.insert_pending(b"overflow".to_vec(), p),
        Err(SessionError::Full)
    );
}

#[test]
fn session_store_complete_unknown_is_not_found() {
    let (_mgr, store) = test_store();
    assert_eq!(
        store.complete(b"missing", b"whatever"),
        Err(SessionError::NotFound)
    );
}

#[test]
fn session_store_double_complete_is_wrong_state() {
    let (mgr, store) = test_store();
    let sid = b"once".to_vec();
    let (pending, handshake) = mgr.begin_session(&sid, b"n");
    store.insert_pending(sid.clone(), pending).unwrap();
    let (enc, _, _) = client_establish(&mgr.epoch_public(), &sid, b"n", &handshake).unwrap();

    store.complete(&sid, &enc).unwrap();
    // Second completion finds an Established entry and must not clobber it.
    assert_eq!(store.complete(&sid, &enc), Err(SessionError::WrongState));
    assert!(store.with_records(&sid, |_, _| ()).is_ok());
}

#[test]
fn session_store_evicts_expired() {
    let mgr = EpochManager::new(&FakeAttester, 1).expect("attest");
    let store = SessionStore::new(SessionConfig {
        ttl: Duration::ZERO,
        max_sessions: 8,
    });
    let (pending, _) = mgr.begin_session(b"sid", b"n");
    store.insert_pending(b"sid".to_vec(), pending).unwrap();
    assert_eq!(store.len(), 1);
    store.evict_expired();
    assert!(store.is_empty());
}

#[test]
fn session_store_ensure_established() {
    let (mgr, store) = test_store();
    let sid = b"ready".to_vec();
    assert_eq!(store.ensure_established(&sid), Err(SessionError::NotFound));

    let (pending, handshake) = mgr.begin_session(&sid, b"n");
    store.insert_pending(sid.clone(), pending).unwrap();
    assert_eq!(
        store.ensure_established(&sid),
        Err(SessionError::WrongState)
    );

    let (enc, _, _) = client_establish(&mgr.epoch_public(), &sid, b"n", &handshake).unwrap();
    store.complete(&sid, &enc).unwrap();
    assert!(store.ensure_established(&sid).is_ok());
}

#[test]
fn session_store_complete_and_with_records_respect_ttl() {
    let mgr = EpochManager::new(&FakeAttester, 1).expect("attest");
    let store = SessionStore::new(SessionConfig {
        ttl: Duration::from_millis(30),
        max_sessions: 8,
    });
    let sid = b"ttl-proxy".to_vec();
    let (pending, handshake) = mgr.begin_session(&sid, b"n");
    store.insert_pending(sid.clone(), pending).unwrap();
    let (enc, _, _) = client_establish(&mgr.epoch_public(), &sid, b"n", &handshake).unwrap();
    store.complete(&sid, &enc).unwrap();
    assert!(store.with_records(&sid, |_, _| ()).is_ok());

    std::thread::sleep(Duration::from_millis(40));
    assert_eq!(
        store.with_records(&sid, |_, _| ()),
        Err(SessionError::NotFound)
    );
}

// --- Phase 3: decrypt-and-forward proxy record layer ------------------------

/// Mirrors the `POST /proxy` handler: for each request the enclave `open`s the
/// c2s record, forwards the plaintext to a (stubbed) upstream, then `seal`s the
/// response on s2c — each via a *separate* `with_records` call, as the async
/// handler must (it cannot hold the store lock across the upstream await). This
/// verifies the directional sequence counters stay in lockstep across many
/// sequential round-trips despite the interleaved, separate lock acquisitions.
#[test]
fn session_store_proxy_style_roundtrips_keep_sequence() {
    let (mgr, store) = test_store();
    let sid = b"sid-proxy".to_vec();
    let nonce_c = b"nonce-proxy";

    let (pending, handshake) = mgr.begin_session(&sid, nonce_c);
    store.insert_pending(sid.clone(), pending).unwrap();
    let (enc, mut client_c2s, mut client_s2c) =
        client_establish(&mgr.epoch_public(), &sid, nonce_c, &handshake).unwrap();
    store.complete(&sid, &enc).unwrap();

    // Stub upstream: echo the request with a trailing marker byte.
    let upstream = |req: &[u8]| {
        let mut resp = req.to_vec();
        resp.push(0xAA);
        resp
    };

    for i in 0..4u8 {
        let request = vec![i; usize::from(i) + 1];
        let ct_req = client_c2s.seal(&sid, &request).unwrap();

        // Enclave decrypts in-VM (aad = sid).
        let got = store
            .with_records(&sid, |c2s, _s2c| c2s.open(&sid, &ct_req))
            .unwrap()
            .unwrap();
        assert_eq!(got, request);

        let response = upstream(&got);

        // Enclave re-encrypts the upstream response.
        let ct_resp = store
            .with_records(&sid, |_c2s, s2c| s2c.seal(&sid, &response))
            .unwrap()
            .unwrap();
        assert_eq!(client_s2c.open(&sid, &ct_resp).unwrap(), response);
    }
}

/// A proxied record that fails to authenticate (tampered ciphertext) is a
/// desync/forgery; the handler drops the session, so a subsequent lookup is
/// `NotFound`. Here we assert the open fails and emulate the handler's
/// `remove`.
#[test]
fn session_store_proxy_bad_record_then_removed() {
    let (mgr, store) = test_store();
    let sid = b"sid-bad".to_vec();
    let nonce_c = b"n";

    let (pending, handshake) = mgr.begin_session(&sid, nonce_c);
    store.insert_pending(sid.clone(), pending).unwrap();
    let (enc, mut client_c2s, _client_s2c) =
        client_establish(&mgr.epoch_public(), &sid, nonce_c, &handshake).unwrap();
    store.complete(&sid, &enc).unwrap();

    let mut ct = client_c2s.seal(&sid, b"payload").unwrap();
    ct[0] ^= 0x01; // tamper

    let open_result = store
        .with_records(&sid, |c2s, _s2c| c2s.open(&sid, &ct))
        .unwrap();
    assert!(open_result.is_err());

    // Handler drops the session on a bad record.
    assert!(store.remove(&sid));
    assert_eq!(
        store.with_records(&sid, |_, _| ()),
        Err(SessionError::NotFound)
    );
}

// --- Phase 6: attestation refresh + epoch rotation --------------------------

use std::sync::atomic::{AtomicU64, Ordering};

/// Attester that tags each bundle with a monotonic counter so refresh is
/// observable (FakeAttester alone is deterministic and would hide refresh).
struct CountingAttester(AtomicU64);

impl Attester for CountingAttester {
    fn attest(&self, report_data: &[u8; 64]) -> Result<Vec<u8>, AkxError> {
        let n = self.0.fetch_add(1, Ordering::SeqCst);
        let mut out = Vec::with_capacity(4 + 8 + report_data.len());
        out.extend_from_slice(b"CNT!");
        out.extend_from_slice(&n.to_be_bytes());
        out.extend_from_slice(report_data);
        Ok(out)
    }
}

#[test]
fn epoch_manager_refresh_keeps_key_updates_attestation() {
    let attester = CountingAttester(AtomicU64::new(0));
    let mgr = EpochManager::new(&attester, 3).expect("attest");
    let pk_before = mgr.epoch_public();
    let first = mgr.attestation();

    mgr.refresh_attestation(&attester).expect("refresh");
    let second = mgr.attestation();

    assert_eq!(mgr.epoch(), 3);
    assert_eq!(mgr.epoch_public(), pk_before); // same key
    assert_ne!(first, second); // fresh evidence
                               // Both bundles still bind the same report_data (last 64 bytes).
    assert_eq!(first[first.len() - 64..], second[second.len() - 64..]);
    assert_eq!(&second[second.len() - 64..], report_data_for(3, &pk_before));
}

#[test]
fn epoch_manager_rotate_changes_key_and_epoch() {
    let attester = CountingAttester(AtomicU64::new(0));
    let mgr = EpochManager::new(&attester, 1).expect("attest");
    let pk_old = mgr.epoch_public();

    mgr.rotate(&attester, 2).expect("rotate");
    assert_eq!(mgr.epoch(), 2);
    assert_ne!(mgr.epoch_public(), pk_old);

    // A handshake under the new key verifies against the new public key.
    let sid = b"sid";
    let nonce_c = b"n";
    let (pending, handshake) = mgr.begin_session(sid, nonce_c);
    let (enc, mut c2s, _) =
        client_establish(&mgr.epoch_public(), sid, nonce_c, &handshake).expect("client");
    let (mut e_c2s, _) = enclave_complete(pending, &enc).expect("complete");
    let ct = c2s.seal(sid, b"ok").unwrap();
    assert_eq!(e_c2s.open(sid, &ct).unwrap(), b"ok");

    // Old public key must not verify the new handshake.
    assert!(matches!(
        client_establish(&pk_old, sid, nonce_c, &handshake),
        Err(AkxError::BadSignature)
    ));
}
