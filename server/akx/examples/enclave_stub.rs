//! Interop test harness: a line-oriented stdin/stdout "enclave" built on the
//! `akx` public API. It exists so the Python reference client
//! (`cli/veritee/attested_channel.py`) can be exercised **end to end
//! against the real Rust crypto off-CVM**, where the production server
//! (`azure_attestation_server`) cannot build (it needs `tss-esapi`).
//!
//! Protocol: one JSON object per line.
//!
//! - On start the stub prints `{ epoch, epochPublic, attestation }` (the
//!   `GET /enclave-key` payload; the attestation is the deterministic
//!   `FakeAttester` bundle).
//! - `{ "cmd": "session",  "sid", "nonceC" }` → `{ enclaveSessionPub, signature }`
//! - `{ "cmd": "complete", "sid", "enc" }`    → `{ ok: true }`
//! - `{ "cmd": "proxy",    "sid", "ciphertext" }` → `{ ciphertext }`
//!   (stub upstream accepts the Phase 7 HTTP tunnel envelope)
//! - `{ "cmd": "vectors" }` → deterministic cross-impl vectors
//!
//! All binary fields are standard base64.

use std::collections::HashMap;
use std::io::{self, BufRead, Write};

use akx::{enclave_complete, EnclavePending, EpochManager, FakeAttester, RecordKey};
use base64::prelude::{Engine as _, BASE64_STANDARD};
use serde_json::{json, Value};

fn b64d(v: &Value, key: &str) -> Vec<u8> {
    BASE64_STANDARD
        .decode(v[key].as_str().expect("string field"))
        .expect("valid base64")
}

fn b64s(value: &Value) -> Vec<u8> {
    BASE64_STANDARD
        .decode(value.as_str().expect("string field"))
        .expect("valid base64")
}

fn main() {
    let mgr = EpochManager::new(&FakeAttester, 1).expect("attest");

    let stdout = io::stdout();
    let mut out = stdout.lock();

    // Announce the epoch key (stands in for GET /enclave-key).
    let hello = json!({
        "epoch": mgr.epoch(),
        "epochPublic": BASE64_STANDARD.encode(mgr.epoch_public()),
        "attestation": BASE64_STANDARD.encode(mgr.attestation()),
    });
    writeln!(out, "{hello}").unwrap();
    out.flush().unwrap();

    let mut pending: HashMap<Vec<u8>, EnclavePending> = HashMap::new();
    let mut records: HashMap<Vec<u8>, (RecordKey, RecordKey)> = HashMap::new();

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        if line.trim().is_empty() {
            continue;
        }
        let req: Value = serde_json::from_str(&line).expect("valid json");
        let resp = match req["cmd"].as_str().unwrap_or("") {
            "session" => {
                let sid = b64d(&req, "sid");
                let nonce_c = b64d(&req, "nonceC");
                let (pend, hs) = mgr.begin_session(&sid, &nonce_c);
                pending.insert(sid, pend);
                json!({
                    "enclaveSessionPub": BASE64_STANDARD.encode(&hs.enclave_session_pub),
                    "signature": BASE64_STANDARD.encode(hs.signature),
                })
            }
            "complete" => {
                let sid = b64d(&req, "sid");
                let enc = b64d(&req, "enc");
                let pend = pending.remove(&sid).expect("pending session");
                match enclave_complete(pend, &enc) {
                    Ok((c2s, s2c)) => {
                        records.insert(sid, (c2s, s2c));
                        json!({ "ok": true })
                    }
                    Err(e) => json!({ "error": e.to_string() }),
                }
            }
            "proxy" => {
                let sid = b64d(&req, "sid");
                let ct = b64d(&req, "ciphertext");
                let (c2s, s2c) = records.get_mut(&sid).expect("established session");
                match c2s.open(&sid, &ct) {
                    Ok(pt) => {
                        let env: Value = serde_json::from_slice(&pt).expect("tunnel request");
                        assert_eq!(env["version"].as_u64(), Some(1));
                        let request = &env["request"];
                        let method = request["method"].as_str().expect("method");
                        let path = request["path"].as_str().expect("path");
                        let mut body = b64s(&request["body"]);
                        let status = if path == "/error" { 400 } else { 200 };
                        let content_type = request["headers"]["content-type"]
                            .as_str()
                            .unwrap_or("application/octet-stream");
                        if path == "/prove" {
                            body.push(0xAA); // historical stub behavior
                        } else {
                            body = format!("{method} {path}").into_bytes();
                        }
                        let response = json!({
                            "version": 1,
                            "response": {
                                "status": status,
                                "headers": { "content-type": content_type },
                                "body": BASE64_STANDARD.encode(body),
                            }
                        });
                        let sealed = s2c
                            .seal(&sid, serde_json::to_string(&response).unwrap().as_bytes())
                            .expect("seal");
                        json!({ "ciphertext": BASE64_STANDARD.encode(sealed) })
                    }
                    Err(e) => json!({ "error": e.to_string() }),
                }
            }
            "vectors" => {
                let sid = b"vec-sid";
                let nonce_c = b"vec-nonce";
                let sess_pub = b"vec-enclave-session-public-key!!"; // 32 bytes
                let th = akx::transcript_hash(sid, nonce_c, sess_pub);
                let epoch_pub = [7u8; 32];
                let rd = akx::report_data_for(42, &epoch_pub);
                json!({
                    "transcriptHash": BASE64_STANDARD.encode(th),
                    "reportData": BASE64_STANDARD.encode(rd),
                })
            }
            other => json!({ "error": format!("unknown cmd {other}") }),
        };
        writeln!(out, "{resp}").unwrap();
        out.flush().unwrap();
    }
}
