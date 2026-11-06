//! Phase 2 of the attested channel (issue #15): the session handshake routes.
//!
//! Two-message handshake (two-tier model, `docs/tls-channel-binding.md` §6.1):
//!
//! - `POST /session`          — `ClientHello { sid, nonce_c }` → `{ enclaveSessionPub, signature }`.
//!   The enclave mints a fresh ephemeral key, signs the transcript with the
//!   epoch key, and stores the pending session.
//! - `POST /session/complete` — `{ sid, enc }` → `204`. The client's HPKE
//!   encapsulated key completes the handshake; directional record keys are
//!   derived and stored for the `/proxy` record layer (Phase 3).
//!
//! All binary fields are base64-encoded JSON. The cryptography and session
//! bookkeeping live in the (unit-tested) `akx` crate.

use std::sync::Arc;

use akx::{EpochManager, SessionError, SessionStore};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

/// Cap on `sid` length (bytes). Client reference uses 16; keep headroom without
/// letting a 2 MiB body become a HashMap key.
const MAX_SID_LEN: usize = 32;
/// Cap on `nonce_c` length (bytes). Client reference uses 32.
const MAX_NONCE_C_LEN: usize = 64;

/// `ClientHello` request body.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionHelloRequest {
    #[serde(with = "crate::base64")]
    sid: Vec<u8>,
    #[serde(with = "crate::base64")]
    nonce_c: Vec<u8>,
}

/// `ServerHello` response body.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionHelloResponse {
    #[serde(with = "crate::base64")]
    enclave_session_pub: Vec<u8>,
    #[serde(with = "crate::base64")]
    signature: Vec<u8>,
}

/// Handshake-completion request body.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionCompleteRequest {
    #[serde(with = "crate::base64")]
    sid: Vec<u8>,
    #[serde(with = "crate::base64")]
    enc: Vec<u8>,
}

/// `POST /session` — begin a session and return the epoch-signed handshake.
pub async fn post_session(
    State(epoch): State<Arc<EpochManager>>,
    State(sessions): State<Arc<SessionStore>>,
    Json(req): Json<SessionHelloRequest>,
) -> Result<Json<SessionHelloResponse>, SessionRouteError> {
    validate_sid(&req.sid)?;
    if req.nonce_c.is_empty() || req.nonce_c.len() > MAX_NONCE_C_LEN {
        return Err(SessionRouteError::BadRequest(format!(
            "nonce_c must be 1..={MAX_NONCE_C_LEN} bytes"
        )));
    }
    let (pending, handshake) = epoch.begin_session(&req.sid, &req.nonce_c);
    sessions.insert_pending(req.sid, pending)?;
    Ok(Json(SessionHelloResponse {
        enclave_session_pub: handshake.enclave_session_pub,
        signature: handshake.signature.to_vec(),
    }))
}

/// `POST /session/complete` — finish the handshake with the client's `enc`.
pub async fn post_session_complete(
    State(sessions): State<Arc<SessionStore>>,
    Json(req): Json<SessionCompleteRequest>,
) -> Result<StatusCode, SessionRouteError> {
    validate_sid(&req.sid)?;
    sessions.complete(&req.sid, &req.enc)?;
    Ok(StatusCode::NO_CONTENT)
}

fn validate_sid(sid: &[u8]) -> Result<(), SessionRouteError> {
    if sid.is_empty() || sid.len() > MAX_SID_LEN {
        return Err(SessionRouteError::BadRequest(format!(
            "sid must be 1..={MAX_SID_LEN} bytes"
        )));
    }
    Ok(())
}

/// Maps [`SessionError`] (or a route-level validation failure) to an HTTP response.
pub enum SessionRouteError {
    Store(SessionError),
    BadRequest(String),
}

impl From<SessionError> for SessionRouteError {
    fn from(err: SessionError) -> Self {
        Self::Store(err)
    }
}

impl IntoResponse for SessionRouteError {
    fn into_response(self) -> Response {
        match self {
            SessionRouteError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg).into_response(),
            SessionRouteError::Store(err) => {
                let status = match &err {
                    SessionError::Duplicate | SessionError::WrongState => StatusCode::CONFLICT,
                    SessionError::Full => StatusCode::SERVICE_UNAVAILABLE,
                    SessionError::NotFound => StatusCode::NOT_FOUND,
                    // A completion failure is a client/protocol error (bad `enc`, etc.).
                    SessionError::Akx(_) => StatusCode::BAD_REQUEST,
                };
                (status, err.to_string()).into_response()
            }
        }
    }
}
