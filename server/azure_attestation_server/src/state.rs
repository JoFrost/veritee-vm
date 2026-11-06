//! Shared Axum application state.
//!
//! Bundles the (cached) epoch key/attestation, the session store, the DApp
//! upstream, and per-session `/proxy` flight gates. The `FromRef` impls let
//! handlers extract just the sub-state they need via
//! `State<Arc<EpochManager>>` / `State<Arc<SessionStore>>` /
//! `State<DappUpstream>` / `State<Arc<ProxyGates>>`.

use std::sync::Arc;

use akx::{EpochManager, SessionStore};
use axum::extract::FromRef;

use crate::proxy_routes::{DappUpstream, ProxyGates};

#[derive(Clone)]
pub struct AppState {
    pub epoch: Arc<EpochManager>,
    pub sessions: Arc<SessionStore>,
    pub upstream: DappUpstream,
    pub proxy_gates: Arc<ProxyGates>,
}

impl FromRef<AppState> for Arc<EpochManager> {
    fn from_ref(state: &AppState) -> Self {
        state.epoch.clone()
    }
}

impl FromRef<AppState> for Arc<SessionStore> {
    fn from_ref(state: &AppState) -> Self {
        state.sessions.clone()
    }
}

impl FromRef<AppState> for DappUpstream {
    fn from_ref(state: &AppState) -> Self {
        state.upstream.clone()
    }
}

impl FromRef<AppState> for Arc<ProxyGates> {
    fn from_ref(state: &AppState) -> Self {
        state.proxy_gates.clone()
    }
}
