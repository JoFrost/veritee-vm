//! In-memory session store for the attested channel.
//!
//! Tracks per-`sid` session state through its lifecycle:
//!
//! ```text
//!   insert_pending ──▶ Pending ──complete──▶ Established ──(TTL/remove)──▶ gone
//! ```
//!
//! A `Pending` entry holds the enclave's secret handshake state between
//! `ClientHello` and the client's HPKE encapsulation; an `Established` entry
//! holds the two directional record keys used by the `/proxy` record layer
//! (Phase 3). The store is internally synchronized (`Mutex`) so it can be shared
//! as `Arc<SessionStore>` across Axum handlers, and enforces a TTL and a
//! maximum session count to bound memory and mitigate setup-flood DoS (§7 A8).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::record::RecordKey;
use crate::session::{enclave_complete, EnclavePending};
use crate::AkxError;

/// Errors from session-store operations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SessionError {
    #[error("session id already exists")]
    Duplicate,
    #[error("session capacity reached")]
    Full,
    #[error("session not found")]
    NotFound,
    #[error("session is not in the expected state")]
    WrongState,
    #[error(transparent)]
    Akx(#[from] AkxError),
}

/// Tunables for the session store.
#[derive(Clone, Copy, Debug)]
pub struct SessionConfig {
    /// Maximum age of an entry before it is evicted.
    pub ttl: Duration,
    /// Hard cap on the number of concurrent sessions.
    pub max_sessions: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(300),
            max_sessions: 10_000,
        }
    }
}

/// The two directional record keys of an established session. Boxed inside
/// [`Entry`] so a pending entry (the common, transient case) stays small.
struct SessionKeys {
    c2s: RecordKey,
    s2c: RecordKey,
}

enum Entry {
    Pending {
        pending: EnclavePending,
        created: Instant,
    },
    Established {
        keys: Box<SessionKeys>,
        created: Instant,
    },
}

impl Entry {
    fn created(&self) -> Instant {
        match self {
            Entry::Pending { created, .. } | Entry::Established { created, .. } => *created,
        }
    }
}

/// Concurrent, TTL-bounded store of channel sessions keyed by `sid`.
pub struct SessionStore {
    inner: Mutex<HashMap<Vec<u8>, Entry>>,
    config: SessionConfig,
}

impl SessionStore {
    pub fn new(config: SessionConfig) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            config,
        }
    }

    /// Register the enclave's pending handshake state for a new `sid`.
    ///
    /// Evicts expired entries first, then rejects a duplicate `sid` (so a
    /// client cannot clobber another session) or a store at capacity.
    pub fn insert_pending(
        &self,
        sid: Vec<u8>,
        pending: EnclavePending,
    ) -> Result<(), SessionError> {
        let mut map = self.inner.lock().expect("session store poisoned");
        evict_expired(&mut map, self.config.ttl);

        if map.contains_key(&sid) {
            return Err(SessionError::Duplicate);
        }
        if map.len() >= self.config.max_sessions {
            return Err(SessionError::Full);
        }
        map.insert(
            sid,
            Entry::Pending {
                pending,
                created: Instant::now(),
            },
        );
        Ok(())
    }

    /// Complete a pending handshake with the client's HPKE encapsulated key,
    /// deriving and storing the directional record keys.
    ///
    /// On success the entry transitions `Pending → Established`. If the entry is
    /// missing → `NotFound`; if already established → `WrongState` (and it is
    /// left intact). A cryptographic failure drops the pending session.
    pub fn complete(&self, sid: &[u8], enc: &[u8]) -> Result<(), SessionError> {
        let mut map = self.inner.lock().expect("session store poisoned");
        evict_expired(&mut map, self.config.ttl);
        let entry = map.remove(sid).ok_or(SessionError::NotFound)?;
        match entry {
            Entry::Pending { pending, .. } => {
                // If this fails, the pending entry is intentionally dropped.
                let (c2s, s2c) = enclave_complete(pending, enc)?;
                map.insert(
                    sid.to_vec(),
                    Entry::Established {
                        keys: Box::new(SessionKeys { c2s, s2c }),
                        created: Instant::now(),
                    },
                );
                Ok(())
            }
            other => {
                map.insert(sid.to_vec(), other);
                Err(SessionError::WrongState)
            }
        }
    }

    /// Return `Ok(())` if `sid` is an established (non-expired) session.
    /// Used by `/proxy` to reject early before taking a per-session flight lock.
    pub fn ensure_established(&self, sid: &[u8]) -> Result<(), SessionError> {
        let mut map = self.inner.lock().expect("session store poisoned");
        evict_expired(&mut map, self.config.ttl);
        match map.get(sid) {
            Some(Entry::Established { .. }) => Ok(()),
            Some(_) => Err(SessionError::WrongState),
            None => Err(SessionError::NotFound),
        }
    }

    /// Run `f` against the directional record keys of an established session.
    /// Used by the `/proxy` record layer (Phase 3). Returns `WrongState` if the
    /// session exists but is still pending, `NotFound` if absent.
    pub fn with_records<F, R>(&self, sid: &[u8], f: F) -> Result<R, SessionError>
    where
        F: FnOnce(&mut RecordKey, &mut RecordKey) -> R,
    {
        let mut map = self.inner.lock().expect("session store poisoned");
        // Evict before use so TTL is not decorative for `/proxy` (which never
        // calls `insert_pending`).
        evict_expired(&mut map, self.config.ttl);
        match map.get_mut(sid) {
            Some(Entry::Established { keys, .. }) => Ok(f(&mut keys.c2s, &mut keys.s2c)),
            Some(_) => Err(SessionError::WrongState),
            None => Err(SessionError::NotFound),
        }
    }

    /// Remove a session regardless of state. Returns whether one was present.
    pub fn remove(&self, sid: &[u8]) -> bool {
        self.inner
            .lock()
            .expect("session store poisoned")
            .remove(sid)
            .is_some()
    }

    /// Evict all entries older than the configured TTL.
    pub fn evict_expired(&self) {
        let mut map = self.inner.lock().expect("session store poisoned");
        evict_expired(&mut map, self.config.ttl);
    }

    /// Current number of tracked sessions (pending + established).
    pub fn len(&self) -> usize {
        self.inner.lock().expect("session store poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn evict_expired(map: &mut HashMap<Vec<u8>, Entry>, ttl: Duration) {
    let now = Instant::now();
    map.retain(|_, entry| now.duration_since(entry.created()) < ttl);
}
