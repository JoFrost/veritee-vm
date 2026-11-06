"""Reference client for the Veritee attested channel (issue #15).

This is the Python counterpart of the Rust ``akx`` crate. It implements the
**client** side of the two-tier attested key-exchange described in
``docs/tls-channel-binding.md`` §6.1 and ``docs/attested-channel-implementation-plan.md``:

1. fetch the attested epoch key (``GET /enclave-key``) and have its attestation
   verified — **verification is delegated to Warden** (see :func:`make_warden_verifier`);
2. run the per-session handshake (``POST /session`` / ``/session/complete``):
   verify the epoch signature over the transcript, then HPKE-encapsulate to the
   enclave's fresh session key;
3. tunnel application traffic as AEAD records (``POST /proxy``).

The cryptography deliberately uses only primitives available in WebCrypto
(X25519, HKDF-SHA256, AES-256-GCM, Ed25519, SHA-256) so the Chromium extension
can reuse this exact protocol. HPKE (RFC 9180, mode Base,
``DHKEM(X25519, HKDF-SHA256)`` / ``HKDF-SHA256`` / ``AES-256-GCM``) is spelled
out here rather than pulled from a library so the reference is self-contained and
auditable.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from typing import Callable, Mapping, Optional, Protocol, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# ---------------------------------------------------------------------------
# Protocol constants — MUST match the Rust `akx` crate byte-for-byte.
# ---------------------------------------------------------------------------

#: Domain-separation label (``akx::transcript::LABEL``).
LABEL = b"temenos-akx-v1"
#: Exporter contexts for the two directional record keys (``akx::session``).
EXPORT_C2S = b"temenos-akx-v1 c2s"
EXPORT_S2C = b"temenos-akx-v1 s2c"
#: Record direction tags (``akx::record``).
DIR_C2S = 0x01
DIR_S2C = 0x02
#: Fake-attester bundle prefix (``akx::attest::FAKE_ATTESTATION_PREFIX``), used
#: only by the off-CVM interop tests.
FAKE_ATTESTATION_PREFIX = b"FAKE"


class ProtocolError(Exception):
    """Raised when the enclave's handshake fails verification / decryption."""


# ---------------------------------------------------------------------------
# Transcript hashing and report_data binding (mirror of `akx::transcript`,
# `akx::epoch`).
# ---------------------------------------------------------------------------


def _absorb(hasher: "hashlib._Hash", field: bytes) -> None:
    hasher.update(len(field).to_bytes(8, "big"))
    hasher.update(field)


def transcript_hash(sid: bytes, nonce_c: bytes, enclave_session_pub: bytes) -> bytes:
    """Domain-separated, length-prefixed transcript hash (32 bytes)."""
    h = hashlib.sha256()
    _absorb(h, LABEL)
    _absorb(h, sid)
    _absorb(h, nonce_c)
    _absorb(h, enclave_session_pub)
    return h.digest()


def report_data_for(epoch: int, epoch_pub: bytes) -> bytes:
    """The 64-byte ``report_data`` binding an epoch key (digest || zero-pad)."""
    if len(epoch_pub) != 32:
        raise ValueError("epoch_pub must be 32 bytes")
    h = hashlib.sha256()
    h.update(LABEL)
    h.update(b"epoch")
    h.update(epoch.to_bytes(8, "big"))
    h.update(epoch_pub)
    return h.digest() + bytes(32)


def verify_epoch_sig(epoch_pub: bytes, msg: bytes, sig: bytes) -> None:
    """Verify an Ed25519 epoch signature; raise :class:`ProtocolError` on failure."""
    try:
        Ed25519PublicKey.from_public_bytes(epoch_pub).verify(sig, msg)
    except Exception as exc:  # cryptography raises InvalidSignature / ValueError
        raise ProtocolError("epoch signature verification failed") from exc


# ---------------------------------------------------------------------------
# HPKE (RFC 9180) — sender + secret export only.
# ---------------------------------------------------------------------------

_KEM_ID = 0x0020  # DHKEM(X25519, HKDF-SHA256)
_KDF_ID = 0x0001  # HKDF-SHA256
_AEAD_ID = 0x0002  # AES-256-GCM
_NSECRET = 32
_NH = 32

_SUITE_ID = (
    b"HPKE"
    + _KEM_ID.to_bytes(2, "big")
    + _KDF_ID.to_bytes(2, "big")
    + _AEAD_ID.to_bytes(2, "big")
)
_KEM_SUITE_ID = b"KEM" + _KEM_ID.to_bytes(2, "big")


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def _labeled_extract(salt: bytes, suite_id: bytes, label: bytes, ikm: bytes) -> bytes:
    return _hkdf_extract(salt, b"HPKE-v1" + suite_id + label + ikm)


def _labeled_expand(
    prk: bytes, suite_id: bytes, label: bytes, info: bytes, length: int
) -> bytes:
    labeled_info = length.to_bytes(2, "big") + b"HPKE-v1" + suite_id + label + info
    return _hkdf_expand(prk, labeled_info, length)


def _dhkem_encap(pk_r_bytes: bytes, sk_e: Optional[X25519PrivateKey]) -> tuple[bytes, bytes]:
    if sk_e is None:
        sk_e = X25519PrivateKey.generate()
    enc = _public_bytes_raw(sk_e.public_key())
    pk_r = X25519PublicKey.from_public_bytes(pk_r_bytes)
    dh = sk_e.exchange(pk_r)
    kem_context = enc + pk_r_bytes
    eae_prk = _labeled_extract(b"", _KEM_SUITE_ID, b"eae_prk", dh)
    shared_secret = _labeled_expand(
        eae_prk, _KEM_SUITE_ID, b"shared_secret", kem_context, _NSECRET
    )
    return shared_secret, enc


def _public_bytes_raw(public_key) -> bytes:
    public_bytes_raw = getattr(public_key, "public_bytes_raw", None)
    if public_bytes_raw is not None:
        return public_bytes_raw()
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def hpke_setup_base_s(
    pk_r_bytes: bytes, info: bytes, sk_e: Optional[X25519PrivateKey] = None
) -> tuple[bytes, bytes]:
    """HPKE ``SetupBaseS``. Returns ``(enc, exporter_secret)``.

    ``sk_e`` is injectable for known-answer (RFC 9180) testing; production callers
    leave it ``None`` so a fresh ephemeral key is generated (forward secrecy).
    """
    shared_secret, enc = _dhkem_encap(pk_r_bytes, sk_e)
    # Key schedule, mode_base = 0x00, empty psk / psk_id.
    psk_id_hash = _labeled_extract(b"", _SUITE_ID, b"psk_id_hash", b"")
    info_hash = _labeled_extract(b"", _SUITE_ID, b"info_hash", info)
    ks_context = bytes([0x00]) + psk_id_hash + info_hash
    secret = _labeled_extract(shared_secret, _SUITE_ID, b"secret", b"")
    exporter_secret = _labeled_expand(secret, _SUITE_ID, b"exp", ks_context, _NH)
    return enc, exporter_secret


def hpke_export(exporter_secret: bytes, context: bytes, length: int) -> bytes:
    """HPKE secret export (``context.export``)."""
    return _labeled_expand(exporter_secret, _SUITE_ID, b"sec", context, length)


# ---------------------------------------------------------------------------
# Directional AEAD record layer (mirror of `akx::record`).
# ---------------------------------------------------------------------------


class RecordKey:
    """One direction of an established channel (AES-256-GCM, monotonic seq)."""

    def __init__(self, key: bytes, direction: int) -> None:
        if len(key) != 32:
            raise ValueError("record key must be 32 bytes")
        self._aead = AESGCM(key)
        self._dir = direction
        self._seq = 0

    def _next_nonce(self) -> bytes:
        # dir(1) || 0x000000 || seq_be(8)
        nonce = bytes([self._dir]) + b"\x00\x00\x00" + self._seq.to_bytes(8, "big")
        self._seq += 1
        return nonce

    def seal(self, aad: bytes, plaintext: bytes) -> bytes:
        return self._aead.encrypt(self._next_nonce(), plaintext, aad)

    def open(self, aad: bytes, ciphertext: bytes) -> bytes:
        try:
            return self._aead.decrypt(self._next_nonce(), ciphertext, aad)
        except Exception as exc:
            raise ProtocolError("record authentication failed") from exc

    @property
    def seq(self) -> int:
        return self._seq


# ---------------------------------------------------------------------------
# Transport + client
# ---------------------------------------------------------------------------


@dataclass
class EnclaveKey:
    epoch: int
    epoch_public: bytes
    attestation: bytes


@dataclass
class Handshake:
    enclave_session_pub: bytes
    signature: bytes


class Transport(Protocol):
    """Abstracts the four attested-channel endpoints (HTTP in production; a
    subprocess in the off-CVM interop tests)."""

    def get_enclave_key(self) -> EnclaveKey: ...
    def post_session(self, sid: bytes, nonce_c: bytes) -> Handshake: ...
    def post_session_complete(self, sid: bytes, enc: bytes) -> None: ...
    def post_proxy(self, sid: bytes, ciphertext: bytes) -> bytes: ...


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data)


class HttpTransport:
    """HTTP transport for a live attestation server (base64-JSON wire format)."""

    def __init__(self, base_url: str, session=None, timeout: float = 30.0) -> None:
        import requests  # local import so the crypto core has no hard HTTP dep

        self._base = base_url.rstrip("/")
        self._http = session or requests.Session()
        self._timeout = timeout

    def get_enclave_key(self) -> EnclaveKey:
        r = self._http.get(f"{self._base}/enclave-key", timeout=self._timeout)
        r.raise_for_status()
        body = r.json()
        return EnclaveKey(
            epoch=int(body["epoch"]),
            epoch_public=_b64d(body["epochPublic"]),
            attestation=_b64d(body["attestation"]),
        )

    def post_session(self, sid: bytes, nonce_c: bytes) -> Handshake:
        r = self._http.post(
            f"{self._base}/session",
            json={"sid": _b64e(sid), "nonceC": _b64e(nonce_c)},
            timeout=self._timeout,
        )
        r.raise_for_status()
        body = r.json()
        return Handshake(
            enclave_session_pub=_b64d(body["enclaveSessionPub"]),
            signature=_b64d(body["signature"]),
        )

    def post_session_complete(self, sid: bytes, enc: bytes) -> None:
        r = self._http.post(
            f"{self._base}/session/complete",
            json={"sid": _b64e(sid), "enc": _b64e(enc)},
            timeout=self._timeout,
        )
        r.raise_for_status()

    def post_proxy(self, sid: bytes, ciphertext: bytes) -> bytes:
        r = self._http.post(
            f"{self._base}/proxy",
            json={"sid": _b64e(sid), "ciphertext": _b64e(ciphertext)},
            timeout=self._timeout,
        )
        r.raise_for_status()
        return _b64d(r.json()["ciphertext"])


#: A verifier is called with the fetched enclave key and must raise if the
#: attestation does not bind ``epoch_public`` at ``epoch``. Verification is
#: delegated to Warden in production (see :func:`make_warden_verifier`).
AttestationVerifier = Callable[[EnclaveKey], None]


def make_warden_verifier(
    endpoint: str,
    dapp_id: str,
    payload=None,
    session=None,
    timeout: float = 30.0,
    *,
    expected_application_id: str | None = None,
) -> AttestationVerifier:
    """Build a verifier that delegates to Warden's ``/dapps/verify_attestation``.

    The enclave attestation bytes are the JSON ``ResponseStruct`` returned by the
    attestation server; we forward it verbatim as ``tee_attestation`` and let
    Warden verifies the exact nonce and payload attested by the OS. The payload
    is recomputed from ``epoch`` and ``epoch_public``. The ``payload`` argument
    remains accepted for caller compatibility.
    """
    import json as _json

    import requests

    http = session or requests.Session()

    def verify(ek: EnclaveKey) -> None:
        tee_attestation = _json.loads(ek.attestation.decode("utf-8"))
        request_payload = {
            "dapp_id": dapp_id,
            "tee_attestation": tee_attestation,
            "nonce": "temenos-akx-v1-epoch",
            "payload": _b64e(report_data_for(ek.epoch, ek.epoch_public)),
        }
        if expected_application_id is not None:
            request_payload["expected_application_id"] = expected_application_id
        r = http.post(endpoint, json=request_payload, timeout=timeout)
        if not r.ok:
            raise ProtocolError(f"Warden rejected attestation: {r.status_code} {r.text}")
        try:
            approved = r.json().get("verified") is True
        except (ValueError, AttributeError):
            approved = False
        if not approved:
            raise ProtocolError("Warden returned no attestation approval")

    return verify


@dataclass
class Session:
    sid: bytes
    epoch: int
    _c2s: RecordKey
    _s2c: RecordKey


@dataclass
class HttpTunnelResponse:
    status: int
    headers: dict[str, str]
    body: bytes

    def raise_for_status(self) -> None:
        """Reject upstream application errors without invalidating the session."""
        if not 200 <= self.status < 300:
            raise UpstreamHttpError(self)


class UpstreamHttpError(Exception):
    """An authenticated upstream response with a non-success HTTP status."""

    def __init__(self, response: HttpTunnelResponse) -> None:
        self.response = response
        super().__init__(f"DApp returned HTTP {response.status}")


class EpochKeyCache:
    """Client-side cache of the attested epoch key (Phase 6 polling).

    Call :meth:`get` (or :meth:`refresh`) before establishing sessions so the
    ~3 s attestation cost is paid out of band. The cache is invalidated when the
    server rotates to a new epoch (different ``epoch`` / ``epoch_public``).
    """

    def __init__(self, transport: Transport, verifier: Optional[AttestationVerifier] = None) -> None:
        self._t = transport
        self._verifier = verifier
        self._cached: Optional[EnclaveKey] = None

    def get(self, *, force: bool = False) -> EnclaveKey:
        if force or self._cached is None:
            return self.refresh()
        return self._cached

    def refresh(self) -> EnclaveKey:
        ek = self._t.get_enclave_key()
        if self._verifier is not None:
            self._verifier(ek)
        self._cached = ek
        return ek


class AttestedChannelClient:
    """Drives the attested-channel handshake and record layer over a transport."""

    def __init__(
        self,
        transport: Transport,
        verifier: Optional[AttestationVerifier] = None,
        epoch_cache: Optional[EpochKeyCache] = None,
    ) -> None:
        self._t = transport
        self._verifier = verifier
        self._epoch_cache = epoch_cache or EpochKeyCache(transport, verifier)

    def create_session(self) -> Session:
        # Prefer a pre-polled / cached epoch key so attestation latency is hidden.
        ek = self._epoch_cache.get()

        sid = os.urandom(16)
        nonce_c = os.urandom(32)
        hs = self._t.post_session(sid, nonce_c)

        # Authenticate the enclave's session key via the epoch signature over the
        # transcript recomputed from *our own* sid/nonce. If the server rotated
        # the epoch since we last polled, refresh the cache and retry once.
        transcript = transcript_hash(sid, nonce_c, hs.enclave_session_pub)
        try:
            verify_epoch_sig(ek.epoch_public, transcript, hs.signature)
        except ProtocolError:
            ek = self._epoch_cache.refresh()
            verify_epoch_sig(ek.epoch_public, transcript, hs.signature)

        enc, exporter_secret = hpke_setup_base_s(hs.enclave_session_pub, transcript)
        k_c2s = hpke_export(exporter_secret, EXPORT_C2S, 32)
        k_s2c = hpke_export(exporter_secret, EXPORT_S2C, 32)

        self._t.post_session_complete(sid, enc)
        return Session(sid=sid, epoch=ek.epoch, _c2s=RecordKey(k_c2s, DIR_C2S), _s2c=RecordKey(k_s2c, DIR_S2C))

    def request(
        self,
        session: Session,
        method: str,
        path: str,
        body: bytes = b"",
        *,
        query: Optional[Sequence[tuple[str, str]]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> HttpTunnelResponse:
        """Send an HTTP-shaped request through the attested channel.

        The outer transport remains ``POST /proxy``. The encrypted record is a
        versioned tunnel envelope carrying the upstream method, path, encrypted
        query values / arguments, allowlisted headers, and body. The decrypted
        response contains the upstream status, allowlisted response headers, and
        body.
        """
        envelope = {
            "version": 1,
            "request": {
                "method": method.upper(),
                "path": path,
                "query": list(query or []),
                "headers": {k.lower(): v for k, v in (headers or {}).items()},
                "body": _b64e(body),
            },
        }
        plaintext = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        ciphertext = session._c2s.seal(session.sid, plaintext)
        response_ct = self._t.post_proxy(session.sid, ciphertext)
        response_plaintext = session._s2c.open(session.sid, response_ct)
        try:
            response_envelope = json.loads(response_plaintext.decode("utf-8"))
            if response_envelope.get("version") != 1:
                raise ValueError("unsupported tunnel response version")
            response = response_envelope["response"]
            return HttpTunnelResponse(
                status=int(response["status"]),
                headers={str(k).lower(): str(v) for k, v in response.get("headers", {}).items()},
                body=_b64d(response.get("body", "")),
            )
        except Exception as exc:
            raise ProtocolError("malformed tunnel response") from exc

    def prove(self, session: Session, request: bytes) -> bytes:
        """Compatibility wrapper for proof-server ``POST /prove`` callers."""
        response = self.request(
            session,
            "POST",
            "/prove",
            request,
            headers={"content-type": "application/octet-stream"},
        )
        response.raise_for_status()
        return response.body
