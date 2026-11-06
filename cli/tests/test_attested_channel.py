"""Tests for the Python attested-channel client (`temenos.attested_channel`).

Two layers:

1. **Unit / cross-impl vectors** — transcript hash, report_data, record layer,
   and HPKE self-consistency. The transcript / report_data vectors are captured
   from the Rust `akx` crate (`cargo run --example enclave_stub -- vectors`) so a
   drift between the Python and Rust byte layouts is caught here.

2. **End-to-end interop** — the client runs the full `create_session` + HTTP tunnel
   flow against the real Rust crypto via the `akx` `enclave_stub` example
   (spawned as a subprocess). This is the authoritative HPKE interop check: the
   proxied round-trip only succeeds if Python and Rust derive identical record
   keys.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

# Import the client module standalone (it only needs `cryptography`) rather than
# via the `temenos` package, whose __init__ pulls the full CLI dependency stack.
_VERITEE_DIR = Path(__file__).resolve().parents[1] / "veritee"
if str(_VERITEE_DIR) not in sys.path:
    sys.path.insert(0, str(_VERITEE_DIR))

import attested_channel as ac

REPO_ROOT = Path(__file__).resolve().parents[2]
AKX_DIR = REPO_ROOT / "server" / "akx"


def _stub_candidates():
    """Possible locations of the compiled `enclave_stub` example."""
    env_bin = os.environ.get("AKX_ENCLAVE_STUB")
    if env_bin:
        yield Path(env_bin)
    target = os.environ.get("CARGO_TARGET_DIR")
    if target:
        yield Path(target) / "debug" / "examples" / "enclave_stub"
    yield AKX_DIR / "target" / "debug" / "examples" / "enclave_stub"

# Deterministic vectors captured from `akx`'s enclave_stub `vectors` command.
VEC_SID = b"vec-sid"
VEC_NONCE = b"vec-nonce"
VEC_SESSION_PUB = b"vec-enclave-session-public-key!!"  # 32 bytes
VEC_TRANSCRIPT_B64 = "wO9wanpkZolFsJlOcTGiXy5htcNs5ND02mU+9gEB5ig="
VEC_EPOCH = 42
VEC_EPOCH_PUB = bytes([7] * 32)
VEC_REPORT_DATA_B64 = "DMhoVbav/EIG1PRdT2Ga9HHtO4UsBwvrN2+E4xdduysAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="


# ---------------------------------------------------------------------------
# Unit / cross-impl vectors
# ---------------------------------------------------------------------------


def test_transcript_hash_matches_rust_vector():
    got = ac.transcript_hash(VEC_SID, VEC_NONCE, VEC_SESSION_PUB)
    assert got == base64.b64decode(VEC_TRANSCRIPT_B64)


def test_report_data_matches_rust_vector():
    got = ac.report_data_for(VEC_EPOCH, VEC_EPOCH_PUB)
    assert got == base64.b64decode(VEC_REPORT_DATA_B64)
    assert len(got) == 64
    assert got[32:] == bytes(32)  # digest in first half, zero-padded


class _EpochBindingWarden:
    """Model Warden's checked nonce/payload fields with the Rust AKX vector."""

    def __init__(self, approval=True):
        self.approval = approval

    def post(self, endpoint, *, json, timeout):
        assert endpoint == "https://warden.example/dapps/verify_attestation"
        accepted = (
            json.get("nonce") == "temenos-akx-v1-epoch"
            and json.get("payload") == VEC_REPORT_DATA_B64
            and json.get("tee_attestation") == {"fixture": "signed-epoch-42"}
            and json.get("dapp_id") == "registered-proof-server"
        )
        approval = self.approval

        class Response:
            ok = accepted
            status_code = 200 if accepted else 400
            text = "epoch binding mismatch" if not accepted else ""

            def json(self):
                return {"verified": approval}

        return Response()


def _epoch_binding_key(epoch=VEC_EPOCH, public=VEC_EPOCH_PUB):
    return ac.EnclaveKey(epoch=epoch, epoch_public=public,
                         attestation=b'{"fixture":"signed-epoch-42"}')


def test_warden_verifier_uses_checked_epoch_binding_fields():
    verify = ac.make_warden_verifier(
        "https://warden.example/dapps/verify_attestation", "registered-proof-server",
        {"legacy-business-payload": "unbound"}, session=_EpochBindingWarden())
    verify(_epoch_binding_key())
    with pytest.raises(ac.ProtocolError, match="epoch binding mismatch"):
        verify(_epoch_binding_key(public=bytes([8] * 32)))
    with pytest.raises(ac.ProtocolError, match="epoch binding mismatch"):
        verify(_epoch_binding_key(epoch=VEC_EPOCH + 1))


def test_warden_verifier_requires_explicit_approval():
    verify = ac.make_warden_verifier(
        "https://warden.example/dapps/verify_attestation", "registered-proof-server",
        session=_EpochBindingWarden(approval=False))
    with pytest.raises(ac.ProtocolError, match="no attestation approval"):
        verify(_epoch_binding_key())


@pytest.mark.parametrize("expected", [None, "ab" * 32])
def test_warden_verifier_sends_optional_expected_application_id(expected):
    from unittest.mock import Mock

    server = Mock(wraps=_EpochBindingWarden())
    verify = ac.make_warden_verifier(
        "https://warden.example/dapps/verify_attestation", "registered-proof-server",
        session=server, expected_application_id=expected)
    verify(_epoch_binding_key())
    body = server.post.call_args.kwargs["json"]
    if expected is None:
        assert "expected_application_id" not in body
    else:
        assert body["expected_application_id"] == expected


def test_record_layer_roundtrip_and_nonce_layout():
    key = bytes(range(32))
    sender = ac.RecordKey(key, ac.DIR_C2S)
    receiver = ac.RecordKey(key, ac.DIR_C2S)
    aad = b"sid"

    for msg in (b"hello", b"", b"second message"):
        ct = sender.seal(aad, msg)
        assert receiver.open(aad, ct) == msg


def test_record_layer_rejects_tamper_and_wrong_aad():
    key = bytes(range(32))
    sender = ac.RecordKey(key, ac.DIR_C2S)
    receiver = ac.RecordKey(key, ac.DIR_C2S)

    ct = sender.seal(b"sid", b"payload")
    tampered = bytearray(ct)
    tampered[0] ^= 0x01
    with pytest.raises(ac.ProtocolError):
        receiver.open(b"sid", bytes(tampered))


def test_record_layer_direction_separation():
    key = bytes(range(32))
    c2s = ac.RecordKey(key, ac.DIR_C2S)
    s2c_open = ac.RecordKey(key, ac.DIR_S2C)
    ct = c2s.seal(b"sid", b"payload")
    with pytest.raises(ac.ProtocolError):
        s2c_open.open(b"sid", ct)  # different direction byte in the nonce


def test_hpke_export_is_deterministic_for_fixed_ephemeral():
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    pk_r = ac._public_bytes_raw(X25519PrivateKey.generate().public_key())
    sk_e = X25519PrivateKey.generate()
    info = b"info"

    enc1, exp1 = ac.hpke_setup_base_s(pk_r, info, sk_e=sk_e)
    enc2, exp2 = ac.hpke_setup_base_s(pk_r, info, sk_e=sk_e)
    assert enc1 == enc2
    assert exp1 == exp2
    # Distinct exporter contexts yield distinct keys.
    assert ac.hpke_export(exp1, ac.EXPORT_C2S, 32) != ac.hpke_export(exp1, ac.EXPORT_S2C, 32)


def test_verify_epoch_sig_accepts_valid_and_rejects_tampered():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.generate()
    pk = ac._public_bytes_raw(sk.public_key())
    msg = b"transcript"
    sig = sk.sign(msg)

    # Valid signature verifies.
    ac.verify_epoch_sig(pk, msg, sig)

    # Wrong message is rejected.
    with pytest.raises(ac.ProtocolError):
        ac.verify_epoch_sig(pk, b"other", sig)

    # Tampered signature is rejected.
    tampered = bytearray(sig)
    tampered[0] ^= 0x01
    with pytest.raises(ac.ProtocolError):
        ac.verify_epoch_sig(pk, msg, bytes(tampered))


# ---------------------------------------------------------------------------
# End-to-end interop against the real Rust `akx` crypto
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", [307, 400, 500])
def test_prove_rejects_upstream_errors_and_keeps_the_session_usable(status):
    sid = b"application-error-test"
    c2s_key, s2c_key = bytes(range(32)), bytes(reversed(range(32)))
    server_c2s = ac.RecordKey(c2s_key, ac.DIR_C2S)
    server_s2c = ac.RecordKey(s2c_key, ac.DIR_S2C)
    responses = iter([(status, b"upstream error"), (200, b"valid proof")])

    class Transport:
        def post_proxy(self, request_sid, ciphertext):
            request = json.loads(server_c2s.open(request_sid, ciphertext))
            assert request["request"]["path"] == "/prove"
            response_status, body = next(responses)
            return server_s2c.seal(request_sid, json.dumps({
                "version": 1,
                "response": {"status": response_status, "headers": {}, "body": _b64(body)},
            }).encode())

    client = ac.AttestedChannelClient(Transport())
    session = ac.Session(sid, 1, ac.RecordKey(c2s_key, ac.DIR_C2S), ac.RecordKey(s2c_key, ac.DIR_S2C))
    with pytest.raises(ac.UpstreamHttpError) as error:
        client.prove(session, b"request")
    assert error.value.response.status == status
    assert error.value.response.body == b"upstream error"
    assert not isinstance(error.value, ac.ProtocolError)
    assert client.prove(session, b"request") == b"valid proof"
    assert session._c2s.seq == session._s2c.seq == 2


def _ensure_stub() -> Path:
    """Return the path to the compiled `enclave_stub`, building it if needed.

    Skips the test if neither a prebuilt binary nor `cargo` is available.
    """
    for candidate in _stub_candidates():
        if candidate.exists():
            return candidate
    if shutil.which("cargo") is None:
        pytest.skip("cargo not available and no prebuilt enclave_stub")
    build = subprocess.run(
        ["cargo", "build", "--example", "enclave_stub"],
        cwd=AKX_DIR,
        capture_output=True,
        text=True,
    )
    if build.returncode != 0:
        pytest.skip(f"failed to build enclave_stub:\n{build.stderr}")
    for candidate in _stub_candidates():
        if candidate.exists():
            return candidate
    pytest.skip("enclave_stub not found after build")


class SubprocessTransport:
    """Drives the `akx` enclave_stub over stdin/stdout as a Transport."""

    def __init__(self, binary: Path) -> None:
        self._proc = subprocess.Popen(
            [str(binary)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            bufsize=1,
            text=True,
        )
        hello = json.loads(self._proc.stdout.readline())
        self._enclave_key = ac.EnclaveKey(
            epoch=int(hello["epoch"]),
            epoch_public=base64.b64decode(hello["epochPublic"]),
            attestation=base64.b64decode(hello["attestation"]),
        )

    def _rpc(self, obj: dict) -> dict:
        self._proc.stdin.write(json.dumps(obj) + "\n")
        self._proc.stdin.flush()
        return json.loads(self._proc.stdout.readline())

    def close(self) -> None:
        self._proc.stdin.close()
        self._proc.terminate()
        self._proc.wait(timeout=5)

    # Transport protocol
    def get_enclave_key(self) -> ac.EnclaveKey:
        return self._enclave_key

    def post_session(self, sid: bytes, nonce_c: bytes) -> ac.Handshake:
        resp = self._rpc(
            {"cmd": "session", "sid": _b64(sid), "nonceC": _b64(nonce_c)}
        )
        return ac.Handshake(
            enclave_session_pub=base64.b64decode(resp["enclaveSessionPub"]),
            signature=base64.b64decode(resp["signature"]),
        )

    def post_session_complete(self, sid: bytes, enc: bytes) -> None:
        resp = self._rpc({"cmd": "complete", "sid": _b64(sid), "enc": _b64(enc)})
        assert resp.get("ok") is True, resp

    def post_proxy(self, sid: bytes, ciphertext: bytes) -> bytes:
        resp = self._rpc(
            {"cmd": "proxy", "sid": _b64(sid), "ciphertext": _b64(ciphertext)}
        )
        assert "ciphertext" in resp, resp
        return base64.b64decode(resp["ciphertext"])


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _fake_attester_verifier(ek: ac.EnclaveKey) -> None:
    """Reproduce the FakeAttester bundle and check it binds the epoch key.

    Stands in for Warden in the off-CVM harness: `attestation` must equal
    ``b"FAKE" || report_data(epoch, epoch_public)``.
    """
    expected = ac.FAKE_ATTESTATION_PREFIX + ac.report_data_for(ek.epoch, ek.epoch_public)
    if ek.attestation != expected:
        raise ac.ProtocolError("fake attestation does not bind the epoch key")


@pytest.fixture()
def stub_transport():
    transport = SubprocessTransport(_ensure_stub())
    yield transport
    transport.close()


def test_epoch_key_cache_avoids_repeat_fetch(stub_transport):
    """Phase 6: a pre-polled cache should not re-fetch on every create_session."""
    fetches = {"n": 0}
    real_get = stub_transport.get_enclave_key

    def counting_get():
        fetches["n"] += 1
        return real_get()

    stub_transport.get_enclave_key = counting_get  # type: ignore[method-assign]
    cache = ac.EpochKeyCache(stub_transport, verifier=_fake_attester_verifier)
    cache.refresh()
    assert fetches["n"] == 1

    client = ac.AttestedChannelClient(
        stub_transport, verifier=_fake_attester_verifier, epoch_cache=cache
    )
    client.create_session()
    client.create_session()
    # Still a single fetch — both sessions reused the cached epoch key.
    assert fetches["n"] == 1


def test_end_to_end_interop_handshake_and_prove(stub_transport):
    client = ac.AttestedChannelClient(stub_transport, verifier=_fake_attester_verifier)
    session = client.create_session()

    # The stub upstream echoes /prove bodies with a trailing 0xAA marker.
    for request in (b"hello dapp", b"", b"another request", bytes(range(64))):
        response = client.prove(session, request)
        assert response == request + b"\xaa"


def test_end_to_end_http_tunnel_get_and_headers(stub_transport):
    client = ac.AttestedChannelClient(stub_transport, verifier=_fake_attester_verifier)
    session = client.create_session()

    response = client.request(
        session,
        "GET",
        "/check",
        query=[("count", "10")],
        headers={"content-type": "application/json"},
    )
    assert response.status == 200
    assert response.headers["content-type"] == "application/json"
    assert response.body == b"GET /check"


def test_end_to_end_http_tunnel_non_2xx_keeps_session(stub_transport):
    client = ac.AttestedChannelClient(stub_transport, verifier=_fake_attester_verifier)
    session = client.create_session()

    response = client.request(session, "POST", "/error", b"bad")
    assert response.status == 400
    assert response.body == b"POST /error"

    # A normal DApp error is an encrypted application response, not a proxy
    # protocol failure. The same session remains usable.
    assert client.prove(session, b"still alive") == b"still alive\xaa"


def test_end_to_end_multiple_sessions_are_independent(stub_transport):
    client = ac.AttestedChannelClient(stub_transport, verifier=_fake_attester_verifier)
    s1 = client.create_session()
    s2 = client.create_session()
    assert s1.sid != s2.sid
    assert client.prove(s1, b"a") == b"a\xaa"
    assert client.prove(s2, b"b") == b"b\xaa"
    # Interleaved use keeps each session's sequence counters consistent.
    assert client.prove(s1, b"c") == b"c\xaa"
    assert client.prove(s2, b"d") == b"d\xaa"


def test_tampered_epoch_key_fails_verification(stub_transport):
    # A client that trusts the wrong epoch key must reject the handshake.
    def bad_verifier(ek: ac.EnclaveKey) -> None:
        # Corrupt the epoch public key so the signature check fails downstream.
        ek.epoch_public = bytes(32)

    client = ac.AttestedChannelClient(stub_transport, verifier=bad_verifier)
    with pytest.raises(ac.ProtocolError):
        client.create_session()
