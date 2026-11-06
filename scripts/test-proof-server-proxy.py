#!/usr/bin/env python3
"""Test direct and encrypted /check + /prove with the PR #53 HTTP client."""

import argparse
from contextlib import nullcontext
from datetime import datetime, timezone
import ipaddress
from pathlib import Path
import socket
import time
from unittest.mock import patch

import requests

from veritee.attested_channel import AttestedChannelClient, HttpTransport, ProtocolError, make_warden_verifier


ROOT = Path(__file__).resolve().parents[1]
PROOF_PREFIX = b"midnight:proof-versioned:"
CHECK_PREFIX = b"midnight:vec(option(u64)):"


def check_proof(body):
    if not body.startswith(PROOF_PREFIX) or len(body) <= 1000:
        raise RuntimeError("Response is not a versioned proof")


def check_result(body):
    if not body.startswith(CHECK_PREFIX) or len(body) <= len(CHECK_PREFIX):
        raise RuntimeError("Response is not a serialized ledger check result")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", type=ipaddress.ip_address, help="Override DNS only; TLS hostname verification stays enabled")
    parser.add_argument("--api-host", default="api.proofserver.wastedp.io")
    parser.add_argument("--attestation-host", default="attestation.proofserver.wastedp.io")
    parser.add_argument("--dapp-id", help="Registered entry ID; enables Warden verification of the epoch key")
    parser.add_argument("--warden-url", default="https://warden.wastedp.io")
    parser.add_argument("--warden-ip", type=ipaddress.ip_address, help="Override Warden DNS while retaining its HTTPS hostname")
    parser.add_argument("--payload", type=Path, default=ROOT / "docs/proof-server-prove-fixture/zswap-prove-payload.bin")
    parser.add_argument("--check-payload", type=Path, default=ROOT / "docs/proof-server-prove-fixture/zswap-check-payload.bin")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--output", type=Path, help="Also save the test output to this file")
    parser.add_argument("--response-dir", type=Path, help="Save binary responses for ledger API validation")
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")

    lines = []

    def report(line=""):
        lines.append(line)
        print(line, flush=True)

    api_url = f"https://{args.api_host}"
    attestation_url = f"https://{args.attestation_host}/tee_attestation"
    report("Proof-server /check + /prove test")
    report(f"UTC: {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
    report(f"Direct: {api_url}")
    report(f"Encrypted: {attestation_url}/proxy")
    report(f"Routing: {args.ip or 'normal DNS'}")
    report("TLS: normal certificate and hostname validation")
    report("Scope: Warden verifies the epoch key before encrypted calls" if args.dapp_id else "Scope: application/transport only; Warden attestation verification is separate")

    def save_response(name, body):
        if args.response_dir:
            args.response_dir.mkdir(parents=True, exist_ok=True)
            (args.response_dir / name).write_bytes(body)

    # Redirect only the two test hosts; keep their original names for TLS/SNI.
    original_resolver = socket.getaddrinfo

    def resolve(host, port, *positional, **keywords):
        if args.ip and host in {args.api_host, args.attestation_host}:
            host = str(args.ip)
        if args.warden_ip and host == requests.utils.urlparse(args.warden_url).hostname:
            host = str(args.warden_ip)
        return original_resolver(host, port, *positional, **keywords)

    routing = patch("socket.getaddrinfo", side_effect=resolve) if args.ip or args.warden_ip else nullcontext()
    failed = False
    try:
        payload = args.payload.read_bytes()
        check_payload = args.check_payload.read_bytes()
        report(f"Payloads: /check {len(check_payload)} bytes; /prove {len(payload)} bytes")
        if not hasattr(AttestedChannelClient, "request"):
            raise RuntimeError("Use the matching HTTP client from PR #53 (feat/attested-http-proxy); set PYTHONPATH to that checkout's cli directory")
        with routing, requests.Session() as http:
            http.trust_env = False
            proxy_response = {}

            def capture_proxy(response, *positional, **keywords):
                if response.request.url == f"{attestation_url}/proxy":
                    proxy_response["status"] = response.status_code
                    proxy_response["ms"] = round(response.elapsed.total_seconds() * 1000)

            http.hooks["response"].append(capture_proxy)
            report()
            report("Direct POST /check")
            started = time.monotonic()
            response = http.post(f"{api_url}/check", data=check_payload, headers={"Content-Type": "application/octet-stream"}, timeout=120)
            response.raise_for_status()
            check_result(response.content)
            direct_check = response.content
            save_response("direct-check.bin", direct_check)
            elapsed = round((time.monotonic() - started) * 1000)
            report(f"PASS: HTTP {response.status_code}; {len(direct_check)}-byte check result; {elapsed} ms")

            report()
            report("Direct POST /prove")
            started = time.monotonic()
            response = http.post(f"{api_url}/prove", data=payload, headers={"Content-Type": "application/octet-stream"}, timeout=120)
            response.raise_for_status()
            check_proof(response.content)
            save_response("direct-prove.bin", response.content)
            elapsed = round((time.monotonic() - started) * 1000)
            report(f"PASS: HTTP {response.status_code}; {len(response.content)}-byte versioned proof; {elapsed} ms")

            report()
            report("Encrypted POST /tee_attestation/proxy")
            verifier = None
            if args.dapp_id:
                verifier = make_warden_verifier(args.warden_url.rstrip("/") + "/dapps/verify_attestation", args.dapp_id, session=http, timeout=120)
            client = AttestedChannelClient(HttpTransport(attestation_url, session=http, timeout=120), verifier=verifier)
            for run in range(1, args.runs + 1):
                started = time.monotonic()
                session = client.create_session()
                handshake_ms = round((time.monotonic() - started) * 1000)
                # An application 400 must preserve this same encrypted session.
                bad = client.request(session, "POST", "/check", b"invalid-fixture")
                if bad.status != 400:
                    raise RuntimeError(f"Malformed /check returned {bad.status}, expected 400")
                checked = client.request(session, "POST", "/check", check_payload, headers={"content-type": "application/octet-stream"})
                if checked.status != 200:
                    raise RuntimeError(f"Encrypted /check returned upstream HTTP {checked.status}")
                check_result(checked.body)
                if checked.body != direct_check:
                    raise RuntimeError("Direct and encrypted check results differ")
                save_response(f"encrypted-check-{run}.bin", checked.body)
                report(f"PASS [{run}/{args.runs}] /check: outer HTTP {proxy_response['status']}; upstream HTTP {checked.status}; {len(checked.body)} bytes; application 400 preserved session")
                proved = client.request(session, "POST", "/prove", payload, headers={"content-type": "application/octet-stream"})
                if proved.status != 200:
                    raise RuntimeError(f"Encrypted /prove returned upstream HTTP {proved.status}")
                check_proof(proved.body)
                save_response(f"encrypted-prove-{run}.bin", proved.body)
                report(f"PASS [{run}/{args.runs}] /prove: outer HTTP {proxy_response['status']}; upstream HTTP {proved.status}; {len(proved.body)}-byte decrypted versioned proof; proxy {proxy_response['ms']} ms; handshake {handshake_ms} ms")
        report()
        report(f"Result: PASS (direct /check + /prove; both routes in each of {args.runs} fresh encrypted sessions)")
    except (OSError, RuntimeError, ProtocolError, requests.RequestException) as error:
        failed = True
        report(f"Result: FAIL ({type(error).__name__}: {error})")
    finally:
        if args.output:
            args.output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
