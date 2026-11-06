import json
import os
import re
import socket
import ssl
import subprocess
import time
from typing import Dict, List
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

import hashlib

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

if __package__:
    from .tpm_quote import collect_quote
else:
    from tpm_quote import collect_quote

PCR_INDEX = 15
SHA256_DIGEST_SIZE = hashlib.sha256().digest_size
ZERO_DIGEST = bytes(SHA256_DIGEST_SIZE)
STATIC_ATTESTATION_DOCUMENT_VERSION = "1"
TLS_INTERNAL_EVIDENCE_DOMAIN = b"temenos-tls-internal-v1\x00"
TLS_SPKI_EVIDENCE_DOMAIN = b"temenos-tls-spki-v1\x00"

def get_caddy_rootca():
    s = requests.Session()
    retries = Retry(total=5, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
    s.mount("http://", HTTPAdapter(max_retries=retries))
    
    r = s.get("http://caddy-in-constrained-attestation-generator-network:2019/pki/ca/local")
    r.raise_for_status()
    caddy_root_ca = r.json()['root_certificate']
    
    if not caddy_root_ca:
    	raise ValueError("Expected a Caddy root CA, got nothing")
    	
    return caddy_root_ca

def retry_operation(description, operation, attempts=60, delay=2.0):
    last_exc = None
    for _ in range(attempts):
        try:
            return operation()
        except Exception as exc:
            last_exc = exc
            time.sleep(delay)

    raise RuntimeError(f"Failed to {description}") from last_exc


def get_tls_leaf_certificate_der(hostname: str, connect_host: str, connect_port: int) -> bytes:
    def fetch_cert():
        context = ssl._create_unverified_context()
        with socket.create_connection((connect_host, connect_port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                return tls_sock.getpeercert(binary_form=True)

    return retry_operation(
        f"fetch TLS certificate for {hostname} via {connect_host}:{connect_port}",
        fetch_cert,
    )


def spki_sha256_from_certificate_der(cert_der: bytes) -> str:
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    spki_der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki_der).hexdigest()


def get_tls_spki_evidence() -> dict:
    connect_host = os.getenv(
        "TEMENOS_CADDY_CONNECT_HOST",
        "caddy-in-constrained-attestation-generator-network",
    )
    connect_port = int(os.getenv("TEMENOS_CADDY_CONNECT_PORT", "443"))
    endpoints = {}

    for endpoint_name, env_var in (
        ("attestation", "TEMENOS_ATTESTATION_TLS_HOST"),
        ("api", "TEMENOS_APP_TLS_HOST"),
    ):
        hostname = os.getenv(env_var, "").strip()
        if not hostname:
            continue

        cert_der = get_tls_leaf_certificate_der(hostname, connect_host, connect_port)
        endpoints[endpoint_name] = {
            "host": hostname,
            "spki_sha256": spki_sha256_from_certificate_der(cert_der),
        }

    if not endpoints:
        raise ValueError("No TLS hostnames configured for SPKI evidence")

    return {
        "mode": "spki",
        "connect_host": connect_host,
        "connect_port": connect_port,
        "endpoints": endpoints,
    }


def domain_separated_sha256(domain: bytes, evidence: bytes) -> bytes:
    return hashlib.sha256(domain + evidence).digest()


def measurement_hash_for_internal_tls_evidence(root_ca_pem: str) -> bytes:
    return domain_separated_sha256(
        TLS_INTERNAL_EVIDENCE_DOMAIN,
        root_ca_pem.encode("utf-8"),
    )


def measurement_hash_for_tls_evidence(tls_evidence: dict) -> bytes:
    return domain_separated_sha256(
        TLS_SPKI_EVIDENCE_DOMAIN,
        json.dumps(tls_evidence, sort_keys=True, separators=(",", ":")).encode("utf-8"),
    )


def simulate_tpm_extend(current_pcr: bytes, digest: bytes) -> bytes:
    if len(current_pcr) != SHA256_DIGEST_SIZE:
        raise ValueError(
            f"Invalid PCR length. Expected {SHA256_DIGEST_SIZE} bytes."
        )
    if len(digest) != SHA256_DIGEST_SIZE:
        raise ValueError(
            f"Invalid digest length. Expected {SHA256_DIGEST_SIZE} bytes."
        )

    return hashlib.sha256(current_pcr + digest).digest()


def expected_setup_pcr(app_root_hash: bytes) -> bytes:
    pcr = ZERO_DIGEST
    pcr = simulate_tpm_extend(pcr, app_root_hash)
    pcr = simulate_tpm_extend(pcr, ZERO_DIGEST)
    return pcr


def read_pcr(pcr_index: int) -> bytes:
    output = subprocess.check_output(["tpm2_pcrread", f"sha256:{pcr_index}"]).decode()
    match = re.search(rf"\b{pcr_index}\s*:\s*0x([0-9a-fA-F]{{64}})\b", output)
    if not match:
        raise ValueError(f"Could not parse PCR {pcr_index} from tpm2_pcrread output")

    return bytes.fromhex(match.group(1))


def tpm_extend_pcr(pcr_index: int, digest: bytes) -> None:
    """
    Extend PCR pcr_index from SHA256 bank with a hash

    >>> hex_hash_value = (
    ...      bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
    ... )
    >>> pcr_index = 15
    >>> tpm_extend_pcr(pcr_index, hex_hash_value)
    """
    if not isinstance(digest, bytes):
        raise TypeError("Expected hash to be of type bytes.")
    
    if len(digest) != SHA256_DIGEST_SIZE:
        raise ValueError(f"Invalid hash length. Expected {SHA256_DIGEST_SIZE} bytes for a SHA256 hash.")
    
    hex_hash_value = digest.hex()
    subprocess.run(
        ["tpm2_pcrextend", f"{pcr_index}:sha256={hex_hash_value}"], check=True
    )


def ensure_tls_evidence_pcr_extended_once(pcr_index: int, app_root_hash: bytes, tls_evidence_hash: bytes) -> None:
    expected_initial_pcr = expected_setup_pcr(app_root_hash)
    expected_final_pcr = simulate_tpm_extend(expected_initial_pcr, tls_evidence_hash)
    current_pcr = read_pcr(pcr_index)

    if current_pcr == expected_final_pcr:
        print(
            f"PCR {pcr_index} already contains the TLS evidence extension; "
            "skipping duplicate extension"
        )
        return

    if current_pcr != expected_initial_pcr:
        raise RuntimeError(
            f"PCR {pcr_index} has an unexpected value before TLS evidence extension. "
            f"current={current_pcr.hex()} "
            f"expected_initial={expected_initial_pcr.hex()} "
            f"expected_after_tls={expected_final_pcr.hex()}"
        )

    tpm_extend_pcr(pcr_index, tls_evidence_hash)
    actual_pcr = read_pcr(pcr_index)
    if actual_pcr != expected_final_pcr:
        raise RuntimeError(
            f"PCR {pcr_index} TLS evidence extension mismatch after extend. "
            f"expected={expected_final_pcr.hex()} got={actual_pcr.hex()}"
        )


def get_quote() -> Dict[str, bytes]:
    return collect_quote()

def tpm_nvread(offset: str) -> bytes:
    return subprocess.run(
        ["tpm2_nvread", "-Co", offset], capture_output=True, check=True
    ).stdout

def extract_first_der_x509(blob: bytes) -> bytes:
    """
    NV index often contains DER cert + trailing padding/extra bytes.
    Extract the first DER SEQUENCE (0x30...) using its encoded length.
    """
    blob = blob.lstrip(b"\x00")
    if len(blob) < 4 or blob[0] != 0x30:
        raise ValueError(f"NV data does not look like DER X.509 (head={blob[:16].hex()})")

    b1 = blob[1]
    if b1 < 0x80:
        total_len = 2 + b1
    else:
        n = b1 & 0x7F
        if n == 0 or n > 4 or len(blob) < 2 + n:
            raise ValueError("Invalid DER length encoding")
        content_len = int.from_bytes(blob[2:2+n], "big")
        total_len = 2 + n + content_len

    if len(blob) < total_len:
        raise ValueError("Truncated DER cert in NV data")

    return blob[:total_len]

def get_cert_chain() -> List[str]:
    root_cert = open("Azure Virtual TPM Root Certificate Authority 2023.crt", "r").read()
    intermediate_cert = open("intermediate_ca.crt", "r").read()
    
    AIK_CERT_INDEX = "0x01C101D0"
    nv_blob = tpm_nvread(AIK_CERT_INDEX)
    cert_der = extract_first_der_x509(nv_blob)
    # Parse the DER certificate
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    # Convert the certificate to PEM format
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8")

    cert_chain = [cert_pem, intermediate_cert, root_cert]
    return cert_chain


def build_attestation_payload() -> dict:
    tls_evidence_mode = os.getenv("TEMENOS_TLS_EVIDENCE_MODE", "internal").strip().lower()
    with open("/application_disk_root_hash", "r") as root_hash_file:
        root_hash = root_hash_file.read()
    app_root_hash = bytes.fromhex(root_hash.strip())

    attestation_payload = {
        "version": STATIC_ATTESTATION_DOCUMENT_VERSION,
        "cert_chain": get_cert_chain(),
    }

    if tls_evidence_mode == "internal":
        caddy_root_ca = get_caddy_rootca()
        root_ca_sha256 = hashlib.sha256(caddy_root_ca.encode("utf-8")).digest()
        ensure_tls_evidence_pcr_extended_once(
            PCR_INDEX,
            app_root_hash,
            measurement_hash_for_internal_tls_evidence(caddy_root_ca),
        )
        attestation_payload["webserver_rootca"] = caddy_root_ca
        attestation_payload["webserver_tls"] = {
            "mode": "internal_ca",
            "root_ca_sha256": root_ca_sha256.hex(),
        }
    elif tls_evidence_mode == "spki":
        tls_evidence = get_tls_spki_evidence()
        ensure_tls_evidence_pcr_extended_once(
            PCR_INDEX,
            app_root_hash,
            measurement_hash_for_tls_evidence(tls_evidence),
        )
        attestation_payload["webserver_tls"] = tls_evidence
    else:
        raise ValueError(f"Unsupported TEMENOS_TLS_EVIDENCE_MODE: {tls_evidence_mode}")

    attestation_payload["quote"] = get_quote()
    attestation_payload["application_disk_roothash"] = root_hash
    return attestation_payload


def main() -> None:
    attestation_payload = build_attestation_payload()
    with open("/srv/attestation.json", "w") as json_file:
        json.dump(attestation_payload, json_file)


if __name__ == "__main__":
    main()
