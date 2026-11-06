import os
import json
import subprocess
import re
import uuid
import hashlib
import shutil
import socket
import sys
import time
from pathlib import Path

from egress import install_from_metadata, policy_from_metadata, validate_compose_file
from proxy_policy import PROXY_POLICY_PATH, install_proxy_policy, validate_proxy_allowed_paths

SHA256_DIGEST_SIZE = hashlib.sha256().digest_size
ZERO_DIGEST = bytes(SHA256_DIGEST_SIZE)
ALLOW_PCR15_FAILURE_ENV = "TEMENOS_ALLOW_PCR15_FAILURE"
HOST_APP_PROXY_URL = "http://127.0.0.1:18080"
PLATFORM_PROXY_URL = "http://127.0.0.1:18081"
APP_PROXY_GATEWAY = "172.30.255.1"
APP_PROXY_SUBNET = "172.30.255.0/24"
PROXY_SERVICES = (
    ("temenos-egress-proxy@app.service", "127.0.0.1", 18080),
    ("temenos-egress-proxy@platform.service", "127.0.0.1", 18081),
)
BASE_NO_PROXY_HOSTS = {
    "127.0.0.1",
    "168.63.129.16",
    "169.254.169.254",
    "::1",
    "attestation",
    "localhost",
}


def warn(message: str) -> None:
    print(f"WARNING: {message}", file=sys.stderr)


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


def expected_setup_pcr(hash_value: bytes) -> bytes:
    pcr = ZERO_DIGEST
    pcr = simulate_tpm_extend(pcr, hash_value)
    pcr = simulate_tpm_extend(pcr, ZERO_DIGEST)
    return pcr


def read_pcr(pcr_index: int) -> bytes:
    output = subprocess.check_output(["tpm2_pcrread", f"sha256:{pcr_index}"]).decode()
    match = re.search(rf"\b{pcr_index}\s*:\s*0x([0-9a-fA-F]{{64}})\b", output)
    if not match:
        raise ValueError(f"Could not parse PCR {pcr_index} from tpm2_pcrread output")

    return bytes.fromhex(match.group(1))

def tpm_extend_pcr(pcr_index: int, hash: bytes) -> None:
    """
    Extend PCR pcr_index from SHA256 bank with a hash

    >>> hex_hash_value = (
    ...      bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
    ... )
    >>> pcr_index = 15
    >>> tpm_extend_pcr(pcr_index, hex_hash_value)
    """
    if not isinstance(hash, bytes):
        raise TypeError("Expected hash to be of type bytes.")
    
    if len(hash) != SHA256_DIGEST_SIZE:
        raise ValueError(f"Invalid hash length. Expected {SHA256_DIGEST_SIZE} bytes for a SHA256 hash.")
    
    hex_hash_value = hash.hex()
    subprocess.run(
        ["tpm2_pcrextend", f"{pcr_index}:sha256={hex_hash_value}"], check=True
    )


def ensure_setup_pcr_extended_once(pcr_index: int, hash_value: bytes) -> bool:
    expected_pcr = expected_setup_pcr(hash_value)
    try:
        current_pcr = read_pcr(pcr_index)
    except Exception as error:
        warn(f"could not read PCR {pcr_index}: {error}")
        return False

    if current_pcr == expected_pcr:
        print(
            f"PCR {pcr_index} already contains the measured setup extension; "
            "skipping duplicate extension"
        )
        return True

    if current_pcr != ZERO_DIGEST:
        warn(
            f"PCR {pcr_index} already has an unexpected value; refusing to modify it. "
            f"current={current_pcr.hex()} expected_initial={ZERO_DIGEST.hex()} "
            f"expected_after_setup={expected_pcr.hex()}"
        )
        return False

    try:
        tpm_extend_pcr(pcr_index, hash_value)
        tpm_extend_pcr(pcr_index, ZERO_DIGEST)
    except Exception as error:
        warn(f"failed to extend PCR {pcr_index}: {error}")
        return False

    try:
        actual_pcr = read_pcr(pcr_index)
    except Exception as error:
        warn(f"could not verify PCR {pcr_index} after extension: {error}")
        return False
    if actual_pcr != expected_pcr:
        warn(
            f"PCR {pcr_index} setup extension mismatch after extend. "
            f"expected={expected_pcr.hex()} got={actual_pcr.hex()}."
        )
        return False

    return True


def require_setup_pcr_extended(pcr_index: int, hash_value: bytes) -> None:
    if ensure_setup_pcr_extended_once(pcr_index, hash_value):
        return

    if os.environ.get(ALLOW_PCR15_FAILURE_ENV) == "1":
        warn(
            f"PCR {pcr_index} setup failed; continuing because "
            f"{ALLOW_PCR15_FAILURE_ENV} is enabled"
        )
        return

    raise RuntimeError(
        f"PCR {pcr_index} setup failed; refusing to start the DApp without "
        "the expected measured state"
    )


def verity_setup_open(device, name, hash_device, root_hash):
    cmd = ["veritysetup", "open", device, name, hash_device, root_hash.hex()]
    subprocess.check_call(cmd)


def verity_setup_close(name):
    cmd = ["veritysetup", "close", name]
    subprocess.check_call(cmd)


def get_partition_uuid(device):
    cmd = ["blkid", device]
    output = subprocess.check_output(cmd).decode()

    # Use a regular expression to extract the UUID
    matches = re.search(r'PARTUUID="([^"]+)"', output)
    if matches:
        return uuid.UUID(matches.group(1))
    else:
        raise ValueError(f"PARTUUID not found for partition {device}")


def mount(source_path, mount_point):
    cmd = ["mount", "-t", "squashfs", "--read-only", source_path, mount_point]
    subprocess.check_call(cmd)


def umount(mount_point):
    cmd = ["umount", mount_point]
    subprocess.check_call(cmd)

def dm_exists(name):
    return subprocess.call(
        ["dmsetup", "info", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    ) == 0

def is_mounted(path):
    return os.path.ismount(path)


def wait_for_tcp_listener(host: str, port: int, timeout_seconds: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"egress proxy did not listen on {host}:{port}")


def start_egress_proxies() -> None:
    for service, _, _ in PROXY_SERVICES:
        subprocess.check_call(["systemctl", "restart", service])
    for _, host, port in PROXY_SERVICES:
        wait_for_tcp_listener(host, port)


def compose_no_proxy(service_names: set[str]) -> str:
    return ",".join(sorted(BASE_NO_PROXY_HOSTS | service_names))


def write_compose_egress_override(
    run_dir: Path,
    service_names: set[str],
) -> Path:
    output = run_dir / "docker-compose.temenos-egress.yml"
    no_proxy = compose_no_proxy(service_names)
    output.write_text(
        f"""services:
  app:
    environment:
      HTTP_PROXY: http://egress-proxy:18080
      HTTPS_PROXY: http://egress-proxy:18080
      http_proxy: http://egress-proxy:18080
      https_proxy: http://egress-proxy:18080
      NO_PROXY: "{no_proxy}"
      no_proxy: "{no_proxy}"
    extra_hosts:
      - "egress-proxy:{APP_PROXY_GATEWAY}"

networks:
  constrained-app:
    ipam:
      config:
        - subnet: {APP_PROXY_SUBNET}
          gateway: {APP_PROXY_GATEWAY}
"""
    )
    os.chmod(output, 0o600)
    return output


def proxy_environment(proxy_url: str) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "HTTP_PROXY": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "http_proxy": proxy_url,
            "https_proxy": proxy_url,
            "NO_PROXY": "127.0.0.1,localhost,::1,169.254.169.254,168.63.129.16",
            "no_proxy": "127.0.0.1,localhost,::1,169.254.169.254,168.63.129.16",
        }
    )
    return environment

PCR_INDEX = 15

def main():
    # /run is cleared on boot; also discard a policy from an earlier setup retry.
    # Attestation can still start for diagnostics when setup fails, with no routes.
    PROXY_POLICY_PATH.unlink(missing_ok=True)
    uuid_app_partition = get_partition_uuid("/dev/disk/by-partlabel/app")
    uuid_app_verity_hash_partition = get_partition_uuid("/dev/disk/by-partlabel/app-verity")
    hash_value = uuid_app_partition.bytes + uuid_app_verity_hash_partition.bytes

    hash_file = open("/root/application_disk_root_hash","w")
    hash_file.write(hash_value.hex())
    hash_file.close()

    require_setup_pcr_extended(PCR_INDEX, hash_value)

    if dm_exists("app"):
        print("dm-verity mapping already exists, skipping setup")
    else:
        verity_setup_open("/dev/disk/by-partlabel/app", "app", "/dev/disk/by-partlabel/app-verity", hash_value)
    subprocess.check_call(["dmsetup", "mknodes", "app"])

    if not is_mounted("/mnt/app"):
        os.makedirs("/mnt/app", exist_ok=True)
        mount("/dev/mapper/app", "/mnt/app")

    metadata_path = Path("/mnt/app/metadata.json")
    metadata = json.loads(metadata_path.read_text())
    validate_proxy_allowed_paths(metadata)
    policy_preview = policy_from_metadata(metadata)
    compose_services = validate_compose_file(
        Path("/mnt/app/run.d/docker-compose.yml"),
        allow_warden_host_access=(policy_preview["profile"] == "warden"),
    )
    policy = install_from_metadata(metadata_path)
    print(
        "Installed measured outbound policy "
        f"({len(policy['outbound'])} DApp rule(s), "
        f"{len(policy['platform_outbound'])} platform rule(s))"
    )
    start_egress_proxies()

    cmd = ["/mnt/app/setup.d/main"]
    subprocess.check_call(cmd, env=proxy_environment(HOST_APP_PROXY_URL))

    shutil.rmtree("/root/run.d", ignore_errors=True)
    shutil.copytree("/mnt/app/run.d", "/root/run.d")
    compose_override = write_compose_egress_override(
        Path("/root/run.d"),
        compose_services,
    )

    umount("/mnt/app")
    verity_setup_close("app")

    run_environment = proxy_environment(PLATFORM_PROXY_URL)
    run_environment["COMPOSE_FILE"] = (
        f"docker-compose.yml:{compose_override.name}"
    )
    subprocess.check_call("/root/run.d/main", env=run_environment)
    install_proxy_policy(metadata, PROXY_POLICY_PATH)


if __name__ == "__main__":
    main()
