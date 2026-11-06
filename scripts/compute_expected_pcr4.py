#!/usr/bin/env python3

import argparse
import json
from enum import Enum
from hashlib import sha256
import hashlib
import logging
from pathlib import Path
import re
import tempfile
import subprocess
from contextlib import contextmanager
import textwrap

logging.basicConfig(level=logging.INFO)

def run_command(*args, capture_output=True):
    logging.info(f"run: {' '.join(args)}")
    try:
        return subprocess.run(args, text=True, capture_output=capture_output, check=True).stdout.strip()
    except FileNotFoundError as e:
        raise RuntimeError(f"Required command not found: {args[0]}") from e
    except subprocess.CalledProcessError as e:
        command = ' '.join(args)
        indented_stderr = textwrap.indent(e.stderr, prefix='   ')
        indented_stdout = textwrap.indent(e.stdout, prefix='   ')
        error_message = (
            f"Command '{command}' failed.\n"
            f"Stdout:\n{indented_stdout}"
            f"Stderr:\n{indented_stderr}"
        )

        raise RuntimeError(error_message) from e


def get_partition_offset(image_file, partition_number=1):
    partition_table = json.loads(run_command('sfdisk', '--json', image_file))
    table = partition_table.get("partitiontable", {})
    sector_size = int(table.get("sectorsize", 512))
    partitions = table.get("partitions", [])

    try:
        partition = partitions[partition_number - 1]
        start_sector = int(partition["start"])
    except (IndexError, KeyError, TypeError, ValueError) as exc:
        raise RuntimeError(f"Could not find partition {partition_number} in {image_file}") from exc

    return start_sector * sector_size


@contextmanager
def open_efi_partition_from_os_disk(image_file):
    if not Path(image_file).is_file():
        raise RuntimeError(f"OS disk image not found at {image_file}")

    tmp_dir = tempfile.TemporaryDirectory()
    boot_dir = Path(tmp_dir.name) / "EFI" / "BOOT"
    boot_dir.mkdir(parents=True)
    efi_partition_offset = get_partition_offset(image_file, partition_number=1)
    run_command(
        'mcopy',
        '-i',
        f"{image_file}@@{efi_partition_offset}",
        '::/EFI/BOOT/BOOTX64.EFI',
        str(boot_dir / "BOOTX64.EFI"),
    )

    try:
        yield tmp_dir
    finally:
        tmp_dir.cleanup()


def ev_separator_pcr256():
    ev_separator_sha256_hex = "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"
    return bytes.fromhex(ev_separator_sha256_hex)

def ev_efi_action(string: str):
    return sha256(string.encode("ascii")).digest()

def test_compute_authenticode_hash_efi():
    pass

def compute_authenticode_hash_efi(path: str):
    """
    Compute the cryptographic digest of the UEFI application
    """
    try:
        command = ["pesign", "--hash", "-d", "sha256", "-i", path]
        output = subprocess.check_output(command, stderr=subprocess.PIPE).decode()
        # Some pesign builds prefix the digest with "hash:"; Ubuntu's builds
        # print the digest followed by the input filename.
        hash_match = re.search(
            r'(?:\bhash:\s*|^\s*)([0-9a-fA-F]{64})(?=\s|$)',
            output,
            re.MULTILINE,
        )
        if not hash_match:
            raise RuntimeError(f"Could not parse output of pesign tool\n{output}")
        
        hash_hex = hash_match.group(1)
        hash_bytes = bytes.fromhex(hash_hex)
        if len(hash_bytes) != sha256().digest_size:
            raise RuntimeError(f"Invalid sha256 hash\n{hash_bytes}")

        return hash_bytes
            
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to compute Authenticode hash\n{e.stderr.decode()}") from e
    
def extract_kernel_from_uki_to_file(path: str):
    t = tempfile.NamedTemporaryFile()
    command = ["objcopy", "-O", "binary", "-j", ".linux", path, t.name]
    try:
        subprocess.check_call(command, stderr=subprocess.STDOUT)
        return t
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error extracting kernel from UKI: {e.output.decode()}") from e
    

def simulate_pcr_extend(
    hashes,
    initial_pcr=32*b'\0',
):
    """
    Compute the resulting PCR value after multiple PCR_Extend operations starting from a given PCR value (default is 00s)

    Args:
        hashes (list of bytes): A list of SHA-256 hash values (as bytes) that are to be 
            extended into the PCR. Each hash in the list represents a single measurement.
        initial_pcr (bytes, optional): The initial PCR value from which to start 
            the simulation. This is the PCR state before any data has been extended.
            By default, it is a sequence of 00s, which represents a cleared 
            PCR state.

    Returns:
        bytes: The final PCR value after all hashes have been extended into it. 
            This value is the result of consecutively hashing the initial PCR value 
            with each hash in the provided list of hashes.
    """
    # Starting from the expected initial PCR state
    # We replay the event extending the PCR
    # At the end we get the expected PCR value
    current_pcr = initial_pcr
    for e in hashes:
        current_pcr = hashlib.sha256(current_pcr + e).digest()
    return current_pcr

class Target(Enum):
    AZURE_TRUSTED_LAUNCH = "Azure Trusted Launch"
    AZURE_CVM = "Azure Confidential VM"


TARGET_FIXED_PCRS = {
    Target.AZURE_CVM: {
        12: "0000000000000000000000000000000000000000000000000000000000000000",
        13: "0000000000000000000000000000000000000000000000000000000000000000",
    },
    Target.AZURE_TRUSTED_LAUNCH: {
        12: "0000000000000000000000000000000000000000000000000000000000000000",
        13: "0000000000000000000000000000000000000000000000000000000000000000",
    },
}


def compute_golden_pcr4(path_to_os_disk_image_file: str, target: Target):
    """
    Compute golden measurement for PCR4

    The PCR4 depends on the Azure target profile.
    """
    with open_efi_partition_from_os_disk(path_to_os_disk_image_file) as efi_partition:
        path_to_uki = f"{efi_partition.name}/EFI/BOOT/BOOTX64.EFI"
        logging.info(f"Path to UKI : {path_to_uki}")
        hash_uki = compute_authenticode_hash_efi(path_to_uki)
        if target is not Target.AZURE_CVM:
            with extract_kernel_from_uki_to_file(path_to_uki) as kernel_file:
                hash_kernel = compute_authenticode_hash_efi(kernel_file.name)

    match target:
        case Target.AZURE_TRUSTED_LAUNCH:
            golden_pcr4 = simulate_pcr_extend([
                ev_efi_action("Calling EFI Application from Boot Option"),
                ev_separator_pcr256(),
                ev_efi_action("Returning from EFI Application from Boot Option"),
                ev_efi_action("Calling EFI Application from Boot Option"),
                # EV_EFI_BOOT_SERVICES_APPLICATION with SHA256 authenticode of the UKI PE
                hash_uki,
                # EV_EFI_BOOT_SERVICES_APPLICATION with SHA256 authenticode of the linux kernel
                hash_kernel
            ])
        case Target.AZURE_CVM:
            golden_pcr4 = simulate_pcr_extend([
                ev_efi_action("Calling EFI Application from Boot Option"), # 3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba
                ev_separator_pcr256(), # df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119
                # EV_EFI_BOOT_SERVICES_APPLICATION with SHA256 authenticode of the UKI PE
                hash_uki, 
            ])
    return golden_pcr4


def compute_golden_measurements(path_to_os_disk_image_file: str, target: Target):
    measurements = dict(TARGET_FIXED_PCRS[target])
    measurements[4] = compute_golden_pcr4(path_to_os_disk_image_file, target).hex()

    return {"measurements": measurements}


def parse_target(value: str) -> Target:
    normalized = value.strip().lower().replace("-", "_")
    aliases = {
        "azure_trusted_launch": Target.AZURE_TRUSTED_LAUNCH,
        "azure": Target.AZURE_TRUSTED_LAUNCH,
        "azure_cvm": Target.AZURE_CVM,
        "azure_snp": Target.AZURE_CVM,
    }

    try:
        return aliases[normalized]
    except KeyError as exc:
        valid = ", ".join(sorted(aliases))
        raise argparse.ArgumentTypeError(f"invalid target {value!r}; expected one of: {valid}") from exc


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--disk", required=True, help="Path to the raw OS disk image")
    parser.add_argument(
        "--target",
        type=parse_target,
        default=Target.AZURE_CVM,
        help="PCR profile to compute: azure-snp or azure",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write full measurements JSON to this path. If omitted, only PCR4 is printed.",
    )
    args = parser.parse_args()

    try:
        if args.output is None:
            print(compute_golden_pcr4(args.disk, args.target).hex())
            return

        args.output.write_text(
            json.dumps(compute_golden_measurements(args.disk, args.target), indent=4) + "\n"
        )
    except RuntimeError as exc:
        parser.exit(1, f"error: {exc}\n")


if __name__ == "__main__":
    main()
