"""Collect the binary TPM quote outputs used by the attestation document."""

import base64
from pathlib import Path
import subprocess
import tempfile


OUTPUT_OPTIONS = (
    ("message", "--message"),
    ("signature", "--signature"),
    ("pcr", "--pcr"),
)


def collect_quote() -> dict[str, str]:
    with tempfile.TemporaryDirectory(prefix="attestation-quote-") as directory:
        outputs = {name: Path(directory) / name for name, _ in OUTPUT_OPTIONS}
        for path in outputs.values():
            path.touch(mode=0o600)

        command = [
            "tpm2_quote", "--quiet",
            "--key-context", "0x81000003",
            "--pcr-list", "sha256:" + ",".join(str(index) for index in range(16)),
        ]
        for name, option in OUTPUT_OPTIONS:
            command.extend((option, str(outputs[name])))
        command.extend(("--hash-algorithm", "sha256"))
        subprocess.run(command, check=True)

        return {
            name: base64.b64encode(path.read_bytes()).decode("utf-8")
            for name, path in outputs.items()
        }
