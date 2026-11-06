import base64
import importlib.util
from pathlib import Path
import stat
import subprocess
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "veritee_attestation/tpm_quote.py"
spec = importlib.util.spec_from_file_location("quote_under_test", SOURCE)
quote = importlib.util.module_from_spec(spec)
spec.loader.exec_module(quote)


class QuoteCollectionTests(unittest.TestCase):
    def test_quote_command_outputs_and_permissions(self):
        content = {"message": b"\0quote\xff", "signature": b"signature\n", "pcr": bytes(range(32))}
        directories = []

        def run(command, *, check):
            self.assertTrue(check)
            self.assertEqual(command[:6], [
                "tpm2_quote", "--quiet", "--key-context", "0x81000003",
                "--pcr-list", "sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15",
            ])
            self.assertEqual(command[-2:], ["--hash-algorithm", "sha256"])
            for name, option in quote.OUTPUT_OPTIONS:
                path = Path(command[command.index(option) + 1])
                directories.append(path.parent)
                self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(path.read_bytes(), b"")
                path.write_bytes(content[name])

        with patch.object(quote.subprocess, "run", side_effect=run) as process:
            evidence = quote.collect_quote()
        process.assert_called_once()
        self.assertEqual(list(evidence), ["message", "signature", "pcr"])
        self.assertEqual(evidence, {
            name: base64.b64encode(data).decode("utf-8") for name, data in content.items()
        })
        self.assertTrue(all(not path.exists() for path in directories))

    def test_tool_failure_propagates_and_cleans_files(self):
        directories = []

        def fail(command, *, check):
            directories.append(Path(command[command.index("--message") + 1]).parent)
            raise subprocess.CalledProcessError(1, command)

        with patch.object(quote.subprocess, "run", side_effect=fail):
            with self.assertRaises(subprocess.CalledProcessError):
                quote.collect_quote()
        self.assertTrue(all(not path.exists() for path in directories))

    def test_success_without_output_preserves_empty_output_encoding(self):
        with patch.object(quote.subprocess, "run"):
            self.assertEqual(quote.collect_quote(), {"message": "", "signature": "", "pcr": ""})


if __name__ == "__main__":
    unittest.main()
