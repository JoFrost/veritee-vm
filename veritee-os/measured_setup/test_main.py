import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
import uuid
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

# Earthfile installs this shared CLI/guest module beside measured setup.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "cli" / "veritee"))
import main as measured_setup


class ComposeEgressOverrideTests(unittest.TestCase):
    def test_no_proxy_includes_all_validated_compose_services(self):
        hosts = set(
            measured_setup.compose_no_proxy(
                {"app", "caddy", "proof-server"}
            ).split(",")
        )

        self.assertTrue(
            {
                "127.0.0.1",
                "168.63.129.16",
                "169.254.169.254",
                "::1",
                "app",
                "attestation",
                "caddy",
                "localhost",
                "proof-server",
            }.issubset(hosts)
        )


class Pcr15SetupTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        policy_path = mock.patch.object(
            measured_setup, "PROXY_POLICY_PATH", Path(scratch.name) / "policy.json"
        )
        policy_path.start()
        self.addCleanup(policy_path.stop)
        self.hash_value = hashlib.sha256(b"application-root").digest()
        self.expected_pcr = measured_setup.expected_setup_pcr(self.hash_value)
        environment = mock.patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)

    def assert_fatal_setup(self, action, expected_warning):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            with self.assertRaisesRegex(RuntimeError, "refusing to start the DApp"):
                action()
        self.assertIn(expected_warning, stderr.getvalue())

    @mock.patch.object(measured_setup, "tpm_extend_pcr")
    @mock.patch.object(measured_setup, "read_pcr")
    def test_extends_clean_pcr_and_verifies_result(self, read_pcr, extend_pcr):
        read_pcr.side_effect = [measured_setup.ZERO_DIGEST, self.expected_pcr]

        self.assertTrue(
            measured_setup.ensure_setup_pcr_extended_once(15, self.hash_value)
        )
        self.assertEqual(
            extend_pcr.call_args_list,
            [
                mock.call(15, self.hash_value),
                mock.call(15, measured_setup.ZERO_DIGEST),
            ],
        )

    @mock.patch.object(measured_setup, "tpm_extend_pcr")
    @mock.patch.object(measured_setup, "read_pcr")
    def test_accepts_expected_pcr_without_extending(self, read_pcr, extend_pcr):
        read_pcr.return_value = self.expected_pcr
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            self.assertTrue(
                measured_setup.ensure_setup_pcr_extended_once(15, self.hash_value)
            )

        extend_pcr.assert_not_called()
        self.assertIn("already contains the measured setup extension", stdout.getvalue())

    @mock.patch.object(measured_setup, "tpm_extend_pcr")
    @mock.patch.object(measured_setup, "read_pcr")
    def test_dirty_pcr_is_fatal_by_default(self, read_pcr, extend_pcr):
        read_pcr.return_value = b"\x01" * measured_setup.SHA256_DIGEST_SIZE
        self.assert_fatal_setup(
            lambda: measured_setup.require_setup_pcr_extended(15, self.hash_value),
            "already has an unexpected value",
        )

        extend_pcr.assert_not_called()

    @mock.patch.object(measured_setup, "read_pcr")
    def test_pcr_read_failure_is_fatal_by_default(self, read_pcr):
        read_pcr.side_effect = OSError("TPM unavailable")
        self.assert_fatal_setup(
            lambda: measured_setup.require_setup_pcr_extended(15, self.hash_value),
            "could not read PCR 15: TPM unavailable",
        )

    @mock.patch.object(measured_setup, "tpm_extend_pcr")
    @mock.patch.object(measured_setup, "read_pcr")
    def test_pcr_extend_failure_is_fatal_by_default(self, read_pcr, extend_pcr):
        read_pcr.return_value = measured_setup.ZERO_DIGEST
        extend_pcr.side_effect = OSError("TPM extend failed")
        self.assert_fatal_setup(
            lambda: measured_setup.require_setup_pcr_extended(15, self.hash_value),
            "failed to extend PCR 15: TPM extend failed",
        )

    @mock.patch.object(measured_setup, "tpm_extend_pcr")
    @mock.patch.object(measured_setup, "read_pcr")
    def test_pcr_readback_mismatch_is_fatal_by_default(
        self, read_pcr, _extend_pcr
    ):
        read_pcr.side_effect = [
            measured_setup.ZERO_DIGEST,
            b"\x02" * measured_setup.SHA256_DIGEST_SIZE,
        ]
        self.assert_fatal_setup(
            lambda: measured_setup.require_setup_pcr_extended(15, self.hash_value),
            "setup extension mismatch after extend",
        )

    @mock.patch.object(measured_setup, "tpm_extend_pcr")
    @mock.patch.object(measured_setup, "read_pcr")
    def test_debug_override_allows_dirty_pcr(self, read_pcr, extend_pcr):
        read_pcr.return_value = b"\x01" * measured_setup.SHA256_DIGEST_SIZE
        stderr = io.StringIO()

        with mock.patch.dict(
            os.environ,
            {measured_setup.ALLOW_PCR15_FAILURE_ENV: "1"},
            clear=True,
        ):
            with redirect_stderr(stderr):
                measured_setup.require_setup_pcr_extended(15, self.hash_value)

        extend_pcr.assert_not_called()
        self.assertIn(
            "continuing because TEMENOS_ALLOW_PCR15_FAILURE is enabled",
            stderr.getvalue(),
        )

    @mock.patch.object(measured_setup, "read_pcr")
    def test_debug_override_requires_exact_value_one(self, read_pcr):
        read_pcr.return_value = b"\x01" * measured_setup.SHA256_DIGEST_SIZE

        with mock.patch.dict(
            os.environ,
            {measured_setup.ALLOW_PCR15_FAILURE_ENV: "true"},
            clear=True,
        ):
            self.assert_fatal_setup(
                lambda: measured_setup.require_setup_pcr_extended(
                    15, self.hash_value
                ),
                "already has an unexpected value",
            )

    def test_main_stops_before_opening_app_disk_when_pcr_setup_fails(self):
        partition_uuids = [uuid.UUID(int=1), uuid.UUID(int=2)]
        dirty_pcr = b"\x03" * measured_setup.SHA256_DIGEST_SIZE

        with (
            mock.patch.object(
                measured_setup,
                "get_partition_uuid",
                side_effect=partition_uuids,
            ),
            mock.patch("builtins.open", mock.mock_open()),
            mock.patch.object(
                measured_setup, "read_pcr", return_value=dirty_pcr
            ),
            mock.patch.object(measured_setup, "tpm_extend_pcr") as extend_pcr,
            mock.patch.object(
                measured_setup, "verity_setup_open"
            ) as verity_open,
            mock.patch.object(
                measured_setup.subprocess, "check_call"
            ) as check_call,
        ):
            self.assert_fatal_setup(
                measured_setup.main,
                "already has an unexpected value",
            )

        extend_pcr.assert_not_called()
        verity_open.assert_not_called()
        check_call.assert_not_called()


class ProxyPolicyStartupTests(unittest.TestCase):
    def run_setup(self, output, fail_run=False):
        metadata = {"proxy_allowed_paths": ["/check", "/prove"]}

        def command(cmd, **kwargs):
            if cmd == "/root/run.d/main":
                self.assertFalse(output.exists(), "policy published before DApp startup")
                if fail_run:
                    raise measured_setup.subprocess.CalledProcessError(1, cmd)

        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(measured_setup, "PROXY_POLICY_PATH", output)
            )
            stack.enter_context(mock.patch("builtins.open", mock.mock_open()))
            stack.enter_context(
                mock.patch.object(Path, "read_text", return_value=json.dumps(metadata))
            )
            stack.enter_context(
                mock.patch.object(
                    measured_setup, "get_partition_uuid",
                    side_effect=[uuid.UUID(int=1), uuid.UUID(int=2)],
                )
            )
            for name in (
                "require_setup_pcr_extended", "start_egress_proxies",
                "umount", "verity_setup_close",
            ):
                stack.enter_context(mock.patch.object(measured_setup, name))
            for name in ("dm_exists", "is_mounted"):
                stack.enter_context(
                    mock.patch.object(measured_setup, name, return_value=True)
                )
            stack.enter_context(
                mock.patch.object(
                    measured_setup, "policy_from_metadata", return_value={"profile": "app"}
                )
            )
            stack.enter_context(
                mock.patch.object(
                    measured_setup, "validate_compose_file", return_value={"app"}
                )
            )
            stack.enter_context(
                mock.patch.object(
                    measured_setup, "install_from_metadata",
                    return_value={"outbound": [], "platform_outbound": []},
                )
            )
            stack.enter_context(mock.patch.object(measured_setup.shutil, "rmtree"))
            stack.enter_context(mock.patch.object(measured_setup.shutil, "copytree"))
            stack.enter_context(
                mock.patch.object(
                    measured_setup, "write_compose_egress_override",
                    return_value=Path("override.yml"),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    measured_setup.subprocess, "check_call", side_effect=command
                )
            )
            measured_setup.main()

    def test_successful_setup_publishes_routes_after_startup(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "policy.json"
            self.run_setup(output)
            self.assertEqual(
                json.loads(output.read_text()),
                {"version": 1, "allowed_paths": ["/check", "/prove"]},
            )

    def test_failed_startup_removes_stale_policy_and_leaves_routes_disabled(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "policy.json"
            output.write_text('{"version":1,"allowed_paths":["/admin"]}')
            with self.assertRaises(measured_setup.subprocess.CalledProcessError):
                self.run_setup(output, fail_run=True)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
