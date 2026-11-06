import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from typer.testing import CliRunner

from veritee import cli, os_release


REPOSITORY = Path(__file__).resolve().parents[2]


class CliRenameTests(unittest.TestCase):
    def test_guest_helper_keeps_the_published_default_and_image_overrides(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(cli.resolve_guest_attestation_image(None), cli.DEFAULT_GUEST_ATTESTATION_IMAGE)
            image = "registry.example/veritee/guest-attestation@sha256:" + "a" * 64
            os.environ["VERITEE_GUEST_ATTESTATION_IMAGE"] = image
            self.assertEqual(cli.resolve_guest_attestation_image(None), image)
            self.assertEqual(cli.resolve_guest_attestation_image("custom-image"), "custom-image")

    def test_installed_command_uses_the_veritee_cli(self):
        result = subprocess.run(
            [str(Path(sys.executable).parent / "veritee"), "--help"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Veritee VM", result.stdout)
        self.assertIn("package-dapp-deployable-vm-image", result.stdout)

    def test_old_command_and_package_are_not_installed(self):
        self.assertFalse((Path(sys.executable).parent / "temenos").exists())
        self.assertIsNone(importlib.util.find_spec("temenos"))

    def test_environment_names_and_os_release_compatibility(self):
        with mock.patch.dict(os.environ, {"TEMENOS_WARDEN_URL": "https://legacy.example"}, clear=True):
            with self.assertRaises(cli.DeployerException):
                cli.resolve_warden_endpoint(None)
            self.assertEqual(os_release.release_env("VERITEE_WARDEN_URL"), "https://legacy.example")
            os.environ["VERITEE_WARDEN_URL"] = "https://canonical.example"
            self.assertEqual(cli.resolve_warden_endpoint(None), "https://canonical.example")
            self.assertEqual(os_release.release_env("VERITEE_WARDEN_URL"), "https://canonical.example")
            os.environ["VERITEE_WARDEN_URL"] = ""
            with self.assertRaises(cli.DeployerException):
                cli.resolve_warden_endpoint(None)

    def test_existing_application_key_is_reused(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {}, clear=True):
            metadata = Path(directory) / "metadata.json"
            key_path = Path(directory) / "temenos_app_key"
            key_path.write_text("existing-fixture-application-identity\n")
            before = key_path.read_bytes()
            with mock.patch.object(cli.secrets, "token_hex") as generate:
                self.assertEqual(cli.resolve_app_key(metadata, None), before.decode().strip())
            generate.assert_not_called()
            self.assertEqual(key_path.read_bytes(), before)

    def test_plain_tpm_flag_is_removed_before_any_build(self):
        with mock.patch.object(cli, "run_streamable_command") as build:
            result = CliRunner().invoke(cli.app, ["build-base-os-image", "--tpm"])
        self.assertNotEqual(result.exit_code, 0)
        build.assert_not_called()
        help_result = CliRunner().invoke(cli.app, ["build-base-os-image", "--help"])
        self.assertIn("--azuresnp", help_result.stdout)
        self.assertNotIn("--tpm", help_result.stdout)

    def test_azure_modes_use_the_renamed_base_target_and_output(self):
        for mode in ("maa", "raw-sev-snp"):
            with self.subTest(mode=mode), \
                    mock.patch.object(cli, "run_streamable_command") as build, \
                    mock.patch.object(os_release, "source_identity", return_value={"modified": False}), \
                    mock.patch.object(os_release, "record_build"), \
                    mock.patch.object(cli, "write_pcr_measurements") as measurements, \
                    mock.patch.object(cli, "write_os_security_files"):
                result = CliRunner().invoke(cli.app, ["build-base-os-image", "--azuresnp", "--attestation-mode", mode])
                self.assertEqual(result.exit_code, 0, result.exception)
                command = build.call_args.args[0]
                self.assertIn("+veritee-os-azure-snp", command)
                self.assertIn("--ATTESTATION_MODE=" + mode, command)
                self.assertIn("--OS_CONFIG=config-azure.yaml", command)
                self.assertEqual(measurements.call_args.args[0], Path.cwd() / "local-base-os/disk.raw")
                self.assertEqual(measurements.call_args.args[2], "azure-snp")

    def test_packager_targets_exist_without_a_plain_tpm_target(self):
        text = (REPOSITORY / "Earthfile").read_text()
        for name in ("veritee-os-azure-snp", "veritee-os-azure-snp-combined", cli.EARTHLY_EXTEND_OS_TARGET, cli.EARTHLY_APP_DISK_TARGET):
            self.assertIn("\n" + name + ":\n", text)
        self.assertNotIn("\ntemen-os-tpm:\n", text)
        self.assertNotIn("\nveritee-os-tpm:\n", text)

    def test_manifest_keeps_the_actual_recipe_for_new_and_historical_build_records(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "disk.raw").write_bytes(b"fixture-base-os")
            (output / "pcrs.json").write_text(json.dumps({"measurements": {"4": "a" * 64}}))
            source = {"commit": "b" * 40, "tree": "c" * 40, "modified": False}
            for target, configuration in (
                ("+veritee-os-azure-snp", "config-azure.yaml"),
                ("+veritee-os-azure-snp", "config-snp-azure.yaml"),
                ("+temen-os-tpm", "config-snp-azure.yaml"),
            ):
                with self.subTest(target=target, configuration=configuration):
                    command = cli.build_earthly_base_os_command(
                        os_config=configuration, attestation_mode=cli.AttestationMode.MAA,
                        allow_unbound_attestation=False,
                    )
                    command[3] = target
                    with mock.patch.object(os_release, "source_identity", return_value=source):
                        os_release.record_build(output, output, source, command, "maa")
                    manifest = os_release.create_manifest(
                        output, "fixture-release", "0.6.0", "registry.example/os@sha256:" + "d" * 64,
                        "https://example.test/source",
                    )
                    self.assertEqual(manifest["build"]["earthly_target"], target)
                    self.assertEqual(manifest["build"]["configuration"], configuration)


if __name__ == "__main__":
    unittest.main()
