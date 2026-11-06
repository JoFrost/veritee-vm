import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import mock_open, patch


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "veritee_attestation/document.py"
VECTORS = json.loads((Path(__file__).parent / "fixtures/measurement-v1.json").read_text())


def load_generator():
    spec = importlib.util.spec_from_file_location("generator_under_test", SOURCE)
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", [str(SOURCE.parent), *sys.path]):
        spec.loader.exec_module(module)
    return module


class MeasurementTests(unittest.TestCase):
    def setUp(self):
        self.generator = load_generator()
        self.app_root = bytes.fromhex(VECTORS["app_root_hash"])
        self.setup_pcr = bytes.fromhex(VECTORS["setup_pcr15"])

    def test_import_has_no_guest_side_effects(self):
        with patch("builtins.open") as files, patch("subprocess.run") as process:
            load_generator()
        files.assert_not_called()
        process.assert_not_called()

    def test_setup_and_internal_tls_match_frozen_vectors(self):
        generator = self.generator
        self.assertEqual(generator.expected_setup_pcr(self.app_root), self.setup_pcr)
        digest = generator.measurement_hash_for_internal_tls_evidence(VECTORS["internal_ca_input"])
        self.assertEqual(digest.hex(), VECTORS["internal_tls_digest"])
        self.assertEqual(
            generator.simulate_tpm_extend(self.setup_pcr, digest).hex(),
            VECTORS["internal_final_pcr15"],
        )
        self.assertNotEqual(
            generator.measurement_hash_for_internal_tls_evidence(VECTORS["internal_ca_input"].rstrip()),
            digest,
        )

    def test_spki_evidence_matches_frozen_vector_independent_of_key_order(self):
        evidence = VECTORS["spki_evidence"]
        digest = self.generator.measurement_hash_for_tls_evidence(evidence)
        self.assertEqual(digest.hex(), VECTORS["spki_tls_digest"])
        self.assertEqual(
            self.generator.simulate_tpm_extend(self.setup_pcr, digest).hex(),
            VECTORS["spki_final_pcr15"],
        )
        reversed_keys = dict(reversed(list(evidence.items())))
        self.assertEqual(self.generator.measurement_hash_for_tls_evidence(reversed_keys), digest)
        changed = {**evidence, "connect_port": 8443}
        self.assertNotEqual(self.generator.measurement_hash_for_tls_evidence(changed), digest)

    def test_extend_rejects_wrong_digest_lengths(self):
        for pcr, digest in [(bytes(31), bytes(32)), (bytes(32), bytes(33))]:
            with self.subTest(pcr_length=len(pcr), digest_length=len(digest)):
                with self.assertRaises(ValueError):
                    self.generator.simulate_tpm_extend(pcr, digest)

    def test_tls_extension_runs_once_and_verifies_the_result(self):
        digest = bytes.fromhex(VECTORS["internal_tls_digest"])
        final = bytes.fromhex(VECTORS["internal_final_pcr15"])
        with patch.object(self.generator, "read_pcr", side_effect=[self.setup_pcr, final]), \
                patch.object(self.generator, "tpm_extend_pcr") as extend:
            self.generator.ensure_tls_evidence_pcr_extended_once(15, self.app_root, digest)
        extend.assert_called_once_with(15, digest)

    def test_completed_tls_extension_is_not_repeated(self):
        digest = bytes.fromhex(VECTORS["internal_tls_digest"])
        final = bytes.fromhex(VECTORS["internal_final_pcr15"])
        with patch.object(self.generator, "read_pcr", return_value=final), \
                patch.object(self.generator, "tpm_extend_pcr") as extend:
            self.generator.ensure_tls_evidence_pcr_extended_once(15, self.app_root, digest)
        extend.assert_not_called()

    def test_unexpected_initial_pcr_is_rejected_without_modification(self):
        digest = bytes.fromhex(VECTORS["internal_tls_digest"])
        with patch.object(self.generator, "read_pcr", return_value=bytes(32)), \
                patch.object(self.generator, "tpm_extend_pcr") as extend:
            with self.assertRaisesRegex(RuntimeError, "unexpected value before TLS"):
                self.generator.ensure_tls_evidence_pcr_extended_once(15, self.app_root, digest)
        extend.assert_not_called()

    def test_wrong_pcr_after_extend_is_rejected(self):
        digest = bytes.fromhex(VECTORS["internal_tls_digest"])
        with patch.object(self.generator, "read_pcr", side_effect=[self.setup_pcr, bytes(32)]), \
                patch.object(self.generator, "tpm_extend_pcr") as extend:
            with self.assertRaisesRegex(RuntimeError, "TLS evidence extension mismatch"):
                self.generator.ensure_tls_evidence_pcr_extended_once(15, self.app_root, digest)
        extend.assert_called_once_with(15, digest)

    def test_bad_or_unreadable_pcr_prevents_extension(self):
        for error in [OSError("TPM unavailable"), ValueError("PCR output malformed")]:
            with self.subTest(error=type(error).__name__):
                with patch.object(self.generator, "read_pcr", side_effect=error), \
                        patch.object(self.generator, "tpm_extend_pcr") as extend:
                    with self.assertRaises(type(error)):
                        self.generator.ensure_tls_evidence_pcr_extended_once(15, self.app_root, bytes(32))
                extend.assert_not_called()

    def test_nv_certificate_extraction_removes_padding_and_rejects_truncation(self):
        der = b"\x30\x03abc"
        self.assertEqual(self.generator.extract_first_der_x509(b"\0\0" + der + b"padding"), der)
        for blob in [b"", b"\x31\x03abc", b"\x30\x80ab", b"\x30\x05abc"]:
            with self.subTest(blob=blob):
                with self.assertRaises(ValueError):
                    self.generator.extract_first_der_x509(blob)


class PayloadTests(unittest.TestCase):
    def setUp(self):
        self.generator = load_generator()
        self.root_text = VECTORS["app_root_hash"] + "\n"
        self.chain = ["fixture-aik", "fixture-intermediate", "fixture-root"]
        self.quote = {"message": "fixture-message", "signature": "fixture-signature", "pcr": "fixture-pcr"}

    def make_payload(self, mode):
        calls = []
        generator = self.generator
        with patch.dict("os.environ", {"TEMENOS_TLS_EVIDENCE_MODE": mode}), \
                patch("builtins.open", mock_open(read_data=self.root_text)), \
                patch.object(generator, "get_cert_chain", side_effect=lambda: calls.append("certificates") or self.chain), \
                patch.object(generator, "get_caddy_rootca", return_value=VECTORS["internal_ca_input"]), \
                patch.object(generator, "get_tls_spki_evidence", return_value=VECTORS["spki_evidence"]), \
                patch.object(generator, "ensure_tls_evidence_pcr_extended_once", side_effect=lambda *args: calls.append(("extend", args))), \
                patch.object(generator, "get_quote", side_effect=lambda: calls.append("quote") or self.quote):
            payload = generator.build_attestation_payload()
        return payload, calls

    def test_internal_payload_preserves_fields_and_extension_before_quote(self):
        payload, calls = self.make_payload("internal")
        self.assertEqual(payload, VECTORS["internal_payload"])
        self.assertEqual(list(payload), list(VECTORS["internal_payload"]))
        self.assertEqual(calls, ["certificates", ("extend", (
            15, bytes.fromhex(VECTORS["app_root_hash"]), bytes.fromhex(VECTORS["internal_tls_digest"])
        )), "quote"])

    def test_spki_payload_preserves_fields_and_extension_before_quote(self):
        payload, calls = self.make_payload(" SPKI ")
        self.assertEqual(payload, VECTORS["spki_payload"])
        self.assertEqual(list(payload), list(VECTORS["spki_payload"]))
        self.assertEqual(calls, ["certificates", ("extend", (
            15, bytes.fromhex(VECTORS["app_root_hash"]), bytes.fromhex(VECTORS["spki_tls_digest"])
        )), "quote"])

    def test_unsupported_mode_never_extends_or_quotes(self):
        with patch.dict("os.environ", {"TEMENOS_TLS_EVIDENCE_MODE": "unsupported"}), \
                patch("builtins.open", mock_open(read_data=self.root_text)), \
                patch.object(self.generator, "get_cert_chain", return_value=self.chain), \
                patch.object(self.generator, "ensure_tls_evidence_pcr_extended_once") as extend, \
                patch.object(self.generator, "get_quote") as quote:
            with self.assertRaisesRegex(ValueError, "Unsupported TEMENOS_TLS_EVIDENCE_MODE"):
                self.generator.build_attestation_payload()
        extend.assert_not_called()
        quote.assert_not_called()

    def test_main_keeps_output_path_and_json_bytes(self):
        for mode in ("internal", "spki"):
            with self.subTest(mode=mode):
                payload = VECTORS[mode + "_payload"]
                files = mock_open()
                with patch.object(self.generator, "build_attestation_payload", return_value=payload), \
                        patch("builtins.open", files):
                    self.generator.main()
                files.assert_called_once_with("/srv/attestation.json", "w")
                written = "".join(call.args[0] for call in files().write.call_args_list)
                self.assertEqual(written, VECTORS[mode + "_wire_json"])


if __name__ == "__main__":
    unittest.main()
