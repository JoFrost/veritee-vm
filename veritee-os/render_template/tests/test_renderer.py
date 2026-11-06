import contextlib
import io
from pathlib import Path
import stat
import tempfile
import unittest

from jinja2 import UndefinedError

from render_template.__main__ import main, render_template


class TemplateFileTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.profile = self.root / "profile.yaml"
        self.profile.write_text("name: Veritee\n", encoding="utf-8")

    def test_absolute_template_resolves_includes_beside_it(self):
        folder = self.root / "nested"
        folder.mkdir()
        (folder / "part.j2").write_text("Olá {{ name }}", encoding="utf-8")
        source = folder / "service.conf.j2"
        source.write_text("{% include 'part.j2' %}\n", encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            render_template(self.profile, source)
        self.assertEqual((folder / "service.conf").read_bytes(), "Olá Veritee".encode())
        self.assertTrue(source.exists())

    def test_missing_variable_preserves_existing_output(self):
        source = self.root / "service.j2"
        source.write_text("{{ missing }}")
        output = self.root / "service"
        output.write_bytes(b"previous output")
        with self.assertRaises(UndefinedError):
            render_template(self.profile, source)
        self.assertEqual(output.read_bytes(), b"previous output")

    def test_non_mapping_profiles_are_rejected_without_output(self):
        source = self.root / "service.j2"
        source.write_text("constant template")
        for contents in ("", "a scalar", "- a list", "1: non-string key"):
            with self.subTest(profile=contents):
                self.profile.write_text(contents)
                with self.assertRaisesRegex(ValueError, "mapping with string keys"):
                    render_template(self.profile, source)
                self.assertFalse((self.root / "service").exists())

    def test_non_template_file_is_not_overwritten(self):
        source = self.root / "service.conf"
        source.write_bytes(b"original config")
        with self.assertRaisesRegex(ValueError, r"\.j2"):
            render_template(self.profile, source)
        self.assertEqual(source.read_bytes(), b"original config")

    def test_existing_output_permissions_are_preserved(self):
        source = self.root / "script.j2"
        source.write_text("echo {{ name }}")
        output = self.root / "script"
        output.write_text("old script")
        output.chmod(0o755)
        with contextlib.redirect_stdout(io.StringIO()):
            render_template(self.profile, source)
        self.assertEqual(output.read_text(), "echo Veritee")
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o755)

    def test_cli_reports_invalid_yaml_without_a_traceback(self):
        self.profile.write_text("name: [")
        source = self.root / "service.j2"
        source.write_text("{{ name }}")
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors), self.assertRaises(SystemExit) as exit:
            main([str(self.profile), str(source)])
        self.assertEqual(exit.exception.code, 2)
        self.assertIn("error:", errors.getvalue())
        self.assertNotIn("Traceback", errors.getvalue())
        self.assertFalse((self.root / "service").exists())


if __name__ == "__main__":
    unittest.main()
