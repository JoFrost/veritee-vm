import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml
from render_template.__main__ import render


REPO_ROOT = Path(__file__).resolve().parents[3]
ROOTFS = REPO_ROOT / "veritee-os" / "mkosi" / "rootfs"


def load_profile(name: str) -> dict:
    with (REPO_ROOT / "veritee-os" / name).open(encoding="utf-8") as config:
        return yaml.safe_load(config)


def render_profile(template_path: Path, profile: dict) -> str:
    return render(profile, template_path.name, str(template_path.parent))


def active_setting(rendered: str, name: str) -> str:
    prefix = f"{name}="
    matches = [line for line in rendered.splitlines() if line.startswith(prefix)]
    if len(matches) != 1:
        raise AssertionError(f"expected one active {name} setting, got {matches}")
    return matches[0]


def assert_default_deny_egress(test_case: unittest.TestCase, profile: dict) -> None:
    for family in ("v4", "v6"):
        with test_case.subTest(family=family):
            rendered = render_profile(
                ROOTFS / "mkosi.extra" / "etc" / "iptables" / f"rules.{family}.j2",
                profile,
            )
            test_case.assertIn(
                "-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
                rendered,
            )
            test_case.assertIn("-A OUTPUT -j TEMENOS-APP-OUTBOUND", rendered)
            test_case.assertIn("-A OUTPUT -j DROP", rendered)
            test_case.assertIn("-A TEMENOS-CONTAINER-EGRESS -j DROP", rendered)


def assert_firewall_syntax(test_case: unittest.TestCase, profile: dict) -> None:
    for family, parser in (
        ("v4", "iptables-restore-translate"),
        ("v6", "ip6tables-restore-translate"),
    ):
        with test_case.subTest(family=family):
            rendered = render_profile(
                ROOTFS / "mkosi.extra" / "etc" / "iptables" / f"rules.{family}.j2",
                profile,
            )
            with tempfile.NamedTemporaryFile(mode="w") as rules_file:
                rules_file.write(rendered)
                rules_file.flush()
                result = subprocess.run(
                    [parser, "-f", rules_file.name],
                    check=False,
                    capture_output=True,
                    text=True,
                )
            test_case.assertEqual(result.returncode, 0, result.stderr)


class ReleaseOsProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = load_profile("config-azure.yaml")

    def test_release_kernel_has_no_serial_console(self):
        rendered = render_profile(ROOTFS / "mkosi.conf.j2", self.profile)
        self.assertNotIn("console=ttyS0", active_setting(rendered, "KernelCommandLine"))

    def test_release_firewall_does_not_allow_ssh(self):
        for family in ("v4", "v6"):
            with self.subTest(family=family):
                rendered = render_profile(
                    ROOTFS / "mkosi.extra" / "etc" / "iptables" / f"rules.{family}.j2",
                    self.profile,
                )
                self.assertNotIn("--dport 22", rendered)

    def test_release_firewall_keeps_default_deny_egress(self):
        assert_default_deny_egress(self, self.profile)

    def test_release_firewall_has_valid_iptables_syntax(self):
        assert_firewall_syntax(self, self.profile)

    def test_release_image_omits_debug_services(self):
        rendered = render_profile(ROOTFS / "copy_services.sh.j2", self.profile)
        self.assertNotIn("start_ssh.service", rendered)
        self.assertNotIn("restart-serial-console.service", rendered)


class DebugOsProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile = load_profile("config-azure.debug.yaml")

    def test_debug_kernel_has_serial_console(self):
        rendered = render_profile(ROOTFS / "mkosi.conf.j2", self.profile)
        self.assertIn("console=ttyS0", active_setting(rendered, "KernelCommandLine"))

    def test_debug_firewall_allows_ssh(self):
        for family in ("v4", "v6"):
            with self.subTest(family=family):
                rendered = render_profile(
                    ROOTFS / "mkosi.extra" / "etc" / "iptables" / f"rules.{family}.j2",
                    self.profile,
                )
                self.assertIn("--dport 22", rendered)

    def test_debug_firewall_keeps_default_deny_egress(self):
        assert_default_deny_egress(self, self.profile)

    def test_debug_firewall_has_valid_iptables_syntax(self):
        assert_firewall_syntax(self, self.profile)

    def test_debug_image_includes_debug_services(self):
        rendered = render_profile(ROOTFS / "copy_services.sh.j2", self.profile)
        self.assertIn("start_ssh.service", rendered)
        self.assertIn("restart-serial-console.service", rendered)
        self.assertIn("multi-user.target.wants/start_ssh.service", rendered)
        self.assertIn(
            "multi-user.target.wants/restart-serial-console.service", rendered
        )


if __name__ == "__main__":
    unittest.main()
