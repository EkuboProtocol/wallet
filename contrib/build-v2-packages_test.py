#!/usr/bin/env python3
"""Mechanical packaging checks; never installs packages or operates host services."""

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "builder", Path(__file__).with_name("build-v2-packages.py"))
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class LinuxPackagingTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="wallet-packaging-test-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.output = self.work / "release"
        self.output.mkdir()
        for name in builder.BINARIES:
            (self.output / name).write_bytes(b"unchanged release binary: " + name.encode())

    def test_deb_and_arch_have_identical_payload_bytes_and_modes(self):
        deb_files = {}

        def capture_deb(command, **kwargs):
            root = Path(command[3])
            for path in (root / "usr").rglob("*"):
                if path.is_file():
                    deb_files[str(path.relative_to(root))] = (
                        path.read_bytes(), path.stat().st_mode & 0o777)

        with patch.object(builder.subprocess, "check_output", return_value="shlibs:Depends=libc6\n"), \
                patch.object(builder.subprocess, "run", side_effect=capture_deb):
            builder.deb("2.0.0", self.output)
        builder.stage_arch_build("2.0.0", self.output, self.work)
        with tarfile.open(self.work / "payload.tar") as archive:
            arch_files = {item.name: (archive.extractfile(item).read(), item.mode)
                          for item in archive if item.isfile()}
            self.assertTrue(all(item.uid == item.gid == 0 for item in archive))
        self.assertEqual(deb_files, arch_files)
        self.assertEqual(arch_files["usr/bin/ekubo-wallet-v2"][1], 0o755)
        self.assertIn("usr/share/licenses/ekubo-wallet-v2/LICENSE", arch_files)
        self.assertIn("usr/share/licenses/ekubo-wallet-v2/THIRD_PARTY_LICENSES.md", arch_files)
        self.assertFalse(any(name.startswith(("etc/", "var/")) for name in arch_files))

    @unittest.skipUnless(os.geteuid() != 0 and all(shutil.which(tool) for tool in
                        ("makepkg", "bsdtar", "fakeroot", "zstd")),
                        "native makepkg tools and a non-root user required")
    def test_makepkg_creates_native_metadata_and_preserves_binary(self):
        builder.arch("2.0.0", self.output)
        package = self.output / "ekubo-wallet-v2-2.0.0-1-x86_64.pkg.tar.zst"
        info = subprocess.check_output(["bsdtar", "-xOf", str(package), ".PKGINFO"], text=True)
        self.assertIn("pkgname = ekubo-wallet-v2\n", info)
        self.assertIn("pkgver = 2.0.0-1\n", info)
        self.assertIn("arch = x86_64\n", info)
        self.assertIn("depend = python\n", info)
        members = subprocess.check_output(["bsdtar", "-tf", str(package)], text=True).splitlines()
        self.assertTrue({".PKGINFO", ".BUILDINFO", ".MTREE", ".INSTALL"}.issubset(members))
        actual = subprocess.check_output(["bsdtar", "-xOf", str(package), "usr/bin/ekubo-wallet-v2"])
        self.assertEqual(actual, (self.output / "ekubo-wallet-v2").read_bytes())
        install = subprocess.check_output(["bsdtar", "-xOf", str(package), ".INSTALL"])
        self.assertEqual(install, (builder.ROOT / "contrib/arch-v2.install").read_bytes())

    def test_root_is_rejected_before_staging(self):
        with patch.object(builder.os, "geteuid", return_value=0), \
                patch.object(builder, "stage_arch_build") as stage:
            with self.assertRaises(PermissionError):
                builder.arch("2.0.0", self.output)
            stage.assert_not_called()


class ArchLifecycleTest(unittest.TestCase):
    def hook(self, name, fail=""):
        # Replace the single absolute helper invocation so no real host command
        # can run. All other external commands are shell-function test doubles.
        hooks = (builder.ROOT / "contrib/arch-v2.install").read_text().replace(
            "/usr/lib/ekubo-wallet-v2/install-profile", "restore_profile")
        mocks = """
record() { printf '%s\\n' "$*"; test "$1" != "$FAIL_COMMAND"; }
systemd-sysusers() { record sysusers "$@"; }
systemd-tmpfiles() { record tmpfiles "$@"; }
systemctl() { record systemctl "$@"; }
busctl() { record busctl "$@"; }
restore_profile() { record restore "$@"; }
"""
        return subprocess.run(["bash", "-c", mocks + hooks + f"\n{name} 2.0.0-1 2.0.0-0\n"],
                              env={**os.environ, "FAIL_COMMAND": fail},
                              capture_output=True, text=True)

    def test_install_and_upgrade_restore_then_only_try_restart_v2(self):
        install_expected = [
            "sysusers /usr/lib/sysusers.d/ekubo-wallet-v2.conf",
            "tmpfiles --create /usr/lib/tmpfiles.d/ekubo-wallet-v2.conf",
            "systemctl daemon-reload",
            "restore --restore-activations",
            "busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ReloadConfig",
            "systemctl try-restart ekubo-wallet-v2@*.service",
        ]
        upgrade_expected = [
            *install_expected,
            "systemctl stop ekubo-wallet-v2-provision@*.service",
        ]
        for hook, expected in (("post_install", install_expected),
                               ("post_upgrade", upgrade_expected)):
            result = self.hook(hook)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), expected)

    def test_failed_profile_restoration_prevents_restart(self):
        result = self.hook("post_upgrade", fail="restore")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("try-restart", result.stdout)
        self.assertNotIn("busctl", result.stdout)
        self.assertNotIn("stop", result.stdout)

    def test_remove_stops_only_v2_and_retains_profile_metadata(self):
        before = self.hook("pre_remove")
        self.assertEqual(before.returncode, 0, before.stderr)
        self.assertEqual(before.stdout.strip(),
                         "systemctl stop ekubo-wallet-v2@*.service ekubo-wallet-v2-provision@*.service")
        after = self.hook("post_remove")
        self.assertEqual(after.returncode, 0, after.stderr)
        self.assertIn("owner activation metadata retained", after.stdout)


if __name__ == "__main__":
    unittest.main()
