#!/usr/bin/env python3
"""Unprivileged temporary-tree regression tests; never installs on the host."""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

loader = importlib.machinery.SourceFileLoader(
    'install_profile', str(Path(__file__).with_name('install-profile')))
installer = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
loader.exec_module(installer)


class ActivationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='ewv2-activation-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in ['etc/owners', 'lib', 'system-services']:
            (self.root / name).mkdir(parents=True)
        self.account = SimpleNamespace(pw_uid=4321)
        self.metadata = self.root / 'etc/owners/1234.json'
        self.metadata.write_text(json.dumps(dict(owner_uid=1234, service_uid=4321,
                                                profile_id='08c0bc73-34ee-4d3a-b420-f67b6cfe9f55')))
        self.template = self.root / 'lib/org.ekubo.Wallet2.Owner.service.in'
        self.template.write_bytes(installer.ACTIVATION_TEMPLATE)
        self.target = self.root / 'system-services/org.ekubo.Wallet2.Owner.u1234.service'
        self.addCleanup(patch.stopall)
        patch.multiple(installer, ETC=self.root / 'etc', LIB=self.root / 'lib',
                       ACTIVATION=self.root / 'system-services', ROOT_UID=os.getuid()).start()
        # The test trust boundary is the temporary root. Only its outside
        # ancestors are synthetic; every tested directory/file uses real stat.
        real_lstat = Path.lstat
        ancestors = set(self.root.parents)

        def scoped_lstat(path):
            if path in ancestors:
                return SimpleNamespace(st_uid=os.getuid(), st_mode=stat.S_IFDIR | 0o755)
            return real_lstat(path)

        patch.object(Path, 'lstat', scoped_lstat).start()

    def publish(self):
        installer.publish_activation(1234, self.account)

    def test_exact_publication_and_idempotence(self):
        self.publish()
        before = self.target.stat()
        self.publish()
        self.assertEqual(before.st_ino, self.target.stat().st_ino)
        self.assertEqual(self.target.stat().st_nlink, 1)
        self.assertEqual(stat.S_IMODE(before.st_mode), 0o644)
        payload = self.target.read_text()
        self.assertIn('Name=org.ekubo.Wallet2.Owner.u1234\n', payload)
        self.assertIn('SystemdService=ekubo-wallet-v2@1234.service\n', payload)
        self.assertIn('User=ekubo-wallet-v2\n', payload)
        self.assertIn('Exec=/usr/bin/false\n', payload)
        self.assertNotIn('@OWNER_UID@', payload)
        self.assertEqual(list(self.target.parent.iterdir()), [self.target])

    def test_invalid_uids(self):
        for value in [0, -1, True, '01', '+1', '1\n', '1/2', '1.service',
                      '4294967295', '99999999999']:
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                installer.publish_activation(value, self.account)
        self.assertFalse(self.target.exists())

    def test_conflicting_file_is_not_replaced(self):
        self.target.write_bytes(b'conflict')
        before = self.target.stat()
        with self.assertRaises(RuntimeError):
            self.publish()
        self.assertEqual(self.target.read_bytes(), b'conflict')
        self.assertEqual(self.target.stat().st_ino, before.st_ino)

    def test_symlink_and_hardlink_are_not_accepted(self):
        self.target.symlink_to(self.root / 'missing')
        with self.assertRaises(OSError):
            self.publish()
        self.target.unlink()
        self.publish()
        os.link(self.target, self.root / 'other')
        with self.assertRaises(RuntimeError):
            self.publish()

    def test_bad_template_and_metadata(self):
        self.template.write_bytes(installer.ACTIVATION_TEMPLATE.replace(b'/usr/bin/false', b'/bin/sh'))
        with self.assertRaises(RuntimeError):
            self.publish()
        self.template.write_bytes(installer.ACTIVATION_TEMPLATE)
        for payload in [b'{}', b'{', b'{"owner_uid":1234,"owner_uid":1234}',
                        self.metadata.read_bytes().replace(b'4321', b'1234')]:
            self.metadata.write_bytes(payload)
            with self.assertRaises((RuntimeError, ValueError)):
                self.publish()
        self.assertFalse(self.target.exists())

    def test_writable_metadata_or_directory_refused(self):
        self.metadata.chmod(0o666)
        with self.assertRaises(RuntimeError):
            self.publish()
        self.metadata.chmod(0o644)
        self.target.parent.chmod(0o777)
        with self.assertRaises(RuntimeError):
            self.publish()

    def test_reinstall_regenerates_only_from_owner_metadata(self):
        with patch.object(installer.pwd, 'getpwnam', return_value=self.account):
            installer.restore_activations()
            expected = self.target.read_bytes()
            self.target.unlink()
            installer.restore_activations()
            self.assertEqual(self.target.read_bytes(), expected)
            installer.restore_activations()

    def test_interrupted_publication_is_resumable(self):
        with patch.object(installer.os, 'fsync', side_effect=OSError('file fsync failed')):
            with self.assertRaises(OSError):
                self.publish()
        self.assertFalse(self.target.exists())
        with patch.object(installer.os, 'fsync', side_effect=[None, OSError('directory fsync failed')]):
            with self.assertRaises(OSError):
                self.publish()
        self.assertEqual(self.target.stat().st_nlink, 1)
        self.publish()
        self.assertEqual(list(self.target.parent.iterdir()), [self.target])

    def test_stray_entry_error_names_offending_path(self):
        stray = self.root / 'etc/owners/stray.txt'
        stray.write_text('tamper')
        with patch.object(installer.pwd, 'getpwnam', return_value=self.account):
            with self.assertRaises(RuntimeError) as raised:
                installer.restore_activations()
        self.assertIn(str(stray), str(raised.exception))

    def test_bad_stem_error_names_offending_path(self):
        bad = self.root / 'etc/owners/evil.json'
        bad.write_text('{}')
        with patch.object(installer.pwd, 'getpwnam', return_value=self.account):
            with self.assertRaises(RuntimeError) as raised:
                installer.restore_activations()
        self.assertIn(str(bad), str(raised.exception))

    def test_reload_bus_failure_names_runtime(self):
        for failure in [subprocess.CalledProcessError(1, 'busctl'),
                        FileNotFoundError('No such file or directory')]:
            with self.subTest(failure=failure):
                with patch.object(installer.subprocess, 'run', side_effect=failure):
                    with self.assertRaises(RuntimeError) as raised:
                        installer.reload_bus()
                self.assertIn('D-Bus', str(raised.exception))


class UmaskTests(unittest.TestCase):
    """Behavioral guard: pkexec preserves the caller umask (and Arch polkit
    PAM has no pam_umask), so main() must reset it through _ensure_umask();
    every protected creation uses an explicit mode, so nothing depends on a
    stricter inherited umask."""

    @classmethod
    def setUpClass(cls):
        cls.source = Path(__file__).with_name('install-profile').read_text()

    def test_main_resets_umask_first(self):
        main = self.source.split('def main():', 1)[1].split('\ndef ', 1)[0]
        first = next(line.strip() for line in main.splitlines()
                     if line.strip() and not line.strip().startswith('#'))
        self.assertEqual(first, '_ensure_umask()')

    def test_ensure_umask_restores_secure_default(self):
        # Pure in-process: impose a hostile umask, call the helper, and read
        # back the live mask. No root, no filesystem.
        hostile = os.umask(0o077)
        try:
            returned = installer._ensure_umask()
            self.assertEqual(returned, 0o077)
            self.assertEqual(os.umask(0o022), 0o022)
        finally:
            os.umask(hostile)

    def test_all_protected_creations_use_explicit_modes(self):
        for marker in ['path.mkdir(mode=mode)',
                       'os.fchmod(output.fileno(), 0o644)',
                       'os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644',
                       'os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600']:
            with self.subTest(marker=marker):
                self.assertIn(marker, self.source)
        self.assertEqual(self.source.count('os.umask('), 1)


if __name__ == '__main__':
    unittest.main()
