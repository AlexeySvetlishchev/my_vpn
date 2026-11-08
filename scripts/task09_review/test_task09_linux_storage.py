import os
import fcntl
from unittest import mock
from pathlib import Path
import tempfile
import unittest
from task09_linux_storage import DurableStorage, OWNED_MODES

class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        names = {key: self.root / key for key in OWNED_MODES}
        for name, target in names.items():
            target.write_bytes(name.encode())
            target.chmod(OWNED_MODES[name])
        (self.root/'active.json').write_text('{"own_table_sha256": "original"}\n')
        (self.root/'active.json').chmod(0o600)
        self.b = DurableStorage(self.root, names, require_root=False)

    def test_read_and_atomic_replace(self):
        with self.b.lock_all():
            before = self.b.read_file('vpn-task07')
            self.b.replace_file('vpn-task07', b'after')
            self.assertNotEqual(before, self.b.read_file('vpn-task07'))
            self.assertEqual(self.b.read_file('vpn-task07'), b'after')
            self.assertEqual((self.root/'vpn-task07').stat().st_mode & 0o777, 0o755)

    def test_journal_roundtrip(self):
        with self.b.lock_all():
            self.assertIsNone(self.b.journal_read())
            self.b.journal_write({'state': 'prepared'})
            self.assertEqual(self.b.journal_read(), {'state': 'prepared'})
            self.b.journal_clear()
            self.assertIsNone(self.b.journal_read())

    def test_ledger_roundtrip(self):
        with self.b.lock_all():
            self.b.ledger_write({'own_table_sha256': 'new'})
            self.assertEqual(self.b.ledger_read()['own_table_sha256'], 'new')

    def test_rejects_wrong_permissions(self):
        (self.root/'vpn-task07').chmod(0o777)
        with self.assertRaises(ValueError):
            self.b.read_file('vpn-task07')

    def test_refuses_symlink(self):
        (self.root/'vpn-task07').unlink()
        (self.root/'vpn-task07').symlink_to(self.root/'apply.py')
        with self.assertRaises(ValueError):
            self.b.replace_file('vpn-task07', b'new')

    def test_lock_conflict(self):
        with self.b.lock_all():
            other = DurableStorage(self.root, self.b.files, require_root=False)
            with self.assertRaises(BlockingIOError):
                with other.lock_all(): pass

    def test_prefix_updater_lock_is_shared(self):
        # Model the exact updater primitive: open ROOT/ru-prefix-update.lock,
        # then take flock(LOCK_EX|LOCK_NB).
        fd = os.open(self.root/'ru-prefix-update.lock', os.O_CREAT|os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                with self.b.lock_all(): pass
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        self.assertEqual(self.b.prefix_lock, self.root/'ru-prefix-update.lock')

    def test_write_failure_before_rename_keeps_previous_file(self):
        before = self.b.read_file('vpn-task07')
        with mock.patch('task09_linux_storage.os.replace', side_effect=OSError('injected')):
            with self.assertRaises(OSError):
                self.b.replace_file('vpn-task07', b'new-complete-content')
        self.assertEqual(self.b.read_file('vpn-task07'), before)
        self.assertFalse(list(self.root.glob('vpn-task07.task09-*')))

    def test_directory_fsync_failure_reports_after_atomic_publish(self):
        before = self.b.read_file('vpn-task07')
        with mock.patch.object(DurableStorage, '_fsync_dir', side_effect=OSError('injected')):
            with self.assertRaises(OSError):
                self.b.replace_file('vpn-task07', b'complete-new-content')
        # Rename is already atomic and visible. Caller must recover from its
        # durable journal; the file is never observed partially written.
        self.assertNotEqual(self.b.read_file('vpn-task07'), before)
        self.assertEqual(self.b.read_file('vpn-task07'), b'complete-new-content')

if __name__=='__main__': unittest.main()
