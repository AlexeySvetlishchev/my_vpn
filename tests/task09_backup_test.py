"""Offline backup and corruption checks with dummy files only."""
import base64
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts' / 'task09'))
from manager_db import Refusal, Store  # noqa: E402
from manager_backup import check_backup, make_backup, stage_restore  # noqa: E402


def pub(number):
    return base64.b64encode(bytes([number]) * 32).decode()


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.db = Store(root / 'manager.sqlite3', enforce_ownership=False)
        self.addCleanup(self.db.close)
        self.legacy = root / 'legacy'
        self.legacy.mkdir()
        self.keys = root / 'keys'
        self.keys.mkdir()
        self.backups = root / 'backups'
        for name in ('server.key', 'client.key', 'client.pub', 'Test_iPhone.conf'):
            (self.legacy / name).write_bytes(('dummy-' + name).encode())
        (self.legacy / 'client.pub').write_text(pub(1) + '\n')
        self.db.add_user('Test')
        self.db.add_device('Test','iPhone',pub(1),str(self.legacy / 'client.key'),
                           origin='task07',ipv4='10.203.253.2')
        self.db.add_user('Ivan')
        record = self.db.add_device('Ivan','MacBook',pub(2),
                                    str(self.keys / ('a'*32) / 'private.key'),
                                    device_id='a'*32)
        folder = self.keys / record['id']
        folder.mkdir()
        (folder / 'private.key').write_bytes(b'dummy-new-client-secret')

    def make(self):
        return make_backup(self.db, destination=self.backups, legacy=self.legacy,
                           device_keys=self.keys, enforce_ownership=False)

    def test_backup_checks_db_and_all_referenced_secrets(self):
        result = self.make()
        self.assertFalse(result['encrypted'])
        self.assertEqual(check_backup(result['path'])['files'], 6)
        self.assertTrue(self.db.integrity_check())

    def test_corruption_is_detected(self):
        result = self.make()
        path = Path(result['path'])
        with tarfile.open(path) as archive:
            member = archive.getmember('legacy/client.key')
            offset = member.offset_data
        data = bytearray(path.read_bytes())
        data[offset] ^= 1
        corrupt = self.backups / 'corrupt.tar'
        corrupt.write_bytes(data)
        with self.assertRaises(Refusal) as error:
            check_backup(corrupt)
        self.assertEqual(error.exception.code, 'backup_integrity')

    def test_restore_stages_without_replacing_live_database(self):
        result = self.make()
        original = self.db.path.read_bytes()
        staged = stage_restore(result['path'], destination=Path(self.temp.name) / 'stage',
                               enforce_ownership=False)
        self.assertFalse(staged['live_state_changed'])
        self.assertTrue((Path(staged['staged_path']) / 'legacy' / 'client.key').exists())
        self.assertEqual(self.db.path.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
