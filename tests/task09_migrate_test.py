"""Offline legacy import tests using public-only dummy identity."""
import base64
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts' / 'task09'))
from manager_db import Refusal, Store  # noqa: E402
import manager_migrate  # noqa: E402


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.store = Store(self.base / 'manager.sqlite3', enforce_ownership=False)
        self.addCleanup(self.store.close)
        self.public = base64.b64encode(b'p' * 32).decode()
        (self.base / 'client.pub').write_text(self.public + '\n')

    def import_record(self):
        with patch.object(manager_migrate, 'LEGACY', self.base), patch.object(
                manager_migrate, 'preflight', return_value={'live_peer_count': 1}):
            return manager_migrate.import_record(self.store)

    def test_import_is_idempotent_and_preserves_identity(self):
        self.assertFalse(self.import_record()['already_imported'])
        self.assertTrue(self.import_record()['already_imported'])
        old = self.store.device('Test', 'iPhone')
        self.assertEqual(old['public_key'], self.public)
        self.assertEqual(old['ipv4'], '10.203.253.2')
        self.assertEqual(len(self.store.list_devices()), 1)

    def test_conflicting_database_is_refused(self):
        self.store.add_user('Other')
        with self.assertRaises(Refusal) as error:
            self.import_record()
        self.assertEqual(error.exception.code, 'import_conflict')


if __name__ == '__main__':
    unittest.main()
