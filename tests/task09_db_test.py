"""Offline TASK 09 SQLite, identity, and allocation tests; no VPS or AWG calls."""
import base64
from pathlib import Path
import tempfile
import unittest

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts' / 'task09'))
from manager_db import Refusal, Store, identity  # noqa: E402


def pub(number):
    return base64.b64encode(bytes([number]) * 32).decode()


class ManagerDbTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Store(Path(self.temp.name) / 'db' / 'manager.sqlite3',
                        enforce_ownership=False)
        self.addCleanup(self.db.close)

    def test_casefold_and_display_name(self):
        self.db.add_user('Ivan')
        self.assertEqual(self.db.user('ivan')['name'], 'Ivan')
        with self.assertRaises(Refusal) as error:
            self.db.add_user('IVAN')
        self.assertEqual(error.exception.code, 'name_conflict')

    def test_unicode_normalization_and_safe_profile_components(self):
        self.db.add_user('Иван')
        with self.assertRaises(Refusal):
            self.db.add_user('иВАН')
        self.assertEqual(identity('Ａｎｎａ'), ('Anna', 'anna'))
        for bad in ('Ivan_2', 'A/B', 'A B', '.hidden', '1Ivan'):
            with self.assertRaises(Refusal):
                identity(bad)

    def test_legacy_identity_and_new_allocation_do_not_collide(self):
        self.db.add_user('Test')
        legacy = self.db.add_device('Test', 'iPhone', pub(1),
                                    '/etc/vpn-task07/client.key', origin='task07',
                                    ipv4='10.203.253.2')
        self.assertEqual(legacy['profile_name'], 'Test_iPhone')
        self.db.add_user('Ivan')
        new = self.db.add_device('Ivan', 'MacBook', pub(2), '/etc/vpn-task09/devices/x/private.key')
        self.assertEqual(new['ipv4'], '10.203.253.3')
        self.assertEqual(new['profile_name'], 'Ivan_MacBook')
        with self.assertRaises(Refusal):
            self.db.add_device('Ivan', 'iPad', pub(1), '/etc/vpn-task09/devices/y/private.key')

    def test_device_and_user_disable_affect_desired_peers(self):
        self.db.add_user('Ivan')
        one = self.db.add_device('Ivan', 'iPhone', pub(3), '/x/one')
        two = self.db.add_device('Ivan', 'MacBook', pub(4), '/x/two')
        self.assertEqual(len(self.db.desired_peers()), 2)
        self.db.set_device_state('Ivan', 'iPhone', 'disabled')
        self.assertEqual(self.db.desired_peers(), {two['public_key']: two['ipv4'] + '/32'})
        self.db.set_user_state('Ivan', 'disabled')
        self.assertEqual(self.db.desired_peers(), {})
        self.db.set_user_state('Ivan', 'enabled')
        self.assertEqual(len(self.db.desired_peers()), 1)
        self.assertNotIn(one['public_key'], self.db.desired_peers())

    def test_revoke_and_delete_are_not_reusable(self):
        self.db.add_user('Ivan')
        self.db.add_device('Ivan', 'iPhone', pub(5), '/x/one')
        self.db.set_device_state('Ivan', 'iPhone', 'revoked')
        with self.assertRaises(Refusal) as error:
            self.db.set_device_state('Ivan', 'iPhone', 'enabled')
        self.assertEqual(error.exception.code, 'revoked')
        with self.assertRaises(Refusal):
            self.db.add_device('Ivan', 'iPhone', pub(6), '/x/two')
        self.db.set_user_state('Ivan', 'deleted')
        with self.assertRaises(Refusal):
            self.db.add_user('ivan')
        self.assertTrue(self.db.integrity_check())

    def test_effective_speed_limit_is_stored_but_not_enforced(self):
        self.db.add_user('Ivan')
        row = self.db.add_device('Ivan', 'iPhone', pub(7), '/x/one')
        self.db.set_limit('user', 'Ivan', None, 5_000_000, 10_000_000)
        self.db.set_limit('device', 'Ivan', 'iPhone', 2_000_000, 20_000_000)
        self.assertEqual(self.db.effective_limits(row['id']),
                         {'up_bps': 2_000_000, 'down_bps': 10_000_000,
                          'enforced': False})


if __name__ == '__main__':
    unittest.main()
