"""TASK 09 peer reconciliation tests with an in-memory fake, never live AWG."""
import base64
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts' / 'task09'))
from manager_db import Refusal, Store  # noqa: E402
from manager_runtime import Controller  # noqa: E402


def pub(number):
    return base64.b64encode(bytes([number]) * 32).decode()


class FakeAwg:
    def __init__(self):
        self.live = {}
        self.events = []

    def peers(self):
        return dict(self.live)

    def metrics(self):
        return {}, {}

    def add(self, key, address):
        self.events.append(('add', key))
        self.live[key] = address

    def remove(self, key):
        self.events.append(('remove', key))
        self.live.pop(key)


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Store(Path(self.temp.name) / 'db.sqlite3', enforce_ownership=False)
        self.addCleanup(self.db.close)
        self.awg = FakeAwg()
        self.control = Controller(self.db, self.awg)
        self.db.add_user('Test')
        self.legacy = self.db.add_device('Test', 'iPhone', pub(1),
                                         '/etc/vpn-task07/client.key', origin='task07',
                                         ipv4='10.203.253.2')
        self.awg.live[pub(1)] = '10.203.253.2/32'

    def test_unknown_peer_blocks_every_mutation(self):
        self.awg.live[pub(9)] = '10.203.253.99/32'
        self.db.add_user('Ivan')
        self.db.add_device('Ivan', 'MacBook', pub(2), '/secret/x')
        with self.assertRaises(Refusal) as error:
            self.control.reconcile()
        self.assertEqual(error.exception.code, 'unknown_live_peer')
        self.assertEqual(self.awg.events, [])

    def test_new_peer_add_preserves_legacy_and_device_disable_removes_only_new(self):
        self.db.add_user('Ivan')
        self.db.add_device('Ivan', 'MacBook', pub(2), '/secret/x')
        self.control.reconcile()
        self.assertEqual(self.awg.live[pub(1)], '10.203.253.2/32')
        self.assertEqual(self.awg.live[pub(2)], '10.203.253.3/32')
        self.db.set_device_state('Ivan', 'MacBook', 'disabled')
        self.control.reconcile()
        self.assertEqual(self.awg.live, {pub(1): '10.203.253.2/32'})
        self.db.set_device_state('Ivan', 'MacBook', 'enabled')
        self.control.reconcile()
        self.assertIn(pub(2), self.awg.live)

    def test_wrong_ip_refused_without_replacing_peer(self):
        self.awg.live[pub(1)] = '10.203.253.99/32'
        with self.assertRaises(Refusal) as error:
            self.control.reconcile()
        self.assertEqual(error.exception.code, 'wrong_allowed_ips')
        self.assertEqual(self.awg.events, [])

    def test_user_delete_revokes_all_after_reconcile(self):
        self.db.add_user('Ivan')
        self.db.add_device('Ivan', 'MacBook', pub(2), '/secret/x')
        self.control.reconcile()
        self.db.set_user_state('Ivan', 'deleted')
        self.control.reconcile()
        self.assertNotIn(pub(2), self.awg.live)
        self.assertIn(pub(1), self.awg.live)

    def test_status_separates_registered_from_connected(self):
        status = self.control.status()
        self.assertEqual(status['registered_devices'], 1)
        self.assertEqual(status['present_in_awg'], 1)
        self.assertEqual(status['connected_recently'], 0)
        self.assertIsNone(status['devices'][0]['handshake_age_seconds'])

    def test_metrics_without_live_peer_do_not_claim_connection(self):
        self.awg.live.clear()
        self.awg.metrics = lambda: ({pub(1): __import__('time').time()}, {})
        status = self.control.status()
        self.assertEqual(status['connected_recently'], 0)


if __name__ == '__main__':
    unittest.main()
