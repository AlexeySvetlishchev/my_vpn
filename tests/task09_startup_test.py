"""Offline TASK 07 startup handoff tests; installed helper is untouched."""
import base64
import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'task09'))
from manager_db import Store  # noqa: E402

spec = importlib.util.spec_from_loader('task09_client_helper', SourceFileLoader(
    'task09_client_helper', str(ROOT / 'scripts' / 'task07' / 'helper.py')))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def pub(number):
    return base64.b64encode(bytes([number]) * 32).decode()


class HandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.database = base / 'manager.sqlite3'
        self.activation = base / 'activation.json'
        self.store = Store(self.database, enforce_ownership=False)
        self.addCleanup(self.store.close)
        self.legacy = pub(1)

    def activate(self):
        self.activation.write_text(json.dumps({
            'schema': 1, 'state': 'approved',
            'legacy_public_sha256': hashlib.sha256(self.legacy.encode()).hexdigest()}))

    def peers(self):
        return helper.startup_peers(self.legacy, activation=self.activation,
                                    database=self.database, strict=False)

    def test_without_activation_original_peer_is_unchanged(self):
        self.assertEqual(self.peers(), [(self.legacy, '10.203.253.2/32')])

    def test_activation_requires_exact_legacy_identity(self):
        self.store.add_user('Test')
        self.store.add_device('Test', 'iPhone', pub(2), '/etc/vpn-task07/client.key',
                              origin='task07', ipv4='10.203.253.2')
        self.activate()
        with self.assertRaises(helper.Refusal):
            self.peers()

    def test_manager_state_restores_both_peers_without_rekey(self):
        self.store.add_user('Test')
        self.store.add_device('Test', 'iPhone', self.legacy,
                              '/etc/vpn-task07/client.key', origin='task07',
                              ipv4='10.203.253.2')
        self.store.add_user('Ivan')
        self.store.add_device('Ivan', 'MacBook', pub(3), '/etc/vpn-task09/devices/x/private.key')
        self.activate()
        self.assertEqual(dict(self.peers()), {
            self.legacy: '10.203.253.2/32', pub(3): '10.203.253.3/32'})
        self.store.set_user_state('Ivan', 'disabled')
        self.assertEqual(self.peers(), [(self.legacy, '10.203.253.2/32')])

    def test_revoked_legacy_identity_is_kept_but_not_restored_as_peer(self):
        self.store.add_user('Test')
        self.store.add_device('Test','iPhone',self.legacy,'/etc/vpn-task07/client.key',
                              origin='task07',ipv4='10.203.253.2')
        self.store.add_user('Permanent')
        self.store.add_device('Permanent','Phone',pub(4),'/test-only/permanent.key')
        self.activate()
        self.store.set_device_state('Test','iPhone','revoked')
        self.assertEqual(self.peers(),[(pub(4),'10.203.253.3/32')])
        self.assertEqual(self.store.device('Test','iPhone')['public_key'],self.legacy)


if __name__ == '__main__':
    unittest.main()
