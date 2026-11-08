"""Offline key-file and explicit export tests with fake keys only."""
import base64
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts' / 'task09'))
from manager_db import Refusal  # noqa: E402
from manager_vault import Vault  # noqa: E402

CLIENT_PRIVATE = base64.b64encode(b'a' * 32).decode()
CLIENT_PUBLIC = base64.b64encode(b'b' * 32).decode()
SERVER_PUBLIC = base64.b64encode(b'c' * 32).decode()


def fake_awg(args, *, input_bytes=None):
    if args[-1] == 'genkey':
        return CLIENT_PRIVATE
    if args[-1] == 'pubkey':
        return CLIENT_PUBLIC if input_bytes.strip() == CLIENT_PRIVATE.encode() else SERVER_PUBLIC
    raise AssertionError('unexpected AWG command')


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.server = base / 'server.key'
        self.server.write_bytes(b'fake-server-secret\n')
        self.vault = Vault(root=base / 'devices', exports=base / 'exports',
                           enforce_ownership=False, awg_command=fake_awg)

    def test_export_is_explicit_file_and_reuses_key(self):
        did = 'a' * 32
        key_ref, public = self.vault.create(did)
        self.assertEqual(public, CLIENT_PUBLIC)
        device = {'id': did, 'origin': 'manager', 'key_ref': key_ref,
                  'public_key': public, 'ipv4': '10.203.253.3',
                  'profile_name': 'Ivan_iPhone'}
        path = Path(self.vault.export(device, server_key=self.server))
        content = path.read_text()
        self.assertIn('Address = 10.203.253.3/32', content)
        self.assertIn('AllowedIPs = 0.0.0.0/0, ::/0', content)
        self.assertIn(CLIENT_PRIVATE, content)
        with self.assertRaises(FileExistsError):
            self.vault.export(device, server_key=self.server)

    def test_key_identity_mismatch_refuses_export(self):
        did = 'b' * 32
        key_ref, _ = self.vault.create(did)
        device = {'id': did, 'origin': 'manager', 'key_ref': key_ref,
                  'public_key': SERVER_PUBLIC, 'ipv4': '10.203.253.3',
                  'profile_name': 'Ivan_iPhone'}
        with self.assertRaises(Refusal) as error:
            self.vault.export(device, server_key=self.server)
        self.assertEqual(error.exception.code, 'secret_identity')


if __name__ == '__main__':
    unittest.main()
