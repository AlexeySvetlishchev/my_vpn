"""Offline key-file and explicit export tests with fake keys only."""
import base64
import json
import zlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts' / 'task09'))
from manager_db import Refusal  # noqa: E402
from manager_vault import Vault  # noqa: E402
from manager_formats import SERVER_DISPLAY_NAME, amnezia_profile  # noqa: E402

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

    def named_pair(self):
        did = 'd' * 32
        key_ref, public = self.vault.create(did)
        device = {'id': did, 'origin': 'manager', 'key_ref': key_ref,
                  'public_key': public, 'ipv4': '10.203.253.3',
                  'profile_name': 'Ivan_iPhone'}
        before = Path(key_ref).read_bytes()
        raw = Path(self.vault.export(device, server_key=self.server)).read_bytes()
        path = Path(self.vault.export(device, server_key=self.server, format='amnezia'))
        self.assertEqual(Path(key_ref).read_bytes(), before)
        self.assertEqual(path.suffix, '.vpn')
        if sys.platform != 'win32':
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        return raw, path.read_bytes()

    def test_named_export_preserves_every_network_and_key_parameter(self):
        raw, uri = self.named_pair()
        self.assertTrue(uri.startswith(b'vpn://'))
        self.assertNotIn(b'=', uri)
        encoded = uri[6:]
        self.assertLessEqual(len(encoded), 2300)
        compressed = base64.urlsafe_b64decode(encoded + b'=' * (-len(encoded) % 4))
        plain = zlib.decompress(compressed[4:])
        self.assertEqual(int.from_bytes(compressed[:4], 'big'), len(plain))
        envelope = json.loads(plain)
        self.assertEqual(envelope['description'], SERVER_DISPLAY_NAME)
        self.assertEqual(envelope['dns1'], '10.203.253.1')
        self.assertEqual(envelope['dns2'], envelope['dns1'])
        awg = envelope['containers'][0]['awg']
        self.assertTrue(awg['isThirdPartyConfig'])
        self.assertEqual(awg['protocol_version'], '2')
        last = json.loads(awg['last_config'])
        self.assertEqual(last['config'].encode(), raw)
        fields = dict(line.split(' = ', 1) for line in raw.decode().splitlines() if ' = ' in line)
        for native, field in {'client_priv_key':'PrivateKey', 'server_pub_key':'PublicKey',
                              'client_ip':'Address', 'mtu':'MTU',
                              'persistent_keep_alive':'PersistentKeepalive'}.items():
            self.assertEqual(last[native], fields[field])
        self.assertEqual(last['hostName'] + ':' + str(last['port']), fields['Endpoint'])
        self.assertEqual(last['allowed_ips'], fields['AllowedIPs'].split(', '))
        for field in ('Jc','Jmin','Jmax','S1','S2','S3','S4','H1','H2','H3','H4'):
            self.assertEqual(last[field], fields[field])
        self.assertNotIn('Name =', raw.decode())
        self.assertNotIn('Description =', raw.decode())
        self.assertNotIn('userName', envelope)
        self.assertNotIn('password', envelope)

    def test_native_conversion_refuses_unknown_directive_without_exposing_input(self):
        raw, _ = self.named_pair()
        bad = raw.replace(b'[Interface]', b'[Interface]\nPostUp = secret-command')
        with self.assertRaises(Refusal) as ctx:
            amnezia_profile(bad)
        self.assertEqual(ctx.exception.code, 'export_format')
        self.assertNotIn('secret-command', str(ctx.exception))
        self.assertNotIn(CLIENT_PRIVATE, str(ctx.exception))
        self.assertIsNone(ctx.exception.__cause__)

    def test_native_same_name_for_different_device_addresses(self):
        raw, uri = self.named_pair()
        def envelope(value):
            text=value[6:];packed=base64.urlsafe_b64decode(text+b'='*(-len(text)%4))
            return json.loads(zlib.decompress(packed[4:]))
        second = amnezia_profile(raw.replace(b'10.203.253.3/32', b'10.203.253.4/32'))
        self.assertEqual(envelope(uri)['description'], envelope(second)['description'])


if __name__ == '__main__':
    unittest.main()
