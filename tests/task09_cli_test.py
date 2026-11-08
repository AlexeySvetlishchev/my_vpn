"""Offline CLI contract and authorization tests; no server commands."""
import base64
from contextlib import redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts' / 'task09'))
from manager_db import Refusal, Store  # noqa: E402
from vpnctl import main, parser  # noqa: E402


class FakeAwg:
    def __init__(self):
        self.live = {}
    def peers(self):
        return dict(self.live)
    def metrics(self):
        return {}, {}
    def add(self, key, address):
        self.live[key] = address
    def remove(self, key):
        self.live.pop(key)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / 'manager.sqlite3',
                           enforce_ownership=False)
        self.addCleanup(self.store.close)
        self.awg = FakeAwg()

    def call(self, *args, permit=False):
        out, err = io.StringIO(), io.StringIO()
        def gate(_store):
            if not permit:
                raise Refusal('approval_required', 'not approved')
        with redirect_stdout(out), redirect_stderr(err):
            status = main(args, store=self.store, adapter=self.awg,
                          require_activation=gate, include_services=False)
        return status, out.getvalue(), err.getvalue()

    def test_all_required_syntax_is_available(self):
        for action in ('add','list','show','disable','enable','delete'):
            args = [action] + ([] if action == 'list' else ['Ivan'])
            parser().parse_args(['user', *args])
        for action in ('add','list','show','disable','enable','revoke','export'):
            args = [action] + ([] if action == 'list' else ['Ivan','iPhone'])
            parser().parse_args(['device', *args])
        for action in ('status','diagnostics','backup','reconcile'):
            parser().parse_args([action])

    def test_json_human_identity_and_duplicate_error(self):
        status, out, _ = self.call('--json', 'user', 'add', 'Ivan')
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(out)['data']['name'], 'Ivan')
        status, out, _ = self.call('--json', 'user', 'add', 'ivan')
        self.assertEqual(status, 3)
        self.assertEqual(json.loads(out)['code'], 'name_conflict')

    def test_peer_change_is_blocked_without_activation(self):
        self.call('user','add','Ivan')
        status, out, _ = self.call('--json','user','disable','Ivan')
        self.assertEqual(status, 3)
        self.assertEqual(json.loads(out)['code'], 'approval_required')
        self.assertEqual(self.store.user('Ivan')['state'], 'enabled')
        status, out, _ = self.call('--json','reconcile')
        self.assertEqual(status, 3)
        self.assertEqual(json.loads(out)['code'], 'approval_required')

    def test_status_never_calls_existing_peer_connected_without_handshake(self):
        self.store.add_user('Test')
        public = base64.b64encode(b'1' * 32).decode()
        self.store.add_device('Test','iPhone',public,'/etc/vpn-task07/client.key',
                              origin='task07',ipv4='10.203.253.2')
        self.awg.live[public] = '10.203.253.2/32'
        status, out, _ = self.call('--json','status')
        self.assertEqual(status, 0)
        data = json.loads(out)['data']
        self.assertEqual(data['present_in_awg'], 1)
        self.assertEqual(data['connected_recently'], 0)
        self.assertNotIn('client.key', out)
        self.assertNotIn(public, out)

    def test_restore_requires_explicit_archive_check(self):
        args = parser().parse_args(['restore', '--check', '/root/backup.tar'])
        self.assertEqual(args.check, '/root/backup.tar')


if __name__ == '__main__':
    unittest.main()
