#!/usr/bin/env python3
"""Offline tests: all system commands and sockets are mocked or forbidden."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('wg_test', Path(__file__).with_name('03_wg_test.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Checks(unittest.TestCase):
    def test_network(self):
        for bad in ('0.0.0.0/0', '10.0.0.0/24', '10.0.0.1/30', '127.0.0.0/30', '45.15.128.136/30'):
            with self.assertRaises((RuntimeError, ValueError)):
                m.network(bad)
        self.assertEqual(str(m.network('10.203.254.0/30')), '10.203.254.0/30')

    def test_overlap_all_tables_and_addresses(self):
        n = m.network('10.203.254.0/30')
        m.check_overlap(n, [{'dst': 'default'}, {'dst': '192.168.1.0/24'}], [])
        for dst in ('10.0.0.0/8', '10.203.254.2/32', '10.203.254.0/30'):
            with self.assertRaises(RuntimeError):
                m.check_overlap(n, [{'dst': dst, 'table': 200}], [])
        with self.assertRaises(RuntimeError):
            m.check_overlap(n, [], [{'addr_info': [{'family': 'inet', 'local': '10.203.254.1', 'prefixlen': 30}]}])

    def test_fresh_handshake(self):
        self.assertTrue(m.fresh(1000, 1001, 1100))
        for stamp in (0, 999, 1101):
            self.assertFalse(m.fresh(1000, stamp, 1100))
        self.assertFalse(m.fresh(1000, 1001, 1182))

    def test_dry_run_every_action_no_io(self):
        for action in ('preflight', 'probe', 'prepare', 'up', 'handshake', 'packets', 'down', 'cleanup'):
            with patch.object(sys, 'argv', ['test', action, '--role', 'ru']), \
                    patch.object(m, 'execute', side_effect=AssertionError('execute')), \
                    patch.object(m.os, 'open', side_effect=AssertionError('write')), \
                    patch.object(m.socket, 'socket', side_effect=AssertionError('network')), \
                    contextlib.redirect_stdout(io.StringIO()) as out:
                m.main()
                self.assertIn('DRY-RUN', out.getvalue())

    def args(self, action, **kw):
        from argparse import Namespace
        return Namespace(action=action, role='ru', subnet='10.203.254.0/30', port=51983,
                         firewall_reviewed=kw.get('firewall_reviewed', False),
                         udp_verified=kw.get('udp_verified', False), peer_key=kw.get('peer_key'))

    def settings(self, name):
        if name == 'settings.json':
            return json.dumps({'role': 'ru', 'subnet': '10.203.254.0/30', 'port': 51983})
        return 'test-fixture'

    def test_activation_gate(self):
        with patch.object(m, 'read', side_effect=self.settings), patch.object(m, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'firewall'):
                m.execute(self.args('up'))
            run.assert_not_called()

    def test_no_secret_error_output(self):
        from subprocess import CompletedProcess
        with patch.object(m.subprocess, 'run', return_value=CompletedProcess([], 1, 'secret', 'secret')):
            with self.assertRaises(RuntimeError) as e:
                m.run('wg', 'genkey')
            self.assertNotIn('secret', str(e.exception))

    def test_route_changes_fail(self):
        with patch.object(m, 'read', return_value='{}'), patch.object(m, 'snapshot', return_value={'changed': True}):
            with self.assertRaisesRegex(RuntimeError, 'Routes/rules changed'):
                m.unchanged()

    def test_packets_require_rx_tx_and_replies(self):
        for counters, output, success in [([(10, 20), (50, 60)], '3 received, 0% packet loss', True),
                                          ([(10, 20), (10, 60)], '3 received, 0% packet loss', False),
                                          ([(10, 20), (50, 60)], '2 received, 33% packet loss', False)]:
            with patch.object(m, 'read', side_effect=self.settings), patch.object(m, 'handshake'), \
                    patch.object(m, 'ip', return_value=[{'dev': 'wg-test'}]), \
                    patch.object(m, 'transfers', side_effect=counters), patch.object(m, 'run', return_value=output), \
                    contextlib.redirect_stdout(io.StringIO()):
                if success:
                    m.execute(self.args('packets'))
                else:
                    with self.assertRaises(RuntimeError):
                        m.execute(self.args('packets'))

    def test_unowned_interface_never_deleted(self):
        with patch.object(m, 'present', return_value=True), \
                patch.object(m, 'owned', side_effect=RuntimeError('unowned')), patch.object(m, 'run') as run:
            with self.assertRaises(RuntimeError):
                m.execute(self.args('down'))
            run.assert_not_called()

    def test_activation_config_and_rollback(self):
        public = m.base64.b64encode(bytes(range(32))).decode()
        for fail_activation in (False, True):
            calls, files = [], {}

            def command(*args, **kw):
                calls.append(args)
                if args[:2] == ('wg', 'pubkey'):
                    return 'different-public-key'
                if fail_activation and args[:2] == ('wg-quick', 'up'):
                    raise RuntimeError('simulated activation failure')
                return ''

            with patch.object(m, 'read', side_effect=self.settings), \
                    patch.object(m, 'run', side_effect=command), \
                    patch.object(m, 'present', side_effect=[False, True] if fail_activation else [False]), \
                    patch.object(m, 'preflight'), patch.object(m, 'snapshot', return_value={}), \
                    patch.object(m, 'write', side_effect=lambda k, v: files.update({k: v})), \
                    patch.object(m, 'unchanged'), contextlib.redirect_stdout(io.StringIO()):
                a = self.args('up', firewall_reviewed=True, udp_verified=True, peer_key=public)
                if fail_activation:
                    with self.assertRaisesRegex(RuntimeError, 'simulated'):
                        m.execute(a)
                    self.assertIn(('ip', 'link', 'delete', 'dev', 'wg-test'), calls)
                else:
                    m.execute(a)
                    self.assertIn(('wg', 'set', 'wg-test', 'private-key', str(m.ROOT / 'private.key')), calls)
                config = files['wg-test.conf']
                self.assertIn('Table = off', config)
                self.assertIn('AllowedIPs = 10.203.254.2/32', config)
                self.assertNotIn('PrivateKey', config)
                self.assertNotIn('0.0.0.0/0', config)

    def test_repeated_activation_does_not_write(self):
        public = m.base64.b64encode(bytes(range(32))).decode()

        def read(name):
            return public if name == 'peer' else self.settings(name)

        with patch.object(m, 'read', side_effect=read), patch.object(m, 'run', return_value='local-public'), \
                patch.object(m, 'present', return_value=True), patch.object(m, 'owned'), \
                patch.object(m, 'unchanged'), patch.object(m, 'write') as write, \
                contextlib.redirect_stdout(io.StringIO()):
            m.execute(self.args('up', firewall_reviewed=True, udp_verified=True, peer_key=public))
            write.assert_not_called()


if __name__ == '__main__':
    unittest.main()
