"""Offline safety tests: no subprocesses, SSH, sudo, root actions or VPN start."""
import base64
import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/task05'))
if sys.platform == 'win32':
    sys.modules.setdefault('fcntl', types.SimpleNamespace(LOCK_EX=2, LOCK_NB=4, flock=lambda *a: None))
spec = importlib.util.spec_from_file_location('task05_helper', ROOT / 'scripts/task05/helper.py')
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
smoke_spec = importlib.util.spec_from_file_location('task05_smoke', ROOT / 'scripts/task05/smoke.py')
smoke = importlib.util.module_from_spec(smoke_spec)
smoke_spec.loader.exec_module(smoke)
update_spec = importlib.util.spec_from_file_location('task05_helper_update', ROOT / 'scripts/task05/make_helper_update.py')
helper_update = importlib.util.module_from_spec(update_spec)
update_spec.loader.exec_module(helper_update)
build_spec = importlib.util.spec_from_file_location('task05_build', ROOT / 'scripts/task05/build.py')
build_module = importlib.util.module_from_spec(build_spec)
build_spec.loader.exec_module(build_module)
package_spec = importlib.util.spec_from_file_location('task05_package', ROOT / 'scripts/task05/package.py')
package_module = importlib.util.module_from_spec(package_spec)
package_spec.loader.exec_module(package_module)
import diagnose_asymmetry as asymmetry


class Task05(unittest.TestCase):
    def state(self):
        return {'nonce': 'a' * 32, 'role': 'ru', 'public': base64.b64encode(b'x' * 32).decode(),
                'peer': base64.b64encode(b'y' * 32).decode(), 'activated_at': 100, 'phase': 'prepared',
                'ifindex': 42, 'baseline': {}}

    def test_peer_input_is_only_canonical_public_key(self):
        for value in ('$(id)', 'a' * 44, base64.b64encode(bytes(32)).decode(), 'x\n' * 22):
            with self.assertRaises(RuntimeError):
                h.public_key(value)
        self.assertEqual(h.public_key(self.state()['peer']), self.state()['peer'])

    def test_peer_idempotent_but_rotation_denied(self):
        s = self.state()
        with patch.object(h, 'save') as save:
            h.set_peer(s, s['peer'])
            save.assert_called_once()
            with self.assertRaises(RuntimeError):
                h.set_peer(s, base64.b64encode(b'z' * 32).decode())
            with self.assertRaises(RuntimeError):
                h.set_peer(s, s['public'])

    def test_conflicts_all_tables_and_addresses(self):
        h.check_overlap([{'dst': 'default'}, {'dst': '10.8.1.0/24'}], [])
        for routes, addresses in (([{'dst': '10.203.0.0/16', 'table': 200}], []),
                                   ([], [{'addr_info': [{'family': 'inet', 'local': '10.203.254.2', 'prefixlen': 30}]}])):
            with self.assertRaises(RuntimeError):
                h.check_overlap(routes, addresses)

    def test_firewall_order_is_not_normalized_away(self):
        a = {'nftables': [{'rule': {'expr': [{'drop': None}]}}, {'rule': {'expr': [{'accept': None}]}}]}
        b = {'nftables': list(reversed(a['nftables']))}
        self.assertNotEqual(h.stable(a), h.stable(b))
        self.assertEqual(h.stable({'counter': {'bytes': 1}, 'x': 1}), h.stable({'counter': {'bytes': 999}, 'x': 1}))

    def test_foreign_unit_cannot_be_stopped(self):
        with patch.object(h, 'unit', return_value={'LoadState': 'loaded', 'Description': 'production'}), patch.object(h, 'call') as call:
            with self.assertRaises(RuntimeError):
                h.down(self.state())
            call.assert_not_called()

    def test_foreign_interface_cannot_be_deleted(self):
        with patch.object(h, 'unit_owned', return_value=False), patch.object(h, 'links', return_value=[{'ifindex': 42, 'ifalias': 'other'}]), patch.object(h, 'call') as call:
            with self.assertRaises(RuntimeError):
                h.down(self.state())
            call.assert_not_called()

    def test_starting_interface_can_be_identified_for_targeted_rollback(self):
        s = dict(self.state(), phase='starting')
        row = {'ifname': h.IFACE, 'ifalias': 'vpn-task05:' + s['nonce'], 'ifindex': 42}
        with patch.object(h, 'links', return_value=[row]):
            self.assertTrue(h.owned_link(s))
        with patch.object(h, 'links', return_value=[dict(row, ifalias='foreign')]):
            with self.assertRaises(RuntimeError):
                h.owned_link(s)

    def test_down_already_absent_does_not_delete_network(self):
        with patch.object(h, 'unit_owned', return_value=False), patch.object(h, 'links', return_value=[]), patch.object(h, 'call') as call, patch.object(h, 'save'), patch.object(h, 'unchanged'):
            self.assertTrue(h.down(self.state())['stopped'])
            call.assert_not_called()

    def test_partial_prepare_cleanup_requires_no_owned_network_objects(self):
        state = Path('/tmp/task05-unit-state')
        with patch.object(h, 'STATE', state), patch.object(h, 'links', return_value=[]), patch.object(h, 'unit', return_value={'LoadState': 'not-found'}), patch.object(h, 'checked') as checked:
            with patch.object(Path, 'iterdir', return_value=[]), patch.object(Path, 'rmdir') as rmdir:
                self.assertTrue(h.cleanup_partial()['cleaned_partial_prepare'])
                checked.assert_called_once()
                rmdir.assert_called_once_with()
        with patch.object(h, 'links', return_value=[{'ifname': h.IFACE}]), patch.object(h, 'unit', return_value={'LoadState': 'not-found'}), patch.object(h, 'checked') as checked:
            with self.assertRaises(RuntimeError):
                h.cleanup_partial()
            checked.assert_not_called()

    def test_prepare_reports_safe_stage_operation_and_category(self):
        with patch.object(h, 'step', side_effect=h.step):
            with patch.object(h, 'STATE', MagicMock()) as state, \
                 patch.object(h, 'links', return_value=[]), \
                 patch.object(h, 'unit', return_value={'LoadState': 'not-found'}), \
                 patch.object(h, 'ip', side_effect=lambda *a: (
                     [{'ifname': 'ens3', 'addr_info': [{'local': h.PUBLIC['fr'], 'family': 'inet', 'prefixlen': 24}]},
                      {'ifname': 'docker0', 'addr_info': [{'local': '172.17.0.1', 'family': 'inet', 'prefixlen': 16}]},
                      {'ifname': 'amn0', 'addr_info': [{'local': '172.29.172.1', 'family': 'inet', 'prefixlen': 24}]}]
                     if a == ('-4', 'address', 'show') else
                     [{'dst': '172.17.0.0/16', 'dev': 'docker0'}, {'dst': '172.29.172.0/24', 'dev': 'amn0'}]
                     if a == ('-4', 'route', 'show', 'table', 'all') else [])), \
                 patch.object(h, 'call', side_effect=['', h.ProbeFailure('timeout')]), \
                 patch.object(h, 'snapshot', return_value={}), \
                 patch.object(h, 'checked'), patch.object(h, 'cleanup_partial') as cleanup:
                state.exists.return_value = False
                state.is_symlink.return_value = False
                state.__truediv__.return_value.exists.return_value = False
                state.iterdir.return_value = []
                with self.assertRaises(h.DiagnosticFailure) as caught:
                    h.prepare('fr')
                self.assertEqual((caught.exception.stage, caught.exception.operation, caught.exception.category),
                                 ('prepare', 'generate_private_key', 'timeout'))
                cleanup.assert_called_once()

    def test_fr_previous_audit_network_baseline_and_test_port(self):
        routes = [{'dst': net, 'dev': dev} for net, dev in h.FR_AUDIT_ROUTES.items()]
        addresses = [{'ifname': name, 'addr_info': [{'family': 'inet', 'local': ip, 'prefixlen': prefix}]}
                     for name, (ip, prefix) in h.FR_AUDIT_ADDRESSES.items()]
        h.check_fr_audit_baseline(routes, addresses)
        with self.assertRaises(RuntimeError):
            h.check_fr_audit_baseline(routes[:-1], addresses)
        with self.assertRaises(RuntimeError):
            h.check_fr_audit_baseline(routes + [{'dst': str(h.NET), 'dev': 'foreign0'}], addresses)
        self.assertNotEqual(h.PORT, h.PRODUCTION_UDP_PORT)

    def test_fr_prepare_snapshot_does_not_read_docker_metadata(self):
        source = (ROOT / 'scripts/task05/helper.py').read_text()
        self.assertNotIn('production_container_metadata', source)
        self.assertNotIn('/var/run/docker.sock', source)
        self.assertNotIn('docker.service', source)
        with patch.object(h, 'ip', return_value=[]), \
             patch.object(h, 'call', return_value='{"nftables":[]}'), \
             patch.object(h, 'prod', create=True, side_effect=AssertionError('Docker API must not be called')):
            snap = h.snapshot('fr')
        self.assertNotIn('production_hash', snap)

    def test_asymmetry_probe_classifies_input_icmp_drop_scope_and_counters(self):
        def rules(interface=None):
            expr = [{'match': {'op': '==', 'left': {'payload': {'protocol': 'icmp', 'field': 'type'}}, 'right': 'echo-request'}}]
            if interface:
                expr.append({'match': {'op': '==', 'left': {'meta': {'key': 'iifname'}}, 'right': interface}})
            expr.extend([{'counter': {'packets': 7, 'bytes': 588}}, {'drop': None}])
            return {'nftables': [
                {'chain': {'family': 'inet', 'table': 'filter', 'name': 'INPUT', 'hook': 'input'}},
                {'rule': {'family': 'inet', 'table': 'filter', 'chain': 'INPUT', 'handle': 31, 'expr': expr}}]}
        for interface, expected in ((None, 'all_interfaces'), ('awg-test', 'awg-test'), ('ens3', 'ens3')):
            with patch.object(asymmetry, 'ssh', return_value=types.SimpleNamespace(
                    returncode=0, stdout=json.dumps(rules(interface)).encode())):
                result = asymmetry.firewall_fr()
            self.assertEqual(result['input_icmp_drop_rules'][0]['interface'], expected)
            self.assertEqual(result['input_icmp_drop_rules'][0]['icmp_type'], 'echo-request')
            self.assertEqual(result['input_icmp_drop_rules'][0]['counter'], (7, 588))

    def test_asymmetry_probe_is_bounded_and_non_mutating(self):
        source = (ROOT / 'scripts/task05/diagnose_asymmetry.py').read_text()
        self.assertIn('DATA_PORT = 51984', source)
        self.assertIn('SO_BINDTODEVICE', source)
        self.assertIn('timeout -s INT 20', source)
        for forbidden in ('iptables -F', 'nft flush', 'ip route add', 'sysctl -w', 'docker stop'):
            self.assertNotIn(forbidden, source)
        self.assertEqual(len(asymmetry.DATA), 1024)

    def test_helper_update_manifest_is_valid_json_with_real_newline(self):
        source = (ROOT / 'artifacts/task05/bundle/manifest.json').read_bytes()
        helper = (ROOT / 'scripts/task05/helper.py').read_bytes()
        generated = helper_update.manifest_bytes(source, helper)
        parsed = json.loads(generated)
        self.assertEqual(parsed['files']['helper.py'], __import__('hashlib').sha256(helper).hexdigest())
        self.assertTrue(generated.endswith(b'\n'))
        self.assertFalse(generated.endswith(b'\\n'))

    def test_all_source_manifest_generators_emit_valid_json_and_real_newline(self):
        sample = {'build': {'repeat_build_identical': True}, 'files': {'helper.py': 'a' * 64}}
        for generated in (build_module.manifest_bytes(sample), package_module.manifest_bytes(sample)):
            self.assertEqual(json.loads(generated), sample)
            self.assertTrue(generated.endswith(b'\n'))
            self.assertFalse(generated.endswith(b'\\n'))

    def test_up_idempotent_does_not_recreate_or_rotate(self):
        s = dict(self.state(), phase='active')
        with patch.object(h, 'status') as status, patch.object(h, 'call') as call:
            self.assertTrue(h.up(s)['idempotent'])
            status.assert_called_once_with(s)
            call.assert_not_called()

    def test_up_checks_baseline_before_launch(self):
        with patch.object(h, 'links', return_value=[]), patch.object(h, 'unchanged', side_effect=RuntimeError('changed')), patch.object(h, 'launch') as launch:
            with self.assertRaises(RuntimeError):
                h.up(self.state())
            launch.assert_not_called()

    def test_no_false_pass_on_handshake_or_counters_alone(self):
        good = {'elapsed': 900, 'errors': 0, 'samples': 156, 'pre_idle': 60, 'post_idle': 96,
                'rx_delta': 100, 'tx_delta': 100, 'invariants_ok': True}
        self.assertTrue(h.test_passed(good))
        for key, value in [('elapsed', 899), ('errors', 1), ('samples', 119),
                           ('rx_delta', 0), ('tx_delta', 0), ('post_idle', 0), ('invariants_ok', False)]:
            self.assertFalse(h.test_passed(dict(good, **{key: value})))
        self.assertFalse(h.test_passed({'handshake': 999, 'rx_delta': 10000, 'tx_delta': 10000}))

    def test_handshake_must_belong_to_activation_and_be_recent(self):
        for stamp in (0, 99, 401, 110):
            self.assertFalse(h.fresh(self.state(), {'handshake': stamp}, 400))
        self.assertTrue(h.fresh(self.state(), {'handshake': 399}, 400))

    def test_short_tcp_and_wrong_echo_fail(self):
        sock = types.SimpleNamespace(recv=lambda n: b'')
        with self.assertRaises(RuntimeError):
            h.receive_exact(sock, 1024)
        class FakeSocket:
            def __enter__(self): return self
            def __exit__(self, *a): pass
            def connect(self, address): pass
            def sendall(self, data): pass
            def recv(self, size): return b'wrong'
        with patch.object(h, 'bound_socket', return_value=FakeSocket()):
            with self.assertRaises(RuntimeError):
                h.exchange('10.203.254.1', '10.203.254.2', False)

    def test_pinned_build_and_private_socket_path(self):
        lock = json.loads((ROOT / 'scripts/task05/build.lock.json').read_text())
        binary_lock = json.loads((ROOT / 'scripts/task05/binary-lock.json').read_text())
        self.assertEqual(len(lock['go_commit']), 40)
        self.assertEqual(len(lock['tools_commit']), 40)
        self.assertIn('@sha256:', lock['builder'])
        self.assertEqual(binary_lock['sha256']['amneziawg-go'], 'af731e3333dbf6dd33e76a1a6009fd778dd39acfbdbadde5177d6be3b6dbc420')
        self.assertEqual(binary_lock['sha256']['awg'], 'd2030b3c0131195ae9fa2b29eec3887e6ec042433ed17f5f620178fcce97b8b0')
        shell = (ROOT / 'scripts/task05/build-inside.sh').read_text()
        self.assertIn('-buildvcs=false', shell)
        self.assertIn('socketDirectory=/run/vpn-task05/amneziawg', shell)
        self.assertIn('RUNSTATEDIR=/run/vpn-task05', shell)

    def test_launcher_not_arbitrary_root_shell(self):
        launcher = (ROOT / 'scripts/task05/launcher.sh').read_text()
        self.assertIn('[[ $# != 1 ]]', launcher)
        self.assertNotIn('_test)', launcher)
        self.assertNotIn('eval', launcher)
        self.assertNotIn('sudo', launcher)
        source = (ROOT / 'scripts/task05/helper.py').read_text()
        self.assertNotIn('shell=True', source)
        self.assertNotIn('modprobe', source)
        self.assertNotIn('iptables', source)
        self.assertNotIn('sysctl', source)

    def test_bootstrap_is_fixed_and_does_not_start_tunnel(self):
        source = (ROOT / 'scripts/task05/bootstrap.py').read_text()
        for fragment in ("SOURCE = Path('/root/vpn-task05-bundle')", "TARGET = Path('/opt/vpn-task05')",
                        "if set(manifest['files']) != names", "visudo", "NOSETENV: NOPASSWD:",
                        "wolffrog ALL=(root) NOSETENV: NOPASSWD:"):
            self.assertIn(fragment, source)
        self.assertNotIn('systemctl start', source)
        self.assertNotIn('systemd-run', source)
        self.assertNotIn('shell=True', source)
        self.assertNotIn('chmod -R', source)
        lowered = source.lower()
        for forbidden in ('docker', 'nft', 'iptables', 'systemctl', 'sysctl', 'ip route', 'ip link'):
            self.assertNotIn(forbidden, lowered)

    def test_smoke_is_bounded_and_does_not_call_long_runner(self):
        source = (ROOT / 'scripts/task05/smoke.py').read_text()
        self.assertNotIn('start-test', source)
        self.assertNotIn('900', source)
        self.assertIn("'-c', '4', '-W', '2'", source)
        good = {r: {'handshake': 1000, 'baseline_unchanged': True} for r in smoke.ROLES}
        with patch.object(smoke.time, 'time', return_value=1010):
            smoke.require_fresh(good)
        with patch.object(smoke.time, 'time', return_value=1201):
            with self.assertRaises(RuntimeError):
                smoke.require_fresh(good)

    def test_smoke_ping_requires_replies_not_just_process_start(self):
        fake = types.SimpleNamespace(returncode=0, stdout=b'4 packets transmitted, 3 received, 25% packet loss')
        with patch.object(smoke.subprocess, 'run', return_value=fake):
            self.assertEqual(smoke.ping('ru'), {'transmitted': 4, 'received': 3})
        fake.stdout = b'4 packets transmitted, 0 received, 100% packet loss'
        with patch.object(smoke.subprocess, 'run', return_value=fake):
            with self.assertRaises(RuntimeError):
                smoke.ping('ru')


if __name__ == '__main__':
    unittest.main(verbosity=2)
