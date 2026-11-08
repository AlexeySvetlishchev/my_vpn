"""Offline TASK 06 guardrail tests; never connects to hosts or starts networking."""
import ast
import hashlib
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
TASK = ROOT / 'scripts/task06'


class Task06SafetyTests(unittest.TestCase):
    def test_fixed_build_pins_and_isolated_socket(self):
        lock = json.loads((TASK / 'build.lock.json').read_text(encoding='utf-8'))
        self.assertRegex(lock['go_commit'], r'^[0-9a-f]{40}$')
        self.assertRegex(lock['tools_commit'], r'^[0-9a-f]{40}$')
        self.assertEqual(lock['socket_directory'], '/run/vpn-task06/amneziawg')
        self.assertNotIn('vpn-task05', lock['socket_directory'])
        builder = (TASK / 'build.py').read_text(encoding='utf-8')
        self.assertIn("'--network=none'", builder)
        self.assertIn("'--cap-drop=ALL'", builder)

    def test_helper_has_fixed_scope_and_no_shell_execution(self):
        source = (TASK / 'helper.py').read_text(encoding='utf-8')
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertFalse(node.func.attr == 'Popen' and any(
                    kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in node.keywords))
        self.assertIn("IFACE = 'awg-transport'", source)
        self.assertIn("NET = ipaddress.ip_network('10.203.254.0/30')", source)
        self.assertIn('PORT, DATA_PORT, MTU = 51983, 51984, 1280', source)
        self.assertIn("'/usr/sbin/nft', '-j', 'list', 'ruleset'", source)
        self.assertIn("'counter', 'metainfo'", source)
        self.assertIn("'probe', 'interface_address_check'", source)
        self.assertIn("action in ('status', 'monitor', 'wait-ready')", source)
        self.assertIn('for attempt in range(3)', source)
        self.assertIn('def owned_task07_interface():', source)
        self.assertIn("state.get('phase') == 'active'", source)
        self.assertIn("link.get('ifindex') == state['ifindex']", source)
        self.assertIn("link.get('linkinfo', {}).get('info_kind') in (None, 'tun')", source)
        self.assertIn("route['dst'], strict=False).subnet_of(TASK07_NET)", source)
        self.assertIn("route.get('dst') == 'ff00::/8'", source)
        self.assertIn("route.get('dst') in link_locals6", source)
        self.assertNotRegex(source, r'\b(?:nft|iptables|ufw)\b[^\n]*(?:add|insert|delete|flush)')

    def test_launcher_is_fixed_allowlist(self):
        launcher = (TASK / 'launcher.sh').read_text(encoding='utf-8')
        self.assertIn('set -eu', launcher)
        self.assertIn('keygen|set-peer|capture-baseline|wait-ready|status|monitor|rollback', launcher)
        self.assertIn('python3 -I -B /opt/vpn-task06/helper.py', launcher)
        self.assertNotIn('eval ', launcher)

    def test_systemd_units_are_scoped_and_autostart_is_explicit(self):
        awg = (TASK / 'vpn-task06-awg.service').read_text(encoding='utf-8')
        self.assertIn('Restart=on-failure', awg)
        self.assertIn('WantedBy=multi-user.target', awg)
        self.assertIn('RuntimeDirectory=vpn-task06', awg)
        self.assertIn('DeviceAllow=/dev/net/tun rw', awg)
        probe = (TASK / 'vpn-task06-probe.service').read_text(encoding='utf-8')
        self.assertIn('AF_NETLINK', probe)
        monitor = (TASK / 'vpn-task06-monitor.service').read_text(encoding='utf-8')
        self.assertIn('ReadWritePaths=/run/vpn-task06', monitor)
        self.assertNotIn('RuntimeDirectory=', monitor)
        self.assertIn('Requires=vpn-task06-awg.service', monitor)
        for path in TASK.glob('vpn-task06-*'):
            content = path.read_text(encoding='utf-8')
            self.assertNotIn('docker ', content)
            self.assertNotIn('nft add', content)
            self.assertNotIn('iptables -', content)
            self.assertNotIn('ip route add', content)

    def test_installer_activation_is_separate_and_fixed_paths_only(self):
        source = (TASK / 'install.py').read_text(encoding='utf-8')
        self.assertIn("'/usr/bin/systemctl', 'daemon-reload'", source)
        self.assertNotIn("'enable'", source)
        self.assertNotIn("'start'", source)
        self.assertIn("'/home/wolffrog/task06-upload/bundle'", source)
        self.assertIn("'vpn-task06-monitor.timer'", source)
        self.assertIn("Path('/opt/vpn-task06') / name", source)

    def test_docs_and_sources_do_not_embed_key_material(self):
        files = [*TASK.glob('*'), ROOT / 'docs/TASK_06_PERMANENT_AWG_TUNNEL.md']
        for path in files:
            if not path.is_file() or path.name.endswith('.pyc'):
                continue
            text = path.read_text(encoding='utf-8', errors='replace')
            self.assertNotRegex(text, r'(?m)^PrivateKey\s*=')
            self.assertNotRegex(text, r'(?m)^[A-Za-z0-9+/]{43}=?$')

    def test_activation_controller_accepts_only_fixed_hosts_and_operations(self):
        source = (TASK / 'activate.py').read_text(encoding='utf-8')
        self.assertIn("HOSTS = {'ru': 'vpn-ru', 'fr': 'vpn-fr'}", source)
        self.assertIn("TASK_ACTIONS = {'keygen', 'set-peer', 'capture-baseline', 'status', 'monitor', 'rollback'}", source)
        self.assertIn("'restart-awg': 'sudo -n /usr/bin/systemctl restart vpn-task06-awg.service'", source)
        self.assertNotIn('shell=True', source)
        self.assertNotIn('PrivateKey', source)

    def test_remote_diagnostic_avoids_powershell_stdin_crlf(self):
        source = (TASK / 'verify-remote.ps1').read_text(encoding='utf-8')
        self.assertIn("[ValidateSet('vpn-ru', 'vpn-fr')]", source)
        self.assertIn("'sudo -n /usr/local/sbin/vpn-task06 wait-ready'", source)
        self.assertNotIn('bash -s', source.split('# Pass fixed commands directly to SSH.', 1)[0])
        self.assertNotIn('head -c', source)

    def test_monitor_owns_no_shared_runtime_and_upgrade_is_pinned(self):
        unit = (TASK / 'vpn-task06-monitor.service').read_bytes()
        self.assertNotIn(b'RuntimeDirectory=', unit)
        self.assertIn(b'Requires=vpn-task06-awg.service', unit)
        upgrade = (TASK / 'upgrade-monitor-runtime.py').read_text(encoding='utf-8')
        self.assertIn(hashlib.sha256(unit).hexdigest(), upgrade)
        self.assertIn("NAME = 'vpn-task06-monitor.service'", upgrade)
        self.assertIn("Path('/root/vpn-task06-monitor-fix-backup')", upgrade)
        self.assertIn("'/usr/bin/systemctl', 'daemon-reload'", upgrade)
        self.assertNotIn('shell=True', upgrade)

    def test_task08_projection_only_selects_its_own_nft_objects(self):
        source = (TASK / 'helper.py').read_text(encoding='utf-8')
        module = ast.parse(source)
        fn = next(node for node in module.body if isinstance(node, ast.FunctionDef)
                  and node.name == 'task08_nft_subset')
        scope = {}
        exec(compile(ast.Module(body=[fn], type_ignores=[]), 'task08_projection', 'exec'), scope)
        select = scope['task08_nft_subset']
        self.assertEqual(select({'table': {'family': 'ip', 'name': 'vpn_task08_fr'}}, 'fr'), 'own')
        self.assertEqual(select({'rule': {'family': 'ip', 'table': 'filter',
                                         'chain': 'FORWARD', 'expr': [
            {'jump': {'target': 'vpn_task08_fr_forward'}}]}}, 'fr'), 'filter')
        self.assertIsNone(select({'rule': {'family': 'ip', 'table': 'filter',
                                            'chain': 'FORWARD', 'expr': [
            {'jump': {'target': 'DOCKER-FORWARD'}}]}}, 'fr'))
        self.assertIsNone(select({'rule': {'family': 'ip', 'table': 'nat',
                                            'chain': 'POSTROUTING', 'expr': [
            {'masquerade': None}]}}, 'fr'))


if __name__ == '__main__':
    unittest.main()
