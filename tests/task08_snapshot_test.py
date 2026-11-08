"""Offline checks for TASK 08 prechange evidence collection."""
import ast
import hashlib
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'scripts/task08/snapshot.py').read_text(encoding='utf-8')


class SnapshotSafetyTests(unittest.TestCase):
    def test_fixed_commands_and_no_shell(self):
        tree = ast.parse(SOURCE)
        self.assertIn("Path('/var/lib/vpn-task08')", SOURCE)
        self.assertIn("os.O_EXCL | os.O_NOFOLLOW", SOURCE)
        self.assertIn("'nft': ['/usr/sbin/nft', '-j', '-n', 'list', 'ruleset']", SOURCE)
        self.assertNotIn('docker', SOURCE.lower())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertFalse(node.func.attr in ('system', 'popen'))
                if node.func.attr == 'run':
                    self.assertFalse(any(k.arg == 'shell' for k in node.keywords))

    def test_snapshot_discards_free_text_and_counters(self):
        namespace = {'__name__': 'task08_test_import'}
        exec(compile(SOURCE, 'snapshot.py', 'exec'), namespace)
        raw = {'nftables': [{'rule': {'expr': [
            {'match': {'left': 'iifname', 'right': 'awg-transport'}},
            {'counter': {'packets': 5, 'bytes': 100}},
            {'comment': 'synthetic-secret'}]}}]}
        stable = namespace['stable'](raw)
        self.assertNotIn('synthetic-secret', repr(stable))
        self.assertNotIn('packets', repr(stable))
        self.assertIn('awg-transport', repr(stable))

    def test_task06_upgrade_is_pinned_to_reviewed_helper(self):
        source = (ROOT / 'scripts/task08/upgrade-task06.py').read_text(encoding='utf-8')
        helper = (ROOT / 'scripts/task06/helper.py').read_bytes()
        self.assertIn(hashlib.sha256(helper).hexdigest(), source)
        self.assertIn("Path('/var/lib/vpn-task08/backup')", source)
        self.assertIn('BACKUP_MANIFEST', source)
        self.assertNotIn('shell=True', source)


if __name__ == '__main__':
    unittest.main()
