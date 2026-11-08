"""Offline ownership and fail-closed ordering tests for TASK 08 rollback."""
import ast
from pathlib import Path
import unittest

SOURCE = (Path(__file__).resolve().parents[1] /
          'scripts/task08/rollback.py').read_text(encoding='utf-8')


class RollbackTests(unittest.TestCase):
    def test_only_fixed_owned_objects_and_no_shell(self):
        tree = ast.parse(SOURCE)
        self.assertIn("TABLE = {'ru': 'vpn_task08_ru', 'fr': 'vpn_task08_fr'}", SOURCE)
        self.assertIn("COMMENT = 'vpn-task08-owned'", SOURCE)
        self.assertNotIn('flush ruleset', SOURCE)
        self.assertNotIn('docker', SOURCE.lower().split('"""', 2)[-1])
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotEqual(node.func.attr, 'system')
                if node.func.attr == 'run':
                    self.assertFalse(any(k.arg == 'shell' for k in node.keywords))

    def test_forwarding_is_disabled_before_ru_guard_removal(self):
        main = SOURCE.split('def main():', 1)[1]
        self.assertLess(main.index('restore_sysctls(baseline)'),
                        main.index('remove_owned_rules(role)'))
        self.assertLess(main.index('restore_sysctls(baseline)'),
                        main.index("'vpn-task08-egress.service'"))
        self.assertLess(main.index('nft_cleanup(role)', main.index('else:',
                        main.index('remove_owned_rules(role)'))),
                        main.index('remove_fr_route()'))

    def test_unrelated_filter_rules_are_not_selected(self):
        module = ast.parse(SOURCE)
        fn = next(n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == 'objects')
        scope = {'TABLE': {'ru': 'vpn_task08_ru', 'fr': 'vpn_task08_fr'}}
        exec(compile(ast.Module(body=[fn], type_ignores=[]), 'objects', 'exec'), scope)
        nft = {'nftables': [
            {'rule': {'family': 'ip', 'table': 'filter', 'chain': 'FORWARD',
                      'expr': [{'jump': {'target': 'DOCKER-USER'}}]}},
            {'rule': {'family': 'ip', 'table': 'filter', 'chain': 'FORWARD',
                      'expr': [{'jump': {'target': 'vpn_task08_fr_forward'}}]}},
            {'table': {'family': 'ip', 'name': 'vpn_task08_fr'}}]}
        own, forward = scope['objects'](nft, 'fr')
        self.assertEqual(len(own), 1)
        self.assertEqual(len(forward), 1)


if __name__ == '__main__':
    unittest.main()
