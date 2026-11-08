"""Offline guardrails for staged TASK 08 activation."""
import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'scripts/task08/apply.py').read_text(encoding='utf-8')


class ApplyTests(unittest.TestCase):
    def test_fr_jump_requires_existing_docker_order(self):
        module = ast.parse(SOURCE)
        fn = next(n for n in module.body if isinstance(n, ast.FunctionDef)
                  and n.name == 'fr_jump_position')
        scope = {}
        exec(compile(ast.Module(body=[fn], type_ignores=[]), 'jump', 'exec'), scope)
        rows = [{'rule': {'family': 'ip', 'table': 'filter', 'chain': 'FORWARD',
                          'handle': handle, 'expr': [{'jump': {'target': target}}]}}
                for handle, target in ((12, 'DOCKER-USER'), (7, 'DOCKER-FORWARD'))]
        self.assertEqual(scope['fr_jump_position']({'nftables': rows}), 7)
        rows[0]['rule']['expr'][0]['jump']['target'] = 'OTHER'
        with self.assertRaises(RuntimeError):
            scope['fr_jump_position']({'nftables': rows})

    def test_ru_terminal_rules_precede_lookup_and_forwarding(self):
        ru = SOURCE.split('def apply_ru(module):', 1)[1].split('def apply_fr(module):', 1)[0]
        self.assertLess(ru.index("'10021'"), ru.index("'10000'"))
        self.assertIn("'fwmark', '0x702/0xffffffff', 'unreachable'", ru)
        self.assertLess(ru.index("'10032'"), ru.index("'10030'"))
        self.assertNotIn('ip_forward', ru)
        self.assertIn("'vpn-task06-awg.service'", ru)

    def test_nft_files_have_only_task08_owned_rules(self):
        for role in ('ru', 'fr'):
            lines = (ROOT / f'scripts/task08/{role}.nft').read_text(encoding='utf-8').splitlines()
            self.assertTrue(all(line.startswith(('add table ', 'add set ',
                                                  'add chain ', 'add rule ')) for line in lines))
            self.assertTrue(all('comment "vpn-task08-owned"' in line
                                for line in lines if line.startswith('add rule ')))
            self.assertFalse(any('flush ruleset' in line or 'delete table' in line
                                 for line in lines))
        fr = (ROOT / 'scripts/task08/fr.nft').read_text(encoding='utf-8')
        self.assertNotIn('DOCKER-', fr)
        self.assertNotIn('amnezia-awg2', fr)


if __name__ == '__main__':
    unittest.main()
