"""Offline simulation of post-migration nft handles (not a kernel test)."""
import copy
from pathlib import Path
import unittest
import task09_nft_plan as p

HERE = Path(__file__).parent

class ReverseTests(unittest.TestCase):
    def snapshot(self):
        rows = [{'table': {'family': 'ip', 'name': p.TABLE}}]
        with_handles = [copy.deepcopy(rows[0])]
        idx = 1000
        for chain, entries in p.source_rules(HERE / 'staged-task09' / 'ru.nft').items():
            for entry in entries:
                # Expressions in this fixture are simplified; source-to-JSON
                # semantic validation remains for Linux integration tests.
                rule = {'family': 'ip', 'table': p.TABLE, 'chain': chain,
                        'expr': [{'accept': None}], 'comment': 'vpn-task08-owned'}
                rows.append({'rule': copy.deepcopy(rule)})
                with_handles.append({'rule': dict(rule, handle=idx)})
                idx += 7  # deliberately unlike pre-migration handles
        plain = {'nftables': rows}
        return plain, {'nftables': with_handles}, {'schema': 1, 'role': 'ru',
            'phase': 'active', 'own_table_sha256': p.owned_hash(plain)}

    def test_fresh_handle_reverse(self):
        a, b, l = self.snapshot()
        result = p.reverse_from_live(HERE/'fixtures'/'ru.nft',
            HERE/'staged-task09'/'ru.nft', a, b, l)
        self.assertEqual(result.count('replace rule'), 6)
        self.assertEqual(result.count('delete rule'), 1)
        self.assertIn('handle 1000', result)
        self.assertNotIn('flush set', result)
        self.assertIn('10.203.253.2', result)

    def test_refuse_stale_snapshot(self):
        a, b, l = self.snapshot()
        b['nftables'][3]['rule']['expr'].append({'drop': None})
        with self.assertRaises(ValueError):
            p.reverse_from_live(HERE/'fixtures'/'ru.nft',
                HERE/'staged-task09'/'ru.nft', a, b, l)

    def test_refuse_renumbered_unpinned_set(self):
        a, b, l = self.snapshot()
        a['nftables'][2]['rule']['comment'] = 'not-ours'
        with self.assertRaises(ValueError):
            p.reverse_from_live(HERE/'fixtures'/'ru.nft',
                HERE/'staged-task09'/'ru.nft', a, b, l)

    def test_refuse_missing_guard(self):
        a,b,l=self.snapshot()
        a['nftables'].pop(1)
        b['nftables'].pop(1)
        l['own_table_sha256']=p.owned_hash(a)
        with self.assertRaises(ValueError):
            p.reverse_from_live(HERE/'fixtures'/'ru.nft',
                HERE/'staged-task09'/'ru.nft', a,b,l)

if __name__ == '__main__': unittest.main()
