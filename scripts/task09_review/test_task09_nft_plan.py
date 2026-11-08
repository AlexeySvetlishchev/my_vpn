import importlib.util
import copy
import json
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('planner', Path(__file__).parent/'task09_nft_plan.py')
p=importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
ROOT=Path(__file__).resolve().parent

class PlannerTests(unittest.TestCase):
    def fixture(self):
        rows=[{'table':{'family':'ip','name':p.TABLE}}]
        handles=[{'table':{'family':'ip','name':p.TABLE}}]
        idx=10
        for chain,entries in p.source_rules(ROOT/'fixtures'/'ru.nft').items():
            for i,_ in enumerate(entries):
                obj={'family':'ip','table':p.TABLE,'chain':chain,
                     'expr':[{'counter':{'packets':5,'bytes':500}}, {'accept':None}],
                     'comment':'vpn-task08-owned'}
                rows.append({'rule':dict(obj)})
                handles.append({'rule':dict(copy.deepcopy(obj),handle=idx)})
                idx+=1
        base={'nftables':rows}
        with_handle={'nftables':handles}
        ledger={'schema':1,'role':'ru','phase':'active','own_table_sha256':p.owned_hash(base)}
        return base,with_handle,ledger
    def test_six_replacements_preserve_sets(self):
        a,b,l=self.fixture()
        output=p.plan(ROOT/'fixtures'/'ru.nft',ROOT/'staged-task09'/'ru.nft',a,b,l)
        self.assertEqual(output.count('replace rule'),6)
        self.assertEqual(output.count('insert rule'),1)
        self.assertNotIn('flush',output)
        self.assertNotIn('delete table',output)
        self.assertNotIn('add element',output)
        self.assertIn('10.203.253.0/24',output)
        self.assertIn('10.203.253.255', output)
    def test_refuses_drift(self):
        a,b,l=self.fixture()
        a['nftables'][1]['rule']['expr'].append({'drop':None})
        with self.assertRaisesRegex(ValueError,'differs'):
            p.plan(ROOT/'fixtures'/'ru.nft',ROOT/'staged-task09'/'ru.nft',a,b,l)
    def test_refuses_handle_snapshot_change(self):
        a,b,l=self.fixture()
        b['nftables'][1]['rule']['expr'].append({'drop':None})
        with self.assertRaisesRegex(ValueError,'snapshot'):
            p.plan(ROOT/'fixtures'/'ru.nft',ROOT/'staged-task09'/'ru.nft',a,b,l)
    def test_refuses_stale_handle_snapshot(self):
        a,b,l=self.fixture()
        b['nftables'][1]['rule']['expr'][0]['counter']['packets']=55
        # Volatile counters in the handle snapshot are allowed.
        self.assertIn('replace rule',p.plan(ROOT/'fixtures'/'ru.nft',ROOT/'staged-task09'/'ru.nft',a,b,l))
        b['nftables'][1]['rule']['expr'].append({'drop':None})
        with self.assertRaises(ValueError):
            p.plan(ROOT/'fixtures'/'ru.nft',ROOT/'staged-task09'/'ru.nft',a,b,l)
    def test_refuses_wrong_source(self):
        a,b,l=self.fixture()
        with self.assertRaisesRegex(ValueError,'reserved-source guard'):
            p.plan(ROOT/'fixtures'/'ru.nft',ROOT/'fixtures'/'ru.nft',a,b,l)
    def test_hash_stable_counters(self):
        a,b,l=self.fixture()
        a['nftables'][1]['rule']['expr'][0]['counter']['packets']=999
        self.assertEqual(p.owned_hash(a),l['own_table_sha256'])
if __name__=='__main__':
    unittest.main()
