"""Bounds, public-address filtering, and transaction shape for RU geofeed."""
from importlib.machinery import SourceFileLoader
import importlib.util
import ipaddress
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


geo = load('task08_geo', ROOT / 'scripts/task08/ru-prefix-data.py')
with patch.dict(sys.modules, {'fcntl': types.SimpleNamespace()}):
    update = load('task08_update', ROOT / 'scripts/task08/ru-prefix-update.py')


class PrefixTests(unittest.TestCase):
    def test_intersection_routes_disagreement_to_fr(self):
        a = geo.merge([(int(ipaddress.IPv4Address('77.88.8.0')),
                        int(ipaddress.IPv4Address('77.88.9.255')))])
        b = geo.merge([(int(ipaddress.IPv4Address('77.88.9.0')),
                        int(ipaddress.IPv4Address('77.88.10.255')))])
        self.assertEqual([str(n) for n in geo.cidrs(geo.intersect(a, b))],
                         ['77.88.9.0/24'])

    def test_management_subnet_is_subtracted_even_inside_aggregated_source(self):
        large = geo.merge([(int(ipaddress.IPv4Address('137.22.144.0')),
                            int(ipaddress.IPv4Address('137.22.159.255')))])
        blocked = geo.merge((int(n.network_address), int(n.broadcast_address))
                            for n in geo.EXCLUDED)
        safe = geo.cidrs(geo.subtract(large, blocked))
        self.assertTrue(safe)
        self.assertFalse(any(n.overlaps(ipaddress.ip_network('137.22.146.0/24'))
                             for n in safe))

    def test_special_and_protected_prefixes_refused(self):
        for prefix in ('10.0.0.0/8', '137.22.146.0/24', '45.15.128.0/24'):
            with self.assertRaises(ValueError):
                geo.validate_public([ipaddress.ip_network(prefix)])

    def test_nft_batch_is_one_transaction_and_only_owned_sets(self):
        batch = update.nft_batch(['77.88.8.0/24'], ['77.88.8.8/32']).decode()
        self.assertIn('flush set ip vpn_task08_ru ru_set', batch)
        self.assertIn('add element ip vpn_task08_ru force_egress { 77.88.8.8/32 }', batch)
        self.assertNotIn('flush ruleset', batch)
        self.assertNotIn('DOCKER-', batch)

    def test_noncanonical_and_tampered_last_good_rejected(self):
        data = {'schema': 1, 'kind': 'baseline', 'prefixes': ['77.88.8.8/32'],
                'force_prefixes': [], 'address_count': 1, 'sources': {}}
        data['payload_sha256'] = update.payload_hash(data)
        self.assertEqual(update.validate_state(data, geo, baseline=True)[0],
                         ['77.88.8.8/32'])
        data['address_count'] = 2
        with self.assertRaises(ValueError):
            update.validate_state(data, geo, baseline=True)

    def test_force_egress_order_is_before_ru_set(self):
        rules = (ROOT / 'scripts/task08/ru.nft').read_text(encoding='utf-8')
        self.assertLess(rules.index('ip daddr @force_egress meta mark set 0x702'),
                        rules.index('ip daddr @ru_set meta mark set 0x701'))

    def test_nft_check_failure_preserves_last_good(self):
        old = {'kind': 'baseline', 'prefixes': ['77.88.8.8/32'],
               'force_prefixes': [], 'address_count': 1}
        new = {'kind': 'conservative_ru_ipv4_intersection',
               'prefixes': ['77.88.8.0/24'], 'force_prefixes': [],
               'address_count': 256}
        ledger = {'own_table_sha256': 'known-good'}
        with (patch.object(update, 'CURRENT', types.SimpleNamespace(exists=lambda: False)),
              patch.object(update, 'root_json', side_effect=[old, ledger]),
              patch.object(update, 'validate_state', return_value=(new['prefixes'], [])),
              patch.object(update, 'nft_elements', side_effect=[old['prefixes'], []]),
              patch.object(update, 'own_hash', return_value='known-good'),
              patch.object(update, 'run', side_effect=RuntimeError('nft check failed')) as run,
              patch.object(update, 'write_json') as write):
            with self.assertRaises(RuntimeError):
                update.apply_state(new, None, None)
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0], [update.NFT, '-c', '-f', '-'])
            write.assert_not_called()


if __name__ == '__main__':
    unittest.main()
