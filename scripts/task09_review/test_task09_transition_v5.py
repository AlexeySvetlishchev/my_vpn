"""Offline model of dynamic live hash/handle transition, NOT a kernel nft test."""
import contextlib
import copy
import ipaddress
import json
import re
from pathlib import Path
import tempfile
import unittest

from task09_linux_storage import DurableStorage, OWNED_MODES
from task09_nft_plan import owned_hash, source_rules, owned
from task09_transition_v5 import Package, Transition, RecoveryRequired, TransitionError

HERE = Path(__file__).parent


class Simulation:
    def __init__(self, error_at=None):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.old_source = (HERE / 'fixtures' / 'ru.nft').read_bytes()
        self.new_source = (HERE / 'staged-task09' / 'ru.nft').read_bytes()
        old_names = {'ru.nft':'ru.nft','apply.py':'apply.py',
                     'rollback.py':'rollback.py','vpn-task07':'helper.py'}
        self.package = Package(
            {n:(HERE/'fixtures'/old_names[n]).read_bytes() for n in OWNED_MODES},
            {n:(HERE/'staged-task09'/n).read_bytes() for n in OWNED_MODES})
        paths = {n: self.root / n for n in OWNED_MODES}
        for n, path in paths.items():
            path.write_bytes(self.package.old[n])
            path.chmod(OWNED_MODES[n])
        (self.root / 'old-source.nft').write_bytes(self.old_source)
        (self.root / 'new-source.nft').write_bytes(self.new_source)
        self.storage = DurableStorage(self.root, paths, require_root=False)
        self.state = 'old'
        self.handle_seed = 100
        self.closed = False
        self.error_at = error_at
        self.files_written = 0
        self.drift = False
        self.storage.ledger_write({'schema': 1, 'role': 'ru', 'phase': 'active',
                                   'own_table_sha256': self.nft_snapshot_hash(), 'rules4': []})

    def close(self):
        self.tmp.cleanup()

    def source_path(self, data):
        if data == self.old_source:
            return self.root / 'old-source.nft'
        if data == self.new_source:
            return self.root / 'new-source.nft'
        raise ValueError('unrecognised source')

    def nft_snapshot(self):
        source = self.old_source if self.state == 'old' else self.new_source
        entries = source_rules(self.root / ('old-source.nft' if self.state == 'old' else 'new-source.nft'))
        rows = [{'table': {'family': 'ip', 'name': 'vpn_task08_ru'}}]
        handled = copy.deepcopy(rows)
        i = self.handle_seed
        for chain, rules in entries.items():
            for rule_text in rules:
                expr = self.rule_expr(rule_text)
                rule = {'family': 'ip', 'table': 'vpn_task08_ru', 'chain': chain,
                        'expr': expr, 'comment': 'vpn-task08-owned'}
                if self.drift and chain == 'input' and rule_text.startswith('iifname "awg-client" ip saddr'):
                    rule['expr'].append({'drop':None})
                rows.append({'rule': copy.deepcopy(rule)})
                handled.append({'rule': dict(rule, handle=i)})
                i += 17
        return {'nftables': rows}, {'nftables': handled}

    @staticmethod
    def rule_expr(text):
        if text.startswith('iifname "awg-client" ip saddr {') and text.endswith(' drop comment "vpn-task08-owned"'):
            return [
                {'match':{'op':'==','left':{'meta':{'key':'iifname'}},'right':'awg-client'}},
                {'match':{'op':'==','left':{'payload':{'protocol':'ip','field':'saddr'}},
                          'right':{'set':['10.203.253.0','10.203.253.1','10.203.253.255']}}},
                {'drop':None}]
        expr=[]
        match=re.search(r'ip (saddr|daddr) (!= )?([0-9.]+(?:/\d+)?)',text)
        if match:
            field,not_equal,value=match.groups()
            if '/' in value:
                net=ipaddress.ip_network(value,strict=False)
                right={'prefix':{'addr':str(net.network_address),'len':net.prefixlen}}
            else:
                right=value
            expr.append({'match':{'op':'!=' if not_equal else '==',
                 'left':{'payload':{'protocol':'ip','field':field}},'right':right}})
        expr.append({'accept':None})
        return expr

    def nft_snapshot_hash(self):
        return owned_hash(self.nft_snapshot()[0])

    def apply_batch(self, batch):
        if self.error_at == 'nft_forward' and self.state == 'old':
            self.error_at = None
            raise OSError('nft forward failed')
        script = batch.decode()
        if self.state == 'old':
            assert script.count('replace rule') == 6 and script.count('insert rule') == 1
            self.state = 'new'
        else:
            assert script.count('replace rule') == 6 and script.count('delete rule') == 1
            # Arbitrary renumber after the forward transaction.
            self.state = 'old'
        self.handle_seed += 500

    def read_file(self, n):
        return self.storage.read_file(n)

    def replace_file(self, n, data):
        self.files_written += 1
        if self.error_at == 'file' and self.files_written == 2:
            self.error_at = None
            raise OSError('file swap interrupted')
        return self.storage.replace_file(n, data)

    def ledger_read(self):
        return self.storage.ledger_read()

    def ledger_write(self, v):
        return self.storage.ledger_write(v)

    def journal_read(self):
        return self.storage.journal_read()

    def journal_write(self, v):
        return self.storage.journal_write(v)

    def journal_clear(self):
        return self.storage.journal_clear()

    def fail_closed(self):
        self.closed = True

    @contextlib.contextmanager
    def lock_all(self):
        with self.storage.lock_all():
            yield


class TestDynamicMigration(unittest.TestCase):
    def setUp(self):
        self.b = Simulation()
        self.addCleanup(self.b.close)
        (self.b.root / 'old-source.nft').write_bytes(self.b.old_source)
        (self.b.root / 'new-source.nft').write_bytes(self.b.new_source)
        self.old_hash = self.b.nft_snapshot_hash()

    def assert_baseline(self):
        self.assertEqual(self.b.state, 'old')
        self.assertEqual(self.b.ledger_read()['own_table_sha256'], self.old_hash)
        self.assertTrue(all(self.b.read_file(n) == self.b.package.old[n] for n in OWNED_MODES))
        self.assertIsNone(self.b.journal_read())

    def test_success_captures_actual_post_hash(self):
        result = Transition(self.b).apply(self.b.package)
        self.assertTrue(result['installed'])
        self.assertEqual(self.b.state, 'new')
        self.assertEqual(result['nft_sha256'], self.b.nft_snapshot_hash())
        self.assertEqual(self.b.ledger_read()['own_table_sha256'], result['nft_sha256'])
        self.assertIsNone(self.b.journal_read())

    def test_forward_error_restores_baseline(self):
        self.b.error_at = 'nft_forward'
        with self.assertRaises(OSError):
            Transition(self.b).apply(self.b.package)
        self.assert_baseline()

    def test_file_error_restores_using_fresh_handles(self):
        self.b.error_at = 'file'
        with self.assertRaises(OSError):
            Transition(self.b).apply(self.b.package)
        self.assert_baseline()
        self.assertGreater(self.b.handle_seed, 100)

    def test_each_file_rename_failure_restores_baseline(self):
        for fail_index in range(1, 5):
            with self.subTest(file_rename=fail_index):
                b = Simulation(error_at=None)
                try:
                    original = b.replace_file
                    count = {'n': 0}
                    def fail_one(name, data):
                        count['n'] += 1
                        if count['n'] == fail_index:
                            raise OSError('injected file replacement failure')
                        return original(name, data)
                    b.replace_file = fail_one
                    with self.assertRaises(OSError):
                        Transition(b).apply(b.package)
                    self.assertEqual(b.state, 'old')
                    self.assertTrue(all(b.read_file(n) == b.package.old[n] for n in OWNED_MODES))
                    self.assertEqual(b.ledger_read()['own_table_sha256'], b.nft_snapshot_hash())
                    self.assertIsNone(b.journal_read())
                finally:
                    b.close()

    def test_ledger_publication_failure_restores_all_baseline(self):
        original = self.b.ledger_write
        first = {'n':0}
        def fail_after_publish(data):
            first['n'] += 1
            original(data)
            if first['n'] == 1:
                raise OSError('injected crash after ledger rename')
        self.b.ledger_write = fail_after_publish
        with self.assertRaises(OSError):
            Transition(self.b).apply(self.b.package)
        self.assert_baseline()

    def test_journal_state_write_failures_restore_baseline(self):
        for target_state in ('nft_applied','files_applied'):
            with self.subTest(journal_state=target_state):
                b = Simulation()
                original = b.journal_write
                triggered = {'yes':False}
                def fail_after_journal(record):
                    original(record)
                    if record.get('state') == target_state and not triggered['yes']:
                        triggered['yes'] = True
                        raise OSError('injected journal boundary failure')
                b.journal_write = fail_after_journal
                try:
                    with self.assertRaises(OSError): Transition(b).apply(b.package)
                    self.assertEqual(b.state,'old')
                    self.assertTrue(all(b.read_file(n)==b.package.old[n] for n in OWNED_MODES))
                    self.assertIsNone(b.journal_read())
                finally: b.close()

    def test_recover_after_interruption_post_nft(self):
        record = {'schema': 1, 'state': 'prepared', 'fingerprint': self.b.package.fingerprint(),
                  'baseline_ledger': self.b.ledger_read(), 'original_nft_hash': self.old_hash,
                  'baseline_nft': {'nftables':owned(self.b.nft_snapshot()[0])}}
        self.b.journal_write(record)
        self.b.state = 'new'
        self.b.handle_seed = 9000
        self.assertTrue(Transition(self.b).recover(self.b.package))
        self.assert_baseline()

    def test_recover_after_partial_files(self):
        record = {'schema': 1, 'state': 'files_applied', 'fingerprint': self.b.package.fingerprint(),
                  'baseline_ledger': self.b.ledger_read(), 'original_nft_hash': self.old_hash,
                  'baseline_nft': {'nftables':owned(self.b.nft_snapshot()[0])}}
        self.b.journal_write(record)
        self.b.state = 'new'
        self.b.replace_file('apply.py', self.b.package.new['apply.py'])
        self.assertTrue(Transition(self.b).recover(self.b.package))
        self.assert_baseline()

    def test_recover_from_every_durable_transition_boundary(self):
        for state, file_count, ledger_new in (
                ('prepared', 0, False), ('nft_applied', 0, False),
                ('files_applied', 4, False), ('files_applied', 4, True),
                ('rolling_back', 2, True)):
            with self.subTest(state=state, file_count=file_count, ledger_new=ledger_new):
                b = Simulation()
                try:
                    old_ledger = b.ledger_read()
                    record = {'schema':1,'state':state,
                              'fingerprint':b.package.fingerprint(),
                              'baseline_ledger':old_ledger,
                              'original_nft_hash':b.nft_snapshot_hash(),
                              'baseline_nft':{'nftables':owned(b.nft_snapshot()[0])}}
                    b.journal_write(record)
                    if state != 'prepared': b.state = 'new'
                    for name in list(OWNED_MODES)[:file_count]:
                        b.replace_file(name,b.package.new[name])
                    if ledger_new:
                        current = dict(old_ledger)
                        current['own_table_sha256'] = b.nft_snapshot_hash()
                        b.ledger_write(current)
                    self.assertTrue(Transition(b).recover(b.package))
                    self.assertEqual(b.state,'old')
                    self.assertTrue(all(b.read_file(n)==b.package.old[n] for n in OWNED_MODES))
                    self.assertEqual(b.ledger_read(),old_ledger)
                    self.assertIsNone(b.journal_read())
                finally:
                    b.close()

    def test_rollback_nft_failure_keeps_journal_and_fails_closed(self):
        b = Simulation(error_at='file')
        original_apply = b.apply_batch
        calls = {'n': 0}
        def fail_rollback(batch):
            calls['n'] += 1
            if calls['n'] == 2:
                raise OSError('injected reverse nft failure')
            return original_apply(batch)
        b.apply_batch = fail_rollback
        try:
            with self.assertRaises(RecoveryRequired):
                Transition(b).apply(b.package)
            self.assertTrue(b.closed)
            self.assertIsNotNone(b.journal_read())
        finally:
            b.close()

    def test_exact_live_expression_drift_is_not_rolled_over(self):
        b = Simulation()
        original_apply = b.apply_batch
        def add_drift(batch):
            original_apply(batch)
            b.drift = True
        b.apply_batch = add_drift
        try:
            with self.assertRaises(RecoveryRequired):
                Transition(b).apply(b.package)
            self.assertTrue(b.closed)
            self.assertIsNotNone(b.journal_read())
            self.assertEqual(b.state,'new')
        finally:
            b.close()

    def test_corrupt_journal_refuses_and_fails_closed(self):
        self.b.journal_write({'state': 'prepared', 'fingerprint': 'invalid'})
        with self.assertRaises(RecoveryRequired):
            Transition(self.b).recover(self.b.package)
        self.assertTrue(self.b.closed)

    def test_drift_is_not_overwritten(self):
        ledger = self.b.ledger_read()
        ledger['own_table_sha256'] = 'z' * 64
        self.b.ledger_write(ledger)
        with self.assertRaises(TransitionError):
            Transition(self.b).apply(self.b.package)
        self.assertEqual(self.b.state, 'old')


if __name__ == '__main__':
    unittest.main()
