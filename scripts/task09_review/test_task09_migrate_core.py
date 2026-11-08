"""Fault-injection suite for the offline TASK09 transition coordinator."""
import contextlib
import unittest
from task09_migrate_core import Coordinator, Plan, MigrationError, IncompleteRollback

OLD_HASH='a'*64
NEW_HASH='b'*64
NAMES=('ru.nft','apply.py','rollback.py','vpn-task07')

class Backend:
    def __init__(self, fail=None):
        self.files={name: ('old_'+name).encode() for name in NAMES}
        self.ledger={'schema':1,'role':'ru','phase':'active','own_table_sha256':OLD_HASH,'rules4':[]}
        self.nft=OLD_HASH
        self.journal=None
        self.fail=fail
        self.calls={}
        self.closed=False
    def hit(self, key):
        self.calls[key]=self.calls.get(key,0)+1
        if self.fail==key:
            self.fail=None
            raise OSError('injected crash at '+key)
    @contextlib.contextmanager
    def lock_all(self):
        yield
    def read_file(self, n):return self.files[n]
    def replace_file(self, n, data):
        self.hit('write_'+n)
        self.files[n]=data
    def ledger_read(self):return dict(self.ledger)
    def ledger_write(self, data):
        self.hit('ledger_write')
        self.ledger=dict(data)
    def observe_nft(self):return self.nft
    def nft_replace(self, batch):
        self.hit('nft')
        self.nft=NEW_HASH if batch==b'forward\n' else OLD_HASH
    def journal_read(self):return self.journal
    def journal_write(self, data):
        self.hit('journal_write')
        self.journal=dict(data)
    def journal_clear(self):
        self.hit('journal_clear')
        self.journal=None
    def fail_closed(self):self.closed=True


def plan():
    return Plan({n:('old_'+n).encode() for n in NAMES},
                {n:('new_'+n).encode() for n in NAMES},
                OLD_HASH, NEW_HASH, b'forward\n',b'reverse\n')

class TestCoordinator(unittest.TestCase):
    def clean_baseline(self,b):
        self.assertEqual(b.nft,OLD_HASH)
        self.assertEqual(b.ledger['own_table_sha256'],OLD_HASH)
        self.assertEqual(b.files,plan().old)
        self.assertIsNone(b.journal)
    def test_success(self):
        b=Backend();Coordinator(b).apply(plan())
        self.assertEqual(b.nft,NEW_HASH)
        self.assertEqual(b.ledger['own_table_sha256'],NEW_HASH)
        self.assertEqual(b.files,plan().new)
        self.assertIsNone(b.journal)
    def test_rejects_drift(self):
        b=Backend();b.nft='c'*64
        with self.assertRaises(MigrationError):Coordinator(b).apply(plan())
        self.assertEqual(b.files,plan().old)
    def test_failed_operations_restore(self):
        for fail in ['nft','write_ru.nft','write_apply.py','write_rollback.py',
                     'write_vpn-task07','ledger_write','journal_clear']:
            with self.subTest(fail=fail):
                b=Backend(fail)
                with self.assertRaises(OSError):Coordinator(b).apply(plan())
                self.clean_baseline(b)
    def test_crash_after_nft_recovery(self):
        b=Backend();b.nft=NEW_HASH
        b.journal={'state':'prepared','baseline_ledger':b.ledger_read(), 'plan':plan().fingerprint()}
        self.assertTrue(Coordinator(b).recover(plan()))
        self.clean_baseline(b)
    def test_crash_after_partial_files_recovery(self):
        b=Backend();b.nft=NEW_HASH
        b.files['ru.nft']=plan().new['ru.nft']
        b.journal={'state':'files_applied','baseline_ledger':b.ledger_read(), 'plan':plan().fingerprint()}
        self.assertTrue(Coordinator(b).recover(plan()))
        self.clean_baseline(b)
    def test_bad_nft_fails_closed(self):
        b=Backend();b.nft='c'*64
        b.journal={'state':'files_applied','baseline_ledger':b.ledger_read(), 'plan':plan().fingerprint()}
        with self.assertRaises(IncompleteRollback):Coordinator(b).recover(plan())
        self.assertTrue(b.closed)
    def test_rejects_nonatomic_geofeed_flush(self):
        p=plan()
        bad=Plan(p.old,p.new,p.original_nft_hash,p.updated_nft_hash,
                 b'flush set ip vpn_task08_ru ru_set\n',p.reverse_batch)
        with self.assertRaises(ValueError):bad.validate()
    def test_refuses_mismatched_crash_plan(self):
        b=Backend();b.journal={'state':'prepared','baseline_ledger':b.ledger_read(), 'plan':'invalid'}
        with self.assertRaises(IncompleteRollback):Coordinator(b).recover(plan())
        self.assertTrue(b.closed)

    def test_requires_preexisting_journal_recovery(self):
        b=Backend();b.journal={'state':'prepared','baseline_ledger':b.ledger_read(), 'plan':plan().fingerprint()}
        with self.assertRaises(MigrationError):Coordinator(b).apply(plan())

if __name__=='__main__':unittest.main()
