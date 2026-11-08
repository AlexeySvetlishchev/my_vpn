import hashlib
import tempfile
import unittest
from pathlib import Path
from task09_stage import build, sha, stage, OLD_RU_SHA, OLD_HELPER_PIN

SOURCES = Path(__file__).resolve().parent / 'fixtures'


class StageTests(unittest.TestCase):
    def test_stage_package_pins_are_consistent(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td)/'staged'
            m = stage(SOURCES, target)
            nft = (target/'ru.nft').read_bytes()
            helper = (target/'vpn-task07').read_bytes()
            self.assertEqual(nft.count(b'10.203.253.0/24'), 6)
            self.assertNotIn(b'ip saddr 10.203.253.2 ', nft)
            self.assertNotIn(b'ip saddr != 10.203.253.2 ', nft)
            self.assertIn(sha(nft).encode(), (target/'apply.py').read_bytes())
            self.assertIn(sha(helper).encode(), (target/'rollback.py').read_bytes())
            self.assertEqual(m['prepared']['ru.nft'], sha(nft))
            self.assertIn(b'77.88.8.8/32', nft)
            self.assertIn(b'force_egress', nft)
    def test_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td)/'stage'
            stage(SOURCES,target)
            with self.assertRaises(ValueError):
                stage(SOURCES,target)
    def test_detect_baseline_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)
            for n in ('ru.nft','apply.py','rollback.py','helper.py'):
                (p/n).write_bytes((SOURCES/n).read_bytes())
            (p/'ru.nft').write_bytes((p/'ru.nft').read_bytes()+b'\n')
            with self.assertRaisesRegex(ValueError, 'baseline'):
                build(p)
    def test_detect_helper_not_sqlite_aware(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)
            for n in ('ru.nft','apply.py','rollback.py','helper.py'):
                (p/n).write_bytes((SOURCES/n).read_bytes())
            (p/'helper.py').write_bytes(b'not a helper')
            with self.assertRaisesRegex(ValueError, 'SQLite'):
                build(p)
    def test_exact_rule_guard(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)
            for n in ('ru.nft','apply.py','rollback.py','helper.py'):
                (p/n).write_bytes((SOURCES/n).read_bytes())
            (p/'ru.nft').write_bytes((p/'ru.nft').read_bytes().replace(
                b'10.203.253.2',b'10.203.253.3',1))
            with self.assertRaises(ValueError):
                build(p)

if __name__=='__main__':
    unittest.main()
