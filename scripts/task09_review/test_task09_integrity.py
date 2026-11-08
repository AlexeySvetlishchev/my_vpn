import json
from pathlib import Path
import unittest

from task09_integrity import PackageMismatch, validate, verify_directories

ROOT = Path(__file__).resolve().parent


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        source = ROOT / 'fixtures'
        stage = ROOT / 'staged-task09'
        self.old = {k: (source / v).read_bytes() for k,v in {
            'ru.nft':'ru.nft', 'apply.py':'apply.py', 'rollback.py':'rollback.py', 'vpn-task07':'helper.py'}.items()}
        self.new = {k:(stage/k).read_bytes() for k in self.old}
        self.manifest = json.loads((stage/'manifest.json').read_text())

    def test_original_package_is_consistent(self):
        self.assertEqual(verify_directories(ROOT/'fixtures', ROOT/'staged-task09')['changed_rules'], 6)

    def test_reject_changed_rollback_pin(self):
        data = dict(self.new)
        data['rollback.py'] = data['rollback.py'].replace(b'TASK07_NEW = ', b'TASK07_MISSING = ')
        with self.assertRaises(PackageMismatch): validate(self.old,data)

    def test_reject_changed_apply_pin(self):
        data = dict(self.new)
        data['apply.py'] = data['apply.py'].replace(b"'ru': '", b"'ru': '0", 1)
        with self.assertRaises(PackageMismatch): validate(self.old,data)

    def test_reject_modified_source_without_matching_pin(self):
        data = dict(self.new)
        data['ru.nft'] += b'\n'
        with self.assertRaises(PackageMismatch): validate(self.old,data)

    def test_reject_unexpected_rule_change_even_with_matching_manifest(self):
        data = dict(self.new)
        data['ru.nft'] = data['ru.nft'].replace(b'eth0', b'eth1', 1)
        with self.assertRaises(PackageMismatch): validate(self.old,data)

    def test_reject_unexpected_rollback_change_even_with_correct_pin(self):
        data = dict(self.new)
        data['rollback.py'] += b'\n# stray change\n'
        with self.assertRaises(PackageMismatch): validate(self.old,data)

    def test_reject_false_manifest(self):
        manifest = dict(self.manifest)
        manifest['prepared'] = dict(manifest['prepared'], **{'ru.nft': 'f'*64})
        with self.assertRaises(PackageMismatch): validate(self.old,self.new,manifest)

    def test_reject_missing_guard(self):
        data = dict(self.new)
        lines = data['ru.nft'].splitlines(keepends=True)
        data['ru.nft'] = b''.join(l for l in lines if b'ip saddr { 10.203.253.0,' not in l)
        with self.assertRaises(PackageMismatch): validate(self.old,data)


if __name__ == '__main__': unittest.main()
