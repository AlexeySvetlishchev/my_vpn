"""Tests use a fake runner; they NEVER access the kernel nftables interface."""
import json
import unittest
from task09_linux_nft import NamespaceNft
from task09_nft_plan import owned_hash


class Result:
    def __init__(self, content=b'{}', code=0):
        self.stdout = content
        self.stderr = b''
        self.returncode = code


class TestNamespaceNft(unittest.TestCase):
    def setUp(self):
        self.calls=[]
        self.payload={'nftables': [
            {'table': {'family': 'ip', 'name': 'vpn_task08_ru', 'handle': 2}},
            {'rule': {'family': 'ip', 'table': 'vpn_task08_ru', 'chain': 'forward',
                      'expr': [{'accept': None}], 'handle': 42, 'comment': 'vpn-task08-owned'}}]}

        def runner(cmd, **kwargs):
            self.calls.append((cmd, kwargs.get('input')))
            return Result(json.dumps(self.payload).encode())
        self.adapter=NamespaceNft('task09-test', runner=runner)

    def test_explicit_namespace_validation(self):
        for bad in ('', '../x', 'evil;rm', 'some name', '/proc/self/ns/net'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                NamespaceNft(bad)

    def test_snapshot_preserves_task08_ownership_handle_format(self):
        plain, handles = self.adapter.nft_snapshot()
        self.assertEqual(plain['nftables'][0]['table']['handle'], 2)
        self.assertEqual(plain['nftables'][1]['rule']['handle'], 42)
        self.assertEqual(handles['nftables'][1]['rule']['handle'], 42)
        self.assertEqual(owned_hash(plain), owned_hash(handles))
        self.assertEqual(self.calls[0][0][:5], ['/usr/sbin/ip','netns','exec','task09-test','/usr/sbin/nft'])

    def test_batch_check_before_commit(self):
        self.adapter.apply_batch(b'replace rule ip vpn_task08_ru forward handle 42 accept\n')
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.calls[0][0][-3:], ['-c', '-f', '-'])
        self.assertEqual(self.calls[1][0][-2:], ['-f', '-'])

    def test_refuses_destructive_batch(self):
        for script in (b'flush set ip x y', b'delete table ip x', b'FLUSH TABLE ip x'):
            with self.assertRaises(ValueError):
                self.adapter.apply_batch(script)
        self.assertFalse(self.calls)

    def test_failure_during_check_prevents_apply(self):
        def badrunner(cmd, **kwargs):
            self.calls.append((cmd, kwargs.get('input')))
            return Result(code=1)
        adapter=NamespaceNft('test', runner=badrunner)
        with self.assertRaises(RuntimeError):
            adapter.apply_batch(b'replace rule ip x y handle 12 accept')
        self.assertEqual(len(self.calls), 1)


if __name__=='__main__': unittest.main()
