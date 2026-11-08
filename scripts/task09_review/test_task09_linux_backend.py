import tempfile
import unittest
from pathlib import Path
from unittest import mock

from task09_linux_backend import LinuxMigrationBackend
from task09_linux_storage import DurableStorage, OWNED_MODES


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.files = {n:self.root/n for n in OWNED_MODES}
        for name,path in self.files.items():
            path.write_bytes(name.encode())
            path.chmod(OWNED_MODES[name])
        (self.root/'active.json').write_text('{"schema":1}\n')
        (self.root/'active.json').chmod(0o600)
        self.src = self.root/'src'
        self.src.mkdir()
        (self.src/'ru.nft').write_bytes(b'old')
        (self.src/'ru-new.nft').write_bytes(b'new')
        self.storage = DurableStorage(self.root,self.files,require_root=False)

    def test_failclosed_action_is_mandatory(self):
        with self.assertRaisesRegex(ValueError,'fail-closed'):
            LinuxMigrationBackend('task09_test',self.storage,self.src,fail_closed=None)

    def test_source_path_exact_content_only(self):
        backend = LinuxMigrationBackend('task09_test',self.storage,self.src,fail_closed=lambda:None)
        self.assertEqual(backend.source_path(b'old'),self.src/'ru.nft')
        self.assertEqual(backend.source_path(b'new'),self.src/'ru-new.nft')
        with self.assertRaisesRegex(ValueError,'absent or ambiguous'):
            backend.source_path(b'arbitrary')

    def test_namespace_backend_routes_nft_through_fixed_namespace(self):
        runner = mock.Mock(return_value=mock.Mock(returncode=0,stdout=b'{"nftables":[]}'))
        backend = LinuxMigrationBackend('task09_test',self.storage,self.src,fail_closed=lambda:None)
        backend.nft.runner = runner
        backend.nft.nft_snapshot()
        command = runner.call_args.args[0]
        self.assertEqual(command[:5],['/usr/sbin/ip','netns','exec','task09_test','/usr/sbin/nft'])


if __name__ == '__main__': unittest.main()
