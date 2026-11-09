"""Export updater fault tests. All files/units are isolated fakes, no server I/O."""
from contextlib import ExitStack, nullcontext, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path[:0] = [str(Path(__file__).resolve().parents[1]/'scripts/task10'),
               str(Path(__file__).resolve().parents[1]/'scripts/task09')]
import update_export as update


class ExportUpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.stage = self.root/'stage'
        self.opt = self.root/'opt'
        self.backups = self.root/'backups'
        self.backups.mkdir(mode=0o700)
        baseline = {}
        self.before = {}
        delivery = {}
        for group, names in [('task09',update.MANAGER_FILES),('task10',update.BOT_FILES)]:
            (self.stage/group).mkdir(parents=True)
            (self.opt/('vpn-'+group)).mkdir(parents=True)
            for name in names:
                key = group+'/'+name
                data = ('# new '+name+'\n').encode()
                (self.stage/key).write_bytes(data)
                delivery[key] = update.sha(data)
                path = self.opt/('vpn-'+group)/name
                if name == 'manager_formats.py':
                    self.before[key] = None
                    baseline[key] = None
                else:
                    old = ('# old '+name+'\n').encode()
                    path.write_bytes(old)
                    path.chmod(0o644)
                    self.before[key] = old
                    baseline[key] = update.sha(old)
        old_manifest = {n: baseline['task10/'+n] for n in update.BOT_FILES}
        old_manifest['egress.py'] = 'unchanged-pin'
        new_manifest = {n: delivery['task10/'+n] for n in update.BOT_FILES}
        new_manifest['egress.py'] = 'unchanged-pin'
        key = 'task10/manifest.json'
        self.before[key] = json.dumps(old_manifest).encode()
        update.target  # do not mock atomic writer or hash/file validation
        (self.opt/'vpn-task10/manifest.json').write_bytes(self.before[key])
        (self.opt/'vpn-task10/manifest.json').chmod(0o644)
        data = json.dumps(new_manifest).encode()
        (self.stage/key).write_bytes(data)
        delivery[key] = update.sha(data)
        (self.stage/'export-sha256.json').write_text(json.dumps(delivery))
        self.delivery = delivery
        self.commands = []
        stack = ExitStack()
        self.addCleanup(stack.close)
        for name, value in [('ROOT',self.opt),('BACKUPS',self.backups),('BASELINE',baseline),
                            ('__file__',str(self.stage/'task10/update_export.py'))]:
            stack.enter_context(patch.object(update,name,value))
        stack.enter_context(patch.object(sys,'argv',['update_export.py']))
        stack.enter_context(patch.object(update,'system',side_effect=lambda *args:self.commands.append(args)))
        stack.enter_context(patch.object(update,'health'))
        stack.enter_context(patch.object(update,'peers',return_value=b'unchanged-peer'))
        stack.enter_context(patch.object(update,'unchanged_snapshot',return_value={'unchanged':True}))
        stack.enter_context(patch('manager_lock.process_lock',nullcontext))
        self.start = stack.enter_context(patch.object(update,'start'))
        stack.enter_context(redirect_stdout(io.StringIO()))

    def assert_baseline(self):
        for name, content in self.before.items():
            path = update.target(name)
            self.assertEqual(path.read_bytes() if path.exists() else None,content)

    def test_apply_and_addressed_rollback(self):
        update.main()
        for name, digest in self.delivery.items():
            self.assertEqual(update.sha(update.target(name).read_bytes()),digest)
        backup = next(self.backups.iterdir())
        update.restore(backup)
        self.assert_baseline()
        self.assertTrue(all(cmd[1] in (update.BOT,update.BROKER) for cmd in self.commands))

    def test_failed_start_restores_all_files_and_removes_new_module(self):
        self.start.side_effect = [RuntimeError('synthetic-start-failure'),None]
        with self.assertRaises(RuntimeError):
            update.main()
        self.assert_baseline()
        self.assertEqual(self.start.call_count,2)

    def test_rejects_baseline_drift_before_stopping_bot(self):
        update.target('task09/vpnctl.py').write_bytes(b'# different\n')
        with self.assertRaises(AssertionError):
            update.main()
        self.assertFalse(self.commands)
        self.assertFalse(list(self.backups.iterdir()))

    def test_rejects_corrupt_delivery_before_mutation(self):
        (self.stage/'task09/manager_formats.py').write_bytes(b'# corrupt\n')
        with self.assertRaises(AssertionError):
            update.main()
        self.assertFalse(self.commands)
        self.assert_baseline()

    def test_partial_file_install_failure_automatically_restores(self):
        real_publish = update.publish
        failed = False
        def injected(path,data,mode):
            nonlocal failed
            if path == update.target('task10/broker.py') and not failed:
                failed = True
                raise OSError('synthetic-install-failure')
            return real_publish(path,data,mode)
        with patch.object(update,'publish',side_effect=injected):
            with self.assertRaises(OSError):
                update.main()
        self.assert_baseline()


if __name__ == '__main__':
    unittest.main()
