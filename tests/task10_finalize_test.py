"""Finalization guards: synthetic identities, no real peer or server access."""
from contextlib import ExitStack,nullcontext,redirect_stdout
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'scripts/task10'),str(ROOT/'scripts/task09')]
import retire_legacy as retire
import update_name
import rollback_entry as rollback
import egress_control as egress


class RetirementTests(unittest.TestCase):
    def fixture(self):
        old={'id':'old','profile':'Test_iPhone','ipv4':'10.203.253.2','state':'enabled',
             'present_in_awg':True,'handshake_age_seconds':20000,'rx_bytes':100,'tx_bytes':200}
        new={**old,'id':'new','profile':'Permanent_Phone','ipv4':'10.203.253.5','handshake_age_seconds':20}
        before={'devices':[old,new],'drift':{},'services':{'vpn':True}}
        user={'devices':[{'id':'old','profile_name':'Test_iPhone','ipv4':'10.203.253.2','origin':'task07'}]}
        return before,user
    def test_exact_target_and_real_separate_recent_traffic_required(self):
        before,user=self.fixture()
        old,permanent=retire.inspect(before,user)
        self.assertEqual(old['id'],'old');self.assertEqual(permanent[0]['id'],'new')
        for field,value in [('rx_bytes',0),('handshake_age_seconds',None),
                            ('handshake_age_seconds',601),('present_in_awg',False)]:
            bad=copy.deepcopy(before);bad['devices'][1][field]=value
            with self.assertRaises(AssertionError):retire.inspect(bad,user)
    def test_wrong_old_identity_refused(self):
        before,user=self.fixture();user['devices'][0]['origin']='manager'
        with self.assertRaises(AssertionError):retire.inspect(before,user)
    def test_preserved_permanent_profile_and_real_revocation(self):
        before,_=self.fixture();after=copy.deepcopy(before)
        after['devices'][0].update(state='revoked',present_in_awg=False)
        retire.verify_preserved(before,after,'old')
        after['devices'][1]['present_in_awg']=False
        with self.assertRaises(AssertionError):retire.verify_preserved(before,after,'old')


class NameUpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.stage=self.root/'stage';self.opt=self.root/'opt'
        self.backups=self.root/'backup';self.backups.mkdir()
        self.old={'task09/manager_formats.py':b"SERVER_DISPLAY_NAME = 'synthetic-old'\n",
                  'task10/rollback_entry.py':b'# old rollback\n'}
        self.new={'task09/manager_formats.py':b"SERVER_DISPLAY_NAME = 'synthetic-new'\n",
                  'task10/rollback_entry.py':b'# new rollback\n'}
        base=update_name.base
        old_manifest={'rollback_entry.py':base.sha(self.old['task10/rollback_entry.py']),'egress.py':'keep-pin'}
        new_manifest={'rollback_entry.py':base.sha(self.new['task10/rollback_entry.py']),'egress.py':'keep-pin'}
        self.old['task10/manifest.json']=json.dumps(old_manifest).encode()
        self.new['task10/manifest.json']=json.dumps(new_manifest).encode()
        for name in self.new:
            task,file=name.split('/')
            source=self.stage/name;source.parent.mkdir(parents=True,exist_ok=True);source.write_bytes(self.new[name])
            dest=self.opt/('vpn-'+task)/file;dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_bytes(self.old[name]);dest.chmod(0o644)
        (self.stage/'final-sha256.json').write_text(json.dumps({n:base.sha(v) for n,v in self.new.items()}))
        stack=ExitStack();self.addCleanup(stack.close)
        for module,name,value in [(base,'ROOT',self.opt),(base,'BACKUPS',self.backups),
                (update_name,'__file__',str(self.stage/'task10/update_name.py')),
                (update_name,'EXPECTED',{k:base.sha(v) for k,v in self.old.items() if k.endswith('.py')})]:
            stack.enter_context(patch.object(module,name,value))
        stack.enter_context(patch.object(sys,'argv',['update_name.py']))
        stack.enter_context(patch('manager_lock.process_lock',nullcontext))
        stack.enter_context(patch.object(base,'system'))
        stack.enter_context(patch.object(base,'health'))
        stack.enter_context(patch.object(base,'peers',return_value=b'unchanged'))
        stack.enter_context(patch.object(base,'unchanged_snapshot',return_value='unchanged'))
        self.start=stack.enter_context(patch.object(base,'start'))
        stack.enter_context(redirect_stdout(io.StringIO()))
    def test_name_apply_and_addressed_restore(self):
        update_name.main()
        for name,data in self.new.items():self.assertEqual(update_name.base.target(name).read_bytes(),data)
        update_name.base.restore(next(self.backups.iterdir()))
        for name,data in self.old.items():self.assertEqual(update_name.base.target(name).read_bytes(),data)
    def test_failed_start_restores_exact_prior_files(self):
        self.start.side_effect=[RuntimeError('synthetic-failure'),None]
        with self.assertRaises(RuntimeError):update_name.main()
        for name,data in self.old.items():self.assertEqual(update_name.base.target(name).read_bytes(),data)
    def test_refuse_non_name_format_changes_before_stop(self):
        path=self.stage/'task09/manager_formats.py';path.write_bytes(path.read_bytes()+b'# another change\n')
        hashes=json.loads((self.stage/'final-sha256.json').read_text());hashes['task09/manager_formats.py']=update_name.base.sha(path.read_bytes())
        (self.stage/'final-sha256.json').write_text(json.dumps(hashes))
        with self.assertRaises(AssertionError):update_name.main()
        self.assertFalse(self.start.called)


class RollbackCheckTests(unittest.TestCase):
    def test_check_is_read_only_and_detects_manifest_drift(self):
        with tempfile.TemporaryDirectory() as folder,ExitStack() as stack:
            root=Path(folder)
            def mapped(path):return root/str(path).lstrip('/')
            baseline='/var/backups/vpn-task10/original'
            files={'/opt/vpn-task10/bot.py':b'# bot\n',
                   '/opt/vpn-task08/recover.py':b'# current\n',
                   baseline+'/task08-recover.py':b'# original\n'}
            for name,data in files.items():
                path=mapped(name);path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
            record={'baseline':baseline,'original_recovery_sha256':rollback.sha(mapped(baseline+'/task08-recover.py'))}
            mapped('/etc/vpn-task10').mkdir(parents=True)
            mapped('/etc/vpn-task10/installation.json').write_text(json.dumps(record))
            manifest={'bot.py':rollback.sha(mapped('/opt/vpn-task10/bot.py')),
                      'task08-recover.py':rollback.sha(mapped('/opt/vpn-task08/recover.py'))}
            mapped('/opt/vpn-task10/manifest.json').write_text(json.dumps(manifest))
            marker=root/'marker';marker.write_text(json.dumps({'schema':1,'role':'ru','mark':'0x704','rules4':egress.EXPECTED}))
            ledger=root/'ledger';ledger.write_text(json.dumps({'rules4':[{'priority':i} for i in range(7)]+egress.EXPECTED}))
            stack.enter_context(patch.object(rollback,'Path',side_effect=mapped))
            stack.enter_context(patch.object(egress,'STATE',marker));stack.enter_context(patch.object(egress,'LEDGER',ledger))
            stack.enter_context(patch.object(egress,'rules',return_value=egress.EXPECTED))
            system=stack.enter_context(patch.object(rollback.subprocess,'run',side_effect=AssertionError('mutation')))
            remove=stack.enter_context(patch.object(rollback,'action',side_effect=AssertionError('mutation')))
            stack.enter_context(redirect_stdout(io.StringIO()))
            rollback.main('check');self.assertFalse(system.called);self.assertFalse(remove.called)
            mapped('/opt/vpn-task10/bot.py').write_bytes(b'# changed\n')
            with self.assertRaises(AssertionError):rollback.main('check')


if __name__=='__main__':unittest.main()
