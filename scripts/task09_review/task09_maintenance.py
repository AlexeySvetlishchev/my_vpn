#!/usr/bin/python3
"""Owner-approved RU maintenance cutover; fixed paths, no shell commands.

Run only from a root-owned delivered package. Client ingress is stopped before
the transaction; existing nft fail-closed rules remain installed throughout.
"""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tarfile
import time

from task09_linux_nft import NamespaceNft
from task09_linux_storage import DurableStorage, OWNED_MODES
from task09_transition_v5 import Package, Transition
from task09_integrity import validate
from task09_nft_plan import owned

HERE = Path(__file__).resolve().parent
FILES = {'ru.nft':Path('/opt/vpn-task08/ru.nft'),
         'apply.py':Path('/opt/vpn-task08/apply.py'),
         'rollback.py':Path('/usr/local/sbin/vpn-task08-rollback'),
         'vpn-task07':Path('/usr/local/sbin/vpn-task07')}
TIMERS = ['vpn-task06-monitor.timer','vpn-task08-egress.timer',
          'vpn-task08-ru-prefixes.timer']
CLIENT = 'vpn-task07-client.service'
DB = Path('/var/lib/vpn-task09/manager.sqlite3')
ACTIVATION = Path('/etc/vpn-task09/activation.json')

def run(argv, *, data=None, allow=False):
    r = subprocess.run(argv,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90)
    if r.returncode and not allow:
        raise RuntimeError('fixed operation failed: '+Path(argv[0]).name+' '+str(argv[1]))
    return r

def system(*args,allow=False): return run(['/usr/bin/systemctl',*args],allow=allow)
def active(unit): return system('is-active','--quiet',unit,allow=True).returncode == 0
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def write(path,data,mode=0o600):
    path=Path(path)
    tmp=path.with_name(path.name+'.task09-new')
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as f:
        f.write(data); f.flush(); os.fchmod(f.fileno(),mode); os.fsync(f.fileno())
    os.replace(tmp,path)
    DurableStorage._fsync_dir(path.parent)

class Storage(DurableStorage):
    def __init__(self,modes):
        super().__init__(Path('/var/lib/vpn-task08'),FILES)
        self.modes=modes
    def read_file(self,n): return self._read(self.files[n],self.modes[n])
    def replace_file(self,n,data): return self._write(self.files[n],data,self.modes[n])

class Backend:
    def __init__(self,storage,backup):
        self.storage=storage; self.backup=backup
        self.nft=NamespaceNft('unused')
        self.nft._run=self.nft_run
    def nft_run(self,*args,data=None):
        if data is not None and active(CLIENT):
            raise RuntimeError('client must be stopped for maintenance nft transaction')
        return run(['/usr/sbin/nft',*args],data=data).stdout
    def source_path(self,data):
        for path in (self.backup/'old'/'ru.nft',HERE/'staged-task09'/'ru.nft'):
            if path.read_bytes()==data:return path
        raise RuntimeError('unrecognized source')
    def fail_closed(self): system('stop',CLIENT,allow=True)
    def __getattr__(self,n):
        if n in ('nft_snapshot','apply_batch'):return getattr(self.nft,n)
        return getattr(self.storage,n)

def package(backup):
    return Package({n:(backup/'old'/n).read_bytes() for n in FILES},
                   {n:(HERE/'staged-task09'/n).read_bytes() for n in FILES})

def pause():
    system('stop',*TIMERS)
    system('stop','vpn-task08-ru-prefixes.service','vpn-task08-egress.service',
           'vpn-task06-monitor.service','vpn-task09-reconcile.timer',
           'vpn-task09-reconcile.service',allow=True)
    system('stop',CLIENT)
    if active(CLIENT):raise RuntimeError('client did not stop')

def restore(backup,meta):
    pause()
    system('disable','vpn-task09-reconcile.timer',allow=True)
    b=Backend(Storage(meta['modes']),backup)
    p=package(backup)
    t=Transition(b)
    with b.lock_all():
        t._rollback_locked(p,meta['transition'])
    # Restore only this stage's Manager/legacy config and DB, not global nft.
    for folder in ('etc/vpn-task07','etc/vpn-task09'):
        saved=backup/'files'/folder
        if saved.exists():
            for f in saved.rglob('*'):
                if f.is_file():
                    dest=Path('/')/f.relative_to(backup/'files')
                    dest.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                    write(dest,f.read_bytes(),stat.S_IMODE(f.stat().st_mode))
    if not meta['activation_existed']:ACTIVATION.unlink(missing_ok=True)
    write(DB,(backup/'sqlite.db').read_bytes())
    state=Path('/etc/vpn-task07/state.json')
    record=json.loads(state.read_text()); record['phase']='prepared'; record['ifindex']=None
    write(state,(json.dumps(record)+'\n').encode())
    system('daemon-reload')
    system('start',CLIENT)
    if not meta.get('client_enabled',False):system('disable',CLIENT)
    system('start','vpn-task08-egress.service','vpn-task08-dns.service')
    for timer,was in meta['timers'].items():
        if was:system('start',timer)
    run(['/usr/local/sbin/vpn-task08-rollback','ru','check'])

def deploy():
    assert os.geteuid()==0
    assert Path('/etc/vpn-task06/role').read_text().strip()=='ru'
    run(['/usr/local/sbin/vpn-task08-rollback','ru','check'])
    run(['/usr/local/sbin/vpn-task06','monitor'])
    # Public identity preflight is intentionally run before stopping awg-client.
    run(['/usr/bin/python3','-B','/opt/vpn-task09/manager_migrate.py','preflight'])
    modes={n:stat.S_IMODE(path.stat().st_mode) for n,path in FILES.items()}
    old={n:path.read_bytes() for n,path in FILES.items()}
    new={n:(HERE/'staged-task09'/n).read_bytes() for n in FILES}
    validate(old,new)
    backup=Path('/var/backups/vpn-task09')/time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())
    backup.mkdir(parents=True,mode=0o700)
    os.chmod(backup.parent,0o700)
    (backup/'old').mkdir(mode=0o700)
    for n,data in old.items():write(backup/'old'/n,data)
    timers={u:active(u) for u in TIMERS}
    from manager_lock import process_lock
    with process_lock():
        with sqlite3.connect(DB) as src, sqlite3.connect(backup/'sqlite.db') as dst:src.backup(dst)
        os.chmod(backup/'sqlite.db',0o600)
        roots=['etc/vpn-task07','etc/vpn-task09','opt/vpn-task07','opt/vpn-task08',
               'opt/vpn-task09','var/lib/vpn-task08','etc/systemd/system/vpn-task07-client.service']
        (backup/'files').mkdir(mode=0o700)
        import shutil
        for name in roots:
            source=Path('/')/name
            if not source.exists():continue
            dest=backup/'files'/name; dest.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            if source.is_dir():shutil.copytree(source,dest,symlinks=True)
            else:shutil.copy2(source,dest)
        secret_names=['server.key','client.key','client.pub','Test_iPhone.conf']
        secret_hash={n:digest(Path('/etc/vpn-task07')/n) for n in secret_names}
        b=Backend(Storage(modes),backup)
        plain,_=b.nft_snapshot()
        ledger=b.ledger_read()
        meta={'modes':modes,'timers':timers,'activation_existed':ACTIVATION.exists(),
              'client_enabled':system('is-enabled','--quiet',CLIENT,allow=True).returncode==0,
              'transition':{'schema':1,'state':'prepared','fingerprint':Package(old,new).fingerprint(),
                            'baseline_ledger':ledger,'original_nft_hash':ledger['own_table_sha256'],
                            'baseline_nft':{'nftables':owned(plain)}}}
        write(backup/'metadata.json',(json.dumps(meta)+'\n').encode())
        write(backup/'routes.json',run(['/usr/sbin/ip','-j','-4','route','show','table','main']).stdout)
        # Backup is completely prepared before the first service stop.
        print(json.dumps({'backup':str(backup),'stage':'backup_complete'}),flush=True)
        try:
            pause()
            Transition(b).apply(Package(old,new))
            ACTIVATION.parent.mkdir(mode=0o700,exist_ok=True)
            marker={'schema':1,'state':'approved','legacy_public_sha256':hashlib.sha256(
                    Path('/etc/vpn-task07/client.pub').read_bytes().strip()).hexdigest()}
            write(ACTIVATION,(json.dumps(marker)+'\n').encode())
            system('start',CLIENT)
            system('start','vpn-task08-egress.service','vpn-task08-dns.service')
            run(['/usr/local/sbin/vpn-task08-rollback','ru','check'])
            run(['/usr/local/sbin/vpn-task06','monitor'])
            # The enclosing process already holds Manager's lock; invoking
            # vpnctl as a child would correctly refuse with `busy`.
            from manager_db import Store
            from manager_runtime import Controller,AwgAdapter
            from vpnctl import services
            store=Store(DB)
            try:
                assert store.integrity_check()
                assert not any(Controller(store,AwgAdapter()).drift().values())
            finally:store.close()
            assert all(services().values())
            assert all(digest(Path('/etc/vpn-task07')/n)==v for n,v in secret_hash.items())
            assert json.loads((backup/'routes.json').read_bytes()) == json.loads(run(
                ['/usr/sbin/ip','-j','-4','route','show','table','main']).stdout)
            for timer,was in timers.items():
                if was:system('start',timer)
            print(json.dumps({'deployed':True,'backup':str(backup),'legacy_identity_unchanged':True}),flush=True)
        except BaseException:
            restore(backup,meta)
            print(json.dumps({'restored_baseline':True,'backup':str(backup)}),flush=True)
            raise

if __name__=='__main__':
    sys.path.insert(0,'/opt/vpn-task09')
    if sys.argv[1:]==['deploy']:deploy()
    elif len(sys.argv)==3 and sys.argv[1]=='rollback':
        backup=Path(sys.argv[2]).resolve()
        if backup.parent!=Path('/var/backups/vpn-task09'):raise RuntimeError('invalid backup path')
        restore(backup,json.loads((backup/'metadata.json').read_text()))
        print(json.dumps({'restored_baseline':True}))
    else:raise SystemExit(2)
