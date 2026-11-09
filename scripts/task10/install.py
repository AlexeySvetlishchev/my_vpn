#!/usr/bin/python3
"""Install TASK10 sources and its socket policy, preserving client routing."""
import hashlib,json,os,shutil,subprocess,sys,time
from pathlib import Path

FILES=('bot.py','broker.py','telegram_api.py','bot_entry.py','broker_entry.py',
       'egress.py','egress_control.py','egress_entry.py','qr.py','rollback_entry.py')
UNITS=('vpn-task10-broker.service','vpn-task10-bot.service','vpn-task10-egress.service')
def publish(source,target,mode=0o644):
    target=Path(target);temp=target.with_name(target.name+'.task10-new')
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:
        with os.fdopen(fd,'wb') as out:
            out.write(Path(source).read_bytes());out.flush();os.fchmod(out.fileno(),mode);os.fsync(out.fileno())
        os.replace(temp,target)
        fd=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:temp.unlink(missing_ok=True)
def main():
    assert os.geteuid()==0
    src=Path(__file__).resolve().parent
    manifest=json.loads((src/'manifest.json').read_text())
    for n in FILES+UNITS:
        if hashlib.sha256((src/n).read_bytes()).hexdigest()!=manifest[n]:raise RuntimeError('delivery_hash_mismatch')
        if n.endswith('.py'):compile((src/n).read_bytes(),n,'exec')
    recovery=src.parent/'task08/recover.py'
    assert hashlib.sha256(recovery.read_bytes()).hexdigest()==manifest['task08-recover.py']
    compile(recovery.read_bytes(),'recover.py','exec')
    result=subprocess.run(['/usr/local/sbin/vpnctl','--json','diagnostics'],capture_output=True,timeout=60,check=True)
    health=json.loads(result.stdout)['data']
    assert not any(health['peer_drift'].values()) and all(health['services'].values())
    backup=Path('/var/backups/vpn-task10')/time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())
    backup.mkdir(parents=True,mode=0o700);os.chmod(backup.parent,0o700)
    for source,name in [(Path('/opt/vpn-task08/recover.py'),'task08-recover.py'),
                        (Path('/var/lib/vpn-task08/active.json'),'task08-active.json')]:
        shutil.copy2(source,backup/name);os.chmod(backup/name,0o600)
    for args,name in [(['ip','-j','-4','rule','show'],'rules.json'),
                      (['ip','-j','-4','route','show','table','main'],'main-routes.json')]:
        (backup/name).write_bytes(subprocess.check_output(args))
    for n in UNITS:
        path=Path('/etc/systemd/system')/n
        if path.exists():shutil.copy2(path,backup/n)
    package=Path('/opt/vpn-task10')
    if package.exists():shutil.copytree(package,backup/'package')
    package.mkdir(mode=0o755,exist_ok=True)
    for n in FILES:publish(src/n,package/n)
    publish(src/'manifest.json',package/'manifest.json')
    for n in UNITS:
        target=Path('/etc/systemd/system')/n
        publish(src/n,target)
    publish(recovery,'/opt/vpn-task08/recover.py')
    config=Path('/etc/vpn-task10');config.mkdir(mode=0o700,exist_ok=True)
    record=config/'installation.json'
    if not record.exists():
        candidates=[]
        for old in sorted(backup.parent.iterdir()):
            helper=old/'task08-recover.py';active=old/'task08-active.json'
            if (helper.exists() and active.exists() and
                    hashlib.sha256(helper.read_bytes()).hexdigest()==manifest['legacy-task08-recover-sha256'] and
                    len(json.loads(active.read_text()).get('rules4',[]))==7):candidates.append(old)
        assert candidates,'original_task08_baseline_missing'
        fd=os.open(record,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'w') as out:
            json.dump({'schema':1,'baseline':str(candidates[0]),
                       'original_recovery_sha256':manifest['legacy-task08-recover-sha256']},out)
            out.flush();os.fsync(out.fileno())
    # Existing Manager paths required by the broker sandbox, no VPN operations.
    Path('/etc/vpn-task09/devices').mkdir(mode=0o700,exist_ok=True)
    subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=True)
    subprocess.run(['/usr/bin/systemd-analyze','verify',*(str(Path('/etc/systemd/system')/n) for n in UNITS)],check=True)
    subprocess.run(['/usr/bin/systemctl','enable','vpn-task10-bot.service'],check=True)
    subprocess.run(['/usr/bin/systemctl','enable','--now','vpn-task10-egress.service'],check=True)
    running=subprocess.run(['/usr/bin/systemctl','is-active','--quiet','vpn-task10-bot.service']).returncode==0
    print(json.dumps({'installed':True,'bot_running':running,'egress_active':True,
                      'credentials_required':not (config/'token').exists(),'backup':str(backup)}))
if __name__=='__main__':
    try:main()
    except Exception:
        print('{"installed":false,"error":"installation_failed"}')
        raise SystemExit(1)
