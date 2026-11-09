"""Addressed removal of TASK10 only. Refuse changed public sources/units."""
import hashlib,json,os,shutil,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,'/opt/vpn-task10')
from egress_control import action

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main(mode='remove'):
    assert os.geteuid()==0
    if mode not in ('remove','check'):raise ValueError('invalid_rollback_mode')
    root=Path('/opt/vpn-task10');config=Path('/etc/vpn-task10')
    manifest=json.loads((root/'manifest.json').read_text())
    record=json.loads((config/'installation.json').read_text())
    baseline=Path(record['baseline']).resolve()
    assert baseline.parent==Path('/var/backups/vpn-task10')
    original=baseline/'task08-recover.py'
    assert sha(original)==record['original_recovery_sha256']
    assert sha(Path('/opt/vpn-task08/recover.py'))==manifest['task08-recover.py']
    paths=[]
    for name,pin in manifest.items():
        if name.endswith('.service'):path=Path('/etc/systemd/system')/name
        elif name.endswith('.py') and name!='task08-recover.py':path=root/name
        else:continue
        assert sha(path)==pin
        paths.append(path)
    from egress_control import STATE, LEDGER, EXPECTED, selected, rules
    marker=json.loads(STATE.read_text())
    ledger=json.loads(LEDGER.read_text())
    assert marker=={'schema':1,'role':'ru','mark':'0x704','rules4':EXPECTED}
    assert selected(rules())==EXPECTED and selected(ledger['rules4'])==EXPECTED
    assert len([r for r in ledger['rules4'] if r.get('priority') not in (10040,10041)])==7
    if mode=='check':
        print(json.dumps({'task10_rollback_ready':True,'effects':'read_only',
                          'manager_peers_and_exports_retained':True}))
        return
    for args in [('disable','--now','vpn-task10-bot.service'),('disable','--now','vpn-task10-broker.service'),
                 ('disable','--now','vpn-task10-egress.service')]:
        subprocess.run(['/usr/bin/systemctl',*args],check=True)
    action('remove')
    backup=Path('/var/backups/vpn-task10')/('removed-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime()))
    backup.mkdir(mode=0o700)
    # Credential backups remain root-only on RU, never in the source package.
    for name in ('token','admins.json','installation.json','acceptance-messages.json'):
        path=config/name
        if path.exists():shutil.copy2(path,backup/name);os.chmod(backup/name,0o600);path.unlink()
    temp=Path('/opt/vpn-task08/recover.py.task10-rollback')
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
    with os.fdopen(fd,'wb') as f:f.write(original.read_bytes());f.flush();os.fchmod(f.fileno(),0o644);os.fsync(f.fileno())
    os.replace(temp,'/opt/vpn-task08/recover.py')
    for path in paths:path.unlink()
    (root/'manifest.json').unlink()
    if not list(root.iterdir()):root.rmdir()
    subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=True)
    subprocess.run(['/usr/local/sbin/vpn-task08-rollback','ru','check'],check=True,stdout=subprocess.DEVNULL)
    print(json.dumps({'task10_removed':True,'new_peers_removed':0,'credentials_backup':str(backup)}))
if __name__=='__main__':
    try:
        if sys.argv[1:] not in ([],['--check']):raise ValueError('invalid_arguments')
        main('check' if sys.argv[1:] else 'remove')
    except Exception:
        print('{"task10_removed":false,"error":"ownership_or_removal_conflict"}');raise SystemExit(1)
