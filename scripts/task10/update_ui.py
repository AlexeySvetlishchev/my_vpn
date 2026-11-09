#!/usr/bin/python3
"""Owner-approved UI-only update. Never invoke the network/Manager installer."""
import hashlib,json,os,subprocess,sys,time
from pathlib import Path

FILES=('bot.py','telegram_api.py')
PACKAGE=Path('/opt/vpn-task10')
UNIT='vpn-task10-bot.service'
def run(argv):return subprocess.check_output(argv,stderr=subprocess.DEVNULL,timeout=60)
def system(*args):return run(['/usr/bin/systemctl',*args])
def pid(unit):return system('show',unit,'-p','MainPID','--value').strip()
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def peers():return run(['/opt/vpn-task07/awg','show','awg-client','allowed-ips'])
def health():
    data=json.loads(run(['/usr/local/sbin/vpnctl','--json','diagnostics']))['data']
    assert not any(data['peer_drift'].values()) and all(data['services'].values())
    return True
def publish(path,data,mode):
    temp=path.with_name(path.name+'.ui-new')
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:
        with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fchmod(f.fileno(),mode);os.fsync(f.fileno())
        os.replace(temp,path)
        fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:temp.unlink(missing_ok=True)
def main():
    assert os.geteuid()==0
    src=Path(__file__).resolve().parent
    old=json.loads((PACKAGE/'manifest.json').read_text());new=json.loads((src/'manifest.json').read_text())
    assert old.keys()==new.keys()
    assert all(old[k]==new[k] for k in old if k not in FILES),'non_ui_manifest_change'
    for n in FILES:
        assert sha(PACKAGE/n)==old[n] and sha(src/n)==new[n]
        compile((src/n).read_bytes(),n,'exec')
    health()
    unchanged_units=('vpn-task10-broker.service','vpn-task06-awg.service','vpn-task07-client.service')
    processes={u:pid(u) for u in unchanged_units}
    backup=Path('/var/backups/vpn-task10')/('ui-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime()))
    backup.mkdir(mode=0o700)
    for n in FILES+('manifest.json',):publish(backup/n,(PACKAGE/n).read_bytes(),0o600)
    stopped=False
    try:
        system('stop',UNIT);stopped=True
        baseline=peers();publish(backup/'peers-before.txt',baseline,0o600)
        for n in FILES:publish(PACKAGE/n,(src/n).read_bytes(),0o644)
        publish(PACKAGE/'manifest.json',(src/'manifest.json').read_bytes(),0o644)
        system('start',UNIT)
        connected=False
        for _ in range(30):
            current=pid(UNIT)
            if current not in (b'',b'0'):
                journal=run(['/usr/bin/journalctl','-b','-u',UNIT,'_PID='+current.decode(),'-o','cat','--no-pager'])
                if b'telegram_connected' in journal:connected=True;break
            time.sleep(.5)
        assert connected,'telegram_start_not_confirmed'
        assert peers()==baseline,'live_peers_changed'
        assert all(pid(u)==value for u,value in processes.items()),'unrelated_unit_restarted'
        health()
        sys.path.insert(0,str(PACKAGE))
        from telegram_api import Telegram
        from egress import Opener,dial_telegram
        me=Telegram(Path('/etc/vpn-task10/token').read_text().strip(),opener=Opener(dial_telegram)).call('getMe')
        assert me.get('is_bot')
        for n in FILES:assert sha(PACKAGE/n)==new[n]
        print(json.dumps({'ui_updated':True,'telegram_via_fr':True,'peers_unchanged':True,
                          'unrelated_services_unchanged':True,'backup':str(backup)}))
    except BaseException:
        if stopped:
            system('stop',UNIT)
            for n in FILES+('manifest.json',):publish(PACKAGE/n,(backup/n).read_bytes(),0o644)
            system('start',UNIT)
        raise
if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(json.dumps({'ui_updated':False,'category':type(exc).__name__}));raise SystemExit(1)
