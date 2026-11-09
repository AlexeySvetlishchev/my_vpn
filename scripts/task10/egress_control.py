#!/usr/bin/python3
"""Own exactly two mark-0x704 RPDB rules; preserve all TASK08 client rules."""
import fcntl,hashlib,json,os,secrets,subprocess,sys
from pathlib import Path

ROOT=Path('/etc/vpn-task10');STATE=ROOT/'egress.json'
LEDGER=Path('/var/lib/vpn-task08/active.json')
LOCK=Path('/var/lib/vpn-task08/ru-prefix-update.lock')
PRIORITIES=(10040,10041)
EXPECTED=[{'priority':10040,'src':'all','fwmark':'0x704','table':'220'},
          {'priority':10041,'src':'all','fwmark':'0x704','action':'unreachable'}]

def run(args,allow=False):
    p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
    if p.returncode and not allow:raise RuntimeError('fixed_route_operation_failed')
    return p
def atomic(path,value):
    data=(json.dumps(value,sort_keys=True)+'\n').encode();tmp=path.with_name(path.name+'.task10-'+secrets.token_hex(8))
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
    os.replace(tmp,path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
def rules():return json.loads(run(['/usr/sbin/ip','-j','-4','rule','show']).stdout)
def selected(rows):return [r for r in rows if r.get('priority') in PRIORITIES]
def valid(rows):
    if len(rows)!=2 or [r.get('priority') for r in rows]!=list(PRIORITIES):return False
    return rows==EXPECTED
def action(mode):
    lock=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        ledger=json.loads(LEDGER.read_text());current=selected(rules())
        state=json.loads(STATE.read_text()) if STATE.exists() else None
        if state and state!={'schema':1,'role':'ru','mark':'0x704','rules4':EXPECTED}:raise RuntimeError('task10_marker_conflict')
        if current and (not state or any(r not in EXPECTED for r in current)):raise RuntimeError('task10_rule_conflict')
        base=[r for r in ledger['rules4'] if r.get('priority') not in PRIORITIES]
        if len(base)!=7:raise RuntimeError('task08_base_rule_conflict')
        if mode=='ensure':
            # Durable intent precedes rule creation, so interrupted setup can
            # safely finish only its exact recorded rules after reboot.
            if not state:atomic(STATE,{'schema':1,'role':'ru','mark':'0x704','rules4':EXPECTED})
            if EXPECTED[1] not in current:
                run(['/usr/sbin/ip','-4','rule','add','pref','10041','fwmark','0x704','unreachable'])
            if EXPECTED[0] not in current:
                run(['/usr/sbin/ip','-4','rule','add','pref','10040','fwmark','0x704','lookup','220'])
            current=selected(rules())
            if not valid(current):raise RuntimeError('unexpected_kernel_rule_format')
            atomic(STATE,{'schema':1,'role':'ru','mark':'0x704','rules4':current})
            ledger['rules4']=sorted(base+current,key=lambda r:r['priority']);atomic(LEDGER,ledger)
        elif mode=='remove':
            if current:
                # Remove lookup before terminal; no fallback leakage window.
                for pref in PRIORITIES:
                    if any(r['priority']==pref for r in current):run(['/usr/sbin/ip','-4','rule','del','pref',str(pref),'fwmark','0x704'])
            ledger['rules4']=base;atomic(LEDGER,ledger)
            STATE.unlink(missing_ok=True)
        else:raise ValueError('fixed_action_required')
        print(json.dumps({'task10_egress':mode,'new_peer':False}))
    finally:os.close(lock)
if __name__=='__main__':
    try:
        assert os.geteuid()==0 and sys.argv[1:] in (['ensure'],['remove'])
        action(sys.argv[1])
    except Exception:
        print('{"task10_egress":"refused"}');raise SystemExit(1)
