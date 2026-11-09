"""TASK10-only stop/start cycle and invariant checks; no VPN service restart."""
import json,subprocess,sys
from pathlib import Path
sys.path.insert(0,'/opt/vpn-task10')
from egress_control import EXPECTED,selected

def run(args):return subprocess.check_output(args,stderr=subprocess.DEVNULL,timeout=60)
def system(*args):return run(['/usr/bin/systemctl',*args])
def main():
    baseline=Path('/var/backups/vpn-task10/20261109T072236Z')
    old_rules=json.loads((baseline/'rules.json').read_bytes())
    old_main=json.loads((baseline/'main-routes.json').read_bytes())
    try:
        system('stop','vpn-task10-bot.service','vpn-task10-broker.service','vpn-task10-egress.service')
        assert not selected(json.loads(run(['/usr/sbin/ip','-j','-4','rule','show'])))
        assert len(json.loads(Path('/var/lib/vpn-task08/active.json').read_text())['rules4'])==7
        system('start','vpn-task08-egress.service')
    finally:
        system('start','vpn-task10-egress.service','vpn-task10-bot.service')
    assert selected(json.loads(run(['/usr/sbin/ip','-j','-4','rule','show'])))==EXPECTED
    assert len(json.loads(Path('/var/lib/vpn-task08/active.json').read_text())['rules4'])==9
    current=json.loads(run(['/usr/sbin/ip','-j','-4','rule','show']))
    assert [r for r in current if r.get('priority') not in (10040,10041)]==old_rules
    assert json.loads(run(['/usr/sbin/ip','-j','-4','route','show','table','main']))==old_main
    system('start','vpn-task08-egress.service')
    run(['/usr/local/sbin/vpn-task08-rollback','ru','check'])
    health=json.loads(run(['/usr/local/sbin/vpnctl','--json','diagnostics']))['data']
    assert all(health['services'].values()) and not any(health['peer_drift'].values())
    print(json.dumps({'task10_restart_recovered':True,'task08_recovery_7_and_9_rules':True,
                      'client_rules_unchanged':True,'main_routes_unchanged':True,'ownership_ready':True}))
if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(json.dumps({'recovery_check':False,'category':type(exc).__name__}));raise SystemExit(1)
