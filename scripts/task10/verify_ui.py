"""Read-only post-update proof; never invokes routing/failover test helpers."""
import json,subprocess
from pathlib import Path

def run(args):return subprocess.check_output(args,stderr=subprocess.DEVNULL,timeout=60)
def main():
    backup=Path('/var/backups/vpn-task10/ui-20261109T085532Z')
    def parsed(data):return dict(line.split('\t',1) for line in data.decode().splitlines())
    baseline=parsed((backup/'peers-before.txt').read_bytes())
    current=parsed(run(['/opt/vpn-task07/awg','show','awg-client','allowed-ips']))
    assert all(current.get(key)==ip for key,ip in baseline.items())
    status=json.loads(run(['/usr/local/sbin/vpnctl','--json','status']))['data']
    phone=next(d for d in status['devices'] if d['profile']=='Test_iPhone')
    assert phone['present_in_awg'] and phone['state']=='enabled'
    diagnostic=json.loads(run(['/usr/local/sbin/vpnctl','--json','diagnostics']))['data']
    assert not any(diagnostic['peer_drift'].values()) and all(diagnostic['services'].values())
    logs=run(['/usr/bin/journalctl','-u','vpn-task10-bot.service','--since','2026-11-09 08:55:32','-o','cat','--no-pager'])
    assert Path('/etc/vpn-task10/token').read_bytes().strip() not in logs
    assert b'PrivateKey =' not in logs and b'[Interface]' not in logs
    assert b'telegram_connected' in logs
    print(json.dumps({'existing_peers_preserved':True,'Test_iPhone_enabled_and_present':True,
                      'baseline_peer_count':len(baseline),'current_peer_count':len(current),
                      'manager_healthy':True,'drift':False,'telegram_connected':True,
                      'token_or_profile_in_bot_log':False}))
if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(json.dumps({'ui_verification':False,'category':type(exc).__name__}));raise SystemExit(1)
