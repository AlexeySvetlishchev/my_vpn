"""Read-only export rollout proof. Never exports/reissues a real profile."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


def run(argv):
    return subprocess.check_output(argv, stderr=subprocess.DEVNULL, timeout=60)


def main():
    sys.path[:0] = ['/opt/vpn-task09', '/opt/vpn-task10']
    from manager_formats import SERVER_DISPLAY_NAME
    assert SERVER_DISPLAY_NAME and len(SERVER_DISPLAY_NAME) <= 100
    status = json.loads(run(['/usr/local/sbin/vpnctl', '--json', 'status']))['data']
    diagnostics = json.loads(run(['/usr/local/sbin/vpnctl', '--json', 'diagnostics']))['data']
    assert all(diagnostics['services'].values()) and not any(diagnostics['peer_drift'].values())
    assert not diagnostics['incomplete_operations']
    enabled = [d for d in status['devices'] if d['state'] == 'enabled' and d['profile'] != 'Test_iPhone']
    assert enabled and all(d['present_in_awg'] for d in enabled)
    phone = next(d for d in status['devices'] if d['profile'] == 'Test_iPhone')
    root = Path('/opt/vpn-task10')
    manifest = json.loads((root/'manifest.json').read_text())
    for name, digest in manifest.items():
        if name == 'task08-recover.py':
            path = Path('/opt/vpn-task08/recover.py')
        elif name.endswith('.service'):
            path = Path('/etc/systemd/system')/name
        elif name.endswith('.py'):
            path = root/name
        else:
            continue
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
    pid = run(['/usr/bin/systemctl','show','vpn-task10-bot.service','-p','MainPID','--value']).strip().decode()
    assert pid and pid != '0'
    logs = run(['/usr/bin/journalctl','-b','-u','vpn-task10-bot.service',
                '-u','vpn-task10-broker.service','--since','-5min','-o','cat','--no-pager'])
    assert b'PrivateKey =' not in logs and b'[Interface]' not in logs and b'vpn://' not in logs
    assert not re.search(rb'[0-9]{5,15}:[A-Za-z0-9_-]{30,100}',logs)
    startup = run(['/usr/bin/journalctl','-b','-u','vpn-task10-bot.service',
                   '_PID='+pid,'-o','cat','--no-pager'])
    assert b'telegram_connected' in startup
    print(json.dumps({'named_native_export_installed':True,'manifest_valid':True,
                      'telegram_connected_via_fr':True,'manager_healthy':True,
                      'enabled_permanent_peers_present':True,
                      'Test_iPhone_state':phone['state'],
                      'Test_iPhone_present':phone['present_in_awg'],
                      'Test_iPhone_handshake_age_seconds':phone.get('handshake_age_seconds'),
                      'existing_devices':len(status['devices']),
                      'profile_or_token_detected_in_recent_logs':False,
                      'physical_named_import_tested':False}))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'export_verification':False,'category':type(exc).__name__}))
        raise SystemExit(1)
