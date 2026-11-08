#!/usr/bin/python3
"""Brief RU transport-loss route probe with unconditional own-service recovery."""
import json
import os
import subprocess
import sys

ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'HOME': '/'}
SYSTEMCTL = '/usr/bin/systemctl'
IP = '/usr/sbin/ip'


def run(argv, required=True):
    proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          env=ENV, timeout=30, check=False)
    if required and proc.returncode:
        raise RuntimeError('fixed operation failed')
    return proc


def lookup():
    return run([IP, '-4', 'route', 'get', '1.1.1.1', 'from', '10.203.253.2',
                'iif', 'awg-client', 'mark', '0x702'], required=False)


def main():
    if os.geteuid() != 0 or len(sys.argv) != 1 or not os.path.exists('/etc/vpn-task06/role'):
        raise RuntimeError('root and fixed RU host required')
    if open('/etc/vpn-task06/role', encoding='ascii').read().strip() != 'ru':
        raise RuntimeError('RU role required')
    before = lookup()
    if before.returncode or b'dev awg-transport' not in before.stdout:
        raise RuntimeError('pretest foreign route is not via transport')
    run([SYSTEMCTL, 'stop', 'vpn-task08-egress.timer'])
    blocked = False
    restored = False
    try:
        run([SYSTEMCTL, 'stop', 'vpn-task06-awg.service'])
        after = lookup()
        blocked = after.returncode != 0 and b'dev eth0' not in after.stdout
    finally:
        try:
            run([SYSTEMCTL, 'start', 'vpn-task06-awg.service'])
            run([SYSTEMCTL, 'start', 'vpn-task08-egress.service'])
            run([SYSTEMCTL, 'start', 'vpn-task08-egress.timer'])
            run(['/usr/local/sbin/vpn-task06', 'monitor'])
            restored = True
        except Exception:
            run([SYSTEMCTL, 'start', 'vpn-task08-egress.timer'], required=False)
    print(json.dumps({'foreign_no_ru_wan_when_transport_down': blocked,
                      'own_services_restored': restored}))
    if not blocked or not restored:
        raise RuntimeError('fail-closed or restoration not confirmed')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps({'test_passed': False, 'reason': 'fixed_step_failed'}), file=sys.stderr)
        raise SystemExit(1)
