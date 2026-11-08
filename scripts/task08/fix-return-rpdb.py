#!/usr/bin/python3
"""Narrow RU's TASK 08 terminal RPDB rule so rp_filter can validate replies."""
import fcntl
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

ROOT = Path('/var/lib/vpn-task08')
LEDGER = ROOT / 'active.json'
IP = '/usr/sbin/ip'
SYSTEMCTL = '/usr/bin/systemctl'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'HOME': '/'}
OLD = [IP, '-4', 'rule', 'add', 'pref', '10020', 'iif', 'awg-client', 'unreachable']
NEW = [IP, '-4', 'rule', 'add', 'pref', '10021', 'iif', 'awg-client',
       'fwmark', '0x702/0xffffffff', 'unreachable']


def run(args, ok=True):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          env=ENV, timeout=25, check=False)
    if ok and proc.returncode:
        raise RuntimeError('fixed migration operation failed')
    return proc


def rules():
    return json.loads(run([IP, '-j', '-4', 'rule', 'show']).stdout)


def atomic(data):
    temp = LEDGER.with_name('active.json.task08-rpdb-new')
    fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write((json.dumps(data, sort_keys=True, indent=2) + '\n').encode())
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, LEDGER)
    finally:
        if temp.exists():
            temp.unlink()


def main():
    if os.geteuid() != 0 or len(sys.argv) != 1:
        raise RuntimeError('root and zero arguments required')
    if Path('/etc/vpn-task06/role').read_text().strip() != 'ru':
        raise RuntimeError('RU role required')
    st = LEDGER.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o600:
        raise RuntimeError('ledger ownership mismatch')
    original = json.loads(LEDGER.read_bytes())
    if original.get('schema') != 1 or original.get('role') != 'ru' or original.get('phase') != 'active':
        raise RuntimeError('active ledger mismatch')
    lock = os.open(ROOT / 'rpdb-fix.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = rules()
        old = [r for r in before if r.get('priority') == 10020]
        if (len(old) != 1 or old[0].get('iif') != 'awg-client' or
                old[0].get('action') != 'unreachable' or
                any(r.get('priority') == 10021 for r in before) or
                old[0] not in original['rules4']):
            raise RuntimeError('old RPDB rule mismatch')
        run([SYSTEMCTL, 'stop', 'vpn-task08-egress.timer'])
        run([SYSTEMCTL, 'stop', 'vpn-task06-monitor.timer'])
        added = False
        deleted = False
        try:
            run(NEW)
            added = True
            run([IP, '-4', 'rule', 'del', 'pref', '10020'])
            deleted = True
            after = rules()
            fresh = [r for r in after if r.get('priority') == 10021]
            if (len(fresh) != 1 or fresh[0].get('iif') != 'awg-client' or
                    fresh[0].get('fwmark') != '0x702' or
                    fresh[0].get('action') != 'unreachable'):
                raise RuntimeError('new RPDB rule mismatch')
            route = run([IP, '-4', 'route', 'get', '10.203.253.2',
                         'from', '1.1.1.1', 'iif', 'awg-transport']).stdout
            if b'dev awg-client' not in route:
                raise RuntimeError('return route still unavailable')
            updated = dict(original)
            updated['rules4'] = sorted([r for r in original['rules4'] if r['priority'] != 10020] +
                                       fresh, key=lambda row: row['priority'])
            atomic(updated)
            run(['/usr/local/sbin/vpn-task06', 'status'])
            run(['/usr/local/sbin/vpn-task08-rollback', 'ru', 'check'])
        except Exception:
            if deleted:
                run(OLD, ok=False)
            if added:
                run([IP, '-4', 'rule', 'del', 'pref', '10021'], ok=False)
            atomic(original)
            raise
        finally:
            run([SYSTEMCTL, 'start', 'vpn-task06-monitor.timer'], ok=False)
            run([SYSTEMCTL, 'start', 'vpn-task08-egress.timer'], ok=False)
    finally:
        os.close(lock)
    print(json.dumps({'rpdb_return_path_fixed': True, 'foreign_terminal_mark': '0x702'}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps({'rpdb_return_path_fixed': False,
                          'reason': 'ownership_or_fixed_operation_failed'}), file=sys.stderr)
        raise SystemExit(1)
