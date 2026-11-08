#!/usr/bin/python3
"""Record a root-only TASK 08 prechange network baseline; never print raw data."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from datetime import datetime, timezone

BASE = Path('/var/lib/vpn-task08')
TARGET = BASE / 'prechange.json'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'HOME': '/'}
COMMANDS = {
    'addresses4': ['/usr/sbin/ip', '-j', '-4', 'address', 'show'],
    'routes4': ['/usr/sbin/ip', '-j', '-4', 'route', 'show', 'table', 'all'],
    'rules4': ['/usr/sbin/ip', '-j', '-4', 'rule', 'show'],
    'links': ['/usr/sbin/ip', '-j', '-d', 'link', 'show'],
    'nft': ['/usr/sbin/nft', '-j', '-n', 'list', 'ruleset'],
}
FILES = {
    'task06_helper': Path('/opt/vpn-task06/helper.py'),
    'task06_manifest': Path('/opt/vpn-task06/manifest.json'),
    'task06_monitor_unit': Path('/etc/systemd/system/vpn-task06-monitor.service'),
}


def run(argv):
    p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                       env=ENV, timeout=20, check=True)
    if len(p.stdout) > 8 * 1024 * 1024:
        raise RuntimeError('bounded command output exceeded')
    return p.stdout


def stable(obj):
    if isinstance(obj, dict):
        excluded = {'packets', 'bytes', 'expires', 'valid_life_time',
                    'preferred_life_time', 'cache', 'counter', 'metainfo',
                    'comment', 'userdata'}
        return {k: stable(v) for k, v in obj.items() if k not in excluded}
    if isinstance(obj, list):
        return [stable(v) for v in obj]
    return obj


def sysctls():
    values = {'net.ipv4.ip_forward': Path('/proc/sys/net/ipv4/ip_forward').read_text().strip()}
    root = Path('/proc/sys/net/ipv4/conf')
    for iface in root.iterdir():
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,32}', iface.name) or not iface.is_dir():
            raise RuntimeError('unexpected IPv4 interface sysctl path')
        for path in iface.iterdir():
            if not re.fullmatch(r'[a-z0-9_]{1,64}', path.name) or not path.is_file():
                raise RuntimeError('unexpected IPv4 sysctl')
            value = path.read_text().strip()
            if not re.fullmatch(r'-?[0-9]+', value):
                raise RuntimeError('non-numeric IPv4 sysctl')
            values['net.ipv4.conf.' + iface.name + '.' + path.name] = value
    return values


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2 or sys.argv[1] not in ('ru', 'fr'):
        raise RuntimeError('root and exact ru/fr role required')
    role = sys.argv[1]
    installed_role = Path('/etc/vpn-task06/role').read_text().strip()
    if role != installed_role:
        raise RuntimeError('TASK 06 role mismatch')
    if BASE.exists() or BASE.is_symlink():
        raise RuntimeError('TASK 08 baseline directory already exists')
    observed = {}
    for label, argv in COMMANDS.items():
        raw = run(argv)
        parsed = json.loads(raw) if raw.strip() else {'nftables': []}
        if label == 'nft':
            canonical = json.dumps(stable(parsed), sort_keys=True, separators=(',', ':')).encode()
            observed['nft_sha256'] = hashlib.sha256(canonical).hexdigest()
            observed['nft_chains'] = [
                {'family': obj['chain'].get('family'),
                 'table': obj['chain'].get('table'),
                 'name': obj['chain'].get('name'),
                 'hook': obj['chain'].get('hook'),
                 'prio': obj['chain'].get('prio'),
                 'policy': obj['chain'].get('policy')}
                for obj in parsed.get('nftables', []) if 'chain' in obj
            ]
        else:
            observed[label] = stable(parsed)
    observed['sysctls'] = sysctls()
    observed['file_sha256'] = {}
    for name, path in FILES.items():
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or stat.S_ISLNK(st.st_mode):
            raise RuntimeError('TASK 06 installed file ownership mismatch')
        observed['file_sha256'][name] = hashlib.sha256(path.read_bytes()).hexdigest()
    if role == 'ru':
        path = Path('/usr/local/sbin/vpn-task07')
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0:
            raise RuntimeError('TASK 07 helper ownership mismatch')
        observed['file_sha256']['task07_helper'] = hashlib.sha256(path.read_bytes()).hexdigest()
    data = {'schema': 1, 'role': role, 'utc': datetime.now(timezone.utc).isoformat(),
            'observed': observed}
    BASE.mkdir(mode=0o700)
    fd = os.open(TARGET, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write((json.dumps(data, sort_keys=True, indent=2) + '\n').encode())
        out.flush()
        os.fsync(out.fileno())
    print(json.dumps({'baseline_saved': True, 'role': role,
                      'nft_sha256': observed['nft_sha256'],
                      'record_sha256': hashlib.sha256(TARGET.read_bytes()).hexdigest()}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps({'baseline_saved': False, 'reason': 'validation_or_io_failure'}),
              file=sys.stderr)
        raise SystemExit(1)
