#!/usr/bin/python3
"""Addressed TASK 08 rollback; no Docker, SSH, default-route or bulk flush verbs."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path('/var/lib/vpn-task08')
BASELINE = ROOT / 'prechange.json'
BACKUP = ROOT / 'backup'
ACTIVE = ROOT / 'active.json'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'HOME': '/'}
IP = '/usr/sbin/ip'
NFT = '/usr/sbin/nft'
SYSTEMCTL = '/usr/bin/systemctl'
TABLE = {'ru': 'vpn_task08_ru', 'fr': 'vpn_task08_fr'}
COMMENT = 'vpn-task08-owned'
PRIORITIES = (10000, 10010, 10020, 10021, 10030, 10031, 10032, 10033)
TASK07_NEW = 'd2370830e7cc9228127d019d9dc53036a5dacb37320627328228fee58395a141'


def run(argv, *, data=None, allow_failure=False):
    p = subprocess.run(argv, input=data, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, env=ENV, timeout=25, check=False)
    if p.returncode and not allow_failure:
        raise RuntimeError('fixed operation failed')
    if len(p.stdout) > 8 * 1024 * 1024:
        raise RuntimeError('bounded output exceeded')
    return p.stdout


def root_file(path, mode):
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != mode:
        raise RuntimeError('root-owned file mismatch')
    return path.read_bytes()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def objects(nft, role):
    own, forward = [], []
    for obj in nft.get('nftables', []):
        if len(obj) != 1:
            continue
        kind, val = next(iter(obj.items()))
        if not isinstance(val, dict):
            continue
        name = val.get('table') or (val.get('name') if kind == 'table' else None)
        if val.get('family') == 'ip' and name == TABLE[role]:
            own.append(obj)
        if role == 'fr' and val.get('family') == 'ip' and val.get('table') == 'filter':
            if ((kind == 'chain' and val.get('name') == 'vpn_task08_fr_forward') or
                    (kind == 'rule' and val.get('chain') == 'vpn_task08_fr_forward') or
                    (kind == 'rule' and val.get('chain') == 'FORWARD' and any(
                        e.get('jump', {}).get('target') == 'vpn_task08_fr_forward'
                        for e in val.get('expr', []) if isinstance(e, dict)))):
                forward.append(obj)
    return own, forward


def validate_nft_ownership(own, forward, role):
    for obj in own + forward:
        kind, val = next(iter(obj.items()))
        if kind not in ('table', 'chain', 'rule', 'set', 'element'):
            raise RuntimeError('unknown TASK 08 nft object')
        if kind == 'rule' and val.get('comment') != COMMENT:
            raise RuntimeError('TASK 08 rule ownership marker mismatch')
    if role == 'fr':
        jumps = [val for obj in forward for kind, val in obj.items()
                 if kind == 'rule' and val.get('chain') == 'FORWARD']
        if len(jumps) > 1:
            raise RuntimeError('multiple TASK 08 jumps')
        for val in jumps:
            if not isinstance(val.get('handle'), int) or val['handle'] <= 0:
                raise RuntimeError('invalid TASK 08 jump handle')


def nft_cleanup(role):
    nft = json.loads(run([NFT, '-j', '-n', 'list', 'ruleset']))
    own, forward = objects(nft, role)
    validate_nft_ownership(own, forward, role)
    statements = []
    if role == 'fr':
        jumps = [val for obj in forward for kind, val in obj.items()
                 if kind == 'rule' and val.get('chain') == 'FORWARD']
        if jumps:
            statements.append('delete rule ip filter FORWARD handle ' + str(jumps[0]['handle']))
        if any('chain' in obj for obj in forward):
            statements.extend(('flush chain ip filter vpn_task08_fr_forward',
                               'delete chain ip filter vpn_task08_fr_forward'))
    if own:
        statements.append('delete table ip ' + TABLE[role])
    if statements:
        run([NFT, '-f', '-'], data=('\n'.join(statements) + '\n').encode())


def remove_owned_rules(role):
    if role != 'ru':
        return
    rules = json.loads(run([IP, '-j', '-4', 'rule', 'show']))
    rows = [row for row in rules if row.get('priority') in PRIORITIES]
    for row in rows:
        pref = row['priority']
        if pref in (10000, 10010, 10020, 10021):
            if row.get('iif') != 'awg-client':
                raise RuntimeError('TASK 08 rule priority conflict')
            if pref == 10021 and row.get('fwmark') not in ('0x702', '0x702/0xffffffff'):
                raise RuntimeError('TASK 08 foreign terminal rule conflict')
        else:
            if row.get('src') not in ('10.203.254.1', '10.203.254.1/32') or row.get('dst') not in (
                    '9.9.9.9', '9.9.9.9/32', '149.112.112.112', '149.112.112.112/32'):
                raise RuntimeError('TASK 08 DNS rule priority conflict')
        run([IP, '-4', 'rule', 'del', 'pref', str(pref)])
    routes = json.loads(run([IP, '-j', '-4', 'route', 'show', 'table', '220'],
                            allow_failure=True) or b'[]')
    if routes:
        if (len(routes) != 1 or routes[0].get('dst') != 'default' or
                routes[0].get('gateway') != '10.203.254.2' or
                routes[0].get('dev') != 'awg-transport'):
            raise RuntimeError('TASK 08 route table conflict')
        run([IP, '-4', 'route', 'del', 'default', 'via', '10.203.254.2',
             'dev', 'awg-transport', 'table', '220'])


def remove_fr_route():
    routes = json.loads(run([IP, '-j', '-4', 'route', 'show', '10.203.253.0/24']))
    matches = [r for r in routes if r.get('dst') == '10.203.253.0/24']
    if not matches:
        return
    if len(matches) != 1 or matches[0].get('dev') != 'awg-transport':
        raise RuntimeError('FR client return route conflict')
    run([IP, '-4', 'route', 'del', '10.203.253.0/24', 'dev', 'awg-transport'])


def restore_sysctls(baseline):
    recorded = baseline['observed']['sysctls']
    if recorded.get('net.ipv4.ip_forward') != '0':
        raise RuntimeError('RU forwarding baseline was not zero')
    Path('/proc/sys/net/ipv4/ip_forward').write_text('0\n')
    for key, value in sorted(recorded.items()):
        if key == 'net.ipv4.ip_forward':
            continue
        if not re.fullmatch(r'net\.ipv4\.conf\.[A-Za-z0-9_.-]{1,32}\.[a-z0-9_]{1,64}', key):
            raise RuntimeError('invalid recorded sysctl key')
        path = Path('/proc/sys') / key.replace('.', '/')
        if path.is_file() and path.read_text().strip() != value:
            if not re.fullmatch(r'-?[0-9]+', value):
                raise RuntimeError('invalid recorded sysctl value')
            path.write_text(value + '\n')


def atomic(path, data, mode):
    temp = path.with_name(path.name + '.task08-rollback-new')
    fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(temp, mode)
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def restore_task06(baseline):
    hashes = baseline['observed']['file_sha256']
    source = root_file(BACKUP / 'task06-helper.py', 0o600)
    manifest = root_file(BACKUP / 'task06-manifest.json', 0o600)
    if digest(source) != hashes['task06_helper'] or digest(manifest) != hashes['task06_manifest']:
        raise RuntimeError('TASK 06 backup mismatch')
    current = root_file(Path('/opt/vpn-task06/helper.py'), 0o644)
    if digest(current) not in (hashes['task06_helper'],
                               'e60439c1858ac9407d5e8e411c76e374f8ef44b7273376e3c503de7e1e6a8384'):
        raise RuntimeError('TASK 06 helper changed by another owner')
    atomic(Path('/opt/vpn-task06/helper.py'), source, 0o644)
    atomic(Path('/opt/vpn-task06/manifest.json'), manifest, 0o644)
    if ACTIVE.exists():
        st = ACTIVE.lstat()
        if st.st_uid != 0 or not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o600:
            raise RuntimeError('TASK 08 active ledger ownership mismatch')
        ACTIVE.unlink()
    run([SYSTEMCTL, 'reset-failed', 'vpn-task06-awg.service'], allow_failure=True)
    run([SYSTEMCTL, 'restart', 'vpn-task06-awg.service'])


def restore_task07_profile(baseline, dry_run=False):
    original_path = BACKUP / 'task07-test-profile.conf'
    if not original_path.exists() and not original_path.is_symlink():
        return
    old_profile = root_file(original_path, 0o600)
    old_helper = root_file(BACKUP / 'task07-helper.py', 0o600)
    if digest(old_helper) != baseline['observed']['file_sha256']['task07_helper']:
        raise RuntimeError('TASK 07 helper backup mismatch')
    old_allowed = b'AllowedIPs = 10.203.253.1/32\n'
    new_allowed = b'AllowedIPs = 0.0.0.0/0, ::/0\n'
    mtu = b'MTU = 1280\n'
    dns = b'DNS = 10.203.253.1\n'
    if old_profile.count(old_allowed) != 1 or old_profile.count(mtu) != 1:
        raise RuntimeError('TASK 07 profile backup format mismatch')
    expected = old_profile.replace(mtu, mtu + dns).replace(old_allowed, new_allowed)
    helper = Path('/usr/local/sbin/vpn-task07')
    profile = Path('/etc/vpn-task07/Test_iPhone.conf')
    if (digest(root_file(helper, 0o755)) != TASK07_NEW or
            root_file(profile, 0o600) != expected):
        raise RuntimeError('TASK 07 test profile changed outside TASK 08')
    if dry_run:
        return
    atomic(helper, old_helper, 0o755)
    atomic(profile, old_profile, 0o600)


def main():
    if (os.geteuid() != 0 or len(sys.argv) != 3 or
            sys.argv[1] not in ('ru', 'fr') or sys.argv[2] not in ('check', 'run')):
        raise RuntimeError('root, exact role and fixed action required')
    role, action = sys.argv[1:]
    baseline = json.loads(root_file(BASELINE, 0o600))
    if baseline.get('schema') != 1 or baseline.get('role') != role:
        raise RuntimeError('baseline role mismatch')
    st = BACKUP.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
        raise RuntimeError('backup directory mismatch')
    if Path('/etc/vpn-task06/role').read_text().strip() != role:
        raise RuntimeError('installed role mismatch')
    hashes = baseline['observed']['file_sha256']
    if (digest(root_file(BACKUP / 'task06-helper.py', 0o600)) != hashes['task06_helper'] or
            digest(root_file(BACKUP / 'task06-manifest.json', 0o600)) != hashes['task06_manifest']):
        raise RuntimeError('backup does not match baseline')
    if action == 'check':
        nft = json.loads(run([NFT, '-j', '-n', 'list', 'ruleset']))
        own, forward = objects(nft, role)
        validate_nft_ownership(own, forward, role)
        if role == 'ru':
            restore_task07_profile(baseline, dry_run=True)
        print(json.dumps({'rollback_ready': True, 'role': role,
                          'owned_nft_objects': len(own) + len(forward)}))
        return
    if role == 'ru':
        restore_sysctls(baseline)
    run([SYSTEMCTL, 'disable', '--now', 'vpn-task08-egress.timer'], allow_failure=True)
    run([SYSTEMCTL, 'disable', '--now', 'vpn-task08-dns.service'], allow_failure=True)
    run([SYSTEMCTL, 'stop', 'vpn-task08-egress.service'], allow_failure=True)
    if role == 'ru':
        remove_owned_rules(role)
        nft_cleanup(role)
    else:
        nft_cleanup(role)
        remove_fr_route()
    if role == 'ru':
        restore_task07_profile(baseline)
    restore_task06(baseline)
    print(json.dumps({'rolled_back': True, 'role': role, 'scope': 'task08_only'}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps({'success': False, 'reason': 'conflict_or_operation_failure'}),
              file=sys.stderr)
        raise SystemExit(1)
