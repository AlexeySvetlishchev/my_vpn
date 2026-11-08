#!/usr/bin/python3
"""Restore only TASK 08-owned runtime state; fail closed on drift."""
import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path('/var/lib/vpn-task08')
ACTIVE = ROOT / 'active.json'
BASELINE = ROOT / 'prechange.json'
PACKAGE = Path('/opt/vpn-task08')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'HOME': '/'}
IP = '/usr/sbin/ip'
NFT = '/usr/sbin/nft'
TASK06 = '/usr/local/sbin/vpn-task06'


def run(argv, data=None):
    proc = subprocess.run(argv, input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, env=ENV, timeout=30,
                          check=False)
    if proc.returncode or len(proc.stdout) > 8 * 1024 * 1024:
        raise RuntimeError('fixed recovery operation failed: ' + Path(argv[0]).name +
                           (' ' + argv[1] if len(argv) > 1 else ''))
    return proc.stdout


def read_root(path, mode):
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != mode:
        raise RuntimeError('root-owned record mismatch')
    return path.read_bytes()


def module(path, name):
    spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def nft_state(task06, role):
    parsed = json.loads(run([NFT, '-j', 'list', 'ruleset']))
    parts = {'own': [], 'filter': []}
    for item in parsed['nftables']:
        kind = task06.task08_nft_subset(item, role)
        if kind:
            parts[kind].append(item)
    return parts


def part_hash(task06, rows):
    return hashlib.sha256(json.dumps(task06.stable({'nftables': rows}),
                                     sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def atomic_ledger(ledger):
    temp = ACTIVE.with_name('active.json.recovery-new')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write((json.dumps(ledger, sort_keys=True, indent=2) + '\n').encode())
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, ACTIVE)
    finally:
        if temp.exists():
            temp.unlink()


def restore_nft(role, ledger, task06, apply, rollback):
    parts = nft_state(task06, role)
    if parts['own'] and (role == 'ru' or parts['filter']):
        if part_hash(task06, parts['own']) != ledger['own_table_sha256']:
            raise RuntimeError('owned nft table changed')
        if role == 'fr' and part_hash(task06, parts['filter']) != ledger['filter_sha256']:
            raise RuntimeError('owned FR filter chain changed')
        rollback.validate_nft_ownership(*rollback.objects(
            json.loads(run([NFT, '-j', '-n', 'list', 'ruleset'])), role), role)
        return False
    if parts['own'] or parts['filter']:
        raise RuntimeError('partial TASK 08 nft state')
    if role == 'ru':
        batch = read_root(PACKAGE / 'ru.nft', 0o644)
    else:
        batch = apply.fr_batch()
    run([NFT, '-c', '-f', '-'], batch)
    run([NFT, '-f', '-'], batch)
    if role == 'ru' and (Path('/var/lib/vpn-task08/ru-prefix-current.json')).exists():
        read_root(PACKAGE / 'ru-prefix-update.py', 0o644)
        read_root(PACKAGE / 'ru-prefix-data.py', 0o644)
        updater = module(PACKAGE / 'ru-prefix-update.py', 'task08_prefix_recovery')
        geo = module(PACKAGE / 'ru-prefix-data.py', 'task08_geo_recovery')
        state = updater.root_json(updater.CURRENT)
        ru, force = updater.validate_state(state, geo,
                                           baseline=state['kind'] == 'baseline')
        update_batch = updater.nft_batch(ru, force)
        run([NFT, '-c', '-f', '-'], update_batch)
        run([NFT, '-f', '-'], update_batch)
        if updater.nft_elements('ru_set') != ru or updater.nft_elements('force_egress') != force:
            raise RuntimeError('last-good RU set restore failed')
    parts = nft_state(task06, role)
    if not parts['own'] or (role == 'fr' and not parts['filter']):
        raise RuntimeError('TASK 08 nft restore incomplete')
    rollback.validate_nft_ownership(*rollback.objects(
        json.loads(run([NFT, '-j', '-n', 'list', 'ruleset'])), role), role)
    ledger['own_table_sha256'] = part_hash(task06, parts['own'])
    if role == 'fr':
        ledger['filter_sha256'] = part_hash(task06, parts['filter'])
    atomic_ledger(ledger)
    return True


def restore_ru_rules(ledger):
    expected = ledger['rules4']
    if len(expected) != 7:
        raise RuntimeError('RU ledger rule count mismatch')
    current = json.loads(run([IP, '-j', '-4', 'rule', 'show']))
    priorities = {row['priority'] for row in expected}
    actual = [row for row in current if row.get('priority') in priorities]
    if actual == expected:
        return
    if actual:
        raise RuntimeError('partial or changed RU RPDB rules')
    fixed = [
        ['10021', 'iif', 'awg-client', 'fwmark', '0x702/0xffffffff', 'unreachable'],
        ['10032', 'from', '10.203.254.1/32', 'to', '9.9.9.9/32', 'unreachable'],
        ['10033', 'from', '10.203.254.1/32', 'to', '149.112.112.112/32', 'unreachable'],
        ['10000', 'iif', 'awg-client', 'fwmark', '0x701/0xffffffff', 'lookup', 'main'],
        ['10010', 'iif', 'awg-client', 'fwmark', '0x702/0xffffffff', 'lookup', '220'],
        ['10030', 'from', '10.203.254.1/32', 'to', '9.9.9.9/32', 'lookup', '220'],
        ['10031', 'from', '10.203.254.1/32', 'to', '149.112.112.112/32', 'lookup', '220'],
    ]
    for args in fixed:
        run([IP, '-4', 'rule', 'add', 'pref', *args])
    rows = json.loads(run([IP, '-j', '-4', 'rule', 'show']))
    if [row for row in rows if row.get('priority') in priorities] != expected:
        raise RuntimeError('restored RU RPDB differs from ledger')


def restore_route(role):
    if role == 'ru':
        rows = json.loads(run([IP, '-j', '-4', 'route', 'show', 'table', '220']))
        expected = {'dst': 'default', 'gateway': '10.203.254.2', 'dev': 'awg-transport'}
        add = [IP, '-4', 'route', 'add', 'default', 'via', '10.203.254.2',
               'dev', 'awg-transport', 'table', '220']
    else:
        rows = json.loads(run([IP, '-j', '-4', 'route', 'show', '10.203.253.0/24']))
        expected = {'dst': '10.203.253.0/24', 'dev': 'awg-transport'}
        add = [IP, '-4', 'route', 'add', '10.203.253.0/24', 'dev', 'awg-transport']
    if not rows:
        run(add)
        rows = json.loads(run([IP, '-j', '-4', 'route', 'show',
                               'table', '220'] if role == 'ru' else
                              [IP, '-j', '-4', 'route', 'show', '10.203.253.0/24']))
    if len(rows) != 1 or any(rows[0].get(k) != v for k, v in expected.items()):
        raise RuntimeError('owned route conflict')


def restore_forwarding(baseline):
    old = baseline['observed']['sysctls']
    path = Path('/proc/sys/net/ipv4/ip_forward')
    current = path.read_text().strip()
    if current not in ('0', '1') or old['net.ipv4.ip_forward'] != '0':
        raise RuntimeError('forwarding state conflict')
    if current == '0':
        path.write_text('1\n')
    for key, value in sorted(old.items()):
        if key == 'net.ipv4.ip_forward' or key.endswith('.forwarding'):
            continue
        if not re.fullmatch(r'net\.ipv4\.conf\.[A-Za-z0-9_.-]{1,32}\.[a-z0-9_]{1,64}', key):
            raise RuntimeError('invalid baseline sysctl key')
        dest = Path('/proc/sys') / key.replace('.', '/')
        if dest.is_file() and dest.read_text().strip() != value:
            if not re.fullmatch(r'-?[0-9]+', value):
                raise RuntimeError('invalid baseline sysctl value')
            dest.write_text(value + '\n')
    if path.read_text().strip() != '1':
        raise RuntimeError('forwarding did not remain enabled')


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2 or sys.argv[1] not in ('ru', 'fr'):
        raise RuntimeError('root and exact role required')
    role = sys.argv[1]
    if Path('/etc/vpn-task06/role').read_text().strip() != role:
        raise RuntimeError('role mismatch')
    ledger = json.loads(read_root(ACTIVE, 0o600))
    baseline = json.loads(read_root(BASELINE, 0o600))
    if ledger.get('schema') != 1 or ledger.get('role') != role or ledger.get('phase') != 'active':
        raise RuntimeError('active ledger mismatch')
    task06 = module(Path('/opt/vpn-task06/helper.py'), 'task06_recovery')
    apply = module(PACKAGE / 'apply.py', 'task08_apply_recovery')
    rollback = module(Path('/usr/local/sbin/vpn-task08-rollback'), 'task08_rollback_recovery')
    if hashlib.sha256(read_root(PACKAGE / (role + '.nft'), 0o644)).hexdigest() != apply.NFT_HASH[role]:
        raise RuntimeError('TASK 08 package hash changed')
    if hashlib.sha256(read_root(Path('/opt/vpn-task06/helper.py'), 0o644)).hexdigest() != apply.TASK06_HASH:
        raise RuntimeError('TASK 06 helper hash changed')
    if role == 'ru':
        # A missing guard with forwarding enabled must fail closed immediately.
        parts = nft_state(task06, role)
        if not parts['own'] and Path('/proc/sys/net/ipv4/ip_forward').read_text().strip() == '1':
            Path('/proc/sys/net/ipv4/ip_forward').write_text('0\n')
    try:
        restored = restore_nft(role, ledger, task06, apply, rollback)
        if role == 'ru':
            restore_ru_rules(ledger)
        restore_route(role)
        if role == 'ru':
            restore_forwarding(baseline)
    except Exception:
        if role == 'ru':
            Path('/proc/sys/net/ipv4/ip_forward').write_text('0\n')
        raise
    print(json.dumps({'recovered': True, 'role': role, 'nft_recreated': restored,
                      'client_egress_verified': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        category = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
        print(json.dumps({'recovered': False, 'category': category}),
              file=sys.stderr)
        raise SystemExit(1)
