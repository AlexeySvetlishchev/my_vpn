#!/usr/bin/python3
"""Staged TASK 08 guard activation; role and actions are fixed, no shell."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from datetime import datetime, timezone

ROOT = Path('/var/lib/vpn-task08')
BASELINE = ROOT / 'prechange.json'
ACTIVE = ROOT / 'active.json'
PACKAGE = Path('/opt/vpn-task08')
NFT = '/usr/sbin/nft'
IP = '/usr/sbin/ip'
SYSTEMCTL = '/usr/bin/systemctl'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'HOME': '/'}
NFT_HASH = {
    'ru': 'fa997aa75d9ce57983cbf0a60e77506cf8567ecf1942da8e8377b5c46f2ae389',
    'fr': '74c34f24f2e00dc0a38d9ce4a2877ebb32457a6ad30903a734628eeed17fb243',
}
TASK06_HASH = 'e60439c1858ac9407d5e8e411c76e374f8ef44b7273376e3c503de7e1e6a8384'


def run(argv, *, data=None, allow_failure=False):
    p = subprocess.run(argv, input=data, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, env=ENV, timeout=45, check=False)
    if p.returncode and not allow_failure:
        raise RuntimeError('fixed operation failed')
    if len(p.stdout) > 8 * 1024 * 1024:
        raise RuntimeError('bounded output exceeded')
    return p.stdout


def digest(data):
    return hashlib.sha256(data).hexdigest()


def root_file(path, mode):
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != mode:
        raise RuntimeError('root-owned package or record mismatch')
    return path.read_bytes()


def task06_module():
    path = Path('/opt/vpn-task06/helper.py')
    if digest(root_file(path, 0o644)) != TASK06_HASH:
        raise RuntimeError('TASK 06 helper hash mismatch')
    spec = importlib.util.spec_from_file_location('task06_task08_projection', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stable_snapshot(obj):
    if isinstance(obj, dict):
        excluded = {'packets', 'bytes', 'expires', 'valid_life_time',
                    'preferred_life_time', 'cache', 'counter', 'metainfo',
                    'comment', 'userdata'}
        return {k: stable_snapshot(v) for k, v in obj.items() if k not in excluded}
    if isinstance(obj, list):
        return [stable_snapshot(v) for v in obj]
    return obj


def nft_json():
    return json.loads(run([NFT, '-j', 'list', 'ruleset']))


def nft_hash_before():
    parsed = json.loads(run([NFT, '-j', '-n', 'list', 'ruleset']))
    return digest(json.dumps(stable_snapshot(parsed), sort_keys=True,
                             separators=(',', ':')).encode())


def preflight(role):
    if Path('/etc/vpn-task06/role').read_text().strip() != role:
        raise RuntimeError('installed role mismatch')
    baseline = json.loads(root_file(BASELINE, 0o600))
    if baseline.get('schema') != 1 or baseline.get('role') != role:
        raise RuntimeError('baseline role mismatch')
    if ACTIVE.exists() or ACTIVE.is_symlink():
        raise RuntimeError('TASK 08 is already active or conflicting')
    if nft_hash_before() != baseline['observed']['nft_sha256']:
        raise RuntimeError('host nft baseline changed')
    if json.loads(run([IP, '-j', '-4', 'rule', 'show'])) != baseline['observed']['rules4']:
        raise RuntimeError('host rule baseline changed')
    if role == 'ru' and Path('/proc/sys/net/ipv4/ip_forward').read_text().strip() != '0':
        raise RuntimeError('RU forwarding is no longer at baseline')
    package = PACKAGE / (role + '.nft')
    if digest(root_file(package, 0o644)) != NFT_HASH[role]:
        raise RuntimeError('TASK 08 nft package hash mismatch')
    task06_module()
    run(['/usr/local/sbin/vpn-task08-rollback', role, 'check'])
    return baseline


def fr_jump_position(nft):
    rows = [obj['rule'] for obj in nft.get('nftables', []) if 'rule' in obj and
            obj['rule'].get('family') == 'ip' and obj['rule'].get('table') == 'filter' and
            obj['rule'].get('chain') == 'FORWARD']
    targets = []
    for row in rows:
        targets.append(next((expr['jump']['target'] for expr in row.get('expr', [])
                             if isinstance(expr, dict) and 'jump' in expr), None))
    if len(rows) < 2 or targets[:2] != ['DOCKER-USER', 'DOCKER-FORWARD']:
        raise RuntimeError('FR Docker FORWARD ordering changed')
    handle = rows[1].get('handle')
    if not isinstance(handle, int) or handle <= 0:
        raise RuntimeError('FR insertion handle invalid')
    return handle


def fr_batch():
    handle = fr_jump_position(nft_json())
    package = root_file(PACKAGE / 'fr.nft', 0o644)
    insert = ('insert rule ip filter FORWARD position ' + str(handle) +
              ' jump vpn_task08_fr_forward comment "vpn-task08-owned"\n').encode()
    return package + insert


def require_production_precheck():
    record = json.loads(root_file(ROOT / 'production-precheck.json', 0o600))
    stamp = datetime.fromisoformat(record['utc'])
    age = (datetime.now(timezone.utc) - stamp).total_seconds()
    if not (stamp.tzinfo is not None and 0 <= age <= 900 and
            record.get('vpn_adapter_up') is True and
            record.get('default_via_vpn') is True and
            record.get('public_ip_matches_fr') is True and
            record.get('https_echo_succeeded') is True):
        raise RuntimeError('fresh production client precheck is required')


def subset_hash(module, nft, role, kind):
    selected = [obj for obj in nft.get('nftables', [])
                if module.task08_nft_subset(obj, role) == kind]
    if not selected:
        raise RuntimeError('TASK 08 nft subset is missing')
    return digest(json.dumps(module.stable({'nftables': selected}), sort_keys=True,
                             separators=(',', ':')).encode())


def atomic_active(data):
    fd = os.open(ACTIVE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write((json.dumps(data, sort_keys=True, indent=2) + '\n').encode())
        out.flush()
        os.fsync(out.fileno())


def apply_ru(module):
    package = PACKAGE / 'ru.nft'
    run([NFT, '-c', '-f', str(package)])
    run([NFT, '-f', str(package)])
    # Terminal rule precedes lookups, so a missing mark or route never falls to main.
    commands = [
        [IP, '-4', 'rule', 'add', 'pref', '10021', 'iif', 'awg-client',
         'fwmark', '0x702/0xffffffff', 'unreachable'],
        [IP, '-4', 'rule', 'add', 'pref', '10032', 'from', '10.203.254.1/32',
         'to', '9.9.9.9/32', 'unreachable'],
        [IP, '-4', 'rule', 'add', 'pref', '10033', 'from', '10.203.254.1/32',
         'to', '149.112.112.112/32', 'unreachable'],
        [IP, '-4', 'route', 'add', 'default', 'via', '10.203.254.2',
         'dev', 'awg-transport', 'table', '220'],
        [IP, '-4', 'rule', 'add', 'pref', '10000', 'iif', 'awg-client',
         'fwmark', '0x701/0xffffffff', 'lookup', 'main'],
        [IP, '-4', 'rule', 'add', 'pref', '10010', 'iif', 'awg-client',
         'fwmark', '0x702/0xffffffff', 'lookup', '220'],
        [IP, '-4', 'rule', 'add', 'pref', '10030', 'from', '10.203.254.1/32',
         'to', '9.9.9.9/32', 'lookup', '220'],
        [IP, '-4', 'rule', 'add', 'pref', '10031', 'from', '10.203.254.1/32',
         'to', '149.112.112.112/32', 'lookup', '220'],
    ]
    for argv in commands:
        run(argv)
    rows = json.loads(run([IP, '-j', '-4', 'rule', 'show']))
    owned = [r for r in rows if r.get('priority') in (10000, 10010, 10021,
                                                     10030, 10031, 10032, 10033)]
    if len(owned) != 7:
        raise RuntimeError('RU RPDB ownership verification failed')
    active = {'schema': 1, 'role': 'ru', 'phase': 'active', 'rules4': owned,
              'own_table_sha256': subset_hash(module, nft_json(), 'ru', 'own'),
              'started_utc': datetime.now(timezone.utc).isoformat()}
    atomic_active(active)
    run([SYSTEMCTL, 'reset-failed', 'vpn-task06-awg.service'], allow_failure=True)
    run([SYSTEMCTL, 'restart', 'vpn-task06-awg.service'])
    # A TUN restart removes dev-bound routes; restore only TASK 08 table 220.
    routes = run([IP, '-j', '-4', 'route', 'show', 'table', '220'], allow_failure=True)
    if not routes.strip() or json.loads(routes) == []:
        run([IP, '-4', 'route', 'add', 'default', 'via', '10.203.254.2',
             'dev', 'awg-transport', 'table', '220'])


def apply_fr(module):
    require_production_precheck()
    batch = fr_batch()
    run([NFT, '-c', '-f', '-'], data=batch)
    run([NFT, '-f', '-'], data=batch)
    changed = nft_json()
    active = {'schema': 1, 'role': 'fr', 'phase': 'active', 'rules4': [],
              'own_table_sha256': subset_hash(module, changed, 'fr', 'own'),
              'filter_sha256': subset_hash(module, changed, 'fr', 'filter'),
              'started_utc': datetime.now(timezone.utc).isoformat()}
    atomic_active(active)
    run([SYSTEMCTL, 'reset-failed', 'vpn-task06-awg.service'], allow_failure=True)
    run([SYSTEMCTL, 'restart', 'vpn-task06-awg.service'])
    run([IP, '-4', 'route', 'add', '10.203.253.0/24', 'dev', 'awg-transport'])


def main():
    if (os.geteuid() != 0 or len(sys.argv) != 3 or
            sys.argv[1] not in ('ru', 'fr') or sys.argv[2] not in ('check', 'run')):
        raise RuntimeError('root, exact role and fixed action required')
    role, action = sys.argv[1:]
    preflight(role)
    if action == 'check':
        if role == 'ru':
            run([NFT, '-c', '-f', str(PACKAGE / 'ru.nft')])
        else:
            run([NFT, '-c', '-f', '-'], data=fr_batch())
        print(json.dumps({'ready': True, 'role': role, 'network_changed': False}))
        return
    module = task06_module()
    run([SYSTEMCTL, 'stop', 'vpn-task06-monitor.timer'])
    try:
        if role == 'ru':
            apply_ru(module)
        else:
            apply_fr(module)
        run(['/usr/local/sbin/vpn-task06', 'status'])
        run(['/usr/local/sbin/vpn-task06', 'monitor'])
    except Exception as exc:
        # Roll back only TASK 08 objects. If ownership drift is detected,
        # rollback fails closed and requires an operator review.
        rollback = subprocess.run(['/usr/local/sbin/vpn-task08-rollback', role, 'run'],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  env=ENV, timeout=60, check=False)
        run([SYSTEMCTL, 'start', 'vpn-task06-monitor.timer'], allow_failure=True)
        raise RuntimeError('apply failed; addressed rollback ' +
                           ('succeeded' if rollback.returncode == 0 else 'FAILED')) from exc
    run([SYSTEMCTL, 'start', 'vpn-task06-monitor.timer'])
    print(json.dumps({'applied': True, 'role': role,
                      'forwarding_enabled': False if role == 'ru' else None,
                      'client_egress_verified': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps({'applied': False, 'reason': 'validation_or_operation_failure'}),
              file=sys.stderr)
        raise SystemExit(1)
