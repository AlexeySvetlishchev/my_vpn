#!/usr/bin/python3
"""RU-only, bounded geofeed update of TASK 08-owned nft interval sets."""
import fcntl
import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = Path('/var/lib/vpn-task08')
CONFIG = Path('/etc/vpn-task08/force-egress.txt')
PACKAGE = Path('/opt/vpn-task08')
ACTIVE = ROOT / 'active.json'
BASELINE = ROOT / 'ru-prefix-baseline.json'
CURRENT = ROOT / 'ru-prefix-current.json'
PREVIOUS = ROOT / 'ru-prefix-previous.json'
CANDIDATE = ROOT / 'ru-prefix-candidate.json'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'HOME': '/'}
NFT = '/usr/sbin/nft'
SYSTEMCTL = '/usr/bin/systemctl'
TABLE = 'vpn_task08_ru'


def run(argv, data=None):
    proc = subprocess.run(argv, input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, env=ENV, timeout=60,
                          check=False)
    if proc.returncode or len(proc.stdout) > 16 * 1024 * 1024:
        raise RuntimeError('fixed prefix operation failed')
    return proc.stdout


def root_file(path, mode):
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != mode:
        raise RuntimeError('root-owned prefix file mismatch')
    return path.read_bytes()


def root_json(path):
    return json.loads(root_file(path, 0o600))


def write_json(path, data, exclusive=False):
    if exclusive and (path.exists() or path.is_symlink()):
        raise RuntimeError('prefix snapshot already exists')
    if not exclusive and (path.exists() or path.is_symlink()):
        root_file(path, 0o600)
    temp = path.with_name(path.name + '.task08-new')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write((json.dumps(data, sort_keys=True, indent=2) + '\n').encode())
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def import_module(path, name):
    root_file(path, 0o644)
    spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical(networks):
    parsed = [ipaddress.ip_network(value, strict=True) for value in networks]
    if any(not isinstance(value, ipaddress.IPv4Network) for value in parsed):
        raise ValueError('non-IPv4 prefix')
    return [str(value) for value in ipaddress.collapse_addresses(parsed)]


def payload_hash(data):
    selected = {key: data[key] for key in ('kind', 'prefixes', 'force_prefixes',
                                           'address_count', 'sources')}
    return hashlib.sha256(json.dumps(selected, sort_keys=True,
                                     separators=(',', ':')).encode()).hexdigest()


def validate_state(data, geo, baseline=False):
    if data.get('schema') != 1 or data.get('kind') not in (
            'baseline', 'conservative_ru_ipv4_intersection'):
        raise ValueError('prefix state schema invalid')
    ru = canonical(data['prefixes'])
    force = canonical(data['force_prefixes'])
    if ru != data['prefixes'] or force != data['force_prefixes']:
        raise ValueError('prefix state is not canonical')
    if not baseline and not 4_000 <= len(ru) <= 30_000:
        raise ValueError('prefix count outside bounds')
    if len(force) > 256 or not ru:
        raise ValueError('exception or baseline count outside bounds')
    geo.validate_public([ipaddress.ip_network(item) for item in ru + force])
    total = sum(ipaddress.ip_network(item).num_addresses for item in ru)
    if data['address_count'] != total or data.get('payload_sha256') != payload_hash(data):
        raise ValueError('prefix state integrity mismatch')
    return ru, force


def nft_elements(name):
    parsed = json.loads(run([NFT, '-j', 'list', 'set', 'ip', TABLE, name]))
    rows = [item['set'] for item in parsed['nftables'] if 'set' in item]
    if len(rows) != 1 or rows[0].get('name') != name or rows[0].get('table') != TABLE:
        raise RuntimeError('owned nft set missing')
    networks = []
    for item in rows[0].get('elem', []):
        if isinstance(item, str):
            networks.append(item if '/' in item else item + '/32')
        elif isinstance(item, dict) and 'prefix' in item:
            value = item['prefix']
            networks.append(value['addr'] + '/' + str(value['len']))
        elif isinstance(item, dict) and 'range' in item:
            low, high = item['range']
            networks.extend(str(value) for value in ipaddress.summarize_address_range(
                ipaddress.IPv4Address(low), ipaddress.IPv4Address(high)))
        else:
            raise RuntimeError('unexpected nft interval representation')
    return canonical(networks)


def nft_batch(ru, force):
    lines = ['flush set ip ' + TABLE + ' ru_set',
             'add element ip ' + TABLE + ' ru_set { ' + ', '.join(ru) + ' }',
             'flush set ip ' + TABLE + ' force_egress']
    if force:
        lines.append('add element ip ' + TABLE + ' force_egress { ' + ', '.join(force) + ' }')
    return ('\n'.join(lines) + '\n').encode('ascii')


def wait_for_checks():
    for unit in ('vpn-task08-egress.service', 'vpn-task06-monitor.service'):
        for _ in range(100):
            proc = subprocess.run([SYSTEMCTL, 'is-active', '--quiet', unit],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  env=ENV, timeout=5, check=False)
            if proc.returncode != 0:
                break
            time.sleep(.2)
        else:
            raise RuntimeError('periodic check still active: ' + unit)


def own_hash(task06):
    parsed = json.loads(run([NFT, '-j', 'list', 'ruleset']))
    selected = [item for item in parsed['nftables']
                if task06.task08_nft_subset(item, 'ru') == 'own']
    if not selected:
        raise RuntimeError('TASK 08 nft table absent')
    return hashlib.sha256(json.dumps(task06.stable({'nftables': selected}),
                                     sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def exceptions(geo):
    text = root_file(CONFIG, 0o600).decode('ascii')
    lines = []
    for line in text.splitlines():
        value = line.split('#', 1)[0].strip()
        if value:
            lines.append(value)
    result = canonical(lines)
    if len(result) > 256:
        raise ValueError('too many force-FR exceptions')
    geo.validate_public([ipaddress.ip_network(item) for item in result])
    return result, hashlib.sha256(text.encode('ascii')).hexdigest()


def baseline_state(geo):
    ru = nft_elements('ru_set')
    force = nft_elements('force_egress')
    data = {'schema': 1, 'kind': 'baseline', 'created_utc': datetime.now(timezone.utc).isoformat(),
            'sources': {}, 'prefixes': ru, 'force_prefixes': force,
            'address_count': sum(ipaddress.ip_network(item).num_addresses for item in ru)}
    data['payload_sha256'] = payload_hash(data)
    validate_state(data, geo, baseline=True)
    return data


def prepare(geo):
    if not BASELINE.exists():
        write_json(BASELINE, baseline_state(geo), exclusive=True)
        write_json(ROOT / 'active-before-ru-prefixes.json', root_json(ACTIVE), exclusive=True)
    else:
        validate_state(root_json(BASELINE), geo, baseline=True)
        root_json(ROOT / 'active-before-ru-prefixes.json')
    built = geo.build()
    force, config_sha = exceptions(geo)
    built['force_prefixes'] = force
    built['force_config_sha256'] = config_sha
    built['payload_sha256'] = payload_hash(built)
    validate_state(built, geo)
    write_json(CANDIDATE, built)
    return built


def apply_state(target, geo, task06, *, rollback=False):
    ru, force = validate_state(target, geo, baseline=target['kind'] == 'baseline')
    previous = root_json(CURRENT) if CURRENT.exists() else root_json(BASELINE)
    validate_state(previous, geo, baseline=previous['kind'] == 'baseline')
    if nft_elements('ru_set') != previous['prefixes'] or nft_elements('force_egress') != previous['force_prefixes']:
        raise RuntimeError('live nft sets differ from last good')
    ledger = root_json(ACTIVE)
    if own_hash(task06) != ledger['own_table_sha256']:
        raise RuntimeError('TASK 08 ledger differs from live nft table')
    if not rollback and previous['kind'] != 'baseline':
        old_addresses = previous['address_count']
        if (abs(target['address_count'] - old_addresses) > old_addresses * .10 or
                abs(len(ru) - len(previous['prefixes'])) > len(previous['prefixes']) * .20):
            raise ValueError('RU set delta exceeds guardrail')
    if ru == previous['prefixes'] and force == previous['force_prefixes']:
        write_json(CURRENT, target)
        return {'changed': False, 'prefixes': len(ru), 'addresses': target['address_count']}
    batch = nft_batch(ru, force)
    run([NFT, '-c', '-f', '-'], batch)
    run([SYSTEMCTL, 'stop', 'vpn-task08-egress.timer'])
    run([SYSTEMCTL, 'stop', 'vpn-task06-monitor.timer'])
    changed = False
    try:
        wait_for_checks()
        run([NFT, '-f', '-'], batch)
        changed = True
        if nft_elements('ru_set') != ru or nft_elements('force_egress') != force:
            raise RuntimeError('nft set verification failed')
        next_ledger = dict(ledger)
        next_ledger['own_table_sha256'] = own_hash(task06)
        write_json(ACTIVE, next_ledger)
        run(['/usr/local/sbin/vpn-task06', 'status'])
        write_json(PREVIOUS, previous)
        write_json(CURRENT, target)
    except Exception:
        if changed:
            try:
                run([NFT, '-f', '-'], nft_batch(previous['prefixes'], previous['force_prefixes']))
                write_json(ACTIVE, ledger)
            except Exception:
                Path('/proc/sys/net/ipv4/ip_forward').write_text('0\n')
                raise RuntimeError('RU set rollback failed; forwarding disabled') from None
        raise
    finally:
        run([SYSTEMCTL, 'start', 'vpn-task06-monitor.timer'])
        run([SYSTEMCTL, 'start', 'vpn-task08-egress.timer'])
    return {'changed': True, 'prefixes': len(ru), 'addresses': target['address_count'],
            'force_exceptions': len(force)}


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2 or sys.argv[1] not in (
            'prepare', 'apply', 'refresh', 'rollback', 'status'):
        raise RuntimeError('root and fixed action required')
    if Path('/etc/vpn-task06/role').read_text().strip() != 'ru':
        raise RuntimeError('RU role required')
    geo = import_module(PACKAGE / 'ru-prefix-data.py', 'task08_ru_prefix_data')
    task06 = import_module(Path('/opt/vpn-task06/helper.py'), 'task06_ru_prefix_update')
    lock_fd = os.open(ROOT / 'ru-prefix-update.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        action = sys.argv[1]
        if action == 'prepare':
            data = prepare(geo)
            result = {'prepared': True, 'prefixes': len(data['prefixes']),
                      'addresses': data['address_count'],
                      'force_exceptions': len(data['force_prefixes'])}
        elif action == 'refresh':
            data = prepare(geo)
            result = apply_state(data, geo, task06)
        elif action == 'apply':
            data = root_json(CANDIDATE)
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(data['created_utc'])).total_seconds()
            if not 0 <= age <= 3600:
                raise ValueError('prepared candidate expired')
            force, config_sha = exceptions(geo)
            if force != data['force_prefixes'] or config_sha != data['force_config_sha256']:
                raise ValueError('force-FR exceptions changed after prepare')
            result = apply_state(data, geo, task06)
        elif action == 'rollback':
            if not PREVIOUS.exists():
                raise RuntimeError('previous RU set missing')
            data = root_json(PREVIOUS)
            result = apply_state(data, geo, task06, rollback=True)
        else:
            data = root_json(CURRENT) if CURRENT.exists() else root_json(BASELINE)
            validate_state(data, geo, baseline=data['kind'] == 'baseline')
            result = {'active_prefixes': len(nft_elements('ru_set')),
                      'recorded_prefixes': len(data['prefixes']),
                      'force_exceptions': len(nft_elements('force_egress')),
                      'ledger_matches': own_hash(task06) == root_json(ACTIVE)['own_table_sha256']}
        print(json.dumps(result, sort_keys=True))
    finally:
        os.close(lock_fd)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        category = str(exc) if isinstance(exc, (RuntimeError, ValueError)) else type(exc).__name__
        print(json.dumps({'success': False, 'category': category}), file=sys.stderr)
        raise SystemExit(1)
