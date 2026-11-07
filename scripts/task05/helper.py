#!/usr/bin/python3
"""TASK 05 fixed-purpose root helper. Install only from owner-reviewed bundle.
No shell commands, arbitrary paths, endpoints, ports or configuration input.
"""
import base64
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import subprocess
import sys
import threading
import time

BASE = Path('/opt/vpn-task05')
STATE = Path('/run/vpn-task05')
IFACE = 'awg-test'
NET = ipaddress.ip_network('10.203.254.0/30')
PORT, DATA_PORT, MTU = 51983, 51984, 1280
PUBLIC = {'ru': '137.22.146.212', 'fr': '45.15.128.138'}
INNER = {'ru': '10.203.254.1', 'fr': '10.203.254.2'}
PUBLIC_ACTIONS = ('prepare', 'peer', 'up', 'status', 'start-test', 'result', 'down', 'cleanup')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'HOME': '/',
       'LOG_LEVEL': 'silent', 'GOMAXPROCS': '1', 'GOMEMLIMIT': '96MiB'}
AWG = str(BASE / 'awg')
IP = '/usr/sbin/ip'
SYSTEMCTL = '/usr/bin/systemctl'
UNITS = {'awg': 'vpn-task05-awg.service', 'test': 'vpn-task05-test.service'}
FR_AUDIT_ADDRESSES = {
    'docker0': ('172.17.0.1', 16),
    'amn0': ('172.29.172.1', 24),
}
FR_AUDIT_ROUTES = {
    '172.17.0.0/16': 'docker0',
    '172.29.172.0/24': 'amn0',
}
PRODUCTION_UDP_PORT = 40905
DIAGNOSTIC_CATEGORIES = {'command_failed', 'timeout', 'permission_denied',
                         'missing_executable', 'io_error', 'invalid_output',
                         'invalid_data', 'validation_failed', 'internal_error'}


class DiagnosticFailure(Exception):
    def __init__(self, stage, operation, category):
        self.stage = stage
        self.operation = operation
        self.category = category if category in DIAGNOSTIC_CATEGORIES else 'internal_error'


class ProbeFailure(Exception):
    def __init__(self, category):
        self.category = category


def step(stage, operation, fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except DiagnosticFailure:
        raise
    except ProbeFailure as error:
        raise DiagnosticFailure(stage, operation, error.category) from None
    except subprocess.TimeoutExpired:
        raise DiagnosticFailure(stage, operation, 'timeout') from None
    except TimeoutError:
        raise DiagnosticFailure(stage, operation, 'timeout') from None
    except PermissionError:
        raise DiagnosticFailure(stage, operation, 'permission_denied') from None
    except FileNotFoundError:
        raise DiagnosticFailure(stage, operation, 'missing_executable') from None
    except UnicodeError:
        raise DiagnosticFailure(stage, operation, 'invalid_output') from None
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        raise DiagnosticFailure(stage, operation, 'invalid_data') from None
    except OSError:
        raise DiagnosticFailure(stage, operation, 'io_error') from None
    except RuntimeError:
        raise DiagnosticFailure(stage, operation, 'validation_failed') from None
    except Exception:
        raise DiagnosticFailure(stage, operation, 'internal_error') from None


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def call(args, data=None, timeout=20):
    try:
        p = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           env=ENV, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise ProbeFailure('timeout') from None
    except PermissionError:
        raise ProbeFailure('permission_denied') from None
    except FileNotFoundError:
        raise ProbeFailure('missing_executable') from None
    except OSError:
        raise ProbeFailure('io_error') from None
    if p.returncode != 0:
        raise ProbeFailure('command_failed')
    if len(p.stdout) > 8 * 1024 * 1024:
        raise ProbeFailure('invalid_output')
    try:
        return p.stdout.decode('utf-8').strip()
    except UnicodeError:
        raise ProbeFailure('invalid_output') from None


def checked(path, directory=False, secret=False):
    """All callers use fixed paths inside owner-controlled directories."""
    s = path.lstat()
    require(s.st_uid == 0 and not s.st_mode & 0o022 and not stat.S_ISLNK(s.st_mode), 'unsafe owner/mode/link')
    require(stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode), 'unexpected object type')
    if secret:
        require(stat.S_IMODE(s.st_mode) == (0o700 if directory else 0o600), 'unsafe secret mode')
    return s


def validate_install():
    for path in (Path('/opt'), BASE, Path('/run')):
        checked(path, directory=True)
    for name in ('role', 'helper.py', 'amneziawg-go', 'awg', 'manifest.json'):
        checked(BASE / name)
    role = (BASE / 'role').read_text().strip()
    require(role in PUBLIC, 'invalid installed role')
    manifest = json.loads((BASE / 'manifest.json').read_text())
    for name in ('amneziawg-go', 'awg', 'helper.py'):
        require(hashlib.sha256((BASE / name).read_bytes()).hexdigest() == manifest['files'][name], 'installed hash mismatch')
    return role


def public_key(value):
    require(isinstance(value, str) and len(value) == 44, 'public key length')
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        raise RuntimeError('invalid public key') from None
    require(len(raw) == 32 and raw != bytes(32) and base64.b64encode(raw).decode() == value, 'invalid public key')
    return value


def atomic(name, data):
    require(name in ('state.json', 'private.key', 'test.json'), 'fixed filename required')
    path = STATE / name
    if path.exists() or path.is_symlink():
        checked(path, secret=True)
    temp = STATE / (name + '.new')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def save(s):
    atomic('state.json', (json.dumps(s, sort_keys=True) + '\n').encode())


def load():
    checked(STATE, directory=True, secret=True)
    checked(STATE / 'state.json', secret=True)
    s = json.loads((STATE / 'state.json').read_text())
    require(s.get('schema') == 1 and s.get('role') in PUBLIC, 'invalid ledger')
    require(isinstance(s.get('nonce'), str) and len(s['nonce']) == 32 and all(c in '0123456789abcdef' for c in s['nonce']), 'invalid ledger identity')
    return s


def ip(*args):
    return json.loads(call([IP, '-j', *args]))


def stable(value):
    if isinstance(value, dict):
        return {k: stable(v) for k, v in value.items()
                if k not in ('expires', 'valid_life_time', 'preferred_life_time', 'cache', 'counter', 'metainfo')}
    if isinstance(value, list):
        # Firewall/rule/expression ORDER is security-relevant. Never sort it.
        return [stable(v) for v in value]
    return value


def snapshot(role):
    result = {}
    for family in ('-4', '-6'):
        suffix = '4' if family == '-4' else '6'
        result[family + 'routes'] = stable([r for r in step('baseline', 'routes' + suffix, ip, family, 'route', 'show', 'table', 'all') if r.get('dev') != IFACE])
        result[family + 'rules'] = stable(step('baseline', 'rules' + suffix, ip, family, 'rule', 'show'))
    result['addresses'] = stable([r for r in step('baseline', 'addresses', ip, 'address', 'show') if r['ifname'] != IFACE])
    # Raw firewall is transient in memory only; no comment/secret contents saved.
    nft_raw = step('baseline', 'nft_ruleset', call, ['/usr/sbin/nft', '-j', 'list', 'ruleset'])
    rules = step('baseline', 'parse_nft_ruleset', json.loads, nft_raw)
    result['firewall_hash'] = hashlib.sha256(json.dumps(stable(rules), sort_keys=True).encode()).hexdigest()
    return result


def check_fr_audit_baseline(routes, addresses):
    """Require the non-conflicting FR network objects recorded by the prior audit."""
    address_rows = {r.get('ifname'): r for r in addresses}
    for ifname, (local, prefix) in FR_AUDIT_ADDRESSES.items():
        row = address_rows.get(ifname)
        require(row is not None and any(
            a.get('family') == 'inet' and a.get('local') == local and a.get('prefixlen') == prefix
            for a in row.get('addr_info', [])), 'previous audit address baseline changed')
    route_rows = {r.get('dst'): r.get('dev') for r in routes}
    for network, ifname in FR_AUDIT_ROUTES.items():
        require(route_rows.get(network) == ifname, 'previous audit route baseline changed')
    require(PORT != PRODUCTION_UDP_PORT, 'test port conflicts with protected production port')
    check_overlap(routes, addresses)


def unchanged(s):
    require(snapshot(s['role']) == s['baseline'], 'baseline changed: stop test; no automatic network restore')


def links():
    return [r for r in ip('link', 'show') if r['ifname'] == IFACE]


def check_overlap(routes, addresses):
    for r in routes:
        dst = r.get('dst', 'default')
        if dst not in ('default', '0.0.0.0/0'):
            require(not NET.overlaps(ipaddress.ip_network(dst, strict=False)), 'test subnet overlaps route')
    for link in addresses:
        for a in link.get('addr_info', []):
            if a.get('family') == 'inet':
                require(not NET.overlaps(ipaddress.ip_network(a['local'] + '/' + str(a['prefixlen']), strict=False)), 'test subnet overlaps address')


def unit(kind):
    p = subprocess.run([SYSTEMCTL, 'show', UNITS[kind], '--property=LoadState,ActiveState,Description,MainPID'],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=ENV, timeout=10)
    out = dict(line.split('=', 1) for line in p.stdout.decode().splitlines() if '=' in line)
    require(p.returncode == 0 or out.get('LoadState') == 'not-found', 'cannot inspect reserved unit')
    return out


def unit_owned(s, kind):
    u = unit(kind)
    if u.get('LoadState') == 'not-found':
        return False
    require(u.get('Description') == 'vpn-task05:' + s['nonce'] + ':' + kind, 'foreign transient unit; refused')
    return True


def launch(s, kind, command, limit):
    require(unit(kind).get('LoadState') == 'not-found', 'unit already exists')
    call(['/usr/bin/systemd-run', '--quiet', '--collect', '--unit=' + UNITS[kind],
          '--description=vpn-task05:' + s['nonce'] + ':' + kind,
          '--property=RuntimeMaxSec=' + str(limit), '--property=Restart=no',
          '--property=UMask=0077', '--property=KillMode=control-group',
          '--property=MemoryMax=192M', '--property=CPUQuota=50%',
          '--property=StandardOutput=null', '--property=StandardError=null',
          '--setenv=LOG_LEVEL=silent', '--setenv=GOMAXPROCS=1', '--setenv=GOMEMLIMIT=96MiB',
          '--', *command])


def prepare(role):
    if step('prepare', 'inspect_runtime_state', lambda: STATE.exists() or STATE.is_symlink()):
        s = step('prepare', 'load_existing_ledger', load)
        step('prepare', 'validate_existing_role', lambda: require(s['role'] == role, 'role mismatch'))
        step('prepare', 'check_existing_private_key', checked, STATE / 'private.key', secret=True)
        derived = step('prepare', 'derive_existing_public_key', call, [AWG, 'pubkey'], (STATE / 'private.key').read_bytes())
        step('prepare', 'validate_existing_key_identity', lambda: require(public_key(derived) == s['public'], 'key identity mismatch'))
        return {'public_key': s['public'], 'prepared': True}
    step('prepare', 'inspect_test_interface', lambda: require(not links(), 'foreign awg-test exists'))
    step('prepare', 'inspect_reserved_units', lambda: require(all(unit(k).get('LoadState') == 'not-found' for k in UNITS), 'reserved unit exists'))
    addresses = step('prepare', 'inspect_host_addresses', ip, '-4', 'address', 'show')
    step('prepare', 'validate_host_identity', lambda: require(any(a.get('local') == PUBLIC[role] for l in addresses for a in l.get('addr_info', [])), 'wrong host for installed role'))
    routes = step('prepare', 'inspect_host_routes', ip, '-4', 'route', 'show', 'table', 'all')
    step('prepare', 'check_test_subnet_conflicts', check_overlap, routes, addresses)
    if role == 'fr':
        step('prepare', 'validate_previous_audit_network_baseline', check_fr_audit_baseline, routes, addresses)
    listeners = step('prepare', 'inspect_udp_port', call, ['/usr/bin/ss', '-H', '-u', '-a', '-n', 'sport = :' + str(PORT)])
    step('prepare', 'validate_udp_port', lambda: require(not listeners, 'test UDP port occupied'))
    baseline = step('prepare', 'capture_baseline', snapshot, role)

    created_state = False
    try:
        step('prepare', 'create_runtime_directory', STATE.mkdir, mode=0o700)
        created_state = True
        private = step('prepare', 'generate_private_key', call, [AWG, 'genkey']).encode() + b'\n'
        step('prepare', 'write_private_key', atomic, 'private.key', private)
        derived = step('prepare', 'derive_public_key', call, [AWG, 'pubkey'], private)
        public = step('prepare', 'validate_derived_public_key', public_key, derived)
        s = {'schema': 1, 'role': role, 'nonce': secrets.token_hex(16), 'public': public,
             'peer': None, 'baseline': baseline, 'phase': 'prepared'}
        step('prepare', 'write_ownership_ledger', save, s)
        return {'public_key': public, 'prepared': True}
    except Exception as primary:
        if created_state and not (STATE / 'state.json').exists():
            try:
                step('prepare_cleanup', 'remove_partial_runtime_state', cleanup_partial)
            except Exception:
                # Preserve only the diagnostic category; never leak filesystem or key data.
                if isinstance(primary, DiagnosticFailure):
                    primary.cleanup_failure = {'stage': 'prepare_cleanup',
                                               'operation': 'remove_partial_runtime_state',
                                               'category': 'cleanup_failed'}
                else:
                    primary = DiagnosticFailure('prepare_cleanup', 'remove_partial_runtime_state', 'cleanup_failed')
        raise primary


def set_peer(s, value):
    key = public_key(value)
    require(key != s['public'], 'peer is local key')
    require(s['peer'] in (None, key), 'peer rotation not allowed; cleanup required')
    s['peer'] = key
    save(s)
    return {'peer_set': True}


def owned_link(s):
    rows = links()
    if not rows:
        return False
    identity_ok = (rows[0].get('ifalias') == 'vpn-task05:' + s['nonce'] and
                   (rows[0].get('ifindex') == s.get('ifindex') if s.get('ifindex') is not None
                    else s.get('phase') == 'starting'))
    require(len(rows) == 1 and identity_ok, 'interface identity mismatch; refused')
    return True


def up(s):
    if s['phase'] == 'active':
        status(s)
        return {'active': True, 'idempotent': True}
    require(s['phase'] == 'prepared' and s['peer'], 'prepare/peer required')
    require(not links(), 'foreign awg-test exists')
    unchanged(s)
    require(not call(['/usr/bin/ss', '-H', '-u', '-a', '-n', 'sport = :' + str(PORT)]), 'UDP port became occupied')
    control = STATE / 'amneziawg'
    require(not control.exists() and not control.is_symlink(), 'control directory conflict')
    control.mkdir(mode=0o700)
    s['phase'], s['activated_at'] = 'starting', int(time.time())
    save(s)  # Ledger before external effect; nonce also stored in transient unit.
    other = 'fr' if s['role'] == 'ru' else 'ru'
    try:
        launch(s, 'awg', [str(BASE / 'amneziawg-go'), '-f', IFACE], 1800)
        for _ in range(100):
            if links() and (control / (IFACE + '.sock')).exists():
                break
            time.sleep(.1)
        require(len(links()) == 1, 'userspace interface did not start')
        call([IP, 'link', 'set', 'dev', IFACE, 'alias', 'vpn-task05:' + s['nonce']])
        s['ifindex'] = links()[0]['ifindex']
        save(s)
        # Separate generated key, no reused production secret. AWG2-compatible
        # obfuscation profile on pinned v3 implementation; no header key transfer.
        call([AWG, 'set', IFACE, 'private-key', str(STATE / 'private.key'),
              'listen-port', str(PORT), 'jc', '4', 'jmin', '64', 'jmax', '256',
              's1', '32', 's2', '64', 's3', '32', 's4', '32',
              'h1', '176321011-176321111', 'h2', '276321011-276321111',
              'h3', '376321011-376321111', 'h4', '476321011-476321111',
              'peer', s['peer'], 'allowed-ips', INNER[other] + '/32',
              'endpoint', PUBLIC[other] + ':' + str(PORT), 'persistent-keepalive', '25'])
        call([IP, 'address', 'add', INNER[s['role']] + '/30', 'dev', IFACE])
        call([IP, 'link', 'set', 'dev', IFACE, 'mtu', str(MTU), 'up'])
        s['phase'] = 'active'
        save(s)
        status(s)
        return {'active': True, 'handshake_not_yet_required': True}
    except Exception:
        # Owned unit termination closes its nonpersistent TUN. Never delete an
        # unmarked interface after a crash between creation and ledger update.
        with contextlib.suppress(Exception):
            down(s)
        raise


def metrics(s):
    require(call([AWG, 'show', IFACE, 'public-key']) == s['public'], 'local public identity mismatch')
    require(call([AWG, 'show', IFACE, 'peers']) == s['peer'], 'peer identity mismatch')
    h = call([AWG, 'show', IFACE, 'latest-handshakes']).split()
    t = call([AWG, 'show', IFACE, 'transfer']).split()
    require(len(h) == 2 and h[0] == s['peer'] and len(t) == 3 and t[0] == s['peer'], 'metrics schema')
    return {'handshake': int(h[1]), 'rx': int(t[1]), 'tx': int(t[2])}


def fresh(s, m, now):
    return s['activated_at'] <= m['handshake'] <= now and now - m['handshake'] <= 180


def status(s):
    require(owned_link(s) and unit_owned(s, 'awg'), 'owned interface/unit absent')
    u = unit('awg')
    require(u.get('ActiveState') == 'active' and int(u.get('MainPID', '0')) > 0, 'AWG process not active')
    require(os.readlink('/proc/' + u['MainPID'] + '/exe') == str(BASE / 'amneziawg-go'), 'AWG executable identity changed')
    row = links()[0]
    require(row['mtu'] == MTU and 'UP' in row['flags'], 'test interface state drift')
    other = 'fr' if s['role'] == 'ru' else 'ru'
    require(ip('-4', 'route', 'get', INNER[other])[0].get('dev') == IFACE, 'test route escaped interface')
    require(ip('-4', 'route', 'get', PUBLIC[other])[0].get('dev') != IFACE, 'endpoint route recursion')
    unchanged(s)
    return dict(metrics(s), baseline_unchanged=True, production_client_health='UNCONFIRMED')


def down(s):
    for kind in ('test', 'awg'):
        if unit_owned(s, kind):
            call([SYSTEMCTL, 'stop', UNITS[kind]])
    if links():
        require(owned_link(s), 'foreign interface remains; no deletion')
        call([IP, 'link', 'delete', 'dev', IFACE])
    s['phase'] = 'stopped'
    save(s)
    unchanged(s)
    return {'stopped': True, 'baseline_unchanged': True}


def cleanup(s):
    require(not links(), 'interface still exists')
    require(all(not unit_owned(s, k) for k in UNITS), 'unit still exists')
    unchanged(s)
    allowed = {'private.key', 'state.json', 'test.json', 'amneziawg'}
    require(all(p.name in allowed for p in STATE.iterdir()), 'unknown runtime file; refused cleanup')
    control = STATE / 'amneziawg'
    if control.exists():
        checked(control, directory=True, secret=True)
        require(not list(control.iterdir()), 'control socket remains; no unlink of unknown object')
        control.rmdir()
    for name in ('test.json', 'private.key', 'state.json'):
        p = STATE / name
        if p.exists() or p.is_symlink():
            checked(p, secret=True)
            p.unlink()
    STATE.rmdir()
    return {'cleaned': True}


def cleanup_partial():
    """Remove only pre-ledger prepare remnants; no networking could have started."""
    require(not links(), 'interface exists without ownership ledger; refused')
    require(all(unit(k).get('LoadState') == 'not-found' for k in UNITS),
            'reserved unit exists without ownership ledger; refused')
    checked(STATE, directory=True, secret=True)
    allowed = {'private.key', 'private.key.new', 'state.json.new'}
    require(all(p.name in allowed for p in STATE.iterdir()),
            'unknown partial state; manual review required')
    for name in allowed:
        p = STATE / name
        if p.exists() or p.is_symlink():
            checked(p, secret=True)
            p.unlink()
    STATE.rmdir()
    return {'cleaned_partial_prepare': True}


def bound_socket(kind, address, port=0):
    sock = socket.socket(socket.AF_INET, kind)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, IFACE.encode() + b'\0')
        sock.settimeout(2)
        sock.bind((address, port))
        return sock
    except Exception:
        sock.close()
        raise


def receive_exact(sock, count):
    data = b''
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        require(bool(chunk), 'short TCP payload')
        data += chunk
    return data


def echo_server(sock, tcp, peer, stop):
    while not stop.is_set():
        try:
            if tcp:
                client, address = sock.accept()
                with client:
                    client.settimeout(2)
                    if address[0] == peer:
                        data = receive_exact(client, 1024)
                        if data.startswith(b'TASK05:'):
                            client.sendall(data)
            else:
                data, address = sock.recvfrom(1025)
                if address[0] == peer and len(data) == 1024 and data.startswith(b'TASK05:'):
                    sock.sendto(data, address)
        except (OSError, RuntimeError):
            continue


def exchange(local, peer, tcp):
    data = b'TASK05:' + secrets.token_bytes(1017)
    started = time.monotonic()
    with bound_socket(socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM, local) as sock:
        sock.connect((peer, DATA_PORT))
        sock.sendall(data)
        result = receive_exact(sock, len(data)) if tcp else sock.recv(1025)
    require(result == data, 'payload mismatch')
    return round((time.monotonic() - started) * 1000, 3)


def test_passed(report):
    return (report.get('elapsed', 0) >= 900 and report.get('errors') == 0 and
            report.get('samples', 0) >= 120 and report.get('pre_idle', 0) > 0 and
            report.get('post_idle', 0) > 0 and report.get('rx_delta', 0) > 0 and
            report.get('tx_delta', 0) > 0 and report.get('invariants_ok') is True)


def run_test(s):
    """Each endpoint initiates TCP + UDP independently, never just keepalives."""
    role = s['role']
    local, peer = INNER[role], INNER['fr' if role == 'ru' else 'ru']
    stop = threading.Event()
    sockets, workers = [], []
    report = {'role': role, 'status': 'RUNNING', 'samples': 0, 'errors': 0,
              'pre_idle': 0, 'post_idle': 0, 'elapsed': 0, 'rtt_ms': [], 'invariants_ok': False}
    try:
        for tcp in (False, True):
            sock = bound_socket(socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM, local, DATA_PORT)
            if tcp:
                sock.listen(4)
            sockets.append(sock)
            worker = threading.Thread(target=echo_server, args=(sock, tcp, peer, stop), daemon=True)
            worker.start()
            workers.append(worker)
        # Both services may start a few seconds apart. Warmup is NOT test time.
        ready = False
        warmup_deadline = time.monotonic() + 60
        while time.monotonic() < warmup_deadline:
            try:
                exchange(local, peer, False)
                exchange(local, peer, True)
                if fresh(s, metrics(s), time.time()):
                    ready = True
                    break
            except (OSError, RuntimeError):
                pass
            time.sleep(1)
        require(ready, 'peer not ready during bounded warmup')
        baseline = metrics(s)
        start = time.monotonic()
        next_sample = start
        while time.monotonic() - start < 900:
            elapsed = time.monotonic() - start
            if not 300 <= elapsed < 420:  # 2-minute application idle; AWG keepalive remains.
                try:
                    udp = exchange(local, peer, False)
                    tcp = exchange(local, peer, True)
                    require(fresh(s, metrics(s), time.time()), 'handshake stale')
                    report['rtt_ms'].append({'udp': udp, 'tcp': tcp})
                    report['samples'] += 1
                    report['pre_idle' if elapsed < 300 else 'post_idle'] += 1
                except (OSError, RuntimeError):
                    report['errors'] += 1
            if int(elapsed) % 30 < 5:
                status(s)
            report['elapsed'] = round(elapsed, 3)
            atomic('test.json', json.dumps(report).encode())
            next_sample += 5
            time.sleep(max(0, next_sample - time.monotonic()))
        end = status(s)
        report.update(elapsed=round(time.monotonic() - start, 3),
                      rx_delta=end['rx'] - baseline['rx'], tx_delta=end['tx'] - baseline['tx'],
                      invariants_ok=True)
        report['status'] = 'PASS' if test_passed(report) else 'FAIL'
    except Exception:
        report['status'] = 'FAIL'
        report['errors'] += 1
    finally:
        # Keep responder alive briefly so the other side can finish its 900s.
        if report['status'] == 'PASS':
            atomic('test.json', json.dumps(report).encode())
            time.sleep(30)
        stop.set()
        for sock in sockets:
            sock.close()
        for worker in workers:
            worker.join(timeout=3)
        atomic('test.json', json.dumps(report).encode())


def start_test(s):
    status(s)
    if (STATE / 'test.json').exists():
        return {'already_started': True, 'restart_requires_cleanup': True}
    if unit_owned(s, 'test'):
        return {'already_started': True}
    require(time.time() - s['activated_at'] < 300, 'activation too old for full test; down/cleanup first')
    launch(s, 'test', ['/usr/bin/python3', '-I', '-B', str(BASE / 'helper.py'), '_test'], 1200)
    return {'started': True, 'duration_seconds': 900}


def main():
    if not (len(sys.argv) == 2 and sys.argv[1] in PUBLIC_ACTIONS + ('_test',)):
        raise DiagnosticFailure('dispatch', 'validate_arguments', 'validation_failed')
    if os.geteuid() != 0:
        raise DiagnosticFailure('dispatch', 'check_privilege', 'permission_denied')
    os.umask(0o077)
    role = step('startup', 'validate_installation', validate_install)
    action = sys.argv[1]
    if action == '_test':
        run_test(load())
        return
    fd = os.open('/run/vpn-task05.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        checked(Path('/run/vpn-task05.lock'), secret=True)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if action == 'prepare':
            result = prepare(role)
        elif action in ('down', 'cleanup') and not STATE.exists():
            require(not links() and all(unit(k).get('LoadState') == 'not-found' for k in UNITS), 'unknown residual objects')
            result = {'already_absent': True}
        elif action == 'cleanup' and not (STATE / 'state.json').exists():
            result = cleanup_partial()
        else:
            s = load()
            require(s['role'] == role, 'role mismatch')
            if action == 'peer':
                # One canonical public key + newline. Nothing executable accepted.
                value = sys.stdin.buffer.read(46)
                require(len(value) == 45 and value.endswith(b'\n'), 'expected one public key line')
                result = set_peer(s, value[:-1].decode('ascii'))
            elif action == 'result':
                checked(STATE / 'test.json', secret=True)
                result = json.loads((STATE / 'test.json').read_text())
                if result.get('status') == 'PASS':
                    require(test_passed(result), 'invalid PASS report')
                    status(s)
            else:
                result = {'up': up, 'status': status, 'down': down,
                          'cleanup': cleanup, 'start-test': start_test}[action](s)
        print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except DiagnosticFailure as error:
        report = {'status': 'BLOCKED', 'diagnostic': {'stage': error.stage,
                  'operation': error.operation, 'category': error.category}}
        if hasattr(error, 'cleanup_failure'):
            report['cleanup_failure'] = error.cleanup_failure
        print(json.dumps(report, sort_keys=True))
        sys.exit(1)
    except Exception:
        print(json.dumps({'status': 'BLOCKED', 'diagnostic': {
            'stage': 'dispatch', 'operation': 'unclassified', 'category': 'internal_error'}}, sort_keys=True))
        sys.exit(1)
