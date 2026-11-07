#!/usr/bin/python3
"""Fixed-purpose TASK 06 userspace AWG service and monitor. No shell or dynamic targets."""
import base64
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import selectors
import signal
import socket
import stat
import subprocess
import sys
import threading
import time

BASE = Path('/opt/vpn-task06')
CONF = Path('/etc/vpn-task06')
STATE = Path('/var/lib/vpn-task06')
RUNTIME = Path('/run/vpn-task06')
IFACE = 'awg-transport'
NET = ipaddress.ip_network('10.203.254.0/30')
PORT, DATA_PORT, MTU = 51983, 51984, 1280
PUBLIC = {'ru': '137.22.146.212', 'fr': '45.15.128.138'}
INNER = {'ru': '10.203.254.1', 'fr': '10.203.254.2'}
PEER = {'ru': 'fr', 'fr': 'ru'}
FR_AUDIT_ADDRESSES = {'docker0': ('172.17.0.1', 16), 'amn0': ('172.29.172.1', 24)}
FR_AUDIT_ROUTES = {'172.17.0.0/16': 'docker0', '172.29.172.0/24': 'amn0'}
PRODUCTION_PORT = 40905
UNIT = 'vpn-task06-awg.service'
PROBE_UNIT = 'vpn-task06-probe.service'
MONITOR_TIMER = 'vpn-task06-monitor.timer'
BIN_GO = str(BASE / 'amneziawg-go')
BIN_AWG = str(BASE / 'awg')
IP = '/usr/sbin/ip'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'HOME': '/',
       'LOG_LEVEL': 'silent', 'GOMAXPROCS': '1', 'GOMEMLIMIT': '96MiB'}
PAYLOAD = b'TASK06:' + bytes(range(256)) * 3 + bytes(range(249))
assert len(PAYLOAD) == 1024
LOCK = RUNTIME / 'control.lock'
DIAGNOSTIC_CATEGORIES = {'command_failed', 'timeout', 'permission_denied',
                         'missing_executable', 'io_error', 'invalid_output',
                         'invalid_data', 'validation_failed', 'internal_error'}


class Failure(Exception):
    def __init__(self, stage, operation, category='validation_failed'):
        self.stage, self.operation = stage, operation
        self.category = category if category in DIAGNOSTIC_CATEGORIES else 'internal_error'


def require(ok):
    if not ok:
        raise Failure('validation', 'invariant_check', 'validation_failed')


def run(args, input_data=None, timeout=15, allow_failure=False):
    try:
        p = subprocess.run(args, input=input_data, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, env=ENV, timeout=timeout,
                           check=False)
    except subprocess.TimeoutExpired:
        raise Failure('command', Path(args[0]).name, 'timeout') from None
    except PermissionError:
        raise Failure('command', Path(args[0]).name, 'permission_denied') from None
    except FileNotFoundError:
        raise Failure('command', Path(args[0]).name, 'missing_executable') from None
    except OSError:
        raise Failure('command', Path(args[0]).name, 'io_error') from None
    if p.returncode and not allow_failure:
        raise Failure('command', Path(args[0]).name, 'command_failed')
    if len(p.stdout) > 8 * 1024 * 1024:
        raise Failure('command', Path(args[0]).name, 'invalid_output')
    try:
        return p.stdout.decode('utf-8').strip()
    except UnicodeError:
        raise Failure('command', Path(args[0]).name, 'invalid_output') from None


def checked(path, directory=False, mode=None):
    s = path.lstat()
    require(s.st_uid == 0 and not s.st_mode & 0o022 and not stat.S_ISLNK(s.st_mode))
    require(stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode))
    if mode is not None:
        require(stat.S_IMODE(s.st_mode) == mode)
    return s


def atomic(path, data, mode):
    temp = path.with_name(path.name + '.new')
    require(not temp.exists() and not temp.is_symlink())
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
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


def validate_install():
    for p in (Path('/opt'), BASE, Path('/etc'), CONF, Path('/var/lib'), STATE,
              Path('/usr/local'), Path('/usr/local/sbin'), Path('/run')):
        checked(p, directory=True)
    if RUNTIME.exists() or RUNTIME.is_symlink():
        checked(RUNTIME, directory=True, mode=0o700)
    checked(CONF / 'role', mode=0o644)
    role = (CONF / 'role').read_text().strip()
    require(role in PUBLIC)
    checked(BASE / 'manifest.json', mode=0o644)
    manifest = json.loads((BASE / 'manifest.json').read_text())
    required = {'amneziawg-go', 'awg', 'helper.py', 'launcher.sh',
                'vpn-task06-awg.service', 'vpn-task06-probe.service',
                'vpn-task06-monitor.service', 'vpn-task06-monitor.timer'}
    require(set(manifest.get('files', {})) == required)
    for name in required:
        checked(BASE / name)
        require(hashlib.sha256((BASE / name).read_bytes()).hexdigest() == manifest['files'][name])
    return role


def canonical_key(value):
    require(isinstance(value, str) and len(value) == 44)
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        raise RuntimeError('invalid public key') from None
    require(len(raw) == 32 and raw != bytes(32) and base64.b64encode(raw).decode() == value)
    return value


def keygen(role):
    key_path = CONF / 'private.key'
    if key_path.exists() or key_path.is_symlink():
        checked(key_path, mode=0o600)
        private = key_path.read_bytes()
    else:
        private = (run([BIN_AWG, 'genkey']) + '\n').encode()
        atomic(key_path, private, 0o600)
    public = canonical_key(run([BIN_AWG, 'pubkey'], input_data=private))
    return {'role': role, 'public_key': public, 'key_created_or_validated': True}


def peer_set(role):
    value = sys.stdin.buffer.read(46)
    require(len(value) == 45 and value.endswith(b'\n'))
    key = canonical_key(value[:-1].decode('ascii'))
    peer_path = CONF / 'peer.pub'
    if peer_path.exists() or peer_path.is_symlink():
        checked(peer_path, mode=0o644)
        require(peer_path.read_text().strip() == key)
    else:
        atomic(peer_path, (key + '\n').encode(), 0o644)
    return {'peer_configured': True, 'role': role}


def ip_json(*args, allow_failure=False):
    out = run([IP, '-j', *args], allow_failure=allow_failure)
    try:
        return json.loads(out) if out else []
    except json.JSONDecodeError:
        raise Failure('network', 'parse_ip_json', 'invalid_output') from None


def links():
    return ip_json('-d', 'link', 'show', 'dev', IFACE, allow_failure=True)


def stable(value):
    if isinstance(value, dict):
        volatile = {'expires', 'valid_life_time', 'preferred_life_time',
                    'cache', 'counter', 'metainfo'}
        return {key: stable(item) for key, item in value.items() if key not in volatile}
    if isinstance(value, list):
        # Keep array order: nft rule/expression order is security relevant.
        return [stable(item) for item in value]
    return value


def snapshot():
    routes = {}
    for family in ('-4', '-6'):
        rows = ip_json(family, 'route', 'show', 'table', 'all')
        routes[family] = stable([r for r in rows if r.get('dev') != IFACE])
    addresses = []
    for family in ('-4', '-6'):
        addresses.extend(r for r in ip_json(family, 'address', 'show') if r.get('ifname') != IFACE)
    addresses = stable(addresses)
    rules = {family: stable(ip_json(family, 'rule', 'show')) for family in ('-4', '-6')}
    nft = run(['/usr/sbin/nft', '-j', 'list', 'ruleset'])
    try:
        fw_hash = hashlib.sha256(json.dumps(stable(json.loads(nft)), sort_keys=True,
                                            separators=(',', ':')).encode()).hexdigest()
    except json.JSONDecodeError:
        raise Failure('baseline', 'parse_firewall_json', 'invalid_output') from None
    return {'routes': routes, 'addresses': addresses, 'rules': rules, 'firewall_hash': fw_hash}


def load_baseline():
    checked(STATE / 'baseline.json', mode=0o600)
    return json.loads((STATE / 'baseline.json').read_text())


def unchanged():
    require(snapshot() == load_baseline())


def check_fr_audit(routes, addresses):
    addr_map = {row.get('ifname'): row for row in addresses}
    for iface, (local, prefix) in FR_AUDIT_ADDRESSES.items():
        row = addr_map.get(iface)
        require(row is not None and any(a.get('family') == 'inet' and
            a.get('local') == local and a.get('prefixlen') == prefix
            for a in row.get('addr_info', [])))
    route_map = {row.get('dst'): row.get('dev') for row in routes}
    for subnet, iface in FR_AUDIT_ROUTES.items():
        require(route_map.get(subnet) == iface)


def check_conflicts(role):
    addresses = ip_json('-4', 'address', 'show')
    routes = ip_json('-4', 'route', 'show', 'table', 'all')
    require(any(a.get('local') == PUBLIC[role] for r in addresses for a in r.get('addr_info', [])))
    for route in routes:
        dst = route.get('dst', 'default')
        if dst not in ('default', '0.0.0.0/0'):
            require(not NET.overlaps(ipaddress.ip_network(dst, strict=False)))
    for row in addresses:
        for addr in row.get('addr_info', []):
            if addr.get('family') == 'inet':
                require(not NET.overlaps(ipaddress.ip_network(
                    addr['local'] + '/' + str(addr['prefixlen']), strict=False)))
    if role == 'fr':
        check_fr_audit(routes, addresses)
    require(not run(['/usr/bin/ss', '-H', '-u', '-a', '-n', 'sport = :' + str(PORT)]))
    require(not run(['/usr/bin/ss', '-H', '-t', '-u', '-l', '-n',
                     'sport = :' + str(DATA_PORT)]))
    return routes, addresses


def baseline_capture(role):
    require(role in PUBLIC and not links())
    check_conflicts(role)
    baseline = snapshot()
    path = STATE / 'baseline.json'
    if path.exists() or path.is_symlink():
        checked(path, mode=0o600)
        require(json.loads(path.read_text()) == baseline)
    else:
        atomic(path, (json.dumps(baseline, sort_keys=True) + '\n').encode(), 0o600)
    return {'captured': True, 'firewall_hash': baseline['firewall_hash']}


def load_identity():
    role = validate_install()
    checked(CONF / 'private.key', mode=0o600)
    checked(CONF / 'peer.pub', mode=0o644)
    own = canonical_key(run([BIN_AWG, 'pubkey'], input_data=(CONF / 'private.key').read_bytes()))
    peer = canonical_key((CONF / 'peer.pub').read_text().strip())
    require(own != peer)
    return role, own, peer


def endpoint_peer(role):
    return PEER[role]


def listener_free():
    return not run(['/usr/bin/ss', '-H', '-u', '-a', '-n', 'sport = :' + str(PORT)])


def owner_state():
    path = STATE / 'ownership.json'
    if not path.exists() and not path.is_symlink():
        return None
    checked(path, mode=0o600)
    state = json.loads(path.read_text())
    require(state.get('iface') == IFACE and isinstance(state.get('nonce'), str) and
            len(state['nonce']) == 32 and all(c in '0123456789abcdef' for c in state['nonce']))
    return state


def save_owner(state):
    atomic(STATE / 'ownership.json', (json.dumps(state, sort_keys=True) + '\n').encode(), 0o600)


def owned_link(state, starting=False):
    rows = links()
    if not rows:
        return False
    require(len(rows) == 1)
    row = rows[0]
    alias_ok = row.get('ifalias') == 'vpn-task06:' + state['nonce']
    index_ok = row.get('ifindex') == state.get('ifindex') if state.get('ifindex') is not None else starting
    flags_ok = 'POINTOPOINT' in row.get('flags', [])
    kind = row.get('linkinfo', {}).get('info_kind')
    kind_ok = kind == state.get('link_kind') if state.get('link_kind') is not None else starting
    require(alias_ok and index_ok and flags_ok and kind_ok)
    return True


def remove_owned(state):
    if links():
        require(owned_link(state, starting=state.get('phase') == 'starting'))
        run([IP, 'link', 'delete', 'dev', IFACE])
        require(not links())


def prepare_existing(role):
    state = owner_state()
    if links():
        require(state is not None)
        remove_owned(state)
    check_conflicts(role)
    unchanged()
    peer = endpoint_peer(role)
    route = ip_json('-4', 'route', 'get', PUBLIC[peer])
    require(route and route[0].get('dev') != IFACE)
    nonce = secrets.token_hex(16)
    state = {'schema': 1, 'iface': IFACE, 'nonce': nonce, 'ifindex': None,
             'link_kind': None, 'phase': 'starting', 'role': role}
    save_owner(state)
    return state


def configure_interface(role, peer_key, state):
    other = PEER[role]
    run([BIN_AWG, 'set', IFACE, 'private-key', str(CONF / 'private.key'),
         'listen-port', str(PORT), 'jc', '4', 'jmin', '64', 'jmax', '256',
         's1', '32', 's2', '64', 's3', '32', 's4', '32',
         'h1', '176321011-176321111', 'h2', '276321011-276321111',
         'h3', '376321011-376321111', 'h4', '476321011-476321111',
         'peer', peer_key, 'allowed-ips', INNER[other] + '/32',
         'endpoint', PUBLIC[other] + ':' + str(PORT), 'persistent-keepalive', '25'])
    run([IP, 'address', 'add', INNER[role] + '/30', 'dev', IFACE])
    run([IP, 'link', 'set', 'dev', IFACE, 'mtu', str(MTU), 'up'])
    state['phase'] = 'active'
    save_owner(state)
    require(ip_json('-4', 'route', 'get', INNER[other])[0].get('dev') == IFACE)
    require(ip_json('-4', 'route', 'get', PUBLIC[other])[0].get('dev') != IFACE)
    unchanged()


def service(role):
    role, _, peer_key = load_identity()
    require((CONF / 'peer.pub').read_text().strip() == peer_key)
    state = prepare_existing(role)
    control = RUNTIME / 'amneziawg'
    control.mkdir(mode=0o700, exist_ok=True)
    s = control.lstat()
    require(s.st_uid == 0 and stat.S_IMODE(s.st_mode) == 0o700 and not stat.S_ISLNK(s.st_mode))
    proc = None
    stopping = threading.Event()

    def stop_signal(_signum, _frame):
        stopping.set()

    old_term = signal.signal(signal.SIGTERM, stop_signal)
    old_int = signal.signal(signal.SIGINT, stop_signal)
    try:
        proc = subprocess.Popen([BIN_GO, '-f', IFACE], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                env=ENV, close_fds=True)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if links() and (control / (IFACE + '.sock')).exists():
                break
            if proc.poll() is not None:
                raise Failure('service', 'start_userspace_awg', 'command_failed')
            time.sleep(.1)
        require(proc.poll() is None and len(links()) == 1)
        run([IP, 'link', 'set', 'dev', IFACE, 'alias', 'vpn-task06:' + state['nonce']])
        row = links()[0]
        state['ifindex'] = row['ifindex']
        state['link_kind'] = row.get('linkinfo', {}).get('info_kind')
        require(state['link_kind'] in (None, 'tun'))
        require('POINTOPOINT' in row.get('flags', []))
        save_owner(state)
        configure_interface(role, peer_key, state)
        while not stopping.wait(.5):
            rc = proc.poll()
            if rc is not None:
                raise Failure('service', 'userspace_awg_exited', 'command_failed')
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
        if links():
            remove_owned(state)
        state['phase'] = 'stopped'
        save_owner(state)
    except Exception:
        if proc is not None and proc.poll() is None:
            with contextlib.suppress(Exception):
                proc.terminate()
                proc.wait(timeout=5)
            if proc.poll() is None:
                with contextlib.suppress(Exception):
                    proc.kill()
                    proc.wait(timeout=2)
        if links():
            with contextlib.suppress(Exception):
                remove_owned(state)
        raise
    finally:
        signal.signal(signal.SIGTERM, old_term)
        signal.signal(signal.SIGINT, old_int)


def service_status(role):
    unit = run(['/usr/bin/systemctl', 'show', UNIT, '--property=ActiveState,SubState,MainPID'])
    fields = dict(line.split('=', 1) for line in unit.splitlines() if '=' in line)
    require(fields.get('ActiveState') == 'active' and int(fields.get('MainPID', '0')) > 0)
    state = owner_state()
    require(state is not None and state.get('phase') == 'active' and owned_link(state))
    role, own, peer = load_identity()
    require(role in PUBLIC and run([BIN_AWG, 'show', IFACE, 'public-key']) == own)
    require(run([BIN_AWG, 'show', IFACE, 'peers']) == peer)
    handshake = run([BIN_AWG, 'show', IFACE, 'latest-handshakes']).split()
    transfer = run([BIN_AWG, 'show', IFACE, 'transfer']).split()
    require(len(handshake) == 2 and handshake[0] == peer and
            len(transfer) == 3 and transfer[0] == peer)
    now = int(time.time())
    stamp = int(handshake[1])
    age = now - stamp if stamp else None
    unchanged()
    return {'active': True, 'handshake_age_seconds': age,
            'rx_bytes': int(transfer[1]), 'tx_bytes': int(transfer[2]),
            'host_network_baseline_unchanged': True}


def probe_ready(role):
    state = owner_state()
    if not (state is not None and state.get('phase') == 'active' and owned_link(state)):
        raise Failure('probe', 'ownership_and_link_check', 'validation_failed')
    role, own, peer = load_identity()
    if run([BIN_AWG, 'show', IFACE, 'public-key']) != own:
        raise Failure('probe', 'interface_identity_check', 'validation_failed')
    if run([BIN_AWG, 'show', IFACE, 'peers']) != peer:
        raise Failure('probe', 'peer_identity_check', 'validation_failed')
    addresses = ip_json('-4', 'address', 'show', 'dev', IFACE)
    if not (len(addresses) == 1 and any(
        item.get('local') == INNER[role] and item.get('prefixlen') == 30
        for item in addresses[0].get('addr_info', []))):
        raise Failure('probe', 'interface_address_check', 'validation_failed')
    return {'probe_ready': True}


def wait_ready(role):
    deadline = time.monotonic() + 40
    last_failure = None
    while time.monotonic() < deadline:
        try:
            state = owner_state()
            if state and state.get('phase') == 'active' and owned_link(state):
                own = canonical_key(run([BIN_AWG, 'show', IFACE, 'public-key']))
                peer = canonical_key(run([BIN_AWG, 'show', IFACE, 'peers']))
                require(own == canonical_key(run([BIN_AWG, 'pubkey'],
                          input_data=(CONF / 'private.key').read_bytes())))
                require(peer == canonical_key((CONF / 'peer.pub').read_text().strip()))
                unchanged()
                return {'ready': True}
        except Failure as error:
            last_failure = error
        except Exception:
            last_failure = Failure('service', 'readiness_check', 'internal_error')
        time.sleep(.25)
    if last_failure is not None:
        raise last_failure
    raise Failure('service', 'wait_ready', 'timeout')


def bound_socket(kind, address, port):
    sock = socket.socket(socket.AF_INET, kind)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, IFACE.encode() + b'\0')
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(3)
        sock.bind((address, port))
        return sock
    except PermissionError:
        sock.close()
        raise Failure('socket', 'setup_interface_bound_socket', 'permission_denied') from None
    except OSError:
        sock.close()
        raise Failure('socket', 'setup_interface_bound_socket', 'io_error') from None
    except Exception:
        sock.close()
        raise Failure('socket', 'setup_interface_bound_socket', 'internal_error') from None


def receive_exact(sock, size):
    data = b''
    while len(data) < size:
        part = sock.recv(size - len(data))
        require(bool(part))
        data += part
    return data


def exchange(local, peer, kind):
    sock_type = socket.SOCK_STREAM if kind == 'tcp' else socket.SOCK_DGRAM
    for attempt in range(3):
        try:
            with bound_socket(sock_type, local, 0) as sock:
                sock.connect((peer, DATA_PORT))
                sock.sendall(PAYLOAD)
                result = receive_exact(sock, len(PAYLOAD)) if kind == 'tcp' else sock.recv(2048)
            if result != PAYLOAD:
                raise Failure('monitor', kind + '_echo', 'invalid_data')
            return
        except socket.timeout:
            error = Failure('monitor', kind + '_echo', 'timeout')
        except OSError:
            error = Failure('monitor', kind + '_echo', 'io_error')
        except Failure as failure:
            if failure.category != 'timeout':
                raise
            error = failure
        if attempt < 2:
            time.sleep(.2)
    raise error


def probe_server(role):
    local, peer = INNER[role], INNER[PEER[role]]
    selector = selectors.DefaultSelector()
    sockets = []
    stop = threading.Event()
    def stop_signal(_signum, _frame):
        stop.set()
    old_term = signal.signal(signal.SIGTERM, stop_signal)
    old_int = signal.signal(signal.SIGINT, stop_signal)
    try:
        for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
            sock = bound_socket(kind, local, DATA_PORT)
            if kind == socket.SOCK_STREAM:
                sock.listen(8)
            selector.register(sock, selectors.EVENT_READ, kind)
            sockets.append(sock)
        while not stop.is_set():
            for key, _ in selector.select(.5):
                if key.data == socket.SOCK_DGRAM:
                    data, addr = key.fileobj.recvfrom(2048)
                    if addr[0] == peer and data == PAYLOAD:
                        key.fileobj.sendto(data, addr)
                else:
                    conn, addr = key.fileobj.accept()
                    with conn:
                        conn.settimeout(3)
                        if addr[0] != peer:
                            continue
                        data = receive_exact(conn, len(PAYLOAD))
                        if data == PAYLOAD:
                            conn.sendall(data)
    finally:
        for sock in sockets:
            selector.unregister(sock)
            sock.close()
        selector.close()
        signal.signal(signal.SIGTERM, old_term)
        signal.signal(signal.SIGINT, old_int)


def monitor(role):
    status = service_status(role)
    age = status['handshake_age_seconds']
    require(age is not None and 0 <= age <= 180)
    exchange(INNER[role], INNER[PEER[role]], 'udp')
    exchange(INNER[role], INNER[PEER[role]], 'tcp')
    return {'healthy': True, 'handshake_age_seconds': age,
            'udp_echo': True, 'tcp_echo': True}


def rollback(role):
    # This verb is intentionally explicit and only removes fixed TASK 06 paths.
    manifest = json.loads((BASE / 'manifest.json').read_text())
    expected_hashes = manifest['files']
    protected_files = {
        '/etc/systemd/system/vpn-task06-awg.service': 'vpn-task06-awg.service',
        '/etc/systemd/system/vpn-task06-probe.service': 'vpn-task06-probe.service',
        '/etc/systemd/system/vpn-task06-monitor.service': 'vpn-task06-monitor.service',
        '/etc/systemd/system/vpn-task06-monitor.timer': 'vpn-task06-monitor.timer',
        '/usr/local/sbin/vpn-task06': 'launcher.sh',
    }
    for destination, package_name in protected_files.items():
        path = Path(destination)
        require(path.exists() and not path.is_symlink())
        checked(path)
        require(hashlib.sha256(path.read_bytes()).hexdigest() == expected_hashes[package_name])
    for unit in (MONITOR_TIMER, 'vpn-task06-monitor.service', PROBE_UNIT, UNIT):
        run(['/usr/bin/systemctl', 'disable', '--now', unit], allow_failure=True)
        state_text = run(['/usr/bin/systemctl', 'show', unit, '--property=ActiveState', '--value'], allow_failure=True)
        require(state_text in ('inactive', 'failed', 'not-found', ''))
    state = owner_state()
    if links():
        require(state is not None)
        remove_owned(state)
    require(not links())
    unit_paths = [Path('/etc/systemd/system/vpn-task06-awg.service'),
                  Path('/etc/systemd/system/vpn-task06-probe.service'),
                  Path('/etc/systemd/system/vpn-task06-monitor.service'),
                  Path('/etc/systemd/system/vpn-task06-monitor.timer'),
                  Path('/usr/local/sbin/vpn-task06')]
    for path in unit_paths:
        if path.exists() or path.is_symlink():
            checked(path)
            path.unlink()
    require({p.name for p in CONF.iterdir()} == {'private.key', 'peer.pub', 'role'})
    require({p.name for p in STATE.iterdir()} == {'baseline.json', 'ownership.json'})
    for name in ('private.key', 'peer.pub', 'role'):
        path = CONF / name
        if path.exists() or path.is_symlink():
            checked(path, mode={'private.key': 0o600, 'peer.pub': 0o644, 'role': 0o644}[name])
            path.unlink()
    for name in ('baseline.json', 'ownership.json'):
        path = STATE / name
        if path.exists() or path.is_symlink():
            checked(path, mode=0o600)
            path.unlink()
    for path in (CONF, STATE):
        require(path.is_dir() and not path.is_symlink())
        path.rmdir()
    names = set(manifest['files']) | {'manifest.json'}
    require({p.name for p in BASE.iterdir()} == names)
    for name in manifest['files']:
        path = BASE / name
        checked(path)
        require(hashlib.sha256(path.read_bytes()).hexdigest() == manifest['files'][name])
        path.unlink()
    checked(BASE / 'manifest.json', mode=0o644)
    (BASE / 'manifest.json').unlink()
    BASE.rmdir()
    run(['/usr/bin/systemctl', 'daemon-reload'])
    return {'rolled_back': True, 'iface_absent': True}


def dispatch():
    if os.geteuid() != 0 or len(sys.argv) != 2:
        raise Failure('dispatch', 'validate_invocation', 'permission_denied')
    action = sys.argv[1]
    if action not in ('keygen', 'set-peer', 'capture-baseline', 'serve',
                      'probe-server', 'wait-ready', 'status', 'monitor', 'rollback'):
        raise Failure('dispatch', 'validate_action', 'validation_failed')
    os.umask(0o077)
    role = validate_install()
    if not RUNTIME.exists():
        RUNTIME.mkdir(mode=0o700)
    checked(RUNTIME, directory=True, mode=0o700)
    # The two long-running systemd workers must not hold the control lock;
    # otherwise read-only status/monitor commands would block for their lifetime.
    lock_required = action not in ('serve', 'probe-server')
    if lock_required:
        fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        lock_context = os.fdopen(fd, 'w')
    else:
        lock_context = contextlib.nullcontext(None)
    with lock_context as lock:
        if lock is not None:
            checked(LOCK, mode=0o600)
            lock_mode = fcntl.LOCK_EX if action in ('status', 'monitor', 'wait-ready') else fcntl.LOCK_EX | fcntl.LOCK_NB
            fcntl.flock(lock, lock_mode)
        if action == 'keygen':
            result = keygen(role)
        elif action == 'set-peer':
            result = peer_set(role)
        elif action == 'capture-baseline':
            result = baseline_capture(role)
        elif action == 'serve':
            service(role)
            result = {'stopped': True}
        elif action == 'probe-server':
            probe_ready(role)
            probe_server(role)
            result = {'probe_stopped': True}
        elif action == 'wait-ready':
            result = wait_ready(role)
        elif action == 'status':
            result = service_status(role)
        elif action == 'monitor':
            result = monitor(role)
        else:
            result = rollback(role)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        dispatch()
    except Failure as error:
        print(json.dumps({'status': 'BLOCKED', 'diagnostic': {
            'stage': error.stage, 'operation': error.operation,
            'category': error.category}}, sort_keys=True))
        sys.exit(1)
    except Exception:
        print(json.dumps({'status': 'BLOCKED', 'diagnostic': {
            'stage': 'dispatch', 'operation': 'unclassified',
            'category': 'internal_error'}}, sort_keys=True))
        sys.exit(1)
