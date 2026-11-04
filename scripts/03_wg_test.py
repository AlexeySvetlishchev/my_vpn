#!/usr/bin/env python3
"""Owner-operated, temporary RU/FR test. Default is an offline dry-run."""
import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import time

ROOT = Path('/run/vpn-task03')
IFACE = 'wg-test'
FR = '45.15.128.138'


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def run(*args, data=None):
    p = subprocess.run(args, input=data, text=True, capture_output=True, timeout=25)
    require(p.returncode == 0, f'{args[0]} {args[1]} failed; output withheld; see runbook')
    return p.stdout.strip()


def ip(*args):
    return json.loads(run('ip', '-j', *args))


def network(value):
    n = ipaddress.IPv4Network(value, strict=True)
    private = [ipaddress.IPv4Network(s) for s in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
    require(n.prefixlen == 30 and any(n.subnet_of(p) for p in private), 'Use an RFC1918 /30')
    return n


def check_overlap(n, routes, addresses):
    for r in routes:
        dst = r.get('dst', 'default')
        if dst in ('default', '0.0.0.0/0'):
            continue  # Default is expected to cover every candidate.
        require(not n.overlaps(ipaddress.IPv4Network(dst, strict=False)),
                'Candidate overlaps an existing route (including non-main tables)')
    for link in addresses:
        for a in link.get('addr_info', []):
            if a['family'] == 'inet':
                other = ipaddress.IPv4Network(f"{a['local']}/{a['prefixlen']}", strict=False)
                require(not n.overlaps(other), 'Candidate overlaps an interface address')


def preflight(n, port):
    require(not any(x['ifname'] == IFACE for x in ip('link', 'show')), 'wg-test already exists')
    check_overlap(n, ip('-4', 'route', 'show', 'table', 'all'), ip('-4', 'address', 'show'))
    require(not run('ss', '-H', '-u', '-a', '-n', f'sport = :{port}'), 'UDP port is occupied')
    print('PASS: candidate subnet and local UDP port are unused; firewall not certified')


def snapshot():
    result = {}
    for family in ('-4', '-6'):
        routes = ip(family, 'route', 'show', 'table', 'all')
        # Only the test interface's connected/local routes may be added.
        result[family] = sorted((json.dumps(r, sort_keys=True) for r in routes
                                  if r.get('dev') != IFACE))
        result[family + 'rules'] = ip(family, 'rule', 'show')
    return result


def secure(path, directory=False):
    s = path.lstat()
    require(not stat.S_ISLNK(s.st_mode) and s.st_uid == 0 and s.st_gid == 0,
            'Unsafe state ownership or symlink')
    require(stat.S_IMODE(s.st_mode) == (0o700 if directory else 0o600), 'Unsafe state mode')
    require(stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode) and s.st_nlink == 1,
            'Unsafe state type or hardlink')


def write(name, text):
    # Atomic publication within a root-only directory; no secret output.
    p = ROOT / name
    tmp = ROOT / (name + '.new')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(text)
    os.replace(tmp, p)


def read(name):
    secure(ROOT / name)
    return (ROOT / name).read_text()


def present():
    return any(x['ifname'] == IFACE for x in ip('link', 'show'))


def owned():
    links = ip('link', 'show', 'dev', IFACE)
    require(links[0].get('ifalias') == 'vpn-task03', 'Unowned wg-test: refusing mutation')
    require(run('wg', 'show', IFACE, 'public-key') == run('wg', 'pubkey', data=read('private.key')),
            'wg-test identity mismatch: refusing mutation')
    require(run('wg', 'show', IFACE, 'peers') == read('peer'),
            'wg-test peer mismatch: refusing operation')


def unchanged():
    require(snapshot() == json.loads(read('baseline.json')), 'Routes/rules changed; do not restore globally; investigate')


def fresh(start, stamp, now):
    return stamp > 0 and stamp >= start and 0 <= now - stamp <= 180


def handshake():
    owned()
    start = int(read('started'))
    rows = run('wg', 'show', IFACE, 'latest-handshakes').splitlines()
    require(len(rows) == 1, 'Expected exactly one peer')
    stamp = int(rows[0].split()[1])
    require(fresh(start, stamp, int(time.time())), 'No fresh handshake from this activation (maximum age 180s)')
    unchanged()
    print(f'PASS: fresh handshake timestamp={stamp}; original routes/rules unchanged')


def transfers():
    rows = run('wg', 'show', IFACE, 'transfer').splitlines()
    require(len(rows) == 1, 'Expected exactly one peer')
    return tuple(map(int, rows[0].split()[1:]))


def probe(a):
    require(a.firewall_reviewed, 'Review host/provider firewall first; then --firewall-reviewed')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(30)
        if a.role == 'fr':
            require(a.ru_ip is not None, 'FR probe needs --ru-ip (actual public RU source)')
            require(not run('ss', '-H', '-u', '-a', '-n', f'sport = :{a.port}'), 'UDP port is occupied')
            s.bind(('0.0.0.0', a.port))
            print('Waiting up to 30s for one RU UDP probe', flush=True)
            end = time.monotonic() + 30
            while time.monotonic() < end:
                s.settimeout(max(0.01, end - time.monotonic()))
                data, source = s.recvfrom(65)
                if source[0] == a.ru_ip and data.startswith(b'TASK03:') and len(data) == 39:
                    s.sendto(data, source)
                    print('PASS: RU datagram received and echoed; confirm RU also reports PASS')
                    return
            raise RuntimeError('UDP probe timed out')
        else:
            token = b'TASK03:' + os.urandom(16).hex().encode()
            s.connect((FR, a.port))
            s.send(token)
            require(s.recv(65) == token, 'UDP echo mismatch')
            print('PASS: bidirectional UDP probe; this is not a WireGuard handshake')


def execute(a):
    n = network(a.subnet)
    local, peer = list(n.hosts()) if a.role == 'ru' else list(n.hosts())[::-1]
    if a.action == 'probe':
        probe(a)
        return
    if a.action == 'preflight':
        preflight(n, a.port)
        return
    if a.action == 'prepare':
        preflight(n, a.port)
        settings = {'role': a.role, 'subnet': str(n), 'port': a.port}
        if (ROOT / 'settings.json').exists():
            require(json.loads(read('settings.json')) == settings, 'Prepared settings differ; cleanup first')
            read('private.key')
        else:
            require(not (ROOT / 'private.key').exists(), 'Partial preparation; cleanup before retry')
            write('private.key', run('wg', 'genkey') + '\n')
            write('settings.json', json.dumps(settings))
        print('PUBLIC KEY (only this value is exchanged):')
        print(run('wg', 'pubkey', data=read('private.key')))
        return
    if a.action in ('down', 'cleanup'):
        if present():
            owned()
            run('ip', 'link', 'delete', 'dev', IFACE)
        if (ROOT / 'baseline.json').exists():
            unchanged()
        if a.action == 'cleanup':
            allowed = {'private.key', 'settings.json', 'baseline.json', 'started', 'wg-test.conf', 'peer'}
            require(all(p.name in allowed or p.name in {x + '.new' for x in allowed}
                        for p in ROOT.iterdir()), 'Unexpected state files; refusing cleanup')
            for p in ROOT.iterdir():
                secure(p)
            for p in ROOT.iterdir():
                p.unlink()
            # Keep locked directory until process exits; next prepare can reuse it.
        print('PASS: test interface absent; cleanup retains only empty /run/vpn-task03')
        return
    settings = json.loads(read('settings.json'))
    require(settings == {'role': a.role, 'subnet': str(n), 'port': a.port}, 'Arguments differ from prepared settings')
    if a.action == 'up':
        require(a.firewall_reviewed and a.udp_verified, 'Require reviewed firewall and successful paired UDP probe')
        require(a.peer_key is not None, 'Supply the other VPS public key with --peer-key')
        key = base64.b64decode(a.peer_key, validate=True)
        require(len(key) == 32 and any(key) and base64.b64encode(key).decode() == a.peer_key, 'Invalid public key')
        require(a.peer_key != run('wg', 'pubkey', data=read('private.key')), 'Peer key equals local key')
        if present():
            owned()
            require(read('peer') == a.peer_key, 'Active peer differs')
            unchanged()
            print('KEEP: owned test interface; use handshake/packets to verify it')
            return
        preflight(n, a.port)
        write('baseline.json', json.dumps(snapshot()))
        write('peer', a.peer_key)
        write('started', str(int(time.time())))
        # No private key in wg-quick config; load via file after interface creation.
        config = (f'[Interface]\nAddress = {local}/30\nListenPort = {a.port}\n'
                  f'Table = off\nMTU = 1380\n[Peer]\nPublicKey = {a.peer_key}\nAllowedIPs = {peer}/32\n')
        if a.role == 'ru':
            config += f'Endpoint = {FR}:{a.port}\nPersistentKeepalive = 5\n'
        write('wg-test.conf', config)
        try:
            run('wg-quick', 'up', str(ROOT / 'wg-test.conf'))
            run('ip', 'link', 'set', 'dev', IFACE, 'alias', 'vpn-task03')
            run('wg', 'set', IFACE, 'private-key', str(ROOT / 'private.key'))
            unchanged()
        except BaseException:
            # preflight established absence; no concurrent network administrators allowed.
            if present():
                run('ip', 'link', 'delete', 'dev', IFACE)
            raise
        print('ACTIVE: interface created; handshake and packets are NOT yet verified')
    elif a.action == 'handshake':
        handshake()
    elif a.action == 'packets':
        handshake()
        route = ip('-4', 'route', 'get', str(peer))
        require(route[0].get('dev') == IFACE, 'Peer route does not use wg-test')
        before = transfers()
        # -I prevents a successful ping through an unrelated interface.
        out = run('ping', '-n', '-I', IFACE, '-c', '3', '-W', '2', '-w', '10', str(peer))
        require('3 received' in out and ' 0% packet loss' in out, 'Require all three echo replies')
        after = transfers()
        require(all(y > x for x, y in zip(before, after)), 'Both RX and TX counters must increase')
        handshake()
        print(f'PASS: 3/3 echo replies; RX delta={after[0]-before[0]}, TX delta={after[1]-before[1]}; repeat on other VPS')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('preflight', 'probe', 'prepare', 'up', 'handshake', 'packets', 'down', 'cleanup'))
    p.add_argument('--role', required=True, choices=('ru', 'fr'))
    p.add_argument('--subnet', default='10.203.254.0/30')
    p.add_argument('--port', type=int, default=51983)
    p.add_argument('--peer-key')
    p.add_argument('--ru-ip')
    p.add_argument('--firewall-reviewed', action='store_true')
    p.add_argument('--udp-verified', action='store_true')
    mode = p.add_mutually_exclusive_group()
    mode.add_argument('--apply', action='store_true')
    mode.add_argument('--dry-run', action='store_true')
    a = p.parse_args()
    network(a.subnet)
    require(1024 <= a.port <= 65535, 'Port must be 1024..65535')
    if a.ru_ip:
        a.ru_ip = str(ipaddress.IPv4Address(a.ru_ip))
    if not a.apply:
        print(f'DRY-RUN: {a.action}, role={a.role}, subnet={a.subnet}, UDP={a.port}, interface={IFACE}')
        print('No commands, files, keys, probes or host checks executed. See TASK_03_WG_TEST.md.')
        return
    require(sys.platform == 'linux' and os.geteuid() == 0, 'Requires sudo on the target Ubuntu VPS')
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    os.environ['LC_ALL'] = 'C'
    os.umask(0o077)
    for tool in ('ip', 'ss', 'wg', 'wg-quick', 'ping'):
        require(shutil.which(tool), f'BLOCKED: missing {tool}; installation is a separate approved action')
    # /run is a root-owned system directory; never follow a substituted state path.
    s = Path('/run').lstat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022, 'Unsafe /run')
    import fcntl
    # Lock /run inode without creating a lock file (including preflight/probe).
    lock = os.open('/run', os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if a.action not in ('preflight', 'probe'):
            if not ROOT.exists() and not ROOT.is_symlink():
                if a.action in ('down', 'cleanup'):
                    require(not present(), 'Unowned wg-test exists; no deletion')
                    print('KEEP: no test state or interface')
                    return
                require(a.action == 'prepare', 'Run prepare first')
                ROOT.mkdir(mode=0o700)
            secure(ROOT, directory=True)
        execute(a)
    finally:
        os.close(lock)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as e:
        print(f'ERROR: {e}', file=sys.stderr)
        sys.exit(1)
