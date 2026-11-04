#!/usr/bin/env python3
"""Read-only verification of TASK 03 WireGuard configuration on RU or FR.

Usage: sudo python3 04_verify_wg_test.py --role ru|fr
No network probes, no state changes, no private-key reads.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import time

NAME = 'wg-test'
ROOT = Path('/run/vpn-task03')
NET = '10.203.254.0/30'
PORT = 51983
RU_PUBLIC = '137.22.146.212'
FR_PUBLIC = '45.15.128.138'
RU_KEY = 's91+SlFlZp/OnSM9vh370BsHxMDjsn6b+hQgk+LNTSk='
FR_KEY = 'VOuHtwi7ASJrBZelQYALws0wpxwkoOCnl5V64A0kAXY='

failures = 0
warnings = 0

def show(status, message):
    global failures, warnings
    print(f'{status:5} {message}')
    failures += status == 'FAIL'
    warnings += status == 'WARN'

def check(ok, msg, detail=''):
    show('PASS' if ok else 'FAIL', msg + (f' ({detail})' if detail else ''))

def cmd(*args):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=8, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        show('FAIL', f'Unable to run {args[0]}: {type(e).__name__}')
        return None
    if p.returncode:
        show('FAIL', f'Command failed: {args[0]} {" ".join(args[1:3])} (exit {p.returncode})')
        return None
    return p.stdout.strip()

def jcmd(*args):
    out = cmd(*args)
    if out is None:
        return None
    try:
        return json.loads(out)
    except ValueError:
        show('FAIL', f'Invalid JSON returned by {args[0]}')
        return None

def path_mode(path):
    try:
        st = path.lstat()
    except OSError:
        show('FAIL', f'Missing state file: {path.name}')
        return
    check(not path.is_symlink() and st.st_uid == 0 and st.st_gid == 0 and
          (st.st_mode & 0o777) == (0o700 if path == ROOT else 0o600),
          f'Secure owner and mode: {path.name}')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role', required=True, choices=['ru', 'fr'])
    a = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('Run on the Linux VPS')
    if os.geteuid() != 0:
        parser.error('Run with sudo (read-only, to inspect protected state)')
    local = '10.203.254.1' if a.role == 'ru' else '10.203.254.2'
    remote = '10.203.254.2' if a.role == 'ru' else '10.203.254.1'
    own_key = RU_KEY if a.role == 'ru' else FR_KEY
    peer_key = FR_KEY if a.role == 'ru' else RU_KEY
    outer_peer = FR_PUBLIC if a.role == 'ru' else RU_PUBLIC
    print(f'TASK 03 READ-ONLY VERIFICATION | role={a.role} | {NAME} | {local} -> {remote}')
    print('No packets generated; no network or configuration changes.\n')

    links = jcmd('ip', '-j', 'link', 'show', 'dev', NAME)
    if links is not None:
        check(len(links) == 1 and links[0].get('ifname') == NAME, 'Interface exists')
        if links:
            check(links[0].get('ifalias') == 'vpn-task03', 'Task 03 interface alias')
            check(links[0].get('mtu') == 1380, 'MTU = 1380')
            check('UP' in links[0].get('flags', []), 'Interface is UP')

    addrs = jcmd('ip', '-j', '-4', 'addr', 'show', 'dev', NAME)
    if addrs is not None:
        assigned = [(i.get('local'), i.get('prefixlen')) for x in addrs for i in x.get('addr_info', []) if i.get('family') == 'inet']
        check(assigned == [(local, 30)], f'IPv4 address {local}/30', f'observed: {assigned}')

    current_key = cmd('wg', 'show', NAME, 'public-key')
    if current_key is not None:
        check(current_key == own_key, 'Local WireGuard public key matches approved key')
    peers = cmd('wg', 'show', NAME, 'peers')
    if peers is not None:
        check(peers.splitlines() == [peer_key], 'Exactly one expected peer')
    allowed = cmd('wg', 'show', NAME, 'allowed-ips')
    if allowed is not None:
        fields = allowed.split()
        check(fields == [peer_key, f'{remote}/32'], f'AllowedIPs = {remote}/32')
    listen = cmd('wg', 'show', NAME, 'listen-port')
    if listen is not None:
        check(listen == str(PORT), f'ListenPort = {PORT}')
    keepalive = cmd('wg', 'show', NAME, 'persistent-keepalive')
    if keepalive is not None:
        parts = keepalive.split()
        expected = '5' if a.role == 'ru' else 'off'
        actual = ' '.join(parts[1:]) if len(parts) >= 2 and parts[0] == peer_key else ''
        valid = actual == ('every 5 seconds' if a.role == 'ru' else 'off')
        check(valid, f'Keepalive = {expected}', f'observed: {actual or "none"}')
    endpoints = cmd('wg', 'show', NAME, 'endpoints')
    if endpoints is not None:
        parts = endpoints.split()
        check(len(parts) == 2 and parts[0] == peer_key and parts[1] == f'{outer_peer}:{PORT}',
              f'Peer endpoint = {outer_peer}:{PORT}', f'observed: {parts[-1] if parts else "none"}')

    route = jcmd('ip', '-j', '-4', 'route', 'get', remote, 'from', local)
    if route is not None:
        check(bool(route) and route[0].get('dev') == NAME and route[0].get('prefsrc', route[0].get('src')) == local,
              'Inner IPv4 route through wg-test with correct source')
    underlay = jcmd('ip', '-j', '-4', 'route', 'get', outer_peer)
    if underlay is not None:
        check(bool(underlay) and underlay[0].get('dev') != NAME,
              'Public peer IP routes outside wg-test')
    rules = jcmd('ip', '-j', '-4', 'rule', 'show')
    if rules is not None:
        observed = [(r.get('priority'), r.get('table')) for r in rules]
        check(observed == [(0, 'local'), (32766, 'main'), (32767, 'default')],
              'Only default IPv4 policy rules', f'observed: {observed}')

    if ROOT.is_dir():
        for name in ['private.key', 'settings.json', 'peer', 'wg-test.conf', 'baseline.json', 'started']:
            path_mode(ROOT / name)
        path_mode(ROOT)
        try:
            settings = json.loads((ROOT / 'settings.json').read_text())
            check(settings == {'role': a.role, 'subnet': NET, 'port': PORT}, 'Prepared parameters match test')
            check((ROOT / 'peer').read_text() == peer_key, 'Recorded peer matches expected public key')
            conf = (ROOT / 'wg-test.conf').read_text()
            check('Table = off' in conf and f'AllowedIPs = {remote}/32' in conf and
                  'PrivateKey' not in conf and 'PostUp' not in conf and 'PreUp' not in conf,
                  'Stored config has Table=off, correct AllowedIPs, no secret/hook')
        except (OSError, ValueError):
            show('FAIL', 'Could not read non-secret test metadata')
    else:
        show('FAIL', 'Missing /run/vpn-task03')

    hs = cmd('wg', 'show', NAME, 'latest-handshakes')
    if hs is not None:
        try:
            key, stamp = hs.split()
            age = int(time.time()) - int(stamp)
            if key != peer_key or int(stamp) == 0:
                show('WARN', 'No confirmed handshake with expected peer')
            elif age < 0:
                show('WARN', 'Handshake timestamp is in the future; check clock')
            else:
                show('PASS' if age <= 180 else 'WARN', f'Last handshake age: {age}s')
        except (ValueError, TypeError):
            show('WARN', 'Could not interpret handshake status')

    for flag_path in ('/proc/sys/net/ipv4/conf/all/rp_filter',
                      '/proc/sys/net/ipv4/conf/' + NAME + '/rp_filter'):
        try:
            val = Path(flag_path).read_text().strip()
            if val != '0':
                show('WARN', f'{flag_path} = {val} (consider reverse-path filtering)')
        except OSError:
            pass

    print(f'\nSUMMARY: {failures} FAIL, {warnings} WARN')
    print('This verifies configuration only; it cannot prove packet delivery or firewall acceptance.')
    return 1 if failures else 0

if __name__ == '__main__':
    sys.exit(main())
