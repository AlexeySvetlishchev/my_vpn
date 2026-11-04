#!/usr/bin/env python3
"""TASK 03 reproducibility experiment: restart only owned wg-test and log both sides.

Run as root on each VPS, FR first, then RU. No keys or packet payloads in logs.
"""
import argparse
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time

IFACE = 'wg-test'
STATE = Path('/run/vpn-task03')
DATA = {
    'ru': dict(local='10.203.254.1', remote='10.203.254.2', public='137.22.146.212',
               outside='45.15.128.138', nic='eth0', key='s91+SlFlZp/OnSM9vh370BsHxMDjsn6b+hQgk+LNTSk=',
               peer='VOuHtwi7ASJrBZelQYALws0wpxwkoOCnl5V64A0kAXY='),
    'fr': dict(local='10.203.254.2', remote='10.203.254.1', public='45.15.128.138',
               outside='137.22.146.212', nic='ens3', key='VOuHtwi7ASJrBZelQYALws0wpxwkoOCnl5V64A0kAXY=',
               peer='s91+SlFlZp/OnSM9vh370BsHxMDjsn6b+hQgk+LNTSk='),
}


def command(*argv, timeout=8, check=True):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f'{argv[0]} {argv[1] if len(argv)>1 else ""} failed (exit {p.returncode}): {p.stderr.strip()[:200]}')
    return p.stdout.strip()


def stamp():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='milliseconds')


def item(role):
    return DATA[role]


def safe_state():
    s = STATE.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or stat.S_IMODE(s.st_mode) != 0o700:
        raise RuntimeError('Unsafe /run/vpn-task03 directory; refusing')
    for name in ('private.key', 'wg-test.conf'):
        p = STATE / name
        x = p.lstat()
        if not stat.S_ISREG(x.st_mode) or x.st_uid != 0 or x.st_nlink != 1 or stat.S_IMODE(x.st_mode) != 0o600:
            raise RuntimeError(f'Unsafe {name}; refusing')
    cfg = (STATE / 'wg-test.conf').read_text()
    if 'Table = off' not in cfg or 'PrivateKey' in cfg or 'PostUp' in cfg or 'PreUp' in cfg:
        raise RuntimeError('Unexpected test config; refusing')


def present():
    return subprocess.run(('ip', 'link', 'show', 'dev', IFACE), capture_output=True).returncode == 0


def assert_owned(cfg):
    out = json.loads(command('ip', '-j', 'link', 'show', 'dev', IFACE))
    if len(out) != 1 or out[0].get('ifalias') != 'vpn-task03':
        raise RuntimeError('Existing interface is not tagged vpn-task03; refusing to touch')
    if command('wg', 'show', IFACE, 'public-key') != cfg['key']:
        raise RuntimeError('Existing WG public key differs; refusing to touch')
    if command('wg', 'show', IFACE, 'peers') != cfg['peer']:
        raise RuntimeError('Existing WG peer differs; refusing to touch')


def validate_cfg(cfg):
    txt = (STATE / 'wg-test.conf').read_text()
    expected = (f'Address = {cfg["local"]}/30', 'Table = off', 'ListenPort = 51983',
                f'PublicKey = {cfg["peer"]}', f'AllowedIPs = {cfg["remote"]}/32')
    if not all(s in txt for s in expected):
        raise RuntimeError('Stored wg-test.conf does not match expected role; refusing')
    if cfg['local'] == DATA['ru']['local']:
        if 'Endpoint = 45.15.128.138:51983' not in txt:
            raise RuntimeError('Unexpected RU endpoint')


def route_snapshot():
    result = {}
    for fam in ('-4', '-6'):
        routes = json.loads(command('ip', '-j', fam, 'route', 'show', 'table', 'all'))
        # Ignore kernel-generated uptime-dependent RA expiry and test-interface routes.
        for r in routes:
            r.pop('expires', None)
        result[fam] = sorted(json.dumps(r, sort_keys=True) for r in routes if r.get('dev') != IFACE)
        result[fam+'rules'] = json.loads(command('ip', '-j', fam, 'rule', 'show'))
    return result


def readings(cfg):
    if not present():
        return dict(state='absent')
    def show(name):
        try:
            return command('wg', 'show', IFACE, name)
        except Exception:
            return 'ERR'
    transfer = show('transfer').split()
    latest = show('latest-handshakes').split()
    endpoint = show('endpoints').split()
    keep = show('persistent-keepalive').split()
    return dict(state='up', rx=transfer[1] if len(transfer)>2 else '?',
                tx=transfer[2] if len(transfer)>2 else '?',
                hs=latest[1] if len(latest)>1 else '?',
                endpoint=endpoint[1] if len(endpoint)>1 else '?',
                keepalive=keep[1] if len(keep)>1 else '?')


def tcpdump_reader(proc, log, lock, start):
    # tcpdump -q prints only UDP datagram metadata/length; never payload bytes.
    for line in proc.stdout:
        with lock:
            log.write(f'{time.monotonic()-start:07.2f} UDP {line.strip()}\n')
            log.flush()


def record(log, lock, line):
    with lock:
        log.write(line + '\n')
        log.flush()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--role', choices=('ru', 'fr'), required=True)
    p.add_argument('--seconds', type=int, default=90)
    p.add_argument('--apply', action='store_true', help='Explicit permission to restart wg-test and send pings')
    a = p.parse_args()
    cfg = item(a.role)
    if not a.apply:
        print(f'DRY RUN: on {a.role} restart only owned {IFACE}, then monitor UDP and ping for {a.seconds}s.')
        print('Run FR first, then RU promptly; no commands or packets sent in dry run.')
        return
    if os.geteuid() != 0 or sys.platform != 'linux':
        raise RuntimeError('Run with sudo on the Linux VPS')
    if not 15 <= a.seconds <= 300:
        raise RuntimeError('--seconds must be 15..300')
    for tool in ('ip', 'wg', 'wg-quick', 'tcpdump', 'ping'):
        if not shutil.which(tool):
            raise RuntimeError(f'Missing required tool: {tool}')
    os.umask(0o077)
    safe_state()
    validate_cfg(cfg)
    if present():
        assert_owned(cfg)
    before = route_snapshot()
    # Remove only own test interface; preserve original settings and keys.
    if present():
        command('ip', 'link', 'delete', 'dev', IFACE)
    if route_snapshot() != before:
        raise RuntimeError('Routes/rules changed after removal; no restart performed')
    out = command('wg-quick', 'up', str(STATE / 'wg-test.conf'), timeout=15)
    try:
        command('ip', 'link', 'set', 'dev', IFACE, 'alias', 'vpn-task03')
        command('wg', 'set', IFACE, 'private-key', str(STATE / 'private.key'))
        if command('wg', 'show', IFACE, 'public-key') != cfg['key']:
            raise RuntimeError('WG identity does not match expected public key')
        if command('wg', 'show', IFACE, 'peers') != cfg['peer']:
            raise RuntimeError('WG peer does not match expected public key')
    except Exception:
        # Only delete the newly created test interface, not anything else.
        if present():
            subprocess.run(('ip', 'link', 'delete', 'dev', IFACE), capture_output=True)
        raise
    logfile = STATE / f'wg-repro-{a.role}-{dt.datetime.now(dt.timezone.utc):%Y%m%dT%H%M%SZ}.log'
    fd = os.open(logfile, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    proc = None
    with os.fdopen(fd, 'w', buffering=1) as log:
        lock = threading.Lock()
        start = time.monotonic()
        record(log, lock, f'START {stamp()} role={a.role} local={cfg["local"]} remote={cfg["remote"]} interface={IFACE} duration={a.seconds}s')
        record(log, lock, 'NOTE tcpdump records UDP headers, IPs, ports, lengths only; NO payloads or private keys')
        # Observe traffic from the instant after starting; traffic may already be passing.
        filt = f'udp and host {cfg["outside"]} and port 51983'
        proc = subprocess.Popen(('tcpdump', '-ni', cfg['nic'], '-l', '-tt', '-q', filt),
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        reader = threading.Thread(target=tcpdump_reader, args=(proc, log, lock, start), daemon=True)
        reader.start()
        last_ping = -10
        seen_success = False
        try:
            while time.monotonic()-start < a.seconds:
                offset = time.monotonic()-start
                r = readings(cfg)
                changes = 'SAMPLE '+json.dumps(r, separators=(',', ':'), ensure_ascii=True)
                record(log, lock, f'{offset:07.2f} {stamp()} {changes}')
                if offset-last_ping >= 5:
                    last_ping = offset
                    ping = subprocess.run(('ping', '-n', '-I', IFACE, '-c', '1', '-W', '1', cfg['remote']),
                                          text=True, capture_output=True, timeout=4)
                    good = ping.returncode == 0 and '1 received' in ping.stdout
                    seen_success |= good
                    record(log, lock, f'{time.monotonic()-start:07.2f} {stamp()} PING '+('PASS' if good else 'FAIL'))
                time.sleep(1)
        except KeyboardInterrupt:
            record(log, lock, f'{time.monotonic()-start:07.2f} INTERRUPTED')
        finally:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
            reader.join(timeout=3)
            after = route_snapshot()
            record(log, lock, f'END {stamp()} ROUTES_RULES '+('MATCH' if before == after else 'DIFF'))
            record(log, lock, f'END {stamp()} ANY_PING_PASS={seen_success} INTERFACE_LEFT_UP=YES')
    print(f'Log saved (root-only): {logfile}')
    print(f'At least one ping succeeded: {seen_success}. wg-test is LEFT UP for further inspection.')
    print('To inspect: sudo tail -n 50 '+str(logfile))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        sys.exit(1)
