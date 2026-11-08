#!/usr/bin/python3
"""Repair the first TASK 08 test-profile field order without exposing key material."""
import json
import os
from pathlib import Path
import stat
import sys

BASE = Path('/var/lib/vpn-task08/backup/task07-test-profile.conf')
PROFILE = Path('/etc/vpn-task07/Test_iPhone.conf')
ADDR = b'Address = 10.203.253.2/32\n'
MTU = b'MTU = 1280\n'
DNS = b'DNS = 10.203.253.1\n'
OLD = b'AllowedIPs = 10.203.253.1/32\n'
NEW = b'AllowedIPs = 0.0.0.0/0, ::/0\n'


def read_root(path):
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o600:
        raise RuntimeError('root profile ownership mismatch')
    return path.read_bytes()


def main():
    if os.geteuid() != 0 or len(sys.argv) != 1:
        raise RuntimeError('root and zero arguments required')
    old = read_root(BASE)
    interim = old.replace(ADDR, ADDR + DNS).replace(OLD, NEW)
    fixed = old.replace(MTU, MTU + DNS).replace(OLD, NEW)
    if read_root(PROFILE) != interim or interim == fixed:
        raise RuntimeError('profile differs from exact repair input')
    tmp = PROFILE.with_name(PROFILE.name + '.task08-order-new')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(fixed)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, PROFILE)
    finally:
        if tmp.exists():
            tmp.unlink()
    print(json.dumps({'test_profile_order_repaired': True, 'secret_disclosed': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps({'test_profile_order_repaired': False}), file=sys.stderr)
        raise SystemExit(1)
