#!/usr/bin/python3
"""Update only the root-only TASK 07 test profile and its matching helper."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path('/var/lib/vpn-task08')
BACKUP = ROOT / 'backup'
HELPER = Path('/usr/local/sbin/vpn-task07')
PROFILE = Path('/etc/vpn-task07/Test_iPhone.conf')
STAGED = Path('/home/wolffrog/task08-stage/task07-helper.py')
OLD = b'AllowedIPs = 10.203.253.1/32\n'
NEW = b'AllowedIPs = 0.0.0.0/0, ::/0\n'
MTU = b'MTU = 1280\n'
DNS = b'DNS = 10.203.253.1\n'


def root_file(path, mode):
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != mode:
        raise RuntimeError('root file ownership mismatch')
    return path.read_bytes()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def atomic(path, data, mode):
    temp = path.with_name(path.name + '.task08-new')
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


def main():
    if os.geteuid() != 0 or len(sys.argv) != 1:
        raise RuntimeError('root and zero arguments required')
    if Path('/etc/vpn-task06/role').read_text().strip() != 'ru':
        raise RuntimeError('RU role required')
    baseline = json.loads(root_file(ROOT / 'prechange.json', 0o600))
    if baseline.get('role') != 'ru':
        raise RuntimeError('baseline role mismatch')
    expected = baseline['observed']['file_sha256']['task07_helper']
    prior_helper = root_file(HELPER, 0o755)
    saved_helper = root_file(BACKUP / 'task07-helper.py', 0o600)
    if digest(prior_helper) != expected or digest(saved_helper) != expected:
        raise RuntimeError('TASK 07 helper changed')
    next_helper = STAGED.read_bytes()
    compile(next_helper, str(STAGED), 'exec')
    prior_profile = root_file(PROFILE, 0o600)
    if (prior_profile.count(OLD) != 1 or prior_profile.count(MTU) != 1 or
            DNS in prior_profile or NEW in prior_profile):
        raise RuntimeError('TASK 07 test profile format conflict')
    next_profile = prior_profile.replace(MTU, MTU + DNS).replace(OLD, NEW)
    if (BACKUP / 'task07-test-profile.conf').exists():
        raise RuntimeError('TASK 07 profile backup already exists')
    atomic(BACKUP / 'task07-test-profile.conf', prior_profile, 0o600)
    try:
        atomic(HELPER, next_helper, 0o755)
        atomic(PROFILE, next_profile, 0o600)
    except Exception:
        atomic(HELPER, prior_helper, 0o755)
        atomic(PROFILE, prior_profile, 0o600)
        raise
    print(json.dumps({'test_profile_updated': True, 'ru_only': True,
                      'private_key_disclosed': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps({'test_profile_updated': False, 'reason': 'ownership_or_format_conflict'}),
              file=sys.stderr)
        raise SystemExit(1)
