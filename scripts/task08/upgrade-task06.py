#!/usr/bin/python3
"""Install TASK 08-aware TASK 06 helper only after exact root backup checks."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

BASE = Path('/opt/vpn-task06')
STAGED = Path('/home/wolffrog/task08-stage/task06-helper.py')
BACKUP = Path('/var/lib/vpn-task08/backup')
NEW = 'e60439c1858ac9407d5e8e411c76e374f8ef44b7273376e3c503de7e1e6a8384'
PREVIOUS = {
    'ru': '6f3e31345156bb5f90d82bc8c6c90f24c66f62331718ca8e9dbead79d72be6b4',
    'fr': '6c92991aa93039d530f13317aa3f4b6eae362918e4996c251d60d5d84a5d4dc2',
}
BACKUP_MANIFEST = {
    'ru': 'e43289926fcf80eedc380197f0c819d1a03ec2c9aed75b4acf451f6aa6c9fda5',
    'fr': '15744c7001d64a981d64beb7c5aa1ff17c83492d1853e1cb49d2817d43ae0c7f',
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def root_file(path, mode):
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != mode:
        raise RuntimeError('root file ownership/mode mismatch')
    return path.read_bytes()


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
    role = root_file(Path('/etc/vpn-task06/role'), 0o644).decode().strip()
    if role not in PREVIOUS:
        raise RuntimeError('unexpected role')
    st = BACKUP.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
        raise RuntimeError('backup directory mismatch')
    old_helper = root_file(BASE / 'helper.py', 0o644)
    old_manifest = root_file(BASE / 'manifest.json', 0o644)
    saved_helper = root_file(BACKUP / 'task06-helper.py', 0o600)
    saved_manifest = root_file(BACKUP / 'task06-manifest.json', 0o600)
    if digest(saved_helper) != PREVIOUS[role] or digest(saved_manifest) != BACKUP_MANIFEST[role]:
        raise RuntimeError('backup hash mismatch')
    saved_index = json.loads(saved_manifest)
    if saved_index['files']['helper.py'] != PREVIOUS[role]:
        raise RuntimeError('backup manifest mismatch')
    new_helper = STAGED.read_bytes()
    if digest(new_helper) != NEW:
        raise RuntimeError('staged helper hash mismatch')
    compile(new_helper, str(STAGED), 'exec')
    manifest = json.loads(old_manifest)
    if digest(old_helper) == NEW and manifest['files']['helper.py'] == NEW:
        print(json.dumps({'updated': False, 'already_installed': True, 'role': role}))
        return
    if digest(old_helper) != PREVIOUS[role] or manifest['files']['helper.py'] != PREVIOUS[role]:
        raise RuntimeError('installed helper/manifest mismatch')
    manifest['files']['helper.py'] = NEW
    new_manifest = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    try:
        atomic(BASE / 'helper.py', new_helper, 0o644)
        atomic(BASE / 'manifest.json', new_manifest, 0o644)
    except Exception:
        atomic(BASE / 'helper.py', old_helper, 0o644)
        atomic(BASE / 'manifest.json', old_manifest, 0o644)
        raise
    print(json.dumps({'updated': True, 'role': role, 'helper_sha256': NEW}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps({'updated': False, 'reason': 'validation_or_io_failure'}), file=sys.stderr)
        raise SystemExit(1)
