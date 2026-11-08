#!/usr/bin/python3
"""Install the reviewed RU-only TASK 06 baseline compatibility patch."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

BASE = Path('/opt/vpn-task06')
STAGED = Path('/home/wolffrog/task06-task07-patch/helper.py')
BACKUP = Path('/root/vpn-task06-task07-baseline-backup')
EXPECTED = '6f3e31345156bb5f90d82bc8c6c90f24c66f62331718ca8e9dbead79d72be6b4'
PREVIOUS = '6c92991aa93039d530f13317aa3f4b6eae362918e4996c251d60d5d84a5d4dc2'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_atomic(path, data, mode):
    tmp = path.with_name(path.name + '.task07-new')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def main():
    if os.geteuid() != 0 or len(sys.argv) != 1:
        raise RuntimeError('root and zero arguments required')
    if Path('/etc/vpn-task06/role').read_text().strip() != 'ru':
        raise RuntimeError('RU-only update')
    old_helper = (BASE / 'helper.py').read_bytes()
    old_manifest = (BASE / 'manifest.json').read_bytes()
    manifest = json.loads(old_manifest)
    if digest(old_helper) != manifest['files']['helper.py']:
        raise RuntimeError('existing helper/manifest mismatch')
    new_helper = STAGED.read_bytes()
    if digest(new_helper) != EXPECTED:
        raise RuntimeError('staged helper hash mismatch')
    compile(new_helper, str(STAGED), 'exec')
    if BACKUP.exists():
        st = BACKUP.lstat()
        if (stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or
                st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700 or
                digest(old_helper) != PREVIOUS):
            raise RuntimeError('existing backup or previous patch mismatch')
        saved = (BACKUP / 'helper.py').read_bytes()
        saved_manifest = json.loads((BACKUP / 'manifest.json').read_bytes())
        if digest(saved) != saved_manifest['files']['helper.py']:
            raise RuntimeError('original backup hash mismatch')
    else:
        if BACKUP.is_symlink():
            raise RuntimeError('backup path is a symlink')
        BACKUP.mkdir(mode=0o700)
        write_atomic(BACKUP / 'helper.py', old_helper, 0o600)
        write_atomic(BACKUP / 'manifest.json', old_manifest, 0o600)
    manifest['files']['helper.py'] = EXPECTED
    new_manifest = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    try:
        write_atomic(BASE / 'helper.py', new_helper, 0o644)
        write_atomic(BASE / 'manifest.json', new_manifest, 0o644)
    except Exception:
        write_atomic(BASE / 'helper.py', old_helper, 0o644)
        write_atomic(BASE / 'manifest.json', old_manifest, 0o644)
        raise
    print(json.dumps({'updated': True, 'role': 'ru', 'helper_sha256': EXPECTED,
                      'backup': str(BACKUP)}))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'updated': False, 'reason': str(exc)}), file=sys.stderr)
        raise SystemExit(1)
