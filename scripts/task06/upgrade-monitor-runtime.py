#!/usr/bin/python3
"""Replace only TASK 06 monitor unit; keep its runtime owned by the AWG unit."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

BASE = Path('/opt/vpn-task06')
UNIT = Path('/etc/systemd/system/vpn-task06-monitor.service')
NAME = 'vpn-task06-monitor.service'
STAGED = Path('/home/wolffrog/task06-monitor-fix/vpn-task06-monitor.service')
BACKUP = Path('/root/vpn-task06-monitor-fix-backup')
OLD = '00f08a9c6a153682c2d7a3b7a85ff83e74a22cd758c7802770287ce1a3e18787'
NEW = '70a529db69d0d665376a5d4a339b926e7357bf3bca1b08a5ebb24bfdc2407f1a'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def checked_file(path, mode):
    st = path.lstat()
    if not (stat.S_ISREG(st.st_mode) and st.st_uid == 0 and
            stat.S_IMODE(st.st_mode) == mode):
        raise RuntimeError('installed file ownership or mode mismatch')
    return path.read_bytes()


def atomic(path, data, mode):
    temp = path.with_name(path.name + '.monitor-fix-new')
    fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
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
    if os.geteuid() or len(sys.argv) != 1:
        raise RuntimeError('root and zero arguments required')
    role = checked_file(Path('/etc/vpn-task06/role'), 0o644).decode().strip()
    if role not in ('ru', 'fr'):
        raise RuntimeError('unexpected role')
    old_package = checked_file(BASE / NAME, 0o644)
    old_unit = checked_file(UNIT, 0o644)
    old_manifest = checked_file(BASE / 'manifest.json', 0o644)
    manifest = json.loads(old_manifest)
    if (digest(old_package) != OLD or old_package != old_unit or
            manifest['files'][NAME] != OLD):
        raise RuntimeError('current monitor unit or manifest mismatch')
    new_unit = STAGED.read_bytes()
    if digest(new_unit) != NEW or b'RuntimeDirectory=' in new_unit:
        raise RuntimeError('staged unit mismatch')
    if BACKUP.exists() or BACKUP.is_symlink():
        raise RuntimeError('backup path already exists')
    BACKUP.mkdir(mode=0o700)
    atomic(BACKUP / NAME, old_unit, 0o600)
    atomic(BACKUP / 'manifest.json', old_manifest, 0o600)
    manifest['files'][NAME] = NEW
    new_manifest = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    try:
        atomic(BASE / NAME, new_unit, 0o644)
        atomic(UNIT, new_unit, 0o644)
        atomic(BASE / 'manifest.json', new_manifest, 0o644)
        subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        atomic(BASE / NAME, old_package, 0o644)
        atomic(UNIT, old_unit, 0o644)
        atomic(BASE / 'manifest.json', old_manifest, 0o644)
        subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        raise
    print(json.dumps({'updated': True, 'role': role, 'monitor_unit_sha256': NEW}))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'updated': False, 'reason': str(exc)}), file=sys.stderr)
        raise SystemExit(1)
