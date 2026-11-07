#!/usr/bin/python3
"""OWNER ONLY, not in sudoers. Reviewed bundle must already be /root/vpn-task05-bundle.
Invocation: sudo python3 -I -B /root/vpn-task05-bundle/bootstrap.py ru|fr
Installs fixed files + exact sudo verbs, never activates a VPN or service.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

SOURCE = Path('/root/vpn-task05-bundle')
TARGET = Path('/opt/vpn-task05')
ACTIONS = ('prepare', 'peer', 'up', 'status', 'start-test', 'result', 'down', 'cleanup')


def check(path, directory=False):
    s = path.lstat()
    if s.st_uid or s.st_mode & 0o022 or stat.S_ISLNK(s.st_mode):
        raise RuntimeError('untrusted owner/mode/symlink')
    if not (stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode)):
        raise RuntimeError('wrong object type')


def install(path, data, mode):
    check(path.parent, directory=True)
    if path.exists() or path.is_symlink():
        check(path)
        if path.read_bytes() == data and stat.S_IMODE(path.stat().st_mode) == mode:
            return
        raise RuntimeError('existing file differs; no overwrite: ' + str(path))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())
    os.chmod(path, mode)


def main():
    if os.geteuid() or len(sys.argv) != 2 or sys.argv[1] not in ('ru', 'fr'):
        raise RuntimeError('owner/root role ru|fr required')
    role = sys.argv[1]
    os.umask(0o077)
    for path in (Path('/root'), SOURCE, Path('/opt'), Path('/usr/local/sbin'), Path('/etc/sudoers.d')):
        check(path, directory=True)
    check(SOURCE / 'manifest.json')
    manifest = json.loads((SOURCE / 'manifest.json').read_text())
    names = {'amneziawg-go', 'awg', 'helper.py', 'launcher.sh', 'bootstrap.py'}
    if set(manifest['files']) != names:
        raise RuntimeError('fixed manifest filenames required')
    for name in names:
        check(SOURCE / name)
        if hashlib.sha256((SOURCE / name).read_bytes()).hexdigest() != manifest['files'][name]:
            raise RuntimeError('bundle hash mismatch')
    if not TARGET.exists():
        TARGET.mkdir(mode=0o755)
    check(TARGET, directory=True)
    for name in ('amneziawg-go', 'awg', 'helper.py'):
        install(TARGET / name, (SOURCE / name).read_bytes(), 0o755 if name != 'helper.py' else 0o644)
    install(TARGET / 'manifest.json', (SOURCE / 'manifest.json').read_bytes(), 0o644)
    install(TARGET / 'role', (role + '\n').encode(), 0o644)
    install(Path('/usr/local/sbin/vpn-task05'), (SOURCE / 'launcher.sh').read_bytes(), 0o755)
    sudoers = ('# TASK05: fixed root-owned helper, no shell/interpreter/path arguments\n'
               'wolffrog ALL=(root) NOSETENV: NOPASSWD: ' + ', '.join('/usr/local/sbin/vpn-task05 ' + a for a in ACTIONS) + '\n')
    draft = TARGET / 'sudoers.reviewed'
    install(draft, sudoers.encode(), 0o440)
    subprocess.run(['/usr/sbin/visudo', '-cf', str(draft)], check=True)
    install(Path('/etc/sudoers.d/vpn-task05'), sudoers.encode(), 0o440)
    print('INSTALLED: reviewed helper and bounded verbs; no tunnel started')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('BLOCKED: bootstrap incomplete; inspect fixed destinations locally; no network rollback needed')
        sys.exit(1)
