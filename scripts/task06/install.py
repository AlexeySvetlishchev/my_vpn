#!/usr/bin/python3
"""Install a hash-pinned TASK 06 bundle. Does not activate network services."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys

SOURCE = Path('/home/wolffrog/task06-upload/bundle')
RUNTIME_FILES = ('amneziawg-go', 'awg', 'helper.py', 'launcher.sh',
                 'vpn-task06-awg.service', 'vpn-task06-probe.service',
                 'vpn-task06-monitor.service', 'vpn-task06-monitor.timer')
PACKAGE_FILES = set(RUNTIME_FILES) | {'install.py'}
DESTINATIONS = {
    'vpn-task06-awg.service': ('/etc/systemd/system/vpn-task06-awg.service', 0o644),
    'vpn-task06-probe.service': ('/etc/systemd/system/vpn-task06-probe.service', 0o644),
    'vpn-task06-monitor.service': ('/etc/systemd/system/vpn-task06-monitor.service', 0o644),
    'vpn-task06-monitor.timer': ('/etc/systemd/system/vpn-task06-monitor.timer', 0o644),
    'launcher.sh': ('/usr/local/sbin/vpn-task06', 0o755),
}
BASE_MODES = {'amneziawg-go': 0o755, 'awg': 0o755, 'helper.py': 0o644,
              'launcher.sh': 0o755, 'vpn-task06-awg.service': 0o644,
              'vpn-task06-probe.service': 0o644,
              'vpn-task06-monitor.service': 0o644,
              'vpn-task06-monitor.timer': 0o644}


def check_dir(path, mode=None):
    info = path.lstat()
    if info.st_uid != 0 or stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError('unsafe directory')
    if info.st_mode & 0o022 or (mode is not None and stat.S_IMODE(info.st_mode) != mode):
        raise RuntimeError('unsafe directory mode')


def check_staging_dir(path, expected_uid):
    info = path.lstat()
    if (info.st_uid != expected_uid or stat.S_ISLNK(info.st_mode) or
            not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022):
        raise RuntimeError('unsafe staging directory')


def ensure_dir(path, mode):
    if not path.exists():
        path.mkdir(mode=mode)
        os.chown(path, 0, 0)
        os.chmod(path, mode)
    check_dir(path, mode)


def install_exact(path, data, mode):
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if (info.st_uid != 0 or stat.S_ISLNK(info.st_mode) or
                not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != mode or
                path.read_bytes() != data):
            raise RuntimeError('destination differs; refusing overwrite')
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.chown(path, 0, 0)
        os.chmod(path, mode)
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def main():
    if os.geteuid() != 0 or len(sys.argv) != 3 or sys.argv[1] not in ('ru', 'fr'):
        raise RuntimeError('root invocation requires role and pinned manifest SHA-256')
    role, expected_manifest = sys.argv[1:]
    if len(expected_manifest) != 64 or any(c not in '0123456789abcdef' for c in expected_manifest):
        raise RuntimeError('invalid pinned manifest hash')
    owner_uid = pwd.getpwnam('wolffrog').pw_uid
    check_dir(Path('/home'))
    for path in (Path('/home/wolffrog'), Path('/home/wolffrog/task06-upload'), SOURCE):
        check_staging_dir(path, owner_uid)
    manifest_data = (SOURCE / 'manifest.json').read_bytes()
    if hashlib.sha256(manifest_data).hexdigest() != expected_manifest:
        raise RuntimeError('bundle manifest hash mismatch')
    manifest = json.loads(manifest_data)
    if manifest.get('schema') != 1 or manifest.get('role') != 'shared' or set(manifest.get('files', {})) != PACKAGE_FILES:
        raise RuntimeError('unexpected bundle manifest')
    payload = {}
    for name in PACKAGE_FILES:
        path = SOURCE / name
        info = path.lstat()
        if (info.st_uid != owner_uid or stat.S_ISLNK(info.st_mode) or
                not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022):
            raise RuntimeError('unsafe package file')
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != manifest['files'][name]:
            raise RuntimeError('bundle file hash mismatch')
        payload[name] = data
    runtime_manifest = {'schema': 1, 'role': role,
                        'build': manifest['build'],
                        'files': {name: manifest['files'][name] for name in RUNTIME_FILES}}
    runtime_manifest_data = (json.dumps(runtime_manifest, sort_keys=True, indent=2) + '\n').encode()

    ensure_dir(Path('/opt'), None)
    ensure_dir(Path('/opt/vpn-task06'), 0o755)
    ensure_dir(Path('/etc'), None)
    ensure_dir(Path('/etc/vpn-task06'), 0o700)
    ensure_dir(Path('/var'), None)
    ensure_dir(Path('/var/lib'), None)
    ensure_dir(Path('/var/lib/vpn-task06'), 0o700)
    ensure_dir(Path('/usr/local'), None)
    ensure_dir(Path('/usr/local/sbin'), None)

    for name in RUNTIME_FILES:
        install_exact(Path('/opt/vpn-task06') / name, payload[name], BASE_MODES[name])
        if name in DESTINATIONS:
            destination, mode = DESTINATIONS[name]
            install_exact(Path(destination), payload[name], mode)
    install_exact(Path('/opt/vpn-task06/manifest.json'), runtime_manifest_data, 0o644)
    install_exact(Path('/etc/vpn-task06/role'), (role + '\n').encode(), 0o644)
    if {p.name for p in Path('/opt/vpn-task06').iterdir()} != set(RUNTIME_FILES) | {'manifest.json'}:
        raise RuntimeError('unexpected object in install directory')
    subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True,
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    print(json.dumps({'installed': True, 'role': role,
                      'manifest_sha256': expected_manifest,
                      'services_activated': False}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('BLOCKED: fixed TASK 06 installation rejected; details withheld')
        sys.exit(1)
