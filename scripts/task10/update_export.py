#!/usr/bin/python3
"""Narrow export-only update; no VPN, peer, database or network mutation.

Backup/restore covers only public Python modules and the TASK10 manifest.
Polling state is never reverted. Starts/stops only TASK10 bot and broker.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

ROOT = Path('/opt')
BACKUPS = Path('/var/backups/vpn-task10')
BOT_FILES = ('bot.py', 'broker.py', 'telegram_api.py')
MANAGER_FILES = ('manager_formats.py', 'manager_vault.py', 'vpnctl.py')
BASELINE = {
    'task09/manager_formats.py': None,
    'task09/manager_vault.py': '4169ac8e0780ab266a4c31df7e573a5c780beeb50fbd2ca21ab26f117aebc45d',
    'task09/vpnctl.py': '6cbff7fd5d9b30453c17b549d3f12a24d625cbcbc37f2389a89d0f064ce49939',
    'task10/bot.py': '1656121ba89dba89ab720eed9ab81aa1573d6b8bfc4cf7b1535ddf171efe5de3',
    'task10/broker.py': '72f1cdb3ce61ac4c5cb114ee59837b5d195cdef902288785daf65f5116db5da0',
    'task10/telegram_api.py': '53f5ca2ee75a0d7aa5e41a4709e09a231b0c3d16bb0eb6d9dacf6568e3c15bbf',
}
BOT = 'vpn-task10-bot.service'
BROKER = 'vpn-task10-broker.service'
KEEP_UNITS = ('vpn-task06-awg.service', 'vpn-task07-client.service', 'vpn-task10-egress.service')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(argv):
    return subprocess.check_output(argv, stderr=subprocess.DEVNULL, timeout=60)


def system(*args):
    return run(['/usr/bin/systemctl', *args])


def publish(path, data, mode):
    tmp = path.with_name(path.name + '.export-new')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(data)
            os.fchmod(out.fileno(), mode)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        tmp.unlink(missing_ok=True)


def target(name):
    task, filename = name.split('/')
    return ROOT/('vpn-' + task)/filename


def public_file(path):
    s = path.lstat()
    assert stat.S_ISREG(s.st_mode) and s.st_uid == 0 and stat.S_IMODE(s.st_mode) == 0o644
    return path.read_bytes()


def health():
    data = json.loads(run(['/usr/local/sbin/vpnctl', '--json', 'diagnostics']))['data']
    assert (not any(data['peer_drift'].values()) and all(data['services'].values())
            and not data['incomplete_operations'])


def peers():
    return run(['/opt/vpn-task07/awg', 'show', 'awg-client', 'allowed-ips'])


def unchanged_snapshot():
    return {
        'processes': {u: system('show', u, '-p', 'MainPID', '--value') for u in KEEP_UNITS},
        'default_routes': run(['/usr/sbin/ip', '-4', 'route', 'show', 'default']),
        'active_ledger': Path('/var/lib/vpn-task08/active.json').read_bytes(),
        'task07_helper': Path('/usr/local/sbin/vpn-task07').read_bytes(),
    }


def start():
    system('start', BROKER)
    system('start', BOT)
    for _ in range(40):
        pid = system('show', BOT, '-p', 'MainPID', '--value').strip()
        if pid not in (b'', b'0'):
            logs = run(['/usr/bin/journalctl', '-b', '-u', BOT, '_PID='+pid.decode(), '-o', 'cat', '--no-pager'])
            if b'telegram_connected' in logs:
                return
        time.sleep(.5)
    raise RuntimeError('telegram_start_not_confirmed')


def restore(backup):
    saved = json.loads((backup/'baseline.json').read_text())
    # Refuse a stale rollback after another export update.
    for name, record in saved.items():
        assert sha(target(name).read_bytes()) == record['installed']
    system('stop', BOT)
    system('stop', BROKER)
    sys.path.insert(0, '/opt/vpn-task09')
    from manager_lock import process_lock
    with process_lock():
        for name, record in saved.items():
            path = target(name)
            if record['before'] is None:
                path.unlink()
            else:
                content = (backup/name.replace('/', '--')).read_bytes()
                assert sha(content) == record['before']
                publish(path, content, 0o644)
    start()
    health()


def main():
    assert os.geteuid() == 0
    if len(sys.argv) == 3 and sys.argv[1] == '--rollback':
        backup = Path(sys.argv[2]).resolve()
        assert backup.parent == BACKUPS and backup.name.startswith('export-')
        restore(backup)
        print('{"export_rollback":true}')
        return
    assert len(sys.argv) == 1
    src = Path(__file__).resolve().parent.parent
    delivery = json.loads((src/'export-sha256.json').read_text())
    assert set(delivery) == set(BASELINE) | {'task10/manifest.json'}
    old_manifest = json.loads(public_file(target('task10/manifest.json')))
    new_manifest = json.loads((src/'task10/manifest.json').read_text())
    assert old_manifest.keys() == new_manifest.keys()
    assert all(old_manifest[k] == new_manifest[k] for k in old_manifest if k not in BOT_FILES)
    saved, new_bytes, previous = {}, {}, {}
    for name, digest in delivery.items():
        content = (src/name).read_bytes()
        assert sha(content) == digest
        if name.endswith('.py'):
            compile(content, name, 'exec')
        new_bytes[name] = content
        path = target(name)
        before = public_file(path) if path.exists() else None
        if name in BASELINE:
            assert (sha(before) if before is not None else None) == BASELINE[name], 'unexpected_baseline'
        previous[name] = before
        saved[name] = {'before': sha(before) if before is not None else None, 'installed': digest}
    for name in BOT_FILES:
        assert sha(previous['task10/'+name]) == old_manifest[name]
        assert delivery['task10/'+name] == new_manifest[name]
    health()
    before_peers, before_state = peers(), unchanged_snapshot()
    backup = BACKUPS/('export-'+time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()))
    backup.mkdir(mode=0o700)
    for name, content in previous.items():
        if content is not None:
            publish(backup/name.replace('/', '--'), content, 0o600)
    publish(backup/'baseline.json', (json.dumps(saved, sort_keys=True)+'\n').encode(), 0o600)
    # Never restore polling offsets or a database: no peer/profile writes occur.
    sys.path.insert(0, '/opt/vpn-task09')
    from manager_lock import process_lock
    stopped = False
    try:
        system('stop', BOT)
        system('stop', BROKER)
        stopped = True
        with process_lock():
            for name, content in new_bytes.items():
                publish(target(name), content, 0o644)
        start()
        health()
        assert peers() == before_peers and unchanged_snapshot() == before_state, 'unrelated_state_changed'
        for name, digest in delivery.items():
            assert sha(public_file(target(name))) == digest
        print(json.dumps({'export_updated': True, 'telegram_connected': True,
                          'live_peers_unchanged': True, 'vpn_and_network_unchanged': True,
                          'backup': str(backup)}))
    except BaseException:
        if stopped:
            system('stop', BOT)
            system('stop', BROKER)
            with process_lock():
                for name, content in previous.items():
                    if content is None:
                        target(name).unlink(missing_ok=True)
                    else:
                        publish(target(name), content, 0o644)
            start()
            health()
            assert peers() == before_peers
        raise


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'export_update': False, 'category': type(exc).__name__}))
        raise SystemExit(1)
