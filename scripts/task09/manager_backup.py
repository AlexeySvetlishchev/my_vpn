#!/usr/bin/python3
"""Root-only local backup and integrity preflight; no live restore side effects."""
from datetime import datetime, timezone
from contextlib import closing
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tarfile
import tempfile

from manager_db import Refusal, check_public_key
from manager_vault import root_file, safe_directory, exclusive_file

BACKUPS = Path('/var/lib/vpn-task09/backups')
LEGACY = Path('/etc/vpn-task07')
DEVICE_KEYS = Path('/etc/vpn-task09/devices')
MAX_ARCHIVE = 100 * 1024 * 1024
RESTORE_STAGE = Path('/var/lib/vpn-task09/restore-stage')


def entries(store, *, legacy=LEGACY, device_keys=DEVICE_KEYS,
            enforce_ownership=True):
    result = {}
    for name in ('server.key', 'client.key', 'client.pub', 'Test_iPhone.conf'):
        result['legacy/' + name] = root_file(legacy / name,
                                             enforce_ownership=enforce_ownership)
    for device in store.list_devices():
        if device['origin'] == 'task07':
            if Path(device['key_ref']) != legacy / 'client.key':
                raise Refusal('backup_conflict', 'legacy key reference mismatch')
            continue
        expected = device_keys / device['id'] / 'private.key'
        if Path(device['key_ref']) != expected:
            raise Refusal('backup_conflict', 'device key reference mismatch')
        result['devices/' + device['id'] + '/private.key'] = root_file(
            expected, enforce_ownership=enforce_ownership)
    return result


def add_bytes(archive, name, data):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o600
    info.uid = info.gid = 0
    info.mtime = 0
    archive.addfile(info, io.BytesIO(data))


def make_backup(store, *, destination=BACKUPS, legacy=LEGACY,
                device_keys=DEVICE_KEYS, enforce_ownership=True):
    destination = safe_directory(destination, enforce_ownership=enforce_ownership)
    with tempfile.TemporaryDirectory(prefix='.task09-', dir=destination) as stage:
        snapshot = Path(stage) / 'manager.sqlite3'
        with closing(sqlite3.connect(snapshot)) as target:
            store.db.backup(target)
        if os.name != 'nt':
            os.chmod(snapshot, 0o600)
        with closing(sqlite3.connect(snapshot)) as check:
            if check.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise Refusal('backup_integrity', 'SQLite snapshot integrity failed')
        files = {'manager.sqlite3': snapshot.read_bytes()}
        files.update(entries(store, legacy=legacy, device_keys=device_keys,
                             enforce_ownership=enforce_ownership))
        manifest = {'schema': 1, 'files': {
            name: {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
            for name, data in sorted(files.items())}}
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        nonce = os.urandom(6).hex()
        output = destination / ('vpn-task09-' + stamp + '-' + nonce + '.tar')
        temp = output.with_suffix('.tar.new')
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            with os.fdopen(fd, 'wb') as stream:
                with tarfile.open(fileobj=stream, mode='w') as archive:
                    for name, data in sorted(files.items()):
                        add_bytes(archive, name, data)
                    add_bytes(archive, 'manifest.json',
                              (json.dumps(manifest, sort_keys=True) + '\n').encode())
                stream.flush()
                os.fsync(stream.fileno())
            if temp.stat().st_size > MAX_ARCHIVE:
                raise Refusal('backup_size', 'backup exceeds fixed size limit')
            check_backup(temp)
            os.replace(temp, output)
            return {'path': str(output), 'sha256': hashlib.sha256(output.read_bytes()).hexdigest(),
                    'bytes': output.stat().st_size, 'encrypted': False}
        finally:
            temp.unlink(missing_ok=True)


def check_backup(path):
    path = Path(path)
    if path.stat().st_size > MAX_ARCHIVE:
        raise Refusal('backup_size', 'backup exceeds fixed size limit')
    with tarfile.open(path, mode='r:') as archive:
        members = archive.getmembers()
        names = [item.name for item in members]
        allowed = {'manager.sqlite3', 'manifest.json',
                   'legacy/server.key', 'legacy/client.key', 'legacy/client.pub',
                   'legacy/Test_iPhone.conf'}
        if (len(names) != len(set(names)) or not allowed.issubset(set(names)) or
                any(not item.isfile() or item.size > 50 * 1024 * 1024 or
                    item.name.startswith('/') or '..' in Path(item.name).parts or
                    item.mode != 0o600 for item in members)):
            raise Refusal('backup_format', 'backup member list invalid')
        if any(name not in allowed and not re.fullmatch(
                r'devices/[0-9a-f]{32}/private\.key', name) for name in names):
            raise Refusal('backup_format', 'unexpected backup member')
        raw = archive.extractfile('manifest.json').read()
        manifest = json.loads(raw)
        if manifest.get('schema') != 1 or set(manifest.get('files', {})) != set(names) - {'manifest.json'}:
            raise Refusal('backup_manifest', 'backup manifest mismatch')
        if any(len(archive.extractfile(name).read()) != archive.getmember(name).size
               for name in names):
            raise Refusal('backup_format', 'backup member is truncated')
        for name, record in manifest['files'].items():
            data = archive.extractfile(name).read()
            if record != {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}:
                raise Refusal('backup_integrity', 'backup content hash mismatch')
        database = archive.extractfile('manager.sqlite3').read()
        legacy_public = archive.extractfile('legacy/client.pub').read().decode('ascii').strip()
    with tempfile.TemporaryDirectory(prefix='task09-verify-') as temp:
        copy = Path(temp) / 'manager.sqlite3'
        copy.write_bytes(database)
        with closing(sqlite3.connect('file:' + str(copy) + '?mode=ro', uri=True)) as check:
            if check.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise Refusal('backup_integrity', 'backup SQLite integrity failed')
            old = check.execute("SELECT public_key,ipv4,key_ref FROM devices "
                                "WHERE origin='task07' AND profile_name='Test_iPhone'").fetchall()
            if (len(old) != 1 or old[0][0] != check_public_key(legacy_public) or
                    old[0][1] != '10.203.253.2' or
                    Path(old[0][2]).name != 'client.key'):
                raise Refusal('backup_identity', 'legacy backup identity mismatch')
            expected = {'manager.sqlite3', 'manifest.json',
                        'legacy/server.key', 'legacy/client.key',
                        'legacy/client.pub', 'legacy/Test_iPhone.conf'}
            for device_id, key_ref in check.execute(
                    "SELECT id,key_ref FROM devices WHERE origin='manager'"):
                name = 'devices/' + device_id + '/private.key'
                if (not re.fullmatch(r'[0-9a-f]{32}', device_id) or
                        Path(key_ref).name != 'private.key' or
                        Path(key_ref).parent.name != device_id):
                    raise Refusal('backup_identity', 'device key reference mismatch')
                expected.add(name)
            if set(names) != expected:
                raise Refusal('backup_identity', 'device backup files mismatch')
    return {'valid': True, 'files': len(manifest['files']),
            'bytes': path.stat().st_size, 'encrypted': False}


def stage_restore(path, *, destination=RESTORE_STAGE, enforce_ownership=True):
    """Extract only to a new protected staging directory, never replace live state."""
    checked = check_backup(path)
    destination = safe_directory(destination, enforce_ownership=enforce_ownership)
    target = destination / ('restore-' + os.urandom(8).hex())
    target.mkdir(mode=0o700)
    try:
        with tarfile.open(path, mode='r:') as archive:
            for member in archive.getmembers():
                output = target / member.name
                output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                exclusive_file(output, archive.extractfile(member).read())
        return {'staged_path': str(target), 'files': checked['files'],
                'live_state_changed': False}
    except Exception:
        # Staging is intentionally retained root-only for inspection after failure.
        raise
