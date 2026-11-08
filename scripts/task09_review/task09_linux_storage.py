#!/usr/bin/env python3
"""Durable, root-owned file/journal storage for TASK09 migration.

This is a storage primitive, not a deployment command. It deliberately has no
service-manager or firewall policy. The caller must hold the *real* TASK08
prefix-update lock and a separate migration lock for the whole transition.
"""
from __future__ import annotations
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import secrets
import stat

OWNED_MODES = {'ru.nft': 0o644, 'apply.py': 0o644,
               'rollback.py': 0o755, 'vpn-task07': 0o755}


class DurableStorage:
    def __init__(self, root: Path, files: dict[str, Path], *, require_root=True,
                 prefix_lock: Path | None = None):
        if require_root and (not hasattr(os, 'geteuid') or os.geteuid() != 0):
            raise PermissionError('root is required for the Linux storage backend')
        self.root = Path(root)
        if set(files) != set(OWNED_MODES):
            raise ValueError('exactly four owned paths required')
        self.files = {key: Path(value) for key, value in files.items()}
        self.require_root = require_root
        self.ledger = self.root / 'active.json'
        self.journal = self.root / 'task09-migration.json'
        self.lockfile = self.root / 'task09-migration.lock'
        # TASK08 ru-prefix-update.py locks ROOT/ru-prefix-update.lock where
        # ROOT is /var/lib/vpn-task08. Migration state lives elsewhere, so
        # deriving this path from `root` silently failed to serialize updates.
        self.prefix_lock = Path(prefix_lock) if prefix_lock is not None else (
            self.root / 'ru-prefix-update.lock' if not require_root
            else Path('/var/lib/vpn-task08/ru-prefix-update.lock'))

    def _check_dir(self, folder):
        st = folder.lstat()
        if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
            raise ValueError('directory type conflict')
        if self.require_root and (st.st_uid != 0 or st.st_mode & 0o022):
            raise ValueError('directory ownership conflict')

    def _read(self, path, mode):
        self._check_dir(path.parent)
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or stat.S_IMODE(st.st_mode) != mode:
            raise ValueError('file ownership/mode conflict')
        if self.require_root and st.st_uid != 0:
            raise ValueError('non-root-owned file')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            after = os.fstat(fd)
            if (after.st_dev, after.st_ino) != (st.st_dev, st.st_ino):
                raise ValueError('file changed during open')
            with os.fdopen(fd, 'rb', closefd=False) as f:
                return f.read()
        finally:
            os.close(fd)

    def _write(self, path, data, mode):
        if not isinstance(data, bytes):
            raise TypeError('atomic file content must be bytes')
        self._check_dir(path.parent)
        if path.exists() or path.is_symlink():
            self._read(path, mode)
        tmp = path.with_name(path.name + '.task09-' + secrets.token_hex(10))
        fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
        try:
            with os.fdopen(fd, 'wb') as out:
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
            # os.open mode is subject to umask; set the exact intended mode
            # before syncing and publishing the replacement.
            fd_sync = os.open(tmp, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fchmod(fd_sync, mode)
                os.fsync(fd_sync)
            finally:
                os.close(fd_sync)
            os.replace(tmp, path)
            self._fsync_dir(path.parent)
        finally:
            if tmp.exists():
                tmp.unlink()

    @staticmethod
    def _fsync_dir(parent):
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @contextmanager
    def lock_all(self):
        self._check_dir(self.root)
        # Same lock path as TASK08 ru-prefix-update.py. Fixed lock ordering
        # prevents deadlock. LOCK_NB makes an active updater a hard stop.
        fds = []
        try:
            for path in (self.prefix_lock, self.lockfile):
                self._check_dir(path.parent)
                fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
                st = os.fstat(fd)
                allowed_modes = {0o600} if path == self.lockfile else {0o600, 0o644}
                if (not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) not in allowed_modes
                        or (self.require_root and st.st_uid != 0)):
                    raise ValueError('migration lockfile conflict')
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BaseException:
                    os.close(fd)
                    raise
                fds.append(fd)
            yield
        finally:
            for fd in reversed(fds):
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)

    def read_file(self, name):
        return self._read(self.files[name], OWNED_MODES[name])

    def replace_file(self, name, data):
        self._write(self.files[name], data, OWNED_MODES[name])

    def ledger_read(self):
        return json.loads(self._read(self.ledger, 0o600))

    def ledger_write(self, record):
        self._write(self.ledger, (json.dumps(record, sort_keys=True) + '\n').encode(), 0o600)

    def journal_read(self):
        if not self.journal.exists() and not self.journal.is_symlink():
            return None
        return json.loads(self._read(self.journal, 0o600))

    def journal_write(self, record):
        self._write(self.journal, (json.dumps(record, sort_keys=True) + '\n').encode(), 0o600)

    def journal_clear(self):
        if self.journal.exists() or self.journal.is_symlink():
            self._read(self.journal, 0o600)
            self.journal.unlink()
            self._fsync_dir(self.root)
