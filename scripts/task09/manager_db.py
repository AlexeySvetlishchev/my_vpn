#!/usr/bin/python3
"""TASK 09 desired-state SQLite core. No network or secret-file operations."""
from contextlib import contextmanager
from datetime import datetime, timezone
import ipaddress
import os
from pathlib import Path
import sqlite3
import unicodedata
import uuid

NETWORK = ipaddress.ip_network('10.203.253.0/24')
RESERVED = {'10.203.253.0', '10.203.253.1', '10.203.253.2', '10.203.253.255'}
STATES_USER = {'enabled', 'disabled', 'deleted'}
STATES_DEVICE = {'enabled', 'disabled', 'revoked'}


class Refusal(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def identity(value):
    if not isinstance(value, str):
        raise Refusal('invalid_name', 'name must be text')
    display = unicodedata.normalize('NFKC', value)
    if not 1 <= len(display) <= 32 or not display[0].isalpha():
        raise Refusal('invalid_name', 'name must begin with a letter and have 1–32 characters')
    if any(not ch.isalnum() for ch in display):
        raise Refusal('invalid_name', 'name may contain only letters and digits')
    return display, display.casefold()


def check_public_key(value):
    import base64
    if not isinstance(value, str) or len(value) != 44:
        raise Refusal('invalid_public_key', 'invalid AWG public identity')
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error):
        raise Refusal('invalid_public_key', 'invalid AWG public identity') from None
    if len(raw) != 32:
        raise Refusal('invalid_public_key', 'invalid AWG public identity')
    return value


SCHEMA = '''
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, name_key TEXT NOT NULL UNIQUE,
 state TEXT NOT NULL CHECK(state IN ('enabled','disabled','deleted')),
 limit_up_bps INTEGER CHECK(limit_up_bps IS NULL OR limit_up_bps > 0),
 limit_down_bps INTEGER CHECK(limit_down_bps IS NULL OR limit_down_bps > 0),
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
 id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
 name TEXT NOT NULL, name_key TEXT NOT NULL, profile_name TEXT NOT NULL UNIQUE,
 ipv4 TEXT NOT NULL UNIQUE, public_key TEXT NOT NULL UNIQUE,
 key_ref TEXT NOT NULL UNIQUE,
 state TEXT NOT NULL CHECK(state IN ('enabled','disabled','revoked')),
 origin TEXT NOT NULL CHECK(origin IN ('task07','manager')),
 limit_up_bps INTEGER CHECK(limit_up_bps IS NULL OR limit_up_bps > 0),
 limit_down_bps INTEGER CHECK(limit_down_bps IS NULL OR limit_down_bps > 0),
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, revoked_at TEXT,
 UNIQUE(user_id,name_key)
);
CREATE TABLE IF NOT EXISTS operations (
 id TEXT PRIMARY KEY, kind TEXT NOT NULL, target_id TEXT NOT NULL,
 phase TEXT NOT NULL CHECK(phase IN ('planned','applying','done','failed')),
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, error_code TEXT
);
CREATE TABLE IF NOT EXISTS audit_events (
 id INTEGER PRIMARY KEY, at TEXT NOT NULL, actor TEXT NOT NULL,
 action TEXT NOT NULL, target_type TEXT NOT NULL, target_id TEXT NOT NULL,
 result TEXT NOT NULL, operation_id TEXT
);
CREATE INDEX IF NOT EXISTS devices_user_idx ON devices(user_id);
CREATE INDEX IF NOT EXISTS operations_phase_idx ON operations(phase);
'''


class Store:
    def __init__(self, path, *, enforce_ownership=True):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != 'nt' and enforce_ownership:
            st = self.path.parent.lstat()
            if st.st_uid != 0 or (st.st_mode & 0o077):
                raise Refusal('unsafe_storage', 'database directory must be root-only')
            if self.path.exists() or self.path.is_symlink():
                st = self.path.lstat()
                if self.path.is_symlink() or st.st_uid != 0 or (st.st_mode & 0o077):
                    raise Refusal('unsafe_storage', 'database file must be root-only')
            else:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             getattr(os, 'O_NOFOLLOW', 0), 0o600)
                os.close(fd)
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA foreign_keys=ON')
        self.db.execute('PRAGMA busy_timeout=10000')
        self.db.execute('PRAGMA journal_mode=DELETE')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript(SCHEMA)
        with self.write():
            self.db.execute('INSERT OR IGNORE INTO schema_meta VALUES (?,?)', ('version', '1'))
            version = self.db.execute('SELECT value FROM schema_meta WHERE key=?', ('version',)).fetchone()[0]
            if version != '1':
                raise Refusal('schema_version', 'unsupported database schema')
        if os.name != 'nt' and enforce_ownership:
            os.chmod(self.path, 0o600)

    def close(self):
        self.db.close()

    @contextmanager
    def write(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            yield
        except Exception:
            self.db.execute('ROLLBACK')
            raise
        else:
            self.db.execute('COMMIT')

    def user(self, name, *, include_deleted=False):
        _, key = identity(name)
        row = self.db.execute('SELECT * FROM users WHERE name_key=?', (key,)).fetchone()
        if row is None or (row['state'] == 'deleted' and not include_deleted):
            raise Refusal('not_found', 'user not found')
        return dict(row)

    def add_user(self, name, actor='local-root'):
        display, key = identity(name)
        stamp = now()
        try:
            with self.write():
                cur = self.db.execute('INSERT INTO users(name,name_key,state,created_at,updated_at) '
                                      'VALUES (?,?,?,?,?)', (display, key, 'enabled', stamp, stamp))
                uid = cur.lastrowid
                self.audit(actor, 'user.add', 'user', str(uid), 'ok')
        except sqlite3.IntegrityError:
            raise Refusal('name_conflict', 'user name already exists') from None
        return self.user(display)

    def list_users(self):
        return [dict(row) for row in self.db.execute(
            "SELECT * FROM users WHERE state!='deleted' ORDER BY name_key")]

    def device(self, user_name, device_name):
        user = self.user(user_name)
        _, key = identity(device_name)
        row = self.db.execute('SELECT * FROM devices WHERE user_id=? AND name_key=?',
                              (user['id'], key)).fetchone()
        if row is None:
            raise Refusal('not_found', 'device not found')
        return dict(row)

    def list_devices(self, user_name=None):
        if user_name is None:
            rows = self.db.execute('SELECT * FROM devices ORDER BY profile_name')
        else:
            user = self.user(user_name)
            rows = self.db.execute('SELECT * FROM devices WHERE user_id=? ORDER BY name_key',
                                   (user['id'],))
        return [dict(row) for row in rows]

    def next_ip(self):
        used = {row[0] for row in self.db.execute('SELECT ipv4 FROM devices')}
        for value in NETWORK.hosts():
            candidate = str(value)
            if candidate not in RESERVED and candidate not in used:
                return candidate
        raise Refusal('pool_exhausted', 'no free client IPv4 address')

    def add_device(self, user_name, device_name, public_key, key_ref,
                   *, origin='manager', ipv4=None, device_id=None, actor='local-root'):
        user = self.user(user_name)
        if user['state'] != 'enabled':
            raise Refusal('user_disabled', 'user is not enabled')
        display, key = identity(device_name)
        public_key = check_public_key(public_key)
        if origin not in ('task07', 'manager'):
            raise Refusal('invalid_origin', 'invalid device origin')
        profile = user['name'] + '_' + display
        stamp = now()
        did = device_id or uuid.uuid4().hex
        if len(did) != 32 or any(c not in '0123456789abcdef' for c in did):
            raise Refusal('invalid_identifier', 'invalid device identifier')
        try:
            with self.write():
                address = ipv4 or self.next_ip()
                if origin == 'task07':
                    if address != '10.203.253.2' or profile != 'Test_iPhone':
                        raise Refusal('legacy_mismatch', 'legacy identity must remain unchanged')
                elif address in RESERVED:
                    raise Refusal('address_reserved', 'reserved client address')
                if ipaddress.ip_address(address) not in NETWORK:
                    raise Refusal('address_outside_pool', 'client address outside pool')
                self.db.execute('INSERT INTO devices VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                                (did, user['id'], display, key, profile, address,
                                 public_key, str(key_ref), 'enabled', origin,
                                 None, None, stamp, stamp, None))
                self.audit(actor, 'device.add', 'device', did, 'planned')
        except sqlite3.IntegrityError:
            raise Refusal('device_conflict', 'device name, key or address already exists') from None
        return self.device(user_name, device_name)

    def set_device_state(self, user_name, device_name, state, actor='local-root'):
        if state not in STATES_DEVICE:
            raise Refusal('invalid_state', 'invalid device state')
        device = self.device(user_name, device_name)
        if device['state'] == 'revoked' and state != 'revoked':
            raise Refusal('revoked', 'revoked device cannot be re-enabled')
        stamp = now()
        with self.write():
            self.db.execute('UPDATE devices SET state=?,updated_at=?,revoked_at=? WHERE id=?',
                            (state, stamp, stamp if state == 'revoked' else device['revoked_at'],
                             device['id']))
            self.audit(actor, 'device.' + state, 'device', device['id'], 'planned')
        return self.device(user_name, device_name)

    def set_user_state(self, name, state, actor='local-root'):
        if state not in STATES_USER:
            raise Refusal('invalid_state', 'invalid user state')
        user = self.user(name)
        stamp = now()
        with self.write():
            self.db.execute('UPDATE users SET state=?,updated_at=? WHERE id=?',
                            (state, stamp, user['id']))
            if state == 'deleted':
                self.db.execute("UPDATE devices SET state='revoked',updated_at=?,revoked_at=? "
                                "WHERE user_id=? AND state!='revoked'", (stamp, stamp, user['id']))
            self.audit(actor, 'user.' + state, 'user', str(user['id']), 'planned')
        return self.user(name, include_deleted=True)

    def desired_peers(self):
        return {row['public_key']: row['ipv4'] + '/32' for row in self.db.execute(
            "SELECT d.public_key,d.ipv4 FROM devices d JOIN users u ON u.id=d.user_id "
            "WHERE d.state='enabled' AND u.state='enabled'")}

    def set_limit(self, kind, user_name, device_name, up_bps, down_bps,
                  actor='local-root'):
        for value in (up_bps, down_bps):
            if value is not None and (not isinstance(value, int) or value < 1_000 or
                                      value > 10_000_000_000):
                raise Refusal('invalid_limit', 'limit must be 1000–10000000000 bps')
        if kind == 'user':
            row = self.user(user_name)
            table, target = 'users', row['id']
        elif kind == 'device':
            row = self.device(user_name, device_name)
            table, target = 'devices', row['id']
        else:
            raise Refusal('invalid_limit', 'invalid limit target')
        with self.write():
            self.db.execute('UPDATE ' + table +
                            ' SET limit_up_bps=?,limit_down_bps=?,updated_at=? WHERE id=?',
                            (up_bps, down_bps, now(), target))
            self.audit(actor, kind + '.limit', kind, str(target), 'stored_unenforced')
        return {'limit_up_bps': up_bps, 'limit_down_bps': down_bps,
                'enforced': False}

    def effective_limits(self, device_id):
        row = self.db.execute('SELECT d.limit_up_bps AS device_up, '
                              'd.limit_down_bps AS device_down, '
                              'u.limit_up_bps AS user_up, u.limit_down_bps AS user_down '
                              'FROM devices d JOIN users u ON u.id=d.user_id WHERE d.id=?',
                              (device_id,)).fetchone()
        if row is None:
            raise Refusal('not_found', 'device not found')
        def effective(a, b):
            options = [value for value in (a, b) if value is not None]
            return min(options) if options else None
        return {'up_bps': effective(row['device_up'], row['user_up']),
                'down_bps': effective(row['device_down'], row['user_down']),
                'enforced': False}

    def all_known_peers(self):
        return {row['public_key'] for row in self.db.execute('SELECT public_key FROM devices')}

    def operation(self, kind, target_id):
        opid = uuid.uuid4().hex
        stamp = now()
        with self.write():
            self.db.execute('INSERT INTO operations VALUES (?,?,?,?,?,?,?)',
                            (opid, kind, str(target_id), 'planned', stamp, stamp, None))
        return opid

    def operation_phase(self, opid, phase, error_code=None):
        if phase not in ('planned', 'applying', 'done', 'failed'):
            raise Refusal('invalid_state', 'invalid operation phase')
        with self.write():
            self.db.execute('UPDATE operations SET phase=?,updated_at=?,error_code=? WHERE id=?',
                            (phase, now(), error_code, opid))

    def pending_operations(self):
        return [dict(row) for row in self.db.execute(
            "SELECT * FROM operations WHERE phase!='done' ORDER BY created_at")]

    def audit(self, actor, action, target_type, target_id, result, operation_id=None):
        self.db.execute('INSERT INTO audit_events(at,actor,action,target_type,target_id,result,operation_id) '
                        'VALUES (?,?,?,?,?,?,?)',
                        (now(), actor, action, target_type, str(target_id), result, operation_id))

    def integrity_check(self):
        return self.db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
