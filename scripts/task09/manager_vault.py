#!/usr/bin/python3
"""Root-only key storage and explicit profile export for TASK 09."""
import os
from pathlib import Path
import stat

from manager_db import Refusal
from manager_runtime import AWG, command
from manager_formats import amnezia_profile

ROOT = Path('/etc/vpn-task09/devices')
EXPORTS = Path('/var/lib/vpn-task09/exports')
LEGACY_KEY = Path('/etc/vpn-task07/client.key')
SERVER_KEY = Path('/etc/vpn-task07/server.key')


def root_file(path, *, enforce_ownership=True):
    path = Path(path)
    st = path.lstat()
    if (not stat.S_ISREG(st.st_mode) or path.is_symlink() or
            (enforce_ownership and (st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o600))):
        raise Refusal('secret_ownership', 'protected file ownership mismatch')
    return path.read_bytes()


def safe_directory(path, *, enforce_ownership=True):
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = path.lstat()
    if (not stat.S_ISDIR(st.st_mode) or path.is_symlink() or
            (enforce_ownership and (st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700))):
        raise Refusal('secret_ownership', 'protected directory ownership mismatch')
    return path


def exclusive_file(path, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(path, 0o600)
    except Exception:
        Path(path).unlink(missing_ok=True)
        raise


class Vault:
    def __init__(self, *, root=ROOT, exports=EXPORTS, enforce_ownership=True,
                 awg_command=command):
        self.root = Path(root)
        self.exports = Path(exports)
        self.enforce_ownership = enforce_ownership
        self.awg_command = awg_command

    def create(self, opaque_id):
        if len(opaque_id) != 32 or any(c not in '0123456789abcdef' for c in opaque_id):
            raise Refusal('invalid_identifier', 'invalid device identifier')
        safe_directory(self.root, enforce_ownership=self.enforce_ownership)
        directory = self.root / opaque_id
        directory.mkdir(mode=0o700)
        key_path = directory / 'private.key'
        try:
            private = self.awg_command([AWG, 'genkey']).encode('ascii') + b'\n'
            if len(private) != 45:
                raise Refusal('key_generation', 'invalid generated key length')
            public = self.awg_command([AWG, 'pubkey'], input_bytes=private).strip()
            exclusive_file(key_path, private)
            return str(key_path), public
        except Exception:
            if key_path.exists():
                key_path.unlink()
            directory.rmdir()
            raise

    def export(self, device, server_key=SERVER_KEY, *, format='conf'):
        if format not in ('conf', 'amnezia'):
            raise Refusal('export_format', 'unsupported export format')
        key_ref = Path(device['key_ref'])
        if device['origin'] == 'task07':
            if key_ref != LEGACY_KEY:
                raise Refusal('legacy_mismatch', 'legacy key path mismatch')
        elif key_ref != self.root / device['id'] / 'private.key':
            raise Refusal('secret_ownership', 'device key path mismatch')
        private = root_file(key_ref, enforce_ownership=self.enforce_ownership).strip()
        derived_public = self.awg_command([AWG, 'pubkey'],
                                          input_bytes=private + b'\n').strip()
        if derived_public != device['public_key']:
            raise Refusal('secret_identity', 'device key does not match registered peer')
        server_private = root_file(server_key, enforce_ownership=self.enforce_ownership)
        server_public = self.awg_command([AWG, 'pubkey'], input_bytes=server_private).strip()
        profile = (
            '[Interface]\n'
            'PrivateKey = ' + private.decode('ascii') + '\n'
            'Address = ' + device['ipv4'] + '/32\n'
            'MTU = 1280\n'
            'DNS = 10.203.253.1\n'
            'Jc = 4\nJmin = 64\nJmax = 256\n'
            'S1 = 32\nS2 = 64\nS3 = 32\nS4 = 32\n'
            'H1 = 176321011-176321111\n'
            'H2 = 276321011-276321111\n'
            'H3 = 376321011-376321111\n'
            'H4 = 476321011-476321111\n\n'
            '[Peer]\n'
            'PublicKey = ' + server_public + '\n'
            'Endpoint = 137.22.146.212:51821\n'
            'AllowedIPs = 0.0.0.0/0, ::/0\n'
            'PersistentKeepalive = 25\n'
        )
        safe_directory(self.exports, enforce_ownership=self.enforce_ownership)
        content = profile.encode('utf-8')
        if format == 'amnezia':
            content = amnezia_profile(content)
        output = self.exports / (device['profile_name'] + ('.vpn' if format == 'amnezia' else '.conf'))
        exclusive_file(output, content)
        return str(output)
