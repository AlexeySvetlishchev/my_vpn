#!/usr/bin/env python3
"""Offline-tested TASK09 migration coordinator with live-derived nft hashes/handles.

No host command interface is provided here. An explicitly reviewed Linux adapter
must implement this interface before any operational use. Never execute on VPS.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from task09_nft_plan import (plan as nft_forward, reverse_from_live, owned_hash,
                             owned, validate_transition_delta)
from task09_integrity import validate as validate_package

NAMES = ('ru.nft', 'apply.py', 'rollback.py', 'vpn-task07')


class TransitionError(RuntimeError):
    pass


class RecoveryRequired(TransitionError):
    pass


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class Package:
    old: dict[str, bytes]
    new: dict[str, bytes]

    def validate(self):
        if set(self.old) != set(NAMES) or set(self.new) != set(NAMES):
            raise TransitionError('incomplete package')
        if self.old['ru.nft'] == self.new['ru.nft']:
            raise TransitionError('no nft source transition')

    def fingerprint(self):
        return _sha(json.dumps({prefix + '/' + name: _sha(content)
                   for prefix, files in (('old', self.old), ('new', self.new))
                   for name, content in sorted(files.items())}, sort_keys=True).encode())


class Transition:
    """Backend exposes DurableStorage methods plus nft_snapshot/apply_batch/fail_closed.

    nft_snapshot() -> (plain_nft_json, nft_handles_json); capture must be coherent.
    apply_batch(bytes) must validate/commit one nftables atomic transaction.
    The backend must lock out timers and protect fail-closed during intermediate
    inconsistent file/ledger state; this coordinator alone cannot do so.
    """
    def __init__(self, backend):
        self.b = backend

    def _state(self):
        plain, handles = self.b.nft_snapshot()
        return plain, handles, owned_hash(plain)

    def _files_match(self, expected):
        return all(self.b.read_file(n) == expected[n] for n in NAMES)

    def _restore_files(self, p):
        for n in NAMES:
            actual = self.b.read_file(n)
            if actual not in (p.old[n],p.new[n]):
                raise TransitionError('refusing to overwrite external file drift: '+n)
            if actual != p.old[n]:
                self.b.replace_file(n, p.old[n])

    def _rollback_locked(self, p, record):
        self.b.journal_write({**record, 'state': 'rolling_back'})
        try:
            plain, handles, actual_hash = self._state()
            original = record['original_nft_hash']
            if actual_hash != original:
                baseline_nft = record.get('baseline_nft')
                if not isinstance(baseline_nft, dict):
                    raise TransitionError('journal lacks exact owned nft baseline')
                validate_transition_delta(baseline_nft, plain,
                                          self._source(p.old['ru.nft']),
                                          self._source(p.new['ru.nft']))
                # The newly generated reverse uses current handles and is pinned
                # against the current, *observed* owned subset, not old handles.
                # It must recognize exact post-migration rule count and ownership.
                post_ledger = dict(record['baseline_ledger'])
                post_ledger['own_table_sha256'] = actual_hash
                reverse = reverse_from_live(self._source(p.old['ru.nft']), self._source(p.new['ru.nft']),
                                            plain, handles, post_ledger)
                self.b.apply_batch(reverse.encode('ascii'))
                if self._state()[2] != original:
                    raise TransitionError('restored nft hash mismatched baseline')
            self._restore_files(p)
            self.b.ledger_write(record['baseline_ledger'])
            if not self._files_match(p.old) or self.b.ledger_read() != record['baseline_ledger']:
                raise TransitionError('restored package or ledger mismatch')
            self.b.journal_clear()
        except Exception as exc:
            self.b.fail_closed()
            raise RecoveryRequired('automatic recovery incomplete; fail-closed required') from exc

    def _source(self, content):
        """Use an existing concrete source path, no untrusted temporary interpolation."""
        return self.b.source_path(content)

    def apply(self, p: Package):
        p.validate()
        validate_package(p.old, p.new)
        with self.b.lock_all():
            try:
                pending = self.b.journal_read()
            except Exception as exc:
                self.b.fail_closed()
                raise RecoveryRequired('migration journal unreadable') from exc
            if pending is not None:
                self.b.fail_closed()
                raise RecoveryRequired('previous migration journal exists')
            if not self._files_match(p.old):
                raise TransitionError('baseline file drift')
            ledger = self.b.ledger_read()
            if not isinstance(ledger, dict):
                raise TransitionError('TASK08 active ledger malformed')
            plain, handles, old_hash = self._state()
            if ledger.get('own_table_sha256') != old_hash:
                raise TransitionError('TASK08 active ledger drift')
            batch = nft_forward(self._source(p.old['ru.nft']), self._source(p.new['ru.nft']),
                                plain, handles, ledger).encode('ascii')
            record = {'schema': 1, 'state': 'prepared', 'fingerprint': p.fingerprint(),
                      'baseline_ledger': ledger, 'original_nft_hash': old_hash,
                      'baseline_nft': {'nftables': owned(plain)}}
            self.b.journal_write(record)
            try:
                self.b.apply_batch(batch)
                plain, handles, new_hash = self._state()
                if new_hash == old_hash:
                    raise TransitionError('nft was not changed')
                prospective = dict(ledger)
                prospective['own_table_sha256'] = new_hash
                validate_transition_delta(record['baseline_nft'], plain,
                                          self._source(p.old['ru.nft']),
                                          self._source(p.new['ru.nft']))
                # Check that the post-migration layout is exactly reverse-plannable
                # before files/ledger are committed.
                reverse_from_live(self._source(p.old['ru.nft']), self._source(p.new['ru.nft']),
                                  plain, handles, prospective)
                self.b.journal_write({**record, 'state': 'nft_applied'})
                for n in NAMES:
                    self.b.replace_file(n, p.new[n])
                self.b.journal_write({**record, 'state': 'files_applied'})
                self.b.ledger_write(prospective)
                if not self._files_match(p.new) or self.b.ledger_read() != prospective or self._state()[2] != new_hash:
                    raise TransitionError('post transition verification failed')
                self.b.journal_clear()
                return {'nft_sha256': new_hash, 'installed': True}
            except BaseException:
                # Ordinary errors: attempt addressed rollback. A process crash or
                # power loss still requires explicit recover() invocation at boot.
                self._rollback_locked(p, record)
                raise

    def recover(self, p: Package):
        with self.b.lock_all():
            try:
                record = self.b.journal_read()
            except Exception as exc:
                self.b.fail_closed()
                raise RecoveryRequired('migration journal unreadable') from exc
            if record is None:
                return False
            try:
                p.validate()
                validate_package(p.old, p.new)
            except Exception as exc:
                self.b.fail_closed()
                raise RecoveryRequired('recovery package validation failed') from exc
            if (not isinstance(record, dict) or record.get('schema') != 1
                    or record.get('fingerprint') != p.fingerprint()
                    or record.get('state') not in {'prepared', 'nft_applied', 'files_applied', 'rolling_back'}
                    or not isinstance(record.get('baseline_ledger'), dict)
                    or not isinstance(record.get('baseline_nft'), dict)
                    or record['baseline_ledger'].get('own_table_sha256') != record.get('original_nft_hash')
                    or owned_hash(record['baseline_nft']) != record.get('original_nft_hash')):
                self.b.fail_closed()
                raise RecoveryRequired('journal identity or baseline invalid')
            self._rollback_locked(p, record)
            return True
