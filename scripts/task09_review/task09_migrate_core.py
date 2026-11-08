#!/usr/bin/env python3
"""TASK09 migration crash-recovery *core* for isolated testing.

This module deliberately does not speak to a live host. A production adapter must
provide durable journal storage, exclusive locks, an nft transaction, and atomic
root-owned file replacement. The contract explicitly detects interruption and
reverses back to the *working TASK08* baseline, not pre-TASK08 configuration.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import json


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class Plan:
    old: dict[str, bytes]
    new: dict[str, bytes]
    original_nft_hash: str
    updated_nft_hash: str
    # A full nft -f batch is generated separately; never flush any interval set.
    forward_batch: bytes
    reverse_batch: bytes

    def fingerprint(self) -> str:
        material = {name: sha(data) for name, data in sorted(self.old.items())}
        material.update({'new/' + name: sha(data) for name, data in sorted(self.new.items())})
        material.update({'old_nft': self.original_nft_hash, 'new_nft': self.updated_nft_hash,
                         'forward_batch': sha(self.forward_batch),
                         'reverse_batch': sha(self.reverse_batch)})
        return sha(json.dumps(material, sort_keys=True).encode())

    def validate(self) -> None:
        required = {'ru.nft', 'apply.py', 'rollback.py', 'vpn-task07'}
        if set(self.old) != required or set(self.new) != required:
            raise ValueError('incomplete migration package')
        if not self.forward_batch or not self.reverse_batch:
            raise ValueError('missing nft batches')
        for batch in (self.forward_batch, self.reverse_batch):
            if any(forbidden in batch for forbidden in (b'flush set', b'delete table', b'flush table')):
                raise ValueError('migration must preserve geofeed nft sets')
        if len(self.original_nft_hash) != 64 or len(self.updated_nft_hash) != 64:
            raise ValueError('missing observed nft snapshot hash')
        if self.original_nft_hash == self.updated_nft_hash:
            raise ValueError('expected distinct nft states')


class MigrationError(RuntimeError):
    pass


class IncompleteRollback(MigrationError):
    pass


class Coordinator:
    """Explicit journaled state machine. Backend operations must be idempotent.

    Safety contract: 'nft_replace' applies the entire batch atomically and
    'observe_nft' returns a stable canonical hash (TASK06 canonicalization).
    A persistent journal must be fsynced before every non-atomic transition.
    Unexpected state is never silently re-baselined.
    """
    def __init__(self, backend):
        self.b = backend

    def _verify_files(self, content):
        for name, expected in content.items():
            if self.b.read_file(name) != expected:
                raise MigrationError('owned file drift: ' + name)

    def _write_files(self, content):
        for name in ('ru.nft', 'apply.py', 'rollback.py', 'vpn-task07'):
            self.b.replace_file(name, content[name])

    def _rollback(self, plan, ledger_before):
        """May itself be interrupted. The journal is retained until verified."""
        self.b.journal_write({'state': 'rolling_back', 'baseline_ledger': ledger_before, 'plan': plan.fingerprint()})
        observed = self.b.observe_nft()
        if observed == plan.updated_nft_hash:
            self.b.nft_replace(plan.reverse_batch)
        elif observed != plan.original_nft_hash:
            raise IncompleteRollback('nft state diverged; manual fail-closed review')
        if self.b.observe_nft() != plan.original_nft_hash:
            raise IncompleteRollback('reverse nft transaction did not restore baseline')
        self._write_files(plan.old)
        self.b.ledger_write(ledger_before)
        self._verify_files(plan.old)
        if self.b.ledger_read() != ledger_before:
            raise IncompleteRollback('ledger baseline mismatch')
        self.b.journal_clear()

    def apply(self, plan):
        plan.validate()
        with self.b.lock_all():
            if self.b.journal_read() is not None:
                raise MigrationError('incomplete previous migration: recover first')
            self._verify_files(plan.old)
            ledger_before = self.b.ledger_read()
            if ledger_before.get('own_table_sha256') != plan.original_nft_hash:
                raise MigrationError('baseline ledger drift')
            if self.b.observe_nft() != plan.original_nft_hash:
                raise MigrationError('runtime nft drift')
            self.b.journal_write({'state': 'prepared', 'baseline_ledger': ledger_before, 'plan': plan.fingerprint()})
            try:
                self.b.nft_replace(plan.forward_batch)
                if self.b.observe_nft() != plan.updated_nft_hash:
                    raise MigrationError('forward nft verification failed')
                # Exact runtime hash is verified before any ownership ledger change.
                self.b.journal_write({'state': 'nft_applied', 'baseline_ledger': ledger_before, 'plan': plan.fingerprint()})
                self._write_files(plan.new)
                self.b.journal_write({'state': 'files_applied', 'baseline_ledger': ledger_before, 'plan': plan.fingerprint()})
                ledger_new = dict(ledger_before)
                ledger_new['own_table_sha256'] = plan.updated_nft_hash
                self.b.ledger_write(ledger_new)
                self._verify_files(plan.new)
                if self.b.ledger_read() != ledger_new or self.b.observe_nft() != plan.updated_nft_hash:
                    raise MigrationError('post-commit ownership mismatch')
                self.b.journal_clear()
            except Exception:
                try:
                    self._rollback(plan, ledger_before)
                except Exception as exc:
                    self.b.fail_closed()
                    raise IncompleteRollback('rollback not verified; forwarding disabled') from exc
                raise

    def recover(self, plan):
        plan.validate()
        with self.b.lock_all():
            record = self.b.journal_read()
            if record is None:
                return False
            if record.get('state') not in {'prepared', 'nft_applied', 'files_applied', 'rolling_back'}:
                self.b.fail_closed()
                raise IncompleteRollback('journal state invalid')
            if record.get('plan') != plan.fingerprint():
                self.b.fail_closed()
                raise IncompleteRollback('migration plan identity mismatch')
            ledger = record.get('baseline_ledger')
            if not isinstance(ledger, dict) or ledger.get('own_table_sha256') != plan.original_nft_hash:
                self.b.fail_closed()
                raise IncompleteRollback('journal baseline invalid')
            try:
                self._rollback(plan, ledger)
            except Exception as exc:
                self.b.fail_closed()
                raise IncompleteRollback('recovery incomplete; forwarding disabled') from exc
            return True
