#!/usr/bin/env python3
"""Linux migration backend restricted to an explicitly named netns.

There is intentionally no root-namespace mode or CLI. This composes the
durable storage and real nft command adapter for isolated integration tests.
Production activation/recovery wiring remains a separate reviewed step.
"""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

from task09_linux_nft import NamespaceNft
from task09_linux_storage import DurableStorage


class LinuxMigrationBackend:
    def __init__(self, namespace: str, storage: DurableStorage,
                 source_dir: Path, *, fail_closed):
        if not callable(fail_closed):
            raise ValueError('explicit fail-closed action required')
        self.nft = NamespaceNft(namespace)
        self.storage = storage
        self.source_dir = Path(source_dir)
        self._fail_closed = fail_closed

    def source_path(self, content: bytes) -> Path:
        """Resolve only one of the two pinned ru.nft sources, by exact bytes."""
        found = []
        for candidate in (self.source_dir / 'ru.nft', self.source_dir / 'ru-new.nft'):
            if candidate.is_symlink() or not candidate.is_file():
                continue
            raw = candidate.read_bytes()
            if raw == content:
                found.append(candidate)
        if len(found) != 1:
            raise ValueError('source content is absent or ambiguous')
        return found[0]

    def nft_snapshot(self): return self.nft.nft_snapshot()
    def apply_batch(self, script): return self.nft.apply_batch(script)
    def read_file(self, name): return self.storage.read_file(name)
    def replace_file(self, name, data): return self.storage.replace_file(name, data)
    def ledger_read(self): return self.storage.ledger_read()
    def ledger_write(self, data): return self.storage.ledger_write(data)
    def journal_read(self): return self.storage.journal_read()
    def journal_write(self, data): return self.storage.journal_write(data)
    def journal_clear(self): return self.storage.journal_clear()
    def fail_closed(self): return self._fail_closed()

    @contextmanager
    def lock_all(self):
        with self.storage.lock_all():
            yield
