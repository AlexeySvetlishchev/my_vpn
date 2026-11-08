#!/usr/bin/env python3
"""Linux nft adapter *restricted to an explicitly named network namespace*.

This module has NO deployment CLI and cannot operate on the root namespace.
TASK09 production coordination, reboot recovery, systemd scheduling and semantic
nft-expression validation have NOT been implemented or verified here.
"""
from __future__ import annotations

import copy
import json
import subprocess

from task09_nft_plan import owned


class NamespaceNft:
    def __init__(self, namespace: str, *, runner=None):
        if (not isinstance(namespace, str) or not namespace or len(namespace) > 48 or
                not all(c.isascii() and (c.isalnum() or c in '_-') for c in namespace)):
            raise ValueError('explicit safe network namespace name required')
        self.namespace = namespace
        self.runner = runner or subprocess.run

    def _run(self, *args, data=None):
        command = ['/usr/sbin/ip', 'netns', 'exec', self.namespace, '/usr/sbin/nft', *args]
        result = self.runner(command, input=data, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, timeout=30, check=False)
        if result.returncode:
            raise RuntimeError('namespace nft operation failed')
        if len(result.stdout) > 32 * 1024 * 1024:
            raise RuntimeError('nft output bound exceeded')
        return result.stdout

    def nft_snapshot(self):
        # A single `-a` capture yields metadata plus handles at one observation
        # point; remove handle fields only on the owned TASK08 objects before
        # calculating the canonical TASK06 hash.
        with_handles = json.loads(self._run('-j', '-a', 'list', 'ruleset'))
        # TASK08 hashes raw nft JSON, whose handles are present even without
        # -a on the deployed nft version. Do not change its ownership format.
        return copy.deepcopy(with_handles), with_handles

    def apply_batch(self, script: bytes):
        if not isinstance(script, bytes) or not script or len(script) > 1024 * 1024:
            raise ValueError('bounded nft batch required')
        for forbidden in (b'flush table', b'delete table', b'flush set'):
            if forbidden in script.lower():
                raise ValueError('destructive table/set operation disallowed')
        self._run('-c', '-f', '-', data=script)
        self._run('-f', '-', data=script)
