"""Opt-in real-kernel nft test; run only inside a disposable isolated netns.

Example: docker run --rm --cap-add=NET_ADMIN -v <repo>:/repo -w
 /repo/scripts/task09_review <prepared-image> python3 test_real_nft_transaction.py
The test never targets the caller's root namespace by itself; the launcher must
provide a disposable container/network namespace. Missing capability is a skip.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
from task09_nft_plan import (owned_hash, plan, reverse_from_live, owned,
                             validate_transition_delta)  # noqa:E402


def nft(*args, data=None, check=True):
    p = subprocess.run(['/usr/sbin/nft', *args], input=data,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and p.returncode:
        raise RuntimeError(f'nft command failed ({p.returncode})')
    return p


class RealNftTransaction(unittest.TestCase):
    def test_apply_and_fresh_handle_reverse_preserve_dynamic_sets(self):
        # The test uses TASK08's real table name, so fail closed unless both
        # an explicit opt-in and Docker's isolation marker are present.
        if os.environ.get('TASK09_ISOLATED_NFT') != '1' or not Path('/.dockerenv').exists():
            self.skipTest('requires explicit disposable Docker network namespace')
        if not Path('/usr/sbin/nft').exists():
            self.skipTest('nft executable unavailable')
        cleanup = b'delete table ip vpn_task08_ru\n'
        nft('-f', '-', data=cleanup, check=False)
        baseline_source = HERE/'fixtures'/'ru.nft'
        target_source = HERE/'staged-task09'/'ru.nft'
        try:
            applied = nft('-f', '-', data=baseline_source.read_bytes(), check=False)
            if applied.returncode:
                self.skipTest('kernel nft permission or feature unavailable')
            # Emulate the geofeed and force-egress sets having live members
            # beyond the source's initial sample; migration must preserve them.
            nft('-f', '-', data=(b'add element ip vpn_task08_ru ru_set { 77.88.55.242 }\n'
                                 b'add element ip vpn_task08_ru force_egress { 203.0.113.9 }\n'))
            before, before_handles = self.snapshot()
            initial_set_data = self.set_data(before)
            ledger = {'schema':1,'role':'ru','phase':'active',
                      'own_table_sha256':owned_hash(before)}
            forward = plan(baseline_source, target_source, before,
                           before_handles, ledger).encode('ascii')
            nft('-c', '-f', '-', data=forward)
            nft('-f', '-', data=forward)
            after, after_handles = self.snapshot()
            validate_transition_delta({'nftables':owned(before)},after,
                                      baseline_source,target_source)
            post_ledger = {'schema':1,'role':'ru','phase':'active',
                           'own_table_sha256':owned_hash(after)}
            reverse = reverse_from_live(baseline_source, target_source,
                                        after, after_handles, post_ledger).encode('ascii')
            nft('-c', '-f', '-', data=reverse)
            nft('-f', '-', data=reverse)
            restored, _ = self.snapshot()
            self.assertEqual(owned_hash(restored), ledger['own_table_sha256'])
            self.assertEqual(self.set_data(restored), initial_set_data)
        finally:
            nft('-f', '-', data=cleanup, check=False)

    @staticmethod
    def snapshot():
        data = json.loads(nft('-j','-a','list','ruleset').stdout)
        plain = json.loads(json.dumps(data))
        return plain, data

    @staticmethod
    def set_data(snapshot):
        return [item['set'] for item in owned(snapshot)
                if 'set' in item and item['set'].get('name') in {'ru_set','force_egress'}]


if __name__ == '__main__':
    unittest.main()
