#!/usr/bin/env python3
"""Offline only: produce a pinned, internally consistent TASK08/TASK09 source package.

Not a server installer. No SSH, nft calls, root access or live modifications.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re

OLD_RU_SHA = '4cc76368089640e048bf414267c22146304d3f0330387632883f3e217ab5460a'
OLD_HELPER_PIN = 'd2370830e7cc9228127d019d9dc53036a5dacb37320627328228fee58395a141'
CLIENT = '10.203.253.2'
SUBNET = '10.203.253.0/24'
FILES = ('ru.nft', 'apply.py', 'rollback.py', 'helper.py')


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def replace_exact(data: bytes, old: bytes, new: bytes, count: int) -> bytes:
    found = data.count(old)
    if found != count:
        raise ValueError(f'expected {count} occurrences of {old!r}, got {found}')
    return data.replace(old, new)


def build(src: Path) -> dict[str, bytes]:
    inputs = {n: (src/n).read_bytes() for n in FILES}
    if sha(inputs['ru.nft']) != OLD_RU_SHA:
        raise ValueError('ru.nft baseline SHA mismatch')
    # Update only the six specified TASK08 client source matches; not the server's
    # address 10.203.253.1 or the interserver subnet.
    nft = replace_exact(inputs['ru.nft'], CLIENT.encode(), SUBNET.encode(), 6)
    if nft.count(SUBNET.encode()) != 6:
        raise ValueError('unexpected subnet replacement count')
    # A client must not impersonate the server, network or broadcast address.
    # Insert at the beginning of prerouting BEFORE the broad /24 source match.
    first = (b'add rule ip vpn_task08_ru prerouting iifname "awg-client" '
             b'ip saddr != ' + SUBNET.encode() + b' drop comment "vpn-task08-owned"\n')
    if nft.count(first) != 1:
        raise ValueError('expected exactly one client source guard')
    reserved = (b'add rule ip vpn_task08_ru prerouting iifname "awg-client" '
                b'ip saddr { 10.203.253.0, 10.203.253.1, 10.203.253.255 } '
                b'drop comment "vpn-task08-owned"\n')
    nft = nft.replace(first, reserved + first, 1)
    old_apply = inputs['apply.py']
    new_apply = replace_exact(old_apply, OLD_RU_SHA.encode(), sha(nft).encode(), 1)
    new_helper = inputs['helper.py']
    if b'def startup_peers(' not in new_helper or b'MANAGER_ACTIVATION' not in new_helper:
        raise ValueError('helper is not SQLite-aware')
    old_rb = inputs['rollback.py']
    new_rb = replace_exact(old_rb, ("TASK07_NEW = '"+OLD_HELPER_PIN+"'").encode(),
                           ("TASK07_NEW = '"+sha(new_helper)+"'").encode(), 1)
    # Check the prepared rollback still verifies the legacy profile; it must not
    # silently relax TASK08 ownership checks.
    for requirement in (b'def restore_task07_profile(', b'dry_run=True',
                        b'TASK07_NEW', b'root_file(helper, 0o755)'):
        if requirement not in new_rb:
            raise ValueError('rollback ownership invariant missing')
    return {'ru.nft': nft, 'apply.py': new_apply,
            'rollback.py': new_rb, 'vpn-task07': new_helper}


def stage(src: Path, dest: Path) -> dict:
    if dest.exists():
        raise ValueError('refuse to overwrite staged package')
    generated = build(src)
    # Build and verify all input before creating output directory.
    manifest = {
        'schema': 1,
        'kind': 'OFFLINE_SOURCE_STAGING_NOT_APPROVED_FOR_DEPLOY',
        'old_ru_nft_sha256': OLD_RU_SHA,
        'old_helper_pin_sha256': OLD_HELPER_PIN,
        'prepared': {n: sha(raw) for n, raw in generated.items()},
        'important': 'No live ledger hash can be precomputed. Do not copy these files onto RU individually.',
    }
    dest.mkdir(parents=True)
    for name, raw in generated.items():
        (dest/name).write_bytes(raw)
        if sha((dest/name).read_bytes()) != manifest['prepared'][name]:
            raise RuntimeError('staged output verification failed')
    (dest/'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True)+'\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    result = stage(args.source_dir, args.output_dir)
    print(json.dumps({'prepared': True, 'offline_only': True,
                      'files': sorted(result['prepared'])}, sort_keys=True))


if __name__ == '__main__':
    main()
