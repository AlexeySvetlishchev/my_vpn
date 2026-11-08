#!/usr/bin/env python3
"""Offline verification of a TASK08 -> TASK09 migration source package.

Does not access network, execute programs, or write to a VPS. The purpose is to
reject an inconsistent candidate before a deployment backend can consider it.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from task09_nft_plan import source_rules, CHAINS

NAMES = ('ru.nft', 'apply.py', 'rollback.py', 'vpn-task07')
EXPECTED_OLD_NFT = '4cc76368089640e048bf414267c22146304d3f0330387632883f3e217ab5460a'
EXPECTED_OLD_HELPER_PIN = 'd2370830e7cc9228127d019d9dc53036a5dacb37320627328228fee58395a141'
PIN_RU = re.compile(rb"'ru': '([0-9a-f]{64})'")
PIN_HELPER = re.compile(rb"^TASK07_NEW = '([0-9a-f]{64})'$", re.MULTILINE)


class PackageMismatch(ValueError):
    pass


def sha(content):
    return hashlib.sha256(content).hexdigest()


def unique_pin(pattern, raw, label):
    found = pattern.findall(raw)
    if len(found) != 1:
        raise PackageMismatch(f'{label}: expected exactly one pin')
    return found[0].decode('ascii')


def validate(old: dict[str, bytes], new: dict[str, bytes], manifest: dict | None = None):
    if set(old) != set(NAMES) or set(new) != set(NAMES):
        raise PackageMismatch('expected exactly four named artifacts')
    if sha(old['ru.nft']) != EXPECTED_OLD_NFT:
        raise PackageMismatch('old nft baseline differs from known TASK08')
    old_helper_pin = unique_pin(PIN_HELPER, old['rollback.py'], 'old helper pin')
    if old_helper_pin != EXPECTED_OLD_HELPER_PIN:
        raise PackageMismatch('old TASK07 helper pin differs from known TASK08')
    if unique_pin(PIN_RU, old['apply.py'], 'old nft pin') != sha(old['ru.nft']):
        raise PackageMismatch('old apply.py pin mismatch')
    if unique_pin(PIN_RU, new['apply.py'], 'new nft pin') != sha(new['ru.nft']):
        raise PackageMismatch('new apply.py pin mismatch')
    if unique_pin(PIN_HELPER, new['rollback.py'], 'new helper pin') != sha(new['vpn-task07']):
        raise PackageMismatch('new rollback.py helper pin mismatch')
    if b'MANAGER_ACTIVATION' not in new['vpn-task07'] or b'def startup_peers(' not in new['vpn-task07']:
        raise PackageMismatch('candidate helper lacks Manager integration')
    if old['ru.nft'].count(b'10.203.253.2') != 6:
        raise PackageMismatch('unexpected baseline client-rule count')
    if re.search(rb'10\.203\.253\.2(?![0-9])', new['ru.nft']):
        raise PackageMismatch('candidate still uses singleton client address')
    old_rules, new_rules = source_rules_text(old['ru.nft']), source_rules_text(new['ru.nft'])
    old_count = sum(map(len, old_rules.values()))
    new_count = sum(map(len, new_rules.values()))
    if new_count != old_count + 1:
        raise PackageMismatch('unexpected nft rule delta')
    guard = ('iifname "awg-client" ip saddr { 10.203.253.0, '
             '10.203.253.1, 10.203.253.255 } drop comment "vpn-task08-owned"')
    if new_rules['prerouting'][0] != guard:
        raise PackageMismatch('reserved source IP guard absent or misplaced')
    new_without_guard = {k: (v[1:] if k == 'prerouting' else v) for k, v in new_rules.items()}
    substitutions = 0
    for chain in CHAINS:
        if len(old_rules[chain]) != len(new_without_guard[chain]):
            raise PackageMismatch('nft chain length altered')
        for before, after in zip(old_rules[chain], new_without_guard[chain]):
            if before == after:
                continue
            if '10.203.253.2' not in before or after != before.replace('10.203.253.2', '10.203.253.0/24'):
                raise PackageMismatch('unexpected nft rule mutation')
            substitutions += 1
    if substitutions != 6:
        raise PackageMismatch('expected six precise nft replacements')
    # Only allow the two constant edits to deployment Python files. This
    # prevents staging a package with an unrelated rollback behavior change.
    if new['apply.py'] != old['apply.py'].replace(EXPECTED_OLD_NFT.encode(), sha(new['ru.nft']).encode()):
        raise PackageMismatch('candidate apply.py has extraneous changes')
    if new['rollback.py'] != old['rollback.py'].replace(EXPECTED_OLD_HELPER_PIN.encode(), sha(new['vpn-task07']).encode()):
        raise PackageMismatch('candidate rollback.py has extraneous changes')
    hashes = {name: sha(new[name]) for name in NAMES}
    if manifest is not None:
        if manifest.get('schema') != 1 or manifest.get('prepared') != hashes:
            raise PackageMismatch('staged manifest differs from package bytes')
    return {'verified': True, 'changed_rules': substitutions, 'extra_guards': 1, 'sha256': hashes}


def source_rules_text(data):
    import tempfile
    with tempfile.TemporaryDirectory(prefix='task09-integrity-') as td:
        source = Path(td) / 'ru.nft'
        source.write_bytes(data)
        return source_rules(source)


def verify_directories(original: Path, staged: Path):
    original, staged = Path(original), Path(staged)
    old_names = {'ru.nft': 'ru.nft', 'apply.py': 'apply.py',
                 'rollback.py': 'rollback.py', 'vpn-task07': 'helper.py'}
    old = {dst: (original / src).read_bytes() for dst, src in old_names.items()}
    new = {name: (staged / name).read_bytes() for name in NAMES}
    manifest = json.loads((staged / 'manifest.json').read_text(encoding='utf-8'))
    return validate(old, new, manifest)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original', type=Path, required=True)
    parser.add_argument('--staged', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify_directories(args.original, args.staged), sort_keys=True))
