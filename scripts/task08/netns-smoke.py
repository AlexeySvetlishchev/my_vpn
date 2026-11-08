#!/usr/bin/python3
"""Exercise TASK 08 nft syntax/JSON in a short-lived isolated net namespace."""
import json
import importlib.util
import os
from pathlib import Path
import subprocess
import sys

NFT = '/usr/sbin/nft'
ROOT = Path('/home/wolffrog/task08-stage')


def run(argv, data=None):
    p = subprocess.run(argv, input=data, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, check=True, timeout=10)
    return p.stdout


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2 or sys.argv[1] not in ('ru', 'fr'):
        raise RuntimeError('root and exact role required')
    role = sys.argv[1]
    if role == 'fr':
        fixture = (b'add table ip filter\n'
                   b'add chain ip filter FORWARD { type filter hook forward priority 0; policy drop; }\n'
                   b'add chain ip filter DOCKER-USER\n'
                   b'add chain ip filter DOCKER-FORWARD\n'
                   b'add rule ip filter FORWARD jump DOCKER-USER\n'
                   b'add rule ip filter FORWARD jump DOCKER-FORWARD\n')
        run([NFT, '-f', '-'], fixture)
        parsed = json.loads(run([NFT, '-j', 'list', 'ruleset']))
        rows = [v['rule'] for v in parsed['nftables'] if 'rule' in v and
                v['rule'].get('chain') == 'FORWARD']
        handle = rows[1]['handle']
        batch = (ROOT / 'fr.nft').read_bytes() + (
            'insert rule ip filter FORWARD position ' + str(handle) +
            ' jump vpn_task08_fr_forward comment "vpn-task08-owned"\n').encode()
    else:
        batch = (ROOT / 'ru.nft').read_bytes()
    run([NFT, '-f', '-'], batch)
    parsed = json.loads(run([NFT, '-j', 'list', 'ruleset']))
    owned = [v['rule'] for v in parsed['nftables'] if 'rule' in v and
             (v['rule'].get('table') == 'vpn_task08_' + role or
              v['rule'].get('chain') == 'vpn_task08_fr_forward' or
              (role == 'fr' and v['rule'].get('chain') == 'FORWARD' and
               any(e.get('jump', {}).get('target') == 'vpn_task08_fr_forward'
                   for e in v['rule'].get('expr', []) if isinstance(e, dict))))]
    if not owned or any(r.get('comment') != 'vpn-task08-owned' for r in owned):
        raise RuntimeError('nft JSON ownership marker mismatch')
    spec = importlib.util.spec_from_file_location('task08_rollback', ROOT / 'rollback.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.nft_cleanup(role)
    remaining = module.objects(json.loads(run([NFT, '-j', 'list', 'ruleset'])), role)
    if any(remaining):
        raise RuntimeError('addressed nft cleanup left owned objects')
    task06_spec = importlib.util.spec_from_file_location('task06_test', '/opt/vpn-task06/helper.py')
    task06 = importlib.util.module_from_spec(task06_spec)
    task06_spec.loader.exec_module(task06)
    recover_spec = importlib.util.spec_from_file_location('task08_recover', ROOT / 'recover.py')
    recover = importlib.util.module_from_spec(recover_spec)
    recover_spec.loader.exec_module(recover)
    apply_spec = importlib.util.spec_from_file_location('task08_apply', ROOT / 'apply.py')
    apply = importlib.util.module_from_spec(apply_spec)
    apply_spec.loader.exec_module(apply)
    recover.PACKAGE = Path('/opt/vpn-task08') if role == 'ru' else ROOT
    recover.atomic_ledger = lambda _ledger: None
    ledger = {'own_table_sha256': '', 'filter_sha256': ''}
    if not recover.restore_nft(role, ledger, task06, apply, module):
        raise RuntimeError('isolated nft recovery did not recreate rules')
    module.nft_cleanup(role)
    print(json.dumps({'isolated_netns_test': True, 'role': role,
                      'owned_rule_count': len(owned), 'cleanup': True,
                      'recovery': True}))


if __name__ == '__main__':
    main()
