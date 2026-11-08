#!/usr/bin/python3
"""Short RU TASK 08 return-path counters, with addressed cleanup."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

NFT = '/usr/sbin/nft'
SYSTEMCTL = '/usr/bin/systemctl'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'HOME': '/'}
TABLE = 'vpn_task08_ru'


def run(args):
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          env=ENV, timeout=15, check=False)
    if proc.returncode or len(proc.stdout) > 8 * 1024 * 1024:
        raise RuntimeError('fixed diagnostic operation failed')
    return proc.stdout


def rules(chain):
    data = json.loads(run([NFT, '-j', 'list', 'chain', 'ip', TABLE, chain]))
    return {obj['rule']['handle']: obj['rule'] for obj in data['nftables']
            if 'rule' in obj and isinstance(obj['rule'].get('handle'), int)}


def install(chain, tokens):
    before = set(rules(chain))
    run([NFT, 'insert', 'rule', 'ip', TABLE, chain, *tokens,
         'counter', 'comment', 'vpn-task08-owned'])
    after = set(rules(chain))
    new = after - before
    if len(new) != 1:
        raise RuntimeError('diagnostic handle mismatch')
    return chain, new.pop()


def count(chain, handle):
    row = rules(chain)[handle]
    return next((expr['counter']['packets'] for expr in row['expr']
                 if 'counter' in expr), None)


def main():
    if os.geteuid() != 0 or len(sys.argv) != 1:
        raise RuntimeError('root and zero arguments required')
    if Path('/etc/vpn-task06/role').read_text().strip() != 'ru':
        raise RuntimeError('RU role required')
    if not Path('/var/lib/vpn-task08/active.json').is_file():
        raise RuntimeError('TASK 08 inactive')
    run([SYSTEMCTL, 'stop', 'vpn-task08-egress.timer'])
    run([SYSTEMCTL, 'stop', 'vpn-task06-monitor.timer'])
    owned = []
    try:
        owned.append(install('prerouting', ['iifname', 'awg-transport',
                                           'ip', 'daddr', '10.203.253.2']))
        owned.append(install('forward', ['iifname', 'awg-transport',
                                        'oifname', 'awg-client', 'ip', 'daddr',
                                        '10.203.253.2']))
        owned.append(install('forward', ['iifname', 'awg-transport',
                                        'oifname', 'awg-client', 'ip', 'daddr',
                                        '10.203.253.2', 'ct', 'state',
                                        'established,related']))
        time.sleep(5)
        values = [count(chain, handle) for chain, handle in owned]
        if any(value is None for value in values):
            raise RuntimeError('diagnostic counter unavailable')
        print(json.dumps({'prerouting_return': values[0],
                          'forward_return': values[1],
                          'forward_established_return': values[2]}))
    finally:
        for chain, handle in reversed(owned):
            run([NFT, 'delete', 'rule', 'ip', TABLE, chain, 'handle', str(handle)])
        run([SYSTEMCTL, 'start', 'vpn-task06-monitor.timer'])
        run([SYSTEMCTL, 'start', 'vpn-task08-egress.timer'])
        run(['/usr/local/sbin/vpn-task06', 'status'])


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps({'diagnosis_complete': False}), file=sys.stderr)
        raise SystemExit(1)
