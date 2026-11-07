"""One explicit --run starts the approved stage after owner bootstrap.
No deployment or SSH occurs without --run. No root shell or arbitrary command.
"""
import concurrent.futures
import json
from pathlib import Path
import subprocess
import sys
import time

ROLES = ('ru', 'fr')
OPTIONS = ['-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
           '-o', 'UpdateHostKeys=no', '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes',
           '-o', 'ConnectTimeout=10', '-o', 'ControlMaster=no']
ACTIONS = ('prepare', 'peer', 'up', 'status', 'start-test', 'result', 'down', 'cleanup')


def remote(role, action, data=None):
    if role not in ROLES or action not in ACTIONS:
        raise ValueError('fixed role/action required')
    command = ['ssh', *OPTIONS, 'vpn-' + role, 'sudo -n /usr/local/sbin/vpn-task05 ' + action]
    p = subprocess.run(command, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    if p.returncode:
        raise RuntimeError(role + ':' + action + ' failed (raw output withheld)')
    return json.loads(p.stdout)


def both(action):
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        jobs = {role: pool.submit(remote, role, action) for role in ROLES}
        return {role: jobs[role].result() for role in ROLES}


def run_stage():
    report = {'transport_test': 'FAIL', 'production_client_health': 'UNCONFIRMED', 'cleanup': {}}
    try:
        keys = both('prepare')
        for role, other in (('ru', 'fr'), ('fr', 'ru')):
            key = keys[other]['public_key']
            if not isinstance(key, str) or len(key) != 44 or '\n' in key:
                raise RuntimeError('invalid public key response')
            remote(role, 'peer', (key + '\n').encode('ascii'))
        remote('fr', 'up')
        remote('ru', 'up')
        both('start-test')
        deadline = time.monotonic() + 1200
        while time.monotonic() < deadline:
            time.sleep(30)
            # Each call opens a NEW SSH connection; failures fail the stage.
            both('status')
            results = both('result')
            print(json.dumps({r: {k: results[r].get(k) for k in ('status', 'samples', 'errors', 'elapsed')} for r in ROLES}), flush=True)
            if any(results[r]['status'] == 'FAIL' for r in ROLES):
                raise RuntimeError('payload/stability test failed')
            if all(results[r]['status'] == 'PASS' for r in ROLES):
                report['results'] = results
                report['transport_test'] = 'PASS'
                break
        else:
            raise RuntimeError('15-minute test did not complete within deadline')
    except Exception:
        report['transport_test'] = 'FAIL'
    finally:
        for role in ROLES:
            try:
                remote(role, 'down')
                # systemd --collect may asynchronously unload the owned unit.
                for attempt in range(10):
                    try:
                        remote(role, 'cleanup')
                        report['cleanup'][role] = 'PASS'
                        break
                    except Exception:
                        time.sleep(1)
                else:
                    report['cleanup'][role] = 'BLOCKED'
            except Exception:
                report['cleanup'][role] = 'BLOCKED'
        if any(report['cleanup'].get(role) != 'PASS' for role in ROLES):
            report['transport_test'] = 'FAIL'
    return report


if __name__ == '__main__':
    if sys.argv[1:] != ['--run']:
        print('PLAN ONLY: owner bootstrap -> prepare/peer -> up -> 900s TCP+UDP on BOTH sides -> down/cleanup')
        sys.exit(0 if not sys.argv[1:] else 2)
    result = run_stage()
    # Sanitized report stdout; operator chooses storage outside Git.
    print(json.dumps(result, indent=2))
    sys.exit(0 if result['transport_test'] == 'PASS' else 1)
