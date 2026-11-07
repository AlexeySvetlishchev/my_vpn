"""Short, bounded TASK 05 smoke check. Does not invoke the 15-minute runner."""
import concurrent.futures
import json
import re
import shutil
import subprocess
import sys
import time

ROLES = ('ru', 'fr')
INNER = {'ru': '10.203.254.1', 'fr': '10.203.254.2'}
SSH_BIN = shutil.which('ssh.exe') or shutil.which('ssh') or 'ssh'
SSH = ['-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
       '-o', 'UpdateHostKeys=no', '-o', 'ForwardAgent=no',
       '-o', 'ClearAllForwardings=yes', '-o', 'ConnectTimeout=10',
       '-o', 'ControlMaster=no']
ACTIONS = ('prepare', 'peer', 'up', 'status', 'down', 'cleanup')


def remote(role, action, data=None):
    if role not in ROLES or action not in ACTIONS:
        raise ValueError('fixed role/action required')
    command = [SSH_BIN, *SSH, 'vpn-' + role,
               'sudo -n /usr/local/sbin/vpn-task05 ' + action]
    p = subprocess.run(command, input=data, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, timeout=60)
    if p.returncode:
        try:
            result = json.loads(p.stdout)
            diagnostic = result.get('diagnostic')
            if isinstance(diagnostic, dict):
                parts = [diagnostic.get(k, '') for k in ('stage', 'operation', 'category')]
                reason = '.'.join(parts) if all(isinstance(x, str) and re.fullmatch(r'[a-z0-9_]{1,48}', x) for x in parts) else 'fixed helper rejected operation'
            else:
                reason = result.get('reason', 'fixed helper rejected operation')
            if not isinstance(reason, str) or not re.fullmatch(r'[A-Za-z0-9_ ,:/;.-]{1,160}', reason):
                reason = 'fixed helper rejected operation'
        except Exception:
            reason = 'fixed helper returned no safe diagnostic'
        raise RuntimeError(role + ':' + action + ': ' + reason)
    return json.loads(p.stdout)


def both(action):
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        jobs = {r: pool.submit(remote, r, action) for r in ROLES}
        return {r: jobs[r].result() for r in ROLES}


def ping(role):
    other = 'fr' if role == 'ru' else 'ru'
    command = [SSH_BIN, *SSH, 'vpn-' + role, '/usr/bin/ping', '-n',
               '-I', 'awg-test', '-c', '4', '-W', '2', INNER[other]]
    p = subprocess.run(command, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, timeout=30)
    match = re.search(rb'([0-9]+) packets transmitted, ([0-9]+) (?:packets )?received', p.stdout)
    if p.returncode or not match or int(match[1]) != 4 or int(match[2]) < 1:
        tx = int(match[1]) if match else 0
        rx = int(match[2]) if match else 0
        raise RuntimeError(role + ' ping failed: exit=' + str(p.returncode) +
                           ' tx=' + str(tx) + ' rx=' + str(rx))
    return {'transmitted': int(match[1]), 'received': int(match[2])}


def require_fresh(rows):
    now = int(time.time())
    for role in ROLES:
        stamp = rows[role].get('handshake', 0)
        if not isinstance(stamp, int) or stamp <= 0 or now - stamp > 120:
            raise RuntimeError(role + ' handshake stale')
        if rows[role].get('baseline_unchanged') is not True:
            raise RuntimeError(role + ' baseline changed')


def run_smoke():
    report = {'status': 'FAIL', 'handshake': False, 'ping': {},
              'bidirectional_counters': False, 'cleanup': {}}
    try:
        keys = both('prepare')
        for role, other in (('ru', 'fr'), ('fr', 'ru')):
            key = keys[other].get('public_key')
            if not isinstance(key, str) or len(key) != 44 or '\n' in key:
                raise RuntimeError('invalid public key response')
            remote(role, 'peer', (key + '\n').encode('ascii'))
        remote('fr', 'up')
        remote('ru', 'up')

        deadline = time.monotonic() + 90
        current = None
        while time.monotonic() < deadline:
            current = both('status')
            if all(isinstance(current[r].get('handshake'), int) and
                   current[r]['handshake'] > 0 for r in ROLES):
                require_fresh(current)
                break
            time.sleep(2)
        else:
            raise RuntimeError('handshake not established within 90 seconds')
        report['handshake'] = True
        before = current

        ping_errors = []
        for role, direction in (('ru', 'ru_to_fr'), ('fr', 'fr_to_ru')):
            try:
                report['ping'][direction] = ping(role)
            except RuntimeError as error:
                # The message is a fixed role plus parsed integer counters only.
                ping_errors.append(str(error))
        after = both('status')
        require_fresh(after)
        report['bidirectional_counters'] = all(
            after[r]['rx'] > before[r]['rx'] and after[r]['tx'] > before[r]['tx']
            for r in ROLES)
        report['production_fr'] = {
            'container_state': 'NOT_CHECKED',
            'docker_metadata_read': False,
            'protected_host_network_baseline_unchanged': after['fr'].get('baseline_unchanged') is True,
            'client_data_plane': 'UNCONFIRMED'}
        if ping_errors:
            raise RuntimeError('; '.join(ping_errors))
        if not report['bidirectional_counters']:
            raise RuntimeError('traffic counters did not grow both ways')
        report['status'] = 'PASS'
    except Exception as error:
        # Report only fixed errors; never echo subprocess output or credentials.
        report['failure'] = str(error) if type(error) is RuntimeError else 'smoke check failed'
    finally:
        for role in ROLES:
            try:
                remote(role, 'down')
                remote(role, 'cleanup')
                # Second down verifies there is no remaining owned link/unit.
                absent = remote(role, 'down').get('already_absent') is True
                report['cleanup'][role] = 'PASS' if absent else 'FAIL'
            except Exception:
                report['cleanup'][role] = 'BLOCKED'
        if any(report['cleanup'].get(r) != 'PASS' for r in ROLES):
            report['status'] = 'FAIL'
    return report


if __name__ == '__main__':
    if sys.argv[1:]:
        print('Usage: python -B scripts/task05/smoke.py')
        sys.exit(2)
    result = run_smoke()
    print(json.dumps(result, indent=2))
    sys.exit(0 if result['status'] == 'PASS' else 1)
