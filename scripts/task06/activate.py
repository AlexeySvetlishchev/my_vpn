"""Activate TASK 06 on the two fixed hosts and run bounded smoke/restart checks."""
import concurrent.futures
import json
import re
import shutil
import subprocess
import sys
import time

HOSTS = {'ru': 'vpn-ru', 'fr': 'vpn-fr'}
INNER = {'ru': '10.203.254.1', 'fr': '10.203.254.2'}
SSH_BIN = shutil.which('ssh.exe') or shutil.which('ssh') or 'ssh'
SSH_OPTIONS = ['-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
               '-o', 'UpdateHostKeys=no', '-o', 'ConnectTimeout=10',
               '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes',
               '-o', 'ControlMaster=no']
HELPER = '/usr/local/sbin/vpn-task06'
UNIT = 'vpn-task06-awg.service'
PROBE = 'vpn-task06-probe.service'
TIMER = 'vpn-task06-monitor.timer'
TASK_ACTIONS = {'keygen', 'set-peer', 'capture-baseline', 'status', 'monitor', 'rollback'}
SYSTEMD_COMMANDS = {
    'enable-awg': 'sudo -n /usr/bin/systemctl enable --now vpn-task06-awg.service',
    'enable-monitor': 'sudo -n /usr/bin/systemctl enable --now vpn-task06-monitor.timer',
    'restart-awg': 'sudo -n /usr/bin/systemctl restart vpn-task06-awg.service',
    'start-monitor': 'sudo -n /usr/bin/systemctl start vpn-task06-monitor.service',
    'active': 'sudo -n /usr/bin/systemctl is-active vpn-task06-awg.service vpn-task06-probe.service vpn-task06-monitor.timer',
    'enabled': 'sudo -n /usr/bin/systemctl is-enabled vpn-task06-awg.service vpn-task06-monitor.timer',
}
PUBLIC_DOCKER_QUERY = 'sudo -n docker ps -q --filter name=amnezia-awg2'
PUBLIC_DOCKER_PORT_QUERY = 'sudo -n docker port amnezia-awg2 40905/udp'


def remote(role, command, data=None, timeout=90):
    if role not in HOSTS:
        raise RuntimeError('invalid fixed role')
    proc = subprocess.run([SSH_BIN, *SSH_OPTIONS, HOSTS[role], command],
                          input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    if proc.returncode:
        try:
            result = json.loads(proc.stdout.decode('utf-8', errors='strict'))
            diagnostic = result.get('diagnostic', {}) if isinstance(result, dict) else {}
            parts = [diagnostic.get(key, '') for key in ('stage', 'operation', 'category')]
            if all(isinstance(v, str) and re.fullmatch(r'[a-z0-9_]{1,48}', v) for v in parts):
                raise RuntimeError(role + ':' + '.'.join(parts))
        except RuntimeError:
            raise
        except Exception:
            pass
        raise RuntimeError(role + ':remote_operation_failed')
    return proc.stdout.decode('utf-8', errors='strict').strip()


def task(role, action, data=None):
    if action not in TASK_ACTIONS:
        raise RuntimeError('invalid fixed task action')
    try:
        raw = remote(role, 'sudo -n ' + HELPER + ' ' + action, data)
    except RuntimeError as error:
        if str(error).startswith(role + ':'):
            raise
        raise RuntimeError(role + ':' + action + ':remote_operation_failed') from None
    result = json.loads(raw)
    if not isinstance(result, dict) or result.get('status') == 'BLOCKED':
        diagnostic = result.get('diagnostic', {})
        fields = [diagnostic.get(key, '') for key in ('stage', 'operation', 'category')]
        if all(isinstance(v, str) and re.fullmatch(r'[a-z0-9_]{1,48}', v) for v in fields):
            reason = '.'.join(fields)
        else:
            reason = 'fixed_helper_rejected_operation'
        raise RuntimeError(role + ':' + action + ':' + reason)
    return result


def systemd(role, action):
    if action not in SYSTEMD_COMMANDS:
        raise RuntimeError('invalid fixed systemd action')
    try:
        return remote(role, SYSTEMD_COMMANDS[action])
    except RuntimeError:
        raise RuntimeError(role + ':systemd_' + action + '_failed') from None


def public_key(role):
    result = task(role, 'keygen')
    key = result.get('public_key')
    if not isinstance(key, str) or not re.fullmatch(r'[A-Za-z0-9+/]{43}=', key):
        raise RuntimeError(role + ':public_key_validation_failed')
    return key


def production_fr():
    matches = [row for row in remote('fr', PUBLIC_DOCKER_QUERY).splitlines()
               if re.fullmatch(r'[0-9a-f]{12,64}', row)]
    port = remote('fr', PUBLIC_DOCKER_PORT_QUERY)
    if len(matches) != 1 or '40905' not in port:
        raise RuntimeError('fr:production_container_or_udp_publication_not_confirmed')
    return True


def monitors_until_ready(timeout=75):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                futures = {r: pool.submit(task, r, 'monitor') for r in HOSTS}
                results = {r: futures[r].result(timeout=15) for r in HOSTS}
            if all(results[r].get('healthy') and results[r].get('udp_echo') and
                   results[r].get('tcp_echo') for r in HOSTS):
                return results
        except Exception as exc:
            last = str(exc)
        time.sleep(2)
    raise RuntimeError('bidirectional_smoke_timeout:' + (last or 'no_valid_result'))


def rollback_both():
    outcome = {}
    for role in ('fr', 'ru'):
        try:
            outcome[role] = task(role, 'rollback').get('rolled_back') is True
        except Exception:
            outcome[role] = False
    return outcome


def main():
    if sys.argv[1:]:
        raise RuntimeError('no command-line overrides accepted')
    try:
        production_fr()
        for role in ('ru', 'fr'):
            task(role, 'capture-baseline')
        keys = {role: public_key(role) for role in HOSTS}
        for role in HOSTS:
            peer = 'fr' if role == 'ru' else 'ru'
            task(role, 'set-peer', (keys[peer] + '\n').encode('ascii'))
        for role in ('ru', 'fr'):
            systemd(role, 'enable-awg')
        for role in ('ru', 'fr'):
            systemd(role, 'enable-monitor')
        initial = monitors_until_ready()
        for role in ('ru', 'fr'):
            enabled = systemd(role, 'enabled').splitlines()
            active = systemd(role, 'active').splitlines()
            if not all('enabled' in item for item in enabled):
                raise RuntimeError(role + ':autostart_not_enabled')
            if active != ['active', 'active', 'active']:
                raise RuntimeError(role + ':required_units_not_active')
            task(role, 'status')

        restarted = {}
        for role in ('ru', 'fr'):
            systemd(role, 'restart-awg')
            active = systemd(role, 'active').splitlines()
            if active != ['active', 'active', 'active']:
                raise RuntimeError(role + ':service_restart_did_not_restore_dependencies')
            restarted[role] = monitors_until_ready()

        # Exercise the actual systemd oneshot monitor under its hardened unit context.
        for role in ('ru', 'fr'):
            systemd(role, 'start-monitor')
        final = monitors_until_ready()
        task('ru', 'status')
        task('fr', 'status')
        production_fr()
        print(json.dumps({'result': 'PASS', 'autostart': 'enabled',
                          'initial_smoke': initial, 'after_ru_restart': restarted['ru'],
                          'after_fr_restart': restarted['fr'], 'final_smoke': final,
                          'ru_fr_udp_tcp_echo': 'passed_both_directions',
                          'ssh_reachability': 'confirmed_by_remote_checks',
                          'host_network_baseline': 'unchanged',
                          'fr_amnezia_awg2_running_and_udp_40905_published': True,
                          'production_data_plane': 'not independently tested'}, sort_keys=True))
    except Exception as error:
        rollback = rollback_both()
        print(json.dumps({'result': 'FAILED', 'reason': str(error),
                          'addressed_rollback': rollback}, sort_keys=True))
        return 1
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print('BLOCKED: TASK 06 controller failed before a safe result')
        sys.exit(1)
