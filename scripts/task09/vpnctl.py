#!/usr/bin/python3
"""Local TASK 09 CLI. Live peer mutations require an explicit activation record."""
import argparse
from contextlib import nullcontext
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from manager_db import Refusal, Store
from manager_runtime import AwgAdapter, Controller
from manager_vault import Vault
from manager_backup import make_backup, check_backup, stage_restore

DB = Path('/var/lib/vpn-task09/manager.sqlite3')
ACTIVATION = Path('/etc/vpn-task09/activation.json')
LEGACY_PUBLIC = Path('/etc/vpn-task07/client.pub')


def activated(store):
    try:
        st = ACTIVATION.lstat()
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or
                stat.S_IMODE(st.st_mode) != 0o600 or ACTIVATION.is_symlink()):
            raise Refusal('activation_invalid', 'activation ownership mismatch')
        record = json.loads(ACTIVATION.read_text(encoding='ascii'))
        public = LEGACY_PUBLIC.read_bytes().strip()
        if (record != {'schema': 1, 'state': 'approved',
                       'legacy_public_sha256': hashlib.sha256(public).hexdigest()} or
                store.device('Test', 'iPhone')['public_key'].encode() != public):
            raise Refusal('activation_invalid', 'legacy identity or activation mismatch')
    except FileNotFoundError:
        raise Refusal('approval_required', 'live peer operations need approved migration') from None
    return True


def fixed_check(argv):
    proc = subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          timeout=20, check=False,
                          env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    return proc.returncode == 0


def fixed_output(argv):
    proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          timeout=10, check=False,
                          env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    if proc.returncode or len(proc.stdout) > 512 * 1024:
        return ''
    return proc.stdout.decode('ascii', errors='replace')


def fail_closed_guards_configured():
    rules = fixed_output(['/usr/sbin/ip', '-4', 'rule', 'show'])
    route = fixed_output(['/usr/sbin/ip', '-4', 'route', 'show', 'table', '220'])
    forward = fixed_output(['/usr/sbin/nft', 'list', 'chain', 'ip',
                            'vpn_task08_ru', 'forward'])
    return (bool(rules and route and forward) and
            'fwmark 0x702 iif awg-client unreachable' in rules and
            'default via 10.203.254.2 dev awg-transport' in route and
            'iifname "awg-client" drop' in forward and
            'oifname "eth0" meta mark 0x00000701 ip daddr @ru_set' in forward and
            'oifname "awg-transport" meta mark 0x00000702 accept' in forward)


def services():
    return {
        'awg_client': fixed_check(['/usr/bin/systemctl', 'is-active', '--quiet',
                                   'vpn-task07-client.service']),
        'awg_transport': fixed_check(['/usr/local/sbin/vpn-task06', 'monitor']),
        'client_dns': fixed_check(['/usr/bin/systemctl', 'is-active', '--quiet',
                                  'vpn-task08-dns.service']),
        'task08_ownership': fixed_check(['/usr/local/sbin/vpn-task08-rollback',
                                        'ru', 'check']),
        'fail_closed_guards_configured': fail_closed_guards_configured(),
    }


def public_device(row):
    return {key: row[key] for key in ('id', 'profile_name', 'ipv4', 'state', 'origin',
                                      'created_at', 'updated_at', 'limit_up_bps',
                                      'limit_down_bps')}


def public_user(row):
    return {key: row[key] for key in ('id', 'name', 'state', 'created_at', 'updated_at',
                                      'limit_up_bps', 'limit_down_bps')}


def parser():
    p = argparse.ArgumentParser(prog='vpnctl', description='Local VPN Manager; no Telegram')
    p.add_argument('--json', action='store_true', help='machine-readable output')
    root = p.add_subparsers(dest='entity', required=True)
    users = root.add_parser('user').add_subparsers(dest='action', required=True)
    for action in ('add', 'show', 'disable', 'enable', 'delete'):
        users.add_parser(action).add_argument('name')
    users.add_parser('list')
    user_limit = users.add_parser('limit')
    user_limit.add_argument('name')
    user_limit.add_argument('--up-bps', type=int)
    user_limit.add_argument('--down-bps', type=int)

    devices = root.add_parser('device').add_subparsers(dest='action', required=True)
    add = devices.add_parser('add')
    add.add_argument('user')
    add.add_argument('name')
    listing = devices.add_parser('list')
    listing.add_argument('user', nargs='?')
    for action in ('show', 'disable', 'enable', 'revoke', 'export'):
        item = devices.add_parser(action)
        item.add_argument('user')
        item.add_argument('name')
    device_limit = devices.add_parser('limit')
    device_limit.add_argument('user')
    device_limit.add_argument('name')
    device_limit.add_argument('--up-bps', type=int)
    device_limit.add_argument('--down-bps', type=int)
    root.add_parser('status')
    root.add_parser('diagnostics')
    root.add_parser('reconcile', help=argparse.SUPPRESS)
    root.add_parser('backup')
    restore = root.add_parser('restore')
    choice = restore.add_mutually_exclusive_group(required=True)
    choice.add_argument('--check', metavar='ARCHIVE')
    choice.add_argument('--stage', metavar='ARCHIVE')
    return p


def execute(args, store, adapter, vault, *, require_activation=activated,
            include_services=True):
    ctl = Controller(store, adapter)
    if args.entity == 'user':
        if args.action == 'add':
            return public_user(store.add_user(args.name))
        if args.action == 'list':
            return [public_user(row) for row in store.list_users()]
        if args.action == 'show':
            user = store.user(args.name)
            result = public_user(user)
            result['devices'] = [public_device(row) for row in store.list_devices(args.name)]
            return result
        if args.action == 'limit':
            return store.set_limit('user', args.name, None, args.up_bps, args.down_bps)
        require_activation(store)
        row = store.user(args.name)
        state = {'disable': 'disabled', 'enable': 'enabled', 'delete': 'deleted'}[args.action]
        ctl.change('user.' + args.action, str(row['id']),
                   lambda: store.set_user_state(args.name, state))
        return public_user(store.user(args.name, include_deleted=True))

    if args.entity == 'device':
        if args.action == 'list':
            return [public_device(row) for row in store.list_devices(args.user)]
        if args.action == 'show':
            return public_device(store.device(args.user, args.name))
        if args.action == 'limit':
            return store.set_limit('device', args.user, args.name,
                                   args.up_bps, args.down_bps)
        if args.action == 'export':
            device = store.device(args.user, args.name)
            if device['state'] != 'enabled' or store.user(args.user)['state'] != 'enabled':
                raise Refusal('device_disabled', 'only enabled devices can be exported')
            if adapter.peers().get(device['public_key']) != device['ipv4'] + '/32':
                raise Refusal('peer_drift', 'device is not active in AWG')
            return {'profile': device['profile_name'], 'path': vault.export(device),
                    'mode': '0600', 'contains_secret': True}
        require_activation(store)
        if args.action == 'add':
            user = store.user(args.user)
            if user['state'] != 'enabled':
                raise Refusal('user_disabled', 'user is not enabled')
            if ctl.drift()['unknown_peers']:
                raise Refusal('unknown_live_peer', 'unknown live peer; refusing key creation')
            did = uuid.uuid4().hex
            key_ref, public_key = vault.create(did)
            ctl.change('device.add', did,
                       lambda: store.add_device(args.user, args.name, public_key,
                                                key_ref, device_id=did))
            return public_device(store.device(args.user, args.name))
        device = store.device(args.user, args.name)
        state = {'disable': 'disabled', 'enable': 'enabled', 'revoke': 'revoked'}[args.action]
        ctl.change('device.' + args.action, device['id'],
                   lambda: store.set_device_state(args.user, args.name, state))
        return public_device(store.device(args.user, args.name))

    if args.entity == 'status':
        data = ctl.status()
        if include_services:
            data['services'] = services()
        return data
    if args.entity == 'diagnostics':
        data = {'sqlite_integrity': store.integrity_check(),
                'peer_drift': ctl.drift(),
                'incomplete_operations': store.pending_operations(),
                'speed_limits_enforced': False}
        if include_services:
            data['services'] = services()
        return data
    if args.entity == 'reconcile':
        require_activation(store)
        return ctl.reconcile()
    if args.entity == 'backup':
        return make_backup(store)
    if args.entity == 'restore':
        return check_backup(args.check) if args.check else stage_restore(args.stage)
    raise Refusal('invalid_command', 'unsupported command')


def output(value, json_mode):
    if json_mode:
        print(json.dumps({'ok': True, 'code': 'ok', 'data': value},
                         ensure_ascii=False, sort_keys=True))
    else:
        print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def main(argv=None, *, store=None, adapter=None, vault=None,
         require_activation=activated, include_services=True, lock_context=None):
    args = parser().parse_args(argv)
    if store is None and os.geteuid() != 0:
        print('vpnctl requires local root', file=sys.stderr)
        return 2
    own_store = store is None
    if lock_context is None:
        if own_store:
            from manager_lock import process_lock
            lock_context = process_lock
        else:
            lock_context = nullcontext
    adapter = adapter or AwgAdapter()
    vault = vault or Vault()
    try:
        with lock_context():
            if store is None:
                store = Store(DB)
            value = execute(args, store, adapter, vault,
                            require_activation=require_activation,
                            include_services=include_services)
        output(value, args.json)
        return 0
    except Refusal as exc:
        payload = {'ok': False, 'code': exc.code, 'error': str(exc)}
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        else:
            print(exc.code + ': ' + str(exc), file=sys.stderr)
        return 3
    except Exception:
        payload = {'ok': False, 'code': 'internal_error',
                   'error': 'operation failed; details withheld'}
        if args.json:
            print(json.dumps(payload, sort_keys=True))
        else:
            print(payload['error'], file=sys.stderr)
        return 4
    finally:
        if own_store and store is not None:
            store.close()


if __name__ == '__main__':
    raise SystemExit(main())
