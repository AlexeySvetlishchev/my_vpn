#!/usr/bin/python3
"""Read-only preflight and separately gated import of TASK 07's test identity."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from manager_db import Refusal, Store, check_public_key
from manager_runtime import AwgAdapter

LEGACY = Path('/etc/vpn-task07')
DATABASE = Path('/var/lib/vpn-task09/manager.sqlite3')
ACTIVATION = Path('/etc/vpn-task09/activation.json')


def protected(path, *, directory=False):
    st = path.lstat()
    expected = 0o700 if directory else 0o600
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if path.is_symlink() or not kind(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != expected:
        raise Refusal('legacy_ownership', 'TASK 07 file ownership mismatch')


def preflight(adapter=None):
    adapter = adapter or AwgAdapter()
    protected(LEGACY, directory=True)
    for name in ('state.json', 'server.key', 'client.key', 'client.pub', 'Test_iPhone.conf'):
        protected(LEGACY / name)
    state = json.loads((LEGACY / 'state.json').read_text(encoding='ascii'))
    if (state.get('phase') != 'active' or state.get('iface') != 'awg-client' or
            state.get('network') != '10.203.253.0/24' or state.get('port') != 51821):
        raise Refusal('legacy_state', 'TASK 07 state differs from expected active interface')
    public = check_public_key((LEGACY / 'client.pub').read_text(encoding='ascii').strip())
    live = adapter.peers()
    if live != {public: '10.203.253.2/32'}:
        raise Refusal('legacy_peer', 'live test peer differs from TASK 07 record')
    return {'legacy_profile': 'Test_iPhone', 'ipv4': '10.203.253.2',
            'public_fingerprint': hashlib.sha256(public.encode()).hexdigest()[:16],
            'live_peer_count': 1, 'secret_files_unchanged': True}


def import_record(store, adapter=None):
    # Database-only import. The marker and AWG peers remain untouched.
    result = preflight(adapter)
    public = (LEGACY / 'client.pub').read_text(encoding='ascii').strip()
    if store.list_devices():
        try:
            old = store.device('Test', 'iPhone')
        except Refusal:
            raise Refusal('import_conflict', 'database has devices but no legacy identity') from None
        if (len(store.list_devices()) != 1 or old['public_key'] != public or
                old['ipv4'] != '10.203.253.2' or old['origin'] != 'task07' or
                Path(old['key_ref']) != LEGACY / 'client.key'):
            raise Refusal('import_conflict', 'database identity differs from live test peer')
        result['already_imported'] = True
        return result
    if store.list_users():
        if len(store.list_users()) != 1 or store.list_users()[0]['name'] != 'Test':
            raise Refusal('import_conflict', 'database user conflicts with legacy identity')
    else:
        store.add_user('Test')
    store.add_device('Test', 'iPhone', public, LEGACY / 'client.key',
                     origin='task07', ipv4='10.203.253.2')
    result['already_imported'] = False
    return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if os.geteuid() != 0 or argv not in (['preflight'], ['import-legacy']):
        raise SystemExit(2)
    try:
        if argv == ['preflight']:
            result = preflight()
        else:
            if ACTIVATION.exists() or ACTIVATION.is_symlink():
                raise Refusal('import_conflict', 'Manager activation already exists')
            from manager_lock import process_lock
            with process_lock():
                preflight()
                store = Store(DATABASE)
                try:
                    result = import_record(store)
                finally:
                    store.close()
        print(json.dumps(result, sort_keys=True))
    except (Refusal, OSError, ValueError, json.JSONDecodeError) as exc:
        code = exc.code if isinstance(exc, Refusal) else 'preflight_failed'
        print(json.dumps({'ok': False, 'code': code}), file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
