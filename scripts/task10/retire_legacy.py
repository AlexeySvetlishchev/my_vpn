"""Owner-approved retirement of ONLY Test/iPhone using the normal vpnctl.

No SQL writes, direct AWG commands or secret reads. Revocation is terminal.
The legacy tombstone/user stay as activation/startup/backup identity anchors.
"""
import json
from pathlib import Path
import subprocess
import sys


def cli(*args):
    proc=subprocess.run(['/usr/local/sbin/vpnctl','--json',*args],
                        stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=60,check=True)
    value=json.loads(proc.stdout)
    assert value['ok']
    return value['data']


def inspect(status,user):
    old=next(d for d in status['devices'] if d['profile']=='Test_iPhone')
    records=[d for d in user['devices'] if d['profile_name']=='Test_iPhone']
    assert len(records)==1
    row=records[0]
    assert row['id']==old['id'] and row['ipv4']==old['ipv4']=='10.203.253.2' and row['origin']=='task07'
    # Require independent established client activity, not a database row alone.
    permanent=[d for d in status['devices'] if d['id']!=old['id'] and d['state']=='enabled'
               and d['present_in_awg'] and d['handshake_age_seconds'] is not None
               and 0<=d['handshake_age_seconds']<=600
               and d['rx_bytes']>0 and d['tx_bytes']>0]
    assert permanent,'no_independently_established_permanent_profile'
    assert not any(status['drift'].values()) and all(status['services'].values())
    return old,permanent


def verify_preserved(before,after,legacy_id):
    current={d['id']:d for d in after['devices']}
    for d in before['devices']:
        if d['id']==legacy_id:continue
        other=current[d['id']]
        assert all(other[k]==d[k] for k in ('profile','ipv4','state','present_in_awg'))
    old=current[legacy_id]
    assert old['state']=='revoked' and not old['present_in_awg']
    assert not any(after['drift'].values()) and all(after['services'].values())


def main():
    before=cli('status');user=cli('user','show','Test')
    old,permanent=inspect(before,user)
    backup=None
    if old['state']!='revoked':
        backup=cli('backup')['path']
        assert cli('restore','--check',backup)['valid']
        # This is the sole peer mutation. Never delete/revoke a different target.
        cli('device','revoke','Test','iPhone')
    # Retain the required identity anchor, but make an otherwise empty test
    # account inactive. Never disable a user with any additional device.
    if len(user['devices'])==1 and user.get('state')=='enabled':
        cli('user','disable','Test')
    cli('reconcile')
    after=cli('status');verify_preserved(before,after,old['id'])
    diagnostic=cli('diagnostics')
    assert not diagnostic['incomplete_operations']
    # Verify the actual installed startup reader won't resurrect the old peer.
    sys.path.insert(0,'/opt/vpn-task09')
    import importlib.machinery,importlib.util
    loader=importlib.machinery.SourceFileLoader('retirement_startup_reader','/usr/local/sbin/vpn-task07')
    spec=importlib.util.spec_from_loader(loader.name,loader)
    helper=importlib.util.module_from_spec(spec);loader.exec_module(helper)
    public=Path('/etc/vpn-task07/client.pub').read_text().strip()  # public identity only
    startup=dict(helper.startup_peers(public))
    assert public not in startup and len(startup)==after['present_in_awg']
    print(json.dumps({'revoked':'Test_iPhone','removed_from_live_awg':True,
                      'not_restored_by_startup_or_reconcile':True,'other_devices_preserved':True,
                      'permanent_profiles_with_observed_traffic':[d['profile'] for d in permanent],
                      'Test_user_retained':'activation_startup_backup_identity_dependency',
                      'Test_user_state':cli('user','show','Test')['state'],
                      'device_record_retained':'audit_tombstone_no_device_delete_command',
                      'protected_backup':backup,'manager_healthy':True}))


if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(json.dumps({'legacy_retirement':False,'category':type(exc).__name__}));raise SystemExit(1)
