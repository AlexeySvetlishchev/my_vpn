#!/usr/bin/python3
"""Finalize only the export name and read-only rollback preflight.

No real export, peer, DB, network or unit configuration operation. Only TASK10
bot/broker restart. Prior protected files are retained for addressed rollback.
"""
import json
import os
from pathlib import Path
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
import update_export as base

EXPECTED = {
    'task09/manager_formats.py':'03a1a251cc8fe55d7febf128e12b958af12ab121d866c303d9dbeea45f0a4e36',
    'task10/rollback_entry.py':'f4c2407961770d91c4f5dfee7990584078123a9d3033f2bacb24f531ae1f7cd1',
}


def main():
    assert os.geteuid()==0
    if len(sys.argv)==3 and sys.argv[1]=='--rollback':
        backup=Path(sys.argv[2]).resolve()
        assert backup.parent==base.BACKUPS and backup.name.startswith('export-final-')
        base.restore(backup)
        print('{"name_update_rolled_back":true}')
        return
    assert len(sys.argv)==1
    src=Path(__file__).resolve().parent.parent
    hashes=json.loads((src/'final-sha256.json').read_text())
    assert set(hashes)==set(EXPECTED)|{'task10/manifest.json'}
    previous={};updated={};record={}
    for name,digest in hashes.items():
        content=(src/name).read_bytes()
        assert base.sha(content)==digest
        if name.endswith('.py'):compile(content,name,'exec')
        old=base.public_file(base.target(name))
        if name in EXPECTED:assert base.sha(old)==EXPECTED[name]
        previous[name]=old;updated[name]=content
        record[name]={'before':base.sha(old),'installed':digest}
    # This module's sole source difference must be its name constant.
    name='task09/manager_formats.py'
    before=previous[name].decode().splitlines();after=updated[name].decode().splitlines()
    assert len(before)==len(after)
    differences=[(a,b) for a,b in zip(before,after) if a!=b]
    assert len(differences)==1 and all(line.startswith('SERVER_DISPLAY_NAME = ') for line in differences[0])
    old_manifest=json.loads(previous['task10/manifest.json'])
    manifest=json.loads(updated['task10/manifest.json'])
    assert old_manifest.keys()==manifest.keys()
    assert all(old_manifest[k]==manifest[k] for k in manifest if k!='rollback_entry.py')
    assert old_manifest['rollback_entry.py']==EXPECTED['task10/rollback_entry.py']
    assert manifest['rollback_entry.py']==hashes['task10/rollback_entry.py']
    base.health();peers=base.peers();state=base.unchanged_snapshot()
    backup=base.BACKUPS/('export-final-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime()))
    backup.mkdir(mode=0o700)
    for name,data in previous.items():base.publish(backup/name.replace('/','--'),data,0o600)
    base.publish(backup/'baseline.json',(json.dumps(record,sort_keys=True)+'\n').encode(),0o600)
    sys.path.insert(0,'/opt/vpn-task09')
    from manager_lock import process_lock
    stopped=False
    try:
        base.system('stop',base.BOT);base.system('stop',base.BROKER);stopped=True
        with process_lock():
            for name,data in updated.items():base.publish(base.target(name),data,0o644)
        base.start();base.health()
        assert base.peers()==peers and base.unchanged_snapshot()==state
        for name,digest in hashes.items():assert base.sha(base.public_file(base.target(name)))==digest
        print(json.dumps({'name_update':True,'peers_unchanged':True,'vpn_network_unchanged':True,
                          'telegram_connected':True,'backup':str(backup)}))
    except BaseException:
        if stopped:
            base.system('stop',base.BOT);base.system('stop',base.BROKER)
            with process_lock():
                for name,data in previous.items():base.publish(base.target(name),data,0o644)
            base.start();base.health()
        raise


if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(json.dumps({'name_update':False,'category':type(exc).__name__}));raise SystemExit(1)
