#!/usr/bin/python3
"""Consume protected upload, validate Telegram identity, install credentials.

Only the bundle path is a process argument. No credential data is ever printed.
"""
import json,os,re,stat,subprocess,sys
from pathlib import Path
from telegram_api import Telegram,ApiError
STAGE='validate_bundle'

def main():
    global STAGE
    assert os.geteuid()==0 and len(sys.argv)==2
    source=Path(sys.argv[1])
    pending=Path('/etc/vpn-task10/pending-credentials.json')
    if (source not in (Path('/home/wolffrog/.task10-intake/credentials.json'),pending) or
            source.is_symlink() or not source.is_file() or
            stat.S_IMODE(source.stat().st_mode)!=0o600 or source.stat().st_size>8192 or
            source.parent.is_symlink() or stat.S_IMODE(source.parent.stat().st_mode)!=0o700):
        raise ValueError('invalid_bundle')
    if source==pending and source.stat().st_uid!=0:raise ValueError('invalid_pending_owner')
    record=json.loads(source.read_text())
    if set(record)!={'token','admin_ids'}:raise ValueError('invalid_bundle')
    ids=record['admin_ids']
    if not isinstance(ids,list) or not ids or any(type(x)!=int or x<=0 or x>=2**52 for x in ids):
        raise ValueError('invalid_admin_ids')
    from egress import Opener,dial_telegram
    api=Telegram(record['token'],opener=Opener(dial_telegram))
    STAGE='telegram_getme'
    me=api.call('getMe')
    STAGE='telegram_webhook_check'
    if not me.get('is_bot') or api.call('getWebhookInfo').get('url'):raise ValueError('bot_webhook_conflict')
    STAGE='install_credentials'
    root=Path('/etc/vpn-task10')
    root.mkdir(mode=0o700,exist_ok=True)
    for name,data in [('token',record['token']+'\n'),('admins.json',json.dumps({'admin_ids':ids})+'\n')]:
        tmp=root/(name+'.new')
        fd=os.open(tmp,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as f:f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(tmp,root/name)
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)
    source.unlink()
    STAGE='start_services'
    subprocess.run(['/usr/bin/systemctl','restart','vpn-task10-broker.service'],check=True)
    subprocess.run(['/usr/bin/systemctl','restart','vpn-task10-bot.service'],check=True)
    print(json.dumps({'telegram_getme':True,'bot_username':me.get('username'),
                      'credentials_installed':True,'upload_removed':True}))
if __name__=='__main__':
    try:main()
    except Exception as exc:
        category=str(exc) if isinstance(exc,ApiError) and re.fullmatch(r'telegram_[a-z_0-9]+',str(exc)) else type(exc).__name__
        print(json.dumps({'provisioned':False,'stage':STAGE,'category':category,
                          'error':'provision_failed_details_withheld'}))
        raise SystemExit(1)
