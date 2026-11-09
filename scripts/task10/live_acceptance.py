#!/usr/bin/python3
"""Owner-approved TelegramTest/Phone integration, no other peer mutation."""
import base64,hashlib,json,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,'/opt/vpn-task10')
from broker import ManagerAPI,load_admins
from egress import Opener,dial_telegram
from telegram_api import Telegram,ApiError
from qr import profile_qr

STAGE='preflight'
def main():
    global STAGE
    admin=min(load_admins('/etc/vpn-task10/admins.json'))
    api=Telegram(Path('/etc/vpn-task10/token').read_text().strip(),opener=Opener(dial_telegram))
    manager=ManagerAPI();invoke=lambda action,*args:manager(action,list(args),admin)
    users=invoke('user.list')
    if any(u['name'].casefold()=='telegramtest' for u in users):raise RuntimeError('test_user_already_exists')
    before=invoke('status');iphone=next(d for d in before['devices'] if d['profile']=='Test_iPhone')
    paths=[Path('/etc/vpn-task07')/n for n in ('client.pub','client.key','server.key','Test_iPhone.conf')]
    identities={p:hashlib.sha256(p.read_bytes()).digest() for p in paths}
    STAGE='telegram_intro'
    api.call('sendMessage',{'chat_id':admin,'text':'TASK 10: начинаю согласованный тест TelegramTest/Phone. Test_iPhone не меняется.','protect_content':True})
    backup=json.loads(subprocess.check_output(['/usr/local/sbin/vpnctl','--json','backup']))['data']['path']
    created=False;messages=[];results={}
    try:
        STAGE='user_add';invoke('user.add','TelegramTest');created=True
        STAGE='device_add';device=invoke('device.add','TelegramTest','Phone')
        did=device['id'];assert device['state']=='enabled'
        assert any(d['id']==did and d['present_in_awg'] for d in invoke('status')['devices'])
        STAGE='profile_export';profile=invoke('device.export','TelegramTest','Phone')
        payload=base64.b64decode(profile['content'],validate=True);image=profile_qr(payload)
        for method,name,content in [('sendDocument',profile['filename'],payload),('sendPhoto','TelegramTest_Phone.png',image)]:
            STAGE='telegram_'+method
            sent=api.call(method,{'chat_id':admin,'caption':'ТЕСТ: TelegramTest/Phone — профиль будет отозван после проверки.'},document=(name,content))
            messages.append(sent['message_id'])
        results['conf_delivered']=True;results['qr_delivered']=True
        STAGE='device_disable';invoke('device.disable','TelegramTest','Phone')
        assert not any(d['id']==did and d['present_in_awg'] for d in invoke('status')['devices'])
        results['disable_removed_live_peer']=True
        STAGE='device_enable';invoke('device.enable','TelegramTest','Phone')
        assert any(d['id']==did and d['present_in_awg'] for d in invoke('status')['devices'])
        results['enable_restored_live_peer']=True
        STAGE='device_revoke';invoke('device.revoke','TelegramTest','Phone')
        assert not any(d['id']==did and d['present_in_awg'] for d in invoke('status')['devices'])
        results['revoke_removed_live_peer']=True
        STAGE='user_delete';invoke('user.delete','TelegramTest');created=False
        assert all(u['name']!='TelegramTest' for u in invoke('user.list'))
        after=invoke('status')
        assert not any(after['drift'].values())
        current=next(d for d in after['devices'] if d['profile']=='Test_iPhone')
        assert current['id']==iphone['id'] and current['ipv4']==iphone['ipv4'] and current['present_in_awg']
        assert all(hashlib.sha256(p.read_bytes()).digest()==value for p,value in identities.items())
        results['legacy_identity_unchanged']=True;results['test_user_deleted']=True
        # Persist only deletion metadata. Never persist the profile or QR here.
        target=Path('/var/lib/vpn-task10-broker/acceptance-messages.json')
        target.write_text(json.dumps({'chat':admin,'message_ids':messages,'created':time.time()})+'\n');target.chmod(0o600)
        api.call('sendMessage',{'chat_id':admin,'text':'Тест завершён: .conf и QR доставлены; disable/enable/revoke и удаление TelegramTest прошли. Тестовый профиль уже не действует. Откройте /start для меню.','protect_content':True})
        print(json.dumps({'passed':True,'checks':results,'backup':backup}))
    finally:
        if created:
            try:invoke('user.delete','TelegramTest')
            except Exception:print('{"test_cleanup":"requires_attention"}')

if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(json.dumps({'passed':False,'stage':STAGE,'category':str(exc) if isinstance(exc,ApiError) else type(exc).__name__}))
        raise SystemExit(1)
