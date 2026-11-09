"""Remove only the agreed test's Telegram attachments once their TTL expires."""
import json,sys,time
from pathlib import Path
sys.path.insert(0,'/opt/vpn-task10')
from broker import load_admins
from telegram_api import Telegram
from egress import Opener,dial_telegram

def main():
    path=Path('/var/lib/vpn-task10-broker/acceptance-messages.json')
    if not path.exists():print('{"test_attachments_removed":0}');return
    record=json.loads(path.read_text())
    assert record['chat'] in load_admins('/etc/vpn-task10/admins.json')
    if time.time()<record['created']+600:print('{"test_attachment_ttl_pending":true}');return
    api=Telegram(Path('/etc/vpn-task10/token').read_text().strip(),opener=Opener(dial_telegram))
    for mid in record['message_ids']:
        assert type(mid)==int
        api.call('deleteMessage',{'chat_id':record['chat'],'message_id':mid})
    path.unlink();print(json.dumps({'test_attachments_removed':len(record['message_ids'])}))
if __name__=='__main__':
    try:main()
    except Exception:
        print('{"test_attachment_cleanup":"retry_required"}');raise SystemExit(1)
