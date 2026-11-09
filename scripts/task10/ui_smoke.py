"""Silent live renderer check; no user/device/peer operations are permitted."""
import json,sys,tempfile
from pathlib import Path
sys.path.insert(0,'/opt/vpn-task10')
from bot import UI,State
from broker import load_admins
from telegram_api import Telegram
from egress import Opener,dial_telegram

def main():
    admin=min(load_admins('/etc/vpn-task10/admins.json'))
    real=Telegram(Path('/etc/vpn-task10/token').read_text().strip(),opener=Opener(dial_telegram))
    calls=[]
    class API:
        def call(self,method,payload=None,document=None):
            calls.append(method);payload=dict(payload or {})
            if method=='sendMessage':payload['disable_notification']=True
            return real.call(method,payload,document)
    def forbidden(*args):raise AssertionError('Manager mutation/read not permitted in renderer check')
    with tempfile.TemporaryDirectory(prefix='task10-ui-smoke-') as folder:
        ui=UI(API(),forbidden,{admin},State(Path(folder)/'state.json'))
        try:
            ui.home(admin);panel=ui.panels[str(admin)]
            ui.action(admin,'newuser',())
            ui.home(admin)
            assert admin not in ui.pending
            assert ui.panels[str(admin)]==panel
            assert calls.count('sendMessage')==1 and calls.count('editMessageText')==2
            print(json.dumps({'live_ui_render':True,'sent_panels':1,'edited_panels':2,'scenario_cleared':True}))
        finally:
            mid=ui.panels.get(str(admin))
            if mid:real.call('deleteMessage',{'chat_id':admin,'message_id':mid})
if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(json.dumps({'live_ui_render':False,'category':type(exc).__name__}));raise SystemExit(1)
