"""Validate protected Windows intake without ever displaying credentials."""
import json,os
from pathlib import Path
from telegram_api import Telegram,ApiError

def main():
    path=Path(os.environ['LOCALAPPDATA'])/'vpn-ru-fr/task10/credentials.json'
    record=json.loads(path.read_text())
    api=Telegram(record['token'])
    me=api.call('getMe')
    webhook=bool(api.call('getWebhookInfo').get('url'))
    print(json.dumps({'telegram_getme':True,'bot_username':me.get('username'),
                      'existing_webhook':webhook}))
if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(json.dumps({'telegram_getme':False,'category':str(exc) if isinstance(exc,ApiError) else type(exc).__name__}))
        raise SystemExit(1)
