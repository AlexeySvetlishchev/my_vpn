"""Administrative inline UI; no VPN configuration, keys, SQLite or root access."""
import base64
import json
import os
from pathlib import Path
import secrets
import socket
import time
import uuid

from telegram_api import Telegram, ApiError
from broker import load_admins
from qr import profile_qr


class Refused(Exception):pass


class BrokerClient:
    def __call__(self,admin,chat,action,args):
        request={'id':uuid.uuid4().hex,'admin':admin,'chat':chat,'action':action,'args':list(args)}
        try:
            with socket.socket(socket.AF_UNIX) as conn:
                conn.settimeout(90)
                conn.connect('/run/vpn-task10-broker/manager.sock')
                conn.sendall(json.dumps(request).encode()+b'\n')
                with conn.makefile('rb') as stream:raw=stream.readline(262145)
            if len(raw)>262144:raise Refused('response_bound')
            reply=json.loads(raw)
            if not reply.get('ok'):raise Refused(reply.get('code','operation_failed'))
            return reply['data']
        except Refused:raise
        except Exception:raise Refused('broker_unavailable') from None


class State:
    def __init__(self,path):
        self.path=Path(path)
        self.value=json.loads(self.path.read_text()) if self.path.exists() else {'offset':0,'deletions':[]}
    def save(self):
        temp=self.path.with_suffix('.new')
        fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as f:
            json.dump(self.value,f);f.flush();os.fsync(f.fileno())
        os.replace(temp,self.path)
        fd=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    def claim(self,uid):
        if type(uid)!=int or uid<self.value['offset']:return False
        self.value['offset']=uid+1;self.save();return True


ERRORS={'name_conflict':'Такое имя уже занято.', 'device_conflict':'Имя устройства уже занято.',
        'invalid_name':'Имя: 1–32 буквы/цифры, первая — буква; без пробелов и подчёркивания.',
        'revoked':'Отозванное устройство нельзя включить: создайте новое.',
        'user_disabled':'Сначала включите пользователя.', 'device_disabled':'Сначала включите устройство и пользователя.',
        'busy':'Manager занят. Проверьте состояние и повторите действие.',
        'broker_unavailable':'Manager недоступен. VPN продолжает работать; обратитесь к CLI.',
        'not_found':'Объект больше не найден. Обновите список.'}

LABELS={'enabled':'включён','disabled':'отключён','revoked':'доступ отозван'}
VERBS={'user.disable':'отключить пользователя и все его устройства',
       'user.delete':'удалить пользователя и отозвать доступ всех его устройств',
       'device.disable':'отключить устройство','device.revoke':'безвозвратно отозвать доступ устройства'}
def speed(value):return 'не задан' if value is None else f'{value/1000000:g} Мбит/с'
HOME='nav:home'
HOME_LABEL='🏠 Главное меню'


class UI:
    def __init__(self,api,manager,admins,state,clock=time.time):
        self.api=api;self.manager=manager;self.admins=set(admins);self.state=state;self.clock=clock
        self.buttons={};self.pending={};self.rate={};self.force_new_panel=set();self.notices={}
        self.panels=self.state.value.setdefault('panels',{})
    def ask(self,uid,action,*args):return self.manager(uid,uid,action,args)
    def cancel(self,uid):
        self.pending.pop(uid,None)
        self.buttons={k:v for k,v in self.buttons.items() if v[1]!=uid}
        self.notices.pop(uid,None)
    def button(self,uid,label,action,*args):
        # Home is always a harmless cancellation, including on older attachments.
        # It never contains an old action/target and still requires private admin auth.
        if action=='home':return {'text':label,'callback_data':HOME}
        self.buttons={k:v for k,v in self.buttons.items() if v[0]>self.clock()}
        token=secrets.token_urlsafe(18)
        self.buttons[token]=(self.clock()+600,uid,action,args)
        return {'text':label,'callback_data':token}
    def send(self,uid,text,rows=()):
        rows=[list(row) for row in rows]
        # Every view, error and prompt gets exactly one explicit Home button.
        rows=[[b for b in row if b.get('callback_data')!=HOME] for row in rows]
        rows=[row for row in rows if row]
        rows.append([self.button(uid,HOME_LABEL,'home')])
        active={b['callback_data'] for row in rows for b in row}
        self.buttons={k:v for k,v in self.buttons.items() if v[1]!=uid or k in active}
        notice=self.notices.pop(uid,None)
        if notice:text=notice+'\n\n'+text
        payload={'chat_id':uid,'text':text[:4000],'reply_markup':{'inline_keyboard':rows}}
        old=self.panels.get(str(uid));move=uid in self.force_new_panel
        self.force_new_panel.discard(uid)
        if old and not move:
            try:return self.api.call('editMessageText',{**payload,'message_id':old})
            except ApiError as exc:
                # An old/deleted/uneditable panel can be replaced. A network
                # timeout is ambiguous, so never amplify it with a second send.
                if str(exc)!='telegram_http_400':raise
        result=self.api.call('sendMessage',{**payload,'protect_content':True})
        self.panels[str(uid)]=result['message_id'];self.state.save()
        if old and old!=result['message_id']:
            try:self.api.call('deleteMessage',{'chat_id':uid,'message_id':old})
            except ApiError:pass  # Its callbacks were already invalidated locally.
        return result
    def home(self,uid,notice=None):
        self.cancel(uid)
        self.send(uid,(notice+'\n\n' if notice else '')+'VPN Manager — управление пользователями и устройствами.',[
            [self.button(uid,'👥 Пользователи','users',0)],
            [self.button(uid,'➕ Создать пользователя','newuser')],
            [self.button(uid,'📊 Статус VPN','status')]])
    def users(self,uid,page=0):
        rows=self.ask(uid,'user.list');start=max(0,page)*8
        buttons=[[self.button(uid,('🟢 ' if u['state']=='enabled' else '⏸ ')+u['name'],'user',u['name'])]
                 for u in rows[start:start+8]]
        nav=[]
        if page:nav.append(self.button(uid,'←','users',page-1))
        if start+8<len(rows):nav.append(self.button(uid,'→','users',page+1))
        if nav:buttons.append(nav)
        buttons += [[self.button(uid,'➕ Пользователь','newuser')],[self.button(uid,'🏠 Главное меню','home')]]
        self.send(uid,f'Пользователей: {len(rows)}',buttons)
    def user(self,uid,name,page=0):
        user=self.ask(uid,'user.show',name);devices=user['devices'];start=max(0,page)*8
        rows=[[self.button(uid,d['name']+' · '+LABELS.get(d['state'],d['state']),'device',name,d['name'])]
              for d in devices[start:start+8]]
        nav=[]
        if page:nav.append(self.button(uid,'←','user',name,page-1))
        if start+8<len(devices):nav.append(self.button(uid,'→','user',name,page+1))
        if nav:rows.append(nav)
        rows.append([self.button(uid,'➕ Устройство','newdevice',name)])
        if user['state']=='enabled':rows.append([self.button(uid,'⏸ Отключить пользователя','confirm','user.disable',name)])
        else:rows.append([self.button(uid,'▶ Включить пользователя','change','user.enable',name)])
        rows += [[self.button(uid,'🗑 Удалить пользователя','confirm','user.delete',name)],
                 [self.button(uid,'← Пользователи','users',0)]]
        self.send(uid,f"{name} · {LABELS.get(user['state'],user['state'])}\nУстройств: {len(devices)}\n"
                  f"Заданные лимиты ↑ {speed(user['limit_up_bps'])} / ↓ {speed(user['limit_down_bps'])}\n"
                  'QoS пока не применяется.',rows)
    def device(self,uid,user,name):
        d=self.ask(uid,'device.show',user,name)
        metrics=next((x for x in self.ask(uid,'status')['devices'] if x['id']==d['id']),{})
        rows=[]
        if d['state']!='revoked':
            if d['state']=='enabled':rows.append([self.button(uid,'⏸ Отключить','confirm','device.disable',user,name)])
            else:rows.append([self.button(uid,'▶ Включить','change','device.enable',user,name)])
            rows += [[self.button(uid,'📲 AmneziaVPN: профиль и QR','confirm','device.export.amnezia',user,name)],
                     [self.button(uid,'📄 Совместимый .conf и QR','confirm','device.export',user,name)],
                     [self.button(uid,'🚫 Отозвать доступ','confirm','device.revoke',user,name)]]
        rows.append([self.button(uid,'← Устройства','user',user,0)])
        age=metrics.get('handshake_age_seconds')
        self.send(uid,f"{d['profile_name']} · {LABELS.get(d['state'],d['state'])}\nIP: {d['ipv4']}\n"
                  f"В AWG: {'да' if metrics.get('present_in_awg') else 'нет'}; "
                  f"свежий handshake: {'да' if metrics.get('connected_recently') else 'нет'}\n"
                  f"Handshake: {str(age)+' с назад' if age is not None else 'не было'}\n"
                  f"RX/TX: {metrics.get('rx_bytes',0)}/{metrics.get('tx_bytes',0)} байт\n"
                  f"Лимиты устройства ↑{speed(d['limit_up_bps'])} ↓{speed(d['limit_down_bps'])}\n"
                  f"С учётом пользователя ↑{speed(d['effective_limits']['up_bps'])} "
                  f"↓{speed(d['effective_limits']['down_bps'])}\nQoS пока не применяется.",rows)
    def status(self,uid):
        s=self.ask(uid,'status')
        text=(f"Пользователей: {s['registered_users']}; устройств: {s['registered_devices']}\n"
              f"Peers в AWG: {s['present_in_awg']}; свежий handshake: {s['connected_recently']}\n")
        labels={'awg_client':'Клиентский AWG','awg_transport':'RU↔FR','client_dns':'DNS',
                'task08_ownership':'Ownership','fail_closed_guards_configured':'Fail-closed guards'}
        text+='\n'.join(labels.get(k,k)+': '+('OK' if v else 'ПРОВЕРИТЬ') for k,v in s['services'].items())
        text+=f"\nСуммарно RX/TX: {sum(d['rx_bytes'] for d in s['devices'])}/{sum(d['tx_bytes'] for d in s['devices'])} байт"
        text+=f"\nDrift: {any(s['drift'].values())}; незавершённых операций: {s['pending_operations']}\n"
        text+='QoS пока не применяется. Handshake и счётчики — с текущего запуска AWG.'
        self.send(uid,text,[[self.button(uid,'Обновить','status')],[self.button(uid,'🏠 Главное меню','home')]])
    def action(self,uid,action,args):
        if action=='home':return self.home(uid)
        if action=='users':return self.users(uid,*args)
        if action=='user':return self.user(uid,*args)
        if action=='device':return self.device(uid,*args)
        if action=='status':return self.status(uid)
        if action in ('newuser','newdevice'):
            self.pending[uid]=(self.clock()+300,action,args)
            return self.send(uid,'Введите имя (1–32 буквы/цифры, первая — буква).')
        if action=='confirm':
            verb=args[0]
            text=('Профиль содержит приватный ключ и будет отправлен в этот личный чат. '
                  'Telegram — облачный канал, не секретный чат. Сообщение будет удалено примерно через 10 минут.'
                  if verb in ('device.export','device.export.amnezia') else 'Подтвердить: '+VERBS.get(verb,verb)+' — '+' / '.join(args[1:])+'?')
            return self.send(uid,text,[[self.button(uid,'Подтвердить','change',*args)]])
        if action=='change':
            verb,*target=args
            data=self.ask(uid,verb,*target)
            if verb in ('device.export','device.export.amnezia'):
                profile=base64.b64decode(data['content'],validate=True)
                # Native QR importer expects base64(qCompress(JSON)), without URI
                # prefix. Raw .conf QR bytes are deliberately unchanged.
                native=verb=='device.export.amnezia'
                if native and not profile.startswith(b'vpn://'):raise ValueError('invalid_native_export')
                image=profile_qr(profile[6:] if native else profile)
                self.force_new_panel.add(uid)
                markup={'inline_keyboard':[[self.button(uid,HOME_LABEL,'home')]]}
                caption=(data['display_name']+' · AmneziaVPN' if native else 'Совместимый AmneziaWG .conf (имя задаёт приложение)')
                result=self.api.call('sendDocument',{'chat_id':uid,'caption':caption+'. Не пересылайте посторонним.',
                                                     'reply_markup':markup},document=(data['filename'],profile))
                self.state.value['deletions'].append([self.clock()+600,uid,result['message_id']]);self.state.save()
                qr_result=self.api.call('sendPhoto',{'chat_id':uid,'caption':'QR того же профиля; содержит приватный ключ.',
                                                    'reply_markup':markup},
                                        document=(str(Path(data['filename']).with_suffix('.png')),image))
                self.state.value['deletions'].append([self.clock()+600,uid,qr_result['message_id']]);self.state.save()
                return self.device(uid,*target)
            self.notices[uid]='Операция выполнена.'
            if verb=='user.delete':return self.users(uid)
            if verb.startswith('device.'):return self.device(uid,*target)
            return self.user(uid,target[0])
        raise Refused('unknown_action')
    def handle(self,update):
        cb=update.get('callback_query')
        msg=cb.get('message',{}) if isinstance(cb,dict) else update.get('message',{})
        sender=cb.get('from',{}) if isinstance(cb,dict) else msg.get('from',{})
        uid=sender.get('id');chat=msg.get('chat',{})
        if (type(uid)!=int or uid not in self.admins or sender.get('is_bot') or
                chat.get('type')!='private' or type(chat.get('id'))!=int or chat.get('id')!=uid):return
        if not self.state.claim(update.get('update_id')):return
        now=self.clock();recent=[t for t in self.rate.get(uid,[]) if t>now-60]
        is_home=isinstance(cb,dict) and cb.get('data')==HOME
        if len(recent)>=20 and not is_home:
            if cb:self.api.call('answerCallbackQuery',{'callback_query_id':cb['id'],'text':'Слишком часто. Подождите минуту.'})
            return
        self.rate[uid]=recent+[now]
        try:
            if cb:
                token=cb.get('data');entry=self.buttons.get(token) if isinstance(token,str) else None
                self.api.call('answerCallbackQuery',{'callback_query_id':cb['id']})
                if msg.get('message_id')!=self.panels.get(str(uid)):
                    self.force_new_panel.add(uid)
                if token==HOME:return self.home(uid)
                if not entry or entry[0]<now or entry[1]!=uid:
                    # Stale actions never run or leave a hidden name-input flow.
                    return self.home(uid,'Кнопка устарела или уже использована.')
                self.cancel(uid)  # Invalidate the entire previous view before work.
                return self.action(uid,entry[2],entry[3])
            text=msg.get('text','')
            if not isinstance(text,str):return
            self.force_new_panel.add(uid)
            if text in ('/start','/menu'):return self.home(uid)
            pending=self.pending.pop(uid,None)
            if not pending or pending[0]<now:return self.home(uid)
            if len(text)>32 or not text or not text[0].isalpha() or not text.isalnum():
                self.pending[uid]=pending
                raise Refused('invalid_name')
            self.cancel(uid)
            if pending[1]=='newuser':
                self.ask(uid,'user.add',text);return self.user(uid,text)
            self.ask(uid,'device.add',pending[2][0],text)
            return self.device(uid,pending[2][0],text)
        except (Refused,ApiError,ValueError,OSError) as exc:
            if not isinstance(exc,Refused) or str(exc)!='invalid_name':self.cancel(uid)
            text=ERRORS.get(str(exc),'Операция не подтверждена. Проверьте текущее состояние перед повтором.') if isinstance(exc,Refused) else 'Операция не подтверждена. Проверьте текущее состояние перед повтором.'
            return self.send(uid,text)
    def cleanup(self):
        remaining=[]
        for when,chat,mid in self.state.value['deletions']:
            if when>self.clock():remaining.append([when,chat,mid]);continue
            try:self.api.call('deleteMessage',{'chat_id':chat,'message_id':mid})
            except ApiError:
                # Retry during the Telegram deletion window, without message content.
                if self.clock()-when<3600:remaining.append([when,chat,mid])
        self.state.value['deletions']=remaining;self.state.save()


def main():
    profile_qr(b'task10-self-check-no-secret')
    credential=Path(os.environ['CREDENTIALS_DIRECTORY'])
    admins=load_admins(credential/'admins',strict=False)
    from egress import Opener,request_fd
    api=Telegram((credential/'token').read_text().strip(),opener=Opener(lambda:request_fd(min(admins))))
    state=State(Path(os.environ['STATE_DIRECTORY'])/'state.json')
    api.call('getMe')
    if api.call('getWebhookInfo').get('url'):raise RuntimeError('existing_webhook_refused')
    ui=UI(api,BrokerClient(),admins,state)
    print('telegram_connected',flush=True)
    while True:
        try:
            ui.cleanup()
            updates=api.call('getUpdates',{'offset':state.value['offset'],'timeout':25,'limit':20,
                                         'allowed_updates':['message','callback_query']})
            for update in updates:
                # Save the polling offset even for unauthorized updates, without
                # executing them. Authorized actions reserve offset before work.
                try:ui.handle(update)
                except Exception:print('update_failed_check_state_before_retry',flush=True)
                finally:
                    if type(update.get('update_id'))==int and update['update_id']>=state.value['offset']:
                        state.claim(update['update_id'])
        except Exception:
            print('telegram_poll_failed',flush=True);time.sleep(5)

if __name__=='__main__':
    try:main()
    except Exception:
        print('bot_start_failed',flush=True);raise SystemExit(1)
