"""Offline Telegram UI/authorization/replay and real Manager-core tests."""
import base64
import copy
import importlib
import json
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import urllib.error
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts/task09'))
sys.path.insert(0,str(ROOT/'scripts/task10'))
import bot
import broker
from telegram_api import Telegram,ApiError,NoRedirect
from manager_db import Store
import vpnctl

ADMIN=123456789  # Synthetic fixture, never production configuration.

class FakeTelegram:
    def __init__(self):self.calls=[]
    def call(self,method,payload=None,document=None):
        self.calls.append((method,copy.deepcopy(payload),document))
        return {'message_id':len(self.calls)}

class FakeAwg:
    def __init__(self):self.live={}
    def peers(self):return dict(self.live)
    def add(self,key,ip):self.live[key]=ip
    def remove(self,key):self.live.pop(key,None)
    def metrics(self):return {},{}

class FakeVault:
    def create(self,did):return '/test-only/'+did,base64.b64encode(bytes.fromhex(did)*2).decode()

class Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)
        self.state=bot.State(self.path/'poll.json')
        self.api=FakeTelegram();self.calls=[];self.clock=[1000.]
        self.ui=bot.UI(self.api,lambda *a:self.calls.append(a),{ADMIN},self.state,lambda:self.clock[0])
    def message(self,text,uid=ADMIN,chat_type='private',update=1):
        return {'update_id':update,'message':{'from':{'id':uid},'chat':{'id':uid,'type':chat_type},'text':text}}
    def callback(self,token,uid=ADMIN,update=1):
        return {'update_id':update,'callback_query':{'id':str(update),'from':{'id':uid},'data':token,
                'message':{'chat':{'id':uid,'type':'private'},'message_id':1}}}
    def test_unknown_user_message_and_callback_denied(self):
        token=self.ui.button(ADMIN,'x','status')['callback_data']
        self.ui.handle(self.message('/start',uid=999))
        self.ui.handle(self.callback(token,uid=999))
        self.assertEqual(self.calls,[]);self.assertEqual(self.api.calls,[])
    def test_groups_and_supergroups_denied_even_admin(self):
        for kind in ('group','supergroup','channel'):
            self.ui.handle(self.message('/start',chat_type=kind))
        self.assertFalse(self.api.calls)
        token=self.ui.button(ADMIN,'x','status')['callback_data']
        cb=self.callback(token);cb['callback_query']['message']['chat']['type']='supergroup'
        self.ui.handle(cb);self.assertFalse(self.calls)
    def test_username_cannot_authorize_and_chat_must_equal_sender(self):
        m=self.message('/start',uid=999);m['message']['from']['username']='Owner'
        self.ui.handle(m)
        m=self.message('/start');m['message']['chat']['id']=999
        self.ui.handle(m);self.assertFalse(self.api.calls)
    def test_bool_userid_rejected(self):
        self.ui.admins={True};self.ui.handle(self.message('/start',uid=True));self.assertFalse(self.api.calls)
    def test_callback_single_use(self):
        token=self.ui.button(ADMIN,'x','change','user.disable','Ivan')['callback_data']
        self.ui.user=lambda *a:None
        self.ui.handle(self.callback(token,update=1));self.ui.handle(self.callback(token,update=2))
        self.assertEqual(len(self.calls),1)
    def test_callback_bound_to_admin_and_expires(self):
        self.ui.admins.add(999)
        token=self.ui.button(ADMIN,'x','change','user.disable','Ivan')['callback_data']
        self.ui.handle(self.callback(token,uid=999,update=1));self.assertFalse(self.calls)
        self.clock[0]+=601;self.ui.handle(self.callback(token,update=2));self.assertFalse(self.calls)
    def test_replayed_update_ignored_after_restart(self):
        self.ui.handle(self.message('/start'))
        state=bot.State(self.path/'poll.json')
        self.assertFalse(state.claim(1));self.assertTrue(state.claim(2))
    def test_pre_restart_buttons_do_not_survive_restart(self):
        token=self.ui.button(ADMIN,'x','change','user.delete','Ivan')['callback_data']
        restarted=bot.UI(self.api,lambda *a:self.calls.append(a),{ADMIN},self.state)
        restarted.handle(self.callback(token));self.assertFalse(self.calls)
    def test_admin_config_only_accepts_numeric_positive_ids(self):
        p=self.path/'admins.json'
        for value in ({'admin_ids':[]},{'admin_ids':['123']},{'admin_ids':[True]},
                      {'admin_ids':[-1]},{'admin_ids':[ADMIN],'username':'Owner'}):
            p.write_text(json.dumps(value))
            with self.assertRaises(ValueError):broker.load_admins(p,strict=False)
        p.write_text(json.dumps({'admin_ids':[ADMIN]}))
        self.assertEqual(broker.load_admins(p,strict=False),{ADMIN})
    def test_dangerous_action_requires_separate_confirmation(self):
        token=self.ui.button(ADMIN,'delete','confirm','user.delete','Ivan')['callback_data']
        self.ui.handle(self.callback(token));self.assertFalse(self.calls)
        confirm=self.api.calls[-1][1]['reply_markup']['inline_keyboard'][0][0]['callback_data']
        self.ui.users=lambda *a:None
        self.ui.handle(self.callback(confirm,update=2));self.assertEqual(self.calls[0][2],'user.delete')
    def test_name_input_invalid_does_not_reach_manager(self):
        self.ui.action(ADMIN,'newuser',())
        self.ui.handle(self.message('--help'));self.assertFalse(self.calls)
    def test_request_rate_limit(self):
        self.ui.action=lambda *a:self.calls.append(a)
        for i in range(25):
            token=self.ui.button(ADMIN,'x','status')['callback_data']
            self.ui.handle(self.callback(token,update=i+1))
        self.assertEqual(len(self.calls),20)
    def test_durable_broker_replay_guard(self):
        guard=broker.ReplayGuard(self.path/'ids')
        guard.reserve('a'*32)
        with self.assertRaises(broker.RequestError):broker.ReplayGuard(self.path/'ids').reserve('a'*32)
    def request(self,**kwargs):
        r={'id':'a'*32,'admin':ADMIN,'chat':ADMIN,'action':'user.list','args':[]};r.update(kwargs);return r
    def test_broker_rejects_outsider_group_arbitrary_command_flags(self):
        for r in [self.request(admin=999),self.request(chat=-1),self.request(action='restore'),
                  self.request(action='user.add',args=['--help']),self.request(action='reconcile')]:
            with self.subTest(r=r),self.assertRaises(broker.RequestError):broker.validate_request(r,{ADMIN})
    def test_broker_sanitizes_error_without_profile_or_token(self):
        def bad(*a):raise RuntimeError('private material must not escape')
        r=broker.dispatch(self.request(),{ADMIN},broker.ReplayGuard(self.path/'ids'),bad)
        self.assertEqual(r,{'ok':False,'code':'operation_failed'})
    def test_kernel_peer_uid_and_cgroup_are_both_required(self):
        class Conn:
            def getsockopt(self,*a):return struct.pack('3i',42,65534,65534)
        proc=self.path/'42';proc.mkdir();cg=proc/'cgroup'
        cg.write_text('0::/system.slice/other.service\n')
        self.assertFalse(broker.approved_peer(Conn(),self.path))
        cg.write_text('0::/system.slice/vpn-task10-bot.service\n')
        self.assertTrue(broker.approved_peer(Conn(),self.path))
    def test_real_manager_core_user_device_lifecycle_isolated(self):
        store=Store(self.path/'manager.sqlite3',enforce_ownership=False);self.addCleanup(store.close)
        awg=FakeAwg()
        def manager(uid,chat,action,args):
            parsed=vpnctl.parser().parse_args(action.split('.')+list(args))
            return vpnctl.execute(parsed,store,awg,FakeVault(),require_activation=lambda s:True,include_services=False)
        self.ui.manager=manager;self.ui.user=lambda *a:None
        self.ui.action(ADMIN,'newuser',());self.ui.handle(self.message('Ivan',update=1))
        self.assertEqual(store.user('Ivan')['state'],'enabled')
        self.ui.device=lambda *a:None
        self.ui.action(ADMIN,'newdevice',('Ivan',));self.ui.handle(self.message('Phone',update=2))
        self.assertEqual(len(awg.peers()),1)
        self.ui.action(ADMIN,'change',('user.disable','Ivan'));self.assertFalse(awg.peers())
        self.ui.action(ADMIN,'change',('user.enable','Ivan'));self.assertEqual(len(awg.peers()),1)
        self.ui.action(ADMIN,'change',('device.revoke','Ivan','Phone'));self.assertFalse(awg.peers())
    def test_menu_device_metrics_and_qos_navigation(self):
        device={'id':'d','name':'Phone','profile_name':'Ivan_Phone','state':'enabled',
                'ipv4':'10.203.253.4','limit_up_bps':1000000,'limit_down_bps':None,
                'effective_limits':{'up_bps':1000000,'down_bps':None,'enforced':False}}
        status={'registered_users':1,'registered_devices':1,'present_in_awg':1,'connected_recently':0,
                'devices':[{'id':'d','rx_bytes':123,'tx_bytes':456,'handshake_age_seconds':None,
                            'present_in_awg':True,'connected_recently':False}],
                'services':{'awg_client':True},'drift':{},'pending_operations':0}
        user={'name':'Ivan','state':'enabled','devices':[device],
              'limit_up_bps':None,'limit_down_bps':None}
        self.ui.manager=lambda uid,chat,action,args:{'user.list':[user],'user.show':user,
                    'device.show':device,'status':status}[action]
        self.ui.home(ADMIN);self.ui.users(ADMIN);self.ui.user(ADMIN,'Ivan')
        self.ui.device(ADMIN,'Ivan','Phone');self.ui.status(ADMIN)
        texts='\n'.join(c[1].get('text','') for c in self.api.calls)
        self.assertIn('123/456',texts);self.assertIn('QoS пока не применяется',texts)
        for call in self.api.calls:
            for row in call[1].get('reply_markup',{}).get('inline_keyboard',[]):
                for button in row:self.assertLessEqual(len(button['callback_data'].encode()),64)
    def test_home_exists_on_every_render_prompt_confirmation_and_error(self):
        self.ui.home(ADMIN)
        self.ui.action(ADMIN,'newuser',())
        self.ui.action(ADMIN,'newdevice',('Ivan',))
        self.ui.action(ADMIN,'confirm',('device.revoke','Ivan','Phone'))
        self.ui.action(ADMIN,'confirm',('device.export','Ivan','Phone'))
        self.ui.send(ADMIN,'Ошибка')
        renders=[c for c in self.api.calls if c[0] in ('sendMessage','editMessageText')]
        self.assertEqual(len(renders),6)
        for _,payload,_ in renders:
            homes=[b for row in payload['reply_markup']['inline_keyboard'] for b in row
                   if b['text']==bot.HOME_LABEL]
            self.assertEqual(homes,[{'text':bot.HOME_LABEL,'callback_data':bot.HOME}])
    def test_home_cancels_name_entry_and_retires_confirmation_tokens(self):
        self.ui.home(ADMIN)
        self.ui.action(ADMIN,'confirm',('user.delete','Ivan'))
        old=next(k for k,v in self.ui.buttons.items() if v[2]=='change')
        self.ui.pending[ADMIN]=(2000,'newuser',())
        self.ui.handle(self.callback(bot.HOME,update=1))
        self.assertNotIn(ADMIN,self.ui.pending)
        self.assertNotIn(old,self.ui.buttons)
        self.ui.handle(self.callback(old,update=2))
        self.ui.handle(self.message('MustNotBeCreated',update=3))
        self.assertEqual(self.calls,[])
    def test_rendering_new_view_retires_previous_view_actions(self):
        self.ui.action(ADMIN,'confirm',('user.delete','Ivan'))
        stale=next(k for k,v in self.ui.buttons.items() if v[2]=='change')
        self.ui.action(ADMIN,'newuser',())
        self.ui.handle(self.callback(stale,update=1))
        self.assertEqual(self.calls,[])
        self.assertNotIn(ADMIN,self.ui.pending)
    def test_home_does_not_cancel_another_admin_and_bypasses_rate_limit(self):
        self.ui.admins.add(999)
        self.ui.pending[ADMIN]=(2000,'newuser',())
        self.ui.pending[999]=(2000,'newuser',())
        other=self.ui.button(999,'safe','status')['callback_data']
        self.ui.rate[ADMIN]=[self.clock[0]]*20
        self.ui.handle(self.callback(bot.HOME))
        self.assertNotIn(ADMIN,self.ui.pending)
        self.assertIn(999,self.ui.pending)
        self.assertIn(other,self.ui.buttons)
        self.assertFalse(self.calls)
    def test_same_panel_is_edited_instead_of_duplicate_messages(self):
        self.ui.home(ADMIN);self.ui.action(ADMIN,'newuser',())
        self.ui.action(ADMIN,'confirm',('user.delete','Ivan'))
        self.assertEqual(sum(c[0]=='sendMessage' for c in self.api.calls),1)
        self.assertEqual(sum(c[0]=='editMessageText' for c in self.api.calls),2)
    def test_deleted_panel_recreated_and_old_actions_stay_retired(self):
        self.ui.home(ADMIN)
        old_token=next(k for k,v in self.ui.buttons.items() if v[2]=='newuser')
        original=self.api.call
        def fail_edit(method,*a,**kw):
            if method=='editMessageText':raise ApiError('telegram_http_400')
            return original(method,*a,**kw)
        self.api.call=fail_edit
        self.ui.action(ADMIN,'confirm',('user.delete','Ivan'))
        self.assertNotIn(old_token,self.ui.buttons)
        self.assertEqual(sum(c[0]=='sendMessage' for c in self.api.calls),2)
    def test_navigation_panel_survives_restart_but_buttons_do_not(self):
        self.ui.home(ADMIN);panel=self.ui.panels[str(ADMIN)]
        restarted=bot.UI(self.api,lambda *a:self.calls.append(a),{ADMIN},bot.State(self.path/'poll.json'))
        restarted.home(ADMIN)
        self.assertEqual(self.api.calls[-1][0],'editMessageText')
        self.assertEqual(self.api.calls[-1][1]['message_id'],panel)
    def test_attachment_home_opens_fresh_panel_and_cancels_input(self):
        self.ui.home(ADMIN);old=self.ui.panels[str(ADMIN)]
        self.ui.pending[ADMIN]=(2000,'newdevice',('Ivan',))
        update=self.callback(bot.HOME);update['callback_query']['message']['message_id']=99999
        self.ui.handle(update)
        self.assertNotEqual(self.ui.panels[str(ADMIN)],old)
        self.assertNotIn(ADMIN,self.ui.pending)
        self.assertTrue(any(c[0]=='deleteMessage' and c[1]['message_id']==old for c in self.api.calls))
    def test_export_delivery_private_and_delete_schedule_without_body(self):
        self.ui.manager=lambda *a:{'filename':'Ivan_Phone.conf','content':base64.b64encode(b'synthetic-profile').decode()}
        self.ui.device=lambda *a:None
        with patch('bot.profile_qr',return_value=b'synthetic-png') as qr:
            self.ui.action(ADMIN,'change',('device.export','Ivan','Phone'))
        qr.assert_called_once_with(b'synthetic-profile')
        call=next(c for c in self.api.calls if c[0]=='sendDocument')
        self.assertEqual(call[0],'sendDocument');self.assertEqual(call[1]['chat_id'],ADMIN)
        self.assertTrue(any(c[0]=='sendPhoto' for c in self.api.calls))
        for c in self.api.calls:
            if c[0] in ('sendDocument','sendPhoto'):
                self.assertEqual(c[1]['reply_markup']['inline_keyboard'][0][0],
                                 {'text':bot.HOME_LABEL,'callback_data':bot.HOME})
        self.assertNotIn('synthetic-profile',(self.path/'poll.json').read_text())
        self.clock[0]+=601;self.ui.cleanup();self.assertEqual(self.api.calls[-1][0],'deleteMessage')
    def test_native_export_qr_has_no_uri_prefix_and_home_is_preserved(self):
        from manager_formats import SERVER_DISPLAY_NAME
        self.ui.manager=lambda *a:{'filename':'Ivan_Phone.vpn','display_name':SERVER_DISPLAY_NAME,
                                  'content':base64.b64encode(b'vpn://synthetic-base64').decode()}
        self.ui.device=lambda *a:None
        with patch('bot.profile_qr',return_value=b'synthetic-png') as qr:
            self.ui.action(ADMIN,'change',('device.export.amnezia','Ivan','Phone'))
        qr.assert_called_once_with(b'synthetic-base64')
        call=next(c for c in self.api.calls if c[0]=='sendDocument')
        self.assertEqual(call[2],('Ivan_Phone.vpn',b'vpn://synthetic-base64'))
        self.assertIn(SERVER_DISPLAY_NAME,call[1]['caption'])
        image=next(c for c in self.api.calls if c[0]=='sendPhoto')
        self.assertEqual(image[2][0],'Ivan_Phone.png')
        self.assertEqual(len(self.state.value['deletions']),2)
        self.assertNotIn('synthetic-base64',(self.path/'poll.json').read_text())
    def test_native_export_is_authorized_as_narrow_action(self):
        request={'id':'a'*32,'admin':ADMIN,'chat':ADMIN,
                 'action':'device.export.amnezia','args':['Ivan','Phone']}
        broker.validate_request(request,{ADMIN})
        request['admin']=999
        with self.assertRaises(broker.RequestError):broker.validate_request(request,{ADMIN})
    def test_network_exception_does_not_expose_token_bearing_url(self):
        class Bad:
            def open(self,*a,**kw):raise RuntimeError('TOKEN private request URL')
        api=Telegram('123456:'+('x'*35),opener=Bad())
        with self.assertRaises(ApiError) as ctx:api.call('getMe')
        self.assertEqual(str(ctx.exception),'telegram_request_failed');self.assertIsNone(ctx.exception.__cause__)
    def test_telegram_http_error_category_never_exposes_response_body(self):
        class Bad:
            def open(self,*a,**kw):
                raise urllib.error.HTTPError('https://private-token-url',401,'sensitive details',{},None)
        api=Telegram('123456:'+('x'*35),opener=Bad())
        with self.assertRaises(ApiError) as ctx:api.call('getMe')
        self.assertEqual(str(ctx.exception),'telegram_http_401')
    def test_telegram_connection_timeout_is_distinct_from_invalid_token(self):
        class Bad:
            def open(self,*a,**kw):raise urllib.error.URLError(TimeoutError('sensitive URL'))
        api=Telegram('123456:'+('x'*35),opener=Bad())
        with self.assertRaises(ApiError) as ctx:api.call('getMe')
        self.assertEqual(str(ctx.exception),'telegram_timeout')
    def test_manager_export_temp_directory_removed_success_and_failure(self):
        db=self.path/'export.sqlite3'
        store=Store(db,enforce_ownership=False);store.add_user('Ivan')
        key=base64.b64encode(b'x'*32).decode()
        device=store.add_device('Ivan','Phone',key,'/test-only/key');store.close()
        awg=FakeAwg();awg.add(key,device['ipv4']+'/32')
        api=broker.ManagerAPI(exports=self.path/'exports')
        class Vault:
            fail=False
            def __init__(self,exports):self.root=Path(exports)
            def export(self,device,**kw):
                path=self.root/('Ivan_Phone.vpn' if kw.get('format')=='amnezia' else 'Ivan_Phone.conf');path.write_bytes(b'synthetic-profile')
                if Vault.fail:raise RuntimeError('profile material must not escape')
                return str(path)
        def store_factory(path):return Store(path,enforce_ownership=False)
        from contextlib import nullcontext
        with patch.object(api.cli,'DB',db),patch('manager_db.Store',side_effect=store_factory),\
             patch('manager_runtime.AwgAdapter',return_value=awg),patch('manager_vault.Vault',Vault),\
             patch('manager_lock.process_lock',nullcontext):
            data=api('device.export',['Ivan','Phone'],ADMIN)
            self.assertEqual(base64.b64decode(data['content']),b'synthetic-profile')
            self.assertEqual(list((self.path/'exports').iterdir()),[])
            data=api('device.export.amnezia',['Ivan','Phone'],ADMIN)
            self.assertEqual(data['filename'],'Ivan_Phone.vpn')
            self.assertEqual(list((self.path/'exports').iterdir()),[])
            Vault.fail=True
            with self.assertRaises(RuntimeError):api('device.export',['Ivan','Phone'],ADMIN)
            self.assertEqual(list((self.path/'exports').iterdir()),[])
    def test_token_http_redirect_not_followed(self):
        with self.assertRaises(ApiError):NoRedirect().redirect_request(None,None,None,None,None,None)
    def test_document_protection_and_no_disk_required(self):
        class Response:
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def read(self,*a):return b'{"ok":true,"result":{"message_id":1}}'
        class Opener:
            def open(s,request,**kw):s.request=request;return Response()
        opener=Opener();api=Telegram('123456:'+('x'*35),opener=opener)
        api.call('sendDocument',{'chat_id':ADMIN},document=('Ivan_Phone.conf',b'synthetic-profile'))
        api.call('sendDocument',{'chat_id':ADMIN},document=('Ivan_Phone.vpn',b'synthetic-native-profile'))
        self.assertIn(b'protect_content',opener.request.data)
        self.assertIn(b'true',opener.request.data)
        with self.assertRaises(ApiError):api.call('sendDocument',{},document=('x\r\n.conf',b'no'))
        with self.assertRaises(ApiError):api.call('sendDocument',{},document=('x.py',b'no'))

if __name__=='__main__':unittest.main()
