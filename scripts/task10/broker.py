"""Root local broker, limited to Manager API. No Telegram HTTP/token access."""
import base64
import json
import os
from pathlib import Path
import re
import socket
import socketserver
import stat
import struct
import sys
import tempfile

ROOT = Path('/run/vpn-task10-broker')
CONFIG = Path('/etc/vpn-task10/admins.json')
ALLOWED = {'user.list':0,'user.show':1,'user.add':1,'user.delete':1,
           'user.disable':1,'user.enable':1,'device.show':2,'device.add':2,
           'device.disable':2,'device.enable':2,'device.revoke':2,'device.export':2,
           'device.export.amnezia':2,'status':0,'network.telegram':0}
READS = {'user.list','user.show','device.show','status'}


def load_admins(path, strict=True):
    path=Path(path)
    if strict:
        s=path.lstat()
        if path.is_symlink() or not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o600:
            raise ValueError('unsafe_admin_config')
    record=json.loads(path.read_text())
    values=record.get('admin_ids')
    if (set(record)!={'admin_ids'} or not isinstance(values,list) or not values or
            any(type(i)!=int or i<=0 or i>=2**52 for i in values)):
        raise ValueError('invalid_admin_config')
    return set(values)


def approved_peer(conn, proc=Path('/proc')):
    pid,uid,_=struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
    if uid==0:return False
    try:
        groups=(proc/str(pid)/'cgroup').read_text().splitlines()
        return '0::/system.slice/vpn-task10-bot.service' in groups
    except OSError:return False


class RequestError(Exception):
    pass


def validate_request(r, admins):
    if not isinstance(r,dict) or set(r)!={'id','admin','chat','action','args'}:
        raise RequestError('invalid_request')
    if type(r['admin'])!=int or type(r['chat'])!=int or r['admin'] not in admins or r['chat']!=r['admin']:
        raise RequestError('forbidden')
    if not isinstance(r['id'],str) or not re.fullmatch('[a-f0-9]{32}',r['id']):
        raise RequestError('invalid_request_id')
    action=r['action'];args=r['args']
    if (not isinstance(action,str) or action not in ALLOWED or not isinstance(args,list)
            or len(args)!=ALLOWED[action] or any(not isinstance(a,str) or len(a)>32 for a in args)):
        raise RequestError('operation_not_allowed')
    # Identity rules are enforced again by Manager; this prevents CLI flag injection.
    if any(not a or not a[0].isalpha() or not a.isalnum() for a in args):
        raise RequestError('invalid_name')


class ReplayGuard:
    """Durable at-most-once requests; crash after reservation needs manual retry."""
    def __init__(self,path):self.path=Path(path)
    def reserve(self,key):
        fd=os.open(self.path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'r+b') as f:
            import fcntl
            fcntl.flock(f,fcntl.LOCK_EX)
            if any(line.strip()==key.encode() for line in f):raise RequestError('request_already_used')
            f.write((key+'\n').encode());f.flush();os.fsync(f.fileno())
        fd=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)


class ManagerAPI:
    def __init__(self, exports=ROOT/'exports'):
        sys.path.insert(0,'/opt/vpn-task09')
        import vpnctl
        self.cli=vpnctl;self.exports=Path(exports)

    def __call__(self,action,args,admin):
        from manager_lock import process_lock
        from manager_db import Store
        from manager_runtime import AwgAdapter
        from manager_vault import Vault
        with process_lock():
            store=Store(self.cli.DB)
            try:
                native=action=='device.export.amnezia'
                exporting=action in ('device.export','device.export.amnezia')
                argv=(['device','export',*args,'--format','amnezia' if native else 'conf']
                      if exporting else action.split('.')+args)
                parsed=self.cli.parser().parse_args(argv)
                if exporting:
                    self.exports.mkdir(mode=0o700,parents=True,exist_ok=True)
                    with tempfile.TemporaryDirectory(dir=self.exports,prefix='export-') as folder:
                        vault=Vault(exports=Path(folder))
                        result=self.cli.execute(parsed,store,AwgAdapter(),vault)
                        path=Path(result['path'])
                        if path.is_symlink() or path.parent.resolve()!=Path(folder).resolve() or path.suffix!=('.vpn' if native else '.conf'):
                            raise RequestError('invalid_export_path')
                        content=path.read_bytes()
                        if len(content)>16384:raise RequestError('profile_bound')
                        data={'filename':path.name,'content':base64.b64encode(content).decode()}
                        if native:
                            from manager_formats import SERVER_DISPLAY_NAME
                            data['display_name']=SERVER_DISPLAY_NAME
                else:
                    data=self.cli.execute(parsed,store,AwgAdapter(),Vault())
                    if action=='user.show':
                        names={d['id']:d['name'] for d in store.list_devices(args[0])}
                        for d in data['devices']:d['name']=names[d['id']]
                    if action=='device.show':
                        row=store.device(*args)
                        data['name']=row['name'];data['effective_limits']=store.effective_limits(row['id'])
                with store.write():
                    target=store.device(*args)['id'] if exporting else str(data.get('id','adapter')) if isinstance(data,dict) else 'adapter'
                    store.audit('telegram-admin:'+str(admin),action,'telegram',target,'ok')
                return data
            finally:store.close()


def dispatch(request,admins,guard,manager):
    try:
        validate_request(request,admins)
        # Reserve reads too: easier contract, no retry side effects or export duplicates.
        guard.reserve(request['id'])
        return {'ok':True,'data':manager(request['action'],request['args'],request['admin'])}
    except Exception as exc:
        code=exc.args[0] if isinstance(exc,RequestError) else getattr(exc,'code','operation_failed')
        return {'ok':False,'code':code if isinstance(code,str) and re.fullmatch('[a-z_]+',code) else 'operation_failed'}


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(5)
        if not approved_peer(self.connection):return
        try:
            raw=self.rfile.readline(65537)
            if len(raw)>65536 or not raw.endswith(b'\n'):return
            request=json.loads(raw)
            if isinstance(request,dict) and request.get('action')=='network.telegram':
                validate_request(request,self.server.admins);self.server.guard.reserve(request['id'])
                from egress import dial_telegram
                import array
                with dial_telegram() as outbound:
                    self.connection.sendmsg([b'{"ok":true}\n'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[outbound.fileno()]))])
                print('telegram_socket_ready',flush=True)
                return
            response=dispatch(request,self.server.admins,self.server.guard,self.server.manager)
            self.wfile.write(json.dumps(response).encode()+b'\n')
            print('broker_request_ok' if response['ok'] else 'broker_request_refused',flush=True)
        except Exception:
            print('broker_request_failed',flush=True)


def main():
    os.umask(0o077)
    admins=load_admins(CONFIG)
    path=ROOT/'manager.sock'
    if path.exists():
        if not stat.S_ISSOCK(path.lstat().st_mode):raise RuntimeError('socket_conflict')
        path.unlink()
    with socketserver.UnixStreamServer(str(path),Handler) as server:
        os.chmod(path,0o666)  # SO_PEERCRED + exact systemd cgroup are mandatory.
        server.admins=admins
        server.guard=ReplayGuard('/var/lib/vpn-task10-broker/requests.log')
        server.manager=ManagerAPI()
        server.serve_forever()

if __name__=='__main__':main()
