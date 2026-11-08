#!/usr/bin/python3
"""Temporary RU-local real AWG client; outer UDP stays in host namespace.

Only the dedicated probe TUN is moved to the disposable namespace. No host
routes, sysctls or firewall are changed. Never prints secret material.
"""
import json,os,socket,ssl,struct,subprocess,sys,time
from pathlib import Path
NS='task09-probe'; IF='awg-probe'
AWG='/opt/vpn-task07/awg'; GO='/opt/vpn-task07/amneziawg-go'
def run(args,allow=False):
    r=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
    if r.returncode and not allow:raise RuntimeError('probe operation failed: '+args[0])
    return r
def query():
    name='api.ipify.org'
    wire=b''.join(bytes([len(p)])+p.encode() for p in name.split('.'))+b'\0'
    q=struct.pack('!HHHHHH',789,0x100,1,0,0,0)+wire+struct.pack('!HH',1,1)
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(5)
    s.sendto(q,('10.203.253.1',53));data=s.recv(4096);s.close()
    def skip(pos):
        while data[pos]:
            if data[pos]&0xc0==0xc0:return pos+2
            pos+=data[pos]+1
        return pos+1
    ident,flags,qd,an,_,_=struct.unpack('!HHHHHH',data[:12])
    assert ident==789 and flags&15==0
    pos=12
    for _ in range(qd):pos=skip(pos)+4
    answers=[]
    for _ in range(an):
        pos=skip(pos);typ,cls,ttl,length=struct.unpack('!HHIH',data[pos:pos+10]);pos+=10
        if typ==1 and cls==1 and length==4:answers.append(socket.inet_ntoa(data[pos:pos+4]))
        pos+=length
    assert answers
    sock=socket.create_connection((answers[0],443),timeout=8)
    with ssl.create_default_context().wrap_socket(sock,server_hostname=name) as tls:
        tls.sendall(b'GET / HTTP/1.0\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n')
        body=b''
        while True:
            chunk=tls.recv(4096)
            if not chunk:break
            body+=chunk
    egress=body.split(b'\r\n\r\n',1)[1].strip().decode('ascii')
    assert egress=='45.15.128.138'
    print(json.dumps({'dns_udp':True,'https_egress':egress}))

def main():
    if sys.argv[1:]==['query']:query();return
    assert os.geteuid()==0 and sys.argv[1:]==['test']
    if Path('/run/netns/'+NS).exists():raise RuntimeError('namespace conflict')
    assert run(['/usr/sbin/ip','link','show','dev',IF],allow=True).returncode!=0
    sys.path.insert(0,'/opt/vpn-task09')
    from manager_db import Store
    store=Store('/var/lib/vpn-task09/manager.sqlite3')
    device=store.device('TaskNine','Probe');key=device['key_ref'];pub=device['public_key'];store.close()
    server=run([AWG,'show','awg-client','public-key']).stdout.decode().strip()
    proc=None
    try:
        run(['/usr/sbin/ip','netns','add',NS])
        proc=subprocess.Popen([GO,'-f',IF],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                              env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LOG_LEVEL':'silent','GOMAXPROCS':'1'})
        for _ in range(50):
            if Path('/run/vpn-task07/amneziawg/'+IF+'.sock').exists():break
            time.sleep(.1)
        run([AWG,'set',IF,'private-key',key,'jc','4','jmin','64','jmax','256',
             's1','32','s2','64','s3','32','s4','32','h1','176321011-176321111',
             'h2','276321011-276321111','h3','376321011-376321111','h4','476321011-476321111',
             'peer',server,'endpoint','127.0.0.1:51821','allowed-ips','0.0.0.0/0','persistent-keepalive','1'])
        run(['/usr/sbin/ip','link','set','dev',IF,'netns',NS])
        base=['/usr/sbin/ip','-n',NS]
        run(base+['addr','add',device['ipv4']+'/32','dev',IF])
        run(base+['link','set','dev','lo','up'])
        run(base+['link','set','dev',IF,'mtu','1280','up'])
        run(base+['route','add','default','dev',IF])
        command=['/usr/sbin/ip','netns','exec',NS,'/usr/bin/python3','-B',str(Path(__file__).resolve()),'query']
        first=run(command);print(first.stdout.decode().strip(),flush=True)
        run(['/usr/local/sbin/vpnctl','--json','device','disable','TaskNine','Probe'])
        blocked=run(command,allow=True)
        assert blocked.returncode!=0
        assert pub not in run([AWG,'show','awg-client','peers']).stdout.decode().splitlines()
        run(['/usr/local/sbin/vpnctl','--json','device','enable','TaskNine','Probe'])
        # The server deliberately discarded the old session on disable.
        # Reconnect the test client to trigger a fresh handshake immediately.
        run([AWG,'set',IF,'peer',server,'remove'])
        run([AWG,'set',IF,'peer',server,'endpoint','127.0.0.1:51821',
             'allowed-ips','0.0.0.0/0','persistent-keepalive','1'])
        time.sleep(2)
        print(run(command).stdout.decode().strip(),flush=True)
        print(json.dumps({'disable_blocked_actual_data':True,'enable_restored_actual_data':True}),flush=True)
    finally:
        # A failed data probe must not leave the test peer disabled.
        run(['/usr/local/sbin/vpnctl','--json','device','enable','TaskNine','Probe'],allow=True)
        if proc:
            proc.terminate()
            try:proc.wait(timeout=6)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
        run(['/usr/sbin/ip','netns','delete',NS],allow=True)
        run(['/usr/sbin/ip','link','delete',IF],allow=True)
if __name__=='__main__':main()
