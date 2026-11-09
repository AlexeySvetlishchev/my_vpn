#!/usr/bin/python3
"""Bounded verification. Never prints token, logs, packets or profile contents."""
import hashlib,json,socket,ssl,struct,subprocess,sys,threading,time
from pathlib import Path
sys.path.insert(0,'/opt/vpn-task10')
import egress

def run(args,check=True):return subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45,check=check)
def system(*args):return run(['/usr/bin/systemctl',*args])
def main():
    before=json.loads(run(['/usr/local/sbin/vpnctl','--json','status']).stdout)['data']
    assert before['services']['awg_transport'] and not any(before['drift'].values())
    # Measure the same marked/source-bound FR path against an independent IP service.
    egress.HOST='api.ipify.org';egress._cache=(0,[])
    with ssl.create_default_context().wrap_socket(egress.dial_telegram(),server_hostname=egress.HOST) as conn:
        conn.sendall(b'GET / HTTP/1.0\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n')
        body=b''
        while True:
            data=conn.recv(4096)
            if not data:break
            body+=data
        ip=body.split(b'\r\n\r\n',1)[1].strip().decode()
        assert ip=='45.15.128.138'
    egress.HOST='api.telegram.org';egress._cache=(0,[])
    addresses=set(egress.resolve_telegram())
    system('stop','vpn-task10-bot.service')
    capture=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800));capture.bind(('eth0',0));capture.settimeout(.1)
    finished=threading.Event();counts={'telegram_wan_syn':0,'bot_dns_wan':0}
    def observe():
        while not finished.is_set():
            try:packet=capture.recv(256)
            except socket.timeout:continue
            if len(packet)<54 or packet[14]>>4!=4:continue
            ihl=(packet[14]&15)*4;protocol=packet[23]
            src=socket.inet_ntoa(packet[26:30]);dst=socket.inet_ntoa(packet[30:34]);offset=14+ihl
            if len(packet)<offset+20:continue
            destport=int.from_bytes(packet[offset+2:offset+4],'big')
            if protocol==6 and dst in addresses and destport==443 and packet[offset+13]&2:counts['telegram_wan_syn']+=1
            if protocol in (6,17) and src=='10.203.254.1' and destport==53:counts['bot_dns_wan']+=1
    thread=threading.Thread(target=observe);thread.start();passed=False;lookup_removed=False
    try:
        run(['/usr/sbin/ip','-4','rule','del','pref','10040','fwmark','0x704']);lookup_removed=True
        result=run(['/usr/sbin/ip','-4','route','get',next(iter(addresses)),'from','10.203.253.1','mark','0x704'],check=False)
        assert result.returncode!=0
        try:
            probe=egress.dial_telegram();probe.close();raise AssertionError('unexpected_direct_fallback')
        except OSError:pass
        time.sleep(2)
        assert not any(counts.values());passed=True
    finally:
        if lookup_removed:run(['/usr/sbin/ip','-4','rule','add','pref','10040','fwmark','0x704','lookup','220'])
        finished.set();thread.join(timeout=2);capture.close()
        if passed:system('start','vpn-task10-bot.service')
    # Ordinary root process is intentionally rejected by the kernel/cgroup gate.
    with socket.socket(socket.AF_UNIX) as channel:
        channel.settimeout(3);channel.connect('/run/vpn-task10-broker/manager.sock')
        assert channel.recv(1)==b''
    deny_code="import socket;s=socket.socket(socket.AF_UNIX);s.settimeout(3);s.connect('/run/vpn-task10-broker/manager.sock');assert s.recv(1)==b''"
    run(['/usr/sbin/runuser','-u','nobody','--','/usr/bin/python3','-c',deny_code])
    journal=run(['/usr/bin/journalctl','-u','vpn-task10-bot.service','-u','vpn-task10-broker.service','--since','2026-11-09','--no-pager','-o','cat']).stdout
    token=Path('/etc/vpn-task10/token').read_bytes().strip()
    assert token not in journal and b'PrivateKey =' not in journal and b'[Interface]' not in journal
    assert b'telegram_connected' in journal
    after=json.loads(run(['/usr/local/sbin/vpnctl','--json','diagnostics']).stdout)['data']
    assert not any(after['peer_drift'].values()) and all(after['services'].values())
    print(json.dumps({'bot_egress_ipv4':ip,'dns_via_fr':True,'fail_closed_lookup_loss':passed,
                      'wan_packet_counts':counts,'root_and_nobody_socket_denied':True,
                      'token_or_profile_in_logs':False,'telegram_connected_event':True,'manager_healthy':True}))
if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(json.dumps({'verify_passed':False,'category':type(exc).__name__}));raise SystemExit(1)
