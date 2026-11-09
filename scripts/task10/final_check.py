"""Bounded final read-only checks. No route/rule/peer mutation or real export."""
import json
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys

sys.path[:0]=['/opt/vpn-task09','/opt/vpn-task10']
STAGE='imports'


def run(argv):
    return subprocess.check_output(argv,stderr=subprocess.DEVNULL,timeout=60)


def main():
    global STAGE
    import egress
    from manager_formats import SERVER_DISPLAY_NAME
    from manager_db import Store
    from manager_runtime import AwgAdapter,Controller
    from manager_lock import process_lock
    # Native and compatibility codecs were tested separately with synthetic
    # profiles. A real re-export is intentionally NOT performed here.
    services={}
    STAGE='services_and_enablement'
    for unit in ('vpn-task10-bot.service','vpn-task10-broker.service','vpn-task10-egress.service'):
        assert run(['/usr/bin/systemctl','is-active',unit]).strip()==b'active'
        services[unit]=run(['/usr/bin/systemctl','show',unit,'-p','UnitFileState','--value']).decode().strip()
    assert services['vpn-task10-bot.service']=='enabled' and services['vpn-task10-egress.service']=='enabled'
    STAGE='unit_verification'
    run(['/usr/bin/systemd-analyze','verify',*[str(Path('/etc/systemd/system')/u) for u in services]])
    STAGE='manager_diagnostics'
    diagnostic=json.loads(run(['/usr/local/sbin/vpnctl','--json','diagnostics']))['data']
    assert all(diagnostic['services'].values()) and not any(diagnostic['peer_drift'].values())
    assert not diagnostic['incomplete_operations']
    STAGE='rollback_readiness'
    run(['/usr/local/sbin/vpn-task08-rollback','ru','check'])
    run(['/usr/bin/python3','-I','-B','/opt/vpn-task10/rollback_entry.py','--check'])
    STAGE='peer_status'
    status=json.loads(run(['/usr/local/sbin/vpnctl','--json','status']))['data']
    old=next(d for d in status['devices'] if d['profile']=='Test_iPhone')
    assert old['state']=='revoked' and not old['present_in_awg']
    enabled=[d for d in status['devices'] if d['state']=='enabled']
    assert enabled and all(d['present_in_awg'] for d in enabled)
    # Read the existing policy decisions, including iif-restricted fail-closed.
    STAGE='policy_routes'
    source=enabled[0]['ipv4']
    ru=run(['/usr/sbin/ip','-4','route','get','77.88.55.242','from',source,'iif','awg-client','mark','0x701'])
    fr=run(['/usr/sbin/ip','-4','route','get','1.1.1.1','from',source,'iif','awg-client','mark','0x702'])
    assert b'dev eth0' in ru and b'dev awg-transport' in fr
    # Client resolver health (not a new physical-client DNS leak test).
    STAGE='client_dns'
    wire=b'\x07example\x03com\0'
    query=struct.pack('!6H',15932,0x100,1,0,0,0)+wire+struct.pack('!HH',1,1)
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as dns:
        dns.settimeout(5);dns.bind(('10.203.253.1',0));dns.connect(('10.203.253.1',53))
        dns.send(query);answer=dns.recv(4096)
    ident,flags,qd,an,_,_=struct.unpack('!6H',answer[:12])
    assert ident==15932 and flags&0x8000 and flags&15==0 and an>0
    # Fresh TLS egress measurement using exactly the marked/source-bound path.
    STAGE='fr_egress'
    previous=egress.HOST
    try:
        egress.HOST='api.ipify.org';egress._cache=(0,[])
        with ssl.create_default_context().wrap_socket(egress.dial_telegram(),server_hostname=egress.HOST) as conn:
            conn.sendall(b'GET / HTTP/1.0\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n')
            raw=b''
            while len(raw)<16384:
                chunk=conn.recv(4096)
                if not chunk:break
                raw+=chunk
        external=raw.split(b'\r\n\r\n',1)[1].strip().decode()
        assert external=='45.15.128.138'
    finally:
        egress.HOST=previous;egress._cache=(0,[])
    # Read-only ownership/activation proof from the actual installed Manager.
    STAGE='activation_and_drift'
    import vpnctl
    with process_lock():
        store=Store(vpnctl.DB)
        try:
            assert vpnctl.activated(store)
            assert not any(Controller(store,AwgAdapter()).drift().values())
        finally:store.close()
    print(json.dumps({'display_name':SERVER_DISPLAY_NAME,'boot_enablement':services,
                      'task08_ownership_and_rollback_ready':True,'task10_rollback_ready':True,
                      'ru_route_eth0':True,'foreign_route_transport':True,
                      'client_dns_answer':True,'bot_path_egress_ipv4':external,
                      'fail_closed_guards_configured':True,'Test_iPhone_no_live_access':True,
                      'active_profiles':[d['profile'] for d in enabled],
                      'host_reboot_tested':False,'new_physical_fail_closed_test':False}))


if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(json.dumps({'final_check':False,'stage':STAGE,'category':type(exc).__name__,
                          'returncode':getattr(exc,'returncode',None)}));raise SystemExit(1)
