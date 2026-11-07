"""Short, bounded TASK 05 asymmetric-packet diagnostic; no system configuration changes."""
import concurrent.futures
import json
import re
import subprocess
import sys
import time

import smoke

ROLES = ('ru', 'fr')
DATA_PORT = 51984
DATA = b'TASK05:' + bytes(range(256)) * 3 + bytes(range(249))  # exactly 1024 bytes
assert len(DATA) == 1024

SERVER_CODE = r'''
import selectors,socket,time
local,peer=__import__('sys').argv[1:3]
payload=b'TASK05:'+bytes(range(256))*3+bytes(range(249))
assert len(payload)==1024
sel=selectors.DefaultSelector(); sockets=[]; seen={'udp':False,'tcp':False}
for kind in (socket.SOCK_DGRAM,socket.SOCK_STREAM):
 s=socket.socket(socket.AF_INET,kind); s.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'awg-test\0'); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((local,51984))
 if kind==socket.SOCK_STREAM: s.listen(4)
 sel.register(s,selectors.EVENT_READ,kind); sockets.append(s)
print('READY',flush=True); deadline=time.monotonic()+35
while time.monotonic()<deadline and not all(seen.values()):
 for key,_ in sel.select(.5):
  if key.data==socket.SOCK_DGRAM:
   data,addr=key.fileobj.recvfrom(2048)
   if addr[0]==peer and data==payload: key.fileobj.sendto(data,addr); seen['udp']=True
  else:
   conn,addr=key.fileobj.accept()
   with conn:
    conn.settimeout(3); data=b''
    while len(data)<1024:
     block=conn.recv(1024-len(data))
     if not block: break
     data+=block
    if addr[0]==peer and data==payload: conn.sendall(data); seen['tcp']=True
for s in sockets: s.close()
print('RESULT udp=%s tcp=%s'%(int(seen['udp']),int(seen['tcp'])),flush=True)
'''

CLIENT_CODE = r'''
import socket,sys
local,peer=sys.argv[1:3]
payload=b'TASK05:'+bytes(range(256))*3+bytes(range(249))
assert len(payload)==1024
results=[]
for kind in (socket.SOCK_DGRAM,socket.SOCK_STREAM):
 s=socket.socket(socket.AF_INET,kind); s.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'awg-test\0'); s.settimeout(4); s.bind((local,0)); s.connect((peer,51984)); s.sendall(payload)
 if kind==socket.SOCK_STREAM:
  data=b''
  while len(data)<1024:
   block=s.recv(1024-len(data))
   if not block: break
   data+=block
 else: data=s.recv(2048)
 s.close(); results.append(len(data)==1024 and data==payload)
print('RESULT udp=%s tcp=%s'%(int(results[0]),int(results[1])),flush=True)
'''


def ssh(role, command, data=None, timeout=15):
    p = subprocess.run([smoke.SSH_BIN, *smoke.SSH, 'vpn-' + role, command],
                       input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                       timeout=timeout)
    return p


def firewall_fr():
    p = ssh('fr', 'sudo -n /usr/sbin/nft -j list ruleset')
    if p.returncode:
        return {'read': False, 'input_icmp_drop_rules': None}
    try:
        rows = json.loads(p.stdout)
    except Exception:
        return {'read': False, 'input_icmp_drop_rules': None}
    chains = set()
    for item in rows.get('nftables', []):
        chain = item.get('chain')
        if isinstance(chain, dict) and chain.get('hook') == 'input':
            chains.add((chain.get('family'), chain.get('table'), chain.get('name')))
    found = []
    for item in rows.get('nftables', []):
        rule = item.get('rule')
        if not isinstance(rule, dict):
            continue
        ident = (rule.get('family'), rule.get('table'), rule.get('chain'))
        if ident not in chains:
            continue
        exprs = rule.get('expr', [])
        encoded = json.dumps(exprs, separators=(',', ':')).lower()
        if 'icmp' not in encoded or not any(isinstance(expr, dict) and ('drop' in expr or 'reject' in expr) for expr in exprs):
            continue
        interfaces, types = [], []
        counters = []
        def visit(value):
            if isinstance(value, dict):
                match = value.get('match')
                if isinstance(match, dict):
                    left = match.get('left', {})
                    meta = left.get('meta', {}) if isinstance(left, dict) else {}
                    if isinstance(meta, dict) and meta.get('key') in ('iifname', 'iif'):
                        # Do not return arbitrary interface names.
                        right = match.get('right')
                        interfaces.append('awg-test' if right == 'awg-test' else 'ens3' if right == 'ens3' else 'other')
                    payload = left.get('payload', {}) if isinstance(left, dict) else {}
                    if isinstance(payload, dict) and payload.get('protocol') in ('icmp', 'icmpv6') and payload.get('field') == 'type':
                        right = match.get('right')
                        if right in ('echo-request', 'echo-reply', 'destination-unreachable', 'time-exceeded'):
                            types.append(right)
                        elif type(right) is int and 0 <= right <= 255:
                            types.append('type-' + str(right))
                        else:
                            types.append('other')
                if 'counter' in value and isinstance(value['counter'], dict):
                    counter = value['counter']
                    counters.append((counter.get('packets'), counter.get('bytes')))
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)
        visit(exprs)
        found.append({'interface': interfaces[0] if interfaces else 'all_interfaces',
                      'icmp_type': types[0] if types else 'all_icmp_types',
                      'counter': counters[0] if counters else None,
                      'handle': rule.get('handle') if type(rule.get('handle')) is int else None})
    return {'read': True, 'input_icmp_drop_rules': found}


def start_server(role):
    local, peer = smoke.INNER[role], smoke.INNER['fr' if role == 'ru' else 'ru']
    p = subprocess.Popen([smoke.SSH_BIN, *smoke.SSH, 'vpn-' + role,
                          'sudo -n /usr/bin/python3 -I -'],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL)
    p.stdin.write(("import sys\nsys.argv=['server',%r,%r]\n" % (local, peer) + SERVER_CODE).encode())
    p.stdin.close()
    time.sleep(2)
    if p.poll() is not None:
        out = p.stdout.read(512).decode('ascii', 'ignore')
        raise RuntimeError(role + '_server_start_failed_' + ('permission' if 'not allowed' in out.lower() else 'startup'))
    return p


def client(role):
    local, peer = smoke.INNER[role], smoke.INNER['fr' if role == 'ru' else 'ru']
    p = ssh(role, 'sudo -n /usr/bin/python3 -I -',
            ("import sys\nsys.argv=['client',%r,%r]\n" % (local, peer) + CLIENT_CODE).encode(), timeout=15)
    if p.returncode:
        return {'udp': False, 'tcp': False, 'command_ok': False}
    match = re.search(rb'RESULT udp=([01]) tcp=([01])', p.stdout)
    return {'udp': bool(match and match[1] == b'1'), 'tcp': bool(match and match[2] == b'1'),
            'command_ok': bool(match)}


def observer(role, executable):
    if executable is None:
        return None
    command = 'sudo -n /usr/bin/timeout -s INT 20 ' + executable + ' -l -nn -tt -i awg-test icmp'
    return subprocess.Popen([smoke.SSH_BIN, *smoke.SSH, 'vpn-' + role, command],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)


def capture_summary(proc):
    if proc is None:
        return {'available': False}
    try:
        output, _ = proc.communicate(timeout=23)
    except Exception:
        proc.kill()
        output, _ = proc.communicate()
    text = output.decode('ascii', 'ignore')
    return {'available': True,
            'echo_requests': len(re.findall(r'echo request', text)),
            'echo_replies': len(re.findall(r'echo reply', text)),
            'ru_to_fr_requests': len(re.findall(r'10\.203\.254\.1\s*>\s*10\.203\.254\.2: ICMP echo request', text)),
            'fr_to_ru_requests': len(re.findall(r'10\.203\.254\.2\s*>\s*10\.203\.254\.1: ICMP echo request', text)),
            'ru_to_fr_replies': len(re.findall(r'10\.203\.254\.2\s*>\s*10\.203\.254\.1: ICMP echo reply', text)),
            'fr_to_ru_replies': len(re.findall(r'10\.203\.254\.1\s*>\s*10\.203\.254\.2: ICMP echo reply', text))}


def run():
    report = {'status': 'FAIL', 'prepare': {}, 'handshake': False,
              'ping': {}, 'payload': {}, 'firewall_fr_before': None,
              'firewall_fr_after': None, 'capture': {}, 'cleanup': {}}
    servers, observers = {}, {}
    try:
        report['firewall_fr_before'] = firewall_fr()
        keys = smoke.both('prepare')
        for role, other in (('ru', 'fr'), ('fr', 'ru')):
            smoke.remote(role, 'peer', (keys[other]['public_key'] + '\n').encode('ascii'))
            report['prepare'][role] = True
        smoke.remote('fr', 'up')
        smoke.remote('ru', 'up')
        deadline = time.monotonic() + 90
        current = None
        while time.monotonic() < deadline:
            current = smoke.both('status')
            if all(current[r].get('handshake', 0) > 0 for r in ROLES):
                smoke.require_fresh(current)
                report['handshake'] = True
                break
            time.sleep(2)
        if not report['handshake']:
            raise RuntimeError('handshake_timeout')
        before = current

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            checks = {r: pool.submit(lambda role=r: next((path for path in ('/usr/bin/tcpdump', '/usr/sbin/tcpdump')
                         if ssh(role, 'sudo -n /usr/bin/test -x ' + path).returncode == 0), None)) for r in ROLES}
            available = {r: checks[r].result() for r in ROLES}
        observers = {r: observer(r, available[r]) for r in ROLES}
        servers = {r: start_server(r) for r in ROLES}
        time.sleep(1)
        for role in ROLES:
            report['payload'][role] = client(role)
        for role in ROLES:
            try:
                output, _ = servers[role].communicate(timeout=5)
                report['payload'][role]['echo_server'] = bool(re.search(rb'RESULT udp=1 tcp=1', output))
            except Exception:
                servers[role].kill()
                report['payload'][role]['echo_server'] = False
        for role in ROLES:
            try:
                report['ping'][role] = smoke.ping(role)
            except RuntimeError as error:
                # Includes only role and numeric packet summary from smoke.ping.
                match = re.search(r'exit=([0-9]+) tx=([0-9]+) rx=([0-9]+)', str(error))
                report['ping'][role] = ({'passed': False, 'exit': int(match[1]),
                                         'transmitted': int(match[2]), 'received': int(match[3])}
                                        if match else {'passed': False})
        after = smoke.both('status')
        smoke.require_fresh(after)
        report['bidirectional_awg_counters'] = all(
            after[r]['rx'] > before[r]['rx'] and after[r]['tx'] > before[r]['tx'] for r in ROLES)
        report['firewall_fr_after'] = firewall_fr()
        if report['firewall_fr_before'].get('read') and report['firewall_fr_after'].get('read'):
            previous = {row.get('handle'): row for row in report['firewall_fr_before']['input_icmp_drop_rules']}
            deltas = []
            for row in report['firewall_fr_after']['input_icmp_drop_rules']:
                old = previous.get(row.get('handle'))
                if old and row.get('counter') and old.get('counter'):
                    deltas.append({'interface': row['interface'],
                                   'packets': row['counter'][0] - old['counter'][0],
                                   'bytes': row['counter'][1] - old['counter'][1]})
            report['firewall_fr_icmp_drop_counter_delta'] = deltas
        report['capture'] = {r: capture_summary(observers.get(r)) for r in ROLES}
        observers = {}
        report['status'] = 'PASS' if (report['bidirectional_awg_counters'] and
            all(report['payload'][r]['udp'] and report['payload'][r]['tcp'] and report['payload'][r]['echo_server'] for r in ROLES)) else 'FAIL'
    except Exception as error:
        report['failure'] = str(error) if type(error) is RuntimeError else 'diagnostic_failed'
        report['firewall_fr_after'] = firewall_fr()
        report['capture'] = {r: capture_summary(observers.get(r)) for r in ROLES}
        observers = {}
        for role, proc in servers.items():
            if proc.poll() is None:
                proc.terminate()
                try: proc.communicate(timeout=3)
                except Exception: proc.kill()
    finally:
        for role in ROLES:
            try:
                smoke.remote(role, 'down')
                smoke.remote(role, 'cleanup')
                report['cleanup'][role] = 'PASS' if smoke.remote(role, 'down').get('already_absent') is True else 'FAIL'
            except Exception:
                report['cleanup'][role] = 'BLOCKED'
        if any(v != 'PASS' for v in report['cleanup'].values()):
            report['status'] = 'FAIL'
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    if sys.argv[1:] == ['--firewall-fr']:
        print(json.dumps(firewall_fr(), indent=2, sort_keys=True))
        sys.exit(0)
    if sys.argv[1:]:
        print('Usage: python -B scripts/task05/diagnose_asymmetry.py [--firewall-fr]')
        sys.exit(2)
    sys.exit(run())
