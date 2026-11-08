"""Read-only verification plus explicit protected backup/check/stage exercise."""
import hashlib,json,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent))
from task09_nft_plan import owned,stable
B=Path('/var/backups/vpn-task09/20261108T180859Z')
def run(a):return subprocess.check_output(a,stderr=subprocess.DEVNULL,timeout=30)
meta=json.loads((B/'metadata.json').read_bytes())
nft=json.loads(run(['/usr/sbin/nft','-j','list','ruleset']))
old=meta['transition']['baseline_nft']
sets=lambda s:[stable({k:v for k,v in x['set'].items() if k!='handle'}) for x in owned(s) if 'set'in x]
assert sets(nft)==sets(old)
paths=['server.key','client.key','client.pub','Test_iPhone.conf']
assert all(hashlib.sha256((Path('/etc/vpn-task07')/n).read_bytes()).digest()==
           hashlib.sha256((B/'files/etc/vpn-task07'/n).read_bytes()).digest() for n in paths)
print(json.dumps({'dynamic_sets_preserved':True,'legacy_keys_profile_unchanged':True}))
for dest,mark in [('77.88.55.242','0x701'),('1.1.1.1','0x702')]:
    route=run(['/usr/sbin/ip','-4','route','get',dest,'from','10.203.253.3','iif','awg-client','mark',mark]).decode()
    assert ('dev eth0' if mark=='0x701' else 'dev awg-transport') in route
    print(json.dumps({'destination':dest,'route':route.strip()}))
rules=run(['/usr/sbin/ip','-4','rule','show']).decode()
assert 'fwmark 0x702 iif awg-client unreachable' in rules
print(json.dumps({'foreign_fallback_unreachable':True}))
backup=json.loads(run(['/usr/local/sbin/vpnctl','--json','backup']))
print(json.dumps(backup))
# backup path key is established by the existing Manager CLI contract.
data=backup['data'];path=data.get('path') or data.get('archive')
assert path
print(run(['/usr/local/sbin/vpnctl','--json','restore','--check',path]).decode().strip())
print(run(['/usr/local/sbin/vpnctl','--json','restore','--stage',path]).decode().strip())
