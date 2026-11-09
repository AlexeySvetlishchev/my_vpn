"""Bot-only FR egress, ownership, crash repair, DNS and real isolated RPDB."""
import copy,json,os,socket,struct,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts/task10'))
import egress
import egress_control as ctl

class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.base=[{'priority':i,'src':'all'} for i in (10000,10010,10021,10030,10031,10032,10033)]
        self.live=[];self.events=[]
        self.ledger=self.root/'active.json';self.ledger.write_text(json.dumps({'rules4':self.base}))
        for name,value in [('STATE',self.root/'marker.json'),('LEDGER',self.ledger),('LOCK',self.root/'lock')]:
            p=patch.object(ctl,name,value);p.start();self.addCleanup(p.stop)
        p=patch.object(ctl,'rules',side_effect=lambda:copy.deepcopy(self.base+self.live));p.start();self.addCleanup(p.stop)
        p=patch.object(ctl,'run',side_effect=self.run_rule);p.start();self.addCleanup(p.stop)
    def run_rule(self,args,allow=False):
        pref=int(args[args.index('pref')+1]);op=args[3];self.events.append((op,pref))
        if op=='add':self.live.append(copy.deepcopy(next(r for r in ctl.EXPECTED if r['priority']==pref)));self.live.sort(key=lambda r:r['priority'])
        elif op=='del':self.live[:]=[r for r in self.live if r['priority']!=pref]
    def test_order_idempotence_and_addressed_removal(self):
        ctl.action('ensure');self.assertEqual(self.events,[('add',10041),('add',10040)])
        ctl.action('ensure');self.assertEqual(len(self.events),2)
        self.assertEqual(json.loads(self.ledger.read_text())['rules4'][:7],self.base)
        ctl.action('remove');self.assertEqual(self.events[-2:],[('del',10040),('del',10041)])
        self.assertEqual(json.loads(self.ledger.read_text())['rules4'],self.base)
    def test_partial_terminal_install_repaired_from_durable_intent(self):
        ctl.atomic(ctl.STATE,{'schema':1,'role':'ru','mark':'0x704','rules4':ctl.EXPECTED})
        self.live=[copy.deepcopy(ctl.EXPECTED[1])]
        ctl.action('ensure');self.assertEqual(self.live,ctl.EXPECTED)
        self.assertEqual(self.events,[('add',10040)])
    def test_unowned_priority_conflict_refused(self):
        self.live=[{'priority':10040,'src':'all','fwmark':'0x999','table':'main'}]
        with self.assertRaises(RuntimeError):ctl.action('ensure')
        self.assertFalse(self.events)
    def test_crash_after_rules_before_ledger_is_repaired(self):
        original=ctl.atomic
        def fail_ledger(path,value):
            if path==self.ledger:raise OSError('injected')
            return original(path,value)
        with patch.object(ctl,'atomic',side_effect=fail_ledger),self.assertRaises(OSError):ctl.action('ensure')
        ctl.action('ensure');self.assertEqual(len(json.loads(self.ledger.read_text())['rules4']),9)
    def test_task08_recovery_keeps_exact_client_seven_rule_contract(self):
        import ast
        source=(ROOT/'scripts/task08/recover.py').read_text()
        node=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name=='restore_ru_rules')
        marker={'schema':1,'role':'ru','mark':'0x704','rules4':ctl.EXPECTED}
        scope={'json':json,'Path':Path,'read_root':lambda *a:json.dumps(marker).encode(),
               'IP':'ip','run':lambda *a:json.dumps(self.base+ctl.EXPECTED).encode()}
        exec(compile(ast.Module(body=[node],type_ignores=[]),'recover','exec'),scope)
        scope['restore_ru_rules']({'rules4':self.base+ctl.EXPECTED})
        with self.assertRaises(RuntimeError):scope['restore_ru_rules']({'rules4':self.base+[{'priority':10040,'fwmark':'0x999'}]})

class NetworkTests(unittest.TestCase):
    def answer(self,query):
        return query[:2]+struct.pack('!5H',0x8180,1,1,0,0)+query[12:]+b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+socket.inet_aton('203.0.113.2')
    def test_dns_bound_to_existing_fr_dns_source_and_no_host_resolver(self):
        outer=self
        class Sock:
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def connect(self,dest):self.dest=dest
            def send(self,query):self.query=query
            def recv(self,n):return outer.answer(self.query)
        egress._cache=(0,[])
        with patch.object(egress,'marked_socket',return_value=Sock()) as marked,patch('socket.getaddrinfo',side_effect=AssertionError('host DNS forbidden')):
            self.assertEqual(egress.resolve_telegram(),['203.0.113.2'])
            marked.assert_called_once_with(socket.SOCK_DGRAM,'10.203.254.1')
    def test_dns_failure_has_no_direct_fallback(self):
        egress._cache=(0,[])
        with patch.object(egress,'marked_socket',side_effect=OSError('blocked')) as marked,self.assertRaises(OSError):egress.resolve_telegram()
        self.assertEqual(marked.call_count,2)
    def test_tcp_uses_existing_server_address_and_fixed_443(self):
        from unittest.mock import Mock
        sock=Mock()
        with patch.object(egress,'resolve_telegram',return_value=['203.0.113.2']),patch.object(egress,'marked_socket',return_value=sock) as marked:
            self.assertIs(egress.dial_telegram(),sock)
        marked.assert_called_once_with(socket.SOCK_STREAM,'10.203.253.1')
        sock.connect.assert_called_once_with(('203.0.113.2',443))
    def test_dns_parser_rejects_wrong_transaction(self):
        with self.assertRaises(ValueError):egress.dns_answers(struct.pack('!6H',1,0x8180,1,1,0,0),2)
    def test_mark_failure_closes_socket_no_unmarked_fallback(self):
        from unittest.mock import Mock
        sock=Mock();sock.setsockopt.side_effect=PermissionError('no cap')
        with patch('socket.socket',return_value=sock),self.assertRaises(PermissionError):egress.marked_socket(socket.SOCK_STREAM,'10.203.253.1')
        sock.close.assert_called_once()
    def test_real_isolated_kernel_no_table_route_hits_terminal_unreachable(self):
        if os.environ.get('TASK10_REAL_RULE_TEST')!='1' or not Path('/.dockerenv').exists():self.skipTest('explicit disposable container required')
        ip='/usr/sbin/ip'
        def run(*args,check=True):return subprocess.run([ip,*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=check)
        before=run('-j','-4','route','show','table','main').stdout
        rows=json.loads(run('-j','-4','rule','show').stdout)
        self.assertFalse(ctl.selected(rows))
        try:
            run('-4','rule','add','pref','10041','fwmark','0x704','unreachable')
            run('-4','rule','add','pref','10040','fwmark','0x704','lookup','220')
            self.assertEqual(ctl.selected(json.loads(run('-j','-4','rule','show').stdout)),ctl.EXPECTED)
            self.assertNotEqual(run('-4','route','get','1.1.1.1','mark','0x704',check=False).returncode,0)
            self.assertEqual(run('-j','-4','route','show','table','main').stdout,before)
        finally:
            for pref in ('10040','10041'):run('-4','rule','del','pref',pref,'fwmark','0x704',check=False)

if __name__=='__main__':unittest.main()
