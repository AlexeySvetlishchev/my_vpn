import sys
sys.path.insert(0,'/opt/vpn-task10')
from egress_control import action
if sys.argv[1:] not in (['ensure'],['remove']):raise SystemExit(2)
try:action(sys.argv[1])
except Exception:
    print('egress_control_failed',flush=True);raise SystemExit(1)
