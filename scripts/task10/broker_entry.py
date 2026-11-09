import sys
sys.path.insert(0,'/opt/vpn-task10')
from broker import main
try:main()
except Exception:
    print('broker_start_failed',flush=True)
    raise SystemExit(1)
