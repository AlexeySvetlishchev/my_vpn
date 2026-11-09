"""Isolated interpreter entry point: no cwd/user-site imports."""
import sys
sys.path.insert(0,'/opt/vpn-task10')
from bot import main
try:main()
except Exception:
    print('bot_start_failed',flush=True)
    raise SystemExit(1)
