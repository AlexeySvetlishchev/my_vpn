#!/usr/bin/python3
"""Print only TASK 06/TASK 07 baseline predicate locations, never state contents."""
import importlib.util
import traceback

spec = importlib.util.spec_from_file_location('task06_diag', '/opt/vpn-task06/helper.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

try:
    print('TASK07_OWNED=', module.owned_task07_interface())
except Exception as exc:
    print('TASK07_OWNED_FAIL=', type(exc).__name__)
    for frame in traceback.extract_tb(exc.__traceback__):
        if frame.filename == '/opt/vpn-task06/helper.py':
            print('TASK06_LINE=', frame.lineno)

try:
    actual = module.snapshot()
    baseline = module.load_baseline()
    for key in ('addresses', 'routes', 'rules', 'firewall_hash'):
        print('BASELINE_EQUAL_', key.upper(), '=', actual[key] == baseline[key])
except Exception as exc:
    print('SNAPSHOT_FAIL=', type(exc).__name__)
    for frame in traceback.extract_tb(exc.__traceback__):
        if frame.filename == '/opt/vpn-task06/helper.py':
            print('TASK06_LINE=', frame.lineno)

try:
    result = module.service_status('ru')
    print('TASK06_SERVICE_STATUS=', result.get('active'),
          'HANDSHAKE_AGE=', result.get('handshake_age_seconds'))
except Exception as exc:
    print('TASK06_SERVICE_STATUS_FAIL=', type(exc).__name__)
    for frame in traceback.extract_tb(exc.__traceback__):
        if frame.filename == '/opt/vpn-task06/helper.py':
            print('TASK06_LINE=', frame.lineno)
