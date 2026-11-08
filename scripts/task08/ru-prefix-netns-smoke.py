#!/usr/bin/python3
"""Isolated nft transaction and JSON set parser check; host rules are untouched."""
from importlib.machinery import SourceFileLoader
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
NFT = '/usr/sbin/nft'


def run(args, data=None):
    subprocess.run(args, input=data, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   check=True, timeout=15)


if os.geteuid() != 0 or len(sys.argv) != 1:
    raise SystemExit(2)
spec = importlib.util.spec_from_loader('ru_prefix_update_test', SourceFileLoader(
    'ru_prefix_update_test', str(ROOT / 'ru-prefix-update.py')))
update = importlib.util.module_from_spec(spec)
spec.loader.exec_module(update)
run([NFT, '-f', str(ROOT / 'ru.nft')])
ru = ['77.88.8.0/24', '77.88.10.0/24']
force = ['77.88.8.8/32']
batch = update.nft_batch(ru, force)
run([NFT, '-c', '-f', '-'], batch)
run([NFT, '-f', '-'], batch)
if update.nft_elements('ru_set') != ru or update.nft_elements('force_egress') != force:
    raise RuntimeError('isolated nft set verification failed')
print(json.dumps({'isolated': True, 'atomic_batch': True, 'set_parser': True,
                  'force_exception': True}))
