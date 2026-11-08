#!/usr/bin/python3
"""Fixed AWG peer adapter and crash-reconcilable desired-state controller."""
import hashlib
import ipaddress
import os
from pathlib import Path
import subprocess
import time

from manager_db import Refusal

AWG = '/opt/vpn-task07/awg'
IFACE = 'awg-client'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'HOME': '/'}


def command(argv, *, input_bytes=None):
    proc = subprocess.run(argv, input=input_bytes, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, env=ENV, timeout=15,
                          check=False)
    if proc.returncode or len(proc.stdout) > 1024 * 1024:
        raise Refusal('adapter_failure', 'fixed AWG operation failed')
    return proc.stdout.decode('ascii').strip()


class AwgAdapter:
    def __init__(self, runner=command):
        self.run = runner

    def peers(self):
        text = self.run([AWG, 'show', IFACE, 'allowed-ips'])
        result = {}
        for line in text.splitlines():
            fields = line.split('\t')
            if len(fields) != 2 or fields[0] in result or fields[1] == '(none)':
                raise Refusal('peer_output_invalid', 'AWG peer metadata invalid')
            try:
                network = ipaddress.ip_network(fields[1], strict=True)
            except ValueError:
                raise Refusal('peer_output_invalid', 'AWG peer address invalid') from None
            if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen != 32:
                raise Refusal('peer_output_invalid', 'unexpected AWG peer address')
            result[fields[0]] = fields[1]
        return result

    def metrics(self):
        handshakes = {}
        transfer = {}
        for line in self.run([AWG, 'show', IFACE, 'latest-handshakes']).splitlines():
            fields = line.split('\t')
            if len(fields) != 2:
                raise Refusal('peer_output_invalid', 'handshake metadata invalid')
            handshakes[fields[0]] = int(fields[1])
        for line in self.run([AWG, 'show', IFACE, 'transfer']).splitlines():
            fields = line.split('\t')
            if len(fields) != 3:
                raise Refusal('peer_output_invalid', 'transfer metadata invalid')
            transfer[fields[0]] = (int(fields[1]), int(fields[2]))
        return handshakes, transfer

    def add(self, public_key, address):
        self.run([AWG, 'set', IFACE, 'peer', public_key, 'allowed-ips', address])
        if self.peers().get(public_key) != address:
            raise Refusal('peer_apply_mismatch', 'AWG did not accept expected peer')

    def remove(self, public_key):
        self.run([AWG, 'set', IFACE, 'peer', public_key, 'remove'])
        if public_key in self.peers():
            raise Refusal('peer_remove_mismatch', 'AWG peer still present')


class Controller:
    def __init__(self, store, adapter):
        self.store = store
        self.adapter = adapter

    def drift(self):
        desired = self.store.desired_peers()
        known = self.store.all_known_peers()
        live = self.adapter.peers()
        return {
            'unknown_peers': sorted(hashlib.sha256(k.encode()).hexdigest()[:12]
                                    for k in live.keys() - known),
            'missing_peers': sorted(hashlib.sha256(k.encode()).hexdigest()[:12]
                                    for k in desired.keys() - live.keys()),
            'unexpected_enabled': sorted(hashlib.sha256(k.encode()).hexdigest()[:12]
                                         for k in live.keys() - desired.keys() if k in known),
            'wrong_allowed_ips': sorted(hashlib.sha256(k.encode()).hexdigest()[:12]
                                        for k in desired.keys() & live.keys()
                                        if desired[k] != live[k]),
        }

    def reconcile(self):
        desired = self.store.desired_peers()
        known = self.store.all_known_peers()
        live = self.adapter.peers()
        if live.keys() - known:
            raise Refusal('unknown_live_peer', 'unknown live AWG peer; refusing changes')
        for public_key in live.keys() & desired.keys():
            if live[public_key] != desired[public_key]:
                raise Refusal('wrong_allowed_ips', 'AWG peer address differs from database')
        # Remove unauthorized access before enabling new peers.
        for public_key in sorted(live.keys() - desired.keys()):
            self.adapter.remove(public_key)
        for public_key in sorted(desired.keys() - live.keys()):
            self.adapter.add(public_key, desired[public_key])
        if self.adapter.peers() != desired:
            raise Refusal('reconcile_mismatch', 'AWG does not match desired peers')
        return {'desired': len(desired), 'live': len(desired), 'drift': False}

    def change(self, kind, target_id, mutation):
        opid = self.store.operation(kind, target_id)
        try:
            mutation()
            self.store.operation_phase(opid, 'applying')
            result = self.reconcile()
            self.store.operation_phase(opid, 'done')
            with self.store.write():
                self.store.audit('local-root', kind, 'operation', target_id, 'ok', opid)
            return result
        except Exception as exc:
            code = exc.code if isinstance(exc, Refusal) else 'operation_failed'
            self.store.operation_phase(opid, 'failed', code)
            with self.store.write():
                self.store.audit('local-root', kind, 'operation', target_id, code, opid)
            raise

    def status(self):
        live = self.adapter.peers()
        handshakes, transfer = self.adapter.metrics()
        now_epoch = int(time.time())
        devices = []
        for row in self.store.list_devices():
            public_key = row['public_key']
            last = handshakes.get(public_key, 0)
            rx, tx = transfer.get(public_key, (0, 0))
            devices.append({
                'id': row['id'], 'profile': row['profile_name'], 'state': row['state'],
                'ipv4': row['ipv4'], 'present_in_awg': public_key in live,
                'handshake_age_seconds': None if not last else max(0, now_epoch - last),
                'connected_recently': bool(public_key in live and last and
                                           0 <= now_epoch - last <= 180),
                'rx_bytes': rx, 'tx_bytes': tx,
                'speed_limits': self.store.effective_limits(row['id']),
            })
        return {'registered_users': len(self.store.list_users()),
                'registered_devices': len(devices),
                'present_in_awg': sum(row['present_in_awg'] for row in devices),
                'connected_recently': sum(row['connected_recently'] for row in devices),
                'devices': devices, 'drift': self.drift(),
                'pending_operations': len(self.store.pending_operations())}
