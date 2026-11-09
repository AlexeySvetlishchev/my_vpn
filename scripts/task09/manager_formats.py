"""Amnezia native client envelope; no change to the embedded AWG config.

Schema/codec verified against amnezia-client 5.1.0.6, ac175c8a8147.
This is client import metadata, never a server/admin-access configuration.
"""
import base64
import configparser
import json
import struct
import zlib

from manager_db import Refusal

SERVER_DISPLAY_NAME = 'WolfVPN'
AWG_FIELDS = ('Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4',
              'H1', 'H2', 'H3', 'H4', 'I1', 'I2', 'I3', 'I4', 'I5')


def amnezia_profile(raw):
    """Return a .vpn URI. raw remains byte-for-byte intact in last_config.

    Reject unknown directives rather than silently dropping future policy.
    Errors never include the input, keys or parser exception text.
    """
    try:
        if not isinstance(raw, bytes) or len(raw) > 16384:
            raise ValueError()
        text = raw.decode('utf-8')
        conf = configparser.ConfigParser(interpolation=None, strict=True)
        conf.optionxform = str
        conf.read_string(text)
        if conf.defaults() or set(conf.sections()) != {'Interface', 'Peer'}:
            raise ValueError()
        interface, peer = conf['Interface'], conf['Peer']
        if (set(interface) - {'PrivateKey', 'Address', 'DNS', 'MTU', *AWG_FIELDS} or
                set(peer) - {'PublicKey', 'Endpoint', 'AllowedIPs',
                             'PersistentKeepalive', 'PresharedKey', 'PreSharedKey'}):
            raise ValueError()
        host, sep, port = peer['Endpoint'].rpartition(':')
        if not sep or not host or not 1 <= int(port) <= 65535:
            raise ValueError()
        dns = [v.strip() for v in interface['DNS'].split(',')]
        if not 1 <= len(dns) <= 2 or not all(dns):
            raise ValueError()
        native = {'config': text, 'hostName': host, 'port': int(port),
                  'client_priv_key': interface['PrivateKey'],
                  'client_ip': interface['Address'], 'server_pub_key': peer['PublicKey'],
                  'mtu': interface['MTU'],
                  'allowed_ips': [v.strip() for v in peer['AllowedIPs'].split(',')]}
        if 'PersistentKeepalive' in peer:
            native['persistent_keep_alive'] = peer['PersistentKeepalive']
        for field in ('PresharedKey', 'PreSharedKey'):
            if field in peer:
                if 'psk_key' in native:
                    raise ValueError()
                native['psk_key'] = peer[field]
        native.update({field: interface[field] for field in AWG_FIELDS if field in interface})
        container = {'container': 'amnezia-awg', 'awg': {
            'last_config': json.dumps(native, ensure_ascii=False, separators=(',', ':')),
            'isThirdPartyConfig': True, 'port': port, 'transport_proto': 'udp'}}
        # Existing AWG2 fields also permit the official client to infer version 2.
        if 'S3' in interface or 'S4' in interface or any('-' in interface.get(h, '') for h in AWG_FIELDS[7:11]):
            container['awg']['protocol_version'] = '2'
        envelope = {'containers': [container], 'defaultContainer': 'amnezia-awg',
                    'description': SERVER_DISPLAY_NAME, 'hostName': host,
                    'dns1': dns[0], 'dns2': dns[-1]}
        data = json.dumps(envelope, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        # Qt qCompress: uint32 big-endian original byte length + zlib stream.
        compressed = struct.pack('>I', len(data)) + zlib.compress(data, 8)
        return b'vpn://' + base64.urlsafe_b64encode(compressed).rstrip(b'=')
    except Exception:
        raise Refusal('export_format', 'unsupported client configuration for native export') from None
