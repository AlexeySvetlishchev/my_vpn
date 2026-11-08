#!/usr/bin/python3
"""Short DNS response probe; prints metadata only, no answer contents."""
import json
import socket
import sys

if len(sys.argv) != 1:
    raise SystemExit(2)
query = (bytes.fromhex('a10101000001000000000000') +
         b'\x07example\x03org\x00' + bytes.fromhex('00010001'))
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(4)
sock.sendto(query, ('10.203.253.1', 53))
answer, _ = sock.recvfrom(4096)
print(json.dumps({'dns_reply': len(answer) > 12, 'rcode': answer[3] & 15,
                  'answer_count': int.from_bytes(answer[6:8], 'big')}))
