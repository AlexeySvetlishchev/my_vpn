"""Encode profile through stdin; no key-bearing argv or temporary file."""
import subprocess

def profile_qr(content):
    if not isinstance(content,bytes) or len(content)>2300:raise ValueError('qr_profile_bound')
    p=subprocess.run(['/usr/bin/qrencode','-t','PNG','-l','M','-s','6','-m','4','-o','-'],
                     input=content,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10)
    if p.returncode or len(p.stdout)>524288 or not p.stdout.startswith(b'\x89PNG\r\n\x1a\n'):
        raise ValueError('qr_encoding_failed')
    return p.stdout
