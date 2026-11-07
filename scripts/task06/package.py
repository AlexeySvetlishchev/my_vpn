"""Assemble a public TASK 06 deployment bundle locally."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(__file__).parent
RUNTIME_FILES = ('amneziawg-go', 'awg', 'helper.py', 'launcher.sh',
                 'vpn-task06-awg.service', 'vpn-task06-probe.service',
                 'vpn-task06-monitor.service', 'vpn-task06-monitor.timer')
PACKAGE_FILES = (*RUNTIME_FILES, 'install.py')


def main():
    output = ROOT / 'artifacts/task06/bundle'
    output.mkdir(parents=True, exist_ok=True)
    build = json.loads((ROOT / 'artifacts/task06/build-manifest.json').read_text())
    hashes = {}
    for name in RUNTIME_FILES:
        source = ROOT / 'artifacts/task06/build1' / name if name in ('amneziawg-go', 'awg') else SOURCE / name
        data = source.read_bytes()
        (output / name).write_bytes(data)
        hashes[name] = hashlib.sha256(data).hexdigest()
    if hashes['amneziawg-go'] != build['binaries']['amneziawg-go'] or hashes['awg'] != build['binaries']['awg']:
        raise RuntimeError('binary differs from repeated pinned build')
    install_data = (SOURCE / 'install.py').read_bytes()
    (output / 'install.py').write_bytes(install_data)
    hashes['install.py'] = hashlib.sha256(install_data).hexdigest()
    manifest = {'schema': 1, 'role': 'shared', 'build': build, 'files': hashes}
    data = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode('utf-8')
    json.loads(data)
    (output / 'manifest.json').write_bytes(data)
    print(json.dumps({'bundle': str(output),
                      'manifest_sha256': hashlib.sha256(data).hexdigest(),
                      'files': hashes}, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
