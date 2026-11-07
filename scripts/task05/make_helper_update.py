"""Create a two-file TASK 05 helper update bundle; no SSH or installation."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NAMES = {'amneziawg-go', 'awg', 'helper.py', 'launcher.sh', 'bootstrap.py'}


def manifest_bytes(source, helper):
    manifest = json.loads(source)
    if set(manifest.get('files', {})) != NAMES:
        raise ValueError('unexpected manifest file set')
    manifest['files']['helper.py'] = hashlib.sha256(helper).hexdigest()
    encoded = (json.dumps(manifest, indent=2) + '\n').encode('utf-8')
    # Parse the exact bytes to catch malformed serialization before delivery.
    json.loads(encoded)
    return encoded


def main():
    helper = (ROOT / 'scripts/task05/helper.py').read_bytes()
    source = (ROOT / 'artifacts/task05/bundle/manifest.json').read_bytes()
    output = ROOT / 'artifacts/task05/helper-update'
    output.mkdir(parents=True, exist_ok=True)
    manifest = manifest_bytes(source, helper)
    (output / 'helper.py').write_bytes(helper)
    (output / 'manifest.json').write_bytes(manifest)
    print('helper_sha256=' + hashlib.sha256(helper).hexdigest())
    print('manifest_sha256=' + hashlib.sha256(manifest).hexdigest())


if __name__ == '__main__':
    main()
