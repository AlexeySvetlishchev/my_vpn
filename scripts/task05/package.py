"""Assemble public owner-review bundle locally; does not connect or install."""
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[2]


def manifest_bytes(manifest):
    """Serialize valid UTF-8 JSON with an actual LF, never a literal backslash-n."""
    data = (json.dumps(manifest, indent=2) + '\n').encode('utf-8')
    json.loads(data)
    return data


def main():
    source = Path(__file__).parent
    out = ROOT / 'artifacts/task05/bundle'
    out.mkdir(parents=True, exist_ok=True)
    build = json.loads((ROOT / 'artifacts/task05/build-manifest.json').read_text())
    files = {}
    for name in ('amneziawg-go', 'awg', 'helper.py', 'launcher.sh', 'bootstrap.py'):
        original = (ROOT / 'artifacts/task05/build1' / name if name in ('amneziawg-go', 'awg') else
                    source / name)
        data = original.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if name in build['binaries'] and digest != build['binaries'][name]:
            raise RuntimeError('binary differs from repeated build')
        (out / name).write_bytes(data)
        files[name] = digest
    manifest = dict(build=build, files=files)
    data = manifest_bytes(manifest)
    (out / 'manifest.json').write_bytes(data)
    print('Bundle manifest SHA256:', hashlib.sha256(data).hexdigest())
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
