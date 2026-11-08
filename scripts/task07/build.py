"""Offline deterministic build from the already pinned TASK 06 source archives."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
TASK06 = ROOT / 'artifacts/task06/build-manifest.json'
INPUTS = ROOT / '.task06-build/inputs'
CACHE = ROOT / '.task06-build/gomod-cache'
OUT = ROOT / 'artifacts/task07'
BUILDER = 'golang@sha256:4f43b271f9673eb7bd0cb3a49cc17b08d8d6ee110277e26dbacc93c43a5a7793'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    pinned = json.loads(TASK06.read_text(encoding='utf-8'))
    assert pinned['go_commit'] == 'b5928efb6ca19f0153958460c3d141f04abc5c2e'
    assert pinned['tools_commit'] == 'ee0f0a9aa34ff0a0da4b3433b9512781cfe02843'
    assert sha(INPUTS / 'go.tar') == pinned['source_archive_sha256']
    assert sha(INPUTS / 'tools.tar') == pinned['tools_archive_sha256']
    results = []
    for index in (1, 2):
        target = OUT / ('build' + str(index))
        target.mkdir(parents=True, exist_ok=True)
        subprocess.run(['docker', 'run', '--rm', '--network=none', '--platform', 'linux/amd64',
                        '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=256',
                        '--cpus=2', '--memory=2g',
                        '--mount', 'type=bind,src=' + str(INPUTS) + ',dst=/input,readonly',
                        '--mount', 'type=bind,src=' + str(CACHE) + ',dst=/go/pkg/mod,readonly',
                        '--mount', 'type=bind,src=' + str(Path(__file__).with_name('build-go.sh')) + ',dst=/build-go.sh,readonly',
                        '--mount', 'type=bind,src=' + str(target) + ',dst=/out',
                        BUILDER, '/bin/bash', '/build-go.sh'], check=True)
        results.append({name: sha(target / name) for name in ('amneziawg-go', 'awg')})
    if results[0] != results[1]:
        raise RuntimeError('TASK 07 independent builds differ')
    OUT.joinpath('build-manifest.json').write_text(json.dumps({
        'go_commit': pinned['go_commit'], 'tools_commit': pinned['tools_commit'],
        'source_archive_sha256': pinned['source_archive_sha256'],
        'tools_archive_sha256': pinned['tools_archive_sha256'],
        'socket_directory': '/run/vpn-task07/amneziawg',
        'binaries': results[0], 'repeat_build_identical': True}, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(results[0], sort_keys=True))


if __name__ == '__main__':
    main()
