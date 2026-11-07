"""Local reproducible build, not a VPS installer. Requires local Docker + git.
Two independent containers build identical archives; unequal binaries fail.
No privileged container, host network, Docker socket mount or TUN access.
"""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
LOCK = json.loads((Path(__file__).with_name('build.lock.json')).read_text())


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest_bytes(manifest):
    """Serialize valid UTF-8 JSON with one real LF, independent of OS newline rules."""
    data = json.dumps(manifest, indent=2).encode('utf-8') + b'\n'
    json.loads(data)
    return data


def main():
    work = ROOT / '.task05-build'
    inputs = work / 'inputs'
    inputs.mkdir(parents=True, exist_ok=True)
    for name in ('go', 'tools'):
        source = work / (name + '-src')
        if not source.exists():
            run(['git', 'clone', '--no-checkout', LOCK[name + '_url'], str(source)])
        commit = LOCK[name + '_commit']
        # Archive immutable object, not checkout/worktree or an upstream branch.
        run(['git', '-C', str(source), 'cat-file', '-e', commit + '^{commit}'])
        with (inputs / (name + '.tar')).open('wb') as out:
            run(['git', '-C', str(source), 'archive', '--format=tar', commit], stdout=out)
    outputs = []
    for index in (1, 2):
        out = ROOT / 'artifacts/task05' / ('build' + str(index))
        out.mkdir(parents=True, exist_ok=True)
        run(['docker', 'run', '--rm', '--platform', LOCK['platform'],
             '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=256',
             '--cpus=2', '--memory=2g',
             '--mount', 'type=bind,src=' + str(inputs) + ',dst=/input,readonly',
             '--mount', 'type=bind,src=' + str(Path(__file__).with_name('build-inside.sh')) + ',dst=/build-inside.sh,readonly',
             '--mount', 'type=bind,src=' + str(out) + ',dst=/out',
             LOCK['builder'], '/bin/bash', '/build-inside.sh'])
        outputs.append({name: sha(out / name) for name in ('amneziawg-go', 'awg')})
    if outputs[0] != outputs[1]:
        raise RuntimeError('Independent builds differ; do not install')
    manifest = dict(LOCK, source_archives={n: sha(inputs / (n + '.tar')) for n in ('go', 'tools')},
                    binaries=outputs[0], repeat_build_identical=True,
                    build_script_sha256=sha(Path(__file__).with_name('build-inside.sh')))
    target = ROOT / 'artifacts/task05/build-manifest.json'
    target.write_bytes(manifest_bytes(manifest))
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
