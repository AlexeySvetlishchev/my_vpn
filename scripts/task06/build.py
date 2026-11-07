"""Build separate TASK 06 userspace binaries with an isolated UAPI socket directory."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
LOCK = json.loads(Path(__file__).with_name('build.lock.json').read_text())


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def output_hashes(directory):
    return {name: sha(directory / name) for name in ('amneziawg-go', 'awg')}


def main():
    work = ROOT / '.task06-build'
    source = ROOT / '.task05-build/go-src'
    tools_source = ROOT / '.task05-build/tools-src'
    commit = LOCK['go_commit']
    tools_commit = LOCK['tools_commit']
    run(['git', '-c', 'safe.directory=' + str(source), '-C', str(source), 'cat-file', '-e', commit + '^{commit}'])
    run(['git', '-c', 'safe.directory=' + str(tools_source), '-C', str(tools_source), 'cat-file', '-e', tools_commit + '^{commit}'])
    inputs = work / 'inputs'
    inputs.mkdir(parents=True, exist_ok=True)
    for repo, revision, archive in ((source, commit, 'go.tar'),
                                    (tools_source, tools_commit, 'tools.tar')):
        with (inputs / archive).open('wb') as out:
            run(['git', '-c', 'safe.directory=' + str(repo), '-C', str(repo),
                 'archive', '--format=tar', revision], stdout=out)
    module_cache = work / 'gomod-cache'
    module_cache.mkdir(parents=True, exist_ok=True)
    if not any(module_cache.iterdir()):
        run(['docker', 'run', '--rm', '--platform', LOCK['platform'],
             '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=256',
             '--cpus=2', '--memory=2g', '--mount',
             'type=bind,src=' + str(inputs) + ',dst=/input,readonly', '--mount',
             'type=bind,src=' + str(Path(__file__).with_name('download-modules.sh')) + ',dst=/download-modules.sh,readonly',
             '--mount', 'type=bind,src=' + str(module_cache) + ',dst=/go/pkg/mod',
             LOCK['builder'], '/bin/bash', '/download-modules.sh'])
    outputs = []
    if sys.argv[1:] == ['--verify-existing']:
        outputs = [output_hashes(ROOT / 'artifacts/task06' / ('build' + str(index)))
                   for index in (1, 2)]
    else:
        for index in (1, 2):
            out = ROOT / 'artifacts/task06' / ('build' + str(index))
            out.mkdir(parents=True, exist_ok=True)
            run(['docker', 'run', '--rm', '--network=none', '--platform', LOCK['platform'],
                 '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=256',
                 '--cpus=2', '--memory=2g',
                 '--mount', 'type=bind,src=' + str(inputs) + ',dst=/input,readonly',
                 '--mount', 'type=bind,src=' + str(module_cache) + ',dst=/go/pkg/mod,readonly',
                 '--mount', 'type=bind,src=' + str(Path(__file__).with_name('build-go.sh')) + ',dst=/build-go.sh,readonly',
                 '--mount', 'type=bind,src=' + str(out) + ',dst=/out',
                 LOCK['builder'], '/bin/bash', '/build-go.sh'])
            outputs.append(output_hashes(out))
    if outputs[0] != outputs[1]:
        raise RuntimeError('Independent TASK 06 builds differ')
    manifest = dict(LOCK, source_archive_sha256=sha(inputs / 'go.tar'),
                    tools_archive_sha256=sha(inputs / 'tools.tar'),
                    go_sum_sha256=sha(source / 'go.sum'),
                    binaries=outputs[0],
                    build_script_sha256=sha(Path(__file__).with_name('build-go.sh')),
                    build_driver_sha256=sha(Path(__file__)),
                    dependency_script_sha256=sha(Path(__file__).with_name('download-modules.sh')),
                    repeat_build_identical=True)
    out = ROOT / 'artifacts/task06'
    out.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(manifest, indent=2) + '\n').encode('utf-8')
    json.loads(data)
    (out / 'build-manifest.json').write_bytes(data)
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
