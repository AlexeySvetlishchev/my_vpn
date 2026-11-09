"""Read-only precommit review of the Git index, never working server secrets.

Checks syntax, common secret signatures, accidental runtime artifacts and
TASK10 manifest reproducibility from committed bytes (including line endings).
Not a general guarantee that an arbitrary file can contain no secret.
"""
import hashlib
import json
from pathlib import Path,PurePosixPath
import re
import subprocess


def git(*args):
    return subprocess.check_output(['git','-c','safe.directory='+str(Path.cwd()),*args],stderr=subprocess.DEVNULL)


def main():
    paths=git('diff','--cached','--name-only','--diff-filter=ACMR','-z').decode().split('\0')
    paths=[p for p in paths if p]
    patterns=[rb'\b[0-9]{5,15}:[A-Za-z0-9_-]{30,100}\b',
              rb'-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----',
              rb'(?m)^\s*(?:PrivateKey|PresharedKey)\s*=\s*[A-Za-z0-9+/]{43}=']
    forbidden={'.key','.pem','.p12','.pfx','.conf','.vpn','.db','.sqlite','.sqlite3',
               '.tar','.gz','.zip','.bak','.log','.tmp','.png','.pyc'}
    content={}
    for path in paths:
        name=PurePosixPath(path)
        if name.suffix in forbidden or name.name in ('token','admins.json','credentials.json','state.json'):
            raise ValueError('forbidden_runtime_file:'+path)
        raw=git('show',':'+path);content[path]=raw
        if any(re.search(pattern,raw) for pattern in patterns):
            raise ValueError('possible_secret_signature:'+path)
        if name.suffix in ('.py','.pyw'):
            compile(raw,path,'exec')
    manifest=json.loads(git('show',':scripts/task10/manifest.json'))
    checked=0
    for name,digest in manifest.items():
        if name=='task08-recover.py':path='scripts/task08/recover.py'
        elif name.endswith(('.py','.service')):path='scripts/task10/'+name
        else:continue
        raw=git('show',':'+path)
        assert hashlib.sha256(raw).hexdigest()==digest,'index_manifest_mismatch:'+path
        checked+=1
    git('diff','--cached','--check')
    print(json.dumps({'staged_files':len(paths),'python_syntax':True,
                      'common_secret_signatures_detected':False,'runtime_artifacts_detected':False,
                      'manifest_matches_committed_bytes':checked,'diff_check':True}))


if __name__=='__main__':main()
