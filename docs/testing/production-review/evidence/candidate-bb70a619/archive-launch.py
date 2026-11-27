"""Launch each canonical x86-64 Linux archive executable in local isolated distribution images."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[5]
out = Path(__file__).resolve().parent
binaries = Path(sys.argv[1]).resolve(strict=True)
manifest = json.loads((out/'linux-archive.json').read_text())
started = datetime.now(timezone.utc).isoformat()
def capture(args):
    return subprocess.run(args,cwd=root,capture_output=True,text=True,timeout=60)
def get(args):
    result = capture(args)
    result.check_returncode()
    return result.stdout.strip()
def stamp():
    return get(['python3','scripts/production_score.py','--source-id'])
source = stamp()
assert source == manifest['source_id'] == manifest['source_after']
assert get(['git','rev-parse','HEAD'])==manifest['source_commit']
variants = {'ubuntu:22.04':('22.04','2.35',False),'ubuntu:24.04':('24.04','2.39',True),
            'debian:bookworm-slim':('12','2.36',False),'debian:trixie-slim':('13','2.41',True)}
artifact, floors, results = {}, {}, {}
for name in ('entangle','entangled'):
    path = binaries/name
    with path.open('rb') as f:
        artifact[name]=hashlib.file_digest(f,'sha256').hexdigest()
    assert artifact[name]==manifest['files_sha256'][name]
    versions=re.findall(r'Name: GLIBC_([\d.]+)',get(['readelf','--version-info',str(path)]))
    floors[name]=max(versions,key=lambda v:tuple(map(int,v.split('.'))))
    assert floors[name]=='2.39'
for tag,(version,glibc,expected_run) in variants.items():
    image=json.loads(get(['docker','image','inspect',tag]))[0]
    prefix=['docker','run','--rm','--pull=never','--network=none','--cap-drop=ALL','--read-only',
            '--security-opt=no-new-privileges','--mount',f'type=bind,src={binaries},dst=/candidate,readonly',image['Id']]
    info=get(prefix+['sh','-ec','. /etc/os-release && echo "$VERSION_ID" && getconf GNU_LIBC_VERSION'])
    assert info==version+'\nglibc '+glibc,(tag,info)
    launches={}
    for name in artifact:
        command=prefix+['/candidate/'+name,'--version']
        run=capture(command)
        launches[name]=dict(command=command,exit_code=run.returncode,stdout=run.stdout,stderr=run.stderr)
        if expected_run: assert run.returncode==0 and '0.1.0' in run.stdout,launches[name]
        else: assert run.returncode!=0 and 'GLIBC_2.39' in run.stderr,launches[name]
    results[tag]=dict(image_id=image['Id'],repo_digests=image['RepoDigests'],os_release_version=version,glibc=glibc,launches=launches)
after=stamp()
assert source==after
record=dict(source_before=source,source_after=after,source_id=source,source_commit=manifest['source_commit'],
            archive_sha256=manifest['sha256'],artifact_sha256=artifact,max_required_glibc=floors,platform_scope='Four isolated local Linux amd64 userspaces on one host; executable launch only',
            started_at_utc=started,finished_at_utc=datetime.now(timezone.utc).isoformat(),exit_code=0,distros=results)
with (out/'archive-launch.json').open('x') as f:
    json.dump(record,f,indent=2);f.write('\n')
for k,v in results.items():print(k,v['glibc'],[(n,s['exit_code'],s['stdout'].strip(),s['stderr'].strip()) for n,s in v['launches'].items()])
