"""Qualify exact release-only source, official package and the prior Jammy build inputs."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

repo = Path('/workspace/Entanglement')
prior = 'a0926c6ef3471aad01cedd256028437b249ef747'
proofs = repo / 'docs/testing/production-review/evidence'
previous = proofs / ('candidate-' + prior[:8]) / 'glibc-compat'
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('commit'); p.add_argument('source')
a = p.parse_args()
proof = proofs / ('candidate-' + a.commit[:8]) / 'glibc-compat'

def get(*args, cwd=repo, env=None):
    return subprocess.check_output(args, cwd=cwd, env=env, text=True).strip()

def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def record(name, data):
    with (proof / name).open('x') as f:
        json.dump(data, f, indent=2); f.write('\n')

def stamp():
    assert get('git', 'rev-parse', 'HEAD') == a.commit
    current = get(sys.executable, 'scripts/production_score.py', '--source-id')
    assert current == a.source
    return current

before = stamp()
roots = ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', '.cargo', 'crates','tools','examples','plugins','supply-chain','docker']
objects = {}
for path in roots:
    old = get('git', 'rev-parse', prior + ':' + path)
    assert old == get('git', 'rev-parse', a.commit + ':' + path), 'Compiler-affecting change; rebuild required: ' + path
    objects[path] = old
changed = get('git','diff','--name-only',prior, a.commit, '--', '.', ':(exclude)docs/testing/production-review/evidence', ':(exclude)docs/testing/production-review/runs').splitlines()
# Fail closed outside explicitly non-compiler-input paths. Rust literal include sites in the workspace were inspected.
assert all(x.startswith(('docs/', 'scripts/', '.github/', 'packaging/')) or x in {'README.md','STATUS.md','CHANGELOG.md','SECURITY.md','LICENSE','.gitignore'} for x in changed), changed
oldbuild = json.loads((previous/'build.json').read_bytes()); oldstate = json.loads((previous/'provision.json').read_bytes())
assert oldbuild['exit_code']==0 and oldbuild['source_before']==oldbuild['source_after']==oldstate['source'] and oldstate['commit']==prior
bins = Path(oldstate['workspace'])/'release'
assert {n:sha(bins/n) for n in oldbuild['binary_sha256']} == oldbuild['binary_sha256']
proof.mkdir()
work = Path(tempfile.mkdtemp(prefix='entangle-release-compat-',dir='/workspace'));work.chmod(0o755)
(work/'frozen').symlink_to(repo); (work/'archive-bins').mkdir(mode=0o755); (work/'archive-bins').chmod(0o755)
record('provision.json', dict(workspace=str(work),commit=a.commit,source=a.source,image_id=oldstate['image_id'], method='verified exact Jammy ELF reuse'))
record('build-inputs.json', dict(source_before=before,source_after=stamp(),commit=a.commit,from_commit=prior,prior_build_receipt_sha256=sha(previous/'build.json'),prior_provision_receipt_sha256=sha(previous/'provision.json'),method='Retained Ubuntu 22.04 ELFs from the prior locked/offline optimized build. The compiler was not run for this release-only successor.',equal_git_tree_or_blob_ids=objects,changed_outside_evidence=changed,unchanged_elfs_sha256=oldbuild['binary_sha256']))
frame = ['entangle','entangled','LICENSE','README.md','architecture.md','tutorial.md']
files = {n:bins/n for n in frame[:2]}; files.update({'LICENSE':repo/'LICENSE','README.md':repo/'README.md','architecture.md':repo/'docs/architecture.md','tutorial.md':repo/'docs/tutorial.md'})
folder = repo / 'target/release-candidate' / (a.commit[:12]+'-ubuntu22');folder.mkdir()
name='entanglement-v0.1.0-x86_64-unknown-linux-gnu.tar.gz';archive=folder/name
epoch=get('git','show','-s','--format=%ct',a.commit)
env = dict(os.environ,PATH='/tmp/entanglement-release-check.zM5PAQ/usr/bin:/tmp/entanglement-cosign-check.OZB1U0:'+os.environ['PATH'])
command = [sys.executable,'scripts/package-native-release.py','--version','v0.1.0','--target','x86_64-unknown-linux-gnu','--bin-dir',str(bins),'--source-date-epoch',epoch,'--output-dir',str(folder)]
with (proof/'package.log').open('x') as f: subprocess.run(command,cwd=repo,env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
with (proof/'verify-release.log').open('x') as f:
    for flags,wanted in [(['--checksums-only'],0),([],1)]:
        check=['bash','scripts/verify-release.sh',*flags,str(archive)];print(check,file=f,flush=True);r=subprocess.run(check,cwd=repo,env=env,stdout=f,stderr=subprocess.STDOUT); print('exit',r.returncode,'expected',wanted,file=f,flush=True);assert r.returncode==wanted
with tarfile.open(archive,'r:gz') as tar:
    members=tar.getmembers(); prefix=name.removesuffix('.tar.gz')+'/'
    regular=[member for member in members if member.isfile()]
    assert len(regular)==len(frame) and {member.name for member in regular}=={prefix+n for n in frame}
    assert len(members)==7 and members[0].isdir() and members[0].name==prefix.rstrip('/')
    assert (members[0].mode,members[0].uid,members[0].gid,members[0].mtime)==(0o755,0,0,int(epoch))
    assert members[1:]==regular
    for member in regular:
        n=member.name[len(prefix):]; wanted_mode=0o755 if n in frame[:2] else 0o644
        assert (member.uid,member.gid,member.mode,member.mtime)==(0,0,wanted_mode,int(epoch)),member
        raw=tar.extractfile(member).read();assert hashlib.sha256(raw).hexdigest()==sha(files[n])
        if n in frame[:2]:
            target=work/'archive-bins'/n;target.write_bytes(raw);target.chmod(0o555)
values=dict(source_before=before,source_after=stamp(),source_id=a.source,source_commit=a.commit,name=name,archive_path=str(archive),sha256=sha(archive),size=archive.stat().st_size,blake3=get('b3sum','--no-names',str(archive),env=env),command=command,packager_sha256=sha(repo/'scripts/package-native-release.py'),verify_release_log_sha256=sha(proof/'verify-release.log'),files_sha256={n:sha(f) for n,f in files.items()},signing_status='unsigned local compatibility candidate',tool_sha256=sha(bins/'cargo-entangle'),build_inputs_receipt_sha256=sha(proof/'build-inputs.json'))
record('linux-archive.json',values)
for filename in ['workload.py','workload-newer-userspaces.py','cross-userspace-warm.py']:
    content=(previous/filename).read_text().replace('a0926c6ef347-ubuntu22',a.commit[:12]+'-ubuntu22');compile(content,filename,'exec');(proof/filename).write_text(content)
print(json.dumps(values,indent=2))
