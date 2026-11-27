"""Stage the supplemental Jammy local archive preserving the canonical package layout and checksum checks."""
import gzip,hashlib,json,os,subprocess,tarfile,tempfile
from pathlib import Path
proof=Path(__file__).resolve().parent
repo=Path('/workspace/Entanglement')
state=json.loads((proof/'provision.json').read_text())
build=json.loads((proof/'build.json').read_text())
source,commit=state['source'],state['commit']
w=Path(state['workspace']);frozen=w/'frozen'
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def stamp():
    assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=frozen,text=True).strip()==commit
    result=subprocess.check_output(['python3','scripts/production_score.py','--source-id'],cwd=frozen,text=True).strip()
    assert result==source
    return result
before=stamp()
assert build['exit_code']==0 and build['source_before']==before==build['source_after']
folder=repo/'target/release-candidate'/f'{commit[:12]}-ubuntu22'
folder.mkdir()
stem='entanglement-v0.1.0-x86_64-unknown-linux-gnu'
archive=folder/(stem+'.tar.gz')
ts=int(subprocess.check_output(['git','show','-s','--format=%ct',commit],cwd=frozen,text=True))
paths={'entangle':w/'release/entangle','entangled':w/'release/entangled','LICENSE':frozen/'LICENSE','README.md':frozen/'README.md','architecture.md':frozen/'docs/architecture.md','tutorial.md':frozen/'docs/tutorial.md'}
reference=json.loads((proof.parent/'linux-archive.json').read_text())
assert reference['source_commit']==commit and set(reference['files_sha256'])==set(paths)
for name,p in paths.items():
    assert sha(p)==(build['binary_sha256'][name] if name in ('entangle','entangled') else reference['files_sha256'][name])
with archive.open('xb') as archive_file:
    with gzip.GzipFile(filename='',mode='wb',fileobj=archive_file,mtime=ts) as gz,tarfile.open(fileobj=gz,mode='w',format=tarfile.USTAR_FORMAT) as out:
        for name,p in sorted(paths.items()):
            info=tarfile.TarInfo(stem+'/'+name)
            info.mode=0o755 if name in ('entangle','entangled') else 0o644
            info.mtime=ts;info.size=p.stat().st_size
            with p.open('rb') as f:out.addfile(info,f)
    archive_file.flush();os.fsync(archive_file.fileno())
bins=w/'archive-bins';bins.mkdir(mode=0o755);bins.chmod(0o755)
with tarfile.open(archive,'r:gz') as tg:
    members=tg.getmembers()
    assert len(members)==6 and {m.name for m in members}=={stem+'/'+name for name in paths}
    for member in members:
        name=member.name.split('/')[1]
        assert member.isreg() and member.size==paths[name].stat().st_size
        assert (member.mode, member.uid, member.gid, member.mtime)==(0o755 if name in ('entangle','entangled') else 0o644,0,0,ts)
        raw=tg.extractfile(member).read();assert hashlib.sha256(raw).hexdigest()==sha(paths[name])
        if name in ('entangle','entangled'):
            p=bins/name;p.write_bytes(raw);p.chmod(0o555)
env=dict(os.environ,PATH='/tmp/entanglement-release-check.zM5PAQ/usr/bin:/tmp/entanglement-cosign-check.OZB1U0:'+os.environ['PATH'])
b3=subprocess.check_output(['b3sum',archive],env=env,text=True).split()[0]
assert b3==subprocess.check_output(['/tmp/entangle-hash-artifact',archive],text=True).strip()
for suffix,checksum in [('sha256',sha(archive)),('b3',b3)]:
    archive.with_name(archive.name+'.'+suffix).write_text(f'{checksum}  {archive.name}\n')
with (proof/'verify-release.log').open('x') as f:
    for flags,expected in [(['--checksums-only'],0),([],1)]:
        cmd=['bash','scripts/verify-release.sh',*flags,str(archive)]
        print(cmd,file=f,flush=True)
        p=subprocess.run(cmd,cwd=frozen,stdout=f,stderr=subprocess.STDOUT,env=env)
        print('exit:',p.returncode,'expected:',expected,file=f,flush=True);assert p.returncode==expected
after=stamp()
sel=dict(source_id=before,source_before=before,source_after=after,source_commit=commit,name=archive.name,size=archive.stat().st_size,sha256=sha(archive),blake3=b3,signing_status='unsigned local compatibility candidate',files_sha256={name:sha(f) for name,f in paths.items()},tool_sha256=sha(w/'release/cargo-entangle'),verification_log_sha256=sha(proof/'verify-release.log'),canonical_source_archive_sha256=reference['sha256'],build_receipt_sha256=sha(proof/'build.json'))
for path in [folder/'verification.json',proof/'linux-archive.json']:
    with path.open('x') as f:json.dump(sel,f,indent=2);f.write('\n')
print(archive,sel['sha256'])
