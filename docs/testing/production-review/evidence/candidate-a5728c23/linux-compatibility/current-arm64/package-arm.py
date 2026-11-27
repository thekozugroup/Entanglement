"""Package the compiled ARM GNU Linux executable pair using the frozen release helper."""
from pathlib import Path
import hashlib,json,os,subprocess,tarfile

work=Path('/workspace/entangle-emulated-arm-a5728c23');proof=work/'proof';source=work/'frozen'
inputs=json.loads((proof/'inputs.json').read_text());build=json.loads((proof/'arm-build.json').read_text());assert build['exit_code']==0
commit=inputs['commit'];get=lambda argv,**kw:subprocess.check_output(argv,text=True,**kw).strip()
def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def stamp():
    assert get(['git','rev-parse','HEAD'],cwd=source)==commit
    t=get(['python3','scripts/production_score.py','--source-id'],cwd=source);assert t==inputs['source_before'];return t
before=stamp();out=work/'release-archive';env=dict(os.environ,PATH='/tmp/entanglement-release-check.zM5PAQ/usr/bin:/tmp/entanglement-cosign-check.OZB1U0:'+os.environ['PATH']);epoch=get(['git','show','-s','--format=%ct',commit],cwd=source);cmd=['python3','scripts/package-native-release.py','--version','v0.1.0','--target','aarch64-unknown-linux-gnu','--bin-dir',str(work/'executables'),'--source-date-epoch',epoch,'--output-dir',str(out)];subprocess.run(cmd,cwd=source,env=env,check=True)
asset=out/'entanglement-v0.1.0-aarch64-unknown-linux-gnu.tar.gz';stem=asset.name.removesuffix('.tar.gz');paths={'entangle':work/'executables/entangle','entangled':work/'executables/entangled','architecture.md':source/'docs/architecture.md','tutorial.md':source/'docs/tutorial.md','README.md':source/'README.md','LICENSE':source/'LICENSE'}
with tarfile.open(asset) as archive:
    members=archive.getmembers();assert len(members)==7 and members[0].isdir() and members[0].name==stem
    assert {m.name for m in members[1:]}=={stem+'/'+n for n in paths}
    for item in members[1:]:
        n=item.name.split('/')[1];assert item.isfile() and item.mtime==int(epoch) and (item.uid,item.gid)==(0,0);assert item.mode==(0o755 if n in ('entangle','entangled') else 0o644)
        assert hashlib.sha256(archive.extractfile(item).read()).hexdigest()==sha(paths[n])
with (proof/'verify-arm-archive.log').open('x') as f:
    for flags,wanted in [(['--checksums-only'],0),([],1)]:
        result=subprocess.run(['bash','scripts/verify-release.sh',*flags,str(asset)],cwd=source,env=env,stdout=f,stderr=subprocess.STDOUT);assert result.returncode==wanted
record=dict(source_before=before,source_after=stamp(),source_commit=commit,archive_name=asset.name,artifact_scope='Cross-compiled release profile ARM64 GNU Linux executables, verified with explicit QEMU user-mode on x86_64. Local unsigned archive.',elfs_sha256=build['executables_sha256'],archive_sha256=sha(asset),size=asset.stat().st_size,blake3=get(['b3sum','--no-names',str(asset)],env=env),packager_sha256=sha(source/'scripts/package-native-release.py'),verifier_sha256=sha(source/'scripts/verify-release.sh'),release_verification_log_sha256=sha(proof/'verify-arm-archive.log'),command=cmd,expected_unsigned_rejection=True,build_receipt_sha256=sha(proof/'arm-build.json'))
with (proof/'arm-archive.json').open('x') as f:json.dump(record,f,indent=2);f.write('\n')
print(record['archive_sha256'],record['blake3'])
