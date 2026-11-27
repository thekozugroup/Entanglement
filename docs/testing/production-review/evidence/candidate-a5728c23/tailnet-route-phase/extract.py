import hashlib,json,sys,tarfile
from pathlib import Path
repo=Path('/workspace/Entanglement')
commit,source=sys.argv[1:]
d=repo/'docs/testing/production-review/evidence'/('candidate-'+commit[:8])
a=json.loads((d/'linux-archive.json').read_bytes())
r=json.loads((d/'release-build.json').read_bytes())
assert r['exit_code']==0 and r['source_after']==a['source_id']==a['source_after']==source
assert a['source_commit']==commit
def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
p=repo/'target/release-candidate'/commit[:12]/a['name']
assert p.name==a['name'] and sha(p)==a['sha256']
dest=Path(__file__).parent/(commit[:8]+'-verified-bin');dest.mkdir(mode=0o700,exist_ok=True)
with tarfile.open(p,'r:gz')as t:
 for name in ['entangled','entangle']:
  entries=[m for m in t.getmembers() if m.isfile() and Path(m.name).name==name]
  assert len(entries)==1
  data=t.extractfile(entries[0]).read()
  assert hashlib.sha256(data).hexdigest()==a['files_sha256'][name]
  out=dest/name
  if out.exists():assert sha(out)==a['files_sha256'][name]
  else:
   with out.open('xb') as f:f.write(data)
   out.chmod(0o700)
print(dest)
