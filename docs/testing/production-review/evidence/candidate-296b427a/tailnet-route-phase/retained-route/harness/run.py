"""Run once against exact archived binaries. Keep evidence on any error."""
import datetime, hashlib, json, os, subprocess, sys, tempfile
from pathlib import Path
D=Path(__file__).resolve().parent
R=Path('/workspace/Entanglement')
COMMIT='296b427a3bb2d60615ea3c56b9779f97039c6e24'
SOURCE='sha256:b65a7bd226264bd85b84fca929676a8cb5be88dd6ee188e3b2e30d9f2cb9ab4b'
E=R/'docs/testing/production-review/evidence/candidate-296b427a'
a=json.loads((E/'linux-archive.json').read_bytes())
b=Path('/tmp/entangle-check-296b427a-archive')
w=R/'plugins/json-pointer/target/wasm32-wasip2/release/entangle_json_pointer.wasm'
def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def command(*args):return subprocess.check_output(args,cwd=R,text=True).strip()
def stamp():return dict(head=command('git','rev-parse','HEAD'),source=command(sys.executable,'scripts/production_score.py','--source-id'))
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
assert a['source_commit']==COMMIT and a['source_id']==SOURCE
el={n:sha(b/n) for n in ['entangle','entangled']}
assert el=={n:a['files_sha256'][n] for n in el}
assert sha(w)==json.loads((E/'private-recovery-scorer-receipt.json').read_bytes())['wasm_sha256']
out=Path(tempfile.mkdtemp(prefix='observed-',dir=D))
before=stamp()
assert before['source']==SOURCE
images={i:command('docker','image','inspect','--format','{{.Id}}',i) for i in ['headscale/headscale:0.27.1','tailscale/tailscale:v1.92.5','python:3.12-slim-trixie']}
counts=command('docker','ps','-a','--format','{{.Names}}').splitlines()
print(str(out),flush=True)
start=utc()
with (out/'result.json').open('w') as f,(out/'stderr.log').open('w') as g:
 rc=subprocess.run([sys.executable,'-B',str(D/'private-tailnet.py'),'--recovery','--bin-dir',str(b),'--wasm',str(w)],stdout=f,stderr=g,env={**os.environ,'TRACE_OUT':str(out)},cwd=R).returncode
post=command('docker','ps','-a','--format','{{.Names}}').splitlines()
receipt=dict(command=sys.argv,before=before,after=stamp(),start=start,end=utc(),rc=rc,sha256=el,archive=a['sha256'],wasm_sha256=sha(w),images=images,script_sha256={p.name:sha(p) for p in D.glob('*.py')},files={p.name:sha(p) for p in out.glob('*')},remaining_new_containers=sorted(set(post)-set(counts)),topology='two Linux network namespaces on one x86_64 physical host')
(out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
sys.exit(rc)
