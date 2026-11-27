"""Run once against exact archived binaries. Keep evidence on any error."""
import datetime, hashlib, json, os, subprocess, sys, tempfile
from pathlib import Path
D=Path(__file__).resolve().parent
R=Path('/workspace/Entanglement')
COMMIT='a5728c230e5049556b806cae8597fe823dd67987'
SOURCE='sha256:a43296d252b79d7a0762861de1251b0e2e77fde20af2ea5dd43254617376fce5'
E=R/'docs/testing/production-review/evidence'/('candidate-'+COMMIT[:8])
a=json.loads((E/'linux-archive.json').read_bytes())
b=Path(sys.argv[1]).resolve()
w=R/'plugins/json-pointer/target/wasm32-wasip2/release/entangle_json_pointer.wasm'
def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def command(*args):return subprocess.check_output(args,cwd=R,text=True).strip()
def stamp():return dict(head=command('git','rev-parse','HEAD'),source=command(sys.executable,'scripts/production_score.py','--source-id'))
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
assert a['source_commit']==COMMIT and a['source_id']==SOURCE
el={n:sha(b/n) for n in ['entangle','entangled']}
assert el=={n:a['files_sha256'][n] for n in el}
assert sha(w)==json.loads((E.parent/'candidate-296b427a/private-recovery-scorer-receipt.json').read_bytes())['wasm_sha256']
out=Path(tempfile.mkdtemp(prefix='observed-',dir=D))
before=stamp()
assert before=={'source':SOURCE,'head':COMMIT}
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
