"""Compare both actual exports and their independent in-container size/SHA measurements."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(subprocess.check_output(['git','rev-parse','--show-toplevel'],text=True).strip())
if len(sys.argv) != 4:
    raise SystemExit('usage: compare.py JAMMY_OUTPUT NOBLE_OUTPUT NEW_COMPARISON_JSON')
started=datetime.now(timezone.utc).isoformat()
before=subprocess.check_output([sys.executable,'-B','scripts/production_score.py','--source-id'],text=True,cwd=ROOT).strip()
versions={}
archives=[]
for version, name in zip(('22.04','24.04'),sys.argv[1:3]):
    folder=Path(name).resolve()
    path=folder/'receipt.json'
    r=json.loads(path.read_bytes())
    assert r['os_version']==version and r['exit_code']==0
    assert before==r['source_before']==r['source_after']
    assert hashlib.sha256((ROOT/r['log']).read_bytes()).hexdigest()==r['sha256']
    data=(folder/'hello-world.tar.zst').read_bytes()
    assert (len(data),hashlib.sha256(data).hexdigest())==(r['archive_size'],r['archive_sha256'])
    archives.append(data)
    versions[version]={'archive_size':len(data),'archive_sha256':r['archive_sha256'],'component':r['members']['plugin.wasm'],
        'base_image':r['base_image'],'native_packager_sha256':r['native_packager_sha256'],
        'receipt':str(path.relative_to(ROOT)),'receipt_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
        'source_bundle_sha256':r['source_bundle_sha256'],'rust_toolchain_digests':r['compiler_sha256']}
assert len({r['native_packager_sha256'] for r in versions.values()})==2
assert versions['22.04']['rust_toolchain_digests']==versions['24.04']['rust_toolchain_digests']
assert versions['22.04']['source_bundle_sha256']==versions['24.04']['source_bundle_sha256']
a,b=archives
same_size=len(a)==len(b)
same_digest=hashlib.sha256(a).digest()==hashlib.sha256(b).digest()
same_component=versions['22.04']['component']==versions['24.04']['component']
success=same_size and same_digest and same_component and a==b
after=subprocess.check_output([sys.executable,'-B','scripts/production_score.py','--source-id'],text=True,cwd=ROOT).strip()
assert before==after
result={'source_id':before,'source_before':before,'source_after':after,'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True,cwd=ROOT).strip(),
        'started_utc':started,'finished_utc':datetime.now(timezone.utc).isoformat(),'exit_code':0 if success else 1,
        'command':['python3','-B',str(Path(__file__).resolve().relative_to(ROOT)),*[str(Path(arg).resolve().relative_to(ROOT)) for arg in sys.argv[1:]]],
        'archive_size_equal':same_size,'archive_sha256_equal':same_digest,'archives_byte_identical':a==b,'component_size_and_sha256_equal':same_component,'observations':versions,
        'scope':'Partial ATC-PKG-2. Separate pinned Ubuntu 22.04 and 24.04 userspaces on one x86_64 Linux host, using two exact native package executables, Rust 1.91.1 and the same public test signer. macOS 14 and independent physical hardware remain unverified.'}
failed=Path(__file__).resolve().parent/'jammy/receipt.json'
first=json.loads(failed.read_bytes())
assert first['exit_code'] != 0 and first['source_after'] == before
assert hashlib.sha256((ROOT/first['log']).read_bytes()).hexdigest() == first['sha256']
result['initial_jammy_attempt']={'receipt':str(failed.relative_to(ROOT)), 'receipt_sha256':hashlib.sha256(failed.read_bytes()).hexdigest(), 'exit_code':first['exit_code'], 'scope':'The first helper invoked Cargo inside the repository, where its development alias shadowed the verified external packager. The command stopped before compilation. Both measured arms invoked the external packager from a neutral directory.'}
with Path(sys.argv[3]).open('x') as f:
    json.dump(result,f,indent=2); f.write('\n')
print(json.dumps({key:result[key] for key in ('archive_size_equal','archive_sha256_equal','archives_byte_identical','component_size_and_sha256_equal','exit_code')}))
sys.exit(result['exit_code'])
