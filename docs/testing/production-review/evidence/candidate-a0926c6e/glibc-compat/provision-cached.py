"""Adopt the prior paused Jammy build's dependency cache for an exact-source successor."""
import hashlib,json,os,shutil,subprocess,sys,tempfile,tomllib
from pathlib import Path
repo=Path('/workspace/Entanglement');commit,source=sys.argv[1:3]
evbase=repo/'docs/testing/production-review/evidence'
proof=evbase/('candidate-'+commit[:8])/'glibc-compat'
prior=evbase/'candidate-8e07cc25/glibc-compat'
ps=json.loads((prior/'provision.json').read_text());bw=json.loads((prior/'build.json').read_text())
assert bw['exit_code']==137 and bw['source_before']==ps['source']
def get(*a):return subprocess.check_output(a,cwd=repo,text=True).strip()
def digest(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
assert get('git','rev-parse',commit+'^{commit}')==commit
c=ps['container']
container=json.loads(get('docker','inspect',c))[0]
assert container['Image']==ps['image_id'] and not container['State']['Running'] and not container['NetworkSettings']['Networks']
w=Path(tempfile.mkdtemp(prefix='entangle-jammy-release-',dir='/workspace'));w.chmod(0o755)
fixture=w/'fixture';fixture.mkdir();fixture.chmod(0o755)
with (proof/'provision.log').open('x') as f:
 def go(*a):
  print([str(x) for x in a],file=f,flush=True)
  subprocess.run(a,cwd=repo,check=True,stdout=f,stderr=subprocess.STDOUT)
 go('git','clone','--shared','--bare','--no-tags',repo,w/'objects.git')
 go('git','--git-dir',w/'objects.git','update-ref','refs/heads/frozen-compatible',commit)
 go('git','--git-dir',w/'objects.git','bundle','create',fixture/'source.bundle','refs/heads/frozen-compatible')
 go('git','bundle','verify',fixture/'source.bundle')
 go('git','clone','--branch','frozen-compatible',fixture/'source.bundle',w/'frozen')
 assert get('git','-C',w/'frozen','rev-parse','HEAD')==commit
 assert subprocess.check_output(['python3','scripts/production_score.py','--source-id'],cwd=w/'frozen',text=True).strip()==source
 oldw=Path(ps['workspace'])
 for name in ['Cargo.lock','rust-toolchain.toml','.cargo/config.toml']:
  assert (oldw/'frozen'/name).read_bytes()==(w/'frozen'/name).read_bytes(),name
 # Profile/dependency settings must match. Workspace exclude may legitimately add an evidence-only probe.
 a,b=[tomllib.loads((p/'frozen/Cargo.toml').read_text()) for p in [oldw,w]]
 for v in [a,b]:v['workspace'].pop('exclude',None)
 assert a==b
 go('cp','-al',oldw/'fixture/toolchain',oldw/'fixture/registry',fixture)
 (fixture/'source.bundle').chmod(0o644)
 for name in ['cargo','rustc']:assert digest(fixture/'toolchain/bin'/name)==bw['compiler'][name]
 go('docker','start',c)
 assert json.loads(get('docker','inspect',c,'--format','{{json .NetworkSettings.Networks}}'))=={}
 go('docker','exec',c,'sh','-ec','cat /proc/net/route; test "$(wc -l </proc/net/route)" -eq 1; getconf GNU_LIBC_VERSION; gcc -v; /fixture/toolchain/bin/rustc -Vv; sha256sum /fixture/toolchain/bin/rustc /fixture/toolchain/bin/cargo')
 with (proof/'jammy-dpkg.txt').open('x') as packages:
  subprocess.run(['docker','exec',c,'dpkg-query','-W','-f=${binary:Package} ${Version}\n'],check=True,stdout=packages)
 assert digest(proof/'jammy-dpkg.txt')==bw['system_packages_sha256']
 go('docker','cp',fixture/'source.bundle',c+':/tmp/successor.bundle')
 assert get('docker','exec',c,'sha256sum','/tmp/successor.bundle').split()[0]==digest(fixture/'source.bundle')
 names=[]
 for mem in a['workspace']['members']:
  for m in (w/'frozen').glob(mem):names.append(tomllib.loads((m/'Cargo.toml').read_text())['package']['name'])
 assert set(names)=={pkg['name'] for pkg in tomllib.loads((w/'frozen/Cargo.lock').read_text())['package'] if 'source' not in pkg}
 assert len(names)==len(set(names)) and {'entangle-cli','entangle-bin','entangle-scheduler','cargo-entangle','xtask'}<=set(names)
 original=(proof/'build.sh').read_text()
 s=original[:original.index('test ! -e "$CARGO_TARGET_DIR"')]+('''test -d "$CARGO_TARGET_DIR"
cd /tmp/build-source
git fetch --no-tags /tmp/successor.bundle refs/heads/frozen-compatible
git checkout --detach FETCH_HEAD
''')+original[original.index('test "$(git rev-parse HEAD)"'):]
 import shlex
 clean=['cargo','clean','--release','--offline','--locked']
 for n in sorted(names):clean.extend(['--package',n])
 s=s.replace('sha256sum Cargo.lock Cargo.toml', 'sha256sum Cargo.lock Cargo.toml\n'+shlex.join(clean))
 (proof/'build.sh').write_text(s)
 b=proof/'build.py'
 b.write_text(b.read_text().replace("scope='clean rootless offline Ubuntu 22.04 build; no prebuilt native project artifacts'","scope='rootless offline Ubuntu 22.04 build; every source-workspace package cleaned before compilation, existing third-party dependency target artifacts may be reused',cache_parent_source_id=state['cache_parent_source_id'],cleaned_workspace_packages=state['cleaned_workspace_packages']"))
 record=dict(commit=commit,source=source,workspace=str(w),image_id=ps['image_id'],container=c,networks_for_build={},cache_parent_source_id=bw['source_before'],cache_parent_build_receipt_sha256=digest(prior/'build.json'),cleaned_workspace_packages=sorted(names))
 for p in [proof/'provision.json',w/'state.json']:p.write_text(json.dumps(record,indent=2)+'\n')
