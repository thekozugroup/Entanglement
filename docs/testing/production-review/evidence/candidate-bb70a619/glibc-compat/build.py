"""Build with empty target in the provisioned, disconnected rootless Jammy userspace."""
import datetime,hashlib,json,os,subprocess,tomllib
from pathlib import Path
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
proof=Path(__file__).resolve().parent
state=json.loads((proof/'provision.json').read_text())
w=Path(state['workspace'])
frozen=w/'frozen'
def stamp():
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=frozen,text=True).strip()
    src=subprocess.check_output(['python3','scripts/production_score.py','--source-id'],cwd=frozen,text=True).strip()
    assert (commit,src)==(state['commit'],state['source'])
    return src
before=stamp()
c=state['container']
cache=w/'fixture/registry/cache'
indices=list(cache.iterdir());assert len(indices)==1
registry_records=[pkg for pkg in tomllib.loads((frozen/'Cargo.lock').read_text())['package'] if pkg.get('source','').startswith('registry+')]
for p in registry_records:
    crate=indices[0]/f"{p['name']}-{p['version']}.crate"
    assert sha(crate)==p['checksum'],crate
assert json.loads(subprocess.check_output(['docker','inspect',c,'--format','{{json .NetworkSettings.Networks}}']))=={}
effective_cpu_max=subprocess.check_output(['docker','exec',c,'cat','/sys/fs/cgroup/cpu.max'],text=True).strip()
subprocess.run(['docker','cp',str(proof/'build.sh'),c+':/tmp/build.sh'],check=True)
start=utc()
cmd=['docker','exec',c,'/bin/bash','/tmp/build.sh']
with (proof/'build.log').open('x') as log:
    p=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT)
after=stamp()
report=dict(source_before=before,source_after=after,source_commit=state['commit'],binary_source_tree_sha256=before,source_id=before,
            effective_cpu_max=effective_cpu_max,locked_verified_crate_tarballs=len(registry_records),lock_sha256=sha(frozen/'Cargo.lock'),source_bundle_sha256=sha(w/'fixture/source.bundle'),
            compiler={t:sha(w/'fixture/toolchain/bin'/t) for t in ['rustc','cargo']},system_packages_sha256=sha(proof/'jammy-dpkg.txt'),container=c,image_id=state['image_id'],scope='clean rootless offline Ubuntu 22.04 build; no prebuilt native project artifacts',
            script_sha256=sha(proof/'build.sh'),command=cmd,started_utc=start,finished_utc=utc(),exit_code=p.returncode,log_sha256=sha(proof/'build.log'))
if p.returncode==0:
    binaries=w/'release';binaries.mkdir()
    for name in ['entangle','entangled','cargo-entangle','xtask']:
        subprocess.run(['docker','cp',c+':/tmp/build-target/release/'+name,str(binaries/name)],check=True)
    report['binary_sha256']={p.name:sha(p) for p in binaries.iterdir()}
    subprocess.run(['docker','rm','-f',c],check=True,stdout=subprocess.DEVNULL)
with (proof/'build.json').open('x') as f:json.dump(report,f,indent=2);f.write('\n')
raise SystemExit(p.returncode)
