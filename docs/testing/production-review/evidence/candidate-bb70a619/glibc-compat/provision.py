"""Prepare the local pinned Ubuntu22 builder; compile is a separate explicit step."""
import json,os,subprocess,sys,tempfile
from pathlib import Path
repo=Path('/workspace/Entanglement')
proof=Path(__file__).resolve().parent
commit='bb70a6193f8879b1feb3e6d3ceb8f2980413ce58'
source='sha256:9cae32b67ebd4784779d1c37cd9cea5efc1a640fdfd71fca9a67dda8d9c777ab'
def get(*argv):return subprocess.check_output(argv,cwd=repo,text=True).strip()
w=Path(tempfile.mkdtemp(prefix='entangle-jammy-release-',dir='/workspace'))
fixture=w/'fixture';fixture.mkdir()
w.chmod(0o755);fixture.chmod(0o755)
record={'commit':commit,'source':source,'workspace':str(w)}
assert get('git','rev-parse',commit+'^{commit}')==commit
# A private ref in this temporary object database pins the requested commit even if the primary HEAD moves.
with (proof/'provision.log').open('x') as log:
 def go(*argv):
  print([str(a) for a in argv],file=log,flush=True)
  subprocess.run(argv,cwd=repo,stdout=log,stderr=subprocess.STDOUT,check=True)
 go('git','clone','--shared','--bare','--no-tags',repo,w/'objects.git')
 go('git','--git-dir',w/'objects.git','update-ref','refs/heads/frozen-compatible',commit)
 go('git','--git-dir',w/'objects.git','bundle','create',fixture/'source.bundle','refs/heads/frozen-compatible')
 go('git','bundle','verify',fixture/'source.bundle')
 go('git','clone','--branch','frozen-compatible',fixture/'source.bundle',w/'frozen')
 assert get('git','-C',w/'frozen','rev-parse','HEAD')==commit
 assert subprocess.check_output(['python3','scripts/production_score.py','--source-id'],cwd=w/'frozen',text=True).strip()==source
 seed=Path('/workspace/entangle-package-seed.2uvRiy')
 go('cp','-al',seed/'toolchain',seed/'registry',fixture)
 (fixture/'source.bundle').chmod(0o644)
 image='ubuntu@sha256:b000e69a50ff940390233025e7a337fb8469b509e2334fa4d018ac30f3e18cdb'
 record['image_id']=get('docker','image','inspect',image,'--format','{{.Id}}')
 print(record,file=log,flush=True)
 c=get('docker','create','--pull=never','--cpus=0.5','--network=bridge','--security-opt=no-new-privileges','--platform=linux/amd64','--mount',f'type=bind,src={fixture},dst=/fixture,readonly',image,'sleep','infinity')
 record['container']=c
 (w/'state.json').write_text(json.dumps(record,indent=2)+'\n')
 Path('/tmp/bb70-compat-state-path').write_text(str(w/'state.json'))
 go('docker','start',c)
 go('docker','exec',c,'sh','-ec','apt-get -o Acquire::Retries=1 update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates git gcc libc6-dev make pkg-config && apt-get clean')
 go('docker','network','disconnect','bridge',c)
 record['networks_for_build']=json.loads(get('docker','inspect',c,'--format','{{json .NetworkSettings.Networks}}'))
 assert not record['networks_for_build']
 with (proof/'jammy-dpkg.txt').open('x') as packages:
  subprocess.run(['docker','exec',c,'dpkg-query','-W','-f=${binary:Package} ${Version}\n'],check=True,stdout=packages)
 go('docker','exec',c,'sh','-ec','cat /etc/os-release; getconf GNU_LIBC_VERSION; gcc -v; ld -v; cat /proc/net/route; /fixture/toolchain/bin/cargo -Vv; /fixture/toolchain/bin/rustc -Vv; sha256sum /fixture/toolchain/bin/cargo /fixture/toolchain/bin/rustc /fixture/source.bundle')
 for f in [w/'state.json',proof/'provision.json']:f.write_text(json.dumps(record,indent=2)+'\n')
