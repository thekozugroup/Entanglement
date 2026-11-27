import concurrent.futures,os,shutil,subprocess,sys,tempfile
from pathlib import Path
r=Path('/workspace/Entanglement')
out=r/'docs/testing/production-review/evidence/candidate-c19ef758/pkg-linux-matrix'
old=r/'docs/testing/production-review/evidence/candidate-a0926c6e/pkg-linux-matrix'
out.mkdir(exist_ok=True)
shutil.copyfile(Path(__file__).resolve(),out/'provision-and-run.py')
src='sha256:81d8219e78f71c2e2987800cec205d72c22d015e1db4e0fc7577ba424e4ef644'
def get(*a): return subprocess.check_output(a,cwd=r,text=True).strip()
assert get('git','rev-parse','HEAD')=='c19ef7587a2215ef9434b642413bebd0473caf20'
assert get('python3','scripts/production_score.py','--source-id')==src
for f in ['verify.py','run-in-container.sh']:shutil.copyfile(old/f,out/f)
seed=Path('/workspace/entangle-package-seed.2uvRiy')
with tempfile.TemporaryDirectory(prefix='entangle-pkg-c19ef758-',dir='/workspace') as temp:
 d=Path(temp);d.chmod(0o755)
 subprocess.run(['cp','-al',seed/'toolchain',seed/'registry',seed/'public-repro-fixture-seed.pem',d],check=True)
 subprocess.run(['git','bundle','create',d/'source.bundle','HEAD'],cwd=r,check=True)
 os.chmod(d/'source.bundle',0o644)
 shutil.copyfile(out/'run-in-container.sh',d/'run-in-container.sh');(d/'run-in-container.sh').chmod(0o644)
 with (out/'seed.log').open('x') as f:
  for cmd in [['git','bundle','verify',str(d/'source.bundle')],['sha256sum',d/'source.bundle',d/'toolchain/bin/rustc',d/'toolchain/bin/cargo']]:
   subprocess.run(cmd,check=True,stdout=f,stderr=subprocess.STDOUT)
 ids=[]
 def setup(version):
  image=get('docker','image','inspect','ubuntu:'+version,'--format','{{index .RepoDigests 0}}')
  c=get('docker','create','--network','bridge','--pull=never','--security-opt','no-new-privileges','--platform','linux/amd64','--mount',f'type=bind,src={d},dst=/fixture,readonly',image,'sleep','infinity')
  ids.append(c)
  with (out/('ubuntu-'+version+'-provision.log')).open('x') as log:
   print('Official base:',image,file=log,flush=True)
   for cmd in [['docker','start',c],['docker','exec',c,'sh','-ec','apt-get -o Acquire::Retries=1 update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates git gcc libc6-dev make pkg-config'],['docker','network','disconnect','bridge',c]]:
    print(cmd,file=log,flush=True)
    subprocess.run(cmd,check=True,stdout=log,stderr=subprocess.STDOUT,timeout=150)
  return c
 try:
  with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
   jammy,noble=pool.map(setup,['22.04','24.04'])
  cmd=[sys.executable,out/'verify.py','--candidate-root',r,'--expected-source',src,'--jammy-container',jammy,'--noble-container',noble,'--output',out]
  subprocess.run(cmd,cwd=r,check=True)
 finally:
  for c in ids:subprocess.run(['docker','rm','-f',c],capture_output=True)
