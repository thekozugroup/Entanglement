"""Provision distro-verified cross tools in a private rootless OCI builder, then detach its network."""
import datetime,hashlib,json,os,pathlib,shutil,subprocess,sys,tomllib
from pathlib import Path
W=Path(__file__).resolve().parent;P=W/'proof';R=Path('/workspace/Entanglement');HEAD='a5728c230e5049556b806cae8597fe823dd67987';SID='sha256:a43296d252b79d7a0762861de1251b0e2e77fde20af2ea5dd43254617376fce5';F=W/'frozen'
OLD=R/'docs/testing/production-review/evidence/candidate-c19ef758/emulated-linux-arm64'
MIX=R/'docs/testing/production-review/evidence/candidate-296b427a/mixed-release-arm64'
OLDINPUT=json.loads((OLD/'inputs.json').read_bytes());IMAGE=json.loads((OLD/'container.json').read_bytes())['image']
STD=Path(OLDINPUT['ruststd_source']);SEED=Path('/workspace/entangle-jammy-release-o7k9vcv7/fixture/registry');EMU=Path('/workspace/entangle-mix-296b.3eCSwyYF/emulator')
def cmd(*args,**kw):return subprocess.check_output(args,text=True,**kw).strip()
def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def write(n,v):
 with (P/n).open('x') as f:f.write(json.dumps(v,indent=2)+'\n')
assert 'name=rootless' in json.loads(cmd('docker','info','--format','{{json .SecurityOptions}}'))
assert cmd('docker','image','inspect','--format','{{.Id}}',IMAGE)==IMAGE
assert shutil.disk_usage(W).free>1200*1024**2
cmd('git','clone','--shared','--no-checkout','--no-tags',R,F)
cmd('git','sparse-checkout','init','--no-cone',cwd=F)
cmd('git','sparse-checkout','set','--no-cone','/*','!/docs/testing/production-review/evidence/','!/docs/testing/production-review/runs/',cwd=F)
cmd('git','checkout','--detach',HEAD,cwd=F)
assert cmd(sys.executable,'scripts/production_score.py','--source-id',cwd=F)==SID
std={str(p.relative_to(STD)):sha(p) for p in STD.rglob('*') if p.is_file()}
assert std==OLDINPUT['ruststd_file_sha256']
# The user namespace that reads read-only bind mounts can map the caller to a different uid.
# Make dedicated copies of only public Rust target and source files readable, never changing the original toolchain.
armstd=W/'arm-std';shutil.copytree(STD,armstd)
for root in [F,armstd]:
    root.chmod(0o755)
    for path in root.rglob('*'):
        if path.is_symlink() or '.git' in path.relative_to(root).parts:continue
        path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)
assert {str(p.relative_to(armstd)):sha(p) for p in armstd.rglob('*') if p.is_file()}==std
m=json.loads((MIX/'mixed-release-arm64.json').read_bytes())['emulation']
assert sha(EMU/'qemu-aarch64')==m['emulator_sha256']
deps=tomllib.loads((F/'Cargo.lock').read_text())['package'];regs=next((SEED/'cache').iterdir());missing=[]
for dep in deps:
 if dep.get('source','').startswith('registry+') and not (regs/f"{dep['name']}-{dep['version']}.crate").is_file():missing.append(dep['name']+'@'+dep['version'])
assert not missing,missing
write('inputs.json',{'commit':HEAD,'source_before':SID,'Cargo.lock':sha(F/'Cargo.lock'),'ruststd_file_sha256':std,'ruststd_source':str(STD),'registry_cache':str(SEED),'registry_package_entries':sum('checksum' in d for d in deps),'registry_validation':'Cargo verifies registry file checksums from frozen Cargo.lock during offline expansion.','image_id':IMAGE,'qemu_sha256':m['emulator_sha256'],'qemu_provenance_sha256':sha(MIX/'mixed-release-arm64.json'),'old_toolchain_inputs_sha256':sha(OLD/'inputs.json')})
name='entangle-arm64-a572-isolated'
args=['docker','create','--pull=never','--name',name,'--network','bridge','--security-opt','no-new-privileges','--cpus','3','--memory','12g','--tmpfs','/private:rw,nosuid,nodev,exec,size=6g,mode=1777']
for src,dst in [(F,'/src'),(armstd,'/usr/local/rustup/toolchains/1.91.1-x86_64-unknown-linux-gnu/lib/rustlib/aarch64-unknown-linux-gnu'),(SEED,'/seed-registry'),(EMU,'/emu')]:
 args.extend(['--mount',f'type=bind,src={src},dst={dst},readonly'])
args.extend([IMAGE,'sleep','infinity']);cid=cmd(*args);write('container.json',{'id':cid,'image':IMAGE,'command':args})
cmd('docker','start',cid)
with (P/'provision-tools.log').open('x') as f:
 r=subprocess.run(['docker','exec','-i',cid,'sh','-s'],input=(P/'provision-tools.sh').read_text(),text=True,stdout=f,stderr=subprocess.STDOUT,timeout=600)
if r.returncode:sys.exit(r.returncode)
cmd('docker','network','disconnect','bridge',cid)
inspect=json.loads(cmd('docker','inspect',cid))[0];assert not inspect['NetworkSettings']['Networks'] and not inspect['HostConfig']['Privileged'] and not inspect['HostConfig']['Binds']
assert all(m['RW']==False for m in inspect['Mounts'] if m['Type']=='bind')
cmd('docker','cp',P/'cross-build.sh',cid+':/tmp/cross-build.sh')
write('provision.json',{'rootless':True,'privileged':False,'networks_after_provision':inspect['NetworkSettings']['Networks'],'tmpfs':inspect['HostConfig']['Tmpfs'],'before_build_disk_available':shutil.disk_usage(W).free,'binfmt_registered':False,'root_image':IMAGE,'cargo_network':'off','offline_routes':cmd('docker','exec',cid,'cat','/proc/net/route'),'package_log_sha256':sha(P/'provision-tools.log')})
