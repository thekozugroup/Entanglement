"""Bind emulated workloads to verified native and ARM archives, publish checksums, clean the builder."""
import datetime,hashlib,json,os,shutil,subprocess,tarfile
from pathlib import Path
W=Path(__file__).resolve().parent;P=W/'proof';R=Path('/workspace/Entanglement');E=R/'docs/testing/production-review/evidence/candidate-a5728c23';C=json.loads((P/'container.json').read_bytes())['id'];I=json.loads((P/'inputs.json').read_bytes());A=json.loads((P/'arm-archive.json').read_bytes());N=json.loads((E/'linux-archive.json').read_bytes());F=R/'plugins/json-pointer/target/wasm32-wasip2/release/entangle_json_pointer.wasm'
def cmd(*args,**kw):return subprocess.check_output(args,text=True,**kw).strip()
def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def store(name,item):(P/name).write_text(json.dumps(item,indent=2)+'\n')
assert N['source_commit']==I['commit']==A['source_commit']
stamp=lambda:cmd('python3','scripts/production_score.py','--source-id',cwd=W/'frozen')
assert stamp()==I['source_before']
apath=W/'release-archive'/A['archive_name'];npath=R/'target/release-candidate/a5728c230e50'/N['name']
assert sha(apath)==A['archive_sha256'] and sha(npath)==N['sha256']
assert sha(F)=='ce0711a821a91f7612bd2337581483bba736f2da6da47b4fd34d492738ae35fb'
dst=R/'target/release-candidate/a5728c230e50-aarch64';dst.mkdir(exist_ok=False)
for p in sorted((W/'release-archive').iterdir()):
    assert p.is_file();os.link(p,dst/p.name)
assert sha(dst/apath.name)==sha(apath)
for role,asset in [('archive-arm',apath),('canonical',npath)]:
    # Stream verified binary archive members to tmpfs and immediately independently digest there.
    cmd('docker','exec',C,'mkdir','-m','700','/private/'+role)
    with tarfile.open(asset) as tg:
        for n in ['entangle','entangled']:
            matches=[m for m in tg.getmembers() if m.isfile() and m.name.endswith('/'+n)];assert len(matches)==1
            required=json.loads((P/'arm-build.json').read_bytes())['executables_sha256'][n] if role=='archive-arm' else N['files_sha256'][n]
            target='/private/'+role+'/'+n
            with tg.extractfile(matches[0]) as member:
                data=member.read();assert hashlib.sha256(data).hexdigest()==required
                subprocess.run(['docker','exec','-i',C,'sh','-ec','cat > "$1" && chmod 555 "$1"','extract',target],input=data,check=True)
            assert cmd('docker','exec',C,'sha256sum',target).split()[0]==required
with F.open('rb') as wasm_file:
    subprocess.run(['docker','exec','-i',C,'sh','-ec','cat >/private/json-pointer.wasm'],stdin=wasm_file,check=True)
print('Verified archive and extracted workload binaries:',sha(apath),flush=True)
for program in ['standalone-local.py','signed-workload.py']:
    log=P/(program[:-3]+'-run.log')
    with log.open('x') as f:
        outcome=subprocess.run(['python3','-B',P/program],stdout=f,stderr=subprocess.STDOUT,timeout=420)
    if outcome.returncode:
        raise RuntimeError(f'{program} failed; raw diagnostic retained at {log}')
    print('Passed',program,flush=True)
# The build source and canonical archive stay read-only throughout the run.
assert stamp()==I['source_before'];q=cmd('docker','exec',C,'/emu/qemu-aarch64','--version')
net=json.loads(cmd('docker','inspect','--format','{{json .NetworkSettings.Networks}}',C))
assert not net
cmd('docker','rm','-f',C)
assert subprocess.run(['docker','inspect',C],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0
assert dst.exists() and sha(dst/apath.name)==A['archive_sha256']
for generated in [W/'arm-std',W/'executables']:
    assert generated.is_dir() and not generated.is_symlink()
    shutil.rmtree(generated)
store('cleanup.json',{'temporary_cross_std_and_duplicate_binaries_removed':True,'durable_archive':str(dst/apath.name),'builder_removed':True,'tmpfs_target_released':True,'host_binfmt_modified':False,'builder_networks_before_removal':net})
s=json.loads((P/'signed-workload.json').read_bytes());l=json.loads((P/'standalone-local.json').read_bytes())
assert s['exit_code']==l['exit_code']==0 and s['source_after']==l['source_after']==I['source_before']
summary={'source_commit':I['commit'],'source_before':I['source_before'],'source_after':stamp(),'archive':str(dst/apath.name),'archive_sha256':sha(apath),'archive_blake3':A['blake3'],'archive_size':apath.stat().st_size,'signing':'unsigned; checksums verified; full verifier rejected missing Sigstore bundle','host_machine':'x86_64','executable_machine':'aarch64','emulated_by':q.splitlines()[0],'rust_command':json.loads((P/'arm-build.json').read_bytes())['cargo_command'],'rustc':'1.91.1','native_archive_sha256':N['sha256'],'standalone':{'plugin':l['plugin'],'expected':l['expected'],'actual':l['actual'],'untrusted_publisher_rejected':l['denied_code']!=0},'directions':{k:v for k,v in s['assertions'].items() if k in ['x86_to_emulated_arm','arm_to_x86']},'independent_physical_hosts':1,'scope':'Offline locked cross-release with independently verified ELF architecture, explicit QEMU Linux user-mode on one x86_64 host. Native and emulated daemons communicate over authenticated loopback QUIC.','evidence_sha256':{p.name:sha(p) for p in sorted(P.glob('*')) if p.is_file()}}
store('summary.json',summary)
dest=E/'linux-compatibility/current-arm64';dest.mkdir(exist_ok=False)
for p in P.iterdir():
 if p.is_file():shutil.copy2(p,dest/p.name)
for p in [W/'prepare.py',W/'provision.py',Path(__file__)]:shutil.copy2(p,dest/p.name)
shutil.copy2(P/'summary.json',dst/'verification.json')
print('Summary SHA-256',sha(dest/'summary.json'),flush=True)
