"""Compile the pinned ARM target strictly offline and verify ELF ABI and digests independently."""
from pathlib import Path
import datetime
import hashlib
import json
import platform
import re
import shutil
import subprocess
import time
import sys

work=Path('/workspace/entangle-emulated-arm-a5728c23');proof=work/'proof';src=work/'frozen';c=json.loads((proof/'container.json').read_bytes())['id'];inputs=json.loads((proof/'inputs.json').read_bytes());exe=('entangle','entangled')
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def host(*args, **kw):return subprocess.check_output(args,text=True,**kw).strip()
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def stamp():
    assert host('git','rev-parse','HEAD',cwd=src)==inputs['commit']
    raw=host(sys.executable,'scripts/production_score.py','--source-id',cwd=src)
    assert raw==inputs['source_before'];return raw
# Post-build only: read timestamps and success from the already completed immutable compiler log.
before=stamp()
log=proof/'cross-build.log'
body=log.read_text();assert "Finished `release` profile [optimized]" in body and 'End UTC:' in body
start=re.search(r'^Start UTC: (.+)$',body,re.M)[1]
end=re.search(r'^End UTC: (.+)$',body,re.M)[1]
elapsed=(datetime.datetime.fromisoformat(end)-datetime.datetime.fromisoformat(start)).total_seconds()
common={'commit':inputs['commit'],'source_before':before,'source_after':stamp(),'host_machine':platform.machine(),'target':'aarch64-unknown-linux-gnu','profile':'unmodified release; workspace optimizations and ThinLTO','command':['docker','exec',c,'sh','/tmp/cross-build.sh'],'cargo_command':'cargo build --release --workspace --bins --locked --target aarch64-unknown-linux-gnu --offline','start_utc':start,'finish_utc':end,'elapsed_s':elapsed,'exit_code':0,'build_log_sha256':sha(log),'script_sha256':sha(proof/'cross-build.sh'),'first_export_sha256':sha(proof/'initial-export-failure.json'),'export_method':'Stream finished tmpfs ELF with docker exec and independently verify cryptographic digest, file, and readelf locally.'}
out=work/'executables';out.mkdir(exist_ok=True);b={};rel={}
for n in exe:
    path='/private/target/aarch64-unknown-linux-gnu/release/'+n
    assert host('docker','exec',c,'test','-x',path)==''
    with (out/n).open('xb') as local:
        subprocess.run(['docker','exec',c,'cat',path],stdout=local,check=True)
    f=out/n; f.chmod(0o555);h=sha(f); assert h==host('docker','exec',c,'sha256sum',path).split()[0];b[n]=h
    assert f.read_bytes()[:4]==b'\x7fELF'
    filetype=host('file','-b',f);hdr=host('readelf','-h',f);dyn=host('readelf','-dW',f);syms=host('readelf','--version-info','--wide',f);prog=host('readelf','-lW',f)
    assert re.search(r'Machine:\s+AArch64',hdr) and 'ELF64' in hdr and 'ARM aarch64' in filetype
    assert '/lib/ld-linux-aarch64.so.1' in prog
    g=sorted(set(re.findall(r'Name: GLIBC_([0-9.]+)',syms)),key=lambda s:tuple(map(int,s.split('.'))));assert g
    rel[n]={'machine':'AArch64','file':filetype,'interpreter':'/lib/ld-linux-aarch64.so.1','sha256':h,'bytes':f.stat().st_size,'glibc_symbol_max':g[-1],'needed':re.findall(r'Shared library: \[(.*?)\]',dyn),'versions':g}
common.update(executables_sha256=b,elf_independent_host_checks=rel,private_networks_after=json.loads(host('docker','inspect','--format','{{json .NetworkSettings.Networks}}',c)),builder_tmpfs=host('docker','exec',c,'df','-B1','/private'),target_disk_usage=host('docker','exec',c,'du','-sb','/private/target'),cargo_home_disk_usage=host('docker','exec',c,'du','-sb','/private/cargo'))
with (proof/'arm-build.json').open('x') as f:json.dump(common,f,indent=2);f.write('\n')
print(json.dumps(rel,indent=2))
