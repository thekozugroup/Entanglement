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

work=Path('/workspace/entangle-emulated-arm-f499e3ed-slim');proof=work/'proof';src=work/'frozen';c=json.loads((proof/'container.json').read_bytes())['id'];inputs=json.loads((proof/'inputs.json').read_bytes());exe=('entangle','entangled')
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def host(*args, **kw):return subprocess.check_output(args,text=True,**kw).strip()
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def stamp():
    assert host('git','rev-parse','HEAD',cwd=src)==inputs['commit']
    raw=host(sys.executable,'scripts/production_score.py','--source-id',cwd=src)
    assert raw==inputs['source_before'];return raw
before=stamp();start=utc();tick=time.monotonic();cap=shutil.disk_usage(work).free;assert cap>=768*1024**2, f'Only {cap} free'
assert not json.loads(host('docker','inspect','--format','{{json .NetworkSettings.Networks}}',c));assert host('docker','inspect','--format','{{.HostConfig.NanoCpus}} {{.HostConfig.Memory}}',c)=='2000000000 12884901888'
log=proof/'cross-build.log';cmd=['docker','exec',c,'sh','/tmp/cross-build.sh'];print('Cross compile started', start,flush=True)
resources=proof/'cross-build-resources.jsonl'; gib=2**30; stop_reason=[]
initial_oom=int(dict(row.split() for row in Path('/sys/fs/cgroup/memory.events').read_text().splitlines())['oom_kill'])
with log.open('x') as f, resources.open('x') as resource_log:
    r=subprocess.Popen(cmd,stdout=f,stderr=subprocess.STDOUT)
    while r.poll() is None:
        try:
            r.wait(timeout=12)
            break
        except subprocess.TimeoutExpired:
            pass
        memory_kib=int(re.search(r'^MemAvailable:\s+(\d+) kB',Path('/proc/meminfo').read_text(),re.M)[1])
        free_bytes=int(host('docker','exec',c,'sh','-ec',"df -B1 /private | awk 'NR==2{print $4}'"))
        oom=int(dict(row.split() for row in Path('/sys/fs/cgroup/memory.events').read_text().splitlines())['oom_kill'])
        sample={'utc':utc(),'host_memory_available_bytes':memory_kib*1024,'builder_tmpfs_free_bytes':free_bytes,'host_oom_kill_count':oom}
        print(json.dumps(sample),file=resource_log,flush=True)
        thresholds={
            'available memory below 9 GiB': memory_kib * 1024 < 9 * gib,
            'builder tmpfs has less than 256 MiB free': free_bytes < gib // 4,
            'host OOM count changed': oom != initial_oom,
            'build exceeded 44 minutes': time.monotonic() - tick > 44 * 60,
        }
        stop_reason=[name for name,triggered in thresholds.items() if triggered]
        if stop_reason:
            host('docker','rm','-f',c)
            r.wait(timeout=25)
            break
common={'commit':inputs['commit'],'source_before':before,'source_after':stamp(),'host_machine':platform.machine(),'target':'aarch64-unknown-linux-gnu','profile':'release; Cargo workspace optimizations and ThinLTO unchanged','command':cmd,'cargo_command':'cargo build --release --workspace --bins --locked --target aarch64-unknown-linux-gnu --offline','start_utc':start,'finish_utc':utc(),'elapsed_s':round(time.monotonic()-tick,3),'exit_code':r.returncode,'build_log_sha256':sha(log),'resource_log_sha256':sha(resources),'stop_reason':stop_reason,'script_sha256':sha(proof/'cross-build.sh'),'disk_free_start_bytes':cap,'disk_free_end_bytes':shutil.disk_usage(work).free}
if r.returncode:
 (proof/'arm-build-incomplete.json').write_text(json.dumps(common,indent=2)+'\n');sys.exit(r.returncode)
out=work/'executables';out.mkdir();b={};rel={}
for n in exe:
    path='/private/target/aarch64-unknown-linux-gnu/release/'+n
    assert host('docker','exec',c,'test','-x',path)==''
    with (out/n).open('xb') as stream:
        subprocess.run(['docker','exec',c,'/bin/cat',path],stdout=stream,check=True,timeout=120)
    f=out/n; f.chmod(0o555);h=sha(f); assert h==host('docker','exec',c,'sha256sum',path).split()[0];b[n]=h
    with f.open('rb') as stream: assert stream.read(4)==b'\x7fELF'
    filetype=host('file','-b',f);hdr=host('readelf','-h',f);dyn=host('readelf','-dW',f);syms=host('readelf','--version-info','--wide',f);prog=host('readelf','-lW',f)
    assert re.search(r'Machine:\s+AArch64',hdr) and 'ELF64' in hdr and 'ARM aarch64' in filetype
    assert '/lib/ld-linux-aarch64.so.1' in prog
    g=sorted(set(re.findall(r'Name: GLIBC_([0-9.]+)',syms)),key=lambda s:tuple(map(int,s.split('.'))));assert g
    rel[n]={'machine':'AArch64','file':filetype,'interpreter':'/lib/ld-linux-aarch64.so.1','sha256':h,'bytes':f.stat().st_size,'glibc_symbol_max':g[-1],'needed':re.findall(r'Shared library: \[(.*?)\]',dyn),'versions':g}
common.update(executables_sha256=b,elf_independent_host_checks=rel,private_networks_after=json.loads(host('docker','inspect','--format','{{json .NetworkSettings.Networks}}',c)),builder_tmpfs=host('docker','exec',c,'df','-B1','/private'),target_disk_usage=host('docker','exec',c,'du','-sb','/private/target'),cargo_home_disk_usage=host('docker','exec',c,'du','-sb','/private/cargo'))
with (proof/'arm-build.json').open('x') as f:json.dump(common,f,indent=2);f.write('\n')
print(json.dumps(rel,indent=2))
