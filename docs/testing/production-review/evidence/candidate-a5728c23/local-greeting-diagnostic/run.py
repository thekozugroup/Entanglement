"""Preregistered, local-only, signed greeting diagnostic on frozen binaries."""
import collections
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import random
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time

E=Path(__file__).resolve().parent
ROOT=next(p for p in E.parents if (p/'scripts/production_score.py').is_file())
ARC=E.parents[1]
CLIENT=Path('/tmp/entangle-rpc-client-patched')
CLIENT_CODE=Path('/tmp/entangle-local-client-review/crates/entangle-rpc/examples/local-client-review.rs')
CLI=Path('/tmp/entangle-demand-qa/final-rust/a5728c23/binaries/entangle')
BINS={'baseline':Path('/tmp/entangle-demand-qa/released-c19ef758/entangled'),
      'candidate':CLI.with_name('entangled')}
WASM=ROOT/'crates/entangle-host/tests/fixtures/hello-pong.wasm'
CG=Path('/sys/fs/cgroup')
NOW=lambda:datetime.now(timezone.utc).isoformat()
def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def write(p,data):p.write_text(json.dumps(data,indent=2)+'\n')
def cpu():return {r.split()[0]:int(r.split()[1]) for r in (CG/'cpu.stat').read_text().splitlines()}
def snapshot():
    states={}
    for p in Path('/proc').glob('[0-9]*/stat'):
        try:
            txt=p.read_text();end=txt.rindex(')');s=txt[end+2:].split()
            if s[0]!='Z':states[p.parent.name]=(txt[txt.index('(')+1:end],int(s[11])+int(s[12]))
        except (OSError,ValueError,IndexError):pass
    return states
def ticks(pid):
    s=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
    return int(s[11])+int(s[12])
def schedule():
    rng=random.Random(572427)
    def sequence(a,b):
        values=[a]*4+[b]*4;rng.shuffle(values);return values
    runs=[]
    for i, (mixed, control, kinds, clients) in enumerate(zip(sequence(['A','B'],['B','A']),sequence(['X','Y'],['Y','X']),sequence(['mixed','control'],['control','mixed']),sequence([1,4],[4,1])),1):
        for kind in kinds:
            for role in (mixed if kind=='mixed' else control):
                runs.append(dict(block=i,kind=kind,label=role,widths=clients))
    return runs

def run():
    assert not (E/'samples.jsonl').exists(), 'existing data must be retained'
    plan=schedule()
    write(E/'schedule.json',plan)
    getsource=lambda:subprocess.check_output([sys.executable,'scripts/production_score.py','--source-id'],cwd=ROOT,text=True).strip()
    canonical=getsource()
    assert digest(E/'plan.md')=='c5fded9c8292fa9eeb95aefc917929b1087df74a957c736cb03c951563197798'
    for role,tag in [('baseline','c19ef758'),('candidate','a5728c23')]:
        m=json.loads((ARC/f'candidate-{tag}'/'linux-archive.json').read_text())
        assert digest(BINS[role])==m['files_sha256']['entangled']
        if role=='candidate':assert canonical==m['source_id']==m['source_after'] and digest(CLI)==m['files_sha256']['entangle']
    assert set(range(4))<=os.sched_getaffinity(0)
    assert digest(CLIENT)=="4bb318daa7551531ac7fa5314ac33225349c3782e4e870fc68917e8d2fc8933f"
    assert digest(CLIENT_CODE)=="055daf38570a7b1a2b0de6b15ec6b43cc3a4aaed06eb57fb2f3a21709469e41f"
    stop=threading.Event();monitor_rows=[]
    def monitor():
        last=snapshot()
        while not stop.wait(1):
            now=snapshot()
            active={p+':'+n:c-last[p][1] for p,(n,c)in now.items() if p in last and c-last[p][1]>=4}
            monitor_rows.append(dict(utc=NOW(),active_4_ticks_per_second=active))
            last=now
    rows=[]
    receipt={'registered_plan_sha256':digest(E/'plan.md'),'source_before':canonical,'started_utc':NOW(),'driver_sha256':digest(__file__),'client_elf_sha256':digest(CLIENT),'client_source_sha256':digest(CLIENT_CODE),'fixture_sha256':digest(WASM),'daemon_sha256':{n:digest(p)for n,p in BINS.items()},'candidate_cli_sha256':digest(CLI),'host_cpu_allowed':sorted(os.sched_getaffinity(0)),'cpu_max':(CG/'cpu.max').read_text().strip(),'cpu_stat_before':cpu(),'schedule_sha256':digest(E/'schedule.json'),'clock_hz':os.sysconf('SC_CLK_TCK'),'status':'initializing'}
    write(E/'receipt.json',receipt)
    started=None
    with tempfile.TemporaryDirectory(prefix='entangle-local-signed-') as tmp:
        tmp=Path(tmp);template=tmp/'template';template.mkdir()
        env={**os.environ,'HOME':str(template),'TOKIO_WORKER_THREADS':'2','RAYON_NUM_THREADS':'2','RUST_LOG':'warn'}
        def cli(*args,environ=env):
            return subprocess.check_output([str(CLI),*map(str,args)],env=environ,cwd=ROOT,stderr=subprocess.STDOUT,text=True,timeout=8)
        init=cli('init','--non-interactive')
        peer=re.search(r'Fingerprint:\s*([0-9a-f-]+)',init)[1].replace('-','')
        assert len(peer)==32
        (template/'.entangle/config.toml').write_text('[mesh]\ntransports=["iroh"]\nmulti_node=false\n[scheduler]\nbind="127.0.0.1:0"\nrelay=false\npeers=[]\n')
        # Same tier, ordinary Wasm world and greeting implementation as the primary driver.
        source=tmp/'source';source.mkdir()
        (source/'entangle.toml').write_text('[plugin]\nid="PUBLISHER_PLACEHOLDER/test-plugin@0.1.0"\nversion="0.1.0"\ntier=1\nruntime="wasm"\ndescription="rpc integration test plugin"\n[build]\nwit_world="entangle:plugin@0.1.0/plugin"\ntarget="wasm32-wasip2"\n')
        package=tmp/'package'
        built=cli('plugins','build',source,'--wasm',WASM,'--out',package)
        key=re.search(r'entangle keyring add ([0-9a-f]{64}) --name',built)[1]
        plugin=re.search(r'entangle plugins invoke (\S+) --input',built)[1]
        assert plugin==peer+'/test-plugin@0.1.0'
        cli('keyring','add',key,'--name','local diagnostic fixture')
        receipt['plugin_id']=plugin;receipt['oracle_peer']=peer
        receipt['signed_package_sha256']={n:digest(package/n)for n in ('entangle.toml','plugin.wasm','plugin.wasm.sig')}
        assert receipt['signed_package_sha256']['plugin.wasm']==receipt['fixture_sha256']
        corpus={};seq=0
        for width in [1,4]:
            for count in [128,1024]:
                dest=tmp/f'corpus-{width}-{count}';dest.mkdir();body=[]
                for i in range(count):
                    value=f'job{seq:08x}';seq+=1
                    body.append(dict(plugin_id=plugin,input=list(value.encode()),timeout_ms=5000,cpu_cores=.01,memory_bytes=0,gpu_required=False,gpu_vram_min_bytes=0,integrity={'kind':'none'}))
                    (dest/f'{i}.bin').write_bytes(f'Hello, {value}!'.encode())
                (dest/'requests.json').write_text(json.dumps(body,separators=(',',':')))
                corpus[(width,count)]=dest
        m=threading.Thread(target=monitor);m.start()
        started=time.monotonic();deadline=started+180
        try:
            with (E/'samples.jsonl').open('x')as log:
                for index,arm in enumerate(plan,1):
                    if time.monotonic()>=deadline:raise TimeoutError('180-second preregistered bound')
                    home=tmp/'arm';shutil.copytree(template,home)
                    local_env={**env,'HOME':str(home)};role='baseline' if arm['label']=='A' else 'candidate'
                    with (tmp/'daemon.log').open('w')as daemon_stdout:
                        daemon=subprocess.Popen(['taskset','-c','2,3',BINS[role],'run'],env=local_env,stdout=daemon_stdout,stderr=subprocess.STDOUT)
                        try:
                            sock=home/'.entangle/sock';ready=min(deadline,time.monotonic()+8)
                            while not sock.is_socket():
                                if daemon.poll() is not None:raise RuntimeError((tmp/'daemon.log').read_text())
                                if time.monotonic()>ready:raise TimeoutError('daemon local socket')
                                time.sleep(.02)
                            cli('plugins','load',package,environ=local_env)
                            assert json.loads(cli('plugins','list','--json',environ=local_env))['plugins']==[plugin]
                            assert os.sched_getaffinity(daemon.pid)=={2,3}
                            for width in arm['widths']:
                                for count in (128,1024):
                                    dest=corpus[(width,count)]
                                    argv=['taskset','-c','0,1',CLIENT,sock,dest/'requests.json',str(count),str(width),peer,dest]
                                    before,stat_before,at=ticks(daemon.pid),cpu(),NOW()
                                    op=subprocess.run(argv,capture_output=True,text=True,timeout=max(.001,deadline-time.monotonic()))
                                    if op.returncode:raise RuntimeError(op.stderr)
                                    raw=json.loads(op.stdout);assert raw['count']==count
                                    if count==1024:
                                        row=dict(**arm,arm_index=index,width=width,release=role,started_utc=at,finished_utc=NOW(),pid=daemon.pid,daemon_allowed=sorted(os.sched_getaffinity(daemon.pid)),client_taskset='0,1',daemon_cpu_ticks=ticks(daemon.pid)-before,cgroup_before=stat_before,cgroup_after=cpu(),**raw)
                                        rows.append(row);log.write(json.dumps(row)+'\n');log.flush()
                        finally:
                            daemon.terminate()
                            try:daemon.wait(timeout=3)
                            except subprocess.TimeoutExpired:daemon.kill();daemon.wait();raise
                    shutil.rmtree(home)
            receipt['status']='complete'
        except Exception as err:
            receipt['status']='stopped';receipt['error']=repr(err)
            if (tmp/'daemon.log').exists():(E/'last-daemon.log').write_text((tmp/'daemon.log').read_text())
        finally:
            stop.set();m.join()
            write(E/'cpu-samples.json',monitor_rows)
            receipt.update(finished_utc=NOW(),elapsed_s=time.monotonic()-started,rows=len(rows),cpu_stat_after=cpu(),source_after=getsource(),samples_sha256=digest(E/'samples.jsonl'))
            write(E/'receipt.json',receipt)
    assert receipt['status']=='complete' and len(rows)==64 and receipt['source_after']==canonical,receipt
if __name__=='__main__':run()
