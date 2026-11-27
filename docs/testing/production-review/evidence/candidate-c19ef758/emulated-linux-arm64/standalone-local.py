"""Run a separate offline catalog exercise, independent of optional interop."""
import importlib.util
import json
import re
import secrets
import subprocess
import time
from pathlib import Path

spec=importlib.util.spec_from_file_location('workload',Path(__file__).parent/'signed-workload.py')
w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
start=w.utc();before=w.stamp();home='/private/standalone-arm'

def cmd(binary,*args):
    return ['docker','exec','-e','HOME='+home,'-e','TOKIO_WORKER_THREADS=2','-e','RAYON_NUM_THREADS=2',w.CID,*w.QEMU,w.ARM+binary,*args]

def cli(*args,**kw):return w.run(cmd('entangle',*args),**kw)

w.raw('mkdir','-m','700',home)
cli('init','--non-interactive')
package='/private/signed-standalone'
build=cli('plugins','build','/src/plugins/json-pointer','--wasm','/private/json-pointer.wasm','--out',package).stdout
public=re.search(r'entangle keyring add ([a-f0-9]{64}) --name',build)[1]
plugin=re.search(r'entangle plugins invoke ([^ ]+) --input',build)[1]
assert re.fullmatch(r'[a-f0-9]{32}/json-pointer@0.1.0',plugin)
w.raw('sh','-ec','cat > "$1"','write-config',home+'/.entangle/config.toml',data='[mesh]\ntransports=[]\n')
plain=cmd('entangled','run');i=plain.index(w.CID)+1;pid=home+'/daemon.pid';entry=plain[:i]+['sh','-ec','echo $$ > "$1"; shift; exec "$@"','start',pid,*plain[i:]]
log=w.PROOF/'standalone-daemon.log'
with log.open('x') as f:
    proc=subprocess.Popen(entry,stdout=f,stderr=subprocess.STDOUT)
    try:
        deadline=time.monotonic()+75
        while w.raw('test','-S',home+'/.entangle/sock',check=False).returncode:
            assert proc.poll() is None and time.monotonic()<deadline,'standalone RPC unavailable'
            time.sleep(.15)
        status=json.loads(cli('mesh','status','--json').stdout)
        assert status['transports_active']==[] and status['local_peer_id']==plugin.split('/')[0]
        denied=cli('plugins','load',package,check=False)
        assert denied.returncode and re.search(r'(trust|publisher|keyring|verification key)',denied.stderr,re.I),denied
        assert json.loads(cli('plugins','list','--json').stdout)=={'plugins':[]}
        cli('keyring','add',public,'--name','Standalone emulated ARM publisher')
        load=cli('plugins','load',package)
        nonce=secrets.token_hex(16);input_=json.dumps({'pointer':'/items/0/value','data':{'items':[{'value':nonce}]}})
        res=cli('plugins','invoke',plugin,'--input',input_,'--raw')
        assert res.stdout==json.dumps(nonce)
    finally:
        if proc.poll() is None:w.raw('sh','-ec','kill -TERM "$(cat "$1")"','stop',pid,check=False)
        code=proc.wait(45)
    assert code==0
arm=json.loads((w.PROOF/'arm-build.json').read_bytes())
wasm=w.raw('sha256sum','/private/json-pointer.wasm').stdout.split()[0]
assert wasm=='ce0711a821a91f7612bd2337581483bba736f2da6da47b4fd34d492738ae35fb'
w.write('standalone-local.json',dict(source_before=before,source_after=w.stamp(),source_commit=w.EXPECTED['commit'],started_utc=start,finished_utc=w.utc(),scope='Both ARM64 ELF programs explicitly interpreted by QEMU on the native x86_64 kernel. Mesh disabled; offline local UDS and ordinary signed WASI JIT.',emulator=w.QEMU,arm_executables_sha256=arm['executables_sha256'],plugin=plugin,publisher=public,wasm_sha256=wasm,denied_code=denied.returncode,denied_stderr=denied.stderr.strip(),load=load.stdout.strip(),before_invoke_status=status,input=input_,expected=json.dumps(nonce),actual=res.stdout,daemon_exit=code,daemon_log_sha256=w.sha(log),harness_sha256=w.sha(Path(__file__)),exit_code=0))
print('standalone actual signed ARM64 catalog output:',res.stdout)
