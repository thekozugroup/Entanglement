"""Run the publisher-key rotation exercise with disposable node identities."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import tomllib

ROOT = Path.cwd()
BIN = (ROOT / 'target/release').resolve()
FIXTURE = ROOT / 'crates/entangle-host/tests/fixtures/hello-pong.wasm'
SOURCE = 'sha256:c276c15010e510172c5fbf07e6d3dc3c979f8270e0eb0b200026e7b6c5f6770e'

def source_id():
    return subprocess.check_output([sys.executable, 'scripts/production_score.py', '--source-id'], text=True).strip()

def exercise(base):
    os.environ.pop('ENTANGLE_ALLOW_LOCAL', None)
    primary, replacement = base / 'operator', base / 'replacement'
    primary.mkdir()
    replacement.mkdir()
    actions = []
    start = time.monotonic()

    def record(step, **fields):
        actions.append(dict(step=step, elapsed_seconds=round(time.monotonic()-start,3), **fields))

    def cli(home, *argv, error=None):
        res = subprocess.run([BIN / 'entangle', *argv], capture_output=True, text=True,
                             timeout=30, env=dict(os.environ, HOME=str(home), TOKIO_WORKER_THREADS='2'))
        if error:
            assert res.returncode != 0 and error in res.stderr, res.stderr
        else:
            assert res.returncode == 0, res.stderr
        return res.stdout

    cli(primary, 'init', '--non-interactive')
    cli(replacement, 'init', '--non-interactive')
    state = primary / '.entangle'
    (state/'config.toml').write_text('[mesh]\ntransports = []\n')
    daemon = subprocess.Popen([BIN / 'entangled', 'run'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              env=dict(os.environ, HOME=str(primary), TOKIO_WORKER_THREADS='2'))
    try:
        deadline = time.monotonic()+15
        while not (state / 'sock').is_socket():
            assert daemon.poll() is None and time.monotonic()<deadline
            time.sleep(.05)
        cli(primary,'plugins','install','hello-world','--catalog',ROOT/'examples','--wasm',FIXTURE)
        old = state/'plugins/hello-world'
        old_id=tomllib.loads((old/'entangle.toml').read_text())['plugin']['id']
        assert 'Hello, original!' in cli(primary,'plugins','invoke',old_id,'--input','original')
        record('Inject private report of suspected signing-key compromise in this exercise',
               affected=old_id, affected_component_sha256=hashlib.sha256((old/'plugin.wasm').read_bytes()).hexdigest())
        cli(primary,'plugins','unload',old_id)
        cli(primary,'keyring','remove',old_id.split('/')[0])
        cli(primary,'plugins','load',old,error='ENTANGLE-E0101')
        record('Unload affected package, remove publisher trust, and verify reload denial', code='ENTANGLE-E0101')
        new = base/'replacement-package'
        cli(replacement,'plugins','build',ROOT/'examples/hello-world','--out',new,'--wasm',FIXTURE)
        new_id=tomllib.loads((new/'entangle.toml').read_text())['plugin']['id']
        assert old_id.split('/')[0] != new_id.split('/')[0]
        der = subprocess.check_output(['openssl','pkey','-in',replacement/'.entangle/identity.key','-pubout','-outform','DER'])
        assert len(der)==44 and der[:12].hex()=='302a300506032b6570032100'
        cli(primary,'plugins','load',new,error='ENTANGLE-E0101')
        cli(primary,'keyring','add',der[-32:].hex(),'--name','rotation-exercise')
        cli(primary,'plugins','load',new)
        assert 'Hello, recovered!' in cli(primary,'plugins','invoke',new_id,'--input','recovered')
        cli(primary,'plugins','load',old,error='ENTANGLE-E0101')
        record('Recover using separately generated publisher key; retired package remains denied',
               replacement=new_id, pid_unchanged=daemon.poll() is None)
    finally:
        daemon.terminate()
        try: daemon.wait(8)
        except subprocess.TimeoutExpired:
            daemon.kill()
            daemon.wait()
    return actions

if __name__ == '__main__':
    assert source_id()==SOURCE
    with tempfile.TemporaryDirectory(dir='/tmp') as temp:
        steps=exercise(Path(temp))
    assert source_id()==SOURCE
    print(json.dumps({'source_id':SOURCE,'source_after':source_id(),'scope':'isolated publisher rotation exercise on Linux x86_64; no messages or reports sent externally','binary_sha256':{n:hashlib.sha256((BIN/n).read_bytes()).hexdigest() for n in ('entangle','entangled')},'actions':steps},indent=2))
