"""Repeat the exact wrapper and encrypted-recovery commands after freeing host disk."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

R = Path('/workspace/Entanglement')
C = '90beded509f93909507c78f2986dea0e085e4f1e'
S = 'sha256:f55d4a44e7f128f7e059ecd7c93625be91e7f56484c49f93b7920e9266cf6cbb'
D = R / 'docs/testing/production-review/evidence' / ('candidate-' + C[:8])
O = D / 'operational-retry'
B = Path('/tmp/entangle-check-90beded5-archive')
env = dict(os.environ, TOKIO_WORKER_THREADS='2', RAYON_NUM_THREADS='2', ENTANGLE_FISH='/tmp/entangle-joint-blackbox/fish')

def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def stamp():
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=R, text=True).strip() == C
    assert subprocess.check_output([sys.executable, 'scripts/production_score.py', '--source-id'], cwd=R, text=True).strip() == S
    return S

def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def finish(name, previous, command, raw=None):
    before = stamp()
    baseline = json.loads(previous.read_text())
    assert baseline['exit_code'] != 0 and baseline['source_after'] == before
    # Use the same command and assets from the failed first attempt. Only the
    # wrapper machine-readable output path redirects to this attempt directory.
    expected = baseline['command'][:]
    if raw is not None:
        expected[expected.index('--out')+1] = str(raw)
    assert command == expected
    log = O / (name + '.log')
    start = utc()
    with log.open('x') as f:
        result = subprocess.run(command, cwd=R, stdout=f, stderr=subprocess.STDOUT, timeout=330, env=env)
    after = stamp()
    receipt = dict(source_commit=C, source_id=before, source_before=before, source_after=after,
                   started_utc=start, finished_utc=utc(), command=command, exit_code=result.returncode,
                   first_attempt=str(previous.relative_to(R)), first_attempt_sha256=sha(previous),
                   log=str(log.relative_to(R)), sha256=sha(log), artifact_sha256=hashes,
                   archive_sha256=sha(archive), archive_receipt_sha256=sha(D/'linux-archive.json'),
                   runner_sha256=sha(Path(command[2])), replay_driver_sha256=sha(Path(__file__)),
                   host='one Linux x86_64 host')
    if raw is not None and result.returncode == 0:
        data = json.loads(raw.read_text())
        assert set(data['reports']) == {'bash', 'zsh', 'fish'}
        assert data['before']['cli_sha256'] == data['after']['cli_sha256'] == hashes['entangle']
        receipt.update(log=str(raw.relative_to(R)), sha256=sha(raw), stdout_log_sha256=sha(log),
                       fixture_sha256=baseline['fixture_sha256'], fixture_signature_sha256=baseline['fixture_signature_sha256'],
                       fixture_keyring_sha256=baseline['fixture_keyring_sha256'])
    with (O / previous.name).open('x') as f:
        json.dump(receipt, f, indent=2)
        f.write('\n')
    print(f'{name}: {result.returncode}', flush=True)
    return result.returncode

stamp()
O.mkdir(exist_ok=True)
m = json.loads((D / 'linux-archive.json').read_text())
archive = R / 'target/release-candidate' / C[:12] / m['name']
hashes = {k: sha(B / k) for k in ('entangle','entangled')}
assert m['source_commit'] == C and m['source_id'] == m['source_after'] == S
assert sha(archive) == m['sha256'] and all(m['files_sha256'][k] == v for k,v in hashes.items())
assert sha(archive) == 'eb481741d88d56263ab99a97979565a0f1d404d9afeac1cb2c895bed7a7113a2'
recovery = D / 'recovery-linux.json'
wrapper = D / 'wrapper-live-scorer-receipt.json'
rc = finish('recovery-linux', recovery, json.loads(recovery.read_text())['command'])
wc = json.loads(wrapper.read_text())['command']
report = O / 'wrapper-live-linux.json'
wc[wc.index('--out') + 1] = str(report)
sys.exit(finish('wrapper-live-linux', wrapper, wc, report) or rc)
