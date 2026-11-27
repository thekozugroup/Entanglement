"""Replay two candidate scheduler preconditions after the quiet benchmark."""
import datetime
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

repo = Path('/workspace/Entanglement')
commit = 'c19ef7587a2215ef9434b642413bebd0473caf20'
source = 'sha256:81d8219e78f71c2e2987800cec205d72c22d015e1db4e0fc7577ba424e4ef644'
evidence = repo / 'docs/testing/production-review/evidence/candidate-c19ef758'
predecessor = evidence.parent / 'candidate-a0926c6e'
source_dir = Path(__file__).resolve().parent
result_dir = evidence / 'bandwidth-placement-attribution'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(*args, cwd=repo):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def stamp():
    assert run('git', 'rev-parse', 'HEAD') == commit
    assert run('python3', 'scripts/production_score.py', '--source-id') == source
    return source


before = stamp()
started = datetime.datetime.now(datetime.timezone.utc).isoformat()
raw = evidence / 'bandwidth-live-linux.json'
failed = json.loads(raw.read_bytes())
assert failed['exit_code'] == 1 and failed['failure']['input_bytes'] == 786515
assert next(o['measured_bps'] for o in failed['observations'] if o['phase']=='fast-measure') == 52689170
assert failed['failure']['measured_bps'] == 3178372
arch = json.loads((evidence/'linux-archive.json').read_bytes())
assert failed['archive_sha256'] == arch['sha256']
prior = json.loads((predecessor/'bandwidth-live-linux.json').read_bytes())
fingerprints = repo / 'target/debug/.fingerprint'
compiled = repo / 'target/debug/deps'
# Select a single coherent set, matching the dependency IDs of the prebuilt scheduler.
fp = fingerprints / 'entangle-scheduler-f77b279499f78527/lib-entangle_scheduler.json'
needs = {'entangle_types', 'serde', 'thiserror', 'parking_lot'}
args = []
dep_receipts = {}
for _,name,_,number in json.loads(fp.read_text())['deps']:
    if name not in needs:
        continue
    wanted = number.to_bytes(8,'little').hex()
    matches = [x for x in fingerprints.glob('*/lib-'+name) if x.read_text().strip()==wanted]
    assert len(matches) == 1
    library = compiled / ('lib'+name+'-'+matches[0].parent.name.rsplit('-',1)[1]+'.rlib')
    args.extend(['--extern',name+'='+str(library)])
    dep_receipts[name] = {'rlib':library.name, 'sha256':digest(library), 'cargo_fingerprint':wanted}
assert set(dep_receipts)==needs
rustc = Path('/workspace/.entanglement-dev/rustup/toolchains/1.91-x86_64-unknown-linux-gnu/bin/rustc')
modules = {}
with tempfile.TemporaryDirectory(prefix='ent-c19-choice-') as tmp:
    scratch = Path(tmp)
    for name in ['placement','worker']:
        relative = 'crates/entangle-scheduler/src/'+name+'.rs'
        body = subprocess.check_output(['git','show',commit+':'+relative],cwd=repo)
        assert body == (repo/relative).read_bytes()
        (scratch/(name+'.rs')).write_bytes(body)
        modules[relative] = hashlib.sha256(body).hexdigest()
    shutil.copyfile(source_dir / 'probe.rs',scratch/'probe.rs')
    command=[str(rustc),'--edition','2021','-C','debuginfo=0','-L','dependency='+str(compiled),*args,'probe.rs','-o','probe']
    subprocess.run(command, cwd=scratch, check=True)
    output=run('./probe',cwd=scratch)
    cases=[]
    for line in output.splitlines():
        fields, reason=line.split(' reason=',1)
        case=dict(pair.split('=',1) for pair in fields.split())
        case['reason']=reason
        assert case['expected']==case['chosen']
        cases.append(case)
assert len(cases)==2 and cases[0]['chosen']!=cases[1]['chosen']
fast=.4/(1+32*786515/52689170);slow=.4/(1+32*786515/3178372)
result=dict(source_commit=commit,source_before=before,source_after=stamp(),started_utc=started,finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),exit_code=0,
            canonical_archive_sha256=arch['sha256'],first_trial_sha256=digest(raw),first_trial_exit_code=failed['exit_code'],earlier_passing_trial_sha256=digest(predecessor/'bandwidth-live-linux.json'),
            prior_passing_measures=[{'phase':row['phase'],'reason':row['reason']} for row in prior['jobs'] if row['phase'] in ('fast-measure','slow-measure','both-eligible')],
            frozen_modules_sha256=modules,probe_sha256=digest(source_dir/'probe.rs'),rustc=run(rustc,'-vV'),command=command,dependencies=dep_receipts,
            prepared_component_states='Fresh authenticated pool per pair, identical hardware/plugin/load/cost/reservations, retained measured upload rates as controlled inputs. Controlled low RTT and high RTT cases only.',
            original_trial_known='Slower worker selected with RTT 57 ms, correct result, load=0, in_flight=0, cost=1, measured upload 3178372 bps. Earlier fast-only selection reported 52689170 bps.',
            original_trial_unknown='Losing peer eligibility and measured upload EWMA, capability RTT, load and reservation state at the contested instant were not recorded. Parallel link and capability conditions can change.',
            bytes=786515,fast_input_bps=52689170,slow_input_bps=3178372,fast_bandwidth_term=fast,slow_bandwidth_term=slow,bandwidth_delta=fast-slow,locality_score_per_ms=.6/195,crossover_rtt_gap_ms=(fast-slow)*195/.6,
            cases=cases,scope='Controlled source-level chooser counterexample to a speed-only oracle; the observed live failure remains a failed independent trial.')
result_dir.mkdir(exist_ok=True)
for file in ['probe.rs','replay.py']:
    if source_dir != result_dir:
        with (result_dir/file).open('xb') as dest: dest.write((source_dir/file).read_bytes())
with (result_dir/'receipt.json').open('x') as f:json.dump(result,f,indent=2);f.write('\n')
print(output)
