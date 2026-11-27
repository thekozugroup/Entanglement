"""Run a preregistered paired qualification on a source-verified release archive."""
import concurrent.futures
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import xml.etree.ElementTree as ET


workspace=Path('/tmp/entangle-demand-qa')
home=Path(__file__).parent.resolve()
jaq=workspace/'jaq-natural'
commit,sid= sys.argv[1:3]
root=Path(sys.argv[3] if len(sys.argv)>3 else '/workspace/Entanglement').resolve()
tag=commit[:8]
manpath=root/'docs/testing/production-review/evidence'/('candidate-'+tag)/'linux-archive.json'
destination=manpath.parent
run=home/tag
run.mkdir(exist_ok=False)
manifest=json.loads(manpath.read_bytes())
assert manifest['source_commit']==commit and manifest['source_id']==manifest['source_after']==sid

def sha(p):
    with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def zipped(src,dst):dst.write_bytes(gzip.compress(src.read_bytes(),mtime=0))
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def source():return subprocess.check_output([sys.executable,'scripts/production_score.py','--source-id'],cwd=root,text=True).strip()
def execute(cmd,log,env,cwd=root):
    with log.open('xb')as fd:return subprocess.run(cmd,cwd=cwd,env=env,stdout=fd,stderr=subprocess.STDOUT).returncode
def read(p):return json.loads(p.read_bytes())
assert source()==sid
archive=root/'target/release-candidate'/commit[:12]/manifest['name']
assert sha(archive)==manifest['sha256']
bins=run/'binaries';bins.mkdir()
with tarfile.open(archive)as tar:
    for name in ('entangle','entangled'):
        content=tar.extractfile(manifest['name'].removesuffix('.tar.gz')+'/'+name).read()
        assert hashlib.sha256(content).hexdigest()==manifest['files_sha256'][name]
        p=bins/name;p.write_bytes(content);p.chmod(0o555)
env={**os.environ,'CARGO_HOME':'/workspace/.entanglement-dev/cargo','RUSTUP_HOME':'/workspace/.entanglement-dev/rustup','CARGO_BUILD_JOBS':'2','CARGO_PROFILE_DEV_DEBUG':'0','CARGO_INCREMENTAL':'0','ENTANGLE_REVIEW_COMMIT':commit,'ENTANGLE_REVIEW_SOURCE_ID':sid}
env['PATH']=env['CARGO_HOME']+'/bin:'+env['PATH']
assert sha(home/'preregistration.md')=='a25064f7571ddd6b48d94feb42eee7481a1b8b3afe40844cd04e0fef2ef93b4f'
assert sha(jaq/'plan.md')=='5c611fc83708fe3886157ca4203bbf8fcc6717096ea2dfc0eae6fb387f238a4b'
registered=dict(started_utc=now(),source_before=source(),release_commit=commit,archive_sha256=sha(archive),
    elf_sha256={n:sha(bins/n)for n in ('entangle','entangled')},preregistration_sha256=sha(home/'preregistration.md'),
    jaq_original_protocol_sha256=sha(jaq/'plan.md'),candidate_sharder_sha256=sha(root/'scripts/run-rust-tests.py'),driver_sha256=sha(Path(__file__)))
save(run/'bound-protocol.json',registered)
def rngs():
    out=destination/'distributed-rust-workspace'
    out.mkdir(exist_ok=False)
    cmd=['bash',workspace/'driver-296/run-workspace.sh',root,manpath,bins,'rngs',workspace/('rngs-'+tag)]
    rc=execute(cmd,run/'rngs-launch.log',env)
    for f in ['rngs-'+tag+'.json','rngs-'+tag+'-qualification.json']:
        assert (workspace/f).is_file(), 'missing '+f
    # Original archive writer retains raw artifacts before testing parity.
    if root != Path('/workspace/Entanglement'):raise RuntimeError('Select the root used by the common packaging helper')
    pack=execute([sys.executable,workspace/'package-296-workspaces.py','rngs',commit,sid],run/'rngs-packing.log',env)
    print('rngs Cargo/packing',rc,pack,flush=True)
    assert rc==pack==0
    report=workspace/('rngs-'+tag+'.multi.json')
    multi=read(report);multi_rc=read(workspace/('rngs-'+tag+'.multi.receipt.json'))
    assert multi_rc['exit_code']==0
    xml=run/'multi-suite.xml'
    command=[sys.executable,root/'scripts/rust-test-junit.py',report,xml]
    conv=execute(command,run/'rngs-junit.log',env)
    assert conv==0
    suites=ET.parse(xml).getroot()
    assert suites.tag=='testsuites'
    assert len(suites.findall('testsuite'))==len(multi['suites'])==17
    expected={ (s['suite'],r['name']):{'status':r['status'],'attempts':r['attempts']}for s in multi['suites']for r in s['results']}
    actual={(s.get('name'),c.get('name')):json.loads(c.findtext('system-out'))for s in suites.findall('testsuite')for c in s.findall('testcase')}
    assert len(actual)==len(expected)==198 and actual==expected and all(a['status']=='passed'for a in actual.values())
    assert set(multi_rc['peers'])==set(a['peer']for v in actual.values()for a in v['attempts'])
    assert all(s['listing_peers']==multi_rc['peers']and len(s['suite_identity'])==2 for s in multi['suites'])
    zipped(report,out/'multi-suite.json.gz');zipped(xml,out/'multi-suite.xml.gz')
    multi_rc.update(stdout_json_sha256=sha(report),junit_sha256=sha(xml),junit_command=[str(c)for c in command],junit_cli_sha256=sha(root/'scripts/rust-test-junit.py'),
        junit_exit=conv,all_suites_cases_status_and_attempt_history_equal=True,counts=multi['counts'],suite_count=len(multi['suites']),source_after=source(),finished_utc=now())
    save(out/'multi-suite-receipt.json',multi_rc)
    per=read(out/'rngs-native-parity.json')
    assert per['all_dispositions_identical'] and per['named_inventory_identical'] and sum(per['worker_attempts'].values())==222
    (out/'README.md').write_text(f"""# Complete nine-crate upstream Rust workspace

On frozen {tag}, native Cargo and two authenticated WASI workers matched all 224 named cases in the unchanged rust-random/rngs workspace. The 198 ordinary tests and 24 doctests passed and two doctests were ignored. Workers handled {sorted(per['worker_attempts'].values())} named cases. Hot-loaded signed ordinary suites took the public sharder negotiation path and pinned the artifact and manifest hashes. Merged Rustdoc 2024 commands were dispatched directly to their authenticated worker with locally verified signed hashes. [Native comparison](rngs-native-parity.json) · [Release and command receipt](rngs-receipt.json) · [Complete replies](rngs-distributed.json.gz)

A separate unmodified 17-suite sharder CLI invocation on the same warm workers succeeded on all 198 ordinary cases. The released-source JUnit converter preserved all suite names, case names, statuses and complete attempt histories, including real peer identity. [JUnit XML](multi-suite.xml.gz) · [Input JSON](multi-suite.json.gz) · [Separate invocation and digests](multi-suite-receipt.json)
""")
    return {'native_ordinary_and_docs':per['native_counts'],'workers':per['worker_attempts'],'coverage':224,'junit_cases':198}
def jaq_run():
    out=destination/'jaq-natural';out.mkdir(exist_ok=False)
    shutil.copy2(home/'preregistration.md',out/'preregistration.md')
    shutil.copy2(jaq/'plan.md',out/'original-protocol.md')
    shutil.copy2(run/'bound-protocol.json',out/'bound-protocol.json')
    encoder=jaq/'component-adapter'
    adapter=Path(env['CARGO_HOME'])/'registry/src/index.crates.io-1949cf8c6b5b557f/wasi-preview1-component-adapter-provider-36.0.23/artefacts/wasi_snapshot_preview1.command.wasm'
    cases=run/'jaq-cohort'
    command=[sys.executable,jaq/'campaign-296.py','--root',root,'--binaries',bins,'--archive',manpath,'--sharder',root/'scripts/run-rust-tests.py','--fixture',root/'scripts/tests/distributed-rust-tests.py','--encoder',encoder,'--adapter',adapter,'--out',cases]
    campaign_exit=execute(command,run/'jaq-cohort.log',env)
    rec=read(cases/'receipt.json')
    shutil.copy2(cases/'receipt.json',out/'cohort-receipt.json')
    if (cases/'blocks.jsonl').is_file():zipped(cases/'blocks.jsonl',out/'blocks.jsonl.gz')
    shutil.copy2(run/'jaq-cohort.log',out/'cohort-launch.log')
    verify=execute([sys.executable,jaq/'verify-cohort.py',out/'cohort-receipt.json',out/'blocks.jsonl.gz','--output',out/'all-block-verification.json'],run/'jaq-validation.log',env)
    shutil.copy2(run/'jaq-validation.log',out/'cohort-verification.log')
    print('jaq 128 paired cohort',campaign_exit,verify,rec.get('remote_patterns'),flush=True)
    bindings=run/'jaq-components';bindings.mkdir()
    jenv={**env,'CARGO_TARGET_DIR':str(jaq/'target178'),'JAQ_COMPONENT_ENCODER':str(encoder),'JAQ_WASI_ADAPTER':str(adapter),'JAQ_ARTIFACT_EVIDENCE':str(bindings)}
    native_cmd=['cargo','+1.78.0','test','--offline','--locked','--workspace','--no-fail-fast']
    native_exit=execute(native_cmd,run/'jaq-native.log',jenv,cwd=jaq/'upstream')
    zipped(run/'jaq-native.log',out/'full-native-cargo.log.gz')
    full_xml=run/'jaq-distributed.json'
    args=[sys.executable,jaq/'workspace-296.py','--root',root,'--workspace',jaq/'upstream','--metadata',jaq/'workspace-metadata178.json','--wasm-artifacts',jaq/'original178-wasi-artifacts.jsonl','--binaries',bins,'--out',full_xml,'--cargo-log',run/'jaq-workspace-cargo.log','--sharder',root/'scripts/run-rust-tests.py','--binary-manifest',manpath]
    full_exit=execute(args,run/'jaq-full.log',jenv)
    if not full_xml.is_file():raise RuntimeError('full jaq adapter did not return its detailed result')
    q=read(full_xml)
    zipped(full_xml,out/'full-workspace.json.gz');zipped(run/'jaq-workspace-cargo.log',out/'full-cargo.log.gz');shutil.copy2(run/'jaq-full.log',out/'full-launch.log')
    save(out/'compiled-component-bindings.json',[read(f)for f in sorted(bindings.glob('*.json'))])
    assert q['source_before']==q['source_after']==rec['source_before']==rec['source_after']==sid
    assert q['daemon_sha256']==registered['elf_sha256']['entangled'] and q['cli_sha256']==registered['elf_sha256']['entangle']
    assert full_exit==q['exit_code']
    import collections,re
    statuses=collections.Counter();native_summary=collections.Counter()
    for t in q['targets']:statuses.update(t['report']['counts'])
    for _,p,f,i in re.findall(r'^test result: (ok|FAILED)\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;', (run/'jaq-native.log').read_text(),re.M):
        native_summary.update(passed=int(p),failed=int(f),ignored=int(i))
    verify_doc=read(out/'all-block-verification.json')if (out/'all-block-verification.json').exists()else {}
    detail=dict(**registered,upstream_revision=q['upstream_commit'],source_after=source(),finished_utc=now(),full_native_command=native_cmd,full_native_exit=native_exit,full_native_counts=native_summary,full_remote_exit=full_exit,full_reported_cases=statuses,
        cohort_exit=campaign_exit,cohort_verifier_exit=verify,cohort_blocks=rec.get('blocks'),remote_cohort_patterns=rec.get('remote_patterns'),native_cohort_patterns=rec.get('native_patterns'),
        cross_peer_blocks=rec.get('verified_remote_transitions'),natural_cross_peer_witness=verify_doc.get('witness_criterion_met'),whole_workspace_native_wasi_parity=(full_exit==native_exit==0 and statuses['passed']==native_summary['passed'] and statuses['ignored']==native_summary['ignored']),
        sharder_sha256=sha(root/'scripts/run-rust-tests.py'),independent_verifier_sha256=sha(jaq/'verify-cohort.py'),workspace_driver_sha256=sha(jaq/'workspace-296.py'),cohort_script_sha256=sha(jaq/'campaign-296.py'))
    save(out/'qualification.json',detail)
    (out/'README.md').write_text(f"""# Naturally intermittent upstream test on authenticated workers

The {tag} release ran the unchanged jaq four-crate workspace at `{q['upstream_commit']}`. The historically documented `jaq-core/tests/named.rs::now` case compares a real wall clock's truncated seconds to a second reading rounded to the nearest integer. The registered cohort completed {rec.get('blocks')} matched native and WASI blocks. Remote attempt histories were {rec.get('remote_patterns')}; native attempt histories were {rec.get('native_patterns')}. Verified cross-peer recovery blocks were {rec.get('verified_remote_transitions')}. The raw archive includes every attempt, both peers, signed identity and complete case diagnostics. [Prospective protocol](preregistration.md) · [Verified published-case outcomes](all-block-verification.json) · [Full raw cohort](blocks.jsonl.gz) · [Upstream removal](https://github.com/01mf02/jaq/commit/191e5e6780aad7fcc6295e3aced68bfd657eef14)

In the separate fresh whole-workspace run, native Cargo exited {native_exit} and recorded {dict(native_summary)}. Distributed Cargo exited {full_exit} and recorded {dict(statuses)} plus any target construction errors in the complete driver log. Every default test target was attempted. The binary and golden integration suites have previously documented native allocator, filesystem and process requirements. The current whole-workspace parity result is {detail['whole_workspace_native_wasi_parity']}. The independent rust-random full-workspace parity result concerns a different project. [Current native and distributed outcomes](qualification.json) · [Full native Cargo log](full-native-cargo.log.gz) · [Full WASI Cargo log](full-cargo.log.gz) · [All distributed responses](full-workspace.json.gz) · [Prior upstream source review](../../candidate-296b427a/jaq-natural/history-window.md)
""")
    return detail
jobs={'rngs':rngs,'jaq':jaq_run}
with concurrent.futures.ThreadPoolExecutor(max_workers=2)as pool:
    futures={pool.submit(fn):name for name,fn in jobs.items()}
    for task in concurrent.futures.as_completed(futures):
        name=futures[task]
        try:
            result=task.result()
            save(run/(name+'-complete.json'),result)
            print(name,'complete',now(),flush=True)
        except Exception as e:
            print(name,'failed',repr(e),flush=True)
            import traceback
            (run/(name+'-error.log')).write_text(traceback.format_exc())
assert all((run/(name+'-complete.json')).exists()for name in jobs)
assert source()==sid
