import datetime,hashlib,json,pathlib,subprocess,sys,tempfile
r=pathlib.Path('/workspace/Entanglement')
base=r/'docs/testing/production-review/evidence/candidate-a5728c23/linux-compatibility'
d=base/'reverse-mixed-isa'
current='a5728c230e5049556b806cae8597fe823dd67987'
sid='sha256:a43296d252b79d7a0762861de1251b0e2e77fde20af2ea5dd43254617376fce5'
def src():return subprocess.check_output([sys.executable,'scripts/production_score.py','--source-id'],cwd=r,text=True).strip()
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
with tempfile.TemporaryDirectory(dir='/workspace',prefix='entangle-reverse-mixed-isa-') as tmp:
 cmd=json.loads((base/'repeat/mixed-release-arm64/normalized.json').read_bytes())['command']
 cmd[2]=str(d/'run.py')
 for flag,path in [('--out',d),('--work',tmp)]:cmd[cmd.index(flag)+1]=str(path)
 start=now();before=src()
 assert before==sid and subprocess.check_output(['git','rev-parse','HEAD'],cwd=r,text=True).strip()==current
 with (d/'run.log').open('x') as f:rc=subprocess.run(cmd,cwd=r,stdout=f,stderr=subprocess.STDOUT).returncode
 after=src();end=now()
 record=d/('reverse-mixed-isa.json' if rc==0 else 'run.log')
 out=dict(source_commit=current,source_before=before,source_after=after,started_utc=start,finished_utc=end,command=cmd,exit_code=rc,log=str(record.relative_to(r)),sha256=sha(record),commands_log_sha256=sha(d/'commands.jsonl'))
 if rc==0:
  p=json.loads(record.read_bytes());job=p['dispatch']; assert job['before']=={'x86':{'ok':0,'error':0},'arm':{'ok':0,'error':0}} and job['after']=={'x86':{'ok':1,'error':0},'arm':{'ok':0,'error':0}} and p['arm_source_before']==p['arm_source_after'] and job['chosen_peer']==p['nodes']['x86']['peer'] and p['nodes']['arm']['daemon_exit_code']==p['nodes']['x86']['daemon_exit_code']==0
  out.update(arm_source_before=p['arm_source_before'],arm_source_after=p['arm_source_after'],arm_source_commit=p['inputs']['arm']['source_commit'],coordinator='QEMU Linux AArch64, c19ef758',worker='native Linux x86_64, a5728c23',fixture_sha256=p['fixture']['component_sha256'],coordinator_loaded_plugins=job['coordinator_loaded_plugins'],worker_loaded_plugins=job['worker_loaded_plugins'],chosen_peer=job['chosen_peer'],exact_output=job['output']==job['expected'],output_sha256=job['output_sha256'],worker_invocations=job['after']['x86']['ok'],coordinator_invocations=job['after']['arm']['ok'],execution_error_counts={'x86':job['after']['x86']['error'],'arm':job['after']['arm']['error']})
 assert after==sid
 (d/'normalized.json').write_text(json.dumps(out,indent=2)+'\n')
 print('source before/after',before,after,'exit',rc,'evidence',record)
sys.exit(rc)
