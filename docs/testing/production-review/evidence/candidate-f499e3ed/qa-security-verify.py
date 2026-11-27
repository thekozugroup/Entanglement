import datetime,hashlib,json,pathlib,subprocess
b=pathlib.Path(__file__).resolve().parent
source='sha256:31991c5d25c0e7b2f721aadb7767b89d1e7cc270869322801e7f879d833587aa'
def sid():return subprocess.check_output(['python3','scripts/production_score.py','--source-id'],text=True).strip()
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
start=now(); before=sid(); assert before==source
review=json.loads((b/'qa-security-review.json').read_text()); assert review['source_id']==source and sha(b/review['report'])==review['report_sha256']
for name,h in review['evidence_sha256'].items(): assert sha(b/name)==h,name
for name in ['auth-live-scorer-receipt.json','qa-publisher-incident.json','sigstore-conformance.json','private-tailnet-ordinary-receipt.json','private-tailnet-recovery-receipt.json','private-tailnet-bridge-receipt.json']:
 d=json.loads((b/name).read_text());assert d['exit_code']==0 and d['source_before']==source and d['source_after']==source;assert sha(pathlib.Path(d['log']))==d['sha256'],name
for name in ['oci-distribution-https','live-publisher']:
 d=json.loads((b/(name+'.json')).read_text());assert d['exit_code']==0 and d['source_id']==source and d['source_after']==source and sha(b/(name+'.log'))==d['log_sha256']
after=sid();assert after==source
log=b/'qa-security-verify.log'; log.write_text('Verified report and bound current-source evidence and raw logs. Scope is the reviewed controls only.\n')
r={'source_commit':'f499e3edf84e20f550312d05df51b9ea4e7cc699','source_id':source,'source_before':before,'source_after':after,'started_utc':start,'finished_utc':now(),'exit_code':0,'command':['python3',str(pathlib.Path(__file__))],'log':str(log.relative_to(pathlib.Path.cwd())),'sha256':sha(log),'reviewed_report':'qa-security-review.md','reviewed_report_sha256':review['report_sha256'],'review_json_sha256':sha(b/'qa-security-review.json'),'verifier_sha256':sha(pathlib.Path(__file__))}
(b/'qa-security-verify-receipt.json').write_text(json.dumps(r,indent=2)+'\n')
print('verified')
