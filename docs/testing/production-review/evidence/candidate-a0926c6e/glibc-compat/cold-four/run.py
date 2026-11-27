"""Run four independent pairs serially and preserve successes and failures alike."""
import hashlib,json,subprocess,sys,time
from pathlib import Path
d=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
attempts=[]
for index in range(1,5):
    start=time.monotonic()
    with (d/('trial-'+str(index)+'.log')).open('x') as f:
        result=subprocess.run([sys.executable,'-B',str(d/'trial.py'),str(index)],stdout=f,stderr=subprocess.STDOUT)
    path=d/('trial-'+str(index))/'result.json'
    item=dict(index=index,harness_exit=result.returncode,elapsed_s=round(time.monotonic()-start,3),raw_file=str(path.relative_to(d)))
    if path.exists():
        r=json.loads(path.read_text());z=r['dispatches'][0];first=z['first_submission'];recovery=z['followup']
        item.update(raw_sha256=sha(path),first_verified=first['verified'],first_exit=first['exit_code'],first_error=first['stderr'] if not first['verified'] else None,first_elapsed_ms=first['elapsed_ms'],
                    load_stop_to_first_start_ms=z['load_stop_to_first_start_ms'],followup_verified=recovery['verified'] if recovery else None,followup_elapsed_ms=recovery['elapsed_ms'] if recovery else None,
                    listener_ages_ms=first['listener_age_start_ms'],source_id=r['source_id'],archive_sha256=r['archive_sha256'])
    attempts.append(item);print(item,flush=True)
complete=all(a.get('harness_exit')==0 and 'first_verified' in a for a in attempts)
report=dict(complete=complete,count=len(attempts),first_succeeded=sum(1 for a in attempts if a.get('first_verified')),harness_sha256={s:sha(d/s) for s in ['trial.py','catalog.py','run.py']},trials=attempts,claim='Same-host rootless Jammy coordinator and Bookworm worker. Observer does not imply wire delivery or receipt by the coordinator.')
with (d/'summary.json').open('x') as f:json.dump(report,f,indent=2);f.write('\n')
sys.exit(0 if complete else 1)
