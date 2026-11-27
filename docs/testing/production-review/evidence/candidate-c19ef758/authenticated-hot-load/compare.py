"""Score two matching preregistered hot-load runs without discarding any trial."""
import argparse
import hashlib
import json
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('baseline',type=Path)
p.add_argument('candidate',type=Path)
p.add_argument('out',type=Path)
args=p.parse_args()
baseline=json.loads(args.baseline.read_text())
candidate=json.loads(args.candidate.read_text())
assert all(baseline[k]==candidate[k] for k in ('plan_sha256','harness_sha256','component_sha256'))
assert all(r.get('complete') and len(r['trials'])==4 for r in (baseline,candidate))
def sha(f):
    return hashlib.sha256(f.read_bytes()).hexdigest()
def measured(r):
    return [{'trial':t['trial'],'route':t['coordinator']+' to '+t['worker'],'first_call_success':t['first_submission']['successful'],'first_call_duration_s':round(t['first_submission']['finish_offset_s']-t['first_submission']['start_offset_s'],5),'load_to_first_success_s':t['load_to_authenticated_result_s'],'pre_success_no_workers_replies':t['initial_no_workers_misses'],'observed_inventory_reads_by_completion':t['queries_to_success']} for t in r['trials']]
def behaviors(r):
    return (all(t['actual_worker_completions']==t['expected_worker_completions'] and t['coordinator_completions']==0 and t['parallel_valid_completions']==4 and t['primary_completed']==1 for t in r['trials'])
      and len({t['worker_peer'] for t in r['trials']})==4 and len({t['coordinator_peer'] for t in r['trials']})==4 and [(t['coordinator'],t['worker']) for t in r['trials']]==[('A','B'),('B','A'),('A','B'),('B','A')]
      and r['trials'][3]['guest_error_worker_attempts']==1 and r['trials'][3]['revoked_new_completions']==0 and r['trials'][3]['retrust_new_completions']==1 and r['trials'][3]['burst_incremental_inventory_reads']<=2)
decision = candidate['first_submission_successes']==candidate['first_submission_under_10s_successes']==4 and all(t['initial_no_workers_misses']==0 for t in candidate['trials']) and behaviors(candidate) and behaviors(baseline)
result={'plans_match':True,'baseline_sha256':sha(args.baseline),'candidate_sha256':sha(args.candidate),'baseline_revision':baseline['revision'],'candidate_revision':candidate['revision'],'baseline_trials':measured(baseline),'candidate_trials':measured(candidate),'baseline_median_s':baseline['median_s'],'candidate_median_s':candidate['median_s'],'candidate_max_s':candidate['max_s'],'candidate_under_10s_on_first_submission_all_four':decision,'baseline_parallel_and_policy_controls_passed':behaviors(baseline),'candidate_parallel_and_policy_controls_passed':behaviors(candidate),'baseline_burst_inventory_reads':baseline['trials'][3]['burst_incremental_inventory_reads'],'candidate_burst_inventory_reads':candidate['trials'][3]['burst_incremental_inventory_reads'],'scope':'same Linux x86_64 VM, actual authenticated Iroh QUIC on loopback, exactly one empty model catalog provider per worker. No physical or production WAN latency claim.'}
with args.out.open('x') as f:json.dump(result,f,indent=2);print(file=f)
print(json.dumps(result,indent=2))
raise SystemExit(0 if decision else 1)
