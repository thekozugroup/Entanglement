"""Produce per-arm relative times from shared Linux monotonic timestamps."""
import collections, json, sys
from pathlib import Path
d=Path(sys.argv[1])
def rows(n):return list(map(json.loads,(d/n).read_text().splitlines()))
e=rows('events.jsonl')
j=json.loads((d/'result.json').read_bytes())
worker=j['identities']['worker'];peer=worker['tailscale_id'];address=worker['address']
def peer_usable(r):
    return r.get('rc')==0 and r.get('backend')=='Running' and any(str(p['id'])==str(peer) and p['online'] and address in p['ips'] for p in r.get('peers',[]))
def deltas(rows,predicate):
    seen=None;out=[]
    for r in rows:
        if anchor-1<=r['end']<=done+.1:
            valid=bool(predicate(r))
            if valid!=seen:
                out.append([round(r['end']-ready,3),valid]);seen=valid
    return out
summary={}
for name,outcome in j['transport_restarts'].items():
    phase=f'{name} worker tailscaled restart'
    anchor=next(r for r in e if r['event']=='arm-start' and r['arm']==name)['snapshot']
    ready=next(r['when'] for r in e if r['event']=='overlay-ready' and r['phase']==phase)
    ds=[r for r in e if r['event']=='dispatch' and r['phase']==phase]
    done=ds[-1]['when']
    summary[name]=dict(outcome=outcome,
        first_dispatch=round(ds[0]['begin']-ready,3),
        failures=dict(collections.Counter(r['reason'] for r in ds if r['rc'])),
        latest_failed_dispatch=round(ds[-2]['when']-ready,3) if len(ds)>1 else None,
        successful_dispatch_began=round(ds[-1]['begin']-ready,3),
        successful_dispatch_returned=round(done-ready,3),
        actual_status_on_coordinator=[[round(r['end']-ready,3),peer_usable(r),r['parent']] for r in rows('coordinator-consumed.jsonl') if anchor-1<=r['end']<=done+.1],
        independent_coordinator_status_changes=deltas(rows('coordinator-observer.jsonl'),peer_usable),
        worker_bind_changes=deltas(rows('worker-observer.jsonl'),lambda r:r.get('bound_udp7443')),
        coordinator_bind_changes=deltas(rows('coordinator-observer.jsonl'),lambda r:r.get('bound_udp7443')),
        offline_duration=next(r['offline_seconds'] for r in e if r['event']=='worker-start-request' and r['phase']==phase))
print(json.dumps(summary,indent=2))
