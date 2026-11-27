#!/usr/bin/env python3
"""Compare native Cargo's actual case names/statuses against signed remote case records."""
import argparse, collections, hashlib, json, re
from pathlib import Path

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('metadata','native-artifacts','native-log','distributed','out'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    packages={p['id']:p['name'] for p in json.loads(args.metadata.read_text())['packages']}
    bins={}
    for l in args.native_artifacts.read_text().splitlines():
        j=json.loads(l)
        if j['reason']=='compiler-artifact' and j['package_id'] in packages and j['profile']['test'] and j['executable']:
            bins[Path(j['executable']).name]=(packages[j['package_id']],'+'.join(j['target']['kind']),j['target']['name'])
    native={}
    cur=None
    for line in args.native_log.read_text().splitlines():
        if z:=re.match(r'\s*Running .+ \(([^)]+)\)$',line):
            cur=bins[Path(z[1]).name]
        elif z:=re.match(r'\s*Doc-tests (\S+)$',line):
            cur=(z[1],'rustdoc','doctest')
        elif z:=re.fullmatch(r'test (.+?) \.\.\. (ok|ignored|FAILED)(?:, .*?)?',line):
            key=(*cur,z[1]);assert key not in native,key
            native[key]={'ok':'passed','ignored':'ignored','FAILED':'failed'}[z[2]]
    run=json.loads(args.distributed.read_text())
    remote={};worker_counts=collections.Counter();attempts=0
    for target in run['targets']:
        for case in target['report']['results']:
            key=(target['package'],target['kind'],target['target'],case['name'])
            if key in remote:raise ValueError(f'duplicate remote case {key}')
            remote[key]=case['status']
            for a in case['attempts']:
                if a['status']!='ignored':
                    worker_counts[a['peer']]+=1;attempts+=1
    failures=[{'case':k,'native':native.get(k),'remote':remote.get(k)}for k in sorted(native.keys()|remote.keys()) if native.get(k)!=remote.get(k)]
    def grouped(items):
        return {label:dict(collections.Counter(v for k,v in items.items() if (k[1]=='rustdoc')==doc))for label,doc in [('unit_and_integration',False),('doctests',True)]}
    report={'native_counts':grouped(native),'distributed_counts':grouped(remote),'native_distinct_cases':len(native),'distributed_distinct_cases':len(remote),
        'all_case_names_and_dispositions_match':not failures,'differences':failures,'expected_workers':run['peers'],'observed_worker_attempts':dict(worker_counts),'attempts':attempts,
        'cargo_exit':run['exit_code'],'native_log_sha256':hashlib.sha256(args.native_log.read_bytes()).hexdigest(),
        'remote_report_sha256':hashlib.sha256(args.distributed.read_bytes()).hexdigest()}
    args.out.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    return int(bool(failures or run['exit_code'] or set(worker_counts)!=set(run['peers'])))
if __name__=='__main__':
    raise SystemExit(main())
