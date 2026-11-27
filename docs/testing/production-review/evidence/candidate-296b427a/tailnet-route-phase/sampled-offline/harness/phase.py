"""Local observations for the isolated 296b route-snapshot phase comparison."""
import json, os, subprocess, time
from pathlib import Path

OUTPUT=Path(os.environ['TRACE_OUT'])
def write(row):
    with (OUTPUT/'events.jsonl').open('a') as f:
        f.write(json.dumps(row)+'\n')
def mark(label,**kwargs):
    write(dict(event=label,when=time.monotonic(),**kwargs))
def records(path):
    try:data=path.read_text()
    except FileNotFoundError:return []
    return [json.loads(line) for line in data.splitlines(keepends=True) if line.endswith('\n')]
def sync(node,worker,label,offset):
    start=time.monotonic()
    expected=worker['id']
    path=node['home']/'route-consumed.jsonl'
    while time.monotonic()-start<42:
        for row in records(path):
            if row['end']>start and row['backend']=='Running' and any(str(p['id'])==str(expected) and p['online'] and worker['addr'] in p['ips'] for p in row['peers']):
                target=row['end']+offset
                time.sleep(max(0,target-time.monotonic()))
                mark('arm-start',arm=label,snapshot=row['end'],offset=offset)
                return
        time.sleep(.08)
    raise RuntimeError('no new healthy coordinator snapshot to anchor bounded comparison')
def preserve(nodes):
    for role,node in nodes.items():
        for typ in ['consumed','observer']:
            path=node['home']/f'route-{typ}.jsonl'
            if path.exists(): (OUTPUT/f'{role}-{typ}.jsonl').write_text(path.read_text())
        proc=subprocess.run(['docker','logs','--timestamps',node['app']],capture_output=True,text=True,timeout=5)
        lines=[r for r in (proc.stdout+proc.stderr).splitlines() if 'scheduler accept loop ended' in r or 'scheduler address unavailable' in r or 'scheduler rebind pending' in r]
        (OUTPUT/f'{role}-endpoint.log').write_text('\n'.join(lines)+'\n')
