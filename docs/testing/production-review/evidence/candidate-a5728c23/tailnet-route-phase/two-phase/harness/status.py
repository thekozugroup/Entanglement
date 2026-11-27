#!/usr/local/bin/python3
"""Relay the real local CLI result exactly and persist only safe fields."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

def projected(r):
    try:
        s=json.loads(r.stdout)
    except (ValueError,UnicodeError):
        s={}
    return dict(rc=r.returncode,backend=s.get('BackendState'),local_ips=s.get('TailscaleIPs'),
                peers=[dict(id=p.get('ID'),online=p.get('Online'),ips=p.get('TailscaleIPs')) for p in (s.get('Peer') or {}).values()])

def poll():
    # Observer reads only from this daemon's own local CLI/Unix socket and /proc.
    # It never contacts the other device.
    end=time.monotonic()+900
    while time.monotonic()<end:
        s=time.monotonic()
        try:r=subprocess.run(['/usr/local/bin/tailscale.real','status','--json'],capture_output=True,timeout=2)
        except (subprocess.TimeoutExpired,OSError):
            row={'sample_error':True}
        else:row=projected(r)
        with open('/proc/net/udp') as f:row['bound_udp7443']=[line.split()[1] for line in f.readlines()[1:] if line.split()[1].endswith(':1D13')]
        row.update(source='observer',begin=s,end=time.monotonic())
        with open('/ent-home/route-observer.jsonl','a') as f:f.write(json.dumps(row)+'\n')
        time.sleep(0.8)

if __name__=='__main__':
    if sys.argv[1:]==['--only-observe']:
        poll()
    else:
        start=time.monotonic()
        r=subprocess.run(['/usr/local/bin/tailscale.real',*sys.argv[1:]],capture_output=True)
        if sys.argv[1:]==['status','--json']:
            row=projected(r)
            row.update(source='consumed-status',parent=Path('/proc',str(os.getppid()),'comm').read_text().strip(),begin=start,end=time.monotonic())
            with open('/ent-home/route-consumed.jsonl','a') as f:f.write(json.dumps(row)+'\n')
        sys.stdout.buffer.write(r.stdout)
        sys.stderr.buffer.write(r.stderr)
        sys.exit(r.returncode)
