"""Observe only the test port's kernel queue and selected transport failure messages."""
import datetime
import json
import re
import subprocess
import sys
import time


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

network=sys.argv[1]
assert re.fullmatch(r"entangle-wg-[0-9a-f]{12}",network)
seen=set()
installed=False
query="""import json,os
from pathlib import Path
rows=[]
for table in ("udp","udp6"):
 for line in Path("/proc/net/"+table).read_text().splitlines()[1:]:
  row=line.split()
  if row[1].endswith(":1D13"):
   tx,rx=row[4].split(":")
   rows.append(dict(table=table,endpoint=row[1],tx_queue=int(tx,16),rx_queue=int(rx,16),drops=int(row[-1]),inode=row[9]))
print(json.dumps(dict(kernel_network_namespace=os.readlink("/proc/self/ns/net"),tun=Path("/sys/class/net/tailscale0").exists(),udp=rows)))
"""
for _ in range(160):
    up=subprocess.run(["docker","inspect","-f","{{.State.Running}}",network+"-control"],capture_output=True,text=True,timeout=5)
    if up.returncode or up.stdout.strip()!="true":
        break
    for role in ("worker","coordinator"):
        name=network+"-"+role+"-app"
        data=subprocess.run(["docker","exec",name,"python3","-c",query],capture_output=True,text=True,timeout=5)
        if data.returncode:
            continue
        installed=True
        print(json.dumps({"time":now(),"role":role,"snapshot":json.loads(data.stdout)}),flush=True)
        logs=subprocess.run(["docker","logs",name],capture_output=True,text=True,timeout=5)
        for line in (logs.stdout+"\n"+logs.stderr).splitlines():
            if line in seen or not any(m in line for m in ("failed to rebind transports","All transports failed to receive","I/O error:")):
                continue
            seen.add(line)
            try:
                entry=json.loads(line)
            except ValueError:
                continue
            print(json.dumps({"time":entry.get("timestamp"),"role":role,"target":entry.get("target"),
                              "warning":entry.get("fields",{}).get("message")}),flush=True)
    time.sleep(2)
if not installed:
    raise SystemExit("no test application observed")
