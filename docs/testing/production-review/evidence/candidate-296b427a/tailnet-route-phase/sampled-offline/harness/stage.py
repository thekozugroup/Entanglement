"""Construct an instrumented private copy, refusing an unexpected frozen fixture."""
from pathlib import Path
import subprocess
D=Path(__file__).resolve().parent
R=Path('/workspace/Entanglement')
HEAD='296b427a3bb2d60615ea3c56b9779f97039c6e24'
def get(file):return subprocess.check_output(['git','show',HEAD+':scripts/tests/'+file],cwd=R,text=True)
def once(s,old,new):
    assert s.count(old)==1,old
    return s.replace(old,new)
s=get('private-tailnet.py')
s=once(s,'REPO = Path(__file__).resolve().parents[2]',f'REPO = Path({str(R)!r})\nfrom phase import preserve')
s=once(s,'-v", f"{ts_cli}:/usr/local/bin/tailscale:ro"','-v", f"{ts_cli}:/usr/local/bin/tailscale.real:ro", "-v", "'+str(D/'status.py')+':/usr/local/bin/tailscale:ro"')
s=once(s,'        return check_recovery(nodes, run, policy, cold_controls, ping.strip().splitlines()[-1])','''        for node in nodes.values():
            run("docker", "exec", "-d",node["app"], "/usr/local/bin/tailscale", "--only-observe")
        try:
            return check_recovery(nodes, run, policy, cold_controls, ping.strip().splitlines()[-1])
        finally:
            preserve(nodes)''')
(D/'private-tailnet.py').write_text(s)
s=get('private_recovery.py')
s=once(s,'import re\nimport secrets','import re\nfrom phase import mark, sync\nimport secrets')
s=once(s,'        result = app(coordinator, "compute"', '        attempt_begin = time.monotonic()\n        result = app(coordinator, "compute"')
s=once(s,'        if result.returncode:\n            require(not result.stdout','''        mark("dispatch",phase=label,begin=attempt_begin,rc=result.returncode,
             reason=("no-route" if "no known network address" in result.stderr else
                     "no-workers" if "no live workers" in result.stderr else
                     "transport-timeout" if "no answer within" in result.stderr else
                     "refused" if "not-authorized" in result.stderr else
                     "ok" if not result.returncode else "other"),nonce=nonce)
        if result.returncode:
            require(not result.stdout''')
s=once(s,'    restarts = {}\n    for role, node in nodes.items():\n        label = f"{role} tailscaled restart"','''    restarts = {}
    for arm, offset in [("C1",17.0),("C2",17.0)]:
        role, node = "worker", worker
        label = f"{arm} worker tailscaled restart"
        sync(coordinator,worker,arm,offset)''')
s=once(s,'        require(echo(nodes, run, 7444) != 0, f"{label}: control traffic crossed stopped link")','''        stopped = time.monotonic()
        mark("worker-stopped",phase=label)
        require(echo(nodes, run, 7444) != 0, f"{label}: control traffic crossed stopped link")''')
s=once(s,'        start = time.monotonic()\n        run("docker", "start", node["name"])','''        time.sleep(max(0, stopped+14.0-time.monotonic()))
        start = time.monotonic()
        mark("worker-start-request",phase=label,offline_seconds=start-stopped)
        run("docker", "start", node["name"])''')
s=once(s,'        ready = time.monotonic()\n        wait_for(label','        ready = time.monotonic()\n        mark("overlay-ready",phase=label)\n        wait_for(label')
s=once(s,'        restarts[role] =','        restarts[arm] =')
(D/'private_recovery.py').write_text(s)
for filename in ['status.py','phase.py','private_recovery.py','private-tailnet.py']:
 name=str(D/filename);compile(Path(name).read_bytes(),name,'exec')
