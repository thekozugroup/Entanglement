#!/usr/bin/env python3
"""Real ACL and transport outage on two disposable local kernel WireGuard namespaces."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import platform
import re
import secrets
import subprocess
import tempfile
import time
import tomllib
from contextlib import ExitStack
from pathlib import Path

REPO = Path(__file__).resolve().parents[5]
BASE = REPO / "scripts/tests/private-tailnet.py"
spec = importlib.util.spec_from_file_location("base_tailnet",BASE)
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
HEADSCALE,TAILSCALE,APP = base.HEADSCALE,base.TAILSCALE,base.APP
CONTROL_CONFIG,run,await_ready = base.CONTROL_CONFIG,base.run,base.await_ready
SOURCE = "sha256:2a5db79622c3130c68614ca443ad93b86efec77c11bb5b4e84f6ad7c02277c68"
COMMIT = "864ae27bf3fd08e9d9c62abd4f43ff7bfd4c68c2"


def require(condition, message):
    if not condition:
        raise RuntimeError(str(message))


def sha(path):
    with open(path,"rb") as f:
        return hashlib.file_digest(f,"sha256").hexdigest()


def millis(start):
    return round(1000*(time.monotonic()-start),3)


def wait(probe, limit):
    start=time.monotonic()
    while time.monotonic()-start < limit:
        value=probe()
        if value:
            return value
        time.sleep(.3)
    raise RuntimeError(f"condition failed to converge in {limit}s")


def stamp(binaries, wasm):
    check=lambda *args: subprocess.check_output(args,cwd=REPO,text=True).strip()
    head=check("git","rev-parse","HEAD")
    source=check("python3","scripts/production_score.py","--source-id")
    require(source==SOURCE,"working source differs from candidate")
    subprocess.run(["git","merge-base","--is-ancestor",COMMIT,head],cwd=REPO,check=True)
    expected=json.loads((Path(__file__).parent/"linux-archive.json").read_text())
    result={k:sha(binaries/k) for k in ("entangle","entangled")}
    require(expected["source_id"]==SOURCE and all(expected["files_sha256"][k]==v for k,v in result.items()),"different release artifacts")
    return dict(working_commit=head,source_id=source,candidate_commit=COMMIT,binary_sha256=result,
                wasm_sha256=sha(wasm),driver_sha256=sha(__file__),base_driver_sha256=sha(BASE))


def run_check(work, cleanup, binaries, wasm):
    network = "entangle-wg-" + secrets.token_hex(6)
    control = network + "-control"
    certs = work / "control"
    certs.mkdir()
    (certs / "config.yaml").write_text(CONTROL_CONFIG.replace("mode: file","mode: database"))
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-keyout", certs / "tls.key", "-out", certs / "tls.crt", "-subj", "/CN=hs.test",
        "-addext", "subjectAltName=DNS:hs.test")

    def start(name, *args):
        run("docker", "create", "--pull=never", "--name", name, *args)
        cleanup.callback(run, "docker", "rm", "-f", name, check=False)
        run("docker", "start", name)

    run("docker", "network", "create", "--internal", network)
    cleanup.callback(run, "docker", "network", "rm", network, check=False)
    start(control, "--network", network, "--network-alias", "hs.test",
          "-v", f"{certs}:/etc/headscale:ro", HEADSCALE, "serve")
    hs = ["docker", "exec", control, "/ko-app/headscale"]
    await_ready(control, "/ko-app/headscale", "users", "list")
    user = json.loads(run(*hs, "users", "create", "test-user", "-o", "json").stdout)

    nodes = {}
    for role in ("worker", "coordinator"):
        name = network + "-" + role
        sock = work / (role + "-sock")
        sock.mkdir()
        # The namespace must outlive tailscaled so the application keeps its real sockets
        # across a transport process restart. TUN access stays confined to the sidecar.
        namespace = name + "-ns"
        start(namespace, "--network", network, "--hostname", role, "--cap-drop", "ALL",
              "--security-opt", "no-new-privileges", APP, "sleep", "600")
        start(name, "--network", "container:"+namespace,
              "--device=/dev/net/tun", "--cap-add=NET_ADMIN", "--entrypoint", "tailscaled",
              "-v", f"{sock}:/var/run/tailscale", "-v", f"{certs}/tls.crt:/tmp/hs.crt:ro",
              "-e", "NO_PROXY=hs.test", "-e", "no_proxy=hs.test", "-e", "SSL_CERT_FILE=/tmp/hs.crt",
              TAILSCALE, "--state=/var/lib/tailscale/tailscaled.state", "--no-logs-no-support", "--port=41641")
        await_ready(name, "test", "-S", "/var/run/tailscale/tailscaled.sock")
        key = json.loads(run(*hs, "preauthkeys", "create", "-u", str(user["id"]), "-o", "json").stdout)["key"]
        run("docker", "exec", "-i", name, "sh", "-ec", "umask 077; cat >/tmp/register.key", data=key)
        ts = ["docker", "exec", name, "tailscale"]
        run(*ts, "up", "--login-server=https://hs.test", "--auth-key=file:/tmp/register.key",
            "--accept-dns=false", "--netfilter-mode=off", "--timeout=20s")
        status = json.loads(run(*ts, "status", "--json").stdout)
        addr = status["TailscaleIPs"][0]
        iface = run("docker", "exec", name, "ip", "-brief", "addr", "show", "tailscale0").stdout
        if addr + "/" not in iface:
            raise RuntimeError(f"{role}: missing kernel TUN address {addr}")
        nodes[role] = {"namespace": namespace,"name": name, "sock": sock, "id": status["Self"]["ID"], "addr": addr}
    worker = nodes["worker"]
    coordinator = nodes["coordinator"]
    ping = run("docker", "exec", coordinator["name"], "tailscale", "ping", "--c=5",
               "--until-direct=true", worker["addr"]).stdout
    if " via " not in ping or not any(" via " in s and "DERP(" not in s for s in ping.splitlines()):
        raise RuntimeError("Tailscale did not establish a direct WireGuard path")

    policies=[]
    policy_applied=[]
    def policy(allow_scheduler):
        ports=[7444]+([7443] if allow_scheduler else [])
        data={"acls":[{"action":"accept","proto":"udp","src":[coordinator["addr"]],
                       "dst":[f'{worker["addr"]}:{p}' for p in ports]}]}
        if allow_scheduler:
            data["acls"].append({"action":"accept","proto":"udp","src":[worker["addr"]],
                                 "dst":[f'{coordinator["addr"]}:7443']})
        path=certs/"entangle-policy.json"
        path.write_text(json.dumps(data))
        run(*hs,"policy","check","--file","/etc/headscale/entangle-policy.json")
        run(*hs,"policy","set","--file","/etc/headscale/entangle-policy.json","--force")
        readback=json.loads(run(*hs,"policy","get").stdout)
        require(readback==data,dict(requested=data,stored=readback))
        policies.append(data)
        start=time.monotonic()
        def applied():
            # Only retain packet filter port ranges for the synthetic devices. The
            # rest of the local Tailscale diagnostic response is never recorded.
            raw=run("docker","exec",worker["name"],"tailscale","debug","netmap").stdout
            rules=json.loads(raw).get("PacketFilter",[])
            ranges=[d["Ports"] for rule in rules if 17 in (rule.get("IPProto") or [])
                    and coordinator["addr"]+"/32" in (rule.get("Srcs") or [])
                    for d in rule.get("Dsts",[]) if d["Net"]==worker["addr"]+"/32"]
            permits=lambda port:any(r["First"]<=port<=r["Last"] for r in ranges)
            return ranges if permits(7444) and permits(7443)==allow_scheduler else None
        ranges=wait(applied,15)
        policy_applied.append({"allowed_ranges_on_worker":ranges,"control_ack_to_local_filter_ms":millis(start)})
        print("Headscale updated and read back allowed UDP ports",ports,flush=True)


    policy(False)
    # Use fresh UDP 5-tuples before application startup, demonstrating precisely
    # what the device policy allows at 7443 and at the neighboring control port.
    responder="""import select,socket,sys
socks=[]
for port in (7443,7444):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
 s.bind((sys.argv[1],port))
 socks.append(s)
while True:
 for s in select.select(socks,[],[],1)[0]:
  b,a=s.recvfrom(128)
  s.sendto(b,a)
"""
    probe="""import secrets,socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(.65)
n=secrets.token_bytes(24);target=(sys.argv[1],int(sys.argv[2]));s.sendto(n,target)
try: reply,addr=s.recvfrom(128)
except TimeoutError: sys.exit(8)
assert addr==target and n==reply
"""
    probe_node=network+"-port-check"
    start(probe_node,"--network","container:"+worker["namespace"],"--cap-drop","ALL","--security-opt",
          "no-new-privileges",APP,"python3","-c",responder,worker["addr"])
    def probe_port(port):
        return run("docker","exec",coordinator["namespace"],"python3","-c",probe,worker["addr"],str(port),check=False).returncode
    wait(lambda:probe_port(7444)==0,20)
    blocked=wait(lambda:probe_port(7443)==8,20)
    require(probe_port(7444)==0 and blocked,"port-specific ACL was not observed")
    ports_control={"worker":worker["addr"],"protocol":"udp","deny":{"7443":"no response","7444":"nonce echoed"}}
    policy(True)
    wait(lambda:probe_port(7443)==0 and probe_port(7444)==0,20)
    ports_control["allow"]={"7443":"nonce echoed","7444":"nonce echoed"}
    # Start the application after verifying the scheduler port is closed to new UDP requests.
    policy(False)
    require(wait(lambda:probe_port(7443)==8 and probe_port(7444)==0,20),"deny did not return")
    run("docker","stop","-t","1",probe_node)
    ts_cli = work / "tailscale"
    run("docker", "cp", worker["name"] + ":/usr/local/bin/tailscale", ts_cli)
    def cli(node, *args):
        return run(binaries / "entangle", *args, env={**os.environ, "HOME": str(node["home"]), "TOKIO_WORKER_THREADS": "2"})
    for role, node in nodes.items():
        home = work / (role + "-home")
        home.mkdir()
        node["home"] = home
        cli(node, "init", "--non-interactive")
        key_path = home / ".entangle/identity.key"
        der = subprocess.check_output(["openssl", "pkey", "-in", key_path, "-pubout", "-outform", "DER"], timeout=5)
        node["pub"] = der[-32:].hex()
        cli(node, "keyring", "add", node["pub"], "--name", "test publisher")
        entries = tomllib.loads((home / ".entangle/keyring.toml").read_text())["entries"]
        node["peer"] = next(e["fingerprint"] for e in entries if e["public_key"] == node["pub"])

    cli(worker, "plugins", "build", REPO / "plugins/json-pointer", "--wasm", wasm, "--out", worker["home"] / "package")
    for role, node in nodes.items():
        other = coordinator if role == "worker" else worker
        cli(node, "mesh", "trust", other["peer"], "--public-key-hex", other["pub"], "--display-name", "test peer")
        config = '[mesh]\ntransports=["tailscale"]\nmulti_node=true\n[scheduler]\nbind="0.0.0.0:7443"\n'
        if role == "coordinator":
            config += f'[[scheduler.tailnet_peers]]\nnode_id="{worker["id"]}"\npublic_key="{worker["pub"]}"\nport=7443\n'
        if role=="worker":
            config+='\n[runtime]\nplugins=["/ent-home/package"]\n'
        (node["home"] / ".entangle/config.toml").write_text(config)
        app = node["name"] + "-app"
        node["app"] = app
        # Rootless Docker can map host file ownership differently from the host's numeric UID.
        owner = run("docker", "run", "--rm", "--pull=never", "--network=none",
                    "-v", f'{node["home"]}:/home-check:ro', APP, "stat", "-c", "%u:%g", "/home-check").stdout.strip()
        start(app, "--network", "container:" + node["namespace"], "--user", owner,
              "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
              "-e", "HOME=/ent-home", "-e", "TOKIO_WORKER_THREADS=2",
              "-v", f'{node["home"]}:/ent-home', "-v", f'{node["sock"]}:/var/run/tailscale',
              "-v", f"{ts_cli}:/usr/local/bin/tailscale:ro", "-v", f"{binaries}/entangle:/usr/local/bin/entangle:ro",
              "-v", f"{binaries}/entangled:/usr/local/bin/entangled:ro",
              "-v", f"{REPO}/scripts/tests/tailnet-compute.py:/tmp/check.py:ro", APP, "entangled", "run")
        await_ready(app, "entangle", "mesh", "status", "--json")


    def app(node,*command,**kwargs):
        return run("docker","exec",node["app"],*command,**kwargs)

    def service(*command,check=True):
        return run("docker","exec",worker["name"],"tailscale",*command,check=check)

    def processes():
        return {n["peer"]:int(run("docker","inspect","-f","{{.State.Pid}}",n["app"]).stdout) for n in nodes.values()}

    initial_pids=processes()
    receipt=dict(initial_application_pids=initial_pids,topology="two Linux network namespaces on one Docker host",
                 network_internal=run("docker","network","inspect","-f","{{.Internal}}",network).stdout.strip()=="true",
                 wireguard_path=ping.strip().splitlines()[-1],worker_peer=worker["peer"],coordinator_peer=coordinator["peer"],
                 worker_ip=worker["addr"],coordinator_ip=coordinator["addr"],stable_tailscale_id=worker["id"],policy=policies,applied_policy=policy_applied,port_controls=ports_control,jobs=[])
    require(receipt["network_internal"],"network is not internal")

    # All application traffic uses the scheduler port. A second, unprivileged UDP
    # responder gives an independent same-peer/transport control for port-selective denial.
    echo_code="""import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind((sys.argv[1],7444))
while True:
 data,source=s.recvfrom(128)
 s.sendto(data,source)
"""
    run("docker","exec","-d",worker["namespace"],"python3","-c",echo_code,worker["addr"])
    probe_code="""import secrets,socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.settimeout(.65)
v=secrets.token_bytes(24)
s.sendto(v,(sys.argv[1],7444))
reply,addr=s.recvfrom(128)
assert reply==v and addr==(sys.argv[1],7444)
"""
    def echo():
        return app(coordinator,"python3","-c",probe_code,worker["addr"],check=False).returncode==0

    socket_info="""import json,os,socket
from pathlib import Path
fd_inodes=set()
for p in Path("/proc/1/fd").iterdir():
 try: fd_inodes.add(os.readlink(p))
 except OSError: pass
rows=[]
for name in ("udp","udp6"):
 for line in Path("/proc/net/"+name).read_text().splitlines()[1:]:
  words=line.split()
  ip,port=words[1].split(":")
  if int(port,16)!=7443: continue
  row={"table":name,"local_address_hex":ip,"port":7443,"fd_owned_by_daemon":("socket:["+words[9]+"]") in fd_inodes}
  if name=="udp": row["local_ip"]=socket.inet_ntoa(bytes.fromhex(ip)[::-1])
  rows.append(row)
print(json.dumps({"network_namespace":os.readlink("/proc/self/ns/net"),"tailscale0":Path("/sys/class/net/tailscale0").exists(),"socket_rows":rows}))
"""
    receipt["socket_observations"]=[]
    def socket_snapshot(phase):
        devices={}
        for role,node in nodes.items():
            d=json.loads(app(node,"python3","-c",socket_info).stdout)
            d["mesh_active"]=json.loads(app(node,"entangle","mesh","status","--json").stdout)["transports_active"]
            d["app_pid"]=int(run("docker","inspect","-f","{{.State.Pid}}",node["app"]).stdout)
            devices[role]=d
        receipt["socket_observations"].append({"phase":phase,"devices":devices})
    def warnings():
        events=[]
        for role,node in nodes.items():
            logs=run("docker","logs",node["app"])
            for line in (logs.stdout+"\n"+logs.stderr).splitlines():
                if "failed to rebind transports" not in line: continue
                try: value=json.loads(line)
                except ValueError: continue
                msg=value.get("fields",{}).get("message","")
                if "failed to rebind transports" in msg:
                    events.append(dict(role=role,timestamp=value["timestamp"],target=value["target"],message=msg))
        return events

    def wasm_count():
        metrics=app(worker,"entangle","metrics").stdout
        return sum(int(n) for n in re.findall(r"(?m)^entangle_wasm_invocation_seconds_count\{[^}]*\} (\d+)$",metrics))

    snapshot=json.loads(app(worker,"python3","/tmp/check.py","worker").stdout)
    require(snapshot["peer_id"]==worker["peer"] and snapshot["node_id"]==worker["id"],"mixed worker identity")
    # Local RPC timeout is longer than the application's own deadline. A wrapper process
    # timing out is an observation failure, never an accepted application rejection.
    rpc_code="""import json,socket,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
s.settimeout(16)
s.connect("/ent-home/.entangle/sock")
s.sendall(json.dumps({"jsonrpc":"2.0","id":1,"method":"compute/dispatch","params":json.loads(sys.argv[1])}).encode()+b"\\n")
with s.makefile("rb") as f:
 response=json.loads(f.readline(1024*1024))
 assert response["id"]==1 and response["jsonrpc"]=="2.0"
 print(json.dumps(response))
"""
    def dispatch(label):
        nonce=secrets.token_hex(16)
        query=json.dumps({"data":{"challenge":nonce},"pointer":"/challenge"}).encode()
        request=dict(plugin_id=snapshot["plugin_id"],input=list(query),timeout_ms=1000,cpu_cores=.01,memory_bytes=0,
                     gpu_required=False,gpu_vram_min_bytes=0,integrity={"kind":"trusted-executor","allowlist":[worker["peer"]]})
        count_before=wasm_count()
        start=time.monotonic()
        ans=json.loads(app(coordinator,"python3","-c",rpc_code,json.dumps(request),timeout=19).stdout)
        event=dict(phase=label,elapsed_ms=millis(start),worker_completed_before=count_before,worker_completed_after=wasm_count())
        if "result" in ans:
            reply=ans["result"]
            require(reply["chosen_peer"]==worker["peer"] and json.loads(bytes(reply["output"]))==nonce,"wrong worker or bytes")
            require(event["worker_completed_after"]==count_before+1,"worker invocation not attributed")
            event.update(chosen_peer=reply["chosen_peer"],nonce=nonce,input_json=query.decode(),
                         returned_output_utf8=bytes(reply["output"]).decode(),verified_json_output=json.loads(bytes(reply["output"])))
        else:
            require(ans["error"]["code"]==-32000 and event["worker_completed_after"]==count_before,str(ans))
            require(event["elapsed_ms"]<15500,"application did not return within bounded test deadline")
            event["rpc_error"]=ans["error"]
        receipt["jobs"].append(event)
        print(label,event.get("rpc_error",{}).get("message","verified remote output"),event["elapsed_ms"],flush=True)
        return event

    def successful(label):
        return wait(lambda: (v if "chosen_peer" in (v:=dispatch(label)) else None),55)

    def denial(label):
        v=dispatch(label)
        if "rpc_error" not in v:
            return None
        msg=v["rpc_error"]["message"]
        require(any(s in msg for s in ["no answer within","no live workers","no known network address","timed out","connection lost","connection refused","endpoint closed","not-authorized"]),msg)
        return v

    v=denial("scheduler-blocked-by-initial-port-policy")
    require(v and echo() and "not-authorized" not in v["rpc_error"]["message"],"scheduler work was not refused under initial policy")
    start=time.monotonic()
    policy(True)
    baseline=json.loads(run("docker","exec","-i",coordinator["app"],"python3","/tmp/check.py","verify",
                            data=json.dumps(snapshot),timeout=80).stdout)
    require(baseline["chosen_peer"]==worker["peer"] and re.fullmatch(r"[0-9a-f]{32}",baseline["verified_output"]),"wrong baseline")
    receipt["documented_compute_check"]=baseline

    receipt["acl_restore_to_verified_job_ms"]=millis(start)
    successful("allow-7443")
    receipt["adjacent_udp_echo_while_scheduler_denied"]=True

    socket_snapshot("before-service-stop")
    old_ts_pid=int(run("docker","inspect","-f","{{.State.Pid}}",worker["name"]).stdout)
    run("docker","stop","-t","4",worker["name"])
    require(not echo(),"UDP echo unexpectedly crossed the stopped worker transport")
    require(not app(worker,"python3","-c","from pathlib import Path;assert not Path('/sys/class/net/tailscale0').exists()",check=False).returncode,
            "the worker's kernel WireGuard interface was still present")
    socket_snapshot("transport-stopped")
    v=denial("worker-tailscaled-stopped")
    require(v and "not-authorized" not in v["rpc_error"]["message"],"partition did not deny compute")
    start=time.monotonic()
    run("docker","start",worker["name"])
    await_ready(worker["name"],"test","-S","/var/run/tailscale/tailscaled.sock")
    wait(echo,30)
    now=json.loads(service("status","--json").stdout)
    new_ts_pid=int(run("docker","inspect","-f","{{.State.Pid}}",worker["name"]).stdout)
    require(new_ts_pid!=old_ts_pid and now["Self"]["ID"]==worker["id"] and worker["addr"] in now["TailscaleIPs"],"worker service identity or restart mismatch")
    socket_snapshot("service-running-echo-restored")
    def restore_application(label):
        start=time.monotonic()
        try:
            successful(label)
            return {"automatic":True,"to_verified_job_ms":millis(start),"application_restarts":[]}
        except RuntimeError as err:
            if not str(err).startswith("condition failed to converge"):
                raise
        observed=millis(start)
        socket_snapshot(label+"-automatic-deadline")
        actions=[]
        for role,node in (("worker",worker),("coordinator",coordinator)):
            app_start=time.monotonic()
            run("docker","restart","-t","3",node["app"])
            await_ready(node["app"],"entangle","mesh","status","--json")
            actions.append(role)
            socket_snapshot(label+"-after-restart-"+role)
            try:
                successful(label+"-after-app-restart-"+role)
            except RuntimeError as err:
                if not str(err).startswith("condition failed to converge"):
                    raise
                continue
            return {"automatic":False,"automatic_observation_ms":observed,"to_verified_job_ms":millis(start),
                    "last_app_restart_to_verified_job_ms":millis(app_start),"application_restarts":actions}
        raise RuntimeError("no verified workload after both application restarts")
    recovery=restore_application("transport-service-restarted")
    receipt["transport_restart"]=dict(old_pid=old_ts_pid,new_pid=new_ts_pid,
                                      stable_tailscale_id=now["Self"]["ID"],recovery=recovery,
                                      restart_to_verified_job_ms=millis(start))

    # A second down/up tests freshness of application authorization across the partition.
    service("down")
    socket_snapshot("tailscale-down")
    require(not echo(),"UDP echo crossed tailscale down")
    app(worker,"entangle","mesh","revoke",coordinator["peer"])
    start=time.monotonic()
    service("up","--timeout=20s","--accept-dns=false","--login-server=https://hs.test","--netfilter-mode=off")
    wait(echo,30)
    denied=denial("link-up-after-entanglement-revocation")
    require(denied,"a revoked identity executed work after transport return")
    receipt["link_up_to_refused_job_ms"]=millis(start)
    receipt["explicit_worker_rejection_on_reconnect"]="not-authorized" in denied["rpc_error"]["message"]
    app(worker,"entangle","mesh","trust",coordinator["peer"],"--public-key-hex",coordinator["pub"],"--display-name","coordinator")
    receipt["later_trust_recovery"]=restore_application("operator-repaired-trust")
    socket_snapshot("final-recovered")
    receipt["rebind_warnings"]=warnings()
    receipt["final_application_pids"]=processes()
    return receipt


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir",type=Path,default=REPO/"target/release")
    parser.add_argument("--wasm",type=Path,default=REPO/"plugins/json-pointer/target/wasm32-wasip2/release/entangle_json_pointer.wasm")
    parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args()
    bins=args.bin_dir.resolve()
    wasm=args.wasm.resolve()
    before=stamp(bins,wasm)
    started=datetime.datetime.now(datetime.timezone.utc).isoformat()
    images={image:run("docker","image","inspect","--format","{{index .RepoDigests 0}}",image).stdout.strip() for image in (APP,TAILSCALE,HEADSCALE)}
    with tempfile.TemporaryDirectory(prefix="ent-acl-") as root, ExitStack() as clean:
        measurements=run_check(Path(root),clean,bins,wasm)
    after=stamp(bins,wasm)
    require(before==after,"source or artifact changed")
    out=dict(before=before,after=after,started_utc=started,finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
             images=images,scope="one Linux host; two real kernel Tailscale namespaces; disposable private Headscale; no external tailnet",
             platform=platform.platform(),measurements=measurements)
    args.out.write_text(json.dumps(out,indent=2)+"\n")
    print("Receipt SHA-256",sha(args.out))


if __name__=="__main__":
    main()
