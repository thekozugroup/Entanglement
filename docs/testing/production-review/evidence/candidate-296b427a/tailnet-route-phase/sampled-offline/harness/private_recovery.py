"""Opt-in black-box recovery cases for private-tailnet.py's disposable devices."""

import json
import re
from phase import mark, sync
import secrets
import sys
import time


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def wait_for(label, probe, seconds):
    start = time.monotonic()
    while time.monotonic() - start < seconds:
        result = probe()
        if result and time.monotonic() - start <= seconds:
            return result
        time.sleep(0.25)
    raise RuntimeError(f"{label} did not converge within {seconds}s")


# The responder in the worker namespace is independent of the application and tailscaled.
ECHO_SERVER = """
import select, socket, sys
sockets = []
for port in sys.argv[2:]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((sys.argv[1], int(port)))
    sockets.append(sock)
while True:
    for sock in select.select(sockets, [], [])[0]:
        data, source = sock.recvfrom(128)
        sock.sendto(data, source)
"""

ECHO_CLIENT = """
import secrets, socket, sys
target = (sys.argv[1], int(sys.argv[2]))
nonce = secrets.token_bytes(24)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(0.6)
    try:
        sock.sendto(nonce, target)
        reply, source = sock.recvfrom(128)
    except TimeoutError:
        sys.exit(8)
    except OSError:
        sys.exit(9)
    if reply != nonce or source != target:
        sys.exit(10)
"""


def echo(nodes, run, port):
    result = run("docker", "exec", nodes["coordinator"]["namespace"], "python3", "-c", ECHO_CLIENT,
                 nodes["worker"]["addr"], str(port), check=False, timeout=3)
    require(result.returncode in {0, 8, 9}, f"unexpected UDP response or probe failure: {result.stderr}")
    return result.returncode


def prepare_port_controls(nodes, run, start, hs, certs, image):
    worker, coordinator = nodes["worker"], nodes["coordinator"]
    source, destination = coordinator["addr"], worker["addr"]
    path = certs / "recovery-policy.json"

    def policy(allow):
        ports = (7443, 7444) if allow else (7444,)
        rules = [{"action": "accept", "proto": "udp", "src": [source],
                  "dst": [f"{destination}:{port}" for port in ports]}]
        if allow:
            rules.append({"action": "accept", "proto": "udp", "src": [destination],
                          "dst": [f"{source}:7443"]})
        document = {"acls": rules}
        path.write_text(json.dumps(document))
        for operation in ("check", "set"):
            flags = ["--force"] if operation == "set" else []
            run(*hs, "policy", operation, "--file", "/etc/headscale/" + path.name, *flags)
        require(json.loads(run(*hs, "policy", "get").stdout) == document, "Headscale policy differs")

        def applied():
            status = run("docker", "exec", worker["name"], "tailscale", "debug", "netmap")
            ranges = [dst["Ports"] for rule in json.loads(status.stdout).get("PacketFilter", [])
                      if 17 in (rule.get("IPProto") or []) and source + "/32" in (rule.get("Srcs") or [])
                      for dst in rule.get("Dsts", []) if dst["Net"] == destination + "/32"]
            def permits(port):
                return any(r["First"] <= port <= r["Last"] for r in ranges)
            return permits(7444) and permits(7443) == allow

        wait_for("device packet filter", applied, 15)

    def serve(name, *ports):
        start(name, "--network", "container:" + worker["namespace"], "--cap-drop", "ALL",
              "--security-opt", "no-new-privileges", image, "python3", "-c", ECHO_SERVER,
              destination, *map(str, ports))

    name = worker["name"] + "-cold"
    serve(name, 7443)
    serve(worker["name"] + "-echo", 7444)
    observations = []
    for allow in (False, True, False):
        policy(allow)
        # A valid response on the adjacent port distinguishes a selective drop from no route.
        expected = 0 if allow else 8
        wait_for("cold scheduler and adjacent UDP ports",
                 lambda: echo(nodes, run, 7444) == 0 and echo(nodes, run, 7443) == expected, 10)
        observations.append({"7443": "nonce echoed" if allow else "timeout", "7444": "nonce echoed"})
    run("docker", "stop", "-t", "1", name)
    return policy, observations


BOUND_ENDPOINT = """
import os, socket, sys
with open("/proc/net/udp") as table:
    endpoints = [line.split()[1] for line in table.readlines()[1:]]
address = socket.inet_aton(sys.argv[1])[::-1].hex().upper() + ":1D13"
if address not in endpoints:
    sys.exit("expected Tailscale scheduler UDP socket absent at " + sys.argv[1] + ":7443")
print(os.readlink("/proc/self/ns/net"))
"""


OFFLINE_ENDPOINT = """
from pathlib import Path
if Path("/sys/class/net/tailscale0").exists():
    raise RuntimeError("unexpected TUN during cold boot")
for path in ("/proc/net/udp", "/proc/net/udp6"):
    if any(line.split()[1].endswith(":1D13") for line in Path(path).read_text().splitlines()[1:]):
        raise RuntimeError("scheduler bound port 7443 while Tailscale was unavailable")
"""


def check_recovery(nodes, run, policy, cold_controls, direct_path):
    worker, coordinator = nodes["worker"], nodes["coordinator"]

    def app(node, *args, **kwargs):
        return run("docker", "exec", node["app"], "entangle", *args, **kwargs)

    def pid(name):
        return int(run("docker", "inspect", "-f", "{{.State.Pid}}", name).stdout)

    def identities():
        result = {}
        for role, node in nodes.items():
            status = json.loads(run("docker", "exec", node["name"], "tailscale", "status", "--json").stdout)
            mesh = json.loads(app(node, "mesh", "status", "--json").stdout)
            require(status["Self"]["ID"] == node["id"] and node["addr"] in status["TailscaleIPs"],
                    f"{role} changed Tailscale identity or address")
            require(mesh["local_peer_id"] == node["peer"] and mesh["transports_active"] == ["tailscale"],
                    f"{role} changed Entanglement peer or active transport: {mesh}")
            namespace = run("docker", "exec", node["app"], "python3", "-c", BOUND_ENDPOINT, node["addr"]).stdout.strip()
            result[role] = {"pid": pid(node["app"]), "network_namespace": namespace, "peer": node["peer"], "public_key": node["pub"],
                            "tailscale_id": node["id"], "address": node["addr"], "scheduler_port": 7443}
        return result

    plugin = worker["peer"] + "/json-pointer@0.1.0"
    events = []

    def dispatch(label):
        nonce = secrets.token_hex(16)
        payload = json.dumps({"data": {"value": nonce}, "pointer": "/value"})
        attempt_begin = time.monotonic()
        result = app(coordinator, "compute", "dispatch", plugin, "--input", payload,
                     "--cpu-cores", "0.01", "--timeout-ms", "1000", "--raw", "--integrity",
                     "trusted-executor", "--allow", worker["peer"], timeout=16, check=False)
        mark("dispatch",phase=label,begin=attempt_begin,rc=result.returncode,
             reason=("no-route" if "no known network address" in result.stderr else
                     "no-workers" if "no live workers" in result.stderr else
                     "transport-timeout" if "no answer within" in result.stderr else
                     "refused" if "not-authorized" in result.stderr else
                     "ok" if not result.returncode else "other"),nonce=nonce)
        if result.returncode:
            require(not result.stdout, f"{label}: unsuccessful dispatch produced output")
            print(f"{label}: {result.stderr.strip()}", file=sys.stderr, flush=True)
        else:
            chosen = re.search(r"^Chosen: ([0-9a-f]+) ", result.stderr, re.M)
            require(chosen and chosen[1] == worker["peer"],
                    f"{label}: unexpected worker {result.stderr}")
            require(result.stdout == json.dumps(nonce), f"{label}: wrong remote output")
            events.append({"phase": label, "chosen_peer": worker["peer"], "nonce": nonce, "output": result.stdout})
        return result

    def allowed(label):
        result = dispatch(label)
        if result.returncode:
            require("not-authorized" not in result.stderr, f"{label}: trusted identity refused")
        return result.returncode == 0

    def worker_count():
        metrics = app(worker, "metrics").stdout
        return sum(map(int, re.findall(r"^entangle_wasm_invocation_seconds_count\{[^}]*\} (\d+)$", metrics, re.M)))

    offline = {}
    for role, node in nodes.items():
        mesh = json.loads(app(node, "mesh", "status", "--json").stdout)
        require(mesh["local_peer_id"] == node["peer"] and mesh["transports_active"] == [],
                f"{role}: inactive local daemon identity missing: {mesh}")
        run("docker", "exec", node["app"], "python3", "-c", OFFLINE_ENDPOINT)
        offline[role] = {"pid": pid(node["app"]), "peer": mesh["local_peer_id"],
                         "active_transports": mesh["transports_active"], "bound_udp_7443": False}
    isolated = dispatch("cold boot without either Tailscale service")
    require(isolated.returncode and worker_count() == 0 and echo(nodes, run, 7444) != 0,
            "unexpected network or work while both transports were offline")
    boot = time.monotonic()
    for node in nodes.values():
        run("docker", "start", node["name"])
    wait_for("cold boot UDP control path", lambda: echo(nodes, run, 7444) == 0, 30)
    policy(False)
    wait_for("cold boot active status", lambda: all(
        json.loads(app(n, "mesh", "status", "--json").stdout)["transports_active"] == ["tailscale"]
        for n in nodes.values()), 45)
    initial = identities()
    for role in nodes:
        require(offline[role]["pid"] == initial[role]["pid"] and offline[role]["peer"] == initial[role]["peer"],
                f"{role}: application restarted or changed identities after cold boot")
    snapshot = json.loads(run("docker", "exec", worker["app"], "python3", "/tmp/check.py", "worker").stdout)
    require((snapshot["peer_id"], snapshot["node_id"], snapshot["plugin_id"]) ==
            (worker["peer"], worker["id"], plugin), "worker published wrong identity, device or signed plugin")
    cold = dispatch("scheduler port denied")
    require(cold.returncode and ("no live workers" in cold.stderr or "ENTANGLE-E0402" in cold.stderr)
            and worker_count() == 0, "cold ACL did not block the first dispatch")
    policy(True)
    wait_for("initial authenticated dispatch", lambda: allowed("scheduler port allowed"), 45)
    require(worker_count() == 1, "initial successful task was not executed at the worker")
    boot_to_output = round(time.monotonic() - boot, 3)
    restarts = {}
    for arm, offset in [("C1",17.0),("C2",17.0)]:
        role, node = "worker", worker
        label = f"{arm} worker tailscaled restart"
        sync(coordinator,worker,arm,offset)
        old_pid = pid(node["name"])
        run("docker", "stop", "-t", "4", node["name"])
        stopped = time.monotonic()
        mark("worker-stopped",phase=label)
        require(echo(nodes, run, 7444) != 0, f"{label}: control traffic crossed stopped link")
        previous = worker_count()
        outage = dispatch(label + " offline")
        require(outage.returncode and worker_count() == previous, f"{label}: ran while disconnected")
        time.sleep(max(0, stopped+14.0-time.monotonic()))
        start = time.monotonic()
        mark("worker-start-request",phase=label,offline_seconds=start-stopped)
        run("docker", "start", node["name"])
        wait_for("adjacent UDP after " + label, lambda: echo(nodes, run, 7444) == 0, 30)
        ready = time.monotonic()
        mark("overlay-ready",phase=label)
        wait_for(label, lambda: allowed(label), 45)
        elapsed = time.monotonic() - ready
        require(worker_count() == previous + 1, f"{label}: recovered job did not execute exactly once")
        new_pid = pid(node["name"])
        require(old_pid != new_pid and identities() == initial, f"{label}: fixture/application identity changed")
        restarts[arm] = {"old_tailscaled_pid": old_pid, "new_tailscaled_pid": new_pid,
                          "to_overlay_s": round(ready - start, 3), "overlay_to_job_s": round(elapsed, 3)}

    ts = ["docker", "exec", worker["name"], "tailscale"]
    run(*ts, "down")
    require(echo(nodes, run, 7444) != 0, "control traffic crossed the disabled worker link")
    app(worker, "mesh", "revoke", coordinator["peer"])
    previous = worker_count()
    run(*ts, "up", "--accept-dns=false", "--login-server=https://hs.test", "--netfilter-mode=off", "--timeout=20s")
    wait_for("reconnected overlay", lambda: echo(nodes, run, 7444) == 0, 30)

    def rejected():
        result = dispatch("revoked during disconnect")
        require(result.returncode and worker_count() == previous, "revoked submitter ran work")
        return "ENTANGLE-E0403" in result.stderr and "not-authorized" in result.stderr and worker["peer"] in result.stderr

    wait_for("explicit authenticated worker rejection", rejected, 45)
    app(worker, "mesh", "trust", coordinator["peer"], "--public-key-hex", coordinator["pub"],
        "--display-name", "reconnected coordinator")
    wait_for("repaired trust", lambda: allowed("repaired trust"), 45)
    require(identities() == initial, "Entanglement identity, PID or tailnet route changed")
    shutdown = {}
    for role, node in nodes.items():
        start = time.monotonic()
        run("docker", "kill", "--signal=TERM", node["app"])
        status = run("docker", "wait", node["app"], timeout=10).stdout.strip()
        require(status == "0" and pid(node["app"]) == 0, f"{role}: expected clean SIGTERM exit, got {status}")
        shutdown[role] = {"exit_code": 0, "elapsed_s": round(time.monotonic() - start, 3)}
    return {"cold_boot": {"offline": offline, "service_start_to_job_s": boot_to_output},
            "wireguard_path": direct_path, "cold_udp": cold_controls, "identities": initial,
            "transport_restarts": restarts, "jobs": events, "revoked_worker_refusal": "ENTANGLE-E0403",
            "shutdown": shutdown}
