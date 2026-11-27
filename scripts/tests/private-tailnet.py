#!/usr/bin/env python3
"""Run the two-host acceptance check on a private Docker bridge and real TUN devices."""

import argparse
import json
import os
import secrets
import subprocess
import tempfile
import time
import tomllib
from contextlib import ExitStack
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
HEADSCALE = "headscale/headscale:0.27.1"
TAILSCALE = "tailscale/tailscale:v1.92.5"
APP = "python:3.12-slim-trixie"

CONTROL_CONFIG = """\
server_url: https://hs.test
listen_addr: 0.0.0.0:443
metrics_listen_addr: 127.0.0.1:9090
grpc_listen_addr: 127.0.0.1:50443
noise:
  private_key_path: /var/lib/headscale/noise_private.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential
derp:
  server:
    enabled: true
    region_id: 999
    region_code: local
    region_name: Private test relay
    stun_listen_addr: 0.0.0.0:3478
    private_key_path: /var/lib/headscale/derp.key
    automatically_add_embedded_derp_region: true
  urls: []
  paths: []
  auto_update_enabled: false
database:
  type: sqlite
  sqlite:
    path: /var/lib/headscale/db.sqlite
tls_cert_path: /etc/headscale/tls.crt
tls_key_path: /etc/headscale/tls.key
policy:
  mode: file
dns:
  magic_dns: false
  override_local_dns: false
  nameservers:
    global: []
log:
  level: warn
logtail:
  enabled: false
disable_check_updates: true
unix_socket: /var/run/headscale/headscale.sock
"""


def run(*args, data=None, env=None, check=True, timeout=30):
    result = subprocess.run(args, input=data, capture_output=True, text=True, env=env, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"{args[0]} exited {result.returncode}: {result.stderr.strip()}")
    return result


def await_ready(name, *command):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if run("docker", "inspect", "-f", "{{.State.Running}}", name).stdout.strip() != "true":
            raise RuntimeError(f"{name} exited: {run('docker', 'logs', name).stderr[-2000:]}")
        if run("docker", "exec", name, *command, check=False).returncode == 0:
            return
        time.sleep(0.25)
    raise RuntimeError(f"{name} did not become ready")


def run_check(work, cleanup, binaries, wasm, bridge=False, recovery=False):
    network = "entangle-wg-" + secrets.token_hex(6)
    control = network + "-control"
    certs = work / "control"
    certs.mkdir()
    config = CONTROL_CONFIG.replace("mode: file", "mode: database") if recovery else CONTROL_CONFIG
    (certs / "config.yaml").write_text(config)
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
        namespace = name
        network_args = ["--network", network, "--hostname", role]
        state = "mem:"
        if recovery:
            # Keep the application network namespace and node registration across sidecar restarts.
            namespace = name + "-ns"
            start(namespace, *network_args, "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                  APP, "sleep", "infinity")
            network_args = ["--network", "container:" + namespace]
            state = "/var/lib/tailscale/tailscaled.state"
        start(name, *network_args,
              "--device=/dev/net/tun", "--cap-add=NET_ADMIN", "--entrypoint", "tailscaled",
              "-v", f"{sock}:/var/run/tailscale", "-v", f"{certs}/tls.crt:/tmp/hs.crt:ro",
              "-e", "NO_PROXY=hs.test", "-e", "no_proxy=hs.test", "-e", "SSL_CERT_FILE=/tmp/hs.crt",
              TAILSCALE, "--state=" + state, "--no-logs-no-support", "--port=41641")
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
        nodes[role] = {"name": name, "namespace": namespace, "sock": sock, "id": status["Self"]["ID"], "addr": addr}
    worker = nodes["worker"]
    coordinator = nodes["coordinator"]
    ping = run("docker", "exec", coordinator["name"], "tailscale", "ping", "--c=5",
               "--until-direct=true", worker["addr"]).stdout
    if " via " not in ping or not any(" via " in s and "DERP(" not in s for s in ping.splitlines()):
        raise RuntimeError("Tailscale did not establish a direct WireGuard path")

    if recovery:
        from private_recovery import prepare_port_controls
        policy, cold_controls = prepare_port_controls(nodes, run, start, hs, certs, APP)
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
    if recovery:
        # These enrolled devices still exist in Headscale, but the kernel links must be absent at app launch.
        for node in nodes.values():
            run("docker", "stop", "-t", "4", node["name"])
    for role, node in nodes.items():
        other = coordinator if role == "worker" else worker
        cli(node, "mesh", "trust", other["peer"], "--public-key-hex", other["pub"], "--display-name", "test peer")
        config = '[mesh]\ntransports=["tailscale"]\nmulti_node=true\n[scheduler]\nbind="0.0.0.0:7443"\n'
        if role == "coordinator":
            config += f'[[scheduler.tailnet_peers]]\nnode_id="{worker["id"]}"\npublic_key="{worker["pub"]}"\nport=7443\n'
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
        if role == "worker":
            run("docker", "exec", app, "entangle", "plugins", "load", "/ent-home/package")

    if recovery:
        from private_recovery import check_recovery
        return check_recovery(nodes, run, policy, cold_controls, ping.strip().splitlines()[-1])

    snapshot = run("docker", "exec", worker["app"], "python3", "/tmp/check.py", "worker").stdout
    receipt = json.loads(run("docker", "exec", "-i", coordinator["app"], "python3", "/tmp/check.py",
                             "verify", data=snapshot, timeout=80).stdout)
    run("docker", "exec", worker["app"], "entangle", "mesh", "revoke", coordinator["peer"])
    rejected = run("docker", "exec", coordinator["app"], "entangle", "compute", "dispatch",
                   receipt["plugin_id"], "--cpu-cores", "0.01", "--input", "{}", check=False)
    if rejected.returncode == 0 or "not-authorized" not in rejected.stderr:
        raise RuntimeError(f"worker did not reject the revoked submitter: {rejected.stderr}")
    receipt.update(wireguard_path=ping.strip().splitlines()[-1], revocation="not-authorized")
    if bridge:
        from private_bridge import run_bridge
        receipt["bridge"] = run_bridge(work, network, worker, coordinator, ts_cli, binaries,
                                       APP, run, start, await_ready)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--recovery", action="store_true", help="test private ACLs, service restart, revocation and shutdown")
    mode.add_argument("--bridge", action="store_true", help="also test a three-node Iroh-to-WireGuard bridge")
    parser.add_argument("--bin-dir", type=Path, default=REPO / "target/release")
    parser.add_argument("--wasm", type=Path, default=REPO / "plugins/json-pointer/target/wasm32-wasip2/release/entangle_json_pointer.wasm")
    args = parser.parse_args()
    for path in [args.bin_dir / "entangle", args.bin_dir / "entangled", args.wasm]:
        if not path.is_file():
            parser.error(f"missing built artifact: {path}")
    for image in [HEADSCALE, TAILSCALE, APP]:
        if run("docker", "image", "inspect", image, check=False).returncode:
            parser.error(f"missing local image: {image}")
    with tempfile.TemporaryDirectory(prefix="entangle-private-tailnet-") as directory, ExitStack() as cleanup:
        receipt = run_check(Path(directory), cleanup, args.bin_dir.resolve(), args.wasm.resolve(), args.bridge, args.recovery)
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
