"""Three independent application identities using the private-tailnet harness's two disposable TUNs."""
import json
import os
import secrets
import subprocess
import tomllib


def run_bridge(work, network, wire_worker, wire_coordinator, ts_cli, binaries, image, run, start, await_ready):
    """A dials B over direct UDP. B forwards to C's real Tailscale IP."""
    nodes = {}
    for role in ("origin", "relay", "destination"):
        home = work / ("bridge-home-" + role)
        home.mkdir()
        env = {**os.environ, "HOME": str(home), "TOKIO_WORKER_THREADS": "2"}
        run(binaries / "entangle", "init", "--non-interactive", env=env)
        der = subprocess.check_output(["openssl", "pkey", "-in", home / ".entangle/identity.key",
                                      "-pubout", "-outform", "DER"], timeout=5)
        public = der[-32:].hex()
        run(binaries / "entangle", "keyring", "add", public, "--name", role, env=env)
        entries = tomllib.loads((home / ".entangle/keyring.toml").read_text())["entries"]
        peer = next(entry["fingerprint"] for entry in entries if entry["public_key"] == public)
        nodes[role] = dict(home=home, env=env, pub=public, peer=peer, app=network + "-bridge-" + role)

    origin, relay, dest = (nodes[role] for role in ("origin", "relay", "destination"))

    def cli(node, *args):
        return run(binaries / "entangle", *args, env=node["env"])

    for node in nodes.values():
        for role, other in nodes.items():
            if other is not node:
                cli(node, "mesh", "trust", other["peer"], "--public-key-hex", other["pub"], "--display-name", role)
    bridge_ip = run("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                    wire_coordinator["name"]).stdout.strip()
    bound = 'bind="0.0.0.0:7445"\nrelay=false\n'
    mapping = (f'[[scheduler.tailnet_peers]]\nnode_id="{wire_worker["id"]}"\n'
               f'public_key="{dest["pub"]}"\nport=7445\n')
    configs = {
        "origin": f'[mesh]\ntransports=["iroh"]\n[scheduler]\n{bound}peers=["{relay["pub"]}@{bridge_ip}:7445"]\n',
        "relay": ('[mesh]\ntransports=["iroh","tailscale"]\n[mesh.bridge]\nenabled=true\n'
                  'pairs=["iroh<->tailscale"]\nledger="/ent-home/budget.toml"\n[scheduler]\n' + bound + mapping),
        "destination": ('[mesh]\ntransports=["tailscale"]\n[mesh.bridge]\nreceive=true\n'
                        'ledger="/ent-home/budget.toml"\n[scheduler]\n' + bound),
    }
    for role, node in nodes.items():
        (node["home"] / ".entangle/config.toml").write_text(configs[role])
        if role != "origin":
            cli(node, "mesh", "bridge", "init", node["home"] / "budget.toml")
    payload = secrets.token_hex(32)
    for role, signer in [("origin", origin), ("destination", dest)]:
        cli(signer, "mesh", "bridge", "grant", "--via", relay["peer"], "--destination", dest["peer"],
            "--rate", "4096", "--total", str(len(payload)), "--ttl", "300",
            "--output", origin["home"] / (role + ".bsk"))
    (origin["home"] / "payload").write_text(payload)

    for role in ("destination", "relay", "origin"):
        node = nodes[role]
        ns = {"relay": wire_coordinator, "destination": wire_worker}.get(role)
        extra = []
        if ns:
            extra += ["-v", f'{ns["sock"]}:/var/run/tailscale', "-v", f"{ts_cli}:/usr/local/bin/tailscale:ro"]
        owner = run("docker", "run", "--rm", "--pull=never", "--network=none",
                    "-v", f'{node["home"]}:/ent-home:ro', image, "stat", "-c", "%u:%g", "/ent-home").stdout.strip()
        start(node["app"], "--network", ("container:" + ns["name"]) if ns else network,
              "--user", owner, "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
              "-e", "HOME=/ent-home", "-e", "TOKIO_WORKER_THREADS=2", "-v", f'{node["home"]}:/ent-home',
              "-v", f"{binaries}/entangle:/usr/local/bin/entangle:ro",
              "-v", f"{binaries}/entangled:/usr/local/bin/entangled:ro", *extra, image, "entangled", "run")
        await_ready(node["app"], "entangle", "mesh", "status", "--json")
    send = ["docker", "exec", origin["app"], "entangle", "mesh", "bridge", "send",
            "--via", relay["peer"], "--destination", dest["peer"], "--origin-grant", "/ent-home/origin.bsk",
            "--destination-grant", "/ent-home/destination.bsk", "--input", "/ent-home/payload"]
    run(*send)
    received = run("docker", "exec", dest["app"], "entangle", "mesh", "bridge", "read")
    if received.stdout != payload or not all(n["peer"] in received.stderr for n in [origin, relay]):
        raise RuntimeError("incorrect signed bridge payload/identity")
    denied = run(*send, check=False)
    if denied.returncode == 0 or "budget exhausted" not in denied.stderr:
        raise RuntimeError(f"bridge failed to reject exhausted cap: {denied.stderr}")
    empty = run("docker", "exec", dest["app"], "entangle", "mesh", "bridge", "read", check=False)
    if empty.returncode == 0 or "empty" not in empty.stderr:
        raise RuntimeError("receiver delivered a rejected second frame")
    return {"origin": origin["peer"], "bridge": relay["peer"], "destination": dest["peer"],
            "transport": "iroh<->tailscale", "bytes_delivered": len(payload), "exhausted": True}
