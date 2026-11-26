#!/usr/bin/env python3
"""Verify cross-host compute on two already paired, Tailscale-only daemons."""

import argparse
import json
import re
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path


class CheckFailed(Exception):
    pass


class RpcFailure(CheckFailed):
    pass


def require(condition, message):
    if not condition:
        raise CheckFailed(message)


def rpc(method, params=None):
    path = Path.home() / ".entangle" / "sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(10)
        sock.connect(str(path))
        request = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        sock.sendall(json.dumps(request).encode() + b"\n")
        with sock.makefile("rb") as stream:
            line = stream.readline(1024 * 1024)
    require(line.endswith(b"\n"), "daemon returned an incomplete or oversized response")
    reply = json.loads(line)
    require(reply.get("id") == 1 and reply.get("jsonrpc") == "2.0", "unexpected RPC response envelope")
    if "error" in reply:
        raise RpcFailure(f"{method}: {reply['error']['message']}")
    return reply["result"]


def snapshot():
    mesh = rpc("mesh/status")
    require(mesh["transports_active"] == ["tailscale"], "daemon must have only Tailscale active")
    status = subprocess.run(
        ["tailscale", "status", "--json"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=5, check=True,
    )
    tailnet = json.loads(status.stdout)
    local = tailnet.get("Self") or {}
    require(tailnet["BackendState"] == "Running" and local.get("Online"),
            "local Tailscale backend must be running and online")
    require(local.get("ID"), "local Tailscale stable node ID unavailable")
    return mesh["local_peer_id"], local["ID"], tailnet.get("Peer") or {}


def worker_snapshot():
    peer, node, _ = snapshot()
    plugins = rpc("plugins/list")["plugins"]
    candidates = [p for p in plugins if re.fullmatch(r"[a-f0-9]{32}/json-pointer@0\.1\.0", p)]
    require(len(candidates) == 1, "worker must have exactly one signed json-pointer@0.1.0 loaded")
    return {"peer_id": peer, "node_id": node, "plugin_id": candidates[0]}


def verify(worker):
    local_peer, local_node, visible = snapshot()
    require(re.fullmatch(r"[a-f0-9]{32}", worker["peer_id"]), "invalid worker peer ID")
    require(re.fullmatch(r"[a-f0-9]{32}/json-pointer@0\.1\.0", worker["plugin_id"]),
            "worker supplied an unexpected plugin ID")
    require(worker["peer_id"] != local_peer and worker["node_id"] != local_node,
            "worker and coordinator must have distinct Entanglement and Tailscale identities")
    require(any(p["ID"] == worker["node_id"] and p.get("Online") for p in visible.values()),
            "worker's stable Tailscale ID is not online in coordinator's network map")
    require(worker["plugin_id"] not in rpc("plugins/list")["plugins"],
            "the test plugin must be loaded only on the worker")
    nonce = secrets.token_hex(16)
    payload = json.dumps({"data": {"acceptance": nonce}, "pointer": "/acceptance"}).encode()
    params = {
        "plugin_id": worker["plugin_id"], "input": list(payload), "timeout_ms": 5000,
        "cpu_cores": 0.01, "memory_bytes": 0, "gpu_required": False,
        "gpu_vram_min_bytes": 0, "integrity": {"kind": "trusted-executor", "allowlist": [worker["peer_id"]]},
    }
    # The coordinator can start before its first authenticated inventory poll.
    deadline = time.monotonic() + 60
    while True:
        try:
            result = rpc("compute/dispatch", params)
            break
        except RpcFailure as error:
            if "no live workers" not in str(error) or time.monotonic() >= deadline:
                raise
            time.sleep(1)
    require(result["chosen_peer"] == worker["peer_id"], "unexpected executor identity")
    require(json.loads(bytes(result["output"])) == nonce, "remote JSON Pointer output mismatch")
    return {"transport": "tailscale", "chosen_peer": result["chosen_peer"],
            "plugin_id": worker["plugin_id"], "verified_output": nonce}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=["worker", "verify"],
                        help="emit the worker's public snapshot or verify it on the coordinator")
    role = parser.parse_args().role
    if role == "worker":
        result = worker_snapshot()
    else:
        data = sys.stdin.buffer.read(8193)
        require(len(data) <= 8192, "worker snapshot exceeded 8 KiB")
        result = verify(json.loads(data))
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except (CheckFailed, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        sys.exit(f"Acceptance check failed: {error}")
