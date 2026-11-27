#!/usr/bin/env python3
"""Behavioral evidence only. Run against prebuilt release binaries from the frozen source."""
import argparse
import contextlib
import datetime
import hashlib
import json
import os
import platform
import re
import secrets
import socket
import subprocess
import tempfile
import time
import tomllib
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[5]
SOURCE = "sha256:d4bac68175f75abfc6b42773658c9022fd822051ffd1d6b38a58ab78df8c7281"
COMMIT = "761485d7490a56c7215ad958db81949204c74245"


def require(test, reason):
    if not test:
        raise RuntimeError(reason)


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def facts(bins):
    out = lambda *args: subprocess.check_output(args, cwd=REPO, text=True).strip()
    f = {"commit": out("git", "rev-parse", "HEAD"), "source_id": out("python3", "scripts/production_score.py", "--source-id"),
         "binary_sha256": {n: sha(bins / n) for n in ["entangle", "entangled"]},
         "driver_sha256": sha(Path(__file__)), "host": platform.platform(), "utc": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    require((f["commit"], f["source_id"]) == (COMMIT, SOURCE), "working source is not the frozen candidate")
    return f


def wait_until(action, seconds=12):
    deadline = time.monotonic() + seconds
    while True:
        try:
            return action()
        except (FileNotFoundError, ConnectionRefusedError, RuntimeError) as err:
            if time.monotonic() >= deadline:
                raise RuntimeError(f"condition failed after {seconds}s: {err}") from err
            time.sleep(.05)


class Node:
    def __init__(self, bins, root, name):
        self.home = root / name
        self.home.mkdir(mode=0o700)
        self.state = self.home / ".entangle"
        self.name, self.bins, self.proc, self.packages = name, bins, None, []
        self.env = {**os.environ, "HOME": str(self.home), "TOKIO_WORKER_THREADS": "2",
                    "RAYON_NUM_THREADS": "2", "ENTANGLE_ALLOW_LOCAL": "0", "RUST_LOG": "entangle_scheduler=warn,entangle_bin=warn"}
        self.cli("init", "--non-interactive")
        self.public = subprocess.check_output(["openssl", "pkey", "-in", str(self.state / "identity.key"),
                                               "-pubout", "-outform", "DER"])[-32:].hex()
        self.cli("keyring", "add", self.public, "--name", "local acceptance publisher")
        self.peer = tomllib.loads((self.state / "keyring.toml").read_text())["entries"][0]["fingerprint"]
        self.port = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.port.bind(("127.0.0.1", 0))
        self.address = "127.0.0.1:" + str(self.port.getsockname()[1])

    def cli(self, *args):
        cmd = [str(self.bins / "entangle"), *map(str, args)]
        r = subprocess.run(cmd, env=self.env, capture_output=True, timeout=20)
        require(r.returncode == 0, f"{args}: {r.stderr.decode()}")
        return r.stdout.decode()

    def package(self, example, fixture):
        dest = self.home / example
        self.cli("plugins", "build", REPO / "examples" / example, "--wasm",
                 REPO / "crates/entangle-host/tests/fixtures" / fixture, "--out", dest)
        self.packages.append(str(dest))
        return tomllib.loads((dest / "entangle.toml").read_text())["plugin"]["id"]

    def pair(self, other):
        self.cli("mesh", "trust", other.peer, "--public-key-hex", other.public, "--display-name", other.name)

    def configure(self, others):
        routes = [f"{n.public}@{n.address}" for n in others]
        (self.state / "config.toml").write_text(
            '[mesh]\ntransports=["iroh"]\nmulti_node=true\n[scheduler]\nrelay=false\n'
            + f'bind="{self.address}"\npeers={json.dumps(routes)}\n[runtime]\nplugins={json.dumps(self.packages)}\n')

    def start(self):
        self.port.close()
        with (self.home / "daemon.log").open("ab") as log:
            self.proc = subprocess.Popen([self.bins / "entangled", "run"], cwd=REPO, env=self.env, stdout=log, stderr=log)

        def started():
            require(self.proc.poll() is None, "daemon exited: " + (self.home / "daemon.log").read_text()[-800:])
            state = self.rpc("mesh/status")["result"]
            require(state["local_peer_id"] == self.peer and state["transports_active"] == ["iroh"], str(state))
        wait_until(started)

    def stop(self):
        self.port.close()
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait(timeout=10)

    def rpc(self, method, params=None):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(8)
            sock.connect(str(self.state / "sock"))
            sock.sendall(json.dumps(dict(jsonrpc="2.0", id=1, method=method, params=params)).encode() + b"\n")
            with sock.makefile("rb") as line:
                ans = json.loads(line.readline(1024 * 1024))
                require(ans["id"] == 1 and ans["jsonrpc"] == "2.0", "invalid JSON-RPC reply")
                return ans


def call(src, dst, label, positive=False):
    nonce = secrets.token_hex(12)
    params = dict(plugin_id=dst.hello, input=list(nonce.encode()), timeout_ms=1500, cpu_cores=.01,
                  memory_bytes=0, gpu_required=False, gpu_vram_min_bytes=0,
                  integrity={"kind": "trusted-executor", "allowlist": [dst.peer]})
    def invocations():
        text = dst.rpc("metrics")["result"]
        return sum(int(n) for n in re.findall(r"(?m)^entangle_wasm_invocation_seconds_count\{[^}]*\} (\d+)$", text))
    count_before = invocations()
    start = time.monotonic()
    r = src.rpc("compute/dispatch", params)
    elapsed = round(1000 * (time.monotonic() - start), 3)
    fact = dict(state=label, source=src.name, target=dst.name, source_pid=src.proc.pid,
                target_pid=dst.proc.pid, method="compute/dispatch", params=params, elapsed_ms=elapsed,
                worker_wasm_completions_before=count_before, worker_wasm_completions_after=invocations())
    require(src.proc.poll() is None and dst.proc.poll() is None, "daemon exited during task")
    if positive:
        require("result" in r, str(r))
        result = r["result"]
        expect = f"Hello, {nonce}!".encode()
        require(result["chosen_peer"] == dst.peer and bytes(result["output"]) == expect, "wrong executor or result")
        fact.update(chosen_peer=result["chosen_peer"], received_output=bytes(result["output"]).decode(),
                    expected_and_actual_sha256=hashlib.sha256(expect).hexdigest())
        require(fact["worker_wasm_completions_after"] == count_before + 1, "missing remote guest completion")
    else:
        require("error" in r and "result" not in r, f"accepted disallowed job: {r}")
        require(r["error"]["code"] == -32000, str(r))
        fact["rpc_error"] = r["error"]
        require(fact["worker_wasm_completions_after"] == count_before, "denied work ran on worker")
    return fact


def atomic(path, data):
    tmp = path.with_suffix(".new")
    tmp.write_bytes(data)
    tmp.chmod(0o600)
    os.replace(tmp, path)


def auth(a, b, c):
    matrix = []
    store = a.state / "peers.toml"
    original = store.read_bytes()
    require(tomllib.loads(original.decode())["peer"][0]["trust"] == "trusted", "expected trusted pairing")
    # C has never been paired at A; it can probe the configured A route. A reports
    # the exact unknown QUIC identity in its refusal log, including inventory probes.
    require(all(bytes(r["peer_id"]).hex() != c.peer for r in tomllib.loads(original.decode())["peer"]), "C is already known")
    def unknown_log():
        rows = [json.loads(line) for line in (a.home / "daemon.log").read_text().splitlines() if line.startswith("{")]
        hits = [r for r in rows if r.get("fields", {}).get("peer") == c.peer and "refused task" in str(r["fields"].get("message"))]
        require(hits, "no authenticated refusal observed for never-paired C")
        return hits[-1]["fields"]
    unknown = wait_until(unknown_log, 12)
    for src, dst in [(a, c), (c, a)]:
        row = call(src, dst, "never-paired-C")
        require("no live workers" in row["rpc_error"]["message"] or "no known network address" in row["rpc_error"]["message"], str(row))
        row["receiver_refusal_observed_for_C"] = unknown
        matrix.append(row)
    for key in ["revoked", "removed", "observer", "empty-authoritative-store", "malformed"]:
        for src, dst in [(a, b), (b, a)]:
            matrix.append(wait_until(lambda: call(src, dst, "trusted-before-" + key, True)))
        if key == "revoked":
            a.cli("mesh", "revoke", b.peer)
            require(tomllib.loads(store.read_text())["peer"][0]["trust"] == "revoked", "revoke did not persist")
        elif key == "removed":
            a.cli("mesh", "untrust", b.peer)
            require(not tomllib.loads(store.read_text())["peer"], "removal did not persist")
        elif key == "observer":
            edited = original.replace(b'trust = "trusted"', b'trust = "observer"')
            require(edited != original and tomllib.loads(edited.decode())["peer"][0]["trust"] == "observer", "observer fixture")
            atomic(store, edited)
        elif key == "empty-authoritative-store":
            atomic(store, b"peer = []\n")
        else:
            atomic(store, b"peer = [\n")
        change = time.monotonic()
        # No retries for a negative dispatch. B still trusts A; only A's file changed.
        for src, dst, expected in [(b, a, "not-authorized"), (a, b, "no known network address")]:
            row = call(src, dst, key)
            row["ms_since_persist"] = round((time.monotonic() - change) * 1000, 3)
            row["changed_store_sha256"] = sha(store)
            require(expected in row["rpc_error"]["message"], str(row))
            matrix.append(row)
        atomic(store, original)
    for src, dst in [(a,b),(b,a)]:
        matrix.append(wait_until(lambda: call(src, dst, "recovered", True)))
    return matrix


def open_lines(a, b, timeout_ms=5000):
    pub, rest = b.stream.split("/")
    name, version = rest.split("@")
    task = {"id": str(uuid.uuid4()), "plugin": {"publisher": pub, "name": name, "version": version},
            "resources": {"cpu_cores": .01, "gpu": None, "npu": None, "memory_bytes": 0, "network_bandwidth_bps": 0},
            "integrity": {"kind": "trusted-executor", "allowlist": [list(bytes.fromhex(b.peer))]},
            "timeout_ms": timeout_ms, "partial_result": "keep-signed",
            "channel": {"credit_window": 1, "max_chunk_bytes": 32, "max_total_bytes": 512, "heartbeat_ms": 5000}}
    lines = [f"line-{n}-{secrets.token_hex(4)}\n".encode() for n in range(12)]
    r = a.rpc("compute/stream/open", {"task": task, "input": list(b"".join(lines))})
    if "result" in r:
        require(bytes(r["result"]["executor"]).hex() == b.peer, str(r))
    return r, lines


def restart(a, b):
    pid = b.proc.pid
    durable = {n: sha(b.state / n) for n in ["identity.key", "peers.toml", "keyring.toml", "config.toml"]}
    r, lines = open_lines(a,b)
    require("result" in r, str(r))
    session = r["result"]["session"]
    first = a.rpc("compute/stream/read", session)["result"]
    require(first["kind"] == "chunk" and first["seq"] == 0 and bytes(first["bytes"]) == lines[0] and len(first["signature"]) == 64, str(first))
    start = time.monotonic()
    b.proc.kill()
    b.proc.wait(timeout=5)
    require(b.proc.returncode == -9, "expected SIGKILL")
    partial = 1
    while True:
        response = a.rpc("compute/stream/read", session)
        if "error" in response:
            break
        event = response["result"]
        require(event["kind"] in ["waiting", "chunk", "stalled"] and time.monotonic() - start < 18, str(event))
        if event["kind"] == "chunk":
            require(bytes(event["bytes"]) == lines[partial] and partial < len(lines) - 1, "incorrect partial result")
            partial += 1
    failure_ms = round((time.monotonic() - start) * 1000, 3)
    require(response["error"]["code"] == -32000 and failure_ms < 18000, str(response))
    restarted = time.monotonic()
    b.start()
    plugins = b.rpc("plugins/list")["result"]["plugins"]
    require(b.stream in plugins and b.hello in plugins and b.proc.pid != pid, "required startup plugin or new process missing")
    restored = wait_until(lambda: call(a, b, "post-restart", True), 12)
    convergence = round((time.monotonic() - restarted) * 1000, 3)
    require({n: sha(b.state / n) for n in durable} == durable, "restart modified persisted identity/trust/plugin configuration")
    return dict(signal="SIGKILL", source_pid=a.proc.pid, old_worker_pid=pid, new_worker_pid=b.proc.pid,
                partial_verified_chunks=partial, requested_chunks=len(lines), source_rpc_error=response["error"],
                active_work_failure_ms=failure_ms, restart_to_verified_remote_result_ms=convergence,
                architecture_under_10s=convergence < 10000, reloaded_plugins=plugins,
                restored_dispatch=restored, unchanged_public_state_sha256={k:v for k,v in durable.items() if k != "identity.key"},
                same_identity_file=True)


def saturation(a,b,c):
    # C now explicitly joins B. Thirty-two admitted WIT streams from A each hold
    # at one credit; C supplies a distinct coordinator with free local slots.
    b.pair(c)
    c.pair(b)
    wait_until(lambda: call(c,b,"trusted-second-coordinator",True), 45)
    start = time.monotonic()
    sessions = []
    for _ in range(32):
        reply, lines = open_lines(a,b,60_000)
        require("result" in reply, f"only {len(sessions)} sessions admitted: {reply}")
        sid = reply["result"]["session"]
        first = a.rpc("compute/stream/read",sid)["result"]
        require(first["kind"] == "chunk" and first["seq"] == 0 and bytes(first["bytes"]) == lines[0], str(first))
        sessions.append(sid)
    ready_ms = round(1000*(time.monotonic()-start),3)
    denied = {}
    for source, marker in [(a,"too many stream sessions"),(c,"worker busy")]:
        started=time.monotonic()
        reply,_ = open_lines(source,b,60_000)
        require(reply.get("error",{}).get("code") == -32000 and marker in reply["error"]["message"], str(reply))
        denied[source.name]=dict(rpc_error=reply["error"], elapsed_ms=round((time.monotonic()-started)*1000,3))
    for sid in sessions:
        require("result" in a.rpc("compute/stream/close",sid), "failed to release session")
    start = time.monotonic()
    def recovered():
        reply, lines = open_lines(c,b)
        require("result" in reply, str(reply))
        sid=reply["result"]["session"]
        for idx, expected in enumerate(lines):
            item=c.rpc("compute/stream/read",sid)["result"]
            require(item["kind"]=="chunk" and item["seq"]==idx and bytes(item["bytes"])==expected, str(item))
        require(c.rpc("compute/stream/read",sid)["result"]["kind"]=="finished", "missing stream completion")
    wait_until(recovered,10)
    return dict(pids={n.name:n.proc.pid for n in (a,b,c)}, admitted_simultaneous_worker_sessions=len(sessions),
                max_chunk_bytes=32,max_total_bytes=512,credit_window=1, stall_timeout_ms=60000,
                admission_and_first_chunk_ms=ready_ms, excess_request=denied,
                all_recovery_chunks_verified_by_daemon=12,
                freed_worker_slots_to_completed_healthy_stream_ms=round(1000*(time.monotonic()-start),3))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args=parser.parse_args()
    bins=args.bin_dir.resolve()
    before=facts(bins)
    with tempfile.TemporaryDirectory(prefix="ent-auth-", dir="/tmp") as t, contextlib.ExitStack() as cleanup:
        base=Path(t)
        a,b,c=[Node(bins, base, n) for n in "ABC"]
        for node in (a,b,c):
            cleanup.callback(node.stop)
            node.hello=node.package("hello-world", "hello-pong.wasm")
        b.stream=b.package("stream-lines", "stream-lines.wasm")
        a.pair(b)
        b.pair(a)
        c.pair(a)
        a.configure([b,c])
        b.configure([a,c])
        c.configure([a,b])
        for node in [a,b,c]:
            node.start()
        for node in [a,b,c]:
            plugins=node.rpc("plugins/list")["result"]["plugins"]
            require(node.hello in plugins, "own plugin missing")
            require(all(n.hello not in plugins for n in [a,b,c] if n!=node), "counterpart plugin local")
        loaded_daemons = {
            n.name: {"pid": n.proc.pid, "executable_sha256": sha(Path("/proc") / str(n.proc.pid) / "exe")}
            for n in (a,b,c)
        }
        require(all(item["executable_sha256"] == before["binary_sha256"]["entangled"] for item in loaded_daemons.values()),
                "running process differs from the candidate executable")
        results=auth(a,b,c)
        rec=restart(a,b)
        require(sha(Path("/proc") / str(b.proc.pid) / "exe") == before["binary_sha256"]["entangled"],
                "replacement worker differs from candidate executable")
        limits=saturation(a,b,c)
        ids={n.name: n.peer for n in (a,b,c)}
    after=facts(bins)
    for k in ["source_id","commit","binary_sha256","driver_sha256"]:
        require(before[k]==after[k], f"{k} changed in test")
    args.out.write_text(json.dumps({"before":before,"after":after,"command":["python3","-B",str(Path(__file__).relative_to(REPO)),
        "--bin-dir",str(bins),"--out",str(args.out)],"loaded_daemons":loaded_daemons,
        "trust_changes":{"revoked":"candidate CLI mesh revoke", "removed":"candidate CLI mesh untrust",
                         "observer":"atomic replacement of the authoritative paired record trust=observer",
                         "empty-authoritative-store":"atomic publication of an empty peer array",
                         "malformed":"atomic publication of incomplete TOML"},
        "scope":"separate Linux x86_64 daemons on one host with isolated homes, mutual-authenticated direct Iroh QUIC loopback", "peer_ids":ids,"auth_live":results, "rel_restart":rec,"rel_limits":limits},indent=2)+"\n")
    print(json.dumps({"auth_live_rows":len(results), "restart":rec, "limits":limits, "evidence_sha256":sha(args.out)}))


if __name__=="__main__":
    main()
