#!/usr/bin/env python3
"""Compare signed inference from two paired daemons with the same real CPU model's HTTP output."""
import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
from urllib.error import URLError
from urllib.request import build_opener, ProxyHandler, Request
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
SOURCE = json.loads((HERE.parent / "linux-archive.json").read_text())["source_id"]
MODEL_SHA = "9ee11adf737960ff06123d5c4fba24d12c5b05ba460a7afa88950fbf2b61add0"
ALIAS = "tinyllama-cpu-review"
PROMPTS = (
    "Finish the sequence using five words: winter, spring, summer,",
    "Write one sentence describing a bicycle.",
    "The first three prime numbers are",
)
HTTP = build_opener(ProxyHandler({}))
spec = importlib.util.spec_from_file_location("review_nodes", HERE.parent / "auth-live.py")
nodes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nodes)


def digest(path):
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def source_id():
    return subprocess.check_output(["python3", "scripts/production_score.py", "--source-id"], cwd=ROOT, text=True).strip()


def request(base, path, body=None):
    encoded = None if body is None else json.dumps(body).encode()
    req = Request(base + path, data=encoded, headers={"Content-Type": "application/json"})
    with HTTP.open(req, timeout=60) as response:
        return json.load(response)


def stop_process(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def start_backend(stack, server, model, log):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    command = [server, "--host", "127.0.0.1", "--port", str(port), "--model", model,
               "--alias", ALIAS, "--threads", "2", "--threads-batch", "2", "--parallel", "1",
               "--ctx-size", "512", "--n-gpu-layers", "0"]
    process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
    stack.callback(stop_process, process)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"llama-server exited with code {process.returncode}")
        try:
            health = request(base, "/health")
            if health.get("status") == "ok" and any(
                item["id"] == ALIAS for item in request(base, "/v1/models")["data"]
            ):
                return base, [str(value) for value in command]
        except (URLError, OSError):
            pass
        time.sleep(0.1)
    raise RuntimeError("llama-server model inventory timed out")


def rpc(node, method, params):
    reply = node.rpc(method, params)
    if "result" not in reply:
        raise RuntimeError(f"{method}: {reply.get('error')}")
    return reply["result"]


def mesh_query(coordinator, worker, prompt, wait_for_discovery):
    task_id = uuid.uuid4()
    task = {"id": str(task_id),
            "plugin": {"publisher": worker.peer, "name": "openai-inference", "version": "0.1.0"},
            "resources": {"cpu_cores": 0.01, "gpu": None, "npu": None,
                          "memory_bytes": 0, "network_bandwidth_bps": 0},
            "integrity": {"kind": "trusted-executor", "allowlist": [list(bytes.fromhex(worker.peer))]},
            "timeout_ms": 60000, "partial_result": "keep-signed",
            "channel": {"credit_window": 4, "max_chunk_bytes": 4096,
                        "max_total_bytes": 65536, "heartbeat_ms": 5000}}
    user_input = json.dumps({"prompt": prompt, "max_tokens": 24, "temperature": 0}).encode()
    attempted = time.monotonic()
    refusals = 0
    while True:
        start = time.monotonic()
        reply = coordinator.rpc("compute/stream/open", {"task": task, "input": list(user_input)})
        if "result" in reply:
            handle = reply["result"]
            break
        error = reply.get("error", {})
        if (not wait_for_discovery or error.get("message") != "invalid streaming task: no live workers in pool"
                or start - attempted >= 45):
            raise RuntimeError(f"compute/stream/open: {error}")
        # This validation error precedes peer selection and creates no stream.
        refusals += 1
        time.sleep(0.25)
    assert bytes(handle["executor"]).hex() == worker.peer
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(worker.public))
    chunks = []
    output = bytearray()
    try:
        while time.monotonic() - start < 75:
            event = rpc(coordinator, "compute/stream/read", handle["session"])
            if event["kind"] == "finished":
                break
            if event["kind"] in ("waiting", "stalled"):
                continue
            assert event["kind"] == "chunk" and event["seq"] == len(chunks)
            payload = bytes(event["bytes"])
            message = (b"entangle/stream/chunk/1\0" + task_id.bytes + event["seq"].to_bytes(8, "big")
                       + event["timestamp_ms"].to_bytes(8, "big") + hashlib.sha256(payload).digest())
            key.verify(bytes(event["signature"]), message)
            chunks.append({"seq": event["seq"], "timestamp_ms": event["timestamp_ms"],
                           "sha256": hashlib.sha256(payload).hexdigest(), "signature_hex": bytes(event["signature"]).hex(),
                           "payload_hex": payload.hex(), "received_ms": round((time.monotonic()-start)*1000,3)})
            output.extend(payload)
        else:
            raise RuntimeError("mesh inference exceeded the run deadline")
    finally:
        coordinator.rpc("compute/stream/close", handle["session"])
    assert chunks and output and len(chunks) >= 2
    duration = time.monotonic()-start
    return {"task_id": str(task_id), "first_inventory_wait_ms": round(1000*(start-attempted),3),
            "preplacement_refusals": refusals, "executor": worker.peer, "public_key_hex": worker.public,
            "output": output.decode(), "output_sha256": hashlib.sha256(output).hexdigest(),
            "first_signed_chunk_ms": chunks[0]["received_ms"], "duration_ms": round(duration*1000,3),
            "chunks": chunks}


def run_endpoint(root, binaries, base, endpoint):
    with ExitStack() as stack:
        coordinator = nodes.Node(binaries, root, "coordinator")
        stack.callback(coordinator.stop)
        worker = nodes.Node(binaries, root, "worker")
        stack.callback(worker.stop)
        worker.pair(coordinator)
        coordinator.pair(worker)
        worker.configure([])
        coordinator.configure([worker])
        with (worker.state/"config.toml").open("a") as config:
            config.write(f'\n[security]\nmax_tier_allowed=5\n[runtime.inference]\nendpoint="{base}{endpoint}"\nmodel="{ALIAS}"\n')
        worker.start()
        coordinator.start()
        rows = []
        for prompt in PROMPTS:
            row = mesh_query(coordinator, worker, prompt, wait_for_discovery=not rows)
            chat = endpoint.endswith("/chat/completions")
            direct_input = {"messages": [{"role": "user", "content": prompt}]} if chat else {"prompt": prompt}
            expected = request(base, endpoint, dict(direct_input, model=ALIAS, stream=False, max_tokens=24, temperature=0))
            choice = expected["choices"][0]
            answer = choice["message"]["content"] if chat else choice["text"]
            assert answer == row["output"], (endpoint, prompt, answer, row["output"])
            tokens = expected["usage"]["completion_tokens"]
            assert 0 < tokens <= 24
            row.update(prompt=prompt, direct_response=expected, matched_direct_greedy_output=True, generated_tokens=tokens,
                       end_to_end_tokens_per_second=round(1000*tokens/row["duration_ms"],2))
            rows.append(row)
        return {"endpoint": endpoint, "coordinator_peer": coordinator.peer, "worker_peer": worker.peer, "samples": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--bin-dir", type=Path, default=ROOT/"target/release")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    server, model, bins = (p.resolve(strict=True) for p in (args.server, args.model, args.bin_dir))
    assert source_id()==SOURCE and digest(model)==MODEL_SHA
    release = json.loads((HERE.parent/"linux-archive.json").read_text())
    hashes = {name:digest(bins/name) for name in ("entangle","entangled")}
    assert all(hashes[n] == release["files_sha256"][n] for n in hashes)
    started = datetime.now(timezone.utc).isoformat()
    with tempfile.TemporaryDirectory(prefix="ent-llama-", dir="/tmp") as temp, ExitStack() as stack:
        path = Path(temp)
        with args.output.with_suffix(".server.log").open("xb") as log:
            base, command = start_backend(stack, server, model, log)
        results = []
        for index, endpoint in enumerate(("/v1/completions","/v1/chat/completions")):
            local = path/f"run-{index}"
            local.mkdir()
            results.append(run_endpoint(local, bins, base, endpoint))
        assert source_id()==SOURCE and all(hashes[n]==digest(bins/n) for n in hashes)
    report = {"source_id": SOURCE, "source_after": source_id(), "source_commit":release["source_commit"],
              "started_utc":started,"finished_utc":datetime.now(timezone.utc).isoformat(),
              "release_binaries_sha256":hashes,"driver_sha256":digest(Path(__file__)),
              "server_sha256":digest(server),"server_command":command,
              "server_library_sha256":{p.name:digest(p) for p in sorted(server.parent.glob('*.so'))},
              "server_version":subprocess.run([server,"--version"],capture_output=True,text=True).stderr.strip(),
              "model_sha256":MODEL_SHA,"model_file_bytes":model.stat().st_size,"threads":2,"gpu_layers":0,
              "host_scope":"separate Entanglement processes on one x86_64 Linux host","endpoints":results}
    args.output.write_text(json.dumps(report,indent=2)+"\n")


if __name__ == "__main__":
    main()
