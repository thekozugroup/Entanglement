#!/usr/bin/env python3
"""Measure real llama.cpp cancellation through the signed mesh stream."""
import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import http.client
import http.server
import importlib.util
import json
from pathlib import Path
import select
import shlex
import socket
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


CHAT = "/v1/chat/completions"
INVENTORY = "/v1/models"
LONG_PROMPT = "Write a very long story about a bicycle trip. Continue the story through many towns."
FRESH_PROMPT = "Write one sentence describing a bicycle."


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def old_driver(path):
    spec = importlib.util.spec_from_file_location("established_real_inference", path)
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    return driver


class Probe:
    """A test-only fixed-route SSE proxy that watches the worker TCP receive half."""

    def __init__(self, backend_port, model):
        self.backend_port = backend_port
        self.model = model
        self.events = []
        self.errors = []
        self.generation_count = 0
        self.lock = threading.Lock()
        self.eof = threading.Event()
        self.fresh = threading.Event()

    def log(self, event, **fields):
        with self.lock:
            self.events.append(dict(event=event, monotonic=time.monotonic(), **fields))

    def handler(self):
        probe = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                if self.path != INVENTORY:
                    self.send_error(404)
                    return
                with self.upstream("GET", INVENTORY) as response:
                    data = response.read(65537)
                    assert len(data) <= 65536
                    self.send_response(response.status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)

            def do_POST(self):
                if self.path != CHAT:
                    self.send_error(404)
                    return
                length = int(self.headers.get("Content-Length", 0))
                if not 1 <= length <= 65536:
                    self.send_error(400)
                    return
                body = self.rfile.read(length)
                request = json.loads(body)
                with probe.lock:
                    probe.generation_count += 1
                    ordinal = probe.generation_count
                first = ordinal == 1
                assert request["model"] == probe.model and request["stream"] is True
                assert request["messages"][0]["content"] == (LONG_PROMPT if first else FRESH_PROMPT)
                probe.log("backend_request_forwarded", ordinal=ordinal, max_tokens=request["max_tokens"])
                try:
                    with self.upstream("POST", CHAT, body) as response:
                        content_type = response.headers.get("Content-Type", "")
                        assert response.status == 200 and content_type.startswith("text/event-stream")
                        self.send_response(200)
                        self.send_header("Content-Type", content_type)
                        self.send_header("Connection", "close")
                        self.end_headers()
                        output_event = False
                        count = 0
                        while line := response.readline(65537):
                            count += len(line)
                            assert len(line) <= 65536 and count <= 8 * 1024 * 1024
                            self.wfile.write(line)
                            self.wfile.flush()
                            if first and line.startswith(b"data:"):
                                data = line[5:].strip()
                                if data != b"[DONE]":
                                    choices = json.loads(data)["choices"]
                                    output_event |= any(c.get("delta", {}).get("content") for c in choices)
                            if first and output_event and not line.strip():
                                probe.log("first_nonempty_sse_event_forwarded")
                                # Leave the SSE body open so a normal EOF cannot satisfy the probe.
                                readable, _, _ = select.select([self.connection], [], [], 12)
                                assert readable, "worker HTTP connection stayed open after cancel"
                                try:
                                    closed = self.connection.recv(1) == b""
                                except ConnectionResetError:
                                    closed = True
                                assert closed, "worker sent more data on the held-open response"
                                probe.log("worker_http_disconnect_observed")
                                break
                        else:
                            assert not first, "first backend response ended before a nonempty event"
                    if first:
                        probe.log("proxy_backend_socket_closed")
                        probe.eof.set()
                    else:
                        probe.log("replacement_sse_completed")
                        probe.fresh.set()
                except Exception as error:
                    with probe.lock:
                        probe.errors.append(repr(error))
                    raise

            def upstream(self, method, path, body=None):
                return Upstream(probe.backend_port, method, path, body)

        return Handler


class Upstream:
    def __init__(self, port, method, path, body):
        self.client = http.client.HTTPConnection("127.0.0.1", port, timeout=12)
        self.client.request(method, path, body=body, headers={"Content-Type": "application/json", "Connection": "close"})

    def __enter__(self):
        try:
            self.response = self.client.getresponse()
        except BaseException:
            self.client.close()
            raise
        return self.response

    def __exit__(self, *_):
        self.response.close()
        self.client.close()


def open_stream(driver, coordinator, worker, prompt, max_tokens):
    task_id = uuid.uuid4()
    task = {
        "id": str(task_id),
        "plugin": {"publisher": worker.peer, "name": "openai-inference", "version": "0.1.0"},
        "resources": {"cpu_cores": 0.01, "memory_bytes": 0, "gpu": None, "npu": None, "network_bandwidth_bps": 0},
        "integrity": {"kind": "trusted-executor", "allowlist": [list(bytes.fromhex(worker.peer))]},
        "timeout_ms": 25000,
        "partial_result": "keep-signed",
        "channel": {"credit_window": 1, "max_chunk_bytes": 4096, "max_total_bytes": 65536, "heartbeat_ms": 5000},
    }
    payload = json.dumps({"prompt": prompt, "max_tokens": max_tokens, "temperature": 0}).encode()
    called = time.monotonic()
    handle = driver.rpc(coordinator, "compute/stream/open", {"task": task, "input": list(payload)})
    admitted = time.monotonic()
    assert bytes(handle["executor"]).hex() == worker.peer
    return task_id, handle["session"], called, admitted


def next_event(driver, coordinator, worker, task, session, expected_seq):
    deadline = time.monotonic() + 30
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(worker.public))
    while time.monotonic() < deadline:
        response = driver.rpc(coordinator, "compute/stream/read", session)
        if response["kind"] in ("waiting", "stalled"):
            continue
        if response["kind"] == "finished":
            return None
        assert response["kind"] == "chunk" and response["seq"] == expected_seq
        data = bytes(response["bytes"])
        assert data
        signature = bytes(response["signature"])
        message = (b"entangle/stream/chunk/1\0" + task.bytes + expected_seq.to_bytes(8, "big")
                   + response["timestamp_ms"].to_bytes(8, "big") + hashlib.sha256(data).digest())
        key.verify(signature, message)
        return {"seq": expected_seq, "timestamp_ms": response["timestamp_ms"], "signature_hex": signature.hex(),
                "payload_hex": data.hex(), "payload_sha256": hashlib.sha256(data).hexdigest(),
                "received_monotonic": time.monotonic()}
    raise RuntimeError("no stream event before deadline")


def exercise(driver, bins, model, server, out, record):
    with tempfile.TemporaryDirectory(prefix="ent-realcancel-", dir="/tmp") as temp, ExitStack() as stack:
        scratch = Path(temp)
        log = stack.enter_context((out / "llama-server.log").open("xb"))
        base, command = driver.start_backend(stack, server, model, log)
        record["backend_command"] = command
        probe = Probe(urlsplit(base).port, driver.ALIAS)
        address = ("127.0.0.1", 0)
        proxy = stack.enter_context(http.server.ThreadingHTTPServer(address, probe.handler()))
        proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        proxy_thread.start()
        stack.callback(proxy.shutdown)
        proxy_base = f"http://127.0.0.1:{proxy.server_port}"

        coordinator = driver.nodes.Node(bins, scratch, "coordinator")
        stack.callback(coordinator.stop)
        worker = driver.nodes.Node(bins, scratch, "worker")
        stack.callback(worker.stop)
        worker.pair(coordinator)
        coordinator.pair(worker)
        worker.configure([])
        coordinator.configure([worker])
        with (worker.state / "config.toml").open("a") as cfg:
            cfg.write(f'\n[security]\nmax_tier_allowed=5\n[runtime.inference]\nendpoint="{proxy_base}{CHAT}"\nmodel="{driver.ALIAS}"\n')
        worker.start()
        coordinator.start()
        record.update(worker_peer=worker.peer, worker_public_key=worker.public, coordinator_peer=coordinator.peer,
                      worker_endpoint=proxy_base + CHAT, backend_endpoint=base + CHAT)
        try:
            first_task, first_session, first_open, _ = driver.nodes.wait_until(
                lambda: open_stream(driver, coordinator, worker, LONG_PROMPT, 192), seconds=16
            )
            first_chunk = next_event(driver, coordinator, worker, first_task, first_session, 0)
            assert first_chunk is not None
            close_start = time.monotonic()
            driver.rpc(coordinator, "compute/stream/close", first_session)
            close_ack = time.monotonic()
            assert probe.eof.wait(13), "upstream cancellation was not observed"
            record["cancelled"] = {"task_id": str(first_task), "prompt": LONG_PROMPT, "max_tokens": 192,
                                   "signed_first_chunk": first_chunk, "open_monotonic": first_open,
                                   "close_started_monotonic": close_start, "close_rpc_ack_monotonic": close_ack}

            task, session, opened, admitted = open_stream(driver, coordinator, worker, FRESH_PROMPT, 24)
            continued = []
            try:
                while len(continued) <= 64:
                    event = next_event(driver, coordinator, worker, task, session, len(continued))
                    if event is None:
                        break
                    continued.append(event)
                else:
                    raise RuntimeError("replacement stream exceeded the expected chunk budget")
            finally:
                coordinator.rpc("compute/stream/close", session)
            assert continued and task != first_task
            assert probe.fresh.wait(3), "replacement backend stream did not close cleanly"
            expected = driver.request(base, CHAT, {"messages": [{"role": "user", "content": FRESH_PROMPT}],
                                                   "model": driver.ALIAS, "stream": False, "max_tokens": 24, "temperature": 0})
            text = b"".join(bytes.fromhex(chunk["payload_hex"]) for chunk in continued).decode()
            assert expected["choices"][0]["message"]["content"] == text
            assert 0 < expected["usage"]["completion_tokens"] <= 24
            record["fresh"] = {"task_id": str(task), "prompt": FRESH_PROMPT, "signed_chunks": continued, "output": text,
                               "direct_response": expected, "opened_monotonic": opened, "admitted_monotonic": admitted}
            events = {event["event"]: event["monotonic"] for event in probe.events if event["event"] != "backend_request_forwarded"}
            assert events["first_nonempty_sse_event_forwarded"] <= first_chunk["received_monotonic"] <= close_start
            assert close_start <= events["worker_http_disconnect_observed"] <= events["proxy_backend_socket_closed"] <= opened
            replacement_forwarded = next(e["monotonic"] for e in probe.events if e["event"] == "backend_request_forwarded" and e["ordinal"] == 2)
            record["elapsed_ms"] = {
                "close_rpc_ack": round(1000 * (close_ack - close_start), 3),
                "worker_http_disconnect": round(1000 * (events["worker_http_disconnect_observed"] - close_start), 3),
                "backend_socket_closed": round(1000 * (events["proxy_backend_socket_closed"] - close_start), 3),
                "replacement_mesh_admission": round(1000 * (admitted - close_start), 3),
                "replacement_backend_forwarded": round(1000 * (replacement_forwarded - close_start), 3),
                "replacement_first_signed_output": round(1000 * (continued[0]["received_monotonic"] - close_start), 3),
            }
            assert probe.generation_count == 2 and not probe.errors
        finally:
            record["probe_events"] = probe.events
            record["probe_errors"] = probe.errors
            for label, node in (("coordinator", coordinator), ("worker", worker)):
                daemon_log = node.home / "daemon.log"
                if daemon_log.is_file():
                    (out / f"{label}-daemon.log").write_bytes(daemon_log.read_bytes())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "bin-dir", "server", "model", "prior-driver", "reference", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-source", required=True)
    args = parser.parse_args()
    root, bins, server, model = (path.resolve(strict=True) for path in (args.root, args.bin_dir, args.server, args.model))
    prior = args.prior_driver.resolve(strict=True)
    baseline = json.loads(prior.with_name("result.json").read_text())
    reference = json.loads(args.reference.read_text())
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    sys.dont_write_bytecode = True
    driver = old_driver(prior)

    def source():
        return subprocess.check_output([sys.executable, "scripts/production_score.py", "--source-id"], cwd=root, text=True).strip()

    def binaries():
        return {name: sha(bins / name) for name in ("entangle", "entangled")}

    record = {
        "command": shlex.join([sys.executable, *sys.argv]), "started_at_utc": utc(),
        "source_before": source(), "release_source_commit": reference["source_commit"],
        "release_reference_sha256": sha(args.reference), "release_binaries_before": binaries(),
        "prior_driver_sha256": sha(prior), "harness_sha256": sha(Path(__file__)),
        "backend_sha256": sha(server), "model_sha256": sha(model), "model_bytes": model.stat().st_size,
        "backend_library_sha256": {p.name: sha(p) for p in sorted(server.parent.glob("*.so"))},
        "host_scope": "One x86_64 Linux host, two real daemons, pinned TinyLlama CPU model and fixed loopback instrumentation.",
        "instrumentation": "The proxy forwards the first real content event, then keeps its worker response open until worker TCP EOF or reset. It closes the same real upstream socket before opening the replacement job.",
    }
    status = 1
    try:
        assert record["source_before"] == reference["source_id"] == args.expected_source
        assert record["release_binaries_before"] == (reference.get("binary_sha256") or {n: reference["files_sha256"][n] for n in ("entangle", "entangled")})
        assert record["backend_sha256"] == baseline["server_sha256"]
        assert record["model_sha256"] == baseline["model_sha256"]
        assert record["backend_library_sha256"] == baseline["server_library_sha256"]
        exercise(driver, bins, model, server, out, record)
        status = 0
    except Exception as error:
        record["error"] = repr(error)
    record["source_after"] = source()
    record["release_binaries_after"] = binaries()
    if record["source_after"] != record["source_before"] or record["release_binaries_after"] != record["release_binaries_before"]:
        status = 1
    record.update(source_id=record["source_before"], exit_code=status, finished_at_utc=utc())
    with (out / "result.json").open("x", encoding="utf-8") as file:
        json.dump(record, file, indent=2)
        file.write("\n")
    print(json.dumps({k: record.get(k) for k in ("source_id", "elapsed_ms", "exit_code", "error")}, indent=2))
    return status


if __name__ == "__main__":
    sys.exit(main())
