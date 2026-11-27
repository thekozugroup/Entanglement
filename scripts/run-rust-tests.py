#!/usr/bin/env python3
"""Shard a signed WASI libtest suite over paired Entanglement workers."""

import argparse
from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import json
from pathlib import Path
import re
import socket
import sys
import time


class DispatchError(Exception):
    """A transport, worker, or libtest protocol failure."""


class RpcError(DispatchError):
    """A structured error returned by the coordinator."""

    def __init__(self, message, remote_code=None):
        super().__init__(message)
        self.remote_code = remote_code


class TerminalDispatchError(DispatchError):
    """An attempt whose rejection or attribution must end retries."""

    def __init__(self, message, error_kind, remote_code=None):
        super().__init__(message)
        self.error_kind = error_kind
        self.remote_code = remote_code


class SuiteIdentityError(TerminalDispatchError):
    """A worker did not prove the identity of the selected signed suite."""

    def __init__(self, message, remote_code=None):
        super().__init__(message, "suite_identity", remote_code)


MAX_RPC_LINE = 4 * 1024 * 1024
SUITE_DIGESTS = {"artifact_blake3", "manifest_blake3"}
LIBTEST_REMOTE_CODES_VERSION = 1
STATUSES = ("passed", "flaky", "failed", "ignored", "error")
RESULT = re.compile(
    r"^test result: (ok|FAILED)\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored; "
    r"([0-9]+) measured; ([0-9]+) filtered out(?:; finished in [0-9]+(?:\.[0-9]+)?s)?$",
    re.MULTILINE,
)
PANIC = re.compile(r"^thread '[^'\r\n]*'(?: \(\d+\))? panicked at(?: |$)", re.MULTILINE)
RUN_HEADER = re.compile(r"running [0-9]+ tests?")


def rpc(socket_path, method, params, timeout):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.settimeout(timeout)
            stream.connect(str(socket_path))
            request = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
            stream.sendall(json.dumps(request).encode() + b"\n")
            with stream.makefile("rb") as reader:
                line = reader.readline(MAX_RPC_LINE + 1)
        if not line.endswith(b"\n") or len(line) > MAX_RPC_LINE:
            raise DispatchError("daemon returned an incomplete or oversized RPC response")
        reply = json.loads(line)
        if reply["id"] != 1 or reply["jsonrpc"] != "2.0":
            raise DispatchError("unexpected RPC response envelope")
        if "error" in reply:
            error = reply["error"]
            message = error["message"]
            data = error.get("data")
            remote_code = data.get("remote_code") if isinstance(data, dict) else None
            raise RpcError(message, remote_code if isinstance(remote_code, str) else None)
        return reply["result"]
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise DispatchError(f"{method}: {error}") from error


def dispatcher(socket_path, plugin, timeout_ms):
    def dispatch(peer, operation):
        expected = operation.get("expected_suite_identity")
        request = {
            "plugin_id": plugin,
            "input": list(json.dumps(operation).encode()),
            "timeout_ms": timeout_ms,
            "cpu_cores": 0.0,
            "memory_bytes": 0,
            "gpu_required": False,
            "gpu_vram_min_bytes": 0,
            "integrity": {"kind": "trusted-executor", "allowlist": [peer]},
        }
        upgrade = f"worker {peer} does not report signed libtest suite identity; upgrade the worker daemon"
        try:
            reply = rpc(socket_path, "compute/dispatch", request, timeout_ms / 1000 + 15)
        except RpcError as error:
            if expected is not None:
                if error.remote_code == "suite-identity-mismatch":
                    raise SuiteIdentityError(f"worker {peer}: {error}", error.remote_code) from error
                if error.remote_code in {"not-authorized", "plugin-not-loaded"}:
                    raise TerminalDispatchError(
                        f"worker {peer}: {error}", "remote_rejected", error.remote_code
                    ) from error
                if error.remote_code == "execution" and operation["operation"] == "list":
                    raise DispatchError(
                        f"pinned listing failed on worker {peer}: {error}. "
                        "Verify the worker daemon supports signed libtest suite pinning."
                    ) from error
            raise
        try:
            if not isinstance(reply, dict):
                raise DispatchError("invalid scheduler response")
            chosen_peer = reply.get("chosen_peer")
            if chosen_peer != peer:
                raise TerminalDispatchError(
                    f"scheduler returned executor {chosen_peer!r}; expected {peer}", "executor_integrity"
                )
            result = json.loads(bytes(reply["output"]))
            if not isinstance(result, dict):
                raise DispatchError("invalid WASI libtest response")
            if "suite_identity" not in result:
                raise SuiteIdentityError(upgrade)
            identity = result["suite_identity"]
            if (not isinstance(identity, dict) or set(identity) != SUITE_DIGESTS
                    or any(not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
                           for digest in identity.values())):
                raise SuiteIdentityError(f"worker {peer} reported an invalid libtest suite identity")
            if expected is not None and identity != expected:
                raise SuiteIdentityError(
                    f"worker {peer}: libtest suite identity mismatch (expected {expected}, got {identity})"
                )
            if (not isinstance(result["stdout"], str) or not isinstance(result["stderr"], str)
                    or (result["exit_code"] is not None and type(result["exit_code"]) is not int)):
                raise DispatchError("invalid WASI libtest response")
            return {"peer": chosen_peer, "exit_code": result["exit_code"],
                    "stdout": result["stdout"], "stderr": result["stderr"], "suite_identity": identity}
        except (KeyError, TypeError, ValueError) as error:
            raise DispatchError(f"invalid WASI libtest response: {error}") from error

    return dispatch


def test_list(result):
    if result["exit_code"] != 0:
        raise DispatchError(f"libtest listing failed on {result['peer']}: {result['stderr']}")
    names = set()
    for line in result["stdout"].splitlines():
        if line.endswith(": test"):
            name = line.removesuffix(": test")
            if name in names:
                raise DispatchError(f"duplicate test in harness listing: {name}")
            names.add(name)
        elif line and not line.endswith(": benchmark"):
            raise DispatchError(f"unexpected libtest listing output: {line}")
    return names


def suite_listing(dispatch, peer):
    listing = dispatch(peer, {"operation": "list"})
    names = test_list(listing)
    identity = listing["suite_identity"]
    ignored = test_list(dispatch(peer, {"operation": "list", "ignored": True,
                                       "expected_suite_identity": identity}))
    if not ignored <= names:
        raise DispatchError(f"inconsistent ignored-test listing on {peer}")
    return names, ignored, identity


def classify(result, name):
    lines = result["stdout"].split("\n")
    header = next((line for line in lines if line.strip()), "")
    last = next((index for index in range(len(lines) - 1, -1, -1) if lines[index].strip()), -1)
    summaries = []
    # Terse libtest writes a progress marker or failure footer before the
    # summary and a blank line after it. With --nocapture a test may print
    # summary-like text, and the final progress dot can follow inline output.
    for index in range(1, len(lines) - 2):
        if not lines[index].startswith("test result:") or lines[index + 1] != "":
            continue
        previous = lines[index - 1]
        terminal = index == last
        if previous.endswith("."):
            marker = "passed"
        elif previous == "i":
            marker = "ignored"
            # An exact ignored test can emit its reason after the summary.
            terminal |= (lines[index + 2].startswith(f"test: {name}, ignore_message: ")
                         and lines[-2:] == ["", ""])
        elif index >= 3 and lines[index - 3:index] == ["failures:", f"    {name}", ""]:
            marker = "failed"
        else:
            continue
        summaries.append((RESULT.fullmatch(lines[index]), marker, terminal))

    exit_code = result["exit_code"]
    if exit_code is None:
        if any(terminal for _, _, terminal in summaries):
            raise DispatchError("WASI libtest trapped after reporting a test summary")
        if RUN_HEADER.fullmatch(header) and header != "running 1 test":
            raise DispatchError("exact libtest selector did not report one selected test")
        if PANIC.search(result["stderr"]):
            return "failed"
        raise DispatchError("WASI libtest trapped without a Rust panic report")
    if len(summaries) != 1:
        raise DispatchError("expected one terminal Rust libtest summary")
    summary, marker, terminal = summaries[0]
    if summary is None or not terminal:
        raise DispatchError("expected one valid terminal Rust libtest summary")
    if header != "running 1 test":
        raise DispatchError("exact libtest selector did not report one selected test")
    status, passed, failed, ignored, measured, _ = summary.groups()
    counts = (passed, failed, ignored, measured)
    if status == "ok" and exit_code == 0:
        if marker == "passed" and counts == ("1", "0", "0", "0"):
            return "passed"
        if marker == "ignored" and counts == ("0", "0", "1", "0"):
            return "ignored"
    if status == "FAILED" and exit_code != 0 and marker == "failed" and counts == ("0", "1", "0", "0"):
        return "failed"
    raise DispatchError("exact libtest selector did not report one completed test")


def run_attempt(dispatch, peer, name, ignored, attempt):
    record = {"attempt": attempt, "peer": peer}
    try:
        result = dispatch(peer, {"operation": "test", "name": name, "ignored": ignored,
                                 "attempt": attempt})
        record.update(result)
        record["status"] = classify(result, name)
    except TerminalDispatchError as error:
        record.update(status="error", error_kind=error.error_kind, error=str(error))
        if error.remote_code is not None:
            record["remote_code"] = error.remote_code
    except DispatchError as error:
        record.update(status="error", error=str(error))
    except Exception as error:
        record.update(status="error", error=f"unexpected {type(error).__name__}: {error}")
    return record


def final_status(attempts, retries):
    last = attempts[-1]
    if "error_kind" in last:
        return "error"
    outcome = last["status"]
    if outcome == "passed":
        return "flaky" if any(a["status"] == "failed" for a in attempts[:-1]) else "passed"
    if outcome == "ignored" and len(attempts) == 1:
        return "ignored"
    if len(attempts) <= retries:
        return None
    # An ignored retry leaves an earlier failure or error unresolved.
    return "failed" if any(a["status"] == "failed" for a in attempts) else "error"


def schedule_tests(executor, dispatch, peers, pending, ignored, retries, results):
    # Each peer owns one dispatch slot. Only retries have a prescribed destination.
    available = deque(range(len(peers)))
    retry_queues = [deque() for _ in peers]
    running = {}
    while True:
        for _ in range(len(available)):
            worker = available.popleft()
            queue = retry_queues[worker] or pending
            if not queue:
                available.append(worker)
                continue
            name = queue.popleft()
            attempt = 1 + len(results[name]["attempts"])
            future = executor.submit(run_attempt, dispatch, peers[worker], name,
                                     name in ignored, attempt)
            running[future] = (worker, name)
        if not running:
            return
        completed, _ = wait(running, return_when=FIRST_COMPLETED)
        for future in completed:
            worker, name = running.pop(future)
            available.append(worker)
            attempts = results[name]["attempts"]
            attempts.append(future.result())
            status = final_status(attempts, retries)
            if status is None:
                retry_queues[(worker + 1) % len(peers)].append(name)
            else:
                results[name]["status"] = status


def run_suite(args, plugin):
    filters = (args.filter,) if isinstance(args.filter, str) else args.filter

    def matches(name, selector):
        return name == selector if args.exact else selector in name

    peers = args.peer
    request = dispatcher(args.socket, plugin, args.timeout_ms)
    started = time.monotonic()
    first_listing = suite_listing(request, peers[0])
    names, ignored, identity = first_listing

    def dispatch(peer, operation):
        return request(peer, {**operation, "expected_suite_identity": identity})

    with ThreadPoolExecutor(max_workers=len(peers)) as executor:
        listings = list(executor.map(lambda peer: suite_listing(dispatch, peer), peers[1:]))
        if any(listing != first_listing for listing in listings):
            raise DispatchError("workers disagree about the signed suite's test names or ignores")
        selected = [name for name in sorted(names)
                    if (not filters or any(matches(name, selector) for selector in filters))
                    and not any(matches(name, skip) for skip in args.skip)
                    and (not args.ignored or name in ignored)]
        results = {}
        pending = deque()
        for name in selected:
            results[name] = {"name": name, "attempts": []}
            if name in ignored and not (args.ignored or args.include_ignored):
                results[name]["status"] = "ignored"
            else:
                pending.append(name)
        schedule_tests(executor, dispatch, peers, pending, ignored, args.retries, results)

    counts = dict.fromkeys(STATUSES, 0)
    for result in results.values():
        counts[result["status"]] += 1
    return {"suite": plugin, "suite_identity": identity, "listing_peers": peers,
            "filtered": len(names) - len(selected),
            "counts": counts, "elapsed_ms": round((time.monotonic() - started) * 1000),
            "results": [results[name] for name in selected]}


def run_suites(args):
    status = rpc(args.socket, "mesh/status", None, 10)
    version = status.get("libtest_remote_codes") if isinstance(status, dict) else None
    if type(version) is not int or version != LIBTEST_REMOTE_CODES_VERSION:
        raise DispatchError("coordinator does not support signed libtest dispatch error codes version 1; "
                            "upgrade the coordinator daemon")
    local_peer = status.get("local_peer_id")
    if not isinstance(local_peer, str):
        raise DispatchError("coordinator did not report its local peer identity")
    if len(set(args.peer)) != len(args.peer) or local_peer in args.peer:
        raise DispatchError("supply distinct remote peer identities")
    started = time.monotonic()
    suites = [run_suite(args, plugin) for plugin in args.plugins]
    return {"suites": suites,
            "counts": {status: sum(suite["counts"][status] for suite in suites) for status in STATUSES},
            "filtered": sum(suite["filtered"] for suite in suites),
            "elapsed_ms": round((time.monotonic() - started) * 1000)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plugins", nargs="+", metavar="PLUGIN", help="operator-loaded, signed libtest plugin IDs")
    parser.add_argument("--socket", type=Path, default=Path.home() / ".entangle" / "sock")
    parser.add_argument("--peer", action="append", required=True, help="trusted remote peer ID")
    parser.add_argument("--filter", action="append", default=[], help="include a matching name (repeatable, any match)")
    parser.add_argument("--exact", action="store_true", help="match complete names in filters and skips")
    parser.add_argument("--skip", action="append", default=[], help="exclude a matching name (repeatable)")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--ignored", action="store_true", help="select ignored tests only")
    modes.add_argument("--include-ignored", action="store_true")
    parser.add_argument("--retries", type=int, choices=range(11), default=0)
    parser.add_argument("--timeout-ms", type=int, default=30_000)
    args = parser.parse_args()
    if any(not re.fullmatch(r"[0-9a-f]{32}", peer) for peer in args.peer):
        parser.error("peer IDs must be 32 lowercase hexadecimal characters")
    if len(set(args.plugins)) != len(args.plugins):
        parser.error("supply distinct plugin IDs")
    if not 0 < args.timeout_ms <= 300_000:
        parser.error("timeout must be between 1 and 300000 milliseconds")
    try:
        report = run_suites(args)
    except DispatchError as error:
        print(f"Rust test dispatch failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return int(bool(report["counts"]["failed"] or report["counts"]["error"]))


if __name__ == "__main__":
    sys.exit(main())
