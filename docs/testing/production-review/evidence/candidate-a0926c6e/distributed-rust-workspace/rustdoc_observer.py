#!/usr/bin/env python3
"""Observe rustdoc 1.91.1's host coordinator; its verdict decides each standalone case."""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import sys
import time
import uuid


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def arg_value(args, option):
    for i, arg in enumerate(args):
        if arg == option:
            return args[i + 1]
        if arg.startswith(option + "="):
            return arg.split("=", 1)[1]
    raise RuntimeError("Cargo rustdoc command omitted " + option)


def invocation():
    directory = Path(os.environ["ENTANGLE_RUSTDOC_INVOCATION"])
    return directory, json.loads((directory / "meta.json").read_text())


def merged_sources(artifact):
    # rustdoc 1.91.1 creates both generated sources beside the WASI executable
    # only for merged doctests, even in a crate with standalone doctests too.
    runner = list(artifact.parent.glob("doctest_runner_*.rs"))
    bundle = list(artifact.parent.glob("doctest_bundle_*.rs"))
    if not runner and not bundle:
        return []
    if len(runner) != 1 or len(bundle) != 1 or runner[0].name.replace("runner", "bundle", 1) != bundle[0].name:
        raise RuntimeError("inconsistent rustdoc merged build artifacts")
    return [{"name": p.name, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in (runner[0], bundle[0])]


def selected_case(directory):
    # The stable, serial pretty formatter flushes this exact prefix before the
    # command runs. Result/ignore lines and sample output cannot select a case.
    transcript = (directory / "stdout").read_bytes()
    partial = transcript.rsplit(b"\n", 1)[-1].decode()
    match = re.fullmatch(r"test (.+?) \.\.\. ", partial)
    if not match:
        raise RuntimeError("no active named case from rustdoc's serial host coordinator")
    return match[1]


def standalone(ctx, artifact, descriptor, plugin, socket, runner):
    directory, meta = invocation()
    name = selected_case(directory)
    peers = ctx["peers"]
    peer = peers[int.from_bytes(hashlib.sha256(name.encode()).digest()[:8], "big") % len(peers)]
    started = time.monotonic()
    raw = None
    error = None
    try:
        dispatch = runner.dispatcher(socket, plugin, 60_000)
        until = time.monotonic() + 75
        while True:
            try:
                raw = dispatch(peer, {"operation": "test", "name": "rustdoc", "attempt": 1})
                break
            except runner.DispatchError as exc:
                if "no live worker" not in str(exc) or time.monotonic() >= until:
                    raise
                time.sleep(.2)
        code = raw["exit_code"]
        if raw["peer"] != peer or (code is not None and (type(code) is not int or not 0 <= code <= 255)):
            raise ValueError("missing guest process exit or authenticated worker mismatch")
    except Exception as exc:
        error = str(exc)
    record = {"elapsed_s": time.monotonic()-started, "name": name, "suite": plugin, "expected_peer": peer, "raw_guest": raw,
              "wasm_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(), "wasi_bytes": artifact.stat().st_size,
              "package": descriptor["package"], "invocation": meta["id"], "infrastructure_error": error,
              "termination": ("infrastructure-error" if error else
                              "guest-unreachable-trap" if raw["exit_code"] is None else "guest-exit")}
    write_json(directory / ("guest-" + uuid.uuid4().hex + ".json"), record)
    if error:
        print(error, file=sys.stderr)
        return 125
    sys.stdout.write(raw["stdout"])
    sys.stderr.write(raw["stderr"])
    if raw["exit_code"] is None:
        # Only UnreachableCodeReached is encoded as present JSON null by the
        # frozen command host. Preserve it as abnormal termination for rustdoc,
        # without inventing a numeric guest exit or matching panic text.
        sys.stdout.flush()
        sys.stderr.flush()
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        signal.signal(signal.SIGABRT, signal.SIG_DFL)
        os.kill(os.getpid(), signal.SIGABRT)
        raise RuntimeError("abnormal termination signal did not terminate runtool")
    return raw["exit_code"]


def main():
    args = sys.argv[1:]
    real = os.environ["ENTANGLE_REAL_RUSTDOC"]
    if "--test" not in args:
        os.execv(real, [real, *args])
    ctxpath = Path(os.environ["ENTANGLE_CARGO_REVIEW"])
    ctx = json.loads(ctxpath.read_text())
    manifest_dir = str(Path(arg_value(args, "--test-run-directory")).resolve())
    package = ctx["manifest_dirs"][manifest_dir]
    if arg_value(args, "--target") != "wasm32-wasip2" or "--test-args" in args:
        raise RuntimeError("expected Cargo's complete unfiltered wasm32-wasip2 doctest command")
    invoke_id = uuid.uuid4().hex
    directory = ctxpath.parent / ("rustdoc-" + invoke_id)
    directory.mkdir()
    meta = {"id": invoke_id, "package": package, "crate": arg_value(args, "--crate-name"),
            "edition": arg_value(args, "--edition"), "manifest_dir": manifest_dir, "cargo_arguments": args}
    write_json(directory / "meta.json", meta)
    extra = ["--test-args=--test-threads=1", "--test-args=--format=pretty"]
    env = {**os.environ, "ENTANGLE_RUSTDOC_INVOCATION": str(directory)}
    stdout_path = directory / "stdout"
    started = time.monotonic()
    with stdout_path.open("wb") as stdout:
        proc = subprocess.run([real, *args, *extra], stdout=stdout, stderr=subprocess.PIPE, env=env)
    output = stdout_path.read_text()
    sys.stdout.write(output)
    sys.stderr.buffer.write(proc.stderr)
    statuses = {"ok": "passed", "FAILED": "failed", "ignored": "ignored"}
    genuine = {}
    for name, status in re.findall(r"^test (.+?) \.\.\. (ok|FAILED|ignored)(?:, [^\n]*)?$", output, re.M):
        if name in genuine:
            raise RuntimeError("duplicate rustdoc case in host output: " + name)
        genuine[name] = statuses[status]
    guests = [json.loads(p.read_text()) for p in sorted(directory.glob("guest-*.json"))]
    merged_names = set()
    for p in directory.glob("merged-*.json"):
        group = json.loads(p.read_text())
        merged_names.update(group)
    consumed = set()
    rows = []
    errors = [p.read_text() for p in directory.glob("fatal-*.txt")]
    for guest in guests:
        name = guest["name"]
        if name not in genuine or name in consumed or name in merged_names:
            raise RuntimeError("rustdoc guest to case mismatch: " + name)
        consumed.add(name)
        error = guest["infrastructure_error"]
        raw = guest["raw_guest"]
        guest["rustdoc_verdict"] = genuine[name]
        if not error and raw["exit_code"] is None:
            match = re.search(r"^thread '[^'\n]+'(?: \(\d+\))? panicked at [^\n]+", raw["stderr"], re.M)
            guest["rust_panic_diagnostic"] = match[0] if match else None
            if genuine[name] == "passed" and match is None:
                error = "rustdoc accepted abnormal termination without a Rust panic diagnostic"
                guest["evidence_error"] = error
        if error:
            errors.append(f"{name}: {error}")
        attempts = [{"attempt": 1, "peer": guest["expected_peer"], "status": genuine[name], **guest}]
        rows.append({"name": name, "status": "error" if error else genuine[name], "attempts": attempts})
    for name, status in genuine.items():
        if name in consumed or name in merged_names:
            continue
        # No executable exists for compile_fail/no_run/ignored cases. For any
        # other pass a missing signed guest receipt is an infrastructure error.
        if status == "passed" and not name.endswith((" - compile fail", " - compile")):
            errors.append("missing signed guest: " + name)
            status = "error"
        rows.append({"name": name, "status": status, "attempts": []})
    counts = {s: sum(r["status"] == s for r in rows) for s in ("passed", "failed", "flaky", "ignored", "error")}
    entry = {"elapsed_s":time.monotonic()-started, "kind": "rustdoc", "package": package, "target": "doctest", "report": {
        "mode": "rustdoc host coordinator", "meta": meta, "coordinator_added_arguments": extra,
        "host_exit_code": proc.returncode, "host_stdout": output, "host_stderr": proc.stderr.decode(errors="replace"),
        "infrastructure_errors": errors, "results": rows, "counts": counts}}
    write_json(ctxpath.parent / "reports" / ("host-" + invoke_id + ".json"), entry)
    return proc.returncode or int(bool(errors))


if __name__ == "__main__":
    sys.exit(main())
