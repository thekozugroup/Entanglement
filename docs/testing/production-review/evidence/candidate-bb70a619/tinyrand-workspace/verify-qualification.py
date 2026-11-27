#!/usr/bin/env python3
"""Reconcile the actual five-crate native inventory, wire results and Cargo doctest log."""
import ast
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import re

here = Path(__file__).resolve().parent


def read(name):
    return gzip.decompress((here / (name + ".gz")).read_bytes()).decode()


run = json.loads(read("distributed.json"))
assert run["exit_code"] == 101 and run["upstream_diff"] == ""
assert run["source_before"] == run["source_after"] == "sha256:9cae32b67ebd4784779d1c37cd9cea5efc1a640fdfd71fca9a67dda8d9c777ab"
assert run["upstream_commit"] == "8dd18ddefc9b057304441d9a7c112ba36d988dfe"
assert run["dependency_lock_sha256"] == hashlib.sha256(read("Cargo.lock").encode()).hexdigest()
assert run["daemon_sha256"] == "8bce7f9fa57f2c1d1cd111c01a5300bdb75e9b0018774a4303af783ae2355042"
assert run["cli_sha256"] == "5f45cea4bb7ff57c073b7407d4aaa140a59f231390c6aee976f0fcee1b713439"
assert "does not have the panic strategy `unwind`" in read("unwind.log")

packages = {p["id"]: p["name"] for p in json.loads(read("meta.json"))["packages"]}
assert len(packages) == 5
bins = {}
for raw in read("native-artifacts.jsonl").splitlines():
    record = json.loads(raw)
    if record.get("executable") and record["package_id"] in packages and record["profile"]["test"]:
        bins[Path(record["executable"]).name] = (packages[record["package_id"]], record["target"]["name"])

native = set()
native_docs = set()
for line in read("native.log").splitlines():
    if match := re.match(r"\s*Running .+ \(([^)]+)\)$", line):
        target = bins[Path(match[1]).name]
    elif re.match(r"\s*Doc-tests \S+$", line):
        target = None
    elif match := re.fullmatch(r"test (.+) \.\.\. (ok|FAILED|ignored)", line):
        name = match[1].removesuffix(" - should panic")
        assert match[2] == "ok"
        if target is None:
            native_docs.add(name)
        else:
            native.add((*target, name))

workers = set(run["peers"])
assert len(workers) == 2
observed = set()
errors = []
statuses = Counter()
attempts = Counter()
selected = None
for target in run["targets"]:
    for case in target["report"]["results"]:
        ident = (target["package"], target["target"], case["name"])
        assert ident not in observed
        observed.add(ident)
        statuses[case["status"]] += 1
        attempts.update(a["peer"] for a in case["attempts"])
        if case["name"] == "thread_local::tests::with_thread_local":
            selected = {"wasm_sha256": target["wasm_sha256"], **case}
        if case["status"] == "error":
            assert {a["peer"] for a in case["attempts"]} == workers
            for a in case["attempts"]:
                assert a["exit_code"] == 0 and "0 passed; 0 failed; 1 ignored;" in a["stdout"]
                assert a["error"] == "exact libtest selector did not report one completed test"
            errors.append({"case": case["name"], "attempts": len(case["attempts"])})
assert observed == native and statuses == {"passed": 97, "error": 7}
assert selected and selected["status"] == "passed" and len(selected["attempts"]) == 1

# Edition 2021 rustdoc runs one command per example. The earlier Cargo driver
# expects a merged runner's summary. Preserve its failure and the nested real
# remote process result separately.
docs = {}
for line in read("distributed.log").splitlines():
    if match := re.fullmatch(r"---- (.+) stdout ----", line):
        name = match[1]
    elif line.startswith("RuntimeError: unrecognised merged rustdoc output "):
        raw = ast.literal_eval(line.removeprefix("RuntimeError: unrecognised merged rustdoc output "))
        assert raw["exit_code"] == 0 and raw["peer"] in workers and name not in docs
        docs[name] = raw

assert set(docs) == native_docs and len(docs) == 27 and set(attempts) == workers
print(json.dumps({
    "upstream_commit": run["upstream_commit"],
    "source_id": run["source_after"],
    "workspace_members": sorted(packages.values()),
    "rust_toolchain": "1.91.1",
    "native_passed": {"ordinary": len(native), "rustdoc": len(native_docs)},
    "remote_cargo_exit": run["exit_code"],
    "remote_ordinary": dict(statuses),
    "remote_ordinary_attempts_by_authenticated_worker": attempts,
    "remote_failed_rustdoc_adapters": len(docs),
    "nested_rustdoc_guest_exit_zero": len(docs),
    "nested_rustdoc_guest_attempts_by_worker": Counter(r["peer"] for r in docs.values()),
    "ordinary_name_sets_agree": True,
    "identical_dispositions": False,
    "should_panic_dispositions": sorted(errors, key=lambda e: e["case"]),
    "ordinary_single_stochastic_case_run": selected,
    "repeated_stochastic_campaign_started": False,
    "raw_gzip_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(here.glob("*.gz"))},
}, indent=2))
